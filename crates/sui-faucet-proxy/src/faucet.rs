// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{metrics::FaucetMetrics, FaucetError};
use prometheus::Registry;
#[cfg(test)]
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use sui_sdk::{
    rpc_types::{SuiTransactionBlockResponse, SuiTransactionBlockResponseOptions},
    types::quorum_driver_types::ExecuteTransactionRequestType,
};

use crate::FaucetConfig;
use shared_crypto::intent::Intent;
use sui_keys::keystore::AccountKeystore;
use sui_sdk::types::{
    base_types::{ObjectID, SuiAddress},
    gas_coin::GasCoin,
    transaction::{Transaction, TransactionData},
};
use sui_sdk::wallet_context::WalletContext;
use tokio::sync::Mutex;
use tokio::time::Duration;
use tracing::info;

pub struct LocalFaucet {
    wallet: WalletContext,
    active_address: SuiAddress,
    coin_id: ObjectID,
    pub metrics: FaucetMetrics,
    ttl_expiration: u64,
    coin_amount: u64,
    num_coins: usize,
    local_queue: Mutex<Vec<SuiAddress>>,
}

/// We do not just derive(Debug) because WalletContext and the WriteAheadLog do not implement Debug / are also hard
/// to implement Debug.
impl fmt::Debug for LocalFaucet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SimpleFaucet")
            .field("faucet_wallet", &self.active_address)
            .field("ttl_expiration", &self.ttl_expiration)
            .field("coin_amount", &self.coin_amount)
            .finish()
    }
}

impl LocalFaucet {
    pub async fn new(
        mut wallet: WalletContext,
        prometheus_registry: &Registry,
        config: FaucetConfig,
    ) -> Result<Arc<Self>, FaucetError> {
        let (coins, active_address) = find_gas_coins_and_address(&mut wallet, &config).await?;
        info!("Starting faucet with address: {:?}", active_address);

        let metrics = FaucetMetrics::new(prometheus_registry);
        // set initial balance when faucet starts
        let balance = coins.iter().map(|coin| coin.0.balance.value()).sum::<u64>();
        metrics.balance.set(balance as i64);

        let local_queue = Mutex::new(vec![]);

        Ok(Arc::new(LocalFaucet {
            wallet,
            active_address,
            metrics,
            ttl_expiration: config.ttl_expiration,
            local_queue,
            coin_id: *coins[0].id(),
            coin_amount: config.amount,
            num_coins: config.num_coins,
        }))
    }

    pub async fn local_request_add_to_queue(&self, recipient: SuiAddress) {
        let mut queue = self.local_queue.lock().await;
        queue.push(recipient);
    }

    pub async fn local_request_execute_tx(&self) -> Result<(), FaucetError> {
        let mut queue = self.local_queue.lock().await;

        let gas_price = self.wallet.get_reference_gas_price().await.map_err(|e| {
            FaucetError::internal(format!("Failed to get gas price: {}", e.to_string()))
        })?;

        let chunks = queue
            .chunks(100)
            .map(|chunk| chunk.to_vec())
            .collect::<Vec<_>>();

        for chunk in chunks {
            let mut ptb = sui_sdk::types::programmable_transaction_builder::ProgrammableTransactionBuilder::new();
            for recipient in chunk {
                let recipients = vec![recipient; self.num_coins];
                let amounts = vec![self.coin_amount; recipients.len()];
                ptb.pay_sui(recipients, amounts.to_vec())
                    .map_err(FaucetError::internal)?;
            }

            let ptb = ptb.finish();

            let coin_id_ref = self
                .wallet
                .get_object_ref(self.coin_id)
                .await
                .map_err(|e| {
                    FaucetError::internal(format!("Failed to get object ref: {}", e.to_string()))
                })?;
            let tx_data = TransactionData::new_programmable(
                self.active_address,
                vec![coin_id_ref],
                ptb,
                5000000000,
                gas_price,
            );

            self.execute_txn_with_retries(tx_data, self.coin_id).await;
        }

        queue.clear();

        Ok(())
    }
    async fn execute_txn(
        &self,
        tx_data: &TransactionData,
        coin_id: ObjectID,
    ) -> Result<SuiTransactionBlockResponse, anyhow::Error> {
        let signature = self
            .wallet
            .config
            .keystore
            .sign_secure(&self.active_address, &tx_data, Intent::sui_transaction())
            .map_err(FaucetError::internal)?;
        let tx = Transaction::from_data(tx_data.clone(), vec![signature]);

        self.metrics.current_executions_in_flight.inc();
        let _metrics_guard = scopeguard::guard(self.metrics.clone(), |metrics| {
            metrics.current_executions_in_flight.dec();
        });

        let client = self.wallet.get_client().await?;

        Ok(client
            .quorum_driver_api()
            .execute_transaction_block(
                tx.clone(),
                SuiTransactionBlockResponseOptions::new()
                    .with_effects()
                    .with_balance_changes(),
                Some(ExecuteTransactionRequestType::WaitForLocalExecution),
            )
            .await
            .map_err(|e| {
                FaucetError::internal(format!(
                    "Failed to execute PaySui transaction for coin {:?}, with err {:?}",
                    coin_id, e
                ))
            })?)
    }

    async fn execute_txn_with_retries(
        &self,
        tx: TransactionData,
        coin_id: ObjectID,
    ) -> SuiTransactionBlockResponse {
        let mut retry_delay = Duration::from_millis(500);

        loop {
            let res = self.execute_txn(&tx, coin_id).await;

            if let Ok(res) = res {
                return res;
            }
            tokio::time::sleep(retry_delay).await;
            retry_delay *= 2;
        }
    }
}

/// Finds gas coins with sufficient balance and returns the address to use as the active address
/// for the faucet. If the initial active address in the wallet does not have enough gas coins,
/// it will iterate through the addresses to find one with sufficient gas coins.
async fn find_gas_coins_and_address(
    wallet: &mut WalletContext,
    config: &FaucetConfig,
) -> Result<(Vec<GasCoin>, SuiAddress), FaucetError> {
    let active_address = wallet
        .active_address()
        .map_err(|e| FaucetError::Wallet(e.to_string()))?;

    for address in std::iter::once(active_address).chain(wallet.get_addresses().into_iter()) {
        let coins: Vec<_> = wallet
            .gas_objects(address)
            .await
            .map_err(|e| FaucetError::Wallet(e.to_string()))?
            .iter()
            .filter_map(|(balance, obj)| {
                if *balance >= config.amount {
                    GasCoin::try_from(obj).ok()
                } else {
                    None
                }
            })
            .collect();

        if !coins.is_empty() {
            return Ok((coins, address));
        }
    }

    Err(FaucetError::Wallet(
        "No address found with sufficient coins".to_string(),
    ))
}
