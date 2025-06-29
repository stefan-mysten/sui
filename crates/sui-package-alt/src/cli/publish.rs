// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use tracing::debug;

use anyhow::anyhow;

use crate::SuiFlavor;
use clap::{Command, Parser, Subcommand};
use move_package_alt::{
    compilation::compiled_package::{compile, BuildConfig, LintFlag},
    errors::PackageResult,
    flavor::Vanilla,
    package::{Package, RootPackage},
};
use shared_crypto::intent::Intent;
use sui_config::{sui_config_dir, SUI_CLIENT_CONFIG};
use sui_sdk::{
    rpc_types::SuiExecutionStatus,
    types::{
        base_types::{ObjectID, SuiAddress},
        transaction::{
            InputObjectKind, SenderSignedData, Transaction, TransactionData, TransactionKind,
        },
    },
    wallet_context::WalletContext,
};

use sui_json_rpc_types::SuiTransactionBlockEffectsAPI;
use sui_keys::keystore::AccountKeystore;

/// Build the package
#[derive(Debug, Clone, Parser)]
pub struct Publish {
    /// Path to the project
    #[arg(name = "path", short = 'p', long = "path", default_value = ".")]
    path: Option<PathBuf>,

    #[arg(
        name = "env",
        short = 'e',
        long = "environment",
        default_value = "testnet"
    )]
    env: Option<String>,
}

impl Publish {
    pub async fn execute(&self) -> PackageResult<()> {
        let path = self.path.clone().unwrap_or_else(|| PathBuf::from("."));

        // wallet

        let config_path = sui_config_dir()?.join(SUI_CLIENT_CONFIG);
        let mut context = WalletContext::new(&config_path)?;

        let sender = context.active_address()?;

        let client = context.get_client().await?;
        let read_api = client.read_api();

        let build_config = BuildConfig {
            generate_docs: false,
            save_disassembly: true,
            install_dir: None,
            force_recompilation: false,
            lock_file: None,
            silence_warnings: false,
            warnings_are_errors: false,
            json_errors: false,
            lint_flag: LintFlag::default(),
            force_lock_file: false,
        };
        // get sender and chain id
        // let sender = context.infer_sender(&payment.gas).await?;
        // let chain_id = read_api.get_chain_identifier().await.ok();
        //
        // compile package
        let root_pkg = RootPackage::<SuiFlavor>::load(path, None).await?;
        let compiled_package = compile::<SuiFlavor>(
            root_pkg,
            build_config,
            &self.env.clone().unwrap_or_default(),
        )
        .await
        .unwrap();
        let compiled_modules = compiled_package.get_package_bytes();

        let dep_ids: Vec<ObjectID> = compiled_package
            .dependency_ids()
            .into_iter()
            .map(|x| x.into())
            .collect();

        debug!("Compiled modules {:?}", compiled_modules);
        debug!("Dependency IDs {:?}", dep_ids);
        println!("Package compiled successfully.");

        // create the publish tx kind
        let tx_kind = client
            .transaction_builder()
            .publish_tx_kind(sender, compiled_modules, dep_ids)
            .await?;

        let result = dry_run_or_execute_or_serialize(tx_kind, &mut context).await?;
        Ok(())
    }
}

pub(crate) async fn dry_run_or_execute_or_serialize(
    tx_kind: TransactionKind,
    context: &mut WalletContext,
) -> Result<(), anyhow::Error> {
    let gas_price = context.get_reference_gas_price().await?;
    let signer = context.active_address()?;

    let client = context.get_client().await?;

    let gas_budget = 50000000;

    let gas_payment = {
        let input_objects: Vec<_> = tx_kind
            .input_objects()?
            .iter()
            .filter_map(|o| match o {
                InputObjectKind::ImmOrOwnedMoveObject((id, _, _)) => Some(*id),
                _ => None,
            })
            .collect();

        let gas_payment = client
            .transaction_builder()
            .select_gas(signer, None, gas_budget, input_objects, gas_price)
            .await?;

        vec![gas_payment]
    };

    debug!("Preparing transaction data");
    let tx_data = TransactionData::new_with_gas_coins_allow_sponsor(
        tx_kind,
        signer,
        gas_payment,
        gas_budget,
        gas_price,
        signer,
    );
    debug!("Finished preparing transaction data");

    let mut signatures = vec![context
        .config
        .keystore
        .sign_secure(&signer, &tx_data, Intent::sui_transaction())?
        .into()];

    let sender_signed_data = SenderSignedData::new(tx_data, signatures);
    let transaction = Transaction::new(sender_signed_data);
    debug!("Executing transaction: {:?}", transaction);
    let mut response = context
        .execute_transaction_may_fail(transaction.clone())
        .await?;
    debug!("Transaction executed: {:?}", transaction);

    let effects = response
        .effects
        .as_ref()
        .ok_or_else(|| anyhow!("Effects from SuiTransactionBlockResult should not be empty"))?;

    let effects_status = effects.clone().into_status();
    if let SuiExecutionStatus::Failure { error } = effects_status {
        return Err(anyhow!(
            "Error executing transaction '{}': {error}",
            response.digest
        ));
    }

    println!(
        "Transaction executed successfully. Digest: {}",
        response.digest
    );

    Ok(())
}
