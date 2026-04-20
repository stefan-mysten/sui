// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;
use sui_config::{
    transaction_deny_config::TransactionDenyConfig, verifier_signing_config::VerifierSigningConfig,
};
use sui_execution::Executor;
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use sui_types::{
    base_types::ObjectID,
    committee::{Committee, EpochId},
    digests::{ChainIdentifier, TransactionDigest},
    effects::{TransactionEffects, TransactionEffectsAPI},
    error::{SuiError, SuiErrorKind},
    execution_params::{ExecutionOrEarlyError, FundsWithdrawStatus, get_early_execution_error},
    full_checkpoint_content::ObjectSet,
    gas::SuiGasStatus,
    inner_temporary_store::InnerTemporaryStore,
    metrics::{BytecodeVerifierMetrics, ExecutionMetrics},
    object::{MoveObject, OBJECT_START_VERSION, Object, Owner},
    sui_system_state::{
        SuiSystemState, SuiSystemStateTrait,
        epoch_start_sui_system_state::{EpochStartSystemState, EpochStartSystemStateTrait},
    },
    transaction::{
        CheckedInputObjects, ObjectReadResult, TransactionData, TransactionDataAPI,
        VerifiedTransaction,
    },
    transaction_executor::{SimulateTransactionResult, TransactionChecks},
};

use crate::SimulatorStore;

const DEV_INSPECT_GAS_COIN_VALUE: u64 = 1_000_000_000_000_000_000;

fn early_execution_error(
    tx_digest: &TransactionDigest,
    checked_input_objects: &CheckedInputObjects,
) -> ExecutionOrEarlyError {
    // Simulacrum has no certificate deny config and doesn't track per-address withdrawal
    // balances, so we only surface errors derivable from the checked inputs themselves
    // (consensus-stream-ended or cancelled objects).
    match get_early_execution_error(
        tx_digest,
        checked_input_objects,
        &HashSet::new(),
        &FundsWithdrawStatus::MaybeSufficient,
    ) {
        Some(error) => ExecutionOrEarlyError::Err(error),
        None => ExecutionOrEarlyError::Ok(()),
    }
}

pub struct EpochState {
    epoch_start_state: EpochStartSystemState,
    committee: Committee,
    protocol_config: ProtocolConfig,
    execution_metrics: Arc<ExecutionMetrics>,
    bytecode_verifier_metrics: Arc<BytecodeVerifierMetrics>,
    executor: Arc<dyn Executor + Send + Sync>,
    chain_identifier: ChainIdentifier,
    /// A counter that advances each time we advance the clock in order to ensure that each update
    /// txn has a unique digest. This is reset on epoch changes
    next_consensus_round: u64,
}

impl EpochState {
    pub fn new(system_state: SuiSystemState, chain_identifier: ChainIdentifier) -> Self {
        let protocol_config =
            ProtocolConfig::get_for_version(system_state.protocol_version().into(), Chain::Unknown);
        Self::new_with_protocol_config(system_state, protocol_config, chain_identifier)
    }

    pub fn new_with_protocol_config(
        system_state: SuiSystemState,
        protocol_config: ProtocolConfig,
        chain_identifier: ChainIdentifier,
    ) -> Self {
        let epoch_start_state = system_state.into_epoch_start_state();
        let committee = epoch_start_state.get_sui_committee();
        let registry = prometheus::Registry::new();
        let execution_metrics = Arc::new(ExecutionMetrics::new(&registry));
        let bytecode_verifier_metrics = Arc::new(BytecodeVerifierMetrics::new(&registry));
        let executor = sui_execution::executor(&protocol_config, true).unwrap();

        Self {
            epoch_start_state,
            committee,
            protocol_config,
            execution_metrics,
            bytecode_verifier_metrics,
            executor,
            chain_identifier,
            next_consensus_round: 0,
        }
    }

    pub fn epoch(&self) -> EpochId {
        self.epoch_start_state.epoch()
    }

    pub fn reference_gas_price(&self) -> u64 {
        self.epoch_start_state.reference_gas_price()
    }

    pub fn next_consensus_round(&mut self) -> u64 {
        let round = self.next_consensus_round;
        self.next_consensus_round += 1;
        round
    }

    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    pub fn epoch_start_state(&self) -> &EpochStartSystemState {
        &self.epoch_start_state
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_config().version
    }

    pub fn protocol_config(&self) -> &ProtocolConfig {
        &self.protocol_config
    }

    pub fn chain_identifier(&self) -> ChainIdentifier {
        self.chain_identifier
    }

    pub fn execute_transaction(
        &self,
        store: &dyn SimulatorStore,
        deny_config: &TransactionDenyConfig,
        verifier_signing_config: &VerifierSigningConfig,
        transaction: &VerifiedTransaction,
    ) -> Result<(
        InnerTemporaryStore,
        SuiGasStatus,
        TransactionEffects,
        Result<(), sui_types::error::ExecutionError>,
    )> {
        let tx_digest = *transaction.digest();
        let tx_data = &transaction.data().intent_message().value;
        let input_object_kinds = tx_data.input_objects()?;
        let receiving_object_refs = tx_data.receiving_objects();

        sui_transaction_checks::deny::check_transaction_for_signing(
            tx_data,
            transaction.tx_signatures(),
            &input_object_kinds,
            &receiving_object_refs,
            deny_config,
            &store,
        )?;

        let (input_objects, receiving_objects) = store.read_objects_for_synchronous_execution(
            &tx_digest,
            &input_object_kinds,
            &receiving_object_refs,
        )?;

        // Run the transaction input checks that would run when submitting the txn to a validator
        // for signing
        let (gas_status, checked_input_objects) = sui_transaction_checks::check_transaction_input(
            &self.protocol_config,
            self.epoch_start_state.reference_gas_price(),
            transaction.data().transaction_data(),
            input_objects,
            &receiving_objects,
            &self.bytecode_verifier_metrics,
            verifier_signing_config,
        )?;

        let transaction_data = transaction.data().transaction_data();
        let (kind, signer, gas_data) = transaction_data.execution_parts();
        let execution_params = early_execution_error(&tx_digest, &checked_input_objects);
        let (inner_temp_store, gas_status, effects, _timings, result) = self
            .executor
            .execute_transaction_to_effects_and_execution_error(
                store.backing_store(),
                &self.protocol_config,
                self.execution_metrics.clone(),
                false, // enable_expensive_checks
                execution_params,
                &self.epoch_start_state.epoch(),
                self.epoch_start_state.epoch_start_timestamp_ms(),
                checked_input_objects,
                gas_data,
                gas_status,
                kind,
                None, // compat_args
                signer,
                tx_digest,
                &mut None,
            );
        Ok((inner_temp_store, gas_status, effects, result))
    }

    pub fn simulate_transaction(
        &self,
        store: &dyn SimulatorStore,
        verifier_signing_config: &VerifierSigningConfig,
        mut transaction: TransactionData,
        checks: TransactionChecks,
        allow_mock_gas_coin: bool,
    ) -> Result<SimulateTransactionResult, SuiError> {
        if transaction.kind().is_system_tx() {
            return Err(SuiErrorKind::UnsupportedFeatureError {
                error: "simulate does not support system transactions".to_string(),
            }
            .into());
        }

        let dev_inspect = checks.disabled();

        transaction.validity_check_no_gas_check(&self.protocol_config)?;

        let input_object_kinds = transaction.input_objects()?;
        let receiving_object_refs = transaction.receiving_objects();
        let is_gasless =
            self.protocol_config.enable_gasless() && transaction.is_gasless_transaction();

        let mock_gas_object = if allow_mock_gas_coin && transaction.gas().is_empty() && !is_gasless
        {
            let obj = Object::new_move(
                MoveObject::new_gas_coin(
                    OBJECT_START_VERSION,
                    ObjectID::MAX,
                    DEV_INSPECT_GAS_COIN_VALUE,
                ),
                Owner::AddressOwner(transaction.gas_data().owner),
                TransactionDigest::genesis_marker(),
            );
            transaction.gas_data_mut().payment = vec![obj.compute_object_reference()];
            Some(obj)
        } else {
            None
        };

        let tx_digest = transaction.digest();
        let (mut input_objects, receiving_objects) = store.read_objects_for_synchronous_execution(
            &tx_digest,
            &input_object_kinds,
            &receiving_object_refs,
        )?;

        let mock_gas_id = mock_gas_object.map(|obj| {
            let id = obj.id();
            input_objects.push(ObjectReadResult::new_from_gas_object(&obj));
            id
        });

        let (gas_status, checked_input_objects) = if dev_inspect {
            sui_transaction_checks::check_dev_inspect_input(
                &self.protocol_config,
                &transaction,
                input_objects,
                receiving_objects,
                self.epoch_start_state.reference_gas_price(),
            )?
        } else {
            sui_transaction_checks::check_transaction_input(
                &self.protocol_config,
                self.epoch_start_state.reference_gas_price(),
                &transaction,
                input_objects,
                &receiving_objects,
                &self.bytecode_verifier_metrics,
                verifier_signing_config,
            )?
        };

        let (kind, signer, gas_data) = transaction.execution_parts();
        let execution_params = early_execution_error(&tx_digest, &checked_input_objects);
        let (inner_temp_store, _, effects, execution_result) =
            self.executor.dev_inspect_transaction(
                store.backing_store(),
                &self.protocol_config,
                self.execution_metrics.clone(),
                false,
                execution_params,
                &self.epoch_start_state.epoch(),
                self.epoch_start_state.epoch_start_timestamp_ms(),
                checked_input_objects,
                gas_data,
                gas_status,
                kind,
                None,
                signer,
                tx_digest,
                dev_inspect,
            );

        // Simulacrum doesn't track runtime-loaded objects; `object_set` is built from the
        // transaction's input and written objects only, and `unchanged_loaded_runtime_objects`
        // is always empty (matching `ReadStore::get_unchanged_loaded_runtime_objects`).
        let objects = {
            let mut objects = ObjectSet::default();
            for o in inner_temp_store
                .input_objects
                .values()
                .chain(inner_temp_store.written.values())
            {
                objects.insert(o.clone());
            }

            let object_keys =
                sui_types::storage::get_transaction_object_set(&transaction, &effects, &[]);

            let mut set = ObjectSet::default();
            for k in object_keys {
                if let Some(o) = objects.get(&k) {
                    set.insert(o.clone());
                }
            }
            set
        };

        Ok(SimulateTransactionResult {
            events: effects.events_digest().map(|_| inner_temp_store.events),
            objects,
            effects,
            execution_result,
            mock_gas_id,
            unchanged_loaded_runtime_objects: vec![],
            suggested_gas_price: None,
        })
    }
}
