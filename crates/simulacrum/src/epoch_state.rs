// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;
use move_core_types::language_storage::TypeTag;
use once_cell::sync::Lazy;
use sui_config::{
    transaction_deny_config::TransactionDenyConfig, verifier_signing_config::VerifierSigningConfig,
};
use sui_core::accumulators::funds_read::AccountFundsRead;
use sui_core::simulation::{
    SimulationContext, SimulationParams, simulate_transaction_with_context,
};
use sui_execution::Executor;
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use sui_types::{
    SUI_ACCUMULATOR_ROOT_OBJECT_ID,
    accumulator_root::{AccumulatorKey, AccumulatorObjId, AccumulatorValue},
    base_types::{ObjectID, ObjectRef, SequenceNumber, SuiAddress},
    coin_reservation::{CoinReservationResolverTrait, ParsedObjectRefWithdrawal},
    committee::{Committee, EpochId},
    digests::{ChainIdentifier, TransactionDigest},
    effects::TransactionEffects,
    error::{SuiResult, UserInputError, UserInputResult},
    execution_params::ExecutionOrEarlyError,
    gas::SuiGasStatus,
    inner_temporary_store::InnerTemporaryStore,
    metrics::{BytecodeVerifierMetrics, ExecutionMetrics},
    storage::BackingPackageStore,
    sui_system_state::{
        SuiSystemState, SuiSystemStateTrait,
        epoch_start_sui_system_state::{EpochStartSystemState, EpochStartSystemStateTrait},
    },
    transaction::{
        FundsWithdrawalArg, InputObjectKind, InputObjects, ReceivingObjects, TransactionData,
        TransactionDataAPI, VerifiedTransaction,
    },
    transaction_executor::{SimulateTransactionResult, TransactionChecks},
};

use crate::SimulatorStore;

static EMPTY_CERTIFICATE_DENY_SET: Lazy<HashSet<TransactionDigest>> = Lazy::new(HashSet::new);

fn invalid_withdraw_reservation(error: impl Into<String>) -> UserInputError {
    UserInputError::InvalidWithdrawReservation {
        error: error.into(),
    }
}

struct SimulatorCoinReservationResolver<'a> {
    store: &'a (dyn SimulatorStore + Send + Sync),
}

impl SimulatorCoinReservationResolver<'_> {
    fn get_owner_and_type_for_object(
        &self,
        object_id: ObjectID,
        accumulator_version: Option<SequenceNumber>,
    ) -> UserInputResult<(SuiAddress, TypeTag)> {
        let object =
            AccumulatorValue::load_object_by_id(self.store, accumulator_version, object_id)
                .map_err(|e| {
                    invalid_withdraw_reservation(format!(
                        "could not load coin reservation object id {e}"
                    ))
                })?
                .ok_or_else(|| {
                    invalid_withdraw_reservation(format!(
                        "coin reservation object id {object_id} not found"
                    ))
                })?;

        let move_object = object.data.try_as_move().ok_or_else(|| {
            invalid_withdraw_reservation(format!(
                "coin reservation object id {object_id} is not a move object"
            ))
        })?;
        let type_tag = move_object
            .type_()
            .balance_accumulator_field_type_maybe()
            .ok_or_else(|| {
                invalid_withdraw_reservation(format!(
                    "coin reservation object id {object_id} is not a balance accumulator field"
                ))
            })?;
        let (key, _): (AccumulatorKey, AccumulatorValue) = move_object.try_into().map_err(|e| {
            invalid_withdraw_reservation(format!("could not load coin reservation object id {e}"))
        })?;
        Ok((key.owner, type_tag))
    }
}

impl CoinReservationResolverTrait for SimulatorCoinReservationResolver<'_> {
    fn resolve_funds_withdrawal(
        &self,
        sender: SuiAddress,
        coin_reservation: ParsedObjectRefWithdrawal,
        accumulator_version: Option<SequenceNumber>,
    ) -> UserInputResult<FundsWithdrawalArg> {
        let (owner, type_tag) = self.get_owner_and_type_for_object(
            coin_reservation.unmasked_object_id,
            accumulator_version,
        )?;

        if sender != owner {
            return Err(invalid_withdraw_reservation(format!(
                "coin reservation object id {} is owned by {}, not sender {}",
                coin_reservation.unmasked_object_id, owner, sender
            )));
        }

        Ok(FundsWithdrawalArg::balance_from_sender(
            coin_reservation.reservation_amount(),
            type_tag,
        ))
    }
}

struct SimulatorAccountFundsRead<'a> {
    store: &'a (dyn SimulatorStore + Send + Sync),
}

impl AccountFundsRead for SimulatorAccountFundsRead<'_> {
    fn get_latest_account_amount(&self, id: &AccumulatorObjId) -> (u128, SequenceNumber) {
        latest_account_amount(self.store, id)
    }

    fn get_account_amount_at_version(
        &self,
        id: &AccumulatorObjId,
        version: SequenceNumber,
    ) -> u128 {
        AccumulatorValue::load_object_by_id(self.store, Some(version), *id.inner())
            .expect("account-balance reads in simulacrum must succeed")
            .map(|object| {
                let move_object = object
                    .data
                    .try_as_move()
                    .expect("accumulator account objects must be move objects");
                let (_, value): (AccumulatorKey, AccumulatorValue) = move_object
                    .try_into()
                    .expect("accumulator account objects must deserialize");
                value
                    .as_u128()
                    .expect("accumulator account objects must store u128 balances")
            })
            .unwrap_or(0)
    }
}

struct EpochSimulationContext<'a> {
    store: &'a (dyn SimulatorStore + Send + Sync),
}

impl SimulationContext for EpochSimulationContext<'_> {
    fn read_inputs_for_simulation(
        &self,
        tx_digest: &TransactionDigest,
        input_object_kinds: &[InputObjectKind],
        receiving_object_refs: &[ObjectRef],
    ) -> SuiResult<(InputObjects, ReceivingObjects)> {
        self.store.read_objects_for_synchronous_execution(
            tx_digest,
            input_object_kinds,
            receiving_object_refs,
        )
    }
}

fn latest_account_amount(
    store: &(dyn SimulatorStore + Send + Sync),
    id: &AccumulatorObjId,
) -> (u128, SequenceNumber) {
    match crate::store::SimulatorStore::get_object(store, id.inner()) {
        Some(account_object) => {
            let move_object = account_object
                .data
                .try_as_move()
                .expect("accumulator account objects must be move objects");
            let (_, value): (AccumulatorKey, AccumulatorValue) = move_object
                .try_into()
                .expect("accumulator account objects must deserialize");
            (
                value
                    .as_u128()
                    .expect("accumulator account objects must store u128 balances"),
                account_object.version(),
            )
        }
        None => {
            let accumulator_version =
                crate::store::SimulatorStore::get_object(store, &SUI_ACCUMULATOR_ROOT_OBJECT_ID)
                    .expect(
                        "accumulator root object must exist when balance withdrawals are enabled",
                    )
                    .version();
            (0, accumulator_version)
        }
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
        let (inner_temp_store, gas_status, effects, _timings, result) = self
            .executor
            .execute_transaction_to_effects_and_execution_error(
                store.backing_store(),
                &self.protocol_config,
                self.execution_metrics.clone(),
                false, // enable_expensive_checks
                // TODO: Integrate with early execution error
                ExecutionOrEarlyError::Ok(()),
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
        store: &(dyn SimulatorStore + Send + Sync),
        deny_config: &TransactionDenyConfig,
        verifier_signing_config: &VerifierSigningConfig,
        transaction: TransactionData,
        checks: TransactionChecks,
        allow_mock_gas_coin: bool,
    ) -> SuiResult<SimulateTransactionResult> {
        let coin_reservation_resolver = SimulatorCoinReservationResolver { store };
        let account_funds_read = SimulatorAccountFundsRead { store };
        let params = SimulationParams {
            protocol_config: self.protocol_config(),
            reference_gas_price: self.reference_gas_price(),
            epoch_id: self.epoch(),
            epoch_timestamp_ms: self.epoch_start_state().epoch_start_timestamp_ms(),
            chain_identifier: self.chain_identifier(),
            transaction_deny_config: deny_config,
            verifier_signing_config,
            certificate_deny_set: &EMPTY_CERTIFICATE_DENY_SET,
            bytecode_verifier_metrics: self.bytecode_verifier_metrics.clone(),
            execution_metrics: self.execution_metrics.clone(),
            package_store: store as &dyn BackingPackageStore,
            backing_store: store.backing_store(),
            coin_reservation_resolver: &coin_reservation_resolver,
            account_funds_read: &account_funds_read,
        };
        let context = EpochSimulationContext { store };
        simulate_transaction_with_context(
            &params,
            &context,
            transaction,
            checks,
            allow_mock_gas_coin,
        )
    }
}
