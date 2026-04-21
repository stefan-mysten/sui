// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared transaction simulation logic used by fullnodes and simulacrum.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use move_core_types::language_storage::TypeTag;
use sui_config::{
    transaction_deny_config::TransactionDenyConfig, verifier_signing_config::VerifierSigningConfig,
};
use sui_types::{
    accumulator_root::AccumulatorObjId,
    base_types::{ObjectID, ObjectRef, SuiAddress},
    coin_reservation::{CoinReservationResolverTrait, ParsedDigest},
    committee::EpochId,
    digests::{ChainIdentifier, TransactionDigest},
    effects::{TransactionEffects, TransactionEffectsAPI},
    error::{ExecutionError, SuiErrorKind, SuiResult},
    execution::ExecutionResult,
    execution_params::{ExecutionOrEarlyError, FundsWithdrawStatus, get_early_execution_error},
    execution_status::ExecutionErrorKind,
    full_checkpoint_content::ObjectSet,
    gas::SuiGasStatus,
    inner_temporary_store::InnerTemporaryStore,
    metrics::{BytecodeVerifierMetrics, ExecutionMetrics},
    object::{MoveObject, OBJECT_START_VERSION, Object, Owner},
    signature::GenericSignature,
    storage::{BackingPackageStore, BackingStore, TrackingBackingStore},
    transaction::{
        CheckedInputObjects, GasData, InputObjectKind, InputObjects, ObjectReadResult,
        ReceivingObjects, TransactionData, TransactionDataAPI, TransactionKind,
    },
    transaction_executor::{SimulateTransactionResult, TransactionChecks},
};

use crate::accumulators::funds_read::AccountFundsRead;
use crate::accumulators::transaction_rewriting::rewrite_transaction_for_coin_reservations;
use crate::authority::DEV_INSPECT_GAS_COIN_VALUE;
use crate::transaction_outputs;

/// Data and services needed to run the shared transaction simulation pipeline.
pub struct SimulationParams<'a> {
    pub protocol_config: &'a sui_protocol_config::ProtocolConfig,
    pub reference_gas_price: u64,
    pub epoch_id: EpochId,
    pub epoch_timestamp_ms: u64,
    pub chain_identifier: ChainIdentifier,
    pub transaction_deny_config: &'a TransactionDenyConfig,
    pub verifier_signing_config: &'a VerifierSigningConfig,
    pub certificate_deny_set: &'a HashSet<TransactionDigest>,
    pub bytecode_verifier_metrics: Arc<BytecodeVerifierMetrics>,
    pub execution_metrics: Arc<ExecutionMetrics>,
    pub package_store: &'a dyn BackingPackageStore,
    pub backing_store: &'a dyn BackingStore,
    pub coin_reservation_resolver: &'a dyn CoinReservationResolverTrait,
    pub account_funds_read: &'a dyn AccountFundsRead,
}

/// Behavioral capabilities that vary between simulation environments.
pub trait SimulationContext {
    /// Loads the input and receiving objects needed for simulation.
    ///
    /// `tx_digest` is passed through so implementations that normally key read-side caching on the
    /// transaction digest can preserve that behavior, or intentionally disable it.
    fn read_inputs_for_simulation(
        &self,
        tx_digest: &TransactionDigest,
        input_object_kinds: &[InputObjectKind],
        receiving_object_refs: &[ObjectRef],
    ) -> SuiResult<(InputObjects, ReceivingObjects)>;

    /// Returns a caller-specific suggested gas price, if simulation should surface one.
    ///
    /// Fullnodes can use this to report congestion-aware pricing, while simulators that do not
    /// compute such a signal can keep the default `None`.
    fn suggested_gas_price(&self, _tx: &TransactionData) -> Option<u64> {
        None
    }
}

/// The prepared simulation inputs after request validation, withdrawal prechecks, and any
/// transaction rewriting needed before execution.
struct PreparedSimulation {
    transaction: TransactionData,
    dev_inspect: bool,
    tx_digest: TransactionDigest,
    execution_params: ExecutionOrEarlyError,
    checked_input_objects: CheckedInputObjects,
    gas_status: SuiGasStatus,
    gas_data: GasData,
    kind: TransactionKind,
    rewritten_inputs: Option<Vec<bool>>,
    signer: SuiAddress,
    address_funds: BTreeSet<AccumulatorObjId>,
    mock_gas_id: Option<ObjectID>,
}

/// The execution outputs captured before the final response is assembled for the caller.
struct ExecutedSimulation {
    transaction: TransactionData,
    inner_temp_store: InnerTemporaryStore,
    effects: TransactionEffects,
    execution_result: Result<Vec<ExecutionResult>, ExecutionError>,
    loaded_runtime_objects: ObjectSet,
    mock_gas_id: Option<ObjectID>,
}

/// Run transaction simulation using the provided context.
///
/// # Errors
///
/// Returns an error if the transaction is unsupported for simulation, fails input validation, or
/// fails any shared pre-execution checks.
pub fn simulate_transaction_with_context<C: SimulationContext>(
    params: &SimulationParams<'_>,
    ctx: &C,
    transaction: TransactionData,
    checks: TransactionChecks,
    allow_mock_gas_coin: bool,
) -> SuiResult<SimulateTransactionResult> {
    validate_simulation_request(params, &transaction)?;
    let prepared = prepare_simulation(params, ctx, transaction, checks, allow_mock_gas_coin)?;
    let executed = execute_prepared_simulation(params, prepared)?;
    let suggested_gas_price = ctx.suggested_gas_price(&executed.transaction);
    Ok(build_simulation_result(executed, suggested_gas_price))
}

fn validate_simulation_request(
    params: &SimulationParams<'_>,
    transaction: &TransactionData,
) -> SuiResult {
    if transaction.kind().is_system_tx() {
        return Err(SuiErrorKind::UnsupportedFeatureError {
            error: "simulate does not support system transactions".to_string(),
        }
        .into());
    }

    if !params.protocol_config.enable_coin_reservation_obj_refs()
        && transaction
            .gas()
            .iter()
            .any(|obj_ref| ParsedDigest::is_coin_reservation_digest(&obj_ref.2))
    {
        return Err(SuiErrorKind::UnsupportedFeatureError {
            error: "coin reservations in gas payment are not supported at this protocol version"
                .to_string(),
        }
        .into());
    }

    Ok(())
}

fn prepare_simulation<C: SimulationContext>(
    params: &SimulationParams<'_>,
    ctx: &C,
    mut transaction: TransactionData,
    checks: TransactionChecks,
    allow_mock_gas_coin: bool,
) -> SuiResult<PreparedSimulation> {
    let dev_inspect = checks.disabled();

    transaction.validity_check_no_gas_check(params.protocol_config)?;

    let input_object_kinds = transaction.input_objects()?;
    let receiving_object_refs = transaction.receiving_objects();
    let is_gasless =
        params.protocol_config.enable_gasless() && transaction.is_gasless_transaction();
    let mock_gas_object = if allow_mock_gas_coin && transaction.gas().is_empty() && !is_gasless {
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

    let declared_withdrawals = pre_object_load_checks(
        &transaction,
        &[],
        &input_object_kinds,
        &receiving_object_refs,
        params.transaction_deny_config,
        params.package_store,
        params.chain_identifier,
        params.coin_reservation_resolver,
        params.account_funds_read,
        params.protocol_config,
    )?;
    let address_funds = declared_withdrawals.keys().cloned().collect();

    let tx_digest = transaction.digest();
    let (mut input_objects, receiving_objects) =
        ctx.read_inputs_for_simulation(&tx_digest, &input_object_kinds, &receiving_object_refs)?;

    let mock_gas_id = mock_gas_object.map(|obj| {
        let id = obj.id();
        input_objects.push(ObjectReadResult::new_from_gas_object(&obj));
        id
    });

    let (gas_status, checked_input_objects) = if dev_inspect {
        sui_transaction_checks::check_dev_inspect_input(
            params.protocol_config,
            &transaction,
            input_objects,
            receiving_objects,
            params.reference_gas_price,
        )?
    } else {
        sui_transaction_checks::check_transaction_input(
            params.protocol_config,
            params.reference_gas_price,
            &transaction,
            input_objects,
            &receiving_objects,
            &params.bytecode_verifier_metrics,
            params.verifier_signing_config,
        )?
    };

    let (mut kind, signer, gas_data) = transaction.execution_parts();
    let rewritten_inputs = rewrite_transaction_for_coin_reservations(
        params.chain_identifier,
        params.coin_reservation_resolver,
        signer,
        &mut kind,
        None,
    );
    let execution_params = match get_early_execution_error(
        &tx_digest,
        &checked_input_objects,
        params.certificate_deny_set,
        &FundsWithdrawStatus::MaybeSufficient,
    ) {
        Some(error) => ExecutionOrEarlyError::Err(error),
        None => ExecutionOrEarlyError::Ok(()),
    };

    Ok(PreparedSimulation {
        transaction,
        dev_inspect,
        tx_digest,
        execution_params,
        checked_input_objects,
        gas_status,
        gas_data,
        kind,
        rewritten_inputs,
        signer,
        address_funds,
        mock_gas_id,
    })
}

/// Runs deny list checks and processes funds withdrawals. Called before loading
/// input objects, since these checks don't depend on object state.
///
/// This is the single canonical implementation shared by both the fullnode
/// simulation path and the `AuthorityState` signing path.
pub fn pre_object_load_checks(
    tx_data: &TransactionData,
    tx_signatures: &[GenericSignature],
    input_object_kinds: &[InputObjectKind],
    receiving_object_refs: &[ObjectRef],
    transaction_deny_config: &TransactionDenyConfig,
    package_store: &dyn BackingPackageStore,
    chain_identifier: ChainIdentifier,
    coin_reservation_resolver: &dyn CoinReservationResolverTrait,
    account_funds_read: &dyn AccountFundsRead,
    protocol_config: &sui_protocol_config::ProtocolConfig,
) -> SuiResult<BTreeMap<AccumulatorObjId, (u64, TypeTag)>> {
    // Note: the deny checks may do redundant package loads but:
    // - they only load packages when there is an active package deny map
    // - the loads are cached anyway
    sui_transaction_checks::deny::check_transaction_for_signing(
        tx_data,
        tx_signatures,
        input_object_kinds,
        receiving_object_refs,
        transaction_deny_config,
        package_store,
    )?;

    let declared_withdrawals = tx_data
        .process_funds_withdrawals_for_signing(chain_identifier, coin_reservation_resolver)?;
    account_funds_read.check_amounts_available(&declared_withdrawals)?;

    if protocol_config.gasless_verify_remaining_balance() && tx_data.is_gasless_transaction() {
        let min_amounts = sui_types::transaction::get_gasless_allowed_token_types(protocol_config);
        account_funds_read
            .check_remaining_amounts_after_withdrawal(&declared_withdrawals, &min_amounts)?;
    }

    Ok(declared_withdrawals)
}

fn execute_prepared_simulation(
    params: &SimulationParams<'_>,
    prepared: PreparedSimulation,
) -> SuiResult<ExecutedSimulation> {
    let executor = sui_execution::executor(
        params.protocol_config,
        true, // silent
    )
    .expect("Creating an executor should not fail here");
    let tracking_store = TrackingBackingStore::new(params.backing_store);
    let epoch_id = params.epoch_id;
    let epoch_timestamp_ms = params.epoch_timestamp_ms;

    let PreparedSimulation {
        transaction,
        dev_inspect,
        tx_digest,
        execution_params,
        checked_input_objects,
        gas_status,
        gas_data,
        kind,
        rewritten_inputs,
        signer,
        address_funds,
        mock_gas_id,
    } = prepared;

    let (inner_temp_store, _, effects, execution_result) = executor.dev_inspect_transaction(
        &tracking_store,
        params.protocol_config,
        params.execution_metrics.clone(),
        false,
        execution_params,
        &epoch_id,
        epoch_timestamp_ms,
        checked_input_objects.clone(),
        gas_data.clone(),
        gas_status,
        kind.clone(),
        rewritten_inputs.clone(),
        signer,
        tx_digest,
        dev_inspect,
    );

    let (inner_temp_store, effects, execution_result) = if execution_result.is_ok()
        && has_insufficient_object_funds(
            params.account_funds_read,
            &inner_temp_store.accumulator_running_max_withdraws,
            &address_funds,
        ) {
        let retry_gas_status = SuiGasStatus::new(
            gas_data.budget,
            gas_data.price,
            params.reference_gas_price,
            params.protocol_config,
        )?;
        let (inner_temp_store, _, effects, execution_result) = executor.dev_inspect_transaction(
            &tracking_store,
            params.protocol_config,
            params.execution_metrics.clone(),
            false,
            ExecutionOrEarlyError::Err(ExecutionErrorKind::InsufficientFundsForWithdraw),
            &epoch_id,
            epoch_timestamp_ms,
            checked_input_objects,
            gas_data,
            retry_gas_status,
            kind,
            rewritten_inputs,
            signer,
            tx_digest,
            dev_inspect,
        );
        (inner_temp_store, effects, execution_result)
    } else {
        (inner_temp_store, effects, execution_result)
    };

    Ok(ExecutedSimulation {
        transaction,
        inner_temp_store,
        effects,
        execution_result,
        loaded_runtime_objects: tracking_store.into_read_objects(),
        mock_gas_id,
    })
}

fn has_insufficient_object_funds(
    account_funds_read: &dyn AccountFundsRead,
    max_withdraws: &BTreeMap<AccumulatorObjId, u128>,
    address_funds: &BTreeSet<AccumulatorObjId>,
) -> bool {
    max_withdraws
        .iter()
        .filter(|(id, _)| !address_funds.contains(id))
        .any(|(id, max_withdraw)| {
            account_funds_read.get_latest_account_amount(id).0 < *max_withdraw
        })
}

fn build_simulation_result(
    executed: ExecutedSimulation,
    suggested_gas_price: Option<u64>,
) -> SimulateTransactionResult {
    let ExecutedSimulation {
        transaction,
        inner_temp_store,
        effects,
        execution_result,
        loaded_runtime_objects,
        mock_gas_id,
    } = executed;
    let unchanged_loaded_runtime_objects = transaction_outputs::unchanged_loaded_runtime_objects(
        &transaction,
        &effects,
        &loaded_runtime_objects,
    );

    let InnerTemporaryStore {
        input_objects,
        written,
        events,
        ..
    } = inner_temp_store;

    let mut objects = loaded_runtime_objects;
    for object in input_objects.into_values().chain(written.into_values()) {
        objects.insert(object);
    }

    let object_keys = sui_types::storage::get_transaction_object_set(
        &transaction,
        &effects,
        &unchanged_loaded_runtime_objects,
    );
    let mut object_set = ObjectSet::default();
    for object_key in object_keys {
        if let Some(object) = objects.get(&object_key) {
            object_set.insert(object.clone());
        }
    }

    SimulateTransactionResult {
        objects: object_set,
        events: effects.events_digest().map(|_| events),
        effects,
        execution_result,
        mock_gas_id,
        unchanged_loaded_runtime_objects,
        suggested_gas_price,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sui_types::base_types::SequenceNumber;

    struct FakeAccountFundsRead {
        balances: BTreeMap<AccumulatorObjId, (u128, SequenceNumber)>,
    }

    impl AccountFundsRead for FakeAccountFundsRead {
        fn get_latest_account_amount(&self, id: &AccumulatorObjId) -> (u128, SequenceNumber) {
            self.balances
                .get(id)
                .copied()
                .unwrap_or((0, SequenceNumber::default()))
        }

        fn get_account_amount_at_version(
            &self,
            id: &AccumulatorObjId,
            _version: SequenceNumber,
        ) -> u128 {
            self.balances
                .get(id)
                .map(|(amount, _)| *amount)
                .unwrap_or(0)
        }
    }

    #[test]
    fn post_execution_object_funds_check_skips_prechecked_address_funds() {
        let address_fund = AccumulatorObjId::new_unchecked(ObjectID::from_single_byte(1));
        let object_fund = AccumulatorObjId::new_unchecked(ObjectID::from_single_byte(2));
        let funds_read = FakeAccountFundsRead {
            balances: BTreeMap::from([
                (address_fund, (5, SequenceNumber::new())),
                (object_fund, (5, SequenceNumber::new())),
            ]),
        };
        let max_withdraws = BTreeMap::from([(address_fund, 10), (object_fund, 10)]);

        assert!(has_insufficient_object_funds(
            &funds_read,
            &max_withdraws,
            &BTreeSet::from([address_fund]),
        ));
        assert!(!has_insufficient_object_funds(
            &funds_read,
            &max_withdraws,
            &BTreeSet::from([address_fund, object_fund]),
        ));
    }
}
