// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use prometheus::{
    register_histogram_vec_with_registry, register_histogram_with_registry,
    register_int_counter_vec_with_registry, register_int_counter_with_registry, Histogram,
    HistogramVec, IntCounter, IntCounterVec, Registry,
};

const FINALITY_LATENCY_SEC_BUCKETS: &[f64] = &[
    0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85,
    0.9, 0.95, 1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6,
    2.7, 2.8, 2.9, 3.0, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 4.0, 4.5, 5.0, 5.5, 6.0, 6.5,
    7.0, 7.5, 8.0, 8.5, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0, 16.0, 17.0, 18.0, 19.0, 20.0,
    25.0,
];

const SUBMIT_TRANSACTION_RETRIES_BUCKETS: &[f64] = &[
    0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 15.0, 20.0, 30.0,
];

// TODO(mysticeti-fastpath): For validator names, use display name instead of concise name.
#[derive(Clone)]
pub struct TransactionDriverMetrics {
    pub(crate) settlement_finality_latency: HistogramVec,
    pub(crate) total_transactions_submitted: IntCounter,
    pub(crate) submit_transaction_retries: Histogram,
    pub(crate) submit_transaction_latency: Histogram,
    pub(crate) validator_submit_transaction_errors: IntCounterVec,
    pub(crate) validator_submit_transaction_successes: IntCounterVec,
    pub(crate) executed_transactions: IntCounter,
    pub(crate) rejection_acks: IntCounter,
    pub(crate) expiration_acks: IntCounter,
    pub(crate) effects_digest_mismatches: IntCounter,
    pub(crate) transaction_retries: HistogramVec,
    pub(crate) certified_effects_ack_latency: Histogram,
    pub(crate) certified_effects_ack_attempts: IntCounter,
    pub(crate) certified_effects_ack_successes: IntCounter,
}

impl TransactionDriverMetrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            settlement_finality_latency: register_histogram_vec_with_registry!(
                "transaction_driver_settlement_finality_latency",
                "Settlement finality latency observed from transaction driver",
                &["tx_type"],
                FINALITY_LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            total_transactions_submitted: register_int_counter_with_registry!(
                "transaction_driver_total_transactions_submitted",
                "Total number of transactions submitted through the transaction driver",
                registry,
            )
            .unwrap(),
            submit_transaction_retries: register_histogram_with_registry!(
                "transaction_driver_submit_transaction_retries",
                "Number of retries needed for successful transaction submission",
                SUBMIT_TRANSACTION_RETRIES_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            submit_transaction_latency: register_histogram_with_registry!(
                "transaction_driver_submit_transaction_latency",
                "Time in seconds to successfully submit a transaction to a validator.\n\
                Includes all retries and measures from the start of submission\n\
                until a validator accepts the transaction.",
                FINALITY_LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            validator_submit_transaction_errors: register_int_counter_vec_with_registry!(
                "transaction_driver_validator_submit_transaction_errors",
                "Number of submit transaction errors by validator",
                &["validator", "error_type"],
                registry,
            )
            .unwrap(),
            validator_submit_transaction_successes: register_int_counter_vec_with_registry!(
                "transaction_driver_validator_submit_transaction_successes",
                "Number of successful submit transactions by validator",
                &["validator"],
                registry,
            )
            .unwrap(),
            executed_transactions: register_int_counter_with_registry!(
                "transaction_driver_executed_transactions",
                "Number of transactions executed observed by the transaction driver",
                registry,
            )
            .unwrap(),
            rejection_acks: register_int_counter_with_registry!(
                "transaction_driver_rejected_acks",
                "Number of rejection acknowledgments observed by the transaction driver",
                registry,
            )
            .unwrap(),
            expiration_acks: register_int_counter_with_registry!(
                "transaction_driver_expiration_acks",
                "Number of expiration acknowledgments observed by the transaction driver",
                registry,
            )
            .unwrap(),
            effects_digest_mismatches: register_int_counter_with_registry!(
                "transaction_driver_effects_digest_mismatches",
                "Number of effects digest mismatches detected by the transaction driver",
                registry,
            )
            .unwrap(),
            transaction_retries: register_histogram_vec_with_registry!(
                "transaction_driver_transaction_retries",
                "Number of retries per transaction attempt in drive_transaction",
                &["result"],
                SUBMIT_TRANSACTION_RETRIES_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            certified_effects_ack_latency: register_histogram_with_registry!(
                "transaction_driver_certified_effects_ack_latency",
                "Latency in seconds for getting certified effects acknowledgment",
                FINALITY_LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            certified_effects_ack_attempts: register_int_counter_with_registry!(
                "transaction_driver_certified_effects_ack_attempts",
                "Total number of transactions that went through certified effects ack process",
                registry,
            )
            .unwrap(),
            certified_effects_ack_successes: register_int_counter_with_registry!(
                "transaction_driver_certified_effects_ack_successes",
                "Number of successful certified effects acknowledgments",
                registry,
            )
            .unwrap(),
        }
    }

    pub fn new_for_tests() -> Self {
        let registry = Registry::new();
        Self::new(&registry)
    }
}
