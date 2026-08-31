// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Building blocks for the experimental `sui-fork` tool.

pub mod args;
pub mod cli;
pub(crate) mod context;
mod gql;
pub(crate) mod ingestion;
pub(crate) mod local_store;
pub(crate) mod metadata;
mod node;
pub(crate) mod pending;
mod proto;
pub(crate) mod remote;
mod rpc;
pub(crate) mod seed;
pub(crate) mod services;
pub mod startup;
pub mod store;
#[cfg(test)]
#[path = "tests/support.rs"]
mod test_support;

pub use args::DEFAULT_RPC_ADDR;
pub use args::StartArgs;
pub use node::Node;
pub use proto::forking::AdvanceCheckpointRequest;
pub use proto::forking::AdvanceClockRequest;
pub use proto::forking::GetStatusRequest;
pub use proto::forking::forking_service_client::ForkingServiceClient;
pub use seed::SeedInput;
pub use store::ForkStore;

use std::sync::Arc;
use std::time::Duration;

use tracing::info;

use simulacrum::SimulatorStore as _;
use sui_types::effects::TransactionEffectsAPI as _;
use sui_types::sui_system_state::epoch_start_sui_system_state::EpochStartSystemStateTrait as _;

use crate::context::Context;
use crate::proto::forking::AdvanceCheckpointResponse;
use crate::proto::forking::AdvanceClockResponse;
use crate::proto::forking::GetStatusResponse;

/// Administer the execution state of a running forked network.
pub(crate) struct ForkAdmin {
    context: Arc<Context>,
}

impl ForkAdmin {
    pub(crate) fn new(context: Arc<Context>) -> Self {
        Self { context }
    }

    /// Advance the fork's clock and seal the clock transaction into a new checkpoint.
    pub(crate) async fn advance_clock(&self, duration: Duration) -> AdvanceClockResponse {
        let ((tx_digest, timestamp_ms), checkpoint_metadata) = self
            .context
            .run_with_new_checkpoint(|sim| {
                let effects = sim.advance_clock(duration);
                let tx_digest = *effects.transaction_digest();
                let timestamp_ms = sim.store().get_clock().timestamp_ms;
                (tx_digest, timestamp_ms)
            })
            .await;

        info!(
            %tx_digest,
            duration_ms = duration.as_millis(),
            timestamp_ms,
            checkpoint_sequence_number = checkpoint_metadata.sequence_number,
            "clock advanced"
        );

        AdvanceClockResponse {
            timestamp_ms,
            tx_digest: tx_digest.to_string(),
        }
    }

    /// Create and publish a new checkpoint without executing another transaction.
    pub(crate) async fn advance_checkpoint(&self) -> AdvanceCheckpointResponse {
        let (_, checkpoint_metadata) = self.context.run_with_new_checkpoint(|_| ()).await;

        info!(
            checkpoint_sequence_number = checkpoint_metadata.sequence_number,
            timestamp_ms = checkpoint_metadata.timestamp_ms,
            "checkpoint created"
        );

        AdvanceCheckpointResponse {
            checkpoint_sequence_number: checkpoint_metadata.sequence_number,
            timestamp_ms: checkpoint_metadata.timestamp_ms,
        }
    }

    /// Report the fork's current epoch, checkpoint, clock, and original fork point.
    pub(crate) async fn status(&self) -> GetStatusResponse {
        let sim = self.context.simulacrum().read().await;
        let epoch = sim.epoch_start_state().epoch();
        let timestamp_ms = sim.store().get_clock().timestamp_ms;
        let checkpoint_sequence_number = sim
            .store()
            .get_highest_checkpint()
            .map(|checkpoint| checkpoint.data().sequence_number)
            .unwrap_or(0);
        let forked_at_checkpoint = sim.store().forked_at_checkpoint();

        GetStatusResponse {
            epoch,
            checkpoint_sequence_number,
            timestamp_ms,
            forked_at_checkpoint,
        }
    }
}
