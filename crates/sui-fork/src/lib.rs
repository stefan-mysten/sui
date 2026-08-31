// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Start and administer a local Sui network forked from live network state.
//!
//! Programs call [`ForkNode::start`] with [`StartArgs`]. The returned node exposes in-process
//! administration and owns the services that serve the same fork over gRPC.

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
mod startup;
pub(crate) mod store;
#[cfg(test)]
#[path = "tests/support.rs"]
mod test_support;

pub use args::DEFAULT_RPC_ADDR;
pub use args::StartArgs;
pub use node::Node;
pub use proto::forking::AdvanceCheckpointRequest;
pub use proto::forking::AdvanceCheckpointResponse;
pub use proto::forking::AdvanceClockRequest;
pub use proto::forking::AdvanceClockResponse;
pub use proto::forking::GetStatusRequest;
pub use proto::forking::GetStatusResponse;
pub use proto::forking::forking_service_client::ForkingServiceClient;

use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use prometheus::Registry;
use tracing::info;

use simulacrum::SimulatorStore as _;
use sui_futures::service::Service;
use sui_types::effects::TransactionEffectsAPI as _;
use sui_types::messages_checkpoint::CheckpointSequenceNumber;
use sui_types::sui_system_state::epoch_start_sui_system_state::EpochStartSystemStateTrait as _;

use crate::context::Context;
use crate::seed::SeedInput;
use crate::startup::ForkParts;

/// A running forked Sui node with in-process administration and owned background services.
pub struct ForkNode {
    admin: ForkAdmin,
    service: Service,
    rpc_address: SocketAddr,
    network_name: String,
    data_dir: PathBuf,
    forked_at_checkpoint: CheckpointSequenceNumber,
    starting_checkpoint: CheckpointSequenceNumber,
    resumed: bool,
}

impl ForkNode {
    /// Start a forked node and return after its RPC listener has been bound.
    ///
    /// Returns an error when the listener cannot bind, the remote fork point cannot be resolved, or
    /// persisted metadata is incompatible with the requested network or checkpoint. The caller
    /// owns process signals and tracing because the node can be embedded alongside other services.
    pub async fn start(
        args: StartArgs,
        version: &'static str,
        registry: &Registry,
    ) -> Result<Self> {
        let StartArgs {
            network,
            checkpoint,
            data_dir,
            addresses,
            object_ids,
            rpc_addr,
        } = args;
        let seed_input = SeedInput {
            addresses: addresses.into_iter().collect(),
            object_ids: object_ids.into_iter().collect(),
        };

        let listener = startup::bind(rpc_addr).await?;
        let parts =
            startup::initialize(network, checkpoint, version, data_dir, seed_input, registry)
                .await?;
        Self::from_parts(parts, listener, version, registry).await
    }

    /// Serve initialized fork parts over `listener`.
    pub(crate) async fn from_parts(
        parts: ForkParts,
        listener: tokio::net::TcpListener,
        version: &'static str,
        registry: &Registry,
    ) -> Result<Self> {
        let ForkParts {
            context,
            subscription_handle,
            indexer_service,
            data_dir,
            network_name,
            forked_at_checkpoint,
            starting_checkpoint,
            resumed,
        } = parts;
        let context = Arc::new(context);
        let admin = ForkAdmin::new(context.clone());
        let (rpc_address, server) =
            startup::serve(context, subscription_handle, listener, version, registry).await?;

        Ok(Self {
            admin,
            service: server.merge(indexer_service),
            rpc_address,
            network_name,
            data_dir,
            forked_at_checkpoint,
            starting_checkpoint,
            resumed,
        })
    }

    /// Return the address of the fork's bound RPC listener.
    pub fn rpc_address(&self) -> SocketAddr {
        self.rpc_address
    }

    /// Return the name of the live network from which the fork was created.
    pub fn network_name(&self) -> &str {
        &self.network_name
    }

    /// Return the directory that holds the fork's persistent state.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Return the live-network checkpoint at which the fork was created.
    pub fn forked_at_checkpoint(&self) -> CheckpointSequenceNumber {
        self.forked_at_checkpoint
    }

    /// Return the local checkpoint from which this run started.
    pub fn starting_checkpoint(&self) -> CheckpointSequenceNumber {
        self.starting_checkpoint
    }

    /// Return whether this run resumed previously persisted fork state.
    pub fn resumed(&self) -> bool {
        self.resumed
    }

    /// Advance the fork's clock and return the same response exposed over gRPC.
    pub async fn advance_clock(&self, duration: Duration) -> Result<AdvanceClockResponse> {
        Ok(self.admin.advance_clock(duration).await)
    }

    /// Create a checkpoint and return the same response exposed over gRPC.
    pub async fn advance_checkpoint(&self) -> Result<AdvanceCheckpointResponse> {
        Ok(self.admin.advance_checkpoint().await)
    }

    /// Report the same fork status exposed over gRPC.
    pub async fn status(&self) -> Result<GetStatusResponse> {
        Ok(self.admin.status().await)
    }

    /// Wait until the RPC server or embedded indexer exits.
    ///
    /// Returns the first task failure and resumes unwinding when a managed task panics.
    pub async fn join(&mut self) -> Result<()> {
        self.service.join().await
    }

    /// Shut down the RPC server and embedded indexer gracefully.
    pub async fn shutdown(self) -> Result<()> {
        self.service.shutdown().await.map_err(Into::into)
    }

    /// Convert the running fork into a [`Service`] for composition with other services.
    ///
    /// Consuming the node removes access to its in-process administration methods. The containing
    /// service owns shutdown, while the fork remains controllable through gRPC at
    /// [`Self::rpc_address`].
    pub fn into_service(self) -> Service {
        self.service
    }
}

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
