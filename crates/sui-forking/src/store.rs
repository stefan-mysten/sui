// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Simulator-facing store adapter for `sui-forking`.
//!
//! This wraps the lower-level forking data store and provides the trait surface required by
//! `simulacrum`. The concrete read and write paths are added incrementally in later slices.

use std::collections::BTreeMap;

use forking_data_store::stores::ForkingStore;
use simulacrum::SimulatorStore;
use sui_types::base_types::ObjectID;
use sui_types::base_types::ObjectRef;
use sui_types::base_types::SequenceNumber;
use sui_types::base_types::SuiAddress;
use sui_types::base_types::VersionNumber;
use sui_types::clock::Clock;
use sui_types::committee::Committee;
use sui_types::committee::EpochId;
use sui_types::digests::CheckpointContentsDigest;
use sui_types::digests::CheckpointDigest;
use sui_types::digests::ObjectDigest;
use sui_types::digests::TransactionDigest;
use sui_types::effects::TransactionEffects;
use sui_types::effects::TransactionEvents;
use sui_types::error::SuiResult;
use sui_types::messages_checkpoint::CheckpointContents;
use sui_types::messages_checkpoint::CheckpointSequenceNumber;
use sui_types::messages_checkpoint::VerifiedCheckpoint;
use sui_types::object::Object;
use sui_types::storage::BackingPackageStore;
use sui_types::storage::BackingStore;
use sui_types::storage::ChildObjectResolver;
use sui_types::storage::ObjectStore;
use sui_types::storage::PackageObject;
use sui_types::storage::ParentSync;
use sui_types::sui_system_state::SuiSystemState;
use sui_types::transaction::VerifiedTransaction;

/// `simulacrum` store adapter over the lower-level forking data store.
pub struct DataStore<P, S> {
    forked_at_checkpoint: CheckpointSequenceNumber,
    store: ForkingStore<P, S>,
}

impl<P, S> DataStore<P, S> {
    /// Create a new simulator data store from an already-composed lower-level forking store.
    pub fn new(forked_at_checkpoint: CheckpointSequenceNumber, store: ForkingStore<P, S>) -> Self {
        Self {
            forked_at_checkpoint,
            store,
        }
    }

    /// Create a new simulator data store from primary and secondary store layers.
    pub fn from_layers(
        forked_at_checkpoint: CheckpointSequenceNumber,
        primary: P,
        secondary: S,
    ) -> Self {
        Self::new(forked_at_checkpoint, ForkingStore::new(primary, secondary))
    }

    /// Return the checkpoint this store forked from.
    pub fn forked_at_checkpoint(&self) -> CheckpointSequenceNumber {
        self.forked_at_checkpoint
    }

    /// Return the wrapped lower-level forking store.
    pub fn store(&self) -> &ForkingStore<P, S> {
        &self.store
    }

    /// Return a mutable reference to the wrapped lower-level forking store.
    pub fn store_mut(&mut self) -> &mut ForkingStore<P, S> {
        &mut self.store
    }
}

impl<P, S> BackingPackageStore for DataStore<P, S> {
    fn get_package_object(&self, _package_id: &ObjectID) -> SuiResult<Option<PackageObject>> {
        todo!("simulator package reads are not implemented yet")
    }
}

impl<P, S> ObjectStore for DataStore<P, S> {
    fn get_object(&self, _object_id: &ObjectID) -> Option<Object> {
        todo!("simulator object reads are not implemented yet")
    }

    fn get_object_by_key(&self, _object_id: &ObjectID, _version: VersionNumber) -> Option<Object> {
        todo!("simulator versioned object reads are not implemented yet")
    }
}

impl<P, S> ParentSync for DataStore<P, S> {
    fn get_latest_parent_entry_ref_deprecated(&self, _object_id: ObjectID) -> Option<ObjectRef> {
        todo!("simulator parent-sync reads are not implemented yet")
    }
}

impl<P, S> ChildObjectResolver for DataStore<P, S> {
    fn read_child_object(
        &self,
        _parent: &ObjectID,
        _child: &ObjectID,
        _child_version_upper_bound: SequenceNumber,
    ) -> SuiResult<Option<Object>> {
        todo!("simulator child-object reads are not implemented yet")
    }

    fn get_object_received_at_version(
        &self,
        _owner: &ObjectID,
        _receiving_object_id: &ObjectID,
        _receive_object_at_version: SequenceNumber,
        _epoch_id: EpochId,
    ) -> SuiResult<Option<Object>> {
        todo!("simulator received-object reads are not implemented yet")
    }
}

impl<P, S> SimulatorStore for DataStore<P, S> {
    fn get_checkpoint_by_sequence_number(
        &self,
        _sequence_number: CheckpointSequenceNumber,
    ) -> Option<VerifiedCheckpoint> {
        todo!("simulator checkpoint reads are not implemented yet")
    }

    fn get_checkpoint_by_digest(&self, _digest: &CheckpointDigest) -> Option<VerifiedCheckpoint> {
        todo!("simulator checkpoint-digest reads are not implemented yet")
    }

    fn get_highest_checkpint(&self) -> Option<VerifiedCheckpoint> {
        todo!("simulator latest-checkpoint reads are not implemented yet")
    }

    fn get_checkpoint_contents(
        &self,
        _digest: &CheckpointContentsDigest,
    ) -> Option<CheckpointContents> {
        todo!("simulator checkpoint-contents reads are not implemented yet")
    }

    fn get_committee_by_epoch(&self, _epoch: EpochId) -> Option<Committee> {
        todo!("simulator committee reads are not implemented yet")
    }

    fn get_transaction(&self, _digest: &TransactionDigest) -> Option<VerifiedTransaction> {
        todo!("simulator transaction reads are not implemented yet")
    }

    fn get_transaction_effects(&self, _digest: &TransactionDigest) -> Option<TransactionEffects> {
        todo!("simulator transaction-effects reads are not implemented yet")
    }

    fn get_transaction_events(&self, _digest: &TransactionDigest) -> Option<TransactionEvents> {
        todo!("simulator transaction-event reads are not implemented yet")
    }

    fn get_object(&self, _id: &ObjectID) -> Option<Object> {
        todo!("simulator object reads are not implemented yet")
    }

    fn get_object_at_version(&self, _id: &ObjectID, _version: SequenceNumber) -> Option<Object> {
        todo!("simulator versioned object reads are not implemented yet")
    }

    fn get_system_state(&self) -> SuiSystemState {
        todo!("simulator system-state reads are not implemented yet")
    }

    fn get_clock(&self) -> Clock {
        todo!("simulator clock reads are not implemented yet")
    }

    fn owned_objects(&self, _owner: SuiAddress) -> Box<dyn Iterator<Item = Object> + '_> {
        todo!("simulator owned-object scans are not implemented yet")
    }

    fn insert_checkpoint(&mut self, _checkpoint: VerifiedCheckpoint) {
        todo!("simulator checkpoint writes are not implemented yet")
    }

    fn insert_checkpoint_contents(&mut self, _contents: CheckpointContents) {
        todo!("simulator checkpoint-contents writes are not implemented yet")
    }

    fn insert_committee(&mut self, _committee: Committee) {
        todo!("simulator committee writes are not implemented yet")
    }

    fn insert_executed_transaction(
        &mut self,
        _transaction: VerifiedTransaction,
        _effects: TransactionEffects,
        _events: TransactionEvents,
        _written_objects: BTreeMap<ObjectID, Object>,
    ) {
        todo!("simulator executed-transaction writes are not implemented yet")
    }

    fn insert_transaction(&mut self, _transaction: VerifiedTransaction) {
        todo!("simulator transaction writes are not implemented yet")
    }

    fn insert_transaction_effects(&mut self, _effects: TransactionEffects) {
        todo!("simulator transaction-effects writes are not implemented yet")
    }

    fn insert_events(&mut self, _tx_digest: &TransactionDigest, _events: TransactionEvents) {
        todo!("simulator transaction-event writes are not implemented yet")
    }

    fn update_objects(
        &mut self,
        _written_objects: BTreeMap<ObjectID, Object>,
        _deleted_objects: Vec<(ObjectID, SequenceNumber, ObjectDigest)>,
    ) {
        todo!("simulator object writes are not implemented yet")
    }

    fn backing_store(&self) -> &dyn BackingStore {
        todo!("simulator backing-store access is not implemented yet")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_store_retains_checkpoint_and_wrapped_store() {
        let data_store = DataStore::from_layers(42, (), ());

        assert_eq!(data_store.forked_at_checkpoint(), 42);
        let _ = data_store.store();
    }
}
