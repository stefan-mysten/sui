// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Simulator-facing store adapter for `sui-forking`.
//!
//! This layer intentionally stays thin: it translates the `simulacrum` storage traits into a
//! smaller historical-read interface, so cache/source composition stays outside the simulator.

use std::collections::BTreeMap;

use simulacrum::SimulatorStore;
use sui_types::SUI_CLOCK_OBJECT_ID;
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
use sui_types::storage::load_package_object_from_object_store;
use sui_types::sui_system_state::SuiSystemState;
use sui_types::sui_system_state::get_sui_system_state;
use sui_types::transaction::VerifiedTransaction;

use crate::source::ForkSource;

/// `simulacrum` store adapter over a historical fork source.
pub struct DataStore<S> {
    source: S,
}

impl<S> DataStore<S> {
    /// Create a new simulator data store from a historical source.
    pub fn new(source: S) -> Self {
        Self { source }
    }

    /// Return the wrapped historical source.
    pub fn source(&self) -> &S {
        &self.source
    }

    /// Return a mutable reference to the wrapped historical source.
    pub fn source_mut(&mut self) -> &mut S {
        &mut self.source
    }
}

impl<S> DataStore<S>
where
    S: ForkSource,
{
    /// Return the checkpoint this store forked from.
    pub fn forked_at_checkpoint(&self) -> CheckpointSequenceNumber {
        self.source.forked_at_checkpoint()
    }
}

impl<S> BackingPackageStore for DataStore<S>
where
    S: ForkSource,
{
    fn get_package_object(&self, package_id: &ObjectID) -> SuiResult<Option<PackageObject>> {
        load_package_object_from_object_store(self, package_id)
    }
}

impl<S> ObjectStore for DataStore<S>
where
    S: ForkSource,
{
    fn get_object(&self, object_id: &ObjectID) -> Option<Object> {
        self.source.get_object(object_id)
    }

    fn get_object_by_key(&self, object_id: &ObjectID, version: VersionNumber) -> Option<Object> {
        self.source.get_object_at_version(object_id, version)
    }
}

impl<S> ParentSync for DataStore<S> {
    fn get_latest_parent_entry_ref_deprecated(&self, _object_id: ObjectID) -> Option<ObjectRef> {
        None
    }
}

impl<S> ChildObjectResolver for DataStore<S>
where
    S: ForkSource,
{
    fn read_child_object(
        &self,
        parent: &ObjectID,
        child: &ObjectID,
        child_version_upper_bound: SequenceNumber,
    ) -> SuiResult<Option<Object>> {
        self.source
            .read_child_object(parent, child, child_version_upper_bound)
    }

    fn get_object_received_at_version(
        &self,
        owner: &ObjectID,
        receiving_object_id: &ObjectID,
        receive_object_at_version: SequenceNumber,
        epoch_id: EpochId,
    ) -> SuiResult<Option<Object>> {
        self.source.get_object_received_at_version(
            owner,
            receiving_object_id,
            receive_object_at_version,
            epoch_id,
        )
    }
}

impl<S> SimulatorStore for DataStore<S>
where
    S: ForkSource,
{
    fn get_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Option<VerifiedCheckpoint> {
        self.source
            .get_checkpoint_by_sequence_number(sequence_number)
    }

    fn get_checkpoint_by_digest(&self, _digest: &CheckpointDigest) -> Option<VerifiedCheckpoint> {
        todo!("simulator checkpoint-digest reads are not implemented yet")
    }

    fn get_highest_checkpint(&self) -> Option<VerifiedCheckpoint> {
        self.source.get_latest_checkpoint()
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

    fn get_object(&self, id: &ObjectID) -> Option<Object> {
        ObjectStore::get_object(self, id)
    }

    fn get_object_at_version(&self, id: &ObjectID, version: SequenceNumber) -> Option<Object> {
        ObjectStore::get_object_by_key(self, id, version)
    }

    fn get_system_state(&self) -> SuiSystemState {
        get_sui_system_state(self).expect("system state should exist")
    }

    fn get_clock(&self) -> Clock {
        ObjectStore::get_object(self, &SUI_CLOCK_OBJECT_ID)
            .expect("clock should exist")
            .to_rust()
            .expect("clock object should deserialize")
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
        self
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use sui_types::base_types::ObjectID;
    use sui_types::base_types::SuiAddress;
    use sui_types::object::Object;
    use sui_types::object::Owner;

    use super::*;
    use crate::test_utils::verified_checkpoint;

    #[derive(Default)]
    struct MockForkSource {
        forked_at_checkpoint: CheckpointSequenceNumber,
        object_calls: Mutex<Vec<ObjectID>>,
        objects: BTreeMap<ObjectID, Option<Object>>,
        versioned_object_calls: Mutex<Vec<(ObjectID, VersionNumber)>>,
        versioned_objects: BTreeMap<(ObjectID, VersionNumber), Option<Object>>,
        child_object_calls: Mutex<Vec<(ObjectID, ObjectID, SequenceNumber)>>,
        child_objects: BTreeMap<(ObjectID, ObjectID, SequenceNumber), SuiResult<Option<Object>>>,
        received_object_calls: Mutex<Vec<(ObjectID, ObjectID, SequenceNumber, EpochId)>>,
        received_objects:
            BTreeMap<(ObjectID, ObjectID, SequenceNumber, EpochId), SuiResult<Option<Object>>>,
        checkpoint_calls: Mutex<Vec<CheckpointSequenceNumber>>,
        checkpoints: BTreeMap<CheckpointSequenceNumber, VerifiedCheckpoint>,
        latest_checkpoint_calls: Mutex<u64>,
        latest_checkpoint: Option<VerifiedCheckpoint>,
    }

    impl MockForkSource {
        fn latest_checkpoint_calls(&self) -> u64 {
            *self
                .latest_checkpoint_calls
                .lock()
                .expect("latest-checkpoint-call mutex should not be poisoned")
        }
    }

    impl ForkSource for MockForkSource {
        fn forked_at_checkpoint(&self) -> CheckpointSequenceNumber {
            self.forked_at_checkpoint
        }

        fn get_object(&self, object_id: &ObjectID) -> Option<Object> {
            self.object_calls
                .lock()
                .expect("object-call mutex should not be poisoned")
                .push(*object_id);
            self.objects.get(object_id).cloned().unwrap_or(None)
        }

        fn get_object_at_version(
            &self,
            object_id: &ObjectID,
            version: VersionNumber,
        ) -> Option<Object> {
            self.versioned_object_calls
                .lock()
                .expect("versioned-object-call mutex should not be poisoned")
                .push((*object_id, version));
            self.versioned_objects
                .get(&(*object_id, version))
                .cloned()
                .unwrap_or(None)
        }

        fn read_child_object(
            &self,
            parent: &ObjectID,
            child: &ObjectID,
            child_version_upper_bound: SequenceNumber,
        ) -> SuiResult<Option<Object>> {
            self.child_object_calls
                .lock()
                .expect("child-object-call mutex should not be poisoned")
                .push((*parent, *child, child_version_upper_bound));
            self.child_objects
                .get(&(*parent, *child, child_version_upper_bound))
                .cloned()
                .unwrap_or(Ok(None))
        }

        fn get_object_received_at_version(
            &self,
            owner: &ObjectID,
            receiving_object_id: &ObjectID,
            receive_object_at_version: SequenceNumber,
            epoch_id: EpochId,
        ) -> SuiResult<Option<Object>> {
            self.received_object_calls
                .lock()
                .expect("received-object-call mutex should not be poisoned")
                .push((
                    *owner,
                    *receiving_object_id,
                    receive_object_at_version,
                    epoch_id,
                ));
            self.received_objects
                .get(&(
                    *owner,
                    *receiving_object_id,
                    receive_object_at_version,
                    epoch_id,
                ))
                .cloned()
                .unwrap_or(Ok(None))
        }

        fn get_checkpoint_by_sequence_number(
            &self,
            sequence_number: CheckpointSequenceNumber,
        ) -> Option<VerifiedCheckpoint> {
            self.checkpoint_calls
                .lock()
                .expect("checkpoint-call mutex should not be poisoned")
                .push(sequence_number);
            self.checkpoints.get(&sequence_number).cloned()
        }

        fn get_latest_checkpoint(&self) -> Option<VerifiedCheckpoint> {
            *self
                .latest_checkpoint_calls
                .lock()
                .expect("latest-checkpoint-call mutex should not be poisoned") += 1;
            self.latest_checkpoint.clone()
        }
    }

    #[test]
    fn store_exposes_forked_checkpoint_from_source() {
        let store = DataStore::new(MockForkSource {
            forked_at_checkpoint: 42,
            ..Default::default()
        });

        assert_eq!(store.forked_at_checkpoint(), 42);
    }

    #[test]
    fn get_object_delegates_to_source() {
        let object = Object::immutable_with_id_for_testing(ObjectID::random());
        let store = DataStore::new(MockForkSource {
            objects: BTreeMap::from([(object.id(), Some(object.clone()))]),
            ..Default::default()
        });

        let fetched = ObjectStore::get_object(&store, &object.id());

        assert_eq!(fetched, Some(object.clone()));
        assert_eq!(
            store
                .source()
                .object_calls
                .lock()
                .expect("object-call mutex should not be poisoned")
                .clone(),
            vec![object.id()]
        );
    }

    #[test]
    fn get_object_by_key_delegates_to_source() {
        let version = SequenceNumber::from_u64(7);
        let owner = SuiAddress::random_for_testing_only();
        let object = Object::with_id_owner_version_for_testing(
            ObjectID::random(),
            version,
            Owner::AddressOwner(owner),
        );
        let store = DataStore::new(MockForkSource {
            versioned_objects: BTreeMap::from([((object.id(), version), Some(object.clone()))]),
            ..Default::default()
        });

        let fetched = ObjectStore::get_object_by_key(&store, &object.id(), version);

        assert_eq!(fetched, Some(object.clone()));
        assert_eq!(
            store
                .source()
                .versioned_object_calls
                .lock()
                .expect("versioned-object-call mutex should not be poisoned")
                .clone(),
            vec![(object.id(), version)]
        );
    }

    #[test]
    fn read_child_object_delegates_to_source() {
        let parent = ObjectID::random();
        let child_version = SequenceNumber::from_u64(9);
        let child = Object::with_id_owner_version_for_testing(
            ObjectID::random(),
            child_version,
            Owner::ObjectOwner(parent.into()),
        );
        let store = DataStore::new(MockForkSource {
            child_objects: BTreeMap::from([(
                (parent, child.id(), child_version),
                Ok(Some(child.clone())),
            )]),
            ..Default::default()
        });

        let fetched = store
            .read_child_object(&parent, &child.id(), child_version)
            .expect("child lookup should succeed");

        assert_eq!(fetched, Some(child.clone()));
        assert_eq!(
            store
                .source()
                .child_object_calls
                .lock()
                .expect("child-object-call mutex should not be poisoned")
                .clone(),
            vec![(parent, child.id(), child_version)]
        );
    }

    #[test]
    fn checkpoint_reads_delegate_to_source() {
        let checkpoint = verified_checkpoint(11);
        let store = DataStore::new(MockForkSource {
            checkpoints: BTreeMap::from([(11, checkpoint.clone())]),
            latest_checkpoint: Some(verified_checkpoint(17)),
            ..Default::default()
        });

        let by_sequence = SimulatorStore::get_checkpoint_by_sequence_number(&store, 11);
        let latest = SimulatorStore::get_highest_checkpint(&store);

        assert_eq!(
            by_sequence
                .as_ref()
                .map(|checkpoint| *checkpoint.sequence_number()),
            Some(11)
        );
        assert_eq!(
            latest
                .as_ref()
                .map(|checkpoint| *checkpoint.sequence_number()),
            Some(17)
        );
        assert_eq!(
            store
                .source()
                .checkpoint_calls
                .lock()
                .expect("checkpoint-call mutex should not be poisoned")
                .clone(),
            vec![11]
        );
        assert_eq!(store.source().latest_checkpoint_calls(), 1);
    }
}
