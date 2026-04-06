// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Historical fork-source abstractions.
//!
//! This layer owns fork-checkpoint-aware read semantics and the composition of local/cache stores
//! with remote backing sources. The simulator-facing store delegates all historical reads here.

use forking_data_store::VersionQuery;
use forking_data_store::stores::ForkingStore;
use sui_types::base_types::ObjectID;
use sui_types::base_types::SequenceNumber;
use sui_types::base_types::VersionNumber;
use sui_types::committee::EpochId;
use sui_types::error::SuiErrorKind;
use sui_types::error::SuiResult;
use sui_types::messages_checkpoint::CheckpointSequenceNumber;
use sui_types::messages_checkpoint::VerifiedCheckpoint;
use sui_types::object::Object;
use sui_types::object::Owner;

/// Historical read interface used by the simulator-facing store.
pub trait ForkSource {
    /// Return the checkpoint this source is anchored to.
    fn forked_at_checkpoint(&self) -> CheckpointSequenceNumber;

    /// Return the current object view for the given object ID.
    fn get_object(&self, object_id: &ObjectID) -> Option<Object>;

    /// Return the object at an exact version.
    fn get_object_at_version(&self, object_id: &ObjectID, version: VersionNumber)
    -> Option<Object>;

    /// Resolve a child object under a parent with an upper version bound.
    fn read_child_object(
        &self,
        parent: &ObjectID,
        child: &ObjectID,
        child_version_upper_bound: SequenceNumber,
    ) -> SuiResult<Option<Object>>;

    /// Resolve an address-owned receiving object at an exact version.
    fn get_object_received_at_version(
        &self,
        owner: &ObjectID,
        receiving_object_id: &ObjectID,
        receive_object_at_version: SequenceNumber,
        epoch_id: EpochId,
    ) -> SuiResult<Option<Object>>;

    /// Return a checkpoint summary by sequence number.
    fn get_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Option<VerifiedCheckpoint>;

    /// Return the latest available checkpoint summary.
    fn get_latest_checkpoint(&self) -> Option<VerifiedCheckpoint>;
}

/// Historical source backed by the lower-level `forking-data-store` composition.
pub struct ForkingDataSource<P, S> {
    forked_at_checkpoint: CheckpointSequenceNumber,
    store: ForkingStore<P, S>,
}

impl<P, S> ForkingDataSource<P, S> {
    /// Create a new historical source from an already-composed lower-level store.
    pub fn new(forked_at_checkpoint: CheckpointSequenceNumber, store: ForkingStore<P, S>) -> Self {
        Self {
            forked_at_checkpoint,
            store,
        }
    }

    /// Create a new historical source from primary and secondary stores.
    pub fn from_stores(
        forked_at_checkpoint: CheckpointSequenceNumber,
        primary: P,
        secondary: S,
    ) -> Self {
        Self::new(forked_at_checkpoint, ForkingStore::new(primary, secondary))
    }

    /// Return the wrapped lower-level store.
    pub fn store(&self) -> &ForkingStore<P, S> {
        &self.store
    }

    /// Return a mutable reference to the wrapped lower-level store.
    pub fn store_mut(&mut self) -> &mut ForkingStore<P, S> {
        &mut self.store
    }
}

impl<P, S> ForkingDataSource<P, S>
where
    P: forking_data_store::ObjectStoreWriter,
    S: forking_data_store::ObjectStore,
{
    fn read_object(&self, key: forking_data_store::ObjectKey) -> Option<Object> {
        forking_data_store::ObjectStore::get_objects(&self.store, &[key])
            .ok()
            .and_then(|mut objects| objects.pop())
            .flatten()
            .map(|(object, _actual_version)| object)
    }
}

impl<P, S> ForkingDataSource<P, S>
where
    P: forking_data_store::CheckpointStoreWriter,
    S: forking_data_store::CheckpointStore,
{
    fn read_checkpoint(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Option<VerifiedCheckpoint> {
        forking_data_store::CheckpointStore::get_checkpoint_by_sequence_number(
            &self.store,
            sequence_number,
        )
        .ok()
        .flatten()
    }

    fn read_latest_checkpoint(&self) -> Option<VerifiedCheckpoint> {
        forking_data_store::CheckpointStore::get_latest_checkpoint(self.store.primary())
            .ok()
            .flatten()
            .or_else(|| {
                forking_data_store::CheckpointStore::get_latest_checkpoint(self.store.secondary())
                    .ok()
                    .flatten()
            })
    }
}

impl<P, S> ForkSource for ForkingDataSource<P, S>
where
    P: forking_data_store::CheckpointStoreWriter + forking_data_store::ObjectStoreWriter,
    S: forking_data_store::CheckpointStore + forking_data_store::ObjectStore,
{
    fn forked_at_checkpoint(&self) -> CheckpointSequenceNumber {
        self.forked_at_checkpoint
    }

    fn get_object(&self, object_id: &ObjectID) -> Option<Object> {
        self.read_object(forking_data_store::ObjectKey {
            object_id: *object_id,
            version_query: VersionQuery::Latest,
        })
    }

    fn get_object_at_version(
        &self,
        object_id: &ObjectID,
        version: VersionNumber,
    ) -> Option<Object> {
        self.read_object(forking_data_store::ObjectKey {
            object_id: *object_id,
            version_query: VersionQuery::Version(version.value()),
        })
    }

    fn read_child_object(
        &self,
        parent: &ObjectID,
        child: &ObjectID,
        child_version_upper_bound: SequenceNumber,
    ) -> SuiResult<Option<Object>> {
        let Some(child_object) = self.read_object(forking_data_store::ObjectKey {
            object_id: *child,
            version_query: VersionQuery::RootVersion(child_version_upper_bound.value()),
        }) else {
            return Ok(None);
        };

        if child_object.owner != Owner::ObjectOwner((*parent).into()) {
            return Err(SuiErrorKind::InvalidChildObjectAccess {
                object: *child,
                given_parent: *parent,
                actual_owner: child_object.owner.clone(),
            }
            .into());
        }

        Ok(Some(child_object))
    }

    fn get_object_received_at_version(
        &self,
        owner: &ObjectID,
        receiving_object_id: &ObjectID,
        receive_object_at_version: SequenceNumber,
        _epoch_id: EpochId,
    ) -> SuiResult<Option<Object>> {
        let Some(receiving_object) = self.read_object(forking_data_store::ObjectKey {
            object_id: *receiving_object_id,
            version_query: VersionQuery::Version(receive_object_at_version.value()),
        }) else {
            return Ok(None);
        };

        if receiving_object.owner != Owner::AddressOwner((*owner).into()) {
            return Ok(None);
        }

        Ok(Some(receiving_object))
    }

    fn get_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Option<VerifiedCheckpoint> {
        self.read_checkpoint(sequence_number)
    }

    fn get_latest_checkpoint(&self) -> Option<VerifiedCheckpoint> {
        self.read_latest_checkpoint()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use anyhow::Error;
    use forking_data_store::ObjectKey;
    use sui_types::base_types::ObjectID;
    use sui_types::base_types::SuiAddress;
    use sui_types::object::Object;
    use sui_types::object::Owner;

    use super::*;
    use crate::test_utils::verified_checkpoint;

    #[derive(Default)]
    struct MockStore {
        checkpoint_calls: Mutex<Vec<CheckpointSequenceNumber>>,
        checkpoints: BTreeMap<CheckpointSequenceNumber, VerifiedCheckpoint>,
        latest_checkpoint_calls: Mutex<u64>,
        latest_checkpoint: Option<VerifiedCheckpoint>,
        object_calls: Mutex<Vec<Vec<ObjectKey>>>,
        objects: BTreeMap<ObjectKey, Option<(Object, u64)>>,
    }

    impl MockStore {
        fn with_checkpoints(
            checkpoints: impl IntoIterator<Item = (CheckpointSequenceNumber, VerifiedCheckpoint)>,
            latest_checkpoint: Option<VerifiedCheckpoint>,
        ) -> Self {
            Self {
                checkpoint_calls: Mutex::new(vec![]),
                checkpoints: checkpoints.into_iter().collect(),
                latest_checkpoint_calls: Mutex::new(0),
                latest_checkpoint,
                object_calls: Mutex::new(vec![]),
                objects: BTreeMap::new(),
            }
        }

        fn with_objects(
            objects: impl IntoIterator<Item = (ObjectKey, Option<(Object, u64)>)>,
        ) -> Self {
            Self {
                checkpoint_calls: Mutex::new(vec![]),
                checkpoints: BTreeMap::new(),
                latest_checkpoint_calls: Mutex::new(0),
                latest_checkpoint: None,
                object_calls: Mutex::new(vec![]),
                objects: objects.into_iter().collect(),
            }
        }

        fn checkpoint_calls(&self) -> Vec<CheckpointSequenceNumber> {
            self.checkpoint_calls
                .lock()
                .expect("checkpoint-call mutex should not be poisoned")
                .clone()
        }

        fn latest_checkpoint_calls(&self) -> u64 {
            *self
                .latest_checkpoint_calls
                .lock()
                .expect("latest-checkpoint-call mutex should not be poisoned")
        }

        fn object_calls(&self) -> Vec<Vec<ObjectKey>> {
            self.object_calls
                .lock()
                .expect("object-call mutex should not be poisoned")
                .clone()
        }
    }

    impl forking_data_store::ObjectStore for MockStore {
        fn get_objects(&self, keys: &[ObjectKey]) -> Result<Vec<Option<(Object, u64)>>, Error> {
            self.object_calls
                .lock()
                .expect("object-call mutex should not be poisoned")
                .push(keys.to_vec());
            Ok(keys
                .iter()
                .map(|key| self.objects.get(key).cloned().unwrap_or(None))
                .collect())
        }
    }

    impl forking_data_store::ObjectStoreWriter for MockStore {
        fn write_object(
            &self,
            _key: &ObjectKey,
            _object: Object,
            _actual_version: u64,
        ) -> Result<(), Error> {
            Ok(())
        }
    }

    impl forking_data_store::CheckpointStore for MockStore {
        fn get_checkpoint_by_sequence_number(
            &self,
            sequence: CheckpointSequenceNumber,
        ) -> Result<Option<VerifiedCheckpoint>, Error> {
            self.checkpoint_calls
                .lock()
                .expect("checkpoint-call mutex should not be poisoned")
                .push(sequence);
            Ok(self.checkpoints.get(&sequence).cloned())
        }

        fn get_latest_checkpoint(&self) -> Result<Option<VerifiedCheckpoint>, Error> {
            *self
                .latest_checkpoint_calls
                .lock()
                .expect("latest-checkpoint-call mutex should not be poisoned") += 1;
            Ok(self.latest_checkpoint.clone())
        }

        fn get_sequence_by_checkpoint_digest(
            &self,
            _digest: &sui_types::digests::CheckpointDigest,
        ) -> Result<Option<CheckpointSequenceNumber>, Error> {
            todo!("checkpoint-digest lookups are not needed in these tests")
        }

        fn get_sequence_by_contents_digest(
            &self,
            _digest: &sui_types::digests::CheckpointContentsDigest,
        ) -> Result<Option<CheckpointSequenceNumber>, Error> {
            todo!("contents-digest lookups are not needed in these tests")
        }
    }

    impl forking_data_store::CheckpointStoreWriter for MockStore {
        fn write_checkpoint(&self, _checkpoint: &VerifiedCheckpoint) -> Result<(), Error> {
            Ok(())
        }
    }

    #[test]
    fn get_object_prefers_primary_without_secondary_lookup() {
        let object = Object::immutable_with_id_for_testing(ObjectID::random());
        let latest_key = ObjectKey {
            object_id: object.id(),
            version_query: VersionQuery::Latest,
        };
        let source = ForkingDataSource::from_stores(
            42,
            MockStore::with_objects([(
                latest_key.clone(),
                Some((object.clone(), object.version().value())),
            )]),
            MockStore::default(),
        );

        let fetched = source.get_object(&object.id());

        assert_eq!(fetched, Some(object.clone()));
        assert_eq!(
            source.store().primary().object_calls(),
            vec![vec![latest_key]],
        );
        assert!(source.store().secondary().object_calls().is_empty());
    }

    #[test]
    fn get_object_falls_back_to_secondary_after_primary_miss() {
        let object = Object::immutable_with_id_for_testing(ObjectID::random());
        let latest_key = ObjectKey {
            object_id: object.id(),
            version_query: VersionQuery::Latest,
        };
        let source = ForkingDataSource::from_stores(
            42,
            MockStore::default(),
            MockStore::with_objects([(
                latest_key.clone(),
                Some((object.clone(), object.version().value())),
            )]),
        );

        let fetched = source.get_object(&object.id());

        assert_eq!(fetched, Some(object.clone()));
        assert_eq!(
            source.store().primary().object_calls(),
            vec![vec![latest_key.clone()]],
        );
        assert_eq!(
            source.store().secondary().object_calls(),
            vec![vec![latest_key]],
        );
    }

    #[test]
    fn get_object_at_version_checks_primary_then_secondary() {
        let version = SequenceNumber::from_u64(7);
        let owner = SuiAddress::random_for_testing_only();
        let object = Object::with_id_owner_version_for_testing(
            ObjectID::random(),
            version,
            Owner::AddressOwner(owner),
        );
        let source = ForkingDataSource::from_stores(
            42,
            MockStore::default(),
            MockStore::with_objects([(
                ObjectKey {
                    object_id: object.id(),
                    version_query: VersionQuery::Version(version.value()),
                },
                Some((object.clone(), object.version().value())),
            )]),
        );

        let fetched = source.get_object_at_version(&object.id(), version);

        assert_eq!(fetched, Some(object.clone()));
        assert_eq!(
            source.store().primary().object_calls(),
            vec![vec![ObjectKey {
                object_id: object.id(),
                version_query: VersionQuery::Version(version.value()),
            }]],
        );
        assert_eq!(
            source.store().secondary().object_calls(),
            vec![vec![ObjectKey {
                object_id: object.id(),
                version_query: VersionQuery::Version(version.value()),
            }]],
        );
    }

    #[test]
    fn read_child_object_uses_root_version_and_validates_parent_owner() {
        let parent = ObjectID::random();
        let child_version = SequenceNumber::from_u64(9);
        let child = Object::with_id_owner_version_for_testing(
            ObjectID::random(),
            child_version,
            Owner::ObjectOwner(parent.into()),
        );
        let source = ForkingDataSource::from_stores(
            42,
            MockStore::default(),
            MockStore::with_objects([(
                ObjectKey {
                    object_id: child.id(),
                    version_query: VersionQuery::RootVersion(child_version.value()),
                },
                Some((child.clone(), child.version().value())),
            )]),
        );

        let fetched = source
            .read_child_object(&parent, &child.id(), child_version)
            .expect("child lookup should succeed");

        assert_eq!(fetched, Some(child.clone()));
        assert_eq!(
            source.store().primary().object_calls(),
            vec![vec![ObjectKey {
                object_id: child.id(),
                version_query: VersionQuery::RootVersion(child_version.value()),
            }]],
        );
        assert_eq!(
            source.store().secondary().object_calls(),
            vec![vec![ObjectKey {
                object_id: child.id(),
                version_query: VersionQuery::RootVersion(child_version.value()),
            }]],
        );
    }

    #[test]
    fn read_child_object_rejects_owner_mismatches() {
        let parent = ObjectID::random();
        let wrong_parent = ObjectID::random();
        let child_version = SequenceNumber::from_u64(5);
        let child = Object::with_id_owner_version_for_testing(
            ObjectID::random(),
            child_version,
            Owner::ObjectOwner(wrong_parent.into()),
        );
        let source = ForkingDataSource::from_stores(
            42,
            MockStore::default(),
            MockStore::with_objects([(
                ObjectKey {
                    object_id: child.id(),
                    version_query: VersionQuery::RootVersion(child_version.value()),
                },
                Some((child.clone(), child_version.value())),
            )]),
        );

        let result = source.read_child_object(&parent, &child.id(), child_version);

        assert!(result.is_err());
    }

    #[test]
    fn get_checkpoint_by_sequence_number_checks_primary_then_secondary() {
        let checkpoint = verified_checkpoint(11);
        let source = ForkingDataSource::from_stores(
            42,
            MockStore::default(),
            MockStore::with_checkpoints([(11, checkpoint.clone())], None),
        );

        let fetched = source.get_checkpoint_by_sequence_number(11);

        assert_eq!(
            fetched
                .as_ref()
                .map(|checkpoint| *checkpoint.sequence_number()),
            Some(11)
        );
        assert_eq!(*checkpoint.sequence_number(), 11);
        assert_eq!(source.store().primary().checkpoint_calls(), vec![11]);
        assert_eq!(source.store().secondary().checkpoint_calls(), vec![11]);
    }

    #[test]
    fn get_highest_checkpoint_prefers_primary_latest_checkpoint() {
        let primary_checkpoint = verified_checkpoint(17);
        let source = ForkingDataSource::from_stores(
            42,
            MockStore::with_checkpoints([], Some(primary_checkpoint.clone())),
            MockStore::with_checkpoints([], Some(verified_checkpoint(29))),
        );

        let fetched = source.get_latest_checkpoint();

        assert_eq!(
            fetched
                .as_ref()
                .map(|checkpoint| *checkpoint.sequence_number()),
            Some(17)
        );
        assert_eq!(*primary_checkpoint.sequence_number(), 17);
        assert_eq!(source.store().primary().latest_checkpoint_calls(), 1);
        assert_eq!(source.store().secondary().latest_checkpoint_calls(), 0);
    }

    #[test]
    fn get_highest_checkpoint_falls_back_to_secondary_when_primary_is_empty() {
        let checkpoint = verified_checkpoint(17);
        let source = ForkingDataSource::from_stores(
            42,
            MockStore::default(),
            MockStore::with_checkpoints([], Some(checkpoint.clone())),
        );

        let fetched = source.get_latest_checkpoint();

        assert_eq!(
            fetched
                .as_ref()
                .map(|checkpoint| *checkpoint.sequence_number()),
            Some(17)
        );
        assert_eq!(*checkpoint.sequence_number(), 17);
        assert_eq!(source.store().primary().latest_checkpoint_calls(), 1);
        assert_eq!(source.store().secondary().latest_checkpoint_calls(), 1);
    }
}
