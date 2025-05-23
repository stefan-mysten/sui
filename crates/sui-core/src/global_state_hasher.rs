// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use itertools::Itertools;
use mysten_common::fatal;
use mysten_metrics::monitored_scope;
use prometheus::{register_int_gauge_with_registry, IntGauge, Registry};
use serde::Serialize;
use sui_protocol_config::ProtocolConfig;
use sui_types::base_types::{ObjectID, ObjectRef, SequenceNumber, VersionNumber};
use sui_types::committee::EpochId;
use sui_types::digests::{ObjectDigest, TransactionDigest};
use sui_types::in_memory_storage::InMemoryStorage;
use sui_types::storage::{ObjectKey, ObjectStore};
use tracing::debug;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use fastcrypto::hash::MultisetHash;
use sui_types::effects::TransactionEffects;
use sui_types::effects::TransactionEffectsAPI;
use sui_types::error::SuiResult;
use sui_types::global_state_hash::GlobalStateHash;
use sui_types::messages_checkpoint::{CheckpointSequenceNumber, ECMHLiveObjectSetDigest};

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::authority::authority_store_tables::LiveObject;

pub struct GlobalStateHashMetrics {
    inconsistent_state: IntGauge,
}

impl GlobalStateHashMetrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        let this = Self {
            inconsistent_state: register_int_gauge_with_registry!(
                "global_state_hasher_inconsistent_state",
                "1 if accumulated live object set differs from GlobalStateHasher root state hash for the previous epoch",
                registry
            )
            .unwrap(),
        };
        Arc::new(this)
    }
}

pub struct GlobalStateHasher {
    store: Arc<dyn GlobalStateHashStore>,
    metrics: Arc<GlobalStateHashMetrics>,
}

pub trait GlobalStateHashStore: ObjectStore + Send + Sync {
    /// This function is only called in older protocol versions, and should no longer be used.
    /// It creates an explicit dependency to tombstones which is not desired.
    fn get_object_ref_prior_to_key_deprecated(
        &self,
        object_id: &ObjectID,
        version: VersionNumber,
    ) -> SuiResult<Option<ObjectRef>>;

    fn get_root_state_hash_for_epoch(
        &self,
        epoch: EpochId,
    ) -> SuiResult<Option<(CheckpointSequenceNumber, GlobalStateHash)>>;

    fn get_root_state_hash_for_highest_epoch(
        &self,
    ) -> SuiResult<Option<(EpochId, (CheckpointSequenceNumber, GlobalStateHash))>>;

    fn insert_state_hash_for_epoch(
        &self,
        epoch: EpochId,
        checkpoint_seq_num: &CheckpointSequenceNumber,
        acc: &GlobalStateHash,
    ) -> SuiResult;

    fn iter_live_object_set(
        &self,
        include_wrapped_tombstone: bool,
    ) -> Box<dyn Iterator<Item = LiveObject> + '_>;

    fn iter_cached_live_object_set_for_testing(
        &self,
        include_wrapped_tombstone: bool,
    ) -> Box<dyn Iterator<Item = LiveObject> + '_> {
        self.iter_live_object_set(include_wrapped_tombstone)
    }
}

impl GlobalStateHashStore for InMemoryStorage {
    fn get_object_ref_prior_to_key_deprecated(
        &self,
        _object_id: &ObjectID,
        _version: VersionNumber,
    ) -> SuiResult<Option<ObjectRef>> {
        unreachable!("get_object_ref_prior_to_key is only called by accumulate_effects_v1, while InMemoryStorage is used by testing and genesis only, which always uses latest protocol ")
    }

    fn get_root_state_hash_for_epoch(
        &self,
        _epoch: EpochId,
    ) -> SuiResult<Option<(CheckpointSequenceNumber, GlobalStateHash)>> {
        unreachable!("not used for testing")
    }

    fn get_root_state_hash_for_highest_epoch(
        &self,
    ) -> SuiResult<Option<(EpochId, (CheckpointSequenceNumber, GlobalStateHash))>> {
        unreachable!("not used for testing")
    }

    fn insert_state_hash_for_epoch(
        &self,
        _epoch: EpochId,
        _checkpoint_seq_num: &CheckpointSequenceNumber,
        _acc: &GlobalStateHash,
    ) -> SuiResult {
        unreachable!("not used for testing")
    }

    fn iter_live_object_set(
        &self,
        _include_wrapped_tombstone: bool,
    ) -> Box<dyn Iterator<Item = LiveObject> + '_> {
        unreachable!("not used for testing")
    }
}

/// Serializable representation of the ObjectRef of an
/// object that has been wrapped
/// TODO: This can be replaced with ObjectKey.
#[derive(Serialize, Debug)]
pub struct WrappedObject {
    id: ObjectID,
    wrapped_at: SequenceNumber,
    digest: ObjectDigest,
}

impl WrappedObject {
    pub fn new(id: ObjectID, wrapped_at: SequenceNumber) -> Self {
        Self {
            id,
            wrapped_at,
            digest: ObjectDigest::OBJECT_DIGEST_WRAPPED,
        }
    }
}

pub fn accumulate_effects<T, S>(
    store: S,
    effects: &[TransactionEffects],
    protocol_config: &ProtocolConfig,
) -> GlobalStateHash
where
    S: std::ops::Deref<Target = T>,
    T: GlobalStateHashStore + ?Sized,
{
    if protocol_config.enable_effects_v2() {
        accumulate_effects_v3(effects)
    } else if protocol_config.simplified_unwrap_then_delete() {
        accumulate_effects_v2(store, effects)
    } else {
        accumulate_effects_v1(store, effects, protocol_config)
    }
}

fn accumulate_effects_v1<T, S>(
    store: S,
    effects: &[TransactionEffects],
    protocol_config: &ProtocolConfig,
) -> GlobalStateHash
where
    S: std::ops::Deref<Target = T>,
    T: GlobalStateHashStore + ?Sized,
{
    let mut acc = GlobalStateHash::default();

    // process insertions to the set
    acc.insert_all(
        effects
            .iter()
            .flat_map(|fx| {
                fx.all_changed_objects()
                    .into_iter()
                    .map(|(oref, _, _)| oref.2)
            })
            .collect::<Vec<ObjectDigest>>(),
    );

    // insert wrapped tombstones. We use a custom struct in order to contain the tombstone
    // against the object id and sequence number, as the tombstone by itself is not unique.
    acc.insert_all(
        effects
            .iter()
            .flat_map(|fx| {
                fx.wrapped()
                    .iter()
                    .map(|oref| {
                        bcs::to_bytes(&WrappedObject::new(oref.0, oref.1))
                            .unwrap()
                            .to_vec()
                    })
                    .collect::<Vec<Vec<u8>>>()
            })
            .collect::<Vec<Vec<u8>>>(),
    );

    let all_unwrapped = effects
        .iter()
        .flat_map(|fx| {
            fx.unwrapped()
                .into_iter()
                .map(|(oref, _owner)| (*fx.transaction_digest(), oref.0, oref.1))
        })
        .chain(effects.iter().flat_map(|fx| {
            fx.unwrapped_then_deleted()
                .into_iter()
                .map(|oref| (*fx.transaction_digest(), oref.0, oref.1))
        }))
        .collect::<Vec<(TransactionDigest, ObjectID, SequenceNumber)>>();

    let unwrapped_ids: HashMap<TransactionDigest, HashSet<ObjectID>> = all_unwrapped
        .iter()
        .map(|(digest, id, _)| (*digest, *id))
        .into_group_map()
        .iter()
        .map(|(digest, ids)| (*digest, HashSet::from_iter(ids.iter().cloned())))
        .collect();

    // Collect keys from modified_at_versions to remove from the hasher.
    // Filter all unwrapped objects (from unwrapped or unwrapped_then_deleted effects)
    // as these were inserted into the hasher as a WrappedObject. Will handle these
    // separately.
    let modified_at_version_keys: Vec<ObjectKey> = effects
        .iter()
        .flat_map(|fx| {
            fx.modified_at_versions()
                .into_iter()
                .map(|(id, seq_num)| (*fx.transaction_digest(), id, seq_num))
        })
        .filter_map(|(tx_digest, id, seq_num)| {
            // unwrapped tx
            if let Some(ids) = unwrapped_ids.get(&tx_digest) {
                // object unwrapped in this tx. We handle it later
                if ids.contains(&id) {
                    return None;
                }
            }
            Some(ObjectKey(id, seq_num))
        })
        .collect();

    let modified_at_digests: Vec<_> = store
        .multi_get_objects_by_key(&modified_at_version_keys.clone())
        .into_iter()
        .zip(modified_at_version_keys)
        .map(|(obj, key)| {
            obj.unwrap_or_else(|| panic!("Object for key {:?} from modified_at_versions effects does not exist in objects table", key))
                .compute_object_reference()
                .2
        })
        .collect();
    acc.remove_all(modified_at_digests);

    // Process unwrapped and unwrapped_then_deleted effects, which need to be
    // removed as WrappedObject using the last sequence number it was tombstoned
    // against. Since this happened in a past transaction, and the child object may
    // have been modified since (and hence its sequence number incremented), we
    // seek the version prior to the unwrapped version from the objects table directly.
    // If the tombstone is not found, then assume this is a newly created wrapped object hence
    // we don't expect to find it in the table.
    let wrapped_objects_to_remove: Vec<WrappedObject> = all_unwrapped
        .iter()
        .filter_map(|(_tx_digest, id, seq_num)| {
            let objref = store
                .get_object_ref_prior_to_key_deprecated(id, *seq_num)
                .expect("read cannot fail");

            objref.map(|(id, version, digest)| {
                assert!(
                    !protocol_config.loaded_child_objects_fixed() || digest.is_wrapped(),
                    "{:?}",
                    id
                );
                WrappedObject::new(id, version)
            })
        })
        .collect();

    acc.remove_all(
        wrapped_objects_to_remove
            .iter()
            .map(|wrapped| bcs::to_bytes(wrapped).unwrap().to_vec())
            .collect::<Vec<Vec<u8>>>(),
    );

    acc
}

fn accumulate_effects_v2<T, S>(store: S, effects: &[TransactionEffects]) -> GlobalStateHash
where
    S: std::ops::Deref<Target = T>,
    T: GlobalStateHashStore + ?Sized,
{
    let mut acc = GlobalStateHash::default();

    // process insertions to the set
    acc.insert_all(
        effects
            .iter()
            .flat_map(|fx| {
                fx.all_changed_objects()
                    .into_iter()
                    .map(|(oref, _, _)| oref.2)
            })
            .collect::<Vec<ObjectDigest>>(),
    );

    // Collect keys from modified_at_versions to remove from the hasher.
    let modified_at_version_keys: Vec<_> = effects
        .iter()
        .flat_map(|fx| {
            fx.modified_at_versions()
                .into_iter()
                .map(|(id, version)| ObjectKey(id, version))
        })
        .collect();

    let modified_at_digests: Vec<_> = store
        .multi_get_objects_by_key(&modified_at_version_keys.clone())
        .into_iter()
        .zip(modified_at_version_keys)
        .map(|(obj, key)| {
            obj.unwrap_or_else(|| panic!("Object for key {:?} from modified_at_versions effects does not exist in objects table", key))
                .compute_object_reference()
                .2
        })
        .collect();
    acc.remove_all(modified_at_digests);

    acc
}

fn accumulate_effects_v3(effects: &[TransactionEffects]) -> GlobalStateHash {
    let mut acc = GlobalStateHash::default();

    // process insertions to the set
    acc.insert_all(
        effects
            .iter()
            .flat_map(|fx| {
                fx.all_changed_objects()
                    .into_iter()
                    .map(|(object_ref, _, _)| object_ref.2)
            })
            .collect::<Vec<ObjectDigest>>(),
    );

    // process modified objects to the set
    acc.remove_all(
        effects
            .iter()
            .flat_map(|fx| {
                fx.old_object_metadata()
                    .into_iter()
                    .map(|(object_ref, _owner)| object_ref.2)
            })
            .collect::<Vec<ObjectDigest>>(),
    );

    acc
}

impl GlobalStateHasher {
    pub fn new(store: Arc<dyn GlobalStateHashStore>, metrics: Arc<GlobalStateHashMetrics>) -> Self {
        Self { store, metrics }
    }

    pub fn new_for_tests(store: Arc<dyn GlobalStateHashStore>) -> Self {
        Self::new(store, GlobalStateHashMetrics::new(&Registry::new()))
    }

    pub fn metrics(&self) -> Arc<GlobalStateHashMetrics> {
        self.metrics.clone()
    }

    pub fn set_inconsistent_state(&self, is_inconsistent_state: bool) {
        self.metrics
            .inconsistent_state
            .set(is_inconsistent_state as i64);
    }

    /// Accumulates the effects of a single checkpoint and persists the hasher.
    pub fn accumulate_checkpoint(
        &self,
        effects: &[TransactionEffects],
        checkpoint_seq_num: CheckpointSequenceNumber,
        epoch_store: &AuthorityPerEpochStore,
    ) -> SuiResult<GlobalStateHash> {
        let _scope = monitored_scope("AccumulateCheckpoint");
        if let Some(acc) = epoch_store.get_state_hash_for_checkpoint(&checkpoint_seq_num)? {
            return Ok(acc);
        }

        let acc = self.accumulate_effects(effects, epoch_store.protocol_config());

        epoch_store.insert_state_hash_for_checkpoint(&checkpoint_seq_num, &acc)?;
        debug!("Accumulated checkpoint {}", checkpoint_seq_num);

        epoch_store
            .checkpoint_state_notify_read
            .notify(&checkpoint_seq_num, &acc);

        Ok(acc)
    }

    pub fn accumulate_cached_live_object_set_for_testing(
        &self,
        include_wrapped_tombstone: bool,
    ) -> GlobalStateHash {
        Self::accumulate_live_object_set_impl(
            self.store
                .iter_cached_live_object_set_for_testing(include_wrapped_tombstone),
        )
    }

    /// Returns the result of accumulating the live object set, without side effects
    pub fn accumulate_live_object_set(&self, include_wrapped_tombstone: bool) -> GlobalStateHash {
        Self::accumulate_live_object_set_impl(
            self.store.iter_live_object_set(include_wrapped_tombstone),
        )
    }

    fn accumulate_live_object_set_impl(iter: impl Iterator<Item = LiveObject>) -> GlobalStateHash {
        let mut acc = GlobalStateHash::default();
        iter.for_each(|live_object| {
            Self::accumulate_live_object(&mut acc, &live_object);
        });
        acc
    }

    pub fn accumulate_live_object(acc: &mut GlobalStateHash, live_object: &LiveObject) {
        match live_object {
            LiveObject::Normal(object) => {
                acc.insert(object.compute_object_reference().2);
            }
            LiveObject::Wrapped(key) => {
                acc.insert(
                    bcs::to_bytes(&WrappedObject::new(key.0, key.1))
                        .expect("Failed to serialize WrappedObject"),
                );
            }
        }
    }

    pub fn digest_live_object_set(
        &self,
        include_wrapped_tombstone: bool,
    ) -> ECMHLiveObjectSetDigest {
        let acc = self.accumulate_live_object_set(include_wrapped_tombstone);
        acc.digest().into()
    }

    pub async fn digest_epoch(
        &self,
        epoch_store: Arc<AuthorityPerEpochStore>,
        last_checkpoint_of_epoch: CheckpointSequenceNumber,
    ) -> SuiResult<ECMHLiveObjectSetDigest> {
        Ok(self
            .accumulate_epoch(epoch_store, last_checkpoint_of_epoch)?
            .digest()
            .into())
    }

    pub async fn wait_for_previous_running_root(
        &self,
        epoch_store: &AuthorityPerEpochStore,
        checkpoint_seq_num: CheckpointSequenceNumber,
    ) -> SuiResult {
        assert!(checkpoint_seq_num > 0);

        // Check if this is the first checkpoint of the new epoch, in which case
        // there is nothing to wait for.
        if self
            .store
            .get_root_state_hash_for_highest_epoch()?
            .map(|(_, (last_checkpoint_prev_epoch, _))| last_checkpoint_prev_epoch)
            == Some(checkpoint_seq_num - 1)
        {
            return Ok(());
        }

        // There is an edge case here where checkpoint_seq_num is 1. This means the previous
        // checkpoint is the genesis checkpoint. CheckpointExecutor is guaranteed to execute
        // and accumulate the genesis checkpoint, so this will resolve.
        epoch_store
            .notify_read_running_root(checkpoint_seq_num - 1)
            .await?;
        Ok(())
    }

    fn get_prior_root(
        &self,
        epoch_store: &AuthorityPerEpochStore,
        checkpoint_seq_num: CheckpointSequenceNumber,
    ) -> SuiResult<GlobalStateHash> {
        if checkpoint_seq_num == 0 {
            return Ok(GlobalStateHash::default());
        }

        if let Some((prev_epoch, (last_checkpoint_prev_epoch, prev_acc))) =
            self.store.get_root_state_hash_for_highest_epoch()?
        {
            assert_eq!(prev_epoch + 1, epoch_store.epoch());
            if last_checkpoint_prev_epoch == checkpoint_seq_num - 1 {
                return Ok(prev_acc);
            }
        }

        let Some(prior_running_root) =
            epoch_store.get_running_root_state_hash(checkpoint_seq_num - 1)?
        else {
            fatal!(
                "Running root state hasher must exist for checkpoint {}",
                checkpoint_seq_num - 1
            );
        };

        Ok(prior_running_root)
    }

    // Accumulate the running root.
    // The previous checkpoint must be accumulated before calling this function, or it will panic.
    pub fn accumulate_running_root(
        &self,
        epoch_store: &AuthorityPerEpochStore,
        checkpoint_seq_num: CheckpointSequenceNumber,
        checkpoint_acc: Option<GlobalStateHash>,
    ) -> SuiResult {
        let _scope = monitored_scope("AccumulateRunningRoot");
        tracing::info!(
            "accumulating running root for checkpoint {}",
            checkpoint_seq_num
        );

        // Idempotency.
        if epoch_store
            .get_running_root_state_hash(checkpoint_seq_num)?
            .is_some()
        {
            debug!(
                "accumulate_running_root {:?} {:?} already exists",
                epoch_store.epoch(),
                checkpoint_seq_num
            );
            return Ok(());
        }

        let mut running_root = self.get_prior_root(epoch_store, checkpoint_seq_num)?;

        let checkpoint_acc = checkpoint_acc.unwrap_or_else(|| {
            epoch_store
                .get_state_hash_for_checkpoint(&checkpoint_seq_num)
                .expect("Failed to get checkpoint accumulator from disk")
                .expect("Expected checkpoint accumulator to exist")
        });
        running_root.union(&checkpoint_acc);
        epoch_store.insert_running_root_state_hash(&checkpoint_seq_num, &running_root)?;
        debug!(
            "Accumulated checkpoint {} to running root accumulator",
            checkpoint_seq_num,
        );
        Ok(())
    }

    pub fn accumulate_epoch(
        &self,
        epoch_store: Arc<AuthorityPerEpochStore>,
        last_checkpoint_of_epoch: CheckpointSequenceNumber,
    ) -> SuiResult<GlobalStateHash> {
        let _scope = monitored_scope("AccumulateEpochV2");
        let running_root = epoch_store
            .get_running_root_state_hash(last_checkpoint_of_epoch)?
            .expect("Expected running root accumulator to exist up to last checkpoint of epoch");

        self.store.insert_state_hash_for_epoch(
            epoch_store.epoch(),
            &last_checkpoint_of_epoch,
            &running_root,
        )?;
        debug!(
            "Finalized root state hash for epoch {} (up to checkpoint {})",
            epoch_store.epoch(),
            last_checkpoint_of_epoch
        );
        Ok(running_root.clone())
    }

    pub fn accumulate_effects(
        &self,
        effects: &[TransactionEffects],
        protocol_config: &ProtocolConfig,
    ) -> GlobalStateHash {
        accumulate_effects(&*self.store, effects, protocol_config)
    }
}
