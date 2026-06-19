Copyright (c) Mysten Labs, Inc.
SPDX-License-Identifier: Apache-2.0

# Fork RPC Coin And Balance Indexes

## Goal

`sui-fork` now has a durable DBMap-backed owned-object index for the subset of live objects that the fork knows about. The next step is to fill in the closely related `RpcIndexes` methods that are still useful for forked execution and v2 RPC serving:

- `get_coin_info`
- `get_balance`
- `balance_iter`

These are live-state indexes. They answer questions about the current objects visible to the fork, unlike ledger-history indexes, which answer historical transaction/event filter queries.

## Why Add These Indexes

The v2 RPC layer expects `RpcIndexes` to provide efficient lookup paths for coin metadata and balances. Without these methods, callers that use the fork as an RPC service hit unsupported paths even though the fork already has enough local object state to answer many of them.

The fork store has different constraints from a fullnode:

- It does not own a complete network-wide live object set.
- It starts from a fork checkpoint plus optional seed objects.
- It writes local post-fork execution results to disk.
- It must not resurrect objects that local execution deleted or wrapped.
- It should remain small and simple; ledger-history indexing is out of scope.

So these indexes should be scoped to the fork's known live state: seeded objects, objects fetched and cached on demand, and objects written by local execution.

## High-Level Design

Use one fork-local RocksDB index store for all live `RpcIndexes` data. This replaces the current owned-object DBMap store. In the section below (Why these tables) it is explained why the following tables are needed.

The index store should maintain one row per indexed fact:

- one row per live owned object
- one row per live Move object keyed by exact type
- one row per owner and coin type balance

This avoids rewriting whole index files and gives each RPC method the scan order it needs. The object store remains the source of truth for object contents and current-state removal markers; the indexes are lightweight lookup structures.

The core update model is the same as the owned-object index:

1. Before applying a local object diff, read the old live object state for every affected object ID.
2. Persist the local object writes/removals.
3. Apply index deletes derived from old objects.
4. Apply index inserts/deltas derived from new live objects.

This is preferable to rescanning the filesystem because it is bounded by the transaction diff and keeps index behavior aligned with execution.

## Why These Tables

`get_coin_info` needs to find wrapper objects by exact type:

- `CoinMetadata<T>`
- `TreasuryCap<T>`
- `RegulatedCoinMetadata<T>`

The way to do this is to either find the object by type in the local store, or fetch it from GraphQL at the fork checkpoint if it is missing. The data is stored as DBMap rows ordered by `(type, object_id)`.

`get_balance` needs a direct lookup by `(owner, coin_type)`.

`balance_iter` needs the same data ordered by owner first, then coin type, so it can scan all balances for one owner and stop as soon as the owner changes.

These access patterns map directly to DBMap key ordering:

```text
owned_objects: (owner, object_type, inverted_balance, object_id) -> version
object_types:  (object_type, object_id)                    -> version
balances:      (owner, coin_type)                          -> BalanceInfo
```

The owned-object table already exists in this PR: https://github.com/MystenLabs/sui/pull/26707 (and hopefully we can merge that soon). The new work is to generalize the store around it and add `object_types` and `balances`.

## Initialization

Initialization should remain lazy. The first RPC/indexed read should initialize the index if it is missing.

Initialization should use the existing seed manifest path:

1. Check for the index metadata marker.
2. If missing, take the local write snapshot lock.
3. Check again in case another reader initialized it.
4. Refuse to rebuild if local checkpoints have advanced past the fork checkpoint.
5. Fetch seed manifest objects at the fork checkpoint.
6. Cache those objects locally.
7. Build owned-object, object-type, and balance rows from those live objects.
8. Write the metadata marker in the same batch.

The fail-closed behavior is important. Once local execution has advanced the fork, rebuilding from only seed state would be stale.

## Coin Info Fallback

The local type index can only know about wrapper objects the fork has already seen. For `get_coin_info`, that may be too narrow because coin metadata may not have been seeded, and we should not require the user to do so.

For this method only, fetch object from GraphQL::

1. Look up the requested wrapper type in the local `object_types` table.
2. If found, return the object ID.
3. If missing, query GraphQL at `forked_at_checkpoint` for the first object with that exact type.
4. Validate that the returned object's type matches the requested type.
5. If the object was locally deleted or wrapped, do not cache or return it.
6. Otherwise, write the object to the local object cache and add it to the type index.

This keeps repeated `get_coin_info` calls local after the first miss, while respecting local removals.

## Balance Semantics

Balances should represent only the fork-known live state. Coin-object balances come from live address-owned or consensus-address-owned coin objects.
When a coin object changes, transfer/wrap/delete/create behavior is handled by subtracting the old object's contribution and adding the new object's contribution.

Address-balance accumulator values can be tracked when the local execution writes accumulator field objects. This should be best-effort; full upstream address-balance seeding is out of scope for this design.

When a balance update results in both `coin_balance == 0` and `address_balance == 0`, remove the row. This keeps `balance_iter` from returning empty balances.

# Implementation Details

The proposed `OwnedObjectIndexStore` from [PR 26707](https://github.com/MystenLabs/sui/pull/26707) should be a small live RPC index store. Exact names can change, but the structure should look like this:

```rust
const RPC_INDEX_DB_DIR: &str = "rpc_indexes_db";
const RPC_INDEX_VERSION: u64 = 1;

#[derive(DBMapUtils)]
struct RpcIndexTables {
    meta: DBMap<(), RpcIndexMetadata>,
    owned_objects: DBMap<OwnedObjectIndexKey, SequenceNumber>,
    object_types: DBMap<ObjectTypeIndexKey, SequenceNumber>,
    balances: DBMap<BalanceIndexKey, BalanceInfo>,
}

struct RpcIndexStore {
    tables: RpcIndexTables,
}

struct RpcIndexMetadata {
    version: u64,
}
```

The key types should encode the required scan order:

```rust
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
struct OwnedObjectIndexKey {
    owner: SuiAddress,
    object_type: StructTag,
    inverted_balance: Option<u64>,
    object_id: ObjectID,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
struct ObjectTypeIndexKey {
    object_type: StructTag,
    object_id: ObjectID,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
struct BalanceIndexKey {
    owner: SuiAddress,
    coin_type: StructTag,
}
```

Balance updates should be derived as signed deltas, even if the DB stores final `BalanceInfo` values:

```rust
#[derive(Clone, Copy, Debug, Default)]
struct BalanceDelta {
    coin_balance: i128,
    address_balance: i128,
}
```

## Store Pseudocode

The index store should expose helpers that map directly to initialization, object updates, and the `RpcIndexes` methods:

```rust
impl RpcIndexStore {
    fn open(root: &Path) -> Self;

    fn index_exists(&self) -> anyhow::Result<bool>;

    fn replace_from_objects<'a>(
        &self,
        objects: impl IntoIterator<Item = &'a Object>,
    ) -> anyhow::Result<()> {
        // Clear owned_objects, object_types, and balances.
        // Insert rows/deltas for every live seed object.
        // Write meta marker in the same batch, including empty indexes.
    }

    fn apply_object_updates<'a>(
        &self,
        old_objects: impl IntoIterator<Item = &'a Object>,
        new_objects: impl IntoIterator<Item = &'a Object>,
    ) -> anyhow::Result<()> {
        // Delete rows/deltas derived from old_objects.
        // Insert rows/deltas derived from new_objects.
        // Remove zero balance rows.
        // Write one RocksDB batch.
    }

    fn scan_owned_objects(
        &self,
        owner: SuiAddress,
        object_type: Option<&StructTag>,
        cursor: Option<OwnedObjectInfo>,
    ) -> anyhow::Result<Vec<OwnedObjectInfo>>;

    fn first_object_id_by_type(
        &self,
        object_type: &StructTag,
    ) -> anyhow::Result<Option<ObjectID>>;

    fn get_balance(
        &self,
        owner: &SuiAddress,
        coin_type: &StructTag,
    ) -> anyhow::Result<Option<BalanceInfo>>;

    fn balance_iter(
        &self,
        owner: &SuiAddress,
        cursor: Option<(SuiAddress, StructTag)>,
    ) -> anyhow::Result<Vec<(StructTag, BalanceInfo)>>;
}
```

The direct lookup methods are simple DBMap operations:

```rust
fn get_balance(owner, coin_type) {
    balances.get(&(owner, coin_type))
}

fn balance_iter(owner, cursor) {
    scan balances from cursor.unwrap_or((owner, min_struct_tag()))
    stop when key.owner != owner
}

fn first_object_id_by_type(object_type) {
    scan object_types from (object_type, ObjectID::ZERO)
    stop when key.object_type != object_type
    return first object id whose local latest state is still live
}
```

## DataStore Integration

`DataStore` should hold one RPC index handle next to the filesystem store:

```rust
struct DataStoreInner {
    forked_at_checkpoint: CheckpointSequenceNumber,
    gql: GraphQLClient,
    local: FilesystemStore,
    rpc_index: RpcIndexStore,
    local_snapshot_lock: RwLock<()>,
}
```

`DataStore::apply_object_updates` should initialize the RPC index, persist the object changes, and then call the index update helper using the old and new live objects.

`RpcIndexes` should delegate as follows:

```rust
fn owned_objects_iter(...) {
    self.rpc_index().scan_owned_objects(...)
}

fn get_coin_info(coin_type) {
    let metadata = self.first_object_id_by_type(&CoinMetadata::type_(coin_type.clone()))?;
    let treasury = self.first_object_id_by_type(&TreasuryCap::type_(coin_type.clone()))?;
    let regulated = self.first_object_id_by_type(&RegulatedCoinMetadata::type_(coin_type.clone()))?;
    ...
}

fn get_balance(owner, coin_type) {
    self.rpc_index().get_balance(owner, coin_type)
}

fn balance_iter(owner, cursor) {
    self.rpc_index().balance_iter(owner, cursor)
}
```

Unsupported `RpcIndexes` methods should return explicit `StorageError::custom(...)` errors instead of `todo!()`.

## Tests

- Add DB-level tests for type index upsert, delete, ordering, and stale local object skipping.
- Add DB-level tests for balance index coin transfer, coin balance mutation, removal/wrapping, and zero-row deletion.
- Add DB-level tests for `balance_iter` ordering and inclusive cursor behavior.
- Add store/RPC-index tests showing `get_balance` returns coin balances for seeded/local coins.
- Add store/RPC-index tests showing `balance_iter` pages by coin type for one owner.
- Add store/RPC-index tests showing `get_coin_info` prefers local wrapper objects.
- Add store/RPC-index tests showing `get_coin_info` fetches missing wrapper objects remotely once and serves repeated lookups locally.
- Add store/RPC-index tests showing local deletion/wrapping prevents remote fallback from resurrecting a wrapper object.
- Run targeted validation:
  - `cargo test -p sui-fork owned_object_index`
  - `cargo test -p sui-fork store_execution`
  - `cargo test -p sui-fork filesystem`
  - `cargo check -p sui-fork`

