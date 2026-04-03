# Sui Data for Forking

Multi-tier caching data store for Sui blockchain data.

This crate provides a flexible data store abstraction for retrieving and caching
Sui blockchain data (transactions, epochs, objects). The stores are loosely modeled
after the GraphQL schema in `crates/sui-indexer-alt-graphql/schema.graphql`.

## Capability Traits

- `TransactionStore` / `TransactionStoreWriter`
- `EpochStore` / `EpochStoreWriter`
- `ObjectStore` / `ObjectStoreWriter`
- `CheckpointStore` / `CheckpointStoreWriter` for `VerifiedCheckpoint` summaries

`ReadDataStore` and `ReadWriteDataStore` remain convenience bundles for the
transaction/epoch/object capability set.

## Store Implementations

| Store | Description | Read | Write |
|-------|-------------|------|-------|
| `GraphQLStore` | Remote GraphQL-backed store (mainnet/testnet) | Yes | No |
| `FileSystemStore` | Persistent local disk cache | Yes | Yes |
| `ForkingStore` | Primary/secondary composition for cached reads | Yes | Primary only |

## Composition Primitives

`ForkingStore<Primary, Secondary>`
- Reads `Primary` first, falls back to `Secondary`, and caches successful misses into `Primary`.
- Direct writes update `Primary` only.

## Composition Examples

```rust
use sui_data_store::{
    Node,
    stores::{FileSystemStore, ForkingStore, GraphQLStore},
};

// Filesystem -> GraphQL for object reads, persisting successful misses to disk.
let graphql = GraphQLStore::new(Node::Mainnet, "test-version")?;
let disk = FileSystemStore::new(Node::Mainnet)?;
let store = ForkingStore::new(disk, graphql);
```

## Version Queries

The `ObjectStore` trait supports three query modes via `VersionQuery`:

- `Version(v)` - Request object at exact version `v`
- `RootVersion(v)` - Request object at version `<= v` (for dynamic field roots)
- `AtCheckpoint(c)` - Request object as it existed at checkpoint `c`

## Network Configuration

Use the `Node` enum to configure which network to connect to:

```rust
use sui_data_store::Node;

let mainnet = Node::Mainnet;
let testnet = Node::Testnet;
let custom = Node::Custom("https://my-rpc.example.com".to_string());
```
