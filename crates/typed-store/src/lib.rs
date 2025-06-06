// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]

// Re-export rocksdb so that consumers can use the version of rocksdb via typed-store
pub use rocksdb;

pub mod traits;
pub use traits::{DbIterator, Map};
pub mod memstore;
pub mod metrics;
pub mod rocks;
#[cfg(tidehunter)]
pub mod tidehunter_util;
mod util;
pub use metrics::DBMetrics;
pub use typed_store_error::TypedStoreError;
pub use util::be_fix_int_ser;

pub type StoreError = typed_store_error::TypedStoreError;

/// A helper macro to simplify common operations for opening and debugging TypedStore (currently internally structs of DBMaps)
/// It operates on a struct where all the members are DBMap<K, V>
/// The main features are:
/// 1. Flexible configuration of each table (column family) via defaults and overrides
/// 2. Auto-generated `open` routine
/// 3. Auto-generated `read_only_mode` handle
/// 4. Auto-generated memory stats method
/// 5. Other convenience features
///
/// 1. Flexible configuration:
///     a. Static options specified at struct definition
///
/// The definer of the struct can specify the default options for each table using annotations
/// We can also supply column family options on the default ones
/// A user defined function of signature () -> Options can be provided for each table
/// If an override function is not specified, the default in `typed_store::rocks::default_db_options` is used
/// ```
/// use typed_store::rocks::DBOptions;
/// use typed_store::rocks::DBMap;
/// use typed_store::rocks::MetricConf;
/// use typed_store::DBMapUtils;
/// use core::fmt::Error;
/// /// Define a struct with all members having type DBMap<K, V>
///
/// fn custom_fn_name1() -> DBOptions {DBOptions::default()}
/// fn custom_fn_name2() -> DBOptions {
///     let mut op = custom_fn_name1();
///     op.options.set_write_buffer_size(123456);
///     op
/// }
/// #[derive(DBMapUtils)]
/// struct Tables {
///     /// Specify custom options function `custom_fn_name1`
///     #[default_options_override_fn = "custom_fn_name1"]
///     table1: DBMap<String, String>,
///     #[default_options_override_fn = "custom_fn_name2"]
///     table2: DBMap<i32, String>,
///     // Nothing specified so `typed_store::rocks::default_db_options` is used
///     table3: DBMap<i32, String>,
///     #[default_options_override_fn = "custom_fn_name1"]
///     table4: DBMap<i32, String>,
/// }
///
///
///```
///
/// 2. Auto-generated `open` routine
///     The function `open_tables_read_write` is generated which allows for specifying DB wide options and custom table configs as mentioned above
///
/// 3. Auto-generated `read_only_mode` handle
///     This mode provides handle struct which opens the DB in read only mode and has certain features like dumping and counting the keys in the tables
///
/// Use the function `Tables::get_read_only_handle` which returns a handle that only allows read only features
///```
/// use typed_store::rocks::DBOptions;
/// use typed_store::rocks::DBMap;
/// use typed_store::DBMapUtils;
/// use core::fmt::Error;
/// /// Define a struct with all members having type DBMap<K, V>
///
/// fn custom_fn_name1() -> DBOptions {DBOptions::default()}
/// fn custom_fn_name2() -> DBOptions {
///     let mut op = custom_fn_name1();
///     op.options.set_write_buffer_size(123456);
///     op
/// }
/// #[derive(DBMapUtils)]
/// struct Tables {
///     /// Specify custom options function `custom_fn_name1`
///     #[default_options_override_fn = "custom_fn_name1"]
///     table1: DBMap<String, String>,
///     #[default_options_override_fn = "custom_fn_name2"]
///     table2: DBMap<i32, String>,
///     // Nothing specified so `typed_store::rocks::default_db_options` is used
///     table3: DBMap<i32, String>,
///     #[default_options_override_fn = "custom_fn_name1"]
///     table4: DBMap<i32, String>,
/// }
/// #[tokio::main]
/// async fn main() -> Result<(), Error> {
///
/// use typed_store::rocks::MetricConf;let primary_path = tempfile::tempdir().expect("Failed to open temporary directory").keep();
/// let _ = Tables::open_tables_read_write(primary_path.clone(), typed_store::rocks::MetricConf::default(), None, None);
///
/// // Get the read only handle
/// let read_only_handle = Tables::get_read_only_handle(primary_path, None, None, MetricConf::default());
/// // Use this handle for dumping
/// let ret = read_only_handle.dump("table2", 100, 0).unwrap();
/// Ok(())
/// }
/// ```
/// 4. Auto-generated memory stats method
///     `self.get_memory_usage` is derived to provide memory and cache usage
///
/// 5. Other convenience features
///     `Tables::describe_tables` is used to get a list of the table names and key-value types as string in a BTreeMap
///
/// // Bad usage example
/// // Structs fields most only be of type Store<K, V> or DMBap<K, V>
/// // This will fail to compile with error `All struct members must be of type Store<K, V> or DMBap<K, V>`
/// // #[derive(DBMapUtils)]
/// // struct BadTables {
/// //     table1: Store<String, String>,
/// //     bad_field: u32,
/// // #}
pub use typed_store_derive::DBMapUtils;
