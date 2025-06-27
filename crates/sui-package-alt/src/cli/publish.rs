// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use crate::SuiFlavor;
use clap::{Command, Parser, Subcommand};
use move_package_alt::{
    compilation::compiled_package::{compile, BuildConfig, LintFlag},
    errors::PackageResult,
    flavor::Vanilla,
    package::{Package, RootPackage},
};
use sui_config::{sui_config_dir, SUI_CLIENT_CONFIG};
use sui_sdk::wallet_context::WalletContext;

/// Build the package
#[derive(Debug, Clone, Parser)]
pub struct Publish {
    /// Path to the project
    #[arg(name = "path", short = 'p', long = "path", default_value = ".")]
    path: Option<PathBuf>,

    #[arg(
        name = "env",
        short = 'e',
        long = "environment",
        default_value = "testnet"
    )]
    env: Option<String>,
}

impl Publish {
    pub async fn execute(&self) -> PackageResult<()> {
        let path = self.path.clone().unwrap_or_else(|| PathBuf::from("."));

        // wallet

        let config_path = sui_config_dir()?.join(SUI_CLIENT_CONFIG);
        let mut context = WalletContext::new(&config_path)?;

        let client = context.get_client().await?;
        let read_api = client.read_api();

        let build_config = BuildConfig {
            generate_docs: false,
            save_disassembly: true,
            install_dir: None,
            force_recompilation: false,
            lock_file: None,
            silence_warnings: false,
            warnings_are_errors: false,
            json_errors: false,
            lint_flag: LintFlag::default(),
            force_lock_file: false,
        };
        // get sender and chain id
        // let sender = context.infer_sender(&payment.gas).await?;
        // let chain_id = read_api.get_chain_identifier().await.ok();
        //
        // compile package
        let root_pkg = RootPackage::<SuiFlavor>::load(path, None).await?;
        let compiled_package = compile::<SuiFlavor>(
            root_pkg,
            build_config,
            &self.env.clone().unwrap_or_default(),
        )
        .await
        .unwrap();
        let compiled_modules = compiled_package.get_package_bytes();

        println!("Compiled modules {:?}", compiled_modules);

        // figure out the dependency ids - the package's addresses
        // let dep_ids = compiled_package.get_published_dependencies_ids();

        // create the publish tx kind
        // let tx_kind = client
        //     .transaction_builder()
        //     .publish_tx_kind(sender, compiled_modules, dep_ids)
        //     .await?;

        // let gas_payment = client
        //     .transaction_builder()
        //     .input_refs(&payment.gas)
        //     .await?;

        /// let result = dry_run_or_execute_or_serialize(
        /// sender,
        /// tx_kind,
        /// context,
        /// gas_payment,
        /// gas_data,
        /// processing,
        /// )
        /// .await?;
        Ok(())
    }
}
