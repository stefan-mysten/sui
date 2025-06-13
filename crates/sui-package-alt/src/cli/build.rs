// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use clap::{Command, Parser, Subcommand};
use move_package_alt::{
    compilation::compiled_package::{compile, BuildConfig},
    errors::PackageResult,
    flavor::Vanilla,
    package::{Package, RootPackage},
};

/// Build the package
#[derive(Debug, Clone, Parser)]
pub struct Build {
    /// Path to the project
    #[arg(name = "path", short = 'p', long = "path", default_value = ".")]
    path: Option<PathBuf>,

    #[arg(name = "path", short = 'p', long = "path", default_value = "testnet")]
    env: String,

    #[command(flatten)]
    build_config: BuildConfig,
}

impl Build {
    pub async fn execute(&self) -> PackageResult<()> {
        let path = self.path.clone().unwrap_or_else(|| PathBuf::from("."));

        let root_pkg = RootPackage::<Vanilla>::load(path, None).await?;
        compile(root_pkg, self.build_config.clone(), &self.env)
            .await
            .unwrap();

        Ok(())
    }
}
