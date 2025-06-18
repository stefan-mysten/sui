// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use crate::{
    compilation::compiled_package::compile,
    errors::PackageResult,
    flavor::Vanilla,
    package::{Package, RootPackage},
};
use clap::{Command, Parser, Subcommand};

/// Build the package
#[derive(Debug, Clone, Parser)]
pub struct Build {
    /// Path to the project
    #[arg(name = "path", short = 'p', long = "path", default_value = ".")]
    path: Option<PathBuf>,
}

impl Build {
    pub async fn execute(&self) -> PackageResult<()> {
        let path = self.path.clone().unwrap_or_else(|| PathBuf::from("."));

        let root_pkg = RootPackage::<Vanilla>::load(path, None).await?;
        compile::<Vanilla>(root_pkg);

        Ok(())
    }
}
