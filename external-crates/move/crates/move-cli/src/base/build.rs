// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use clap::*;
use move_package_alt::flavor::MoveFlavor;
use move_package_compiling::build_config::BuildConfig;
use move_package_compiling::compiled_package::compile;
use std::path::{Path, PathBuf};

/// Build the package at `path`. If no path is provided defaults to current directory.
#[derive(Parser)]
#[clap(name = "build")]
pub struct Build;

impl Build {
    pub async fn execute<F: MoveFlavor>(
        self,
        path: Option<&Path>,
        config: BuildConfig,
    ) -> anyhow::Result<()> {
        let p = PathBuf::from(".");
        let path = path.clone().unwrap_or_else(|| &p);
        compile::<F>(path, &config).await?;
        Ok(())
    }
}
