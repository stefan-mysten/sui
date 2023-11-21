// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, ensure};
use clap::*;
use move_package::source_package::layout::SourcePackageLayout;
use regex::Regex;
use std::{
    fmt::Display,
    fs::create_dir_all,
    io::Write,
    path::{Path, PathBuf},
};

// TODO get a stable path to this stdlib
// pub const MOVE_STDLIB_PACKAGE_NAME: &str = "MoveStdlib";
// pub const MOVE_STDLIB_PACKAGE_PATH: &str = "{ \
//     git = \"https://github.com/move-language/move.git\", \
//     subdir = \"language/move-stdlib\", rev = \"main\" \
// }";
pub const MOVE_STDLIB_ADDR_NAME: &str = "std";
pub const MOVE_STDLIB_ADDR_VALUE: &str = "0x1";

/// Create a new Move package with name `name` at `path`. If `path` is not provided the package
/// will be created in the directory `name`.
///
/// By default, this command allows a strict naming scheme based on this regex: [A-Za-z][A-Za-z0-9-_]*.
#[derive(Parser)]
#[clap(name = "new")]
pub struct New {
    /// The name of the package to be created.
    pub name: String,
}

impl New {
    pub fn execute_with_defaults(self, path: Option<PathBuf>) -> anyhow::Result<()> {
        self.execute(
            path,
            "0.0.0",
            std::iter::empty::<(&str, &str)>(),
            std::iter::empty::<(&str, &str)>(),
            "",
        )
    }

    pub fn execute(
        self,
        path: Option<PathBuf>,
        version: &str,
        deps: impl IntoIterator<Item = (impl Display, impl Display)>,
        addrs: impl IntoIterator<Item = (impl Display, impl Display)>,
        custom: &str, // anything else that needs to end up being in Move.toml (or empty string)
    ) -> anyhow::Result<()> {
        // TODO warn on build config flags
        let Self { name } = self;

        let valid_identifier_re = Regex::new(r"^[A-Za-z][A-Za-z0-9-_]*$")
            .map_err(|_| anyhow!("Cannot build the regex needed to validate package naming"))?;

        ensure!(
            valid_identifier_re.is_match(&name),
            "Invalid package naming: a valid package name must start with a letter and can contain only letters, digits, hyphens (-), or underscores (_)."
        );

        let p: PathBuf;
        let path: &Path = match path {
            Some(path) => {
                p = path;
                &p
            }
            None => Path::new(&name),
        };
        create_dir_all(path.join(SourcePackageLayout::Sources.path()))?;
        let mut w = std::fs::File::create(path.join(SourcePackageLayout::Manifest.path()))?;
        writeln!(
            &mut w,
            "[package]
name = \"{name}\"
version = \"{version}\"

[dependencies]"
        )?;
        for (dep_name, dep_val) in deps {
            writeln!(w, "{dep_name} = {dep_val}")?;
        }

        writeln!(
            w,
            "
[addresses]"
        )?;
        for (addr_name, addr_val) in addrs {
            let addr_name = addr_name.to_string();
            let addr_name = addr_name.trim().replace('-', "_");
            writeln!(w, "{addr_name} = \"{addr_val}\"")?;
        }
        if !custom.is_empty() {
            writeln!(w, "{}", custom)?;
        }
        Ok(())
    }
}
