// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    flavor::MoveFlavor,
    graph::PackageGraph,
    package::{EnvironmentName, Package, lockfile::DependencyInfo},
};

use std::{collections::BTreeMap, fmt};

pub struct CompiledPackage<F: MoveFlavor> {
    /// The path to the compiled package
    pub path: String,

    /// The dependencies of the package
    pub dependencies: BTreeMap<EnvironmentName, DependencyInfo<F>>,
}

/// A package that is defined as the root of a Move project.
///
/// This is a special package that contains the project manifest and dependencies' graphs,
/// and associated functions to operate with this data.
pub struct RootPackage<F: MoveFlavor + fmt::Debug> {
    /// The root package itself as a Package
    root: Package<F>,
    /// A map from an environment in the manifest to its dependency graph.
    dependencies: BTreeMap<EnvironmentName, PackageGraph<F>>,
}

pub fn compile<F: MoveFlavor>(root_pkg: RootPackage<F>) {
    // find the dependencies for each environment and compile them
    for (env, deps) in root_pkg.dependencies {
        let paths = deps.package.path();
    }
}
