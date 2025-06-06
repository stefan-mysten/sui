// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    dependency::PinnedDependencyInfo,
    errors::{PackageError, PackageResult},
    flavor::MoveFlavor,
    package::{
        EnvironmentName, Package, PackageName,
        lockfile::Lockfile,
        manifest::{Manifest, digest},
        paths::PackagePath,
    },
};
use petgraph::graph::{DiGraph, NodeIndex};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::OnceCell;

#[derive(Debug)]
pub struct PackageGraph<F: MoveFlavor> {
    inner: DiGraph<Arc<PackageNode<F>>, PackageName>,
}

/// A node in the package graph, containing a [Package] and its pinned dependency info.
#[derive(Debug)]
pub struct PackageNode<F: MoveFlavor> {
    package: Package<F>,
    pinned_dep: PinnedDependencyInfo<F>,
}

struct PackageCache<F: MoveFlavor> {
    // TODO: better errors; I'm using Option for now because PackageResult doesn't have clone, but
    // it's too much effort to add clone everywhere; we should do this when we update the error
    // infra
    // TODO: would dashmap simplify this?
    cache: Mutex<BTreeMap<PathBuf, Arc<OnceCell<Option<Arc<PackageNode<F>>>>>>>,
}

struct PackageGraphBuilder<F: MoveFlavor> {
    cache: PackageCache<F>,
}

impl<F: MoveFlavor> PackageNode<F> {
    fn manifest(&self) -> &Manifest<F> {
        self.package.manifest()
    }
}

impl<F: MoveFlavor> PackageGraph<F> {
    // TODO: load should load for all environments and return a map

    /// Check to see whether the resolution graph in the lockfile inside `path` is up-to-date (i.e.
    /// whether any of the manifests digests are out of date). If the resolution graph is
    /// up-to-date, it is returned. Otherwise a new resolution graph is constructed by traversing
    /// (only) the manifest files.
    pub async fn load(path: &PackagePath, env: &EnvironmentName) -> PackageResult<Self> {
        let builder = PackageGraphBuilder::new();

        if let Some(graph) = builder.load_from_lockfile(path, env).await? {
            Ok(graph)
        } else {
            builder.load_from_manifests(path, env).await
        }
    }

    /// Construct a [PackageGraph] by pinning and fetching all transitive dependencies from the
    /// manifests rooted at `path` (no lockfiles are read).
    pub async fn load_from_manifests(
        path: &PackagePath,
        env: &EnvironmentName,
    ) -> PackageResult<Self> {
        PackageGraphBuilder::new()
            .load_from_manifests(path, env)
            .await
    }

    /// Read a [PackageGraph] from a lockfile, ignoring manifest digests. Primarily useful for
    /// testing - you will usually want [Self::load]
    /// TODO: probably want to take a path to the lockfile
    pub async fn load_from_lockfile_ignore_digests(
        path: &PackagePath,
        env: &EnvironmentName,
    ) -> PackageResult<Option<Self>> {
        PackageGraphBuilder::new()
            .load_from_lockfile_ignore_digests(path, env)
            .await
    }
}

impl<F: MoveFlavor> PackageGraphBuilder<F> {
    pub fn new() -> Self {
        Self {
            cache: PackageCache::new(),
        }
    }

    /// Load a [PackageGraph] from the lockfile at `path`. Returns [None] if the contents of the
    /// lockfile are out of date (i.e. if the lockfile doesn't exist or the manifest digests don't
    /// match).
    pub async fn load_from_lockfile(
        &self,
        path: &PackagePath,
        env: &EnvironmentName,
    ) -> PackageResult<Option<PackageGraph<F>>> {
        self.load_from_lockfile_impl(path, env, true).await
    }

    /// Load a [PackageGraph] from the lockfile at `path`. Returns [None] if there is no lockfile
    pub async fn load_from_lockfile_ignore_digests(
        &self,
        path: &PackagePath,
        env: &EnvironmentName,
    ) -> PackageResult<Option<PackageGraph<F>>> {
        self.load_from_lockfile_impl(path, env, false).await
    }

    /// Load a [PackageGraph] from the lockfile at `path`. Returns [None] if there is no lockfile.
    /// Also returns [None] if `check_digests` is true and any of the digests don't match.
    async fn load_from_lockfile_impl(
        &self,
        path: &PackagePath,
        env: &EnvironmentName,
        check_digests: bool,
    ) -> PackageResult<Option<PackageGraph<F>>> {
        let lockfile = Lockfile::<F>::read_from_dir(path.path())?;
        let mut graph = PackageGraph {
            inner: DiGraph::new(),
        };

        let deps = lockfile.pinned_deps_for_env(env);

        let mut package_indices = BTreeMap::new();
        if let Some(deps) = deps {
            // First pass: create nodes for all packages
            for (pkg_id, dep_info) in deps.data.iter() {
                let package = self.cache.fetch(&dep_info.source).await?;
                let pkg_manifest_path = package.package.path().manifest_path();
                let package_manifest_digest =
                    digest(std::fs::read_to_string(pkg_manifest_path)?.as_bytes());
                if check_digests && package_manifest_digest != dep_info.manifest_digest {
                    return Ok(None);
                }
                let index = graph.inner.add_node(package);
                package_indices.insert(pkg_id.clone(), index);
            }

            // Second pass: add edges based on dependencies
            for (pkg_id, dep_info) in deps.data.iter() {
                let from_index = package_indices.get(pkg_id).unwrap();
                for (dep_name, dep_id) in dep_info.deps.iter() {
                    if let Some(to_index) = package_indices.get(dep_id) {
                        graph
                            .inner
                            .add_edge(*from_index, *to_index, dep_name.clone());
                    }
                }
            }
        }

        Ok(Some(graph))
    }

    /// Construct a new package graph for `env` by recursively fetching and reading manifest files
    /// starting from the package at `path`.
    /// Lockfiles are ignored. See [PackageGraph::load]
    async fn load_from_manifests(
        &self,
        path: &PackagePath,
        env: &EnvironmentName,
    ) -> PackageResult<PackageGraph<F>> {
        // TODO: this is wrong - it is ignoring `path`
        let graph = Arc::new(Mutex::new(DiGraph::new()));
        let visited = Arc::new(Mutex::new(BTreeMap::new()));
        let root = PinnedDependencyInfo::<F>::root_dependency(path);

        self.add_transitive_manifest_deps(&root, env, graph.clone(), visited)
            .await?;

        let graph = graph.lock().expect("unpoisoned").map(
            |_, node| {
                node.clone()
                    .expect("add_transitive_packages removes all `None`s before returning")
            },
            |_, e| e.clone(),
        );

        Ok(PackageGraph { inner: graph })
    }

    /// Adds nodes and edges for the graph rooted at `dep` to `graph` and returns the node ID for
    /// `dep`. Nodes are constructed by fetching the dependencies. All nodes that this function adds to
    /// `graph` will be set to `Some` before this function returns.
    ///
    /// `cache` is used to short-circuit refetching - if a node is in `cache` then neither it nor its
    /// dependencies will be readded.
    ///
    /// TODO: keys for `cache` and `visited` should be `UnfetchedPackagePath`
    ///
    /// Deadlock prevention: `cache` is never acquired while `graph` is held, so there cannot be a
    /// deadlock
    async fn add_transitive_manifest_deps(
        &self,
        dep: &PinnedDependencyInfo<F>,
        env: &EnvironmentName,
        graph: Arc<Mutex<DiGraph<Option<Arc<PackageNode<F>>>, PackageName>>>,
        visited: Arc<Mutex<BTreeMap<PathBuf, NodeIndex>>>,
    ) -> PackageResult<NodeIndex> {
        // return early if node is cached; add empty node to graph and visited list otherwise
        let index = match visited
            .lock()
            .expect("unpoisoned")
            .entry(dep.unfetched_path())
        {
            Entry::Occupied(entry) => return Ok(*entry.get()),
            Entry::Vacant(entry) => *entry.insert(graph.lock().expect("unpoisoned").add_node(None)),
        };

        // fetch package and add it to the graph
        let package = self.cache.fetch(dep).await?;

        // add outgoing edges for dependencies
        // Note: this loop could be parallel if we want parallel fetching:
        for (name, dep) in package.package.direct_deps(env).iter() {
            // TODO: to handle use-environment we need to traverse with a different env here
            let future =
                self.add_transitive_manifest_deps(dep, env, graph.clone(), visited.clone());
            let dep_index = Box::pin(future).await?;

            graph
                .lock()
                .expect("unpoisoned")
                .add_edge(index, dep_index, name.clone());
        }

        graph
            .lock()
            .expect("unpoisoned")
            .node_weight_mut(index)
            .expect("node was added above")
            .replace(package);
        Ok(index)
    }
}

impl<F: MoveFlavor> PackageCache<F> {
    /// Construct a new empty cache
    pub fn new() -> Self {
        Self {
            cache: Mutex::default(),
        }
    }

    /// Return a reference to a cached [Package], loading it if necessary
    pub async fn fetch(&self, dep: &PinnedDependencyInfo<F>) -> PackageResult<Arc<PackageNode<F>>> {
        let cell = self
            .cache
            .lock()
            .expect("unpoisoned")
            .entry(dep.unfetched_path())
            .or_default()
            .clone();

        cell.get_or_init(async || {
            Package::load(dep.clone()).await.ok().map(|package| {
                Arc::new(PackageNode {
                    package,
                    pinned_dep: dep.clone(),
                })
            })
        })
        .await
        .clone()
        .ok_or(PackageError::Generic(
            "TODO: couldn't fetch package".to_string(),
        ))
    }
}
