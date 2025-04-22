// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

//! Types and methods for external dependencies (of the form `{ git = "<repo>" }`)
//!
//! Git dependencies are cached in `~/.move`, which has the following structure:
//!
//! ```ignore
//! .move/
//!   git/
//!     <remote 1>/ # a headless, sparse, and shallow git repository
//!       <sha 1>/ # a worktree checked out to the given sha
//!       <sha 2>/
//!       ...
//!     <remote 2>/
//!       ...
//!     ...
//! ```
use std::{
    marker::PhantomData,
    path::PathBuf,
    process::{Command, Stdio},
};

use derive_where::derive_where;
use serde::{Deserialize, Serialize};

use crate::errors::{PackageError, PackageResult};

use super::{DependencySet, Pinned, Unpinned};

type Sha = String;

// TODO: custom deserialization to verify pinnedness for pinned deps?
#[derive(Debug, Serialize, Deserialize)]
#[derive_where(Clone)]
pub struct GitDependency<P = Unpinned> {
    /// The repository containing the dependency
    #[serde(rename = "git")]
    repo: String,

    /// The git commit-ish for the dep; guaranteed to be a commit if [P] is [Pinned].
    #[serde(default)]
    rev: Option<String>,

    /// The path within the repository
    #[serde(default)]
    path: Option<PathBuf>,

    #[serde(skip)]
    phantom: PhantomData<P>,
}

impl GitDependency<Unpinned> {
    /// Replace all commit-ishes in [deps] with commits (i.e. SHAs). Requires fetching the git
    /// repositories
    pub fn pin(deps: DependencySet<Self>) -> PackageResult<DependencySet<GitDependency<Pinned>>> {
        Ok(deps
            .into_iter()
            .map(|(env, package, dep)| (env, package, dep.pin_one().unwrap())) // TODO: errors!
            .collect())
    }

    /// Replace the commit-ish [self.rev] with a commit (i.e. a SHA). Requires fetching the git
    /// repository
    fn pin_one(&self) -> PackageResult<GitDependency<Pinned>> {
        let mut git_dep: GitDependency<Pinned> = GitDependency {
            repo: self.repo.clone(),
            rev: self.rev.clone(),
            path: self.path.clone(),
            phantom: PhantomData,
        };

        let (sha, git_dep_path) = git_dep.fetch()?;

        git_dep.rev = Some(sha);

        Ok(git_dep)
    }
}

impl GitDependency<Pinned> {
    /// Ensures that the given sha is downloaded
    pub fn fetch(&self) -> PackageResult<(Sha, PathBuf)> {
        // Check first if git is installed
        if Command::new("git")
            .arg("--version")
            .stdin(Stdio::null())
            .output()
            .is_err()
        {
            return Err(PackageError::Generic("git is not installed".to_string()));
        }
        // Get the SHA
        let sha = self.fetch_sha_git_ls_remote()?;

        let repo_fs_path = format_repo_to_fs_path(&self.repo, &sha);

        // Checkout repo if it does not exist already
        if !repo_fs_path.exists() {
            // Sparse checkout repo
            self.try_clone_sparse_checkout(&repo_fs_path)?;
            // Set the sparse checkout path
            self.try_sparse_checkout_init(&repo_fs_path)?;

            // if there's a given path, then set it for the sparse checkout
            if let Some(path) = self.path.as_ref() {
                // check the path exists
                self.check_path_exists(&repo_fs_path, path)?;
                // init the sparse checkout
                self.try_set_sparse_dir(&repo_fs_path, path)?;
            } else if self.repo.contains("MystenLabs/sui") || self.repo.contains("mystenlabs/sui") {
                // if no path is set, then what do we need to checkout
                // we need to checkout the whole repo
                // if it's Sui, we need to sparse checkout the /crates/sui-framework folder
                self.try_set_sparse_dir(&repo_fs_path, &PathBuf::from("crates/sui-framework"))?;
            } else {
                // if no path is set, then what do we need to checkout
                // we need to checkout the whole repo
                // if it's Sui, we need to sparse checkout the /crates/sui-framework folder
                self.try_set_sparse_dir(&repo_fs_path, &repo_fs_path)?;
            }

            self.try_checkout(&repo_fs_path)?;
        }

        Ok((sha, repo_fs_path))
    }

    fn check_path_exists(&self, repo_fs_path: &PathBuf, path: &PathBuf) -> PackageResult<()> {
        let cmd = Command::new("git")
            .current_dir(&repo_fs_path)
            .arg("ls-tree")
            .arg("-d")
            .arg("HEAD")
            .arg(&path)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| {
                PackageError::Generic(format!(
                    "Could not find the specified directory {}, error: {}",
                    path.display(),
                    e
                ))
            })?;

        if cmd.stdout.is_empty() {
            return Err(PackageError::Generic(format!(
                "The specified directory {} does not exist in the repository {}",
                path.display(),
                self.repo
            )));
        }

        Ok(())
    }

    fn try_checkout(&self, repo_fs_path: &PathBuf) -> PackageResult<()> {
        let cmd = Command::new("git")
            .arg("checkout")
            .arg("@")
            .current_dir(&repo_fs_path)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| {
                PackageError::Generic(format!(
                    "git checkout failed for {}, with error: {}",
                    repo_fs_path.display(),
                    e
                ))
            })?;

        Ok(())
    }

    fn try_set_sparse_dir(&self, repo_fs_path: &PathBuf, path: &PathBuf) -> PackageResult<()> {
        let cmd = Command::new("git")
            .arg("sparse-checkout")
            .arg("set")
            .arg(path)
            .current_dir(&repo_fs_path)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| {
                PackageError::Generic(format!(
                    "git sparse-checkout set failed for {}, with error: {}",
                    repo_fs_path.display(),
                    e
                ))
            })?;

        Ok(())
    }

    fn try_sparse_checkout_init(&self, repo_fs_path: &PathBuf) -> PackageResult<()> {
        // git sparse-checkout init --cone
        let cmd = Command::new("git")
            .arg("sparse-checkout")
            .arg("init")
            .arg("--cone")
            .current_dir(&repo_fs_path)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| {
                PackageError::Generic(format!(
                    "git sparse-checkout init failed for {}, with error: {}",
                    repo_fs_path.display(),
                    e
                ))
            })?;

        if !cmd.status.success() {
            return Err(PackageError::Generic(format!(
                "git sparse-checkout init failed for {}, with error: {}",
                repo_fs_path.display(),
                cmd.status
            )));
        }

        Ok(())
    }

    /// Try to clone git repository with sparse checkout
    fn try_clone_sparse_checkout(&self, repo_fs_path: &PathBuf) -> PackageResult<()> {
        let cmd = Command::new("git")
            .arg("clone")
            .arg("--sparse")
            .arg("--filter=blob:none")
            .arg("--no-checkout")
            .arg(&self.repo)
            .arg(&repo_fs_path)
            .stdin(Stdio::null())
            .output();

        if cmd.is_err() {
            return Err(PackageError::Generic(format!(
                "git clone failed for {}, with error: {}",
                self.repo,
                cmd.unwrap_err()
            )));
        }

        Ok(())
    }

    /// Find the SHA of the given commit/branch in the given repo
    fn fetch_sha_git_ls_remote(&self) -> PackageResult<String> {
        // git ls-remote https://github.com/user/repo.git refs/heads/main
        let cmd = Command::new("git")
            .arg("ls-remote")
            .arg(&self.repo)
            .arg(&self.rev.as_ref().unwrap_or(&"main".to_string()))
            .stdin(Stdio::null())
            .output();

        let output =
            cmd.map_err(|e| PackageError::Generic(format!("git ls-remote failed: {}", e)))?;

        let stdout = String::from_utf8(output.stdout)?;
        let sha = stdout
            .split_whitespace()
            .next()
            .ok_or(PackageError::Generic("No SHA found in output".to_string()))?;

        Ok(sha.to_string())
    }
}

/// Format the repository URL to a filesystem path
pub fn format_repo_to_fs_path(repo: &str, sha: &str) -> PathBuf {
    PathBuf::from(format!(
        "{}/{}_{sha}",
        *move_command_line_common::env::MOVE_HOME,
        url_to_file_name(repo)
    ))
}

/// Transform a repository URL into a directory name
// TODO: can we ditch the `https://___` prefix?
fn url_to_file_name(url: &str) -> String {
    regex::Regex::new(r"/|:|\.|@")
        .unwrap()
        .replace_all(url, "_")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tempfile::tempdir;

    fn setup_temp_dir() -> tempfile::TempDir {
        let temp_dir = tempdir().unwrap();
        // Set MOVE_HOME to the temp directory
        env::set_var("MOVE_HOME", temp_dir.path());
        temp_dir
    }

    #[test]
    fn test_sparse_checkout_specific_folder() {
        let _temp_dir = setup_temp_dir();

        // Create a git dependency with specific path
        let git_dep = GitDependency::<Pinned> {
            repo: "https://github.com/MystenLabs/sui.git".to_string(),
            rev: Some("main".to_string()),
            path: Some(PathBuf::from("crates/sui-framework")),
            phantom: std::marker::PhantomData,
        };

        // Fetch the dependency
        let (_, checkout_path) = git_dep.fetch().unwrap();

        // Verify only sui-framework was checked out
        assert!(checkout_path.join("crates/sui-framework").exists());
        assert!(!checkout_path.join("crates/sui-core").exists());
    }

    #[test]
    fn test_full_repository_checkout() {
        let _temp_dir = setup_temp_dir();

        // Create a git dependency without specific path
        let git_dep = GitDependency::<Pinned> {
            repo: "https://github.com/MystenLabs/sui.git".to_string(),
            rev: Some("main".to_string()),
            path: None,
            phantom: std::marker::PhantomData,
        };

        // Fetch the dependency
        let (_, checkout_path) = git_dep.fetch().unwrap();

        // Verify sui-framework was checked out
        assert!(checkout_path.join("crates/sui-framework").exists());
    }

    #[test]
    fn test_non_existent_path_error() {
        let _temp_dir = setup_temp_dir();

        // Create a git dependency with non-existent path
        let git_dep = GitDependency::<Pinned> {
            repo: "https://github.com/MystenLabs/sui.git".to_string(),
            rev: Some("main".to_string()),
            path: Some(PathBuf::from("non_existent_folder")),
            phantom: std::marker::PhantomData,
        };

        // Fetch should fail
        let result = git_dep.fetch();
        assert!(result.is_err());
    }

    #[test]
    fn test_non_sui_repository_full_checkout() {
        let _temp_dir = setup_temp_dir();

        // Create a git dependency for a non-Sui repository
        let git_dep = GitDependency::<Pinned> {
            repo: "https://github.com/MystenLabs/mvr".to_string(),
            rev: Some("9114043".to_string()),
            path: Some(PathBuf::from("packages/mvr")),
            phantom: std::marker::PhantomData,
        };

        // Fetch the dependency
        let (_, checkout_path) = git_dep.fetch().unwrap();

        assert!(checkout_path.join("packages/mvr").exists());
    }
}
