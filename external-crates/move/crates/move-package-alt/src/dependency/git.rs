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
use tracing::debug;

use crate::errors::{GitError, GitErrorKind, Located, PackageError, PackageResult};

use super::{DependencySet, Pinned, Unpinned};

type Sha = String;

// TODO: custom deserialization to verify pinnedness for pinned deps?
#[derive(Debug, Serialize, Deserialize)]
#[derive_where(Clone)]
pub struct GitDependency<P = Unpinned> {
    /// The repository containing the dependency
    #[serde(rename = "git")]
    repo: Located<String>,

    /// The git commit-ish for the dep; guaranteed to be a commit if [P] is [Pinned].
    #[serde(default)]
    rev: Option<Located<String>>,

    /// The path within the repository
    #[serde(default)]
    path: Option<Located<PathBuf>>,

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

        git_dep.rev = Some(Located::new_for_testing(sha));

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

        let repo_fs_path = format_repo_to_fs_path(self.repo.get_ref(), &sha);
        debug!("Repo path on disk: {:?}", repo_fs_path.display());

        // Checkout repo if it does not exist already
        if !repo_fs_path.exists() {
            // Sparse checkout repo
            self.try_clone_sparse_checkout(&repo_fs_path)?;
            // Set the sparse checkout path
            self.try_sparse_checkout_init(&repo_fs_path)?;

            // if there's a given path, then set it for the sparse checkout
            let path = if let Some(path) = self.path.as_ref() {
                path.get_ref()
            } else {
                // we need to checkout the whole repo
                &repo_fs_path
            };

            debug!("Path to checkout: {:?}", path);

            self.try_set_sparse_dir(&repo_fs_path, &path)?;

            self.try_checkout_at_sha(&repo_fs_path, &sha)?;

            // check it is a Move project.
            self.check_is_move_project(&repo_fs_path, path)?;
        } else {
            // check if the repo is dirty and fail if it is
            let cmd = Command::new("git")
                .arg("status")
                .arg("--porcelain")
                .current_dir(&repo_fs_path)
                .stdin(Stdio::null())
                .output()
                .map_err(|e| {
                    PackageError::Generic(format!("Could not execute git status command, {e}",))
                })?;

            if !cmd.stdout.is_empty() {
                return Err(PackageError::Git(GitError {
                    kind: GitErrorKind::Dirty(repo_fs_path.display().to_string()),
                    span: Some(self.repo.span()),
                    handle: self.repo.file(),
                }));
            }
        }

        Ok((sha, repo_fs_path))
    }

    /// This function checks if the given path in this GitDependency has a Move.toml file.
    /// It needs to be called after the checkout, as otherwise it will not be able to find the
    /// file.
    fn check_is_move_project(&self, repo_fs_path: &PathBuf, path: &PathBuf) -> PackageResult<()> {
        let move_toml_path = repo_fs_path.join(path).join("Move.toml");
        debug!("Move toml path: {:?}", move_toml_path.display());
        let cmd = Command::new("git")
            .current_dir(&repo_fs_path)
            .arg("ls-tree")
            .arg("HEAD")
            .arg(&move_toml_path)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| {
                PackageError::Generic(format!("Could not execute git ls-tree command",))
            })?;

        if cmd.stdout.is_empty() {
            if let Some(path) = self.path.as_ref() {
                return Err(PackageError::Git(GitError {
                    kind: GitErrorKind::NotMoveProject(
                        "path".to_string(),
                        path.get_ref().display().to_string(),
                    ),
                    span: Some(path.span()),
                    handle: path.file(),
                }));
            } else {
                return Err(PackageError::Git(GitError {
                    kind: GitErrorKind::NotMoveProject(
                        "repo".to_string(),
                        self.repo.get_ref().to_string(),
                    ),
                    span: Some(self.repo.span()),
                    handle: self.repo.file(),
                }));
            };
        }

        Ok(())
    }

    /// Check out the given SHA in the given repo
    fn try_checkout_at_sha(&self, repo_fs_path: &PathBuf, sha: &str) -> PackageResult<()> {
        debug!("Checking out with SHA: {sha}");
        let cmd = Command::new("git")
            .arg("checkout")
            .arg(sha)
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
            .arg(&self.repo.get_ref())
            .arg(&repo_fs_path)
            .stdin(Stdio::null())
            .output();

        if cmd.is_err() {
            return Err(PackageError::Generic(format!(
                "git clone failed for {}, with error: {}",
                self.repo.get_ref(),
                cmd.unwrap_err()
            )));
        }

        Ok(())
    }

    /// Find the SHA of the given commit/branch in the given repo
    fn fetch_sha_git_ls_remote(&self) -> PackageResult<String> {
        let rev = match self.rev.as_ref() {
            Some(r) if check_is_commit_sha(&r.get_ref()) => return Ok(r.get_ref().to_string()),
            Some(r) => r.get_ref(),
            None => &"main".to_string(),
        };

        // git ls-remote https://github.com/user/repo.git refs/heads/main
        let cmd = Command::new("git")
            .arg("ls-remote")
            .arg(&self.repo.get_ref())
            .arg(rev)
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

/// Format the repository URL to a filesystem path based on the SHA
pub fn format_repo_to_fs_path(repo: &str, sha: &str) -> PathBuf {
    PathBuf::from(format!(
        "{}/{}_{sha}",
        *move_command_line_common::env::MOVE_HOME,
        url_to_file_name(repo)
    ))
}

fn check_is_commit_sha(input: &str) -> bool {
    let len = input.len();
    // Must be all lowercase hex and 5 to 40 characters
    len >= 5
        && len <= 40
        && input
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
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
    use std::fs;
    use std::path::Path;
    use tempfile::{tempdir, TempDir};

    fn setup_temp_dir() -> TempDir {
        let temp_dir = tempdir().unwrap();
        // Set MOVE_HOME to the temp directory
        env::set_var("MOVE_HOME", temp_dir.path());
        temp_dir
    }

    /// Sets up a test Move project with git repository
    /// It returns the temporary directory, the root path of the project, the first commit sha, and
    /// and the second commit sha.
    pub fn setup_test_move_project() -> (TempDir, PathBuf, String, String) {
        // Create a temporary directory
        let temp_dir = tempdir().unwrap();
        let mut root_path = temp_dir.path().to_path_buf();
        root_path.push("test_move_project");

        // Create the root directory for the Move project
        fs::create_dir_all(&root_path).unwrap();

        // Initialize git repository
        Command::new("git")
            .args(["init"])
            .current_dir(&root_path)
            .output()
            .unwrap();

        // Configure git user for commits
        Command::new("git")
            .args(["config", "user.name", "Test User"])
            .current_dir(&root_path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.email", "test@example.com"])
            .current_dir(&root_path)
            .output()
            .unwrap();

        // Create directory structure
        let packages_path = root_path.join("packages");
        let sui_path = packages_path.join("sui");
        let mvr_path = packages_path.join("mvr");
        fs::create_dir_all(&sui_path).unwrap();
        fs::create_dir_all(&mvr_path).unwrap();

        // Create initial Move.toml files
        let sui_toml = create_initial_move_toml("sui");
        let mvr_toml = create_initial_move_toml("mvr");
        fs::write(sui_path.join("Move.toml"), &sui_toml).unwrap();
        fs::write(mvr_path.join("Move.toml"), &mvr_toml).unwrap();

        // Initial commit
        Command::new("git")
            .args(["add", "."])
            .current_dir(&root_path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "Initial commit"])
            .current_dir(&root_path)
            .output()
            .unwrap();

        // Update Move.toml with dependencies
        let mvr_toml = create_updated_move_toml("mvr");
        fs::write(mvr_path.join("Move.toml"), &mvr_toml).unwrap();

        // Commit updates
        Command::new("git")
            .args(["add", "."])
            .current_dir(&root_path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "Add dependencies"])
            .current_dir(&root_path)
            .output()
            .unwrap();

        // Get commits SHA
        let commits = Command::new("git")
            .args(["log", "--pretty=format:%H"])
            .current_dir(&root_path)
            .output()
            .unwrap();
        let commits = String::from_utf8_lossy(&commits.stdout);
        let commits: Vec<_> = commits.lines().collect();

        (
            temp_dir,
            root_path,
            commits[1].to_string(),
            commits[0].to_string(),
        )
    }

    fn create_initial_move_toml(name: &str) -> String {
        format!(
            r#"[package]
name = "{}"
edition = "2024.beta"
license = "Apache-2.0"
authors = ["Move Team"]
flavor = "vanilla"

[environments]
mainnet = "35834a8a"
testnet = "4c78adac"
"#,
            name
        )
    }

    fn create_updated_move_toml(name: &str) -> String {
        format!(
            r#"[package]
name = "{}"
edition = "2024.beta"
license = "Apache-2.0"
authors = ["Move Team"]
flavor = "vanilla"

[environments]
mainnet = "35834a8a"
testnet = "4c78adac"

[dependencies]
foo = {{ git = "https://example.com/foo.git", rev = "releases/v1", rename-from = "Foo", override = true}}
qwer = {{ r.mvr = "@pkg/qwer" }}

[dep-overrides]
# used to override dependencies for specific environments
mainnet.foo = {{ 
    git = "https://example.com/foo.git", 
    original-id = "0x6ba0cc1a418ff3bebce0ff9ec3961e6cc794af9bc3a4114fb138d00a4c9274bb", 
    published-at = "0x6ba0cc1a418ff3bebce0ff9ec3961e6cc794af9bc3a4114fb138d00a4c9274bb", 
    use-environment = "mainnet_alpha" 
}}

[dep-overrides.mainnet.bar]
git = "https://example.com/bar.git"
original-id = "0x12g0cc1a418ff3bebce0ff9ec3961e6cc794af9bc3a4114fb138d00a4c9274bb"
published-at = "0x12ga0cc1a418ff3bebce0ff9ec3961e6cc794af9bc3a4114fb138d00a4c9274bb"
use-environment = "mainnet_beta"
"#,
            name
        )
    }

    #[test]
    fn test_sparse_checkout_folder() {
        let (_temp_folder, fs_repo, first_sha, second_sha) = setup_test_move_project();
        let temp_dir = setup_temp_dir();
        let fs_repo = fs_repo.to_str().unwrap();

        // Pass in a branch name
        let git_dep = GitDependency::<Pinned> {
            repo: Located::new_for_testing(fs_repo.to_string()),
            rev: Some(Located::new_for_testing("main".to_string())),
            path: Some(Located::new_for_testing(PathBuf::from("packages/sui"))),
            phantom: std::marker::PhantomData,
        };

        // Fetch the dependency
        let (sha, checkout_path) = git_dep.fetch().unwrap();

        // Verify the SHA is correct
        assert_eq!(sha, second_sha);

        // Verify only packages/sui was checked out
        assert!(checkout_path.join("packages/sui").exists());
        assert!(!checkout_path.join("packages/mvr").exists());

        let (_temp_folder, fs_repo, first_sha, second_sha) = setup_test_move_project();
        let fs_repo = fs_repo.to_str().unwrap();
        // Pass in a commit SHA
        let git_dep = GitDependency::<Pinned> {
            repo: Located::new_for_testing(fs_repo.to_string()),
            rev: Some(Located::new_for_testing(first_sha.to_string())),
            path: Some(Located::new_for_testing(PathBuf::from("packages/mvr"))),
            phantom: std::marker::PhantomData,
        };

        // Fetch the dependency
        let (sha, checkout_path) = git_dep.fetch().unwrap();

        // Verify the SHA is correct
        assert_eq!(sha, first_sha);

        // Verify only packages/mvr was checked out
        assert!(checkout_path.join("packages/mvr").exists());
        assert!(!checkout_path.join("packages/sui").exists());
    }

    #[test]
    fn test_wrong_sha() {
        let (_temp_folder, fs_repo, first_sha, second_sha) = setup_test_move_project();
        let temp_dir = setup_temp_dir();
        let fs_repo = fs_repo.to_str().unwrap();

        let git_dep = GitDependency::<Pinned> {
            repo: Located::new_for_testing(fs_repo.to_string()),
            rev: Some(Located::new_for_testing("912saTsvc".to_string())),
            path: Some(Located::new_for_testing(PathBuf::from("packages/sui"))),
            phantom: std::marker::PhantomData,
        };

        // Fetch the dependency
        let result = git_dep.fetch();
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_branch_name() {
        let (_temp_folder, fs_repo, first_sha, second_sha) = setup_test_move_project();
        let temp_dir = setup_temp_dir();
        let fs_repo = fs_repo.to_str().unwrap();

        let git_dep = GitDependency::<Pinned> {
            repo: Located::new_for_testing(fs_repo.to_string()),
            rev: Some(Located::new_for_testing("test".to_string())),
            path: Some(Located::new_for_testing(PathBuf::from("packages/sui"))),
            phantom: std::marker::PhantomData,
        };

        // Fetch the dependency
        let result = git_dep.fetch();
        assert!(result.is_err());
    }

    #[test]
    fn test_full_repository_checkout_no_move_toml_in_root() {
        let (_temp_folder, fs_repo, first_sha, second_sha) = setup_test_move_project();
        let temp_dir = setup_temp_dir();
        let fs_repo = fs_repo.to_str().unwrap();

        let git_dep = GitDependency::<Pinned> {
            repo: Located::new_for_testing(fs_repo.to_string()),
            rev: Some(Located::new_for_testing("main".to_string())),
            path: None,
            phantom: std::marker::PhantomData,
        };

        // The move project from setup has no root Move.toml file, so this should fail
        let result = git_dep.fetch();
        assert!(result.is_err());
    }

    #[test]
    fn test_non_existent_path_error() {
        let (_temp_folder, fs_repo, first_sha, second_sha) = setup_test_move_project();
        let temp_dir = setup_temp_dir();
        let fs_repo = fs_repo.to_str().unwrap();

        let git_dep = GitDependency::<Pinned> {
            repo: Located::new_for_testing(fs_repo.to_string()),
            rev: Some(Located::new_for_testing("main".to_string())),
            path: Some(Located::new_for_testing(PathBuf::from(
                "non_existent_folder",
            ))),
            phantom: std::marker::PhantomData,
        };

        // Fetch should fail
        let result = git_dep.fetch();
        assert!(result.is_err());
    }
}
