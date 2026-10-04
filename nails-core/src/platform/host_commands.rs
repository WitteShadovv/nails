// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Resolving host tools from a per-platform search list.
//!
//! nails runs as root and shells out to a handful of host tools (`systemctl`,
//! `loginctl`, `cp`, `nixos-rebuild`, …). Those must never be resolved from the
//! caller's `PATH`, which a lower-privileged invoker can point into a profile it
//! controls. [`HostCommands`] resolves a tool to an absolute path from a fixed,
//! ordered search list — the one a [`Platform`](super::Platform) exposes through
//! [`host_command_dirs`](super::Platform::host_command_dirs) — and, when running
//! as root, rejects a candidate that is not trusted to be run as root.
//!
//! # Trust
//!
//! A resolved executable is trusted only when it is root-owned and not writable
//! by group or other, and its parent directory is root-owned and either not
//! group/other-writable or carries the sticky bit. The sticky exception covers
//! the `/nix/store` convention (mode `1775`, owner `root`): the store directory
//! is group-writable by the build group, but the sticky bit stops anyone but a
//! file's owner (here `root`) from replacing or removing it, so a store path is
//! still safe to execute.
//!
//! The trust check is enforced only when nails itself runs as root (its real
//! operating mode); run as an unprivileged user — on a developer box, or under
//! the test suite — host tools are owned by that user, so enforcing
//! root-ownership would reject every candidate. There the check is advisory: the
//! first executable candidate is used and an untrusted one is logged at debug.

use crate::{NailsError, Result};
use std::cell::RefCell;
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Group- and other-write permission bits.
const GROUP_OTHER_WRITE: u32 = 0o022;
/// The sticky bit on a directory.
const STICKY_BIT: u32 = 0o1000;

/// Whether nails itself is running as root.
///
/// The trust check is enforced only in that case; see the [module docs](self).
pub(crate) fn running_as_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// Whether `path` is a regular file with an execute bit set.
pub(crate) fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

/// Ownership and permission facts the trust check reads from a path.
#[derive(Debug, Clone, Copy)]
struct PathFacts {
    uid: u32,
    mode: u32,
}

impl PathFacts {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            uid: metadata.uid(),
            mode: metadata.permissions().mode(),
        }
    }
}

/// The trust rule over the resolved file's and its parent directory's facts.
///
/// Split out as a pure function so it can be unit-tested against synthesized
/// metadata — the sandbox runs unprivileged and cannot create root-owned files.
fn facts_are_trusted(file: PathFacts, parent: PathFacts) -> bool {
    let file_ok = file.uid == 0 && file.mode & GROUP_OTHER_WRITE == 0;
    let parent_ok =
        parent.uid == 0 && (parent.mode & GROUP_OTHER_WRITE == 0 || parent.mode & STICKY_BIT != 0);
    file_ok && parent_ok
}

/// Whether the executable at `path` is trusted to be run as root.
///
/// Reads the real metadata of the file (following symlinks) and of its parent
/// directory and applies [`facts_are_trusted`]. A path whose metadata cannot be
/// read is untrusted.
pub(crate) fn is_trusted_executable(path: &Path) -> bool {
    let Ok(file) = std::fs::metadata(path) else {
        return false;
    };
    let Some(parent) = path.parent() else {
        return false;
    };
    let Ok(parent) = std::fs::metadata(parent) else {
        return false;
    };
    facts_are_trusted(
        PathFacts::from_metadata(&file),
        PathFacts::from_metadata(&parent),
    )
}

/// Resolves host tools from a fixed, ordered search list.
///
/// Build one from a platform's [`host_command_dirs`](super::Platform::host_command_dirs)
/// before any mount and resolve each tool by name; resolved paths are cached.
#[derive(Debug)]
pub struct HostCommands {
    dirs: Vec<PathBuf>,
    enforce_trust: bool,
    cache: RefCell<HashMap<String, PathBuf>>,
}

impl HostCommands {
    /// A resolver over `dirs`, searched in order.
    ///
    /// Trust enforcement follows [`running_as_root`]: active when nails runs as
    /// root, advisory otherwise.
    pub fn new<I, P>(dirs: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        Self {
            dirs: dirs.into_iter().map(|d| d.as_ref().to_path_buf()).collect(),
            enforce_trust: running_as_root(),
            cache: RefCell::new(HashMap::new()),
        }
    }

    /// Override trust enforcement (tests pin it regardless of the caller's uid).
    #[must_use]
    pub fn with_trust_enforcement(mut self, enforce: bool) -> Self {
        self.enforce_trust = enforce;
        self
    }

    /// The search directories, in order.
    pub fn dirs(&self) -> &[PathBuf] {
        &self.dirs
    }

    /// Resolve `name` to the first trusted, executable candidate.
    ///
    /// Returns a `NotFound` error naming the searched directories when no
    /// candidate qualifies.
    pub fn resolve(&self, name: &str) -> Result<PathBuf> {
        if let Some(hit) = self.cache.borrow().get(name) {
            return Ok(hit.clone());
        }

        for dir in &self.dirs {
            let candidate = dir.join(name);
            if !is_executable_file(&candidate) {
                continue;
            }
            if self.enforce_trust && !is_trusted_executable(&candidate) {
                tracing::warn!(
                    candidate = %candidate.display(),
                    "skipping host tool candidate that failed the root-trust check"
                );
                continue;
            }
            self.cache
                .borrow_mut()
                .insert(name.to_string(), candidate.clone());
            return Ok(candidate);
        }

        Err(NailsError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{name} not found in {}", self.searched_dirs()),
        )))
    }

    fn searched_dirs(&self) -> String {
        self.dirs
            .iter()
            .map(|dir| dir.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn write_executable(path: &Path) {
        fs::write(path, "#!/bin/sh\n").unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[test]
    fn resolve_picks_the_first_executable_in_search_order() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("sbin");
        let second = temp.path().join("bin");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        // Only the second dir holds the tool, so resolution must fall through to it.
        write_executable(&second.join("systemctl"));

        let resolver = HostCommands::new([&first, &second]).with_trust_enforcement(false);
        assert_eq!(
            resolver.resolve("systemctl").unwrap(),
            second.join("systemctl")
        );
    }

    #[test]
    fn resolve_skips_non_executable_candidates() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("bin");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("systemctl"), "not executable").unwrap();

        let resolver = HostCommands::new([&dir]).with_trust_enforcement(false);
        assert!(resolver.resolve("systemctl").is_err());
    }

    #[test]
    fn resolve_missing_tool_reports_the_searched_dirs() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("usr-sbin");
        let second = temp.path().join("usr-bin");

        let resolver = HostCommands::new([&first, &second]).with_trust_enforcement(false);
        let err = resolver.resolve("no-such-tool").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("no-such-tool"), "{message}");
        assert!(message.contains(&first.display().to_string()), "{message}");
        assert!(message.contains(&second.display().to_string()), "{message}");
    }

    #[test]
    fn enforced_trust_skips_a_candidate_this_unprivileged_user_owns() {
        // The sandbox runs unprivileged, so a file it writes is owned by the
        // caller, not root: with enforcement on it must be rejected as untrusted.
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("bin");
        fs::create_dir_all(&dir).unwrap();
        write_executable(&dir.join("systemctl"));

        let enforced = HostCommands::new([&dir]).with_trust_enforcement(true);
        assert!(
            enforced.resolve("systemctl").is_err(),
            "an unprivileged-owned candidate must fail the root-trust check"
        );

        let advisory = HostCommands::new([&dir]).with_trust_enforcement(false);
        assert!(advisory.resolve("systemctl").is_ok());
    }

    #[test]
    fn trust_rejects_a_world_writable_file() {
        assert!(!facts_are_trusted(
            PathFacts {
                uid: 0,
                mode: 0o777,
            },
            PathFacts {
                uid: 0,
                mode: 0o755,
            },
        ));
    }

    #[test]
    fn trust_rejects_a_file_not_owned_by_root() {
        assert!(!facts_are_trusted(
            PathFacts {
                uid: 1000,
                mode: 0o755,
            },
            PathFacts {
                uid: 0,
                mode: 0o755,
            },
        ));
    }

    #[test]
    fn trust_accepts_a_plain_root_owned_file_and_parent() {
        assert!(facts_are_trusted(
            PathFacts {
                uid: 0,
                mode: 0o755,
            },
            PathFacts {
                uid: 0,
                mode: 0o755,
            },
        ));
    }

    #[test]
    fn trust_accepts_a_sticky_group_writable_nix_store_parent() {
        // /nix/store is mode 1775 root:nixbld: group-writable but sticky, so a
        // root-owned store path under it is still safe to execute.
        assert!(facts_are_trusted(
            PathFacts {
                uid: 0,
                mode: 0o555,
            },
            PathFacts {
                uid: 0,
                mode: 0o1775,
            },
        ));
    }

    #[test]
    fn trust_rejects_a_group_writable_non_sticky_parent() {
        assert!(!facts_are_trusted(
            PathFacts {
                uid: 0,
                mode: 0o755,
            },
            PathFacts {
                uid: 0,
                mode: 0o775,
            },
        ));
    }

    #[test]
    fn trust_rejects_a_parent_not_owned_by_root() {
        assert!(!facts_are_trusted(
            PathFacts {
                uid: 0,
                mode: 0o755,
            },
            PathFacts {
                uid: 1000,
                mode: 0o755,
            },
        ));
    }
}
