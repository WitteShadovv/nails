// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Mount-namespace pre-flight check
//!
//! Validates that NAILS runs in PID 1's mount namespace with shared root
//! propagation before any overlay is mounted.

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result};
use std::os::unix::fs::MetadataExt;

/// Identity of a mount namespace: the `(st_dev, st_ino)` of its `nsfs` node.
///
/// Two processes share a mount namespace iff these pairs are equal, which is how
/// the kernel's own tooling compares `/proc/<pid>/ns/mnt` links.
type NamespaceId = (u64, u64);

/// This process's mount-namespace link.
const SELF_NS: &str = "/proc/self/ns/mnt";
/// PID 1's (the init/host) mount-namespace link.
const INIT_NS: &str = "/proc/1/ns/mnt";
/// The mount table, which carries per-mount propagation tags.
const MOUNTINFO: &str = "/proc/self/mountinfo";

/// Pre-flight check that NAILS shares PID 1's mount namespace with shared `/`
/// propagation.
///
/// # Security
///
/// Every overlay NAILS stacks is a plain `mount(2)` in the caller's mount
/// namespace. The no-leak invariant — the rest of the running system sees the
/// hidden environment instead of the decoy disk — only holds if those mounts
/// land in the init namespace and propagate out of it. If `activate` runs under
/// `unshare -m`, from a unit with `MountFlags=private`, or inside a container,
/// the overlays are confined to a private namespace and every other process
/// keeps reading the real decoy disk. Nothing else verifies this, so the check
/// is **fail-closed**: anything it cannot positively prove is a `Fail`.
///
/// # Rationale
///
/// - **Namespace identity**: `(st_dev, st_ino)` of `/proc/self/ns/mnt` must
///   equal that of `/proc/1/ns/mnt`.
/// - **Root propagation**: the `/` line of `/proc/self/mountinfo` must carry a
///   `shared:` tag, otherwise new mounts under `/` do not propagate to peers.
///
/// # Portability
///
/// The comparison reads `/proc` directly and makes no NixOS-specific
/// assumptions, so the forthcoming non-NixOS backends reuse it unchanged.
#[derive(Debug, Default)]
pub struct MountNamespaceCheck;

impl MountNamespaceCheck {
    /// Create a new `MountNamespaceCheck`.
    pub fn new() -> Self {
        Self
    }
}

/// Read the `(st_dev, st_ino)` identity of a namespace link.
///
/// `metadata` follows the magic symlink to the backing `nsfs` node, so the pair
/// identifies the namespace itself rather than the `/proc/<pid>/ns` entry.
fn namespace_id(path: &str) -> std::io::Result<NamespaceId> {
    let metadata = std::fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

/// Pure seam: do two namespace identities refer to the same namespace?
fn namespaces_match(self_ns: NamespaceId, init_ns: NamespaceId) -> bool {
    self_ns == init_ns
}

/// Pure seam: does the `/` line of a mountinfo buffer carry a `shared:` tag?
///
/// This parses mountinfo locally instead of going through the canonical
/// [`crate::filesystem::mountinfo`] parser: that parser intentionally discards
/// the optional fields (`tokens[6..sep]`), and the `shared:` propagation tag
/// lives exactly there. The format is, per proc(5):
///
/// ```text
/// id parent dev root mount_point opts [optional...] - fstype source super_opts
/// (0) (1)  (2)  (3)      (4)     (5)  (6..sep)     (sep)
/// ```
///
/// Any mount whose mount point is `/` and whose optional fields include a token
/// starting with `shared:` means the root is shared-propagation.
fn root_has_shared_propagation(mountinfo: &str) -> bool {
    for line in mountinfo.lines() {
        let tokens: Vec<&str> = line.split(' ').filter(|t| !t.is_empty()).collect();
        let Some(sep) = tokens.iter().position(|&t| t == "-") else {
            continue;
        };
        // Below the separator there must be at least id..opts (indices 0..=5).
        if sep < 6 {
            continue;
        }
        // The mount point is a fixed position; `/` is never octal-escaped.
        if tokens[4] != "/" {
            continue;
        }
        if tokens[6..sep].iter().any(|t| t.starts_with("shared:")) {
            return true;
        }
    }
    false
}

impl<F: Filesystem> PreFlightCheck<F> for MountNamespaceCheck {
    fn name(&self) -> &'static str {
        "mount-namespace"
    }

    fn description(&self) -> &'static str {
        "Validates NAILS runs in PID 1's mount namespace with shared root propagation"
    }

    fn run(&self, _fs: &F) -> Result<CheckResult> {
        // This check reads the real `/proc` rather than the `Filesystem`
        // abstraction, so under a test binary there is no host namespace to
        // compare against. Skip it there, like every other host-touching path,
        // so mock-driven preflight tests stay hermetic; a real deployment never
        // trips this guard.
        if crate::runtime_safety::should_skip_host_interaction() {
            return Ok(CheckResult::Pass(
                "Mount-namespace check skipped under the test runtime".into(),
            ));
        }

        // Fail-closed: if we cannot read our own namespace, we cannot reason
        // about where the overlays will land.
        let self_ns = match namespace_id(SELF_NS) {
            Ok(id) => id,
            Err(e) => {
                return Ok(CheckResult::fail(format!(
                    "Cannot read {SELF_NS} to verify the mount namespace ({e}). \
                     Run activation as root from a host shell."
                )));
            }
        };

        // Fail-closed: without PID 1's namespace we cannot prove we share it.
        // This typically means the check lacks the privilege to inspect PID 1
        // (run as root) or NAILS is isolated from it (a container).
        let init_ns = match namespace_id(INIT_NS) {
            Ok(id) => id,
            Err(e) => {
                return Ok(CheckResult::fail(format!(
                    "Cannot read {INIT_NS} to compare against PID 1's mount namespace ({e}). \
                     Run activation as root from a host shell, not inside a container."
                )));
            }
        };

        if !namespaces_match(self_ns, init_ns) {
            return Ok(CheckResult::fail(
                "NAILS is running in a private mount namespace, not PID 1's. Overlay mounts \
                 would stay invisible to the rest of the system and the decoy disk would keep \
                 showing through. Run activation from a host root shell - not under `unshare -m`, \
                 a service with MountFlags=private, or a container."
                    .to_string(),
            ));
        }

        // Fail-closed: without the mount table we cannot confirm propagation.
        let mountinfo = match std::fs::read_to_string(MOUNTINFO) {
            Ok(content) => content,
            Err(e) => {
                return Ok(CheckResult::fail(format!(
                    "Cannot read {MOUNTINFO} to verify root mount propagation ({e}). \
                     Run activation as root from a host shell."
                )));
            }
        };

        if !root_has_shared_propagation(&mountinfo) {
            return Ok(CheckResult::fail(
                "The root mount `/` does not have shared propagation, so overlay mounts would \
                 not reach the rest of the system. Make `/` shared (`mount --make-rshared /`) \
                 and run activation from a host root shell - not under `unshare -m` or a service \
                 with MountFlags=private."
                    .to_string(),
            ));
        }

        Ok(CheckResult::Pass(
            "Running in PID 1's mount namespace with shared root propagation".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;

    #[test]
    fn test_mount_namespace_check_default_trait() {
        let _check = MountNamespaceCheck;
    }

    #[test]
    fn test_mount_namespace_check_trait_metadata() {
        let check = MountNamespaceCheck::new();

        assert_eq!(
            <MountNamespaceCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "mount-namespace"
        );
        assert_eq!(
            <MountNamespaceCheck as PreFlightCheck<MockFilesystem>>::description(&check),
            "Validates NAILS runs in PID 1's mount namespace with shared root propagation"
        );
    }

    #[test]
    fn test_namespaces_match_equal_pairs() {
        assert!(namespaces_match((4, 0xf00), (4, 0xf00)));
    }

    #[test]
    fn test_namespaces_match_differing_inode() {
        assert!(!namespaces_match((4, 0xf00), (4, 0xf01)));
    }

    #[test]
    fn test_namespaces_match_differing_device() {
        assert!(!namespaces_match((4, 0xf00), (5, 0xf00)));
    }

    #[test]
    fn test_root_shared_propagation_detected() {
        let mountinfo = "23 28 0:21 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n";
        assert!(root_has_shared_propagation(mountinfo));
    }

    #[test]
    fn test_root_private_propagation_not_detected() {
        // A private root (e.g. after `unshare -m`) carries no propagation tag.
        let mountinfo = "23 28 0:21 / / rw,relatime - ext4 /dev/sda1 rw\n";
        assert!(!root_has_shared_propagation(mountinfo));
    }

    #[test]
    fn test_shared_tag_on_non_root_is_ignored() {
        let mountinfo = concat!(
            "23 28 0:21 / / rw,relatime - ext4 /dev/sda1 rw\n",
            "30 23 0:30 / /home rw,relatime shared:5 - ext4 /dev/sda2 rw\n",
        );
        assert!(!root_has_shared_propagation(mountinfo));
    }

    #[test]
    fn test_any_shared_root_overmount_counts() {
        // The topmost `/` is an overlay with shared propagation.
        let mountinfo = concat!(
            "23 28 0:21 / / rw,relatime - ext4 /dev/sda1 rw\n",
            "40 23 0:40 / / rw,relatime shared:9 - overlay overlay rw\n",
        );
        assert!(root_has_shared_propagation(mountinfo));
    }

    #[test]
    fn test_malformed_lines_are_skipped() {
        let mountinfo = concat!(
            "garbage line with no separator\n",
            "a - b\n",
            "\n",
            "23 28 0:21 / / rw,relatime shared:2 - ext4 /dev/sda1 rw\n",
        );
        // The one well-formed shared `/` line still decides the result.
        assert!(root_has_shared_propagation(mountinfo));
    }

    #[test]
    fn test_master_only_root_is_not_shared() {
        // A slave mount advertises `master:` but not `shared:`.
        let mountinfo = "23 28 0:21 / / rw,relatime master:1 - ext4 /dev/sda1 rw\n";
        assert!(!root_has_shared_propagation(mountinfo));
    }
}
