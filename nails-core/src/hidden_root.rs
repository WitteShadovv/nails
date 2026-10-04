// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Hidden-root attach gate.
//!
//! NAILS must write nothing — not a log line, not a staged `configuration.nix`,
//! not a cleaned history file — unless the hidden root is positively *attached*:
//! a real mounted filesystem, separate from `/`, that holds the hidden
//! environment. The binary's own directory is only a hint at where that volume
//! lives; a hint is not a mount. Treating a path that merely *exists* as the
//! hidden volume is what let `verify`, `status` and friends drop identifying
//! logs into a download directory or the decoy, and what let `activate` stage
//! files onto an unmounted mount point on a persistent disk.
//!
//! [`HiddenRoot::verify_attached`] is the single gate every write path consults.
//! It answers one question — is this path a mounted hidden volume we may write
//! to? — and returns a reason when the answer is no, so the caller can degrade
//! to stderr-only logging or refuse the operation with a message the operator
//! can act on.

use crate::{Filesystem, Result};
use std::path::Path;

// The marker names come from the artifact registry, the single source of what
// NAILS writes, so the attach gate and the registry can never disagree about the
// names that identify an initialised hidden root.

/// State-file marker that marks a directory as an initialised NAILS hidden root.
pub const MARKER_STATE_FILE: &str = crate::artifacts::STATE_FILE_NAME;

/// Config directory (holding `nails.toml`) relative to the hidden root.
pub const MARKER_CONFIG_DIR: &str = crate::artifacts::CONFIG_DIR_NAME;
/// Config-file name inside [`MARKER_CONFIG_DIR`].
pub const MARKER_CONFIG_FILE: &str = crate::artifacts::CONFIG_FILE_NAME;

/// Whether a candidate hidden root is a mounted hidden volume we may write to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachState {
    /// The path is a mounted filesystem distinct from `/` (and, when required,
    /// carries a NAILS marker). Writing to it is safe.
    Attached,
    /// The path is not usable as the hidden root. The string explains why, for
    /// an operator-facing message or a degradation log line.
    Unattached(String),
}

impl AttachState {
    /// `true` only for [`AttachState::Attached`].
    pub fn is_attached(&self) -> bool {
        matches!(self, AttachState::Attached)
    }

    /// The reason a path was judged unattached, if it was.
    pub fn reason(&self) -> Option<&str> {
        match self {
            AttachState::Attached => None,
            AttachState::Unattached(reason) => Some(reason.as_str()),
        }
    }
}

/// The attach gate.
pub struct HiddenRoot;

impl HiddenRoot {
    /// Decide whether `root` is a mounted hidden volume NAILS may write to.
    ///
    /// The checks, in order:
    ///
    /// 1. **Present** — the path must exist. A missing mount point is nothing to
    ///    write to.
    /// 2. **Its own filesystem** — `root`'s device id must differ from `/`'s. An
    ///    unmounted mount point reports the device of the disk it sits on (`/` or
    ///    one of its filesystems); a mounted volume reports its own. This is the
    ///    check that distinguishes "the directory exists" from "something is
    ///    mounted here", so a bare directory on the system disk never passes.
    ///    A subdirectory of an attached volume shares the volume's device and so
    ///    passes too.
    /// 3. **A NAILS volume** — when `require_marker` is set, the root must carry
    ///    a marker (`state.json` or `config/nails.toml`). This keeps a write
    ///    command from treating some *other* mounted volume that happens to sit
    ///    at the configured path as the hidden environment. `init` creates the
    ///    marker, so it calls with `require_marker` cleared.
    ///
    /// Returns [`AttachState::Attached`] only when every applicable check passes;
    /// otherwise [`AttachState::Unattached`] carrying the first failing reason.
    pub fn verify_attached<F: Filesystem>(
        fs: &F,
        root: &Path,
        require_marker: bool,
    ) -> Result<AttachState> {
        if root.as_os_str().is_empty() {
            return Ok(AttachState::Unattached(
                "no hidden root is configured".to_string(),
            ));
        }

        if !fs.path_exists(root)? {
            return Ok(AttachState::Unattached(format!(
                "hidden root {} does not exist (mount the hidden volume there first)",
                root.display()
            )));
        }

        if !attach_device_check_bypassed() {
            let root_device = fs.device_id(root)?;
            let slash_device = fs.device_id(Path::new("/"))?;
            if root_device == slash_device {
                return Ok(AttachState::Unattached(format!(
                    "hidden root {} shares a device with /, so nothing is mounted there \
                     (unlock and mount the hidden volume before continuing)",
                    root.display()
                )));
            }
        }

        if require_marker && !Self::has_marker(fs, root)? {
            return Ok(AttachState::Unattached(format!(
                "hidden root {} is mounted but holds no NAILS marker \
                 ({MARKER_STATE_FILE} or {MARKER_CONFIG_DIR}/{MARKER_CONFIG_FILE}); \
                 run `nails init` on the hidden volume first",
                root.display()
            )));
        }

        Ok(AttachState::Attached)
    }

    /// Whether `root` carries a NAILS marker: the state file or the config file.
    fn has_marker<F: Filesystem>(fs: &F, root: &Path) -> Result<bool> {
        if fs.path_exists(&root.join(MARKER_STATE_FILE))? {
            return Ok(true);
        }
        fs.path_exists(&root.join(MARKER_CONFIG_DIR).join(MARKER_CONFIG_FILE))
    }
}

/// Test-only escape hatch for the device comparison.
///
/// Integration tests exercise the real write paths against a temp directory,
/// which shares `/`'s device, so they could never look attached. When this build
/// carries the test hooks *and* `NAILS_TEST_FORCE_ATTACHED` is set, the device
/// comparison is skipped and existence (plus any required marker) decides. The
/// hook is compiled out of release builds entirely, so production always runs
/// the real device check regardless of the environment.
#[cfg(any(test, feature = "test-hooks"))]
fn attach_device_check_bypassed() -> bool {
    std::env::var_os("NAILS_TEST_FORCE_ATTACHED").is_some()
}

#[cfg(not(any(test, feature = "test-hooks")))]
fn attach_device_check_bypassed() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockFilesystem;
    use std::path::{Path, PathBuf};

    const ROOT_DEVICE: u64 = 1;
    const VOLUME_DEVICE: u64 = 42;

    fn attached_fs(root: &Path) -> MockFilesystem {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(root.to_str().unwrap(), true);
        fs.mock_set_device_id(Path::new("/"), ROOT_DEVICE);
        fs.mock_set_device_id(root, VOLUME_DEVICE);
        fs
    }

    #[test]
    fn attached_when_root_is_its_own_device() {
        let root = PathBuf::from("/mnt/data");
        let fs = attached_fs(&root);
        let state = HiddenRoot::verify_attached(&fs, &root, false).unwrap();
        assert_eq!(state, AttachState::Attached);
    }

    #[test]
    fn unattached_when_root_shares_device_with_slash() {
        let root = PathBuf::from("/mnt/data");
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/data", true);
        fs.mock_set_device_id(Path::new("/"), ROOT_DEVICE);
        fs.mock_set_device_id(&root, ROOT_DEVICE);

        let state = HiddenRoot::verify_attached(&fs, &root, false).unwrap();
        assert!(!state.is_attached());
        assert!(state.reason().unwrap().contains("shares a device with /"));
    }

    #[test]
    fn unattached_when_root_missing() {
        let root = PathBuf::from("/mnt/data");
        let fs = MockFilesystem::new();
        let state = HiddenRoot::verify_attached(&fs, &root, false).unwrap();
        assert!(!state.is_attached());
        assert!(state.reason().unwrap().contains("does not exist"));
    }

    #[test]
    fn unattached_when_marker_required_but_absent() {
        let root = PathBuf::from("/mnt/data");
        let fs = attached_fs(&root);
        let state = HiddenRoot::verify_attached(&fs, &root, true).unwrap();
        assert!(!state.is_attached());
        assert!(state.reason().unwrap().contains("no NAILS marker"));
    }

    #[test]
    fn attached_with_marker_via_state_file() {
        let root = PathBuf::from("/mnt/data");
        let fs = attached_fs(&root);
        fs.mock_set_path_exists("/mnt/data/state.json", true);
        let state = HiddenRoot::verify_attached(&fs, &root, true).unwrap();
        assert_eq!(state, AttachState::Attached);
    }

    #[test]
    fn attached_with_marker_via_config_file() {
        let root = PathBuf::from("/mnt/data");
        let fs = attached_fs(&root);
        fs.mock_set_path_exists("/mnt/data/config/nails.toml", true);
        let state = HiddenRoot::verify_attached(&fs, &root, true).unwrap();
        assert_eq!(state, AttachState::Attached);
    }

    #[test]
    fn init_bypasses_marker_requirement() {
        // `init` runs with require_marker = false so a freshly mounted, empty
        // volume can be initialised.
        let root = PathBuf::from("/mnt/data");
        let fs = attached_fs(&root);
        let state = HiddenRoot::verify_attached(&fs, &root, false).unwrap();
        assert_eq!(state, AttachState::Attached);
    }

    #[test]
    fn subdirectory_of_attached_volume_passes() {
        // A subdir shares the volume's device, so it is attached as well.
        let root = PathBuf::from("/mnt/data");
        let subdir = root.join("logs");
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/data/logs", true);
        fs.mock_set_device_id(Path::new("/"), ROOT_DEVICE);
        fs.mock_set_device_id(&subdir, VOLUME_DEVICE);
        let state = HiddenRoot::verify_attached(&fs, &subdir, false).unwrap();
        assert_eq!(state, AttachState::Attached);
    }

    #[test]
    fn empty_root_is_unattached() {
        let fs = MockFilesystem::new();
        let state = HiddenRoot::verify_attached(&fs, Path::new(""), false).unwrap();
        assert!(!state.is_attached());
    }
}
