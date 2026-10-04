// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Hidden volume pre-flight check
//!
//! Validates that the hidden volume is mounted and writable before activation.

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result, config::get_default_hidden_volume_root};
use std::path::{Component, PathBuf};

/// Words that hint at hidden storage. One shared list so the mount path, the
/// device-mapper name and the filesystem label are all judged the same way.
///
/// A match is a leak, not a failure: the name survives in the leftover
/// mount-point directory, in generated systemd `.mount`/`.device` unit names, in
/// `/dev/disk/by-label` and in kernel and sudo journal lines, where anyone who
/// reads them learns that hidden storage exists. Matching is case-insensitive
/// and on substrings, so `veracrypt-hidden`, `MyNailsVol` and `decoy0` all hit.
const SUSPICIOUS_STORAGE_TOKENS: &[&str] = &["hidden", "nails", "veracrypt", "tcrypt", "decoy"];

/// The first [`SUSPICIOUS_STORAGE_TOKENS`] entry contained in `name`, if any.
fn suspicious_token(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    SUSPICIOUS_STORAGE_TOKENS
        .iter()
        .copied()
        .find(|token| lower.contains(token))
}

/// Pre-flight check that validates the hidden volume is mounted and accessible
///
/// This check performs three-step validation and then one name audit:
/// 1. **Path Existence**: Hidden volume path must exist
/// 2. **Mount Status**: Path must be mounted (not just exist as an empty directory)
/// 3. **Write Permission**: Path must be writable to store overlay directories
/// 4. **Neutral naming**: once mounted and writable, the mount path, the
///    device-mapper name and the filesystem label are scanned for words that
///    betray hidden storage, and a match is reported as a non-blocking warning
///
/// # Failure Guidance
///
/// Each failure mode provides actionable guidance with fix steps:
/// - **Path not found**: Suggests mounting the hidden volume
/// - **Not mounted**: Suggests unlocking the backend and mounting it there
/// - **Not writable**: Suggests checking permissions
///
/// # Example
///
/// ```rust
/// use nails_core::preflight::{HiddenVolumeCheck, PreFlightCheck};
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// let check = HiddenVolumeCheck::new(PathBuf::from("/mnt/data"));
///
/// // Set up mock state
/// fs.mock_set_path_exists("/mnt/data", true);
/// fs.mock_set_mounted(std::path::Path::new("/mnt/data"), true);
/// fs.mock_set_writable("/mnt/data", true);
///
/// let result = check.run(&fs).unwrap();
/// assert!(result.is_pass());
/// ```
#[derive(Debug, Clone)]
pub struct HiddenVolumeCheck {
    hidden_volume_root: PathBuf,
}

impl HiddenVolumeCheck {
    /// Create a new HiddenVolumeCheck with a custom path
    ///
    /// # Arguments
    ///
    /// * `hidden_volume_root` - Path to the hidden volume mount point
    pub fn new(hidden_volume_root: PathBuf) -> Self {
        Self { hidden_volume_root }
    }
}

impl Default for HiddenVolumeCheck {
    /// Create check with default hidden volume path
    fn default() -> Self {
        Self {
            hidden_volume_root: PathBuf::from(get_default_hidden_volume_root()),
        }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for HiddenVolumeCheck {
    fn name(&self) -> &'static str {
        "hidden-volume"
    }

    fn description(&self) -> &'static str {
        "Validates hidden volume is mounted and writable"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // Step 1: Check path exists
        if !fs.path_exists(&self.hidden_volume_root)? {
            return Ok(CheckResult::fail(format!(
                "Hidden volume not found at {}. Mount volume before activation.",
                self.hidden_volume_root.display()
            )));
        }

        // Step 2: Check path is mounted
        if !fs.is_mounted(&self.hidden_volume_root)? {
            return Ok(CheckResult::fail(format!(
                "Hidden volume at {} is not mounted. Unlock the hidden storage backend and mount its filesystem at this path before activation (see docs/backends.md).",
                self.hidden_volume_root.display()
            )));
        }

        // Step 3: Check path is writable
        if !fs.is_writable(&self.hidden_volume_root)? {
            return Ok(CheckResult::fail(format!(
                "Hidden volume at {} is not writable. Check permissions.",
                self.hidden_volume_root.display()
            )));
        }

        // Step 4: Audit names for words that betray hidden storage. This never
        // blocks activation — the volume is usable — it only warns so the
        // operator can rename before the name leaks off the box.
        let hints = self.naming_hints(fs);
        if !hints.is_empty() {
            return Ok(CheckResult::Warn(format!(
                "Hidden volume mounted at {}, but a name here hints at hidden storage: {}. \
                 Such a name survives in the leftover mount-point directory, in generated \
                 mount unit names, in /dev/disk/by-label and in kernel and sudo journal \
                 lines. Use neutral names that reveal nothing (for example a \"data\" \
                 mapper, a /mnt/data mountpoint and a plain label). These names also leak \
                 before NAILS runs; see the pre-activation residue section of \
                 docs/operator-guide.md.",
                self.hidden_volume_root.display(),
                hints.join("; ")
            )));
        }

        Ok(CheckResult::Pass(format!(
            "Hidden volume mounted at {}",
            self.hidden_volume_root.display()
        )))
    }
}

impl HiddenVolumeCheck {
    /// Collect every way the mounted volume's names hint at hidden storage.
    ///
    /// Scans the mount path's own components, the device-mapper name behind the
    /// mount source and the filesystem label. The mount source is read through
    /// [`Filesystem::mount_source`]; a source that cannot be read contributes no
    /// hints rather than failing the check, exactly as the backend detector
    /// treats an unreadable mount table.
    fn naming_hints<F: Filesystem>(&self, fs: &F) -> Vec<String> {
        let mut hints = Vec::new();

        // (a) The mount path itself. One mention is enough, so stop at the first
        // component that matches.
        for component in self.hidden_volume_root.components() {
            if let Component::Normal(part) = component {
                let part = part.to_string_lossy();
                if let Some(token) = suspicious_token(&part) {
                    hints.push(format!(
                        "the mount path component \"{part}\" contains \"{token}\""
                    ));
                    break;
                }
            }
        }

        // (b) and (c) The device-mapper name and filesystem label behind the
        // mount source.
        if let Some(source) = fs.mount_source(&self.hidden_volume_root).ok().flatten() {
            if let Some(name) = source.dm_name.as_deref()
                && let Some(token) = suspicious_token(name)
            {
                hints.push(format!(
                    "the device-mapper name \"{name}\" contains \"{token}\""
                ));
            }
            if let Some(label) = source.label.as_deref()
                && let Some(token) = suspicious_token(label)
            {
                hints.push(format!(
                    "the filesystem label \"{label}\" contains \"{token}\""
                ));
            }
        }

        hints
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
    use crate::filesystem::{MockFilesystem, MountSource};
    use std::path::Path;

    /// A neutral root, used wherever a check must pass without a naming warning.
    const NEUTRAL_ROOT: &str = "/mnt/data";

    /// Mark `root` as existing, mounted and writable.
    fn mount_ok(fs: &MockFilesystem, root: &str) {
        fs.mock_set_path_exists(root, true);
        fs.mock_set_mounted(Path::new(root), true);
        fs.mock_set_writable(root, true);
    }

    #[test]
    fn test_hidden_volume_check_default_path() {
        let check = HiddenVolumeCheck::default();
        assert_eq!(
            check.hidden_volume_root,
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
        );
    }

    #[test]
    fn default_root_is_neutral() {
        // The built-in fallback must not itself read as hidden storage.
        assert!(
            suspicious_token(DEFAULT_HIDDEN_VOLUME_ROOT).is_none(),
            "the default hidden root '{DEFAULT_HIDDEN_VOLUME_ROOT}' hints at hidden storage"
        );
    }

    #[test]
    fn test_hidden_volume_check_custom_path() {
        let custom_path = PathBuf::from("/custom/path");
        let check = HiddenVolumeCheck::new(custom_path.clone());
        assert_eq!(check.hidden_volume_root, custom_path);
    }

    #[test]
    fn test_hidden_volume_check_trait_metadata() {
        let check = HiddenVolumeCheck::default();

        assert_eq!(
            <HiddenVolumeCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "hidden-volume"
        );
        assert_eq!(
            <HiddenVolumeCheck as PreFlightCheck<MockFilesystem>>::description(&check),
            "Validates hidden volume is mounted and writable"
        );
    }

    #[test]
    fn test_hidden_volume_check_pass_when_mounted_and_writable() {
        let fs = MockFilesystem::new();
        let check = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT));

        mount_ok(&fs, NEUTRAL_ROOT);

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass(), "got {result:?}");
        assert_eq!(result.message(), "Hidden volume mounted at /mnt/data");
    }

    #[test]
    fn test_hidden_volume_check_fail_when_path_does_not_exist() {
        let fs = MockFilesystem::new();
        let check = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT));

        // Volume path does not exist
        fs.mock_set_path_exists(NEUTRAL_ROOT, false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(
            result
                .message()
                .contains("Hidden volume not found at /mnt/data")
        );
        assert!(result.message().contains("Mount volume before activation"));
    }

    #[test]
    fn test_hidden_volume_check_fail_when_not_mounted() {
        let fs = MockFilesystem::new();
        let check = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT));

        // Volume exists but is NOT mounted
        fs.mock_set_path_exists(NEUTRAL_ROOT, true);
        fs.mock_set_mounted(Path::new(NEUTRAL_ROOT), false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("is not mounted"));
        assert!(
            result
                .message()
                .contains("Unlock the hidden storage backend and mount its filesystem")
        );
        // The guidance applies to every backend, so it names none of them.
        // Matched case-insensitively so any spelling of a backend name trips it.
        let message = result.message().to_lowercase();
        for backend in ["luks", "veracrypt", "tcrypt", "cryptsetup"] {
            assert!(!message.contains(backend), "names {backend}");
        }
    }

    #[test]
    fn test_hidden_volume_check_fail_when_not_writable() {
        let fs = MockFilesystem::new();
        let check = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT));

        // Volume exists and is mounted but NOT writable
        fs.mock_set_path_exists(NEUTRAL_ROOT, true);
        fs.mock_set_mounted(Path::new(NEUTRAL_ROOT), true);
        fs.mock_set_writable(NEUTRAL_ROOT, false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("is not writable"));
        assert!(result.message().contains("Check permissions"));
    }

    #[test]
    fn test_hidden_volume_check_custom_path_works() {
        let fs = MockFilesystem::new();
        let custom_path = PathBuf::from("/custom/volume");
        let check = HiddenVolumeCheck::new(custom_path.clone());

        mount_ok(&fs, "/custom/volume");

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert!(result.message().contains("/custom/volume"));
    }

    #[test]
    fn test_hidden_volume_check_clone() {
        let check = HiddenVolumeCheck::default();
        let cloned = check.clone();
        assert_eq!(check.hidden_volume_root, cloned.hidden_volume_root);
    }

    // ------------------------------------------------------------------------
    // Neutral-naming audit
    // ------------------------------------------------------------------------

    #[test]
    fn suspicious_token_is_case_insensitive_substring() {
        assert_eq!(suspicious_token("MyVeraCryptVol"), Some("veracrypt"));
        assert_eq!(suspicious_token("DECOY0"), Some("decoy"));
        assert_eq!(suspicious_token("nails-store"), Some("nails"));
        assert_eq!(suspicious_token("data"), None);
    }

    #[test]
    fn warns_when_root_path_hints_at_hidden_storage() {
        let fs = MockFilesystem::new();
        let root = "/mnt/hidden-volume";
        let check = HiddenVolumeCheck::new(PathBuf::from(root));
        mount_ok(&fs, root);

        let result = check.run(&fs).unwrap();
        assert!(result.is_warn(), "got {result:?}");
        let msg = result.message();
        assert!(msg.contains("mount path component"), "{msg}");
        assert!(msg.contains("\"hidden\""), "{msg}");
        // The volume is still reported as usable and the message routes the
        // operator to the residue guidance.
        assert!(msg.contains("/mnt/hidden-volume"), "{msg}");
        assert!(msg.contains("pre-activation residue"), "{msg}");
    }

    #[test]
    fn warns_when_dm_name_hints_at_hidden_storage() {
        let fs = MockFilesystem::new();
        let check = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT));
        mount_ok(&fs, NEUTRAL_ROOT);
        fs.mock_set_mount_source(
            Path::new(NEUTRAL_ROOT),
            MountSource {
                device: Some("/dev/mapper/veracrypt-hidden".to_string()),
                dm_name: Some("veracrypt-hidden".to_string()),
                label: None,
            },
        );

        let result = check.run(&fs).unwrap();
        assert!(result.is_warn(), "got {result:?}");
        let msg = result.message();
        assert!(msg.contains("device-mapper name"), "{msg}");
        assert!(msg.contains("veracrypt-hidden"), "{msg}");
    }

    #[test]
    fn warns_when_filesystem_label_hints_at_hidden_storage() {
        let fs = MockFilesystem::new();
        let check = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT));
        mount_ok(&fs, NEUTRAL_ROOT);
        fs.mock_set_mount_source(
            Path::new(NEUTRAL_ROOT),
            MountSource {
                device: Some("/dev/sdb1".to_string()),
                dm_name: None,
                label: Some("decoy-vault".to_string()),
            },
        );

        let result = check.run(&fs).unwrap();
        assert!(result.is_warn(), "got {result:?}");
        let msg = result.message();
        assert!(msg.contains("filesystem label"), "{msg}");
        assert!(msg.contains("decoy-vault"), "{msg}");
    }

    #[test]
    fn warns_report_every_offending_name_at_once() {
        let fs = MockFilesystem::new();
        let root = "/mnt/nails-store";
        let check = HiddenVolumeCheck::new(PathBuf::from(root));
        mount_ok(&fs, root);
        fs.mock_set_mount_source(
            Path::new(root),
            MountSource {
                device: Some("/dev/mapper/tcrypt0".to_string()),
                dm_name: Some("tcrypt0".to_string()),
                label: Some("hidden".to_string()),
            },
        );

        let result = check.run(&fs).unwrap();
        assert!(result.is_warn(), "got {result:?}");
        let msg = result.message();
        assert!(msg.contains("mount path component"), "{msg}");
        assert!(msg.contains("device-mapper name"), "{msg}");
        assert!(msg.contains("filesystem label"), "{msg}");
    }

    #[test]
    fn passes_when_every_name_is_neutral() {
        let fs = MockFilesystem::new();
        let check = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT));
        mount_ok(&fs, NEUTRAL_ROOT);
        fs.mock_set_mount_source(
            Path::new(NEUTRAL_ROOT),
            MountSource {
                device: Some("/dev/mapper/data".to_string()),
                dm_name: Some("data".to_string()),
                label: Some("data".to_string()),
            },
        );

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass(), "got {result:?}");
        assert_eq!(result.message(), "Hidden volume mounted at /mnt/data");
    }
}
