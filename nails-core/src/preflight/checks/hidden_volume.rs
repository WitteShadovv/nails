// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Hidden volume pre-flight check
//!
//! Validates that the hidden volume is mounted and writable before activation.

use super::super::{CheckResult, PreFlightCheck};
use crate::hidden_root::{Allow, Assessment, HiddenRoot, Refusal};
use crate::naming::suspicious_token;
use crate::{Filesystem, Result, config::get_default_hidden_volume_root};
use std::path::{Component, PathBuf};

/// Pre-flight check that validates the hidden volume is mounted and accessible
///
/// This check performs three-step validation and then one name audit:
/// 1. **Path Existence**: Hidden volume path must exist
/// 2. **The attach gate**: a volume of its own must be mounted at the path
///    ([`HiddenRoot::assess`]): not a folder, not a root covered by a second
///    filesystem, not storage the decoy uses, and storage that can be judged.
///    Nothing is probed before it passes, so `check` writes no probe file onto
///    the decoy's storage.
/// 3. **Write Permission**: Path must be writable to store overlay directories
/// 4. **Neutral naming**: once mounted and writable, the mount path, the
///    device-mapper name and the filesystem label are scanned for words that
///    betray hidden storage, and a match is reported as a non-blocking warning
///
/// A root the gate only warns about (a container file on a decoy filesystem),
/// or decoy storage the operator accepted with `--allow-decoy-storage`, passes
/// with that warning. A refusal is reported in the gate's own words.
///
/// # Failure Guidance
///
/// Each failure mode provides actionable guidance with fix steps:
/// - **Missing, or refused by the gate**: the gate's own hint (mount the
///   volume, prepare it where nothing reaches this disk, unmount the second
///   filesystem, run with sudo)
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
    allow: Allow,
}

impl HiddenVolumeCheck {
    /// Create a new HiddenVolumeCheck with a custom path
    ///
    /// # Arguments
    ///
    /// * `hidden_volume_root` - Path to the hidden volume mount point
    pub fn new(hidden_volume_root: PathBuf) -> Self {
        Self {
            hidden_volume_root,
            allow: Allow::Nothing,
        }
    }

    /// Accept the gate refusals `allow` covers (`--allow-decoy-storage`) with a
    /// warning.
    #[must_use]
    pub fn allowing(mut self, allow: Allow) -> Self {
        self.allow = allow;
        self
    }
}

impl Default for HiddenVolumeCheck {
    /// Create check with default hidden volume path
    fn default() -> Self {
        Self::new(PathBuf::from(get_default_hidden_volume_root()))
    }
}

/// The failure of a root the attach gate refused: the gate's own sentence, as
/// `init`, `activate` and `rehearse` print it, with its hint as the
/// remediation.
fn gate_failure(refusal: &Refusal) -> CheckResult {
    let exe = std::env::current_exe().ok();
    CheckResult::fail_with(
        refusal.reason.clone(),
        refusal.hint(exe.as_deref()).join("\n"),
    )
}

impl<F: Filesystem> PreFlightCheck<F> for HiddenVolumeCheck {
    fn name(&self) -> &'static str {
        "hidden-volume"
    }

    fn description(&self) -> &'static str {
        "Validates hidden volume is mounted and writable"
    }

    fn is_hidden_volume_gate(&self) -> bool {
        true
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // Steps 1 and 2: the attach gate, which also finds a missing root,
        // before anything is probed.
        let mut warnings = Vec::new();
        match HiddenRoot::assess_allowing(fs, &self.hidden_volume_root, self.allow)? {
            Assessment::Attached => {}
            Assessment::Warned(refusal) => warnings.push(refusal.warning()),
            Assessment::Refused(refusal) => return Ok(gate_failure(&refusal)),
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
            warnings.push(format!(
                "Hidden volume mounted at {}, but a name here hints at hidden storage: {}. \
                 Such a name survives in the leftover mount-point directory, in generated \
                 mount unit names, in /dev/disk/by-label and in kernel and sudo journal \
                 lines. Use neutral names that reveal nothing (for example a \"data\" \
                 mapper, a /mnt/data mountpoint and a plain label). These names also leak \
                 before NAILS runs; see the pre-activation residue section of \
                 docs/operator-guide.md.",
                self.hidden_volume_root.display(),
                hints.join("; ")
            ));
        }
        if !warnings.is_empty() {
            return Ok(CheckResult::Warn(warnings.join(" ")));
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
        assert_eq!(result.message(), "/mnt/data does not exist");
        assert!(
            result
                .remediation()
                .unwrap()
                .starts_with("If the volume is already prepared, unlock it, mount it at /mnt/data")
        );
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
        assert!(
            result.message().starts_with(
                "/mnt/data is not a volume of its own: it is a folder on the filesystem \
                 mounted at /"
            ),
            "{}",
            result.message()
        );
        // The remediation is the gate's redirect, which names no backend.
        // Matched case-insensitively so any spelling of a backend name trips it.
        let remediation = result.remediation().unwrap().to_lowercase();
        assert!(remediation.contains("where setup happens"), "{remediation}");
        for backend in ["luks", "veracrypt", "tcrypt", "cryptsetup"] {
            assert!(!remediation.contains(backend), "names {backend}");
        }
        assert!(fs.mock_ops().is_empty(), "{:?}", fs.mock_ops());
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
    // Neutral-naming audit (the token list is tested in `nails_base::naming`)
    // ------------------------------------------------------------------------

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
    fn a_root_covered_by_a_mount_on_its_parent_is_no_volume_of_its_own() {
        // The volume is still in the table, but a later mount on /mnt covers
        // it: a lookup of the root ends on that mount instead.
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(NEUTRAL_ROOT, true);
        fs.mock_set_writable(NEUTRAL_ROOT, true);
        fs.mock_set_mount_table(
            "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
             30 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
             31 1 0:40 / /mnt rw - tmpfs tmpfs rw\n",
        );

        let result = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT))
            .run(&fs)
            .unwrap();
        assert!(result.is_fail(), "got {result:?}");
        assert!(result.message().contains("is not a volume of its own"));
    }

    #[test]
    fn two_filesystems_at_the_root_fail_before_any_audit_or_probe() {
        let fs = MockFilesystem::new();
        let check =
            HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT)).allowing(Allow::DecoyStorage);
        fs.mock_set_path_exists(NEUTRAL_ROOT, true);
        fs.mock_set_writable(NEUTRAL_ROOT, true);
        let stacked = |below: &str, above: &str| {
            format!(
                "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                 30 1 253:0 / /mnt/data rw - ext4 /dev/mapper/{below} rw\n\
                 31 30 253:1 / /mnt/data rw - ext4 /dev/mapper/{above} rw\n"
            )
        };
        // Neither order is accepted, not even with the override.
        for (below, above) in [("data", "veracrypt1"), ("veracrypt1", "data")] {
            fs.mock_set_mount_table(&stacked(below, above));
            let result = check.run(&fs).unwrap();
            assert!(result.is_fail(), "got {result:?}");
            assert!(
                result.message().contains(
                    "two filesystems are mounted at /mnt/data: a filesystem of type ext4, then \
                     a filesystem of type ext4 over it"
                ),
                "{}",
                result.message()
            );
            assert!(
                !result.message().contains("veracrypt"),
                "{}",
                result.message()
            );
            assert_eq!(
                result.remediation(),
                Some("Unmount the one that is not the volume, then run the command again.")
            );
        }
        assert!(fs.mock_ops().is_empty(), "{:?}", fs.mock_ops());
    }

    /// A root that is a bind of a folder of `/`: decoy storage.
    fn bind_of_a_decoy_folder() -> MockFilesystem {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(NEUTRAL_ROOT, true);
        fs.mock_set_writable(NEUTRAL_ROOT, true);
        fs.mock_set_mount_table(
            "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
             30 1 8:1 /srv/x /mnt/data rw - ext4 /dev/vda1 rw\n",
        );
        fs
    }

    #[test]
    fn decoy_storage_fails_without_a_write_probe() {
        let fs = bind_of_a_decoy_folder();
        let result = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT))
            .run(&fs)
            .unwrap();
        assert!(result.is_fail(), "got {result:?}");
        assert_eq!(
            result.message(),
            "/mnt/data is not a volume of its own: it is a bind mount of a folder of /"
        );
        assert!(fs.mock_ops().is_empty(), "{:?}", fs.mock_ops());
    }

    #[test]
    fn the_override_turns_decoy_storage_into_a_warning() {
        let fs = bind_of_a_decoy_folder();
        let result = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT))
            .allowing(Allow::DecoyStorage)
            .run(&fs)
            .unwrap();
        assert!(result.is_warn(), "got {result:?}");
        assert!(
            result.message().starts_with(
                "--allow-decoy-storage: using /mnt/data although it is a bind mount of a folder of /"
            ),
            "{}",
            result.message()
        );
    }

    #[test]
    fn unjudged_storage_fails_even_with_the_override() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(NEUTRAL_ROOT, true);
        fs.mock_set_writable(NEUTRAL_ROOT, true);
        fs.mock_set_mount_table(
            "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
             30 1 8:17 / /mnt/data rw - ext4 /dev/sdb1 rw\n",
        );
        // A crypttab that exists but cannot be read.
        fs.mock_set_path_exists("/etc/crypttab", true);
        let result = HiddenVolumeCheck::new(PathBuf::from(NEUTRAL_ROOT))
            .allowing(Allow::DecoyStorage)
            .run(&fs)
            .unwrap();
        assert!(result.is_fail(), "got {result:?}");
        assert!(
            result
                .message()
                .contains("could not read /etc/crypttab to tell where /mnt/data lives"),
            "{}",
            result.message()
        );
        assert_eq!(
            result.remediation(),
            Some("Run the command again with sudo.")
        );
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
