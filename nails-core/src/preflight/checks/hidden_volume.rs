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
#[path = "hidden_volume_tests.rs"]
mod tests;
