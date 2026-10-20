// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pre-flight check that refuses a decoy with a pending offline system update.
//!
//! systemd's offline-update mechanism (and PackageKit on Debian/Ubuntu) stages a
//! system update by creating a `/system-update` symlink to the prepared payload;
//! some tools use `/etc/system-update`. At the next boot `system-update-generator`
//! redirects into `system-update.target`, which applies the update and reboots.
//!
//! A decoy with one staged is a trap for a hidden session: once NAILS has mounted
//! the overlays and the session soft-reboots, the decoy's offline updater would
//! run the package manager against the overlay (writing into the upper on the
//! hidden volume) and then reboot the machine out from under the session. So
//! activation is refused until the pending update is cleared.
//!
//! The marker is looked for on the decoy root and in the root overlay's upper, so
//! one left staged in the upper by an earlier session is caught too. Every probe
//! reads; nothing here writes.

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result};
use std::path::{Path, PathBuf};

/// The offline-update markers, relative to a root: systemd's `/system-update`
/// and the `/etc/system-update` some tools use.
const UPDATE_MARKERS: &[&str] = &["system-update", "etc/system-update"];

/// Pre-flight check that refuses a decoy with a pending offline update staged.
#[derive(Debug)]
pub struct OfflineUpdateCheck {
    /// The decoy root, `/` outside tests.
    root: PathBuf,
    /// The root overlay's upper on the hidden volume, where a staged update left
    /// by an earlier session would sit.
    upper: PathBuf,
}

impl OfflineUpdateCheck {
    /// Create the check over the decoy `root` and the root overlay's `upper`.
    pub fn new(root: PathBuf, upper: PathBuf) -> Self {
        Self { root, upper }
    }

    /// Whether `path` is present as a file, directory or symlink.
    ///
    /// A `/system-update` symlink is counted even when it dangles: its presence
    /// shows the offline-update mechanism is in use, so refusing is the safe,
    /// fail-closed response.
    fn present<F: Filesystem>(fs: &F, path: &Path) -> bool {
        fs.path_exists(path).unwrap_or(false) || fs.is_symlink(path).unwrap_or(false)
    }

    /// The staged-update markers found, described by their location without
    /// naming the hidden volume path.
    fn staged<F: Filesystem>(&self, fs: &F) -> Vec<String> {
        let mut found = Vec::new();
        for marker in UPDATE_MARKERS {
            if Self::present(fs, &self.root.join(marker)) {
                found.push(format!("/{marker} on the decoy"));
            }
            if Self::present(fs, &self.upper.join(marker)) {
                found.push(format!("/{marker} in the hidden session's overlay"));
            }
        }
        found
    }
}

impl<F: Filesystem> PreFlightCheck<F> for OfflineUpdateCheck {
    fn name(&self) -> &'static str {
        "pending-offline-update"
    }

    fn description(&self) -> &'static str {
        "Refuses a decoy with a pending offline system update staged"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let staged = self.staged(fs);
        if staged.is_empty() {
            return Ok(CheckResult::Pass(
                "no pending offline update is staged on the decoy".into(),
            ));
        }
        Ok(CheckResult::fail_with(
            format!(
                "a pending offline update is staged ({}); once the overlays are mounted the \
                 decoy's offline updater would apply it inside the hidden session and reboot \
                 into it",
                staged.join(", ")
            ),
            "Cancel the pending update on the decoy and remove the system-update marker before \
             activating (for example `rm /system-update`, or cancel it in the decoy's software \
             updater).",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::{MockFilesystem, PathKind};

    fn check() -> OfflineUpdateCheck {
        OfflineUpdateCheck::new(PathBuf::from("/"), PathBuf::from("/mnt/hidden/upper"))
    }

    #[test]
    fn a_clean_decoy_passes() {
        let fs = MockFilesystem::new();
        let result = check().run(&fs).unwrap();
        assert!(result.is_pass(), "{result:?}");
    }

    #[test]
    fn a_system_update_symlink_on_the_decoy_refuses() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/system-update", PathKind::Symlink);
        let result = check().run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert!(result.message().contains("/system-update"), "{result:?}");
        assert!(result.remediation().is_some());
    }

    #[test]
    fn an_etc_system_update_directory_on_the_decoy_refuses() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/etc/system-update", PathKind::Dir);
        let result = check().run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert!(
            result.message().contains("/etc/system-update"),
            "{result:?}"
        );
    }

    #[test]
    fn a_marker_staged_in_the_overlay_upper_refuses() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/mnt/hidden/upper/system-update", PathKind::Symlink);
        let result = check().run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert!(
            result.message().contains("in the hidden session's overlay"),
            "{result:?}"
        );
        // The refusal describes the location without naming the hidden path.
        assert!(!result.message().contains("/mnt/hidden"), "{result:?}");
    }

    #[test]
    fn a_dangling_system_update_symlink_still_refuses() {
        // systemd's generator follows the link, but a stray /system-update symlink
        // is a tell on its own, so NAILS refuses fail-closed regardless.
        let fs = MockFilesystem::new();
        fs.mock_set_is_symlink("/system-update", true);
        fs.mock_set_path_exists("/system-update", false);
        let result = check().run(&fs).unwrap();
        assert!(result.is_fail(), "{result:?}");
    }
}
