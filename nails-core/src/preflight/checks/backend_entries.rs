// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Backend-entries pre-flight check
//!
//! Refuses activation while the decoy's `/etc/fstab` or `/etc/crypttab` holds
//! an entry that opens or mounts the hidden volume.
//!
//! Such an entry is an enabler stored on the decoy: it names the hidden drive
//! in the decoy's own configuration, where an examination reads it, and at boot
//! it may even open or mount the volume. The threat model forbids it and the
//! decoy requirements say the hidden backend never has one. The attach gate
//! ignores these entries (writing to the root stays safe); this check reports
//! them, from the same judge ([`separation`]), so `check` and activation share
//! it. `--allow-unmounted` never covers it, and `activate --no-preflight` runs
//! it alone.
//!
//! An entry that opens only another volume on the same drive (a VeraCrypt
//! outer volume of another partition) warns: the decoy is configured to open
//! storage on that drive.

use super::super::{CheckResult, PreFlightCheck};
use crate::filesystem::mountinfo::top_mount_at;
use crate::hidden_root::separation::{self, EntryFinding, EntryKind};
use crate::{Filesystem, Result};
use std::path::{Path, PathBuf};

/// What the operator does about a blocking entry.
pub const REMEDIATION: &str =
    "Remove the line long before the next use; open the volume by hand each time.";

/// Pre-flight check that no decoy fstab or crypttab entry opens or mounts the
/// hidden volume.
#[derive(Debug, Clone)]
pub struct BackendEntriesCheck {
    hidden_volume_root: PathBuf,
}

impl BackendEntriesCheck {
    /// A check of the volume mounted at `hidden_volume_root`.
    pub fn new(hidden_volume_root: PathBuf) -> Self {
        Self { hidden_volume_root }
    }
}

/// `<file>: '<line>' (<why>)` for each finding.
fn describe(findings: &[&EntryFinding]) -> String {
    findings
        .iter()
        .map(|f| format!("{}: '{}' ({})", f.file, f.line, f.why))
        .collect::<Vec<_>>()
        .join("; ")
}

impl<F: Filesystem> PreFlightCheck<F> for BackendEntriesCheck {
    fn name(&self) -> &'static str {
        "backend-entries"
    }

    fn description(&self) -> &'static str {
        "Validates no decoy fstab or crypttab entry opens or mounts the hidden volume"
    }

    fn requires_hidden_volume(&self) -> bool {
        true
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let root = &self.hidden_volume_root;
        let table = fs.mount_table()?;
        let canonical = fs.canonicalize(root).unwrap_or_else(|_| root.clone());
        let Some(hidden) = top_mount_at(&table, &canonical) else {
            // No volume of its own, so no entry can open one; the attach
            // gate refuses such a root before this check matters.
            return Ok(CheckResult::Pass(format!(
                "No volume is mounted at {}, so no entry opens one",
                root.display()
            )));
        };
        if matches!(hidden.fstype.as_str(), "tmpfs" | "ramfs") {
            return Ok(CheckResult::Pass(format!(
                "The volume at {} lives in RAM; no entry can open it",
                root.display()
            )));
        }

        let collected = separation::collect(fs, &table, Path::new("/"));
        if !collected.unreadable.is_empty() {
            let files = collected
                .unreadable
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            return Ok(CheckResult::fail_with(
                format!(
                    "Could not read {files} to look for entries that open the volume at {}",
                    root.display()
                ),
                "Run the command again with sudo.",
            ));
        }
        let judgement = separation::judge(&collected.scene(&table), hidden);
        let of_kind = |kind: EntryKind| -> Vec<&EntryFinding> {
            judgement
                .entries
                .iter()
                .filter(|f| f.kind == kind)
                .collect()
        };

        let blocking = of_kind(EntryKind::Blocking);
        if !blocking.is_empty() {
            return Ok(CheckResult::fail_with(
                format!(
                    "The decoy's configuration names the volume at {}: {}. Such an entry is \
                     stored on the decoy, where an examination reads it, and can open or mount \
                     the volume at boot.",
                    root.display(),
                    describe(&blocking)
                ),
                REMEDIATION,
            ));
        }
        let outer = of_kind(EntryKind::OuterWarning);
        if !outer.is_empty() {
            return Ok(CheckResult::Warn(format!(
                "The decoy is configured to open storage on the drive that holds {}: {}",
                root.display(),
                describe(&outer)
            )));
        }
        Ok(CheckResult::Pass(format!(
            "No fstab or crypttab entry opens or mounts the volume at {}",
            root.display()
        )))
    }
}

#[cfg(test)]
#[path = "backend_entries_tests.rs"]
mod tests;
