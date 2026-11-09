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
//! it. `--allow-decoy-storage` covers only the decoy's own lines for a root it
//! accepted as a part of a filesystem the decoy uses (a bind of a folder of
//! it, or a btrfs subvolume of it): the fstab lines that the decoy's boot
//! mounted at `/` or at a system folder ([`separation::is_system_folder`])
//! for another part of that filesystem, while the mount there shows it, are
//! no finding then ([`EntryFinding::system_folder`]), and neither are the
//! crypttab lines its boot opens that make a device that filesystem lies on
//! while the decoy mounts another part of it at `/` or by such an fstab line,
//! as on an encrypted decoy. A line that mounts that filesystem at any other
//! folder still is one, since it may name the hidden drive's disk, and so are
//! a line whose mount is not there, a line that mounts the volume itself (a
//! bind line from the root's folder among them), a `noauto` crypttab line,
//! one with `tcrypt-hidden`, one for any other device and every line for a
//! root that is the whole filesystem.
//!
//! An entry that opens only another volume on the same drive (a VeraCrypt
//! outer volume of another partition) warns: the decoy is configured to open
//! storage on that drive.
//!
//! A bind line's source and the path of a swap or image file are followed
//! through their links, as `mount` and `swapon` follow them. A line whose
//! path cannot be followed (a link on the way that leads to nothing, links
//! that go round, a place that cannot be looked up, an automount point that
//! the lookup would mount) fails as well: it may mount the volume, and the
//! check says why it cannot tell where the line leads.
//!
//! An entry the decoy's own boot needs (one that mounts its root or another
//! of its filesystems or its swap, or opens a device below one of them) cannot
//! go: the hidden root lies on the decoy's own storage then, and the check says
//! to put it on storage of its own instead. The entries only the hidden volume
//! needs still have to go, so where both kinds are flagged it says both.

use super::super::{CheckResult, PreFlightCheck};
use crate::filesystem::mountinfo::top_mount_at;
use crate::hidden_root::Allow;
use crate::hidden_root::separation::{self, EntryFinding, EntryKind, Verdict};
use crate::{Filesystem, Result};
use std::path::{Path, PathBuf};

/// What the operator does about a blocking entry.
pub const REMEDIATION: &str =
    "Remove the line long before the next use; open the volume by hand each time.";

/// What the operator does when the decoy's own boot needs a blocking entry:
/// removing it would break the decoy, so the hidden root has to move.
pub const STORAGE_OF_ITS_OWN: &str = "Do not remove a line the decoy's own boot needs: put the \
     hidden root on storage of its own instead.";

/// What the operator does about blocking entries of both kinds. A line only
/// the hidden volume needs is flagged no more once the hidden root moves, and
/// would stay behind naming it, so it goes as [`REMEDIATION`] says.
pub const REMOVE_AND_MOVE: &str = "Remove the lines only the hidden volume needs long before the \
     next use, and open the volume by hand each time. Do not remove a line the decoy's own boot \
     needs: put the hidden root on storage of its own instead.";

/// What the operator does about an entry whose path cannot be followed: once
/// it leads to a place that can be looked up, the check tells what it mounts.
pub const UNFOLLOWED: &str = "Make a line whose path cannot be followed lead to a place that can \
     be looked up, or remove it, long before the next use. If the command ran without sudo, run \
     it again with sudo.";

/// Pre-flight check that no decoy fstab or crypttab entry opens or mounts the
/// hidden volume.
#[derive(Debug, Clone)]
pub struct BackendEntriesCheck {
    hidden_volume_root: PathBuf,
    allow: Allow,
}

impl BackendEntriesCheck {
    /// A check of the volume mounted at `hidden_volume_root`.
    pub fn new(hidden_volume_root: PathBuf) -> Self {
        Self {
            hidden_volume_root,
            allow: Allow::Nothing,
        }
    }

    /// Let be the decoy's own lines for a root that `allow`
    /// (`--allow-decoy-storage`) accepts on a filesystem the decoy uses.
    #[must_use]
    pub fn allowing(mut self, allow: Allow) -> Self {
        self.allow = allow;
        self
    }
}

/// `<file>: '<line>' (<why>)` for each finding, and whether the decoy's own
/// boot needs it.
fn describe(findings: &[&EntryFinding]) -> String {
    findings
        .iter()
        .map(|f| {
            let needed = if f.boot_needs {
                ", and the decoy's own boot needs it"
            } else {
                ""
            };
            format!("{}: '{}' ({}{needed})", f.file, f.line, f.why)
        })
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
        // A root the operator accepted on a filesystem the decoy uses lies on
        // it, and the decoy's own lines for / and its system folders mount
        // that filesystem for the decoy, or open the device it lies on: they
        // are what the flag accepted.
        let accepted = self.allow == Allow::DecoyStorage
            && matches!(judgement.verdict, Verdict::OnDecoyFilesystem { .. });
        let (own, entries): (Vec<&EntryFinding>, Vec<&EntryFinding>) = judgement
            .entries
            .iter()
            .partition(|f| accepted && f.system_folder.is_some());
        let of_kind = |kind: EntryKind| -> Vec<&EntryFinding> {
            entries.iter().copied().filter(|f| f.kind == kind).collect()
        };

        let blocking = of_kind(EntryKind::Blocking);
        let untold = of_kind(EntryKind::Untold);
        if !blocking.is_empty() || !untold.is_empty() {
            return Ok(entries_failure(root, &blocking, &untold));
        }
        let outer = of_kind(EntryKind::OuterWarning);
        if !outer.is_empty() {
            return Ok(CheckResult::Warn(format!(
                "The decoy is configured to open storage on the drive that holds {}: {}",
                root.display(),
                describe(&outer)
            )));
        }
        if !own.is_empty() {
            return Ok(CheckResult::Pass(decoys_own_lines(root, &own)));
        }
        Ok(CheckResult::Pass(format!(
            "No fstab or crypttab entry opens or mounts the volume at {}",
            root.display()
        )))
    }
}

/// The failure for the entries for the hidden drive: those that open or
/// mount it, `blocking`, and those whose path cannot be followed, `untold`,
/// which may (at least one of the two is there). The fix says what to do
/// about each kind.
fn entries_failure(
    root: &Path,
    blocking: &[&EntryFinding],
    untold: &[&EntryFinding],
) -> CheckResult {
    let root = root.display();
    let mut message = Vec::new();
    let mut fix = Vec::new();
    if !blocking.is_empty() {
        message.push(format!(
            "The decoy's configuration names the volume at {root}: {}.",
            describe(blocking)
        ));
        let needed = blocking.iter().filter(|f| f.boot_needs).count();
        fix.push(if needed == 0 {
            REMEDIATION
        } else if needed == blocking.len() {
            STORAGE_OF_ITS_OWN
        } else {
            REMOVE_AND_MOVE
        });
    }
    if !untold.is_empty() {
        let may = if blocking.is_empty() {
            format!("The decoy's configuration may name the volume at {root}")
        } else {
            "It may name it as well".to_string()
        };
        message.push(format!("{may}: {}.", describe(untold)));
        fix.push(UNFOLLOWED);
    }
    message.push(
        "Such an entry is stored on the decoy, where an examination reads it, and can open or \
         mount the volume at boot."
            .to_string(),
    );
    CheckResult::fail_with(message.join(" "), fix.join("\n"))
}

/// The pass of a root that `--allow-decoy-storage` accepted on a filesystem
/// the decoy uses, which only the decoy's own lines in `own` name: its fstab
/// lines by their folders, and its crypttab lines, which unlock a device that
/// filesystem lies on, as they read.
fn decoys_own_lines(root: &Path, own: &[&EntryFinding]) -> String {
    let places: Vec<String> = own
        .iter()
        .filter(|f| f.file == separation::FSTAB)
        .filter_map(|f| f.system_folder.as_deref())
        .map(|at| at.display().to_string())
        .collect();
    let unlocked: Vec<String> = own
        .iter()
        .filter(|f| f.file == separation::CRYPTTAB)
        .map(|f| format!("'{}'", f.line))
        .collect();
    let lines = |count: usize| if count == 1 { "line" } else { "lines" };
    let mut named = Vec::new();
    if !places.is_empty() {
        named.push(format!("{} for {}", lines(places.len()), listed(&places)));
    }
    if !unlocked.is_empty() {
        let its = if named.is_empty() { "" } else { "its " };
        named.push(format!(
            "{its}crypttab {} {}",
            lines(unlocked.len()),
            listed(&unlocked)
        ));
    }
    let does = match (places.len(), unlocked.len()) {
        (1, 0) => "mounts",
        (_, 0) => "mount",
        (0, 1) => "unlocks",
        (0, _) => "unlock",
        _ => "unlock and mount",
    };
    format!(
        "No fstab or crypttab entry names the volume at {} other than the decoy's own {}, which \
         {does} the filesystem that --allow-decoy-storage accepted it on",
        root.display(),
        named.join(" and ")
    )
}

/// `items` as a list: `a`, `a and b`, `a, b and c`.
fn listed(items: &[String]) -> String {
    match items.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        _ => items.join(""),
    }
}

#[cfg(test)]
#[path = "backend_entries_tests.rs"]
mod tests;
