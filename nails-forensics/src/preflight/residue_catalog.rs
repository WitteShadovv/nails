// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pre-flight probes driven by the residue catalog.
//!
//! Every catalog row whose pre-flight probe is a [`Probe::Paths`] list is
//! checked here: a listed path that exists (a directory only when it has
//! entries) means the channel is live on this decoy, and the finding carries the
//! row's mitigation and doc section. Rows covered by a dedicated check name it
//! in the catalog instead, so this check never duplicates them.
//!
//! Warn-only: a channel being present is something to fix or accept, never a
//! reason to refuse activation on its own. A probe path the check cannot look
//! up, for another reason than that nothing is there, warns that it cannot
//! tell whether the channel is live, also for a row whose hit is only noted.
//! The check only tests existence and lists directories (without updating
//! access times); it writes nothing.

use crate::filesystem::automount::describe;
use crate::residue_catalog::{self, Platforms, Probe, ProbeHit, ProbeSeverity};
use crate::{Filesystem, Result};
use nails_base::preflight::{CheckResult, PreFlightCheck};
use std::path::{Path, PathBuf};

/// Pre-flight check that runs the catalog's path probes.
#[derive(Debug)]
pub struct ResidueCatalogCheck {
    /// Root of the system tree to inspect; `/` outside tests.
    root: PathBuf,
}

impl Default for ResidueCatalogCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl ResidueCatalogCheck {
    /// Create the check for the live root.
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("/"),
        }
    }

    /// Inspect the tree rooted at `root` instead of `/` (tests).
    #[cfg(test)]
    fn with_root(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    /// `path` under the inspected root.
    fn rebase(&self, path: &str) -> PathBuf {
        self.root
            .join(Path::new(path).strip_prefix("/").unwrap_or(Path::new(path)))
    }
}

/// One probe hit.
struct Hit {
    id: &'static str,
    path: &'static str,
    severity: ProbeSeverity,
    mitigation: &'static str,
    see_also: String,
}

/// A probe path the check could not look up.
struct Untold {
    id: &'static str,
    path: &'static str,
    /// Why, naming the path.
    sentence: String,
}

impl<F: Filesystem> PreFlightCheck<F> for ResidueCatalogCheck {
    fn name(&self) -> &'static str {
        "residue-catalog"
    }

    fn description(&self) -> &'static str {
        "Warns about residue channels from the catalog that are live on this decoy"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let platform = crate::platform::detect(fs)
            .ok()
            .and_then(|profile| Platforms::for_host(&profile));
        let mut hits = Vec::new();
        let mut untold = Vec::new();
        let mut probed = 0usize;

        for row in residue_catalog::catalog() {
            let Probe::Paths { paths, severity } = row.preflight else {
                continue;
            };
            if !row.platforms.applies_to(platform) {
                continue;
            }
            probed += 1;
            for path in paths {
                match residue_catalog::path_probe_hit(fs, &self.rebase(path)) {
                    ProbeHit::NoHit => {}
                    ProbeHit::Hit => hits.push(Hit {
                        id: row.id,
                        path,
                        severity,
                        mitigation: row.mitigation,
                        see_also: row.see_also(),
                    }),
                    // Whatever the row's hit would be, a channel NAILS cannot
                    // tell about warns.
                    ProbeHit::CannotTell(error) => untold.push(Untold {
                        id: row.id,
                        path,
                        sentence: describe(path, &error).sentence,
                    }),
                }
            }
        }
        Ok(judge(&hits, &untold, probed))
    }
}

/// The check's result for `hits` and the probe paths it could not look up,
/// `untold`, of `probed` catalog probes.
fn judge(hits: &[Hit], untold: &[Untold], probed: usize) -> CheckResult {
    let warnings: Vec<&Hit> = hits
        .iter()
        .filter(|hit| hit.severity != ProbeSeverity::Info)
        .collect();
    let notes: Vec<&Hit> = hits
        .iter()
        .filter(|hit| hit.severity == ProbeSeverity::Info)
        .collect();

    let entry = |hit: &&Hit| {
        format!(
            "{} ({}): {} ({})",
            hit.id, hit.path, hit.mitigation, hit.see_also
        )
    };

    if warnings.is_empty() && untold.is_empty() {
        let mut message = format!(
            "no warned residue channel is live ({})",
            nails_base::output::count_noun(probed, "catalog probe", "catalog probes")
        );
        if !notes.is_empty() {
            let lines: Vec<String> = notes.iter().map(entry).collect();
            message.push_str(&format!("; noted: {}", lines.join("; ")));
        }
        return CheckResult::Pass(message);
    }

    let mut lines = Vec::new();
    if !warnings.is_empty() {
        let mut found: Vec<String> = warnings.iter().map(entry).collect();
        found.extend(notes.iter().map(|hit| format!("note: {}", entry(hit))));
        let live = if warnings.len() == 1 {
            "1 residue channel is live".to_string()
        } else {
            format!("{} residue channels are live", warnings.len())
        };
        lines.push(format!("{live} on this decoy: {}", found.join("; ")));
    }
    lines.extend(untold.iter().map(|untold| {
        format!(
            "NAILS cannot tell whether the residue channel {} is live at {}: {}",
            untold.id, untold.path, untold.sentence
        )
    }));
    if warnings.is_empty() && !notes.is_empty() {
        let found: Vec<String> = notes.iter().map(entry).collect();
        lines.push(format!("Noted: {}", found.join("; ")));
    }
    CheckResult::Warn(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RealFilesystem;

    /// Every path under `root`, sorted, with its size: a cheap fingerprint
    /// that changes when anything is created, removed or rewritten.
    fn tree_listing(root: &Path) -> Vec<(PathBuf, u64)> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let entry = entry.unwrap();
                let meta = entry.metadata().unwrap();
                if meta.is_dir() {
                    stack.push(entry.path());
                }
                out.push((entry.path(), meta.len()));
            }
        }
        out.sort();
        out
    }

    #[test]
    fn a_clean_tree_passes() {
        let root = tempfile::tempdir().unwrap();
        let result = ResidueCatalogCheck::with_root(root.path())
            .run(&RealFilesystem)
            .unwrap();
        assert!(result.is_pass(), "{}", result.message());
        assert!(
            result.message().ends_with(" catalog probes)"),
            "{}",
            result.message()
        );
    }

    #[test]
    fn a_populated_lvm_archive_warns_with_its_doc_section() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("etc/lvm/archive");
        std::fs::create_dir_all(&archive).unwrap();
        std::fs::write(archive.join("vg0_00000-1.vg"), "contents").unwrap();

        let result = ResidueCatalogCheck::with_root(root.path())
            .run(&RealFilesystem)
            .unwrap();

        assert!(result.is_warn(), "{}", result.message());
        assert!(
            result
                .message()
                .starts_with("1 residue channel is live on this decoy: "),
            "{}",
            result.message()
        );
        assert!(result.message().contains("lvm-metadata-archive"));
        assert!(
            result
                .message()
                .contains("decoy-requirements.md#lvm-metadata-archives")
        );

        // A second live channel: the plural.
        let udisks = root.path().join("var/lib/udisks2");
        std::fs::create_dir_all(&udisks).unwrap();
        std::fs::write(udisks.join("drive.conf"), "x").unwrap();
        let result = ResidueCatalogCheck::with_root(root.path())
            .run(&RealFilesystem)
            .unwrap();
        assert!(
            result
                .message()
                .starts_with("2 residue channels are live on this decoy: "),
            "{}",
            result.message()
        );
    }

    #[test]
    fn an_empty_directory_is_not_a_hit() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("etc/lvm/archive")).unwrap();
        std::fs::create_dir_all(root.path().join("var/lib/udisks2")).unwrap();

        let result = ResidueCatalogCheck::with_root(root.path())
            .run(&RealFilesystem)
            .unwrap();
        assert!(result.is_pass(), "{}", result.message());
    }

    #[test]
    fn an_info_channel_is_noted_without_warning() {
        let root = tempfile::tempdir().unwrap();
        let clock = root.path().join("var/lib/systemd/timesync");
        std::fs::create_dir_all(&clock).unwrap();
        std::fs::write(clock.join("clock"), "").unwrap();

        let result = ResidueCatalogCheck::with_root(root.path())
            .run(&RealFilesystem)
            .unwrap();
        assert!(result.is_pass(), "{}", result.message());
        assert!(result.message().contains("timesync-clock"));
    }

    #[test]
    fn the_check_writes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let udisks = root.path().join("var/lib/udisks2");
        std::fs::create_dir_all(&udisks).unwrap();
        std::fs::write(udisks.join("drive.conf"), "x").unwrap();
        let before = tree_listing(root.path());

        let _ = ResidueCatalogCheck::with_root(root.path())
            .run(&RealFilesystem)
            .unwrap();

        assert_eq!(tree_listing(root.path()), before);
    }

    /// A probe path whose lookup fails for another reason than that nothing
    /// is there was taken for one that holds nothing, so the check passed on
    /// a path it never saw. It warns that it cannot tell, naming the path
    /// and why, for a row whose hit is only noted too.
    #[test]
    fn a_probe_path_nails_cannot_look_up_warns_for_every_row() {
        use crate::MockFilesystem;
        use std::io::ErrorKind;
        let fs = MockFilesystem::new();
        fs.mock_set_lookup_error("/var/lib/chrony", ErrorKind::PermissionDenied);
        let result = ResidueCatalogCheck::new().run(&fs).unwrap();
        assert_eq!(
            result,
            CheckResult::Warn(
                "NAILS cannot tell whether the residue channel chrony-drift is live at \
                 /var/lib/chrony: NAILS cannot look up /var/lib/chrony; run the command again \
                 with sudo"
                    .to_string()
            )
        );

        // Beside a live channel and a noted one, the line comes after them;
        // an error other than a missing permission is named.
        fs.mock_set_lookup_error("/var/lib/chrony", ErrorKind::Other);
        fs.mock_add_file("/var/lib/udisks2/drive.conf", "x");
        fs.mock_set_path_type("/var/lib/udisks2", crate::filesystem::PathKind::Dir);
        fs.mock_set_directory_contents(
            Path::new("/var/lib/udisks2"),
            vec![PathBuf::from("/var/lib/udisks2/drive.conf")],
        );
        fs.mock_add_file("/var/lib/systemd/timesync/clock", "");
        let result = ResidueCatalogCheck::new().run(&fs).unwrap();
        assert!(result.is_warn(), "{result:?}");
        let lines: Vec<&str> = result.message().lines().collect();
        assert_eq!(lines.len(), 2, "{result:?}");
        assert!(
            lines[0].starts_with("1 residue channel is live on this decoy: udisks2-state (")
                && lines[0].contains("; note: timesync-clock ("),
            "{result:?}"
        );
        assert!(
            lines[1].starts_with(
                "NAILS cannot tell whether the residue channel chrony-drift is live at \
                 /var/lib/chrony: NAILS cannot look up /var/lib/chrony (/var/lib/chrony: "
            ),
            "{result:?}"
        );

        // Without a live channel, the noted one follows the line.
        fs.mock_set_path_exists("/var/lib/udisks2", false);
        let result = ResidueCatalogCheck::new().run(&fs).unwrap();
        let lines: Vec<&str> = result.message().lines().collect();
        assert_eq!(lines.len(), 2, "{result:?}");
        assert!(
            lines[0].starts_with("NAILS cannot tell whether the residue channel chrony-drift"),
            "{result:?}"
        );
        assert!(
            lines[1].starts_with("Noted: timesync-clock ("),
            "{result:?}"
        );
    }
}
