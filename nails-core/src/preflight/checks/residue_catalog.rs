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
//! reason to refuse activation on its own. The check only tests existence and
//! lists directories (without updating access times); it writes nothing.

use super::super::{CheckResult, PreFlightCheck};
use crate::residue_catalog::{self, Probe, ProbeSeverity};
use crate::{Filesystem, Result};
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

impl<F: Filesystem> PreFlightCheck<F> for ResidueCatalogCheck {
    fn name(&self) -> &'static str {
        "residue-catalog"
    }

    fn description(&self) -> &'static str {
        "Warns about residue channels from the catalog that are live on this decoy"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let platform = crate::platform::detect(fs).ok().map(|profile| profile.kind);
        let mut hits = Vec::new();
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
                if residue_catalog::path_probe_hit(fs, &self.rebase(path)) {
                    hits.push(Hit {
                        id: row.id,
                        path,
                        severity,
                        mitigation: row.mitigation,
                        see_also: row.see_also(),
                    });
                }
            }
        }

        let warnings: Vec<&Hit> = hits
            .iter()
            .filter(|hit| hit.severity != ProbeSeverity::Info)
            .collect();
        let notes: Vec<&Hit> = hits
            .iter()
            .filter(|hit| hit.severity == ProbeSeverity::Info)
            .collect();

        let describe = |hit: &&Hit| {
            format!(
                "{} ({}): {} ({})",
                hit.id, hit.path, hit.mitigation, hit.see_also
            )
        };

        if !warnings.is_empty() {
            let mut lines: Vec<String> = warnings.iter().map(describe).collect();
            lines.extend(notes.iter().map(|hit| format!("note: {}", describe(hit))));
            return Ok(CheckResult::Warn(format!(
                "{} residue channel(s) are live on this decoy: {}",
                warnings.len(),
                lines.join("; ")
            )));
        }

        let mut message = format!("no warned residue channel is live ({probed} catalog probe(s))");
        if !notes.is_empty() {
            let lines: Vec<String> = notes.iter().map(describe).collect();
            message.push_str(&format!("; noted: {}", lines.join("; ")));
        }
        Ok(CheckResult::Pass(message))
    }
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
        assert!(result.message().contains("lvm-metadata-archive"));
        assert!(
            result
                .message()
                .contains("decoy-requirements.md#lvm-metadata-archives")
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
}
