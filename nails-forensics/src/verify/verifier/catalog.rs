// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The residue catalog's part of a verify run: its path probes, and the areas
//! a run could not cover, derived from the catalog rows instead of a fixed list.

use super::*;
use crate::residue_catalog::{self, Platforms, Probe, ProbeSeverity, ResidueKind};
use std::time::SystemTime;

/// Every check id a verify run can execute. Catalog rows name these in
/// [`Probe::Check`]; a unit test keeps the two in step.
pub const VERIFY_CHECK_IDS: &[&str] = &[
    "session-leftovers",
    "artifact-files",
    "processes",
    "memory-swap",
    "block-devices",
    "platform-scanners",
    "config-paths",
    "state",
    "deep-scan-files",
    "deep-scan-history",
    "deep-scan-recent-files",
    "journal-scan",
    "catalog-paths",
    "examiner-catalog-paths",
    "examiner-disk",
    "examiner-containers",
    "examiner-config",
    "examiner-lvm",
    "examiner-tooling",
    "examiner-history",
];

impl<F: Filesystem> Verifier<F> {
    /// The host family the catalog rows are filtered by: the live host's, or
    /// `None` (every row) for an offline image — whose family is not the host's —
    /// or a host detection could not place.
    fn catalog_platform(&self) -> Option<Platforms> {
        if self.is_offline() {
            return None;
        }
        crate::platform::detect(&self.filesystem)
            .ok()
            .and_then(|profile| Platforms::for_host(&profile))
    }

    /// Run the catalog's verify path probes for one kind of residue.
    ///
    /// Each row whose verify probe is a [`Probe::Paths`] list reports every
    /// listed path that exists on the inspected root (a directory only when it
    /// has entries), with the row's mitigation and doc section as guidance. A
    /// file's modification time is included, because for the session-time
    /// classes the time is the evidence.
    pub(super) fn check_catalog_paths(&self, kind: ResidueKind) -> Vec<Finding> {
        let platform = self.catalog_platform();
        let mut findings = Vec::new();
        for row in residue_catalog::catalog() {
            if row.kind != kind || !row.platforms.applies_to(platform) {
                continue;
            }
            let Probe::Paths { paths, severity } = row.verify else {
                continue;
            };
            for path in paths {
                let probe = self.rebase(Path::new(path));
                if !residue_catalog::path_probe_hit(&self.filesystem, &probe) {
                    continue;
                }
                let when = std::fs::symlink_metadata(&probe)
                    .and_then(|meta| meta.modified())
                    .ok()
                    .map(|time| format!(", modified {}", format_time(time)))
                    .unwrap_or_default();
                findings.push(
                    Finding::new(
                        map_probe_severity(severity),
                        "catalog",
                        format!("{} present: {path}{when} [{}]", row.title, row.id),
                    )
                    .with_fix_guidance(format!(
                        "{} ({})",
                        row.mitigation,
                        row.see_also()
                    )),
                );
            }
        }
        findings
    }

    /// The catalog rows this run could not cover, as areas not checked.
    ///
    /// A row whose verify probe is a check that did not run in this mode is
    /// grouped under the hint that would run it (`--deep`, the live host,
    /// `--examiner`); a row no verify probe can see is listed with its reason.
    /// Setup traces are summarised in one line unless the examiner audit ran.
    pub(super) fn catalog_areas_not_checked(
        &self,
        ran: &BTreeSet<&'static str>,
        examiner: bool,
    ) -> Vec<String> {
        let platform = self.catalog_platform();
        let mut grouped: Vec<(String, Vec<&'static str>)> = Vec::new();
        let mut undetectable = Vec::new();
        let mut setup_titles = Vec::new();

        for row in residue_catalog::catalog() {
            if !row.platforms.applies_to(platform) {
                continue;
            }
            if row.kind == ResidueKind::Setup && !examiner {
                setup_titles.push(row.title);
                continue;
            }
            match row.verify {
                Probe::Check(id) if !ran.contains(id) => {
                    let hint = self.hint_for(id);
                    match grouped.iter_mut().find(|(h, _)| *h == hint) {
                        Some((_, titles)) => titles.push(row.title),
                        None => grouped.push((hint, vec![row.title])),
                    }
                }
                Probe::None(reason) => undetectable.push(format!("{}: {reason}", row.title)),
                _ => {}
            }
        }

        let mut areas: Vec<String> = grouped
            .into_iter()
            .map(|(hint, titles)| format!("{} ({hint})", titles.join(", ")))
            .collect();
        areas.extend(undetectable);
        if !setup_titles.is_empty() {
            areas.push(format!(
                "setup traces an examiner looks for ({}): run verify --offline --root <image> --examiner",
                setup_titles.join(", ")
            ));
        }
        areas
    }

    /// What would make a check that did not run in this mode run.
    fn hint_for(&self, id: &str) -> String {
        if id.starts_with("examiner-disk") {
            return "pass --disk to verify --offline --examiner".to_string();
        }
        if id.starts_with("examiner-") {
            return "run verify --offline --root <image> --examiner".to_string();
        }
        let live_only = matches!(
            id,
            "session-leftovers"
                | "processes"
                | "memory-swap"
                | "block-devices"
                | "platform-scanners"
                | "config-paths"
                | "state"
                | "journal-scan"
        );
        if self.is_offline() && live_only {
            return "live host only".to_string();
        }
        if id.starts_with("deep-scan") || id == "journal-scan" {
            return "re-run with --deep".to_string();
        }
        "not run in this mode".to_string()
    }
}

/// Map a catalog probe severity onto a finding severity.
fn map_probe_severity(severity: ProbeSeverity) -> Severity {
    match severity {
        ProbeSeverity::Info => Severity::Info,
        ProbeSeverity::Warn => Severity::Warn,
        ProbeSeverity::Critical => Severity::Critical,
    }
}

/// An RFC 3339 UTC timestamp for a file time.
pub(crate) fn format_time(time: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(time)
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

#[cfg(test)]
mod tests {
    use crate::{RealFilesystem, Verifier};

    fn offline_scan(root: &std::path::Path) -> crate::VerifyResult {
        Verifier::new(RealFilesystem)
            .offline_under(root.to_path_buf())
            .run(false)
            .unwrap()
    }

    #[test]
    fn a_populated_catalog_path_is_reported_with_its_row_and_doc() {
        let root = tempfile::tempdir().unwrap();
        let iolog = root.path().join("var/log/sudo-io/00/00");
        std::fs::create_dir_all(&iolog).unwrap();
        std::fs::write(iolog.join("log"), "session").unwrap();

        let result = offline_scan(root.path());

        let finding = result
            .findings
            .iter()
            .find(|f| f.category == "catalog" && f.message.contains("[sudo-io-log]"))
            .unwrap_or_else(|| panic!("no catalog finding: {:?}", result.findings));
        assert_eq!(finding.severity, crate::Severity::Warn);
        assert!(
            finding
                .fix_guidance
                .as_deref()
                .is_some_and(|g| g.contains("docs/decoy-requirements.md#")),
            "{finding:?}"
        );
        assert_eq!(result.status, crate::VerifyStatus::Warning);
    }

    #[test]
    fn a_session_time_stamp_is_a_note_with_its_time() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("var/lib/systemd/timesync");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("clock"), "").unwrap();

        let result = offline_scan(root.path());

        let finding = result
            .findings
            .iter()
            .find(|f| f.message.contains("[timesync-clock]"))
            .unwrap_or_else(|| panic!("no timesync finding: {:?}", result.findings));
        assert_eq!(finding.severity, crate::Severity::Info);
        assert!(
            finding.message.contains("modified 20"),
            "{}",
            finding.message
        );
        assert_eq!(result.status, crate::VerifyStatus::Secure);
    }

    #[test]
    fn a_clean_image_reports_no_catalog_finding() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("var/log/sudo-io")).unwrap();
        let result = offline_scan(root.path());
        assert!(
            result.findings.iter().all(|f| f.category != "catalog"),
            "{:?}",
            result.findings
        );
    }

    #[test]
    fn areas_not_checked_come_from_the_catalog() {
        let root = tempfile::tempdir().unwrap();
        let result = offline_scan(root.path());
        let areas = result.areas_not_checked.join("\n");

        // A class no verify probe can see is listed with its reason.
        assert!(areas.contains("SMART power-on hours: "), "{areas}");
        // A class whose check needs the live host is grouped under that hint.
        assert!(areas.contains("Swap and hibernation"), "{areas}");
        assert!(areas.contains("(live host only)"), "{areas}");
        // Setup traces are summarised once, pointing at the examiner audit.
        assert!(
            areas.contains("setup traces an examiner looks for ("),
            "{areas}"
        );
    }

    #[test]
    fn catalog_paths_are_filtered_to_the_detected_host_platform() {
        use crate::MockFilesystem;
        use crate::residue_catalog::ResidueKind;

        // A live run (Host context) whose host detection resolves to NixOS:
        // `ID=nixos` with systemd as PID 1. On a live run `catalog_platform`
        // returns `Some(NIXOS)`, so the catalog is filtered to the host family.
        let fs = MockFilesystem::new();
        fs.mock_add_file("/etc/os-release", "ID=nixos\nVERSION_ID=\"24.11\"\n");
        fs.mock_add_file("/proc/1/comm", "systemd");
        // All-platform session classes present on disk: one every host writes,
        // and Plymouth's boot log, which a NixOS decoy booting with Plymouth
        // writes as the other families do...
        fs.mock_add_file("/var/log/sudo.log", "activation command line");
        fs.mock_add_file("/var/log/boot.log", "boot messages");
        // ...and a Fedora-only session class present on disk (Fedora's GRUB
        // environment block, which no NixOS decoy keeps).
        fs.mock_add_file("/boot/grub2/grubenv", "boot_success=1");

        let verifier = Verifier::new(fs);
        let findings = verifier.check_catalog_paths(ResidueKind::Session);
        let messages: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();

        // The all-platform rows apply to a NixOS host, so their probes fire and
        // the present paths are reported: this proves the probe machinery ran.
        for id in ["[sudo-logfile]", "[plymouth-boot-log]"] {
            assert!(
                messages.iter().any(|m| m.contains(id)),
                "an all-platform catalog row must apply to a detected NixOS host ({id}): \
                 {messages:?}"
            );
        }
        // The Fedora-only row does NOT apply to a NixOS host, so its present
        // path is filtered out. If `catalog_platform` returned `None` (every
        // row applies), this Fedora-only class would be reported — so this
        // assertion fails the moment the host platform is not consulted.
        assert!(
            !messages
                .iter()
                .any(|m| m.contains("[grubenv-boot-success]")),
            "a Fedora-only catalog row must be filtered out on a detected NixOS host: {messages:?}"
        );
    }

    #[test]
    fn every_verify_check_id_is_unique() {
        let mut ids: Vec<&str> = super::VERIFY_CHECK_IDS.to_vec();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len());
    }
}
