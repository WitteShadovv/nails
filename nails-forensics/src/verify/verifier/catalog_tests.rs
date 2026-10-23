// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the residue catalog's part of a verify run.

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
    // An all-platform session class present on disk...
    fs.mock_add_file("/var/log/sudo.log", "activation command line");
    // ...and an FHS-only session class present on disk (Plymouth's boot log
    // belongs to the Debian/Fedora/Arch families, never to NixOS).
    fs.mock_add_file("/var/log/boot.log", "boot messages");

    let verifier = Verifier::new(fs);
    let findings = verifier.check_catalog_paths(ResidueKind::Session);
    let messages: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();

    // The all-platform row applies to a NixOS host, so the probe fires and
    // the present path is reported: this proves the probe machinery ran.
    assert!(
        messages.iter().any(|m| m.contains("[sudo-logfile]")),
        "an all-platform catalog row must apply to a detected NixOS host: {messages:?}"
    );
    // The FHS-only row does NOT apply to a NixOS host, so its present path
    // is filtered out. If `catalog_platform` returned `None` (every row
    // applies), this FHS-only class would be reported — so this assertion
    // fails the moment the host platform is not consulted.
    assert!(
        !messages.iter().any(|m| m.contains("[plymouth-boot-log]")),
        "an FHS-only catalog row must be filtered out on a detected NixOS host: {messages:?}"
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
