// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What verify reports where a lookup fails for another reason than that
//! nothing is there: a finding that it could not tell, at the severity a hit
//! would have but at most a warning, and the scan goes on. A path verify
//! could not look up never reads as clean, and never as a critical leftover.

use super::Verifier;
use crate::MockFilesystem;
use crate::filesystem::PathKind;
use crate::residue_catalog::ResidueKind;
use crate::verify::{Finding, Severity, VerifyStatus};
use std::io::ErrorKind;
use std::path::Path;

/// The error text the mock gives a lookup it fails.
const MOCK: &str = "Mock: the lookup fails here";

/// The one finding of `findings` whose message holds `needle`.
fn finding<'a>(findings: &'a [Finding], needle: &str) -> &'a Finding {
    let mut matching = findings.iter().filter(|f| f.message.contains(needle));
    let found = matching
        .next()
        .unwrap_or_else(|| panic!("no finding holds {needle:?}: {findings:#?}"));
    assert!(matching.next().is_none(), "{findings:#?}");
    found
}

/// A catalog path verify cannot look up was taken for one that holds
/// nothing. It is a finding that verify could not tell, at the row's
/// severity: a warning for a row whose hit warns, a note for one whose hit
/// is only noted.
#[test]
fn a_catalog_path_verify_cannot_look_up_is_one_it_cannot_tell() {
    let fs = MockFilesystem::new();
    fs.mock_set_lookup_error("/var/log/sudo-io", ErrorKind::PermissionDenied);
    fs.mock_set_lookup_error("/var/lib/chrony", ErrorKind::Other);
    let findings = Verifier::new(fs).check_catalog_paths(ResidueKind::Session);

    let sudo = finding(&findings, "[sudo-io-log]");
    assert_eq!(sudo.severity, Severity::Warn);
    assert_eq!(sudo.category, "catalog");
    assert_eq!(
        sudo.message,
        "sudo I/O logging not checked: could not tell whether /var/log/sudo-io is live \
         [sudo-io-log]: Mock: the lookup fails here"
    );
    assert_eq!(
        sudo.fix_guidance.as_deref(),
        Some("Find out why /var/log/sudo-io cannot be looked up, then run verify again")
    );
    let chrony = finding(&findings, "[chrony-drift]");
    assert_eq!(chrony.severity, Severity::Info);
    assert!(
        chrony
            .message
            .contains("could not tell whether /var/lib/chrony is live"),
        "{chrony:?}"
    );
}

/// What an entry or a session leaves in /run cannot be looked up: each
/// leftover is one verify cannot tell is left, a warning where a leftover it
/// found would be critical. The run's status is a warning (exit 10), never
/// critical (exit 11), which keeps meaning that a leftover was found.
#[test]
fn session_leftovers_verify_cannot_look_up_warn_and_never_read_as_critical() {
    let fs = MockFilesystem::new();
    fs.mock_set_lookup_error("/run/overlay-runtime", ErrorKind::PermissionDenied);
    fs.mock_set_lookup_error("/run/systemd", ErrorKind::PermissionDenied);
    let result = Verifier::new(fs).run(false).unwrap();
    assert_eq!(
        result.status,
        VerifyStatus::Warning,
        "{:#?}",
        result.findings
    );
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.severity != Severity::Critical),
        "{:#?}",
        result.findings
    );
    for message in [
        format!(
            "Could not tell whether a session plan is left at /run/overlay-runtime/plan.json: \
             {MOCK}"
        ),
        format!(
            "Could not tell whether the session runtime directory /run/overlay-runtime is left \
             in RAM: {MOCK}"
        ),
        format!(
            "Could not tell whether the soft-reboot transition drop-in \
             /run/systemd/system/systemd-soft-reboot.service.d/50-overlay-runtime.conf is left: \
             {MOCK}"
        ),
        format!(
            "Could not tell whether a unit or a mask of the session is left in \
             /run/systemd/system: {MOCK}"
        ),
        format!(
            "Could not tell whether a skip drop-in of the session is left in \
             /run/systemd/system: {MOCK}"
        ),
    ] {
        let found = finding(&result.findings, &message);
        assert_eq!(found.message, message);
        assert_eq!(found.severity, Severity::Warn, "{found:?}");
        assert_eq!(found.category, "session");
    }
    let guard = finding(
        &result.findings,
        "Could not tell whether the session's runtime guard /run/systemd/system/dbus.service.d/",
    );
    assert_eq!(guard.severity, Severity::Warn, "{guard:?}");

    // A plan that cannot be looked up beside a runtime directory that can:
    // the directory left in RAM is still found, and critical.
    let fs = MockFilesystem::new();
    fs.mock_set_lookup_error("/run/overlay-runtime/plan.json", ErrorKind::Other);
    fs.mock_set_path_type("/run/overlay-runtime", PathKind::Dir);
    let findings = Verifier::new(fs).check_session_leftovers(None);
    assert_eq!(
        finding(&findings, "a session plan is left").severity,
        Severity::Warn
    );
    assert_eq!(
        finding(&findings, "is left in RAM").severity,
        Severity::Critical
    );
}

/// A runtime unit link that cannot be looked up is one verify cannot tell
/// is a mask: a warning, as a mask it found would be.
#[test]
fn a_runtime_unit_link_verify_cannot_look_up_may_be_a_mask() {
    let fs = MockFilesystem::new();
    let dir = Path::new("/run/systemd/system");
    fs.mock_set_path_type("/run/systemd/system", PathKind::Dir);
    fs.mock_set_directory_contents(dir, vec![dir.join("foo.service")]);
    fs.mock_set_lookup_error(
        "/run/systemd/system/foo.service",
        ErrorKind::PermissionDenied,
    );
    let findings = Verifier::new(fs).check_session_leftovers(None);
    let masked = finding(&findings, "foo.service is masked");
    assert_eq!(masked.severity, Severity::Warn);
    assert_eq!(
        masked.message,
        format!(
            "Could not tell whether foo.service is masked at runtime \
             (/run/systemd/system/foo.service): {MOCK}"
        )
    );
}

/// An artifact path verify cannot look up was taken for a missing one. It
/// is a finding that verify could not tell, at the registry's severity but
/// at most a warning: a critical decoy trace it could not look up warns.
#[test]
fn an_artifact_path_verify_cannot_look_up_is_one_it_cannot_tell() {
    let fs = MockFilesystem::new();
    fs.mock_set_lookup_error("/mnt/nails-pivot", ErrorKind::PermissionDenied);
    let findings = Verifier::new(fs).check_artifact_files(None);
    let pivot = finding(&findings, "/mnt/nails-pivot");
    assert_eq!(pivot.severity, Severity::Warn);
    assert_eq!(pivot.category, "file");
    assert_eq!(
        pivot.message,
        format!("Could not tell whether an artifact file is at /mnt/nails-pivot: {MOCK}")
    );
}
