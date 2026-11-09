// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What verify reports where a lookup fails for another reason than that
//! nothing is there: a finding that it could not tell, at the severity a hit
//! would have but at most a warning, and the scan goes on. A path verify
//! could not look up never reads as clean, and never as a critical leftover.

use super::Verifier;
use crate::MockFilesystem;
use crate::config::Config;
use crate::filesystem::PathKind;
use crate::residue_catalog::ResidueKind;
use crate::verify::{Finding, Severity, StateFileStatus, VerifyStatus};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

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

/// A verifier over `fs` with `config` and no state file.
fn configured(fs: &MockFilesystem, config: Config) -> Verifier<MockFilesystem> {
    Verifier::with_config(fs.clone(), config, None, StateFileStatus::NotChecked)
}

/// The configured paths verify cannot look up: the hidden volume path, the
/// log directory off the volume and the state file were taken for missing.
/// Each is a warning that verify could not tell.
#[test]
fn configured_paths_verify_cannot_look_up_warn() {
    let fs = MockFilesystem::new();
    for path in ["/mnt/test-hidden", "/var/log/nails-test", "/srv/state.json"] {
        fs.mock_set_lookup_error(path, ErrorKind::PermissionDenied);
    }
    let config = Config {
        hidden_volume_root: PathBuf::from("/mnt/test-hidden"),
        log_path: PathBuf::from("/var/log/nails-test"),
        state_file_path: PathBuf::from("/srv/state.json"),
        ..Config::default()
    };
    let (findings, checked) = configured(&fs, config.clone())
        .check_config_paths(&config, false)
        .unwrap();
    assert_eq!(checked, 3);
    for message in [
        format!(
            "Could not tell whether the hidden volume path /mnt/test-hidden is accessible: {MOCK}"
        ),
        format!(
            "Could not tell whether log files are left in the configured log directory \
             /var/log/nails-test: {MOCK}"
        ),
        format!(
            "Could not tell whether a state file exists at the configured path \
             /srv/state.json: {MOCK}"
        ),
    ] {
        let found = finding(&findings, &message);
        assert_eq!(found.message, message);
        assert_eq!(found.severity, Severity::Warn);
        assert_eq!(found.category, "config");
    }
}

/// The hidden root defaults to the binary's folder, which counts only when
/// the attach gate takes it for a mounted, marked volume. Where the gate
/// cannot tell (no marker can be looked up, or no mount table read), the
/// root counts as genuine: the exposure is still reported, saying what
/// verify could not tell, where before the scan stopped with the error or
/// reported nothing.
#[test]
fn a_defaulted_root_the_gate_cannot_tell_about_still_reports_its_exposure() {
    let root = crate::config::derive_hidden_volume_root();
    let config = || Config {
        hidden_volume_root: root.clone(),
        ..Config::default()
    };
    // Mounted on its own device, with markers that cannot be looked up.
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(root.to_str().unwrap(), true);
    fs.mock_set_mounted(&root, true);
    fs.mock_set_device_id(Path::new("/"), 1);
    fs.mock_set_device_id(&root, 42);
    for marker in ["state.json", "config"] {
        fs.mock_set_lookup_error(
            root.join(marker).to_str().unwrap(),
            ErrorKind::PermissionDenied,
        );
    }
    let result = configured(&fs, config()).run(false).unwrap();
    let exposure = finding(&result.findings, "Hidden volume path is accessible");
    assert_eq!(exposure.severity, Severity::Warn);
    assert!(
        exposure.message.starts_with(&format!(
            "Hidden volume path is accessible: {}, and verify could not tell whether it is a \
             mounted hidden volume or only the folder the program runs from: ",
            root.display()
        )) && exposure.message.contains("state.json"),
        "{exposure:?}"
    );
    assert_eq!(result.status, VerifyStatus::Warning);

    // No mount table: the gate cannot tell either.
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(root.to_str().unwrap(), true);
    fs.mock_set_mount_table_error("no mountinfo");
    let result = configured(&fs, config()).run(false).unwrap();
    let exposure = finding(&result.findings, "Hidden volume path is accessible");
    assert!(
        exposure.message.contains("the mount table cannot be read"),
        "{exposure:?}"
    );

    // A root that cannot be looked up is one verify cannot tell is
    // accessible.
    let fs = MockFilesystem::new();
    fs.mock_set_lookup_error(root.to_str().unwrap(), ErrorKind::PermissionDenied);
    let result = configured(&fs, config()).run(false).unwrap();
    let message = format!(
        "Could not tell whether the hidden volume path {} is accessible: {MOCK}",
        root.display()
    );
    assert_eq!(finding(&result.findings, &message).severity, Severity::Warn);
}

/// What the deep scan cannot look up: a temporary or log directory, a shell
/// history and a desktop recency file were skipped as missing. Each is a
/// warning that verify could not tell what it holds.
#[test]
fn deep_scan_paths_verify_cannot_look_up_warn() {
    let fs = MockFilesystem::new();
    for path in [
        "/var/tmp",
        "/root/.bash_history",
        "/root/.local/share/recently-used.xbel",
    ] {
        fs.mock_set_lookup_error(path, ErrorKind::PermissionDenied);
    }
    let config = Config {
        hidden_volume_root: PathBuf::from("/mnt/hidden"),
        ..Config::default()
    };
    let findings = configured(&fs, config).deep_scan().unwrap();
    for message in [
        format!("Could not tell whether NAILS-related files are left in /var/tmp: {MOCK}"),
        format!(
            "Could not tell whether the shell history /root/.bash_history contains nails \
             commands: {MOCK}"
        ),
        format!(
            "Could not tell whether the desktop recency file \
             /root/.local/share/recently-used.xbel references the hidden volume root: {MOCK}"
        ),
    ] {
        let found = finding(&findings, &message);
        assert_eq!(found.message, message);
        assert_eq!(found.severity, Severity::Warn);
        assert_eq!(found.category, "file");
    }
}

/// The residue report goes on a hidden root the attach gate takes for
/// attached; on one whose lookup fails it is refused and nothing is
/// written.
#[test]
fn no_residue_report_is_written_on_a_root_that_cannot_be_looked_up() {
    let fs = MockFilesystem::new();
    fs.mock_set_lookup_error("/mnt/hidden", ErrorKind::PermissionDenied);
    let result = crate::verify::VerifyResult::secure(crate::verify::ScanDepth::Standard);
    let error = crate::verify::write_activation_residue_report(
        &fs,
        Path::new("/mnt/hidden"),
        &result,
        "2026-11-09T10:00:00Z",
    )
    .unwrap_err();
    assert!(
        error.to_string().contains(
            "refusing to write the residue report: nothing shows that /mnt/hidden is a volume \
             of its own: it cannot be looked up"
        ),
        "{error}"
    );
    assert!(fs.mock_written_paths().is_empty());
    assert!(fs.mock_ops().is_empty(), "{:?}", fs.mock_ops());
}
