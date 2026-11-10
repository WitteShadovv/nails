// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What unattended-upgrades' checks make of a lookup that fails for another
//! reason than that nothing is there, or that the automount guard does not
//! make: never a path that is not there.

use super::tests::{OFF, ON, mock_decoy};
use super::*;
use crate::filesystem::MockFilesystem;
use crate::preflight::checks::automount_fixture::{reached, with_automounts};
use crate::preflight::checks::decoy_posture::DecoyPersistenceCheck;
use crate::preflight::{CheckResult, InstallAtShutdown, PreFlightCheck};
use std::io::ErrorKind;

/// The helper's link in the dependency directory its package enables it
/// from, which the mock lists.
const WANTS: &str = "/etc/systemd/system/multi-user.target.wants";

/// Enable the helper on `fs`, as its package does.
fn enable(fs: &MockFilesystem) {
    fs.mock_set_directory_contents(Path::new("/etc/systemd/system"), vec![PathBuf::from(WANTS)]);
    fs.create_symlink(
        Path::new("/usr/lib/systemd/system/unattended-upgrades.service"),
        &Path::new(WANTS).join(UNIT),
    )
    .unwrap();
}

fn blocker(finding: &Finding) -> &Blocker {
    finding
        .blocker
        .as_ref()
        .unwrap_or_else(|| panic!("no refusal: {finding:?}"))
}

/// A part of `/etc/apt/apt.conf.d` that cannot be looked up may turn the
/// setting on: the setting is unknown, and refused as if on, where a lookup
/// that failed read as a file that is not there and the other part's `false`
/// let the decoy pass.
#[test]
fn a_part_that_cannot_be_looked_up_leaves_the_setting_unknown() {
    for kind in [ErrorKind::PermissionDenied, ErrorKind::Other] {
        let fs = mock_decoy(
            true,
            &[("50unattended-upgrades", Some(OFF)), ("99local", Some(ON))],
        );
        fs.mock_set_lookup_error("/etc/apt/apt.conf.d/99local", kind);
        let found = finding(&fs, Path::new("/"), None);
        let blocker = blocker(&found);
        assert_eq!(blocker.at_the_switch, AtTheSwitch::Unknown, "{kind:?}");
        assert!(
            blocker
                .finding
                .contains("/etc/apt/apt.conf.d/99local cannot be looked up ("),
            "{kind:?}: {}",
            blocker.finding
        );
    }
    // A part that is not there is no part.
    let fs = mock_decoy(true, &[("50unattended-upgrades", Some(OFF))]);
    fs.mock_set_lookup_error("/etc/apt/apt.conf.d/99local", ErrorKind::NotFound);
    assert_eq!(finding(&fs, Path::new("/"), None).blocker, None);
}

/// `/etc/apt/apt.conf.d` itself that cannot be looked up hides every part:
/// unknown, never a directory that is not there.
#[test]
fn a_parts_directory_that_cannot_be_looked_up_leaves_the_setting_unknown() {
    let fs = mock_decoy(true, &[("50unattended-upgrades", Some(OFF))]);
    fs.mock_set_lookup_error("/etc/apt/apt.conf.d", ErrorKind::Other);
    let found = finding(&fs, Path::new("/"), None);
    let blocker = blocker(&found);
    assert_eq!(blocker.at_the_switch, AtTheSwitch::Unknown);
    assert!(
        blocker
            .finding
            .contains("/etc/apt/apt.conf.d cannot be looked up ("),
        "{}",
        blocker.finding
    );
}

/// A helper whose unit's marker cannot be looked up, and that no other route
/// shows running, may run: refused as if it installed, where it read as a
/// helper that does not run.
#[test]
fn a_helper_nails_cannot_tell_runs_is_refused() {
    let fs = mock_decoy(false, &[("99local", Some(ON))]);
    fs.mock_set_lookup_error(
        "/run/systemd/units/invocation:unattended-upgrades.service",
        ErrorKind::PermissionDenied,
    );
    let found = finding(&fs, Path::new("/"), None);
    let blocker = blocker(&found);
    assert_eq!(blocker.at_the_switch, AtTheSwitch::Unknown);
    assert!(
        blocker.finding.contains(
            "NAILS cannot tell whether unattended-upgrades.service runs: NAILS cannot look up \
             /run/systemd/units/invocation:unattended-upgrades.service"
        ),
        "{}",
        blocker.finding
    );
}

/// python3-gi's module that cannot be looked up may be missing: the warning
/// says NAILS cannot tell, where it said python3-gi is not installed.
#[test]
fn a_module_that_cannot_be_looked_up_leaves_python3_gi_unknown() {
    let fs = MockFilesystem::new();
    enable(&fs);
    fs.mock_set_lookup_error(
        "/usr/lib/python3/dist-packages/gi/__init__.py",
        ErrorKind::PermissionDenied,
    );
    let warning = polling::warning(&fs, Path::new("/")).expect("a warning");
    assert!(
        warning.contains(
            "unattended-upgrades.service is enabled on the decoy and NAILS cannot tell whether \
             python3-gi is installed"
        ),
        "{warning}"
    );
}

/// A helper NAILS cannot tell is enabled warns where python3-gi may be
/// missing, and says why; with python3-gi there it does not matter.
#[test]
fn a_helper_nails_cannot_tell_is_enabled_warns_where_python3_gi_is_missing() {
    let fs = MockFilesystem::new();
    enable(&fs);
    fs.mock_set_lookup_error(&format!("{WANTS}/{UNIT}"), ErrorKind::Other);
    let warning = polling::warning(&fs, Path::new("/")).expect("a warning");
    assert!(
        warning.starts_with(
            "NAILS cannot tell whether unattended-upgrades.service is enabled: NAILS cannot \
             look up /etc/systemd/system/multi-user.target.wants/unattended-upgrades.service"
        ),
        "{warning}"
    );
    assert!(
        warning.contains(
            ", and python3-gi is not installed (no \
             /usr/lib/python3/dist-packages/gi/__init__.py): if unattended-upgrades.service is \
             enabled, it writes two WARNING lines"
        ),
        "{warning}"
    );
    fs.mock_add_file("/usr/lib/python3/dist-packages/gi/__init__.py", "");
    assert_eq!(polling::warning(&fs, Path::new("/")), None);
}

/// A mask that cannot be looked up leaves NAILS unable to tell whether the
/// hidden session starts its own copy of the helper, where it read as no
/// mask: the warning says so.
#[test]
fn a_mask_that_cannot_be_looked_up_leaves_the_sessions_copy_unknown() {
    let fs = mock_decoy(false, &[("99local", Some(ON))]);
    enable(&fs);
    fs.mock_set_lookup_error(
        "/etc/systemd/system/unattended-upgrades.service",
        ErrorKind::PermissionDenied,
    );
    let found = finding(&fs, Path::new("/"), None);
    assert_eq!(found.blocker, None);
    let warning = found.warning.expect("a warning");
    assert!(
        warning.starts_with(
            "NAILS cannot tell whether the hidden session starts its own copy of \
             unattended-upgrades' shutdown helper (unattended-upgrades.service is enabled unless \
             /etc/systemd/system/unattended-upgrades.service masks it, which NAILS cannot tell"
        ),
        "{warning}"
    );
}

/// decoy-persistence reads apt's files through the automount guard: where
/// `/etc/apt/apt.conf.d` is an automount point that nothing is mounted on
/// yet, it is not looked up, the check refuses naming the point, with the
/// override, and status cannot tell either.
#[test]
fn apts_files_behind_an_automount_point_are_not_looked_up() {
    let fs = mock_decoy(true, &[("50unattended-upgrades", Some(OFF))]);
    with_automounts(&fs, &["/etc/apt/apt.conf.d"]);
    fs.mock_clear_lookups();
    let result = DecoyPersistenceCheck::new(false, false).run(&fs).unwrap();
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .contains("since the lookup would mount the automount point /etc/apt/apt.conf.d"),
        "{result:?}"
    );
    assert!(
        matches!(
            result,
            CheckResult::Fail {
                allowable: Some(nails_api::Allowable::PersistentDecoy),
                ..
            }
        ),
        "{result:?}"
    );
    assert!(
        !reached(&fs, "/etc/apt/apt.conf.d"),
        "{:?}",
        fs.mock_lookups()
    );

    fs.mock_clear_lookups();
    assert_eq!(
        DecoyPersistenceCheck::decoy_install_at_shutdown(&fs),
        Some(InstallAtShutdown::Unknown)
    );
    assert!(
        !reached(&fs, "/etc/apt/apt.conf.d"),
        "{:?}",
        fs.mock_lookups()
    );
}

/// The refusal says the decoy keeps a record where the helper installs, and
/// that it keeps, or may keep, one where NAILS cannot tell.
#[test]
fn the_refusal_says_may_keep_only_where_nails_cannot_tell() {
    let check = DecoyPersistenceCheck::new(false, false);
    // An amnesic decoy, whose one blocker is the install at shutdown.
    let decoy = || {
        let fs = mock_decoy(true, &[("99local", Some(ON))]);
        fs.mock_add_file(
            "/etc/systemd/journald.conf",
            "[Journal]\nStorage=volatile\n",
        );
        fs
    };
    let on = decoy();
    let result = check.run(&on).unwrap();
    assert!(
        result.message().starts_with(
            "decoy keeps a persistent record of the hidden session: unattended-upgrades \
             installs the pending updates"
        ),
        "{result:?}"
    );

    let untold = decoy();
    untold.mock_set_lookup_error("/etc/apt/apt.conf.d/99local", ErrorKind::Other);
    let result = check.run(&untold).unwrap();
    assert!(
        result.message().starts_with(
            "decoy keeps, or may keep, a persistent record of the hidden session: NAILS cannot \
             tell whether unattended-upgrades installs the pending updates at activation"
        ),
        "{result:?}"
    );
}

/// status cannot tell where the guard made no lookup the probe needed, even
/// where what it did read finds nothing: behind an automount point, and
/// without the mount table.
#[test]
fn status_cannot_tell_where_a_lookup_was_not_made() {
    let fs = MockFilesystem::new();
    enable(&fs);
    fs.mock_add_file("/usr/lib/python3/dist-packages/gi/__init__.py", "");
    assert_eq!(DecoyPersistenceCheck::decoy_install_at_shutdown(&fs), None);

    with_automounts(&fs, &["/usr/lib/python3/dist-packages/gi"]);
    fs.mock_clear_lookups();
    assert_eq!(
        DecoyPersistenceCheck::decoy_install_at_shutdown(&fs),
        Some(InstallAtShutdown::Unknown)
    );
    assert!(
        !reached(&fs, "/usr/lib/python3/dist-packages/gi"),
        "{:?}",
        fs.mock_lookups()
    );

    fs.mock_set_mount_table_error("permission denied");
    fs.mock_clear_lookups();
    assert_eq!(
        DecoyPersistenceCheck::decoy_install_at_shutdown(&fs),
        Some(InstallAtShutdown::Unknown)
    );
    assert!(fs.mock_lookups().is_empty(), "{:?}", fs.mock_lookups());
}
