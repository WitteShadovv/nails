// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What unattended-upgrades' checks make of a lookup that fails for another
//! reason than that nothing is there, or that the automount guard does not
//! make: never a path that is not there.

use super::tests::{OFF, ON, mock_decoy};
use super::*;
use crate::filesystem::automount::mount_fix;
use crate::filesystem::{MockFailure, MockFilesystem, MockLookup, PathKind};
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
        let found = finding(&fs, &fs, Path::new("/"), None);
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
    assert_eq!(finding(&fs, &fs, Path::new("/"), None).blocker, None);
}

/// `/etc/apt/apt.conf.d` itself that cannot be looked up hides every part:
/// unknown, never a directory that is not there.
#[test]
fn a_parts_directory_that_cannot_be_looked_up_leaves_the_setting_unknown() {
    let fs = mock_decoy(true, &[("50unattended-upgrades", Some(OFF))]);
    fs.mock_set_lookup_error("/etc/apt/apt.conf.d", ErrorKind::Other);
    let found = finding(&fs, &fs, Path::new("/"), None);
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
    let found = finding(&fs, &fs, Path::new("/"), None);
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
    let found = finding(&fs, &fs, Path::new("/"), None);
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
/// yet, it is not looked up, and for a helper that runs, the check refuses
/// naming the point, with the override, and status cannot tell either.
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

/// The root overlay's upper of the tests that read what the hidden session
/// sees.
const UPPER: &str = "/hidden/upper";

/// The warning of the hidden session's own copy of the helper on `fs`, read
/// with [`UPPER`], where it refuses nothing.
fn session_warning_of(fs: &MockFilesystem) -> String {
    let found = finding(fs, fs, Path::new("/"), Some(Path::new(UPPER)));
    assert_eq!(found.blocker, None, "{found:?}");
    found
        .warning
        .clone()
        .unwrap_or_else(|| panic!("no warning: {found:?}"))
}

/// What the session's warning says where NAILS cannot tell what its copy
/// reads, before why.
const SESSION_UNKNOWN: &str = "NAILS cannot tell whether Unattended-Upgrade::InstallOnShutdown \
                               is on there, which would make it install the pending updates \
                               when the session ends with deactivate: ";

/// In what the hidden session sees, a part of apt's configuration whose
/// link lookup fails may be a link, which resolves through the overlay
/// there: the session's setting is unknown, where it read as no link. Every
/// lookup of the part fails, or only its link lookup, while the part reads
/// as the file it is.
#[test]
fn a_link_lookup_that_fails_in_the_sessions_view_leaves_its_setting_unknown() {
    let part = "/etc/apt/apt.conf.d/99local";
    for fails in [None, Some(MockLookup::IsSymlink)] {
        let fs = mock_decoy(
            false,
            &[("50unattended-upgrades", Some(OFF)), ("99local", Some(OFF))],
        );
        enable(&fs);
        let clear = finding(&fs, &fs, Path::new("/"), Some(Path::new(UPPER)));
        assert_eq!(clear, Finding::default());
        match fails {
            None => fs.mock_set_lookup_error(part, ErrorKind::Other),
            Some(lookup) => {
                fs.mock_fail_only(Path::new(part), lookup, MockFailure::Io(ErrorKind::Other));
            }
        }
        let warning = session_warning_of(&fs);
        assert!(
            warning.contains(&format!("{SESSION_UNKNOWN}{part} cannot be looked up (")),
            "{fails:?}: {warning}"
        );
    }
}

/// What the session's overlay holds on the way to apt's files, where its
/// lookup fails, may be a directory, a link or a whiteout: the session's
/// setting is unknown, where it read as nothing there. Every lookup of the
/// place fails (its link lookup the first), or only its link lookup, the one
/// of whether it is there, or the one of whether it is a directory.
#[test]
fn what_the_upper_holds_on_the_way_that_cannot_be_looked_up_leaves_its_setting_unknown() {
    let place = "/hidden/upper/etc";
    for fails in [
        None,
        Some(MockLookup::IsSymlink),
        Some(MockLookup::PathExists),
        Some(MockLookup::IsDirectory),
    ] {
        let fs = mock_decoy(false, &[("50unattended-upgrades", Some(OFF))]);
        enable(&fs);
        match fails {
            None => fs.mock_set_lookup_error(place, ErrorKind::Other),
            Some(lookup) => {
                fs.mock_set_path_type(place, PathKind::Dir);
                fs.mock_fail_only(Path::new(place), lookup, MockFailure::Io(ErrorKind::Other));
            }
        }
        let warning = session_warning_of(&fs);
        assert!(
            warning.contains(&format!(
                "{SESSION_UNKNOWN}what the hidden session's overlay holds at /etc cannot be read ("
            )),
            "{fails:?}: {warning}"
        );
    }
}

/// The upper's apt.conf, where the session's overlay holds `/etc/apt`, whose
/// lookup fails may be the file the session reads last: its setting is
/// unknown. Every lookup of it fails, or only the one of whether it is
/// there, or only its link lookup.
#[test]
fn an_upper_apt_conf_that_cannot_be_looked_up_leaves_the_sessions_setting_unknown() {
    let main = "/hidden/upper/etc/apt/apt.conf";
    for fails in [
        None,
        Some(MockLookup::PathExists),
        Some(MockLookup::IsSymlink),
    ] {
        let fs = mock_decoy(false, &[("50unattended-upgrades", Some(OFF))]);
        enable(&fs);
        fs.mock_set_path_type("/hidden/upper/etc", PathKind::Dir);
        fs.mock_set_path_type("/hidden/upper/etc/apt", PathKind::Dir);
        assert_eq!(
            finding(&fs, &fs, Path::new("/"), Some(Path::new(UPPER))),
            Finding::default()
        );
        match fails {
            None => fs.mock_set_lookup_error(main, ErrorKind::Other),
            Some(lookup) => {
                fs.mock_fail_only(Path::new(main), lookup, MockFailure::Io(ErrorKind::Other));
            }
        }
        let warning = session_warning_of(&fs);
        assert!(
            warning.contains(&format!(
                "{SESSION_UNKNOWN}/etc/apt/apt.conf in the hidden session's overlay cannot be \
                 looked up ("
            )),
            "{fails:?}: {warning}"
        );
    }
}

/// What the session's overlay holds in the place of the helper's mask, where
/// its lookup fails, may unmask it: NAILS cannot tell whether the session
/// starts its own copy, where it read as nothing there. Every lookup of the
/// place fails, or only its link lookup, or only the one of whether it is
/// there.
#[test]
fn a_mask_place_in_the_upper_that_cannot_be_looked_up_leaves_the_sessions_copy_unknown() {
    let place = "/hidden/upper/etc/systemd/system/unattended-upgrades.service";
    for fails in [
        None,
        Some(MockLookup::IsSymlink),
        Some(MockLookup::PathExists),
    ] {
        let fs = mock_decoy(false, &[("99local", Some(ON))]);
        enable(&fs);
        match fails {
            None => fs.mock_set_lookup_error(place, ErrorKind::Other),
            Some(lookup) => {
                fs.mock_fail_only(Path::new(place), lookup, MockFailure::Io(ErrorKind::Other));
            }
        }
        let warning = session_warning_of(&fs);
        assert!(
            warning.starts_with(
                "NAILS cannot tell whether the hidden session starts its own copy of \
                 unattended-upgrades' shutdown helper (what the hidden session's overlay holds \
                 at /etc/systemd/system/unattended-upgrades.service cannot be read ("
            ),
            "{fails:?}: {warning}"
        );
        assert!(
            warning.contains(
                "Unattended-Upgrade::InstallOnShutdown is on there \
                 (/etc/apt/apt.conf.d/99local:1): if the session starts it, it installs"
            ),
            "{fails:?}: {warning}"
        );
    }
}

/// On the decoy, a part of apt's configuration, or apt.conf, that is no file
/// may be a link that leads to no file now, which apt skips at the signal
/// while the running helper may have read through it at its start: one
/// whose link lookup fails leaves the setting unknown, refused as if on,
/// where it read as no link.
#[test]
fn a_link_lookup_that_fails_of_what_apt_skips_leaves_the_setting_unknown() {
    for (path, parts) in [
        (
            "/etc/apt/apt.conf.d/99local",
            &[("50unattended-upgrades", Some(OFF)), ("99local", None)][..],
        ),
        (
            "/etc/apt/apt.conf",
            &[("50unattended-upgrades", Some(OFF))][..],
        ),
    ] {
        let fs = mock_decoy(true, parts);
        fs.mock_set_path_type(path, PathKind::Dir);
        assert_eq!(
            finding(&fs, &fs, Path::new("/"), None).blocker,
            None,
            "{path}"
        );
        fs.mock_fail_only(
            Path::new(path),
            MockLookup::IsSymlink,
            MockFailure::Io(ErrorKind::Other),
        );
        let found = finding(&fs, &fs, Path::new("/"), None);
        let blocker = blocker(&found);
        assert_eq!(blocker.at_the_switch, AtTheSwitch::Unknown, "{path}");
        assert!(
            blocker
                .finding
                .contains(&format!("{path} cannot be looked up (")),
            "{path}: {}",
            blocker.finding
        );
    }
}

/// A check run without sudo cannot search the root overlay's upper, which
/// only root may: where the decoy's helper is stopped but enabled,
/// decoy-persistence warns that it cannot tell what the session's own copy
/// reads, where it passed.
#[test]
fn a_check_that_cannot_search_the_upper_warns_it_cannot_tell_what_the_session_reads() {
    let fs = amnesic_with_a_stopped_helper(&[("50unattended-upgrades", Some(OFF))]);
    let check = DecoyPersistenceCheck::new(false, false).with_upper(PathBuf::from(UPPER));
    let clear = check.run(&fs).unwrap();
    assert!(clear.is_pass(), "{clear:?}");
    fs.mock_set_lookup_error(UPPER, ErrorKind::PermissionDenied);
    let result = check.run(&fs).unwrap();
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains(&format!(
            "{SESSION_UNKNOWN}what the hidden session's overlay holds at /etc cannot be read ("
        )),
        "{result:?}"
    );
}

/// An amnesic decoy of the mock, journald set volatile, whose helper is
/// enabled and stopped: the hidden session starts its own copy.
fn amnesic_with_a_stopped_helper(parts: &[(&str, Option<&str>)]) -> MockFilesystem {
    let fs = mock_decoy(false, parts);
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    enable(&fs);
    fs
}

/// The check as `check` runs it, reading what the hidden session sees with
/// the root overlay's upper at `upper` on top, or the decoy alone.
fn check_with(allow: bool, upper: Option<&str>) -> DecoyPersistenceCheck {
    let check = DecoyPersistenceCheck::new(allow, false);
    match upper {
        Some(upper) => check.with_upper(PathBuf::from(upper)),
        None => check,
    }
}

/// Where the automount guard makes no lookup that only a warning needs,
/// python3-gi's module or what the hidden session's own copy of the helper
/// reads, decoy-persistence warns, naming the point and how to mount it,
/// and does not refuse, with the override or without: on the decoy alone,
/// and with the root overlay's upper, as `check` reads what the session
/// sees. Status, whose line is for the refusal, says nothing of it.
#[test]
fn a_lookup_not_made_for_a_warning_warns_and_never_refuses() {
    let python3_gi = "unattended-upgrades.service is enabled on the decoy and NAILS cannot tell \
                      whether python3-gi is installed \
                      (/usr/lib/python3/dist-packages/gi/__init__.py cannot be looked up: NAILS \
                      does not look up /usr/lib/python3/dist-packages/gi/__init__.py, since the \
                      lookup would mount the automount point /usr/lib/python3)";
    let session = "unattended-upgrades.service is stopped on the decoy but enabled, so the hidden \
                   session starts it, and NAILS cannot tell whether \
                   Unattended-Upgrade::InstallOnShutdown is on there, which would make it install \
                   the pending updates when the session ends with deactivate: ";
    let not_made = "(NAILS does not look up /etc/apt/apt.conf.d, since the lookup would mount the \
                    automount point /etc/apt/apt.conf.d)";
    let session_upper = Some("/hidden/upper");
    for (point, upper, says) in [
        ("/usr/lib/python3", None, python3_gi.to_string()),
        ("/usr/lib/python3", session_upper, python3_gi.to_string()),
        (
            "/etc/apt/apt.conf.d",
            None,
            format!("{session}/etc/apt/apt.conf.d cannot be looked up {not_made}"),
        ),
        // The session's view asks first whether the decoy's directory is a
        // link, which resolves through the overlay there.
        (
            "/etc/apt/apt.conf.d",
            session_upper,
            format!("{session}/etc/apt/apt.conf.d on the decoy cannot be looked up {not_made}"),
        ),
    ] {
        let fs = amnesic_with_a_stopped_helper(&[("50unattended-upgrades", Some(OFF))]);
        with_automounts(&fs, &[]);
        let clear = check_with(false, upper).run(&fs).unwrap();
        assert!(clear.is_pass(), "{point}, {upper:?}: {clear:?}");

        with_automounts(&fs, &[point]);
        fs.mock_clear_lookups();
        for allow in [false, true] {
            let result = check_with(allow, upper).run(&fs).unwrap();
            assert!(result.is_warn(), "{point}, {upper:?}, {allow}: {result:?}");
            assert!(
                result.message().contains(&says),
                "{point}, {upper:?}: {result:?}"
            );
            assert!(
                result.message().ends_with(&mount_fix(&[Path::new(point)])),
                "{point}, {upper:?}: {result:?}"
            );
        }
        assert!(!reached(&fs, point), "{point}: {:?}", fs.mock_lookups());
        assert_eq!(
            DecoyPersistenceCheck::decoy_install_at_shutdown(&fs),
            None,
            "{point}"
        );
        assert!(!reached(&fs, point), "{point}: {:?}", fs.mock_lookups());
    }
}

/// How the hidden session comes to start its own copy of the helper is read
/// through the warnings' view too: where the automount guard makes no lookup
/// of the place of the helper's mask in the session's overlay,
/// decoy-persistence warns, naming the point and how to mount it, and does
/// not refuse, with the override or without, while the decoy's helper runs
/// with the setting off.
#[test]
fn a_lookup_not_made_of_how_the_sessions_copy_starts_warns_and_never_refuses() {
    let point = "/hidden/upper/etc/systemd";
    let fs = mock_decoy(true, &[("50unattended-upgrades", Some(OFF))]);
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    enable(&fs);
    with_automounts(&fs, &[]);
    let clear = check_with(false, Some("/hidden/upper")).run(&fs).unwrap();
    assert!(clear.is_pass(), "{clear:?}");

    with_automounts(&fs, &[point]);
    fs.mock_clear_lookups();
    for allow in [false, true] {
        let result = check_with(allow, Some("/hidden/upper")).run(&fs).unwrap();
        assert!(result.is_warn(), "{allow}: {result:?}");
        assert!(
            result.message().contains(
                "NAILS does not look up \
                 /hidden/upper/etc/systemd/system/unattended-upgrades.service, since the lookup \
                 would mount the automount point /hidden/upper/etc/systemd"
            ),
            "{result:?}"
        );
        assert!(
            result.message().ends_with(&mount_fix(&[Path::new(point)])),
            "{result:?}"
        );
    }
    assert!(!reached(&fs, point), "{:?}", fs.mock_lookups());
}

/// status cannot tell where the guard made no lookup that decides the
/// install, even where what it did read finds nothing: behind an automount
/// point, and without the mount table. A lookup it did not make for what
/// only warns, python3-gi's module, changes nothing.
#[test]
fn status_cannot_tell_where_a_lookup_that_decides_the_install_was_not_made() {
    let fs = MockFilesystem::new();
    enable(&fs);
    fs.mock_add_file("/usr/lib/python3/dist-packages/gi/__init__.py", "");
    assert_eq!(DecoyPersistenceCheck::decoy_install_at_shutdown(&fs), None);

    with_automounts(&fs, &["/usr/lib/python3/dist-packages/gi"]);
    fs.mock_clear_lookups();
    assert_eq!(DecoyPersistenceCheck::decoy_install_at_shutdown(&fs), None);
    assert!(
        !reached(&fs, "/usr/lib/python3/dist-packages/gi"),
        "{:?}",
        fs.mock_lookups()
    );

    // Where the helper's unit leaves its marker, which shows whether it
    // runs, and where it keeps its cgroup, which shows it running where the
    // marker does not.
    for point in ["/run/systemd/units", "/sys/fs/cgroup/system.slice"] {
        with_automounts(&fs, &[point]);
        fs.mock_clear_lookups();
        assert_eq!(
            DecoyPersistenceCheck::decoy_install_at_shutdown(&fs),
            Some(InstallAtShutdown::Unknown),
            "{point}"
        );
        assert!(!reached(&fs, point), "{point}: {:?}", fs.mock_lookups());
    }

    fs.mock_set_mount_table_error("permission denied");
    fs.mock_clear_lookups();
    assert_eq!(
        DecoyPersistenceCheck::decoy_install_at_shutdown(&fs),
        Some(InstallAtShutdown::Unknown)
    );
    assert!(fs.mock_lookups().is_empty(), "{:?}", fs.mock_lookups());
}
