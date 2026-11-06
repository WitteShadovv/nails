// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! incremental-history-flush where a lookup fails or the automount guard
//! does not make it: it warns that it cannot tell, and makes no lookup at or
//! below an automount point that nothing is mounted on yet.

use super::*;
use crate::filesystem::MockFilesystem;
use crate::filesystem::automount::mount_fix;
use crate::preflight::checks::automount_fixture::{reached, with_automounts};
use std::io::ErrorKind;

/// The operator, whose login shell is bash, with the home `home`.
fn operator(home: &str) -> TargetUser {
    TargetUser::for_test(1000, 100, "alice", home, "/bin/bash")
}

/// The check's result for the login shell of `operator` on `fs`.
fn run(fs: &MockFilesystem, operator: &TargetUser) -> CheckResult {
    let check = IncrementalHistoryFlushCheck::new(InspectedShell::login(operator));
    PreFlightCheck::run(&check, fs).unwrap()
}

/// Whether fish keeps its configuration in the home decides whether fish is
/// read. A lookup of it that fails was taken for none, and the check could
/// pass without reading fish: now it warns that it cannot tell.
#[test]
fn a_fish_configuration_nails_cannot_look_up_warns() {
    let fs = MockFilesystem::new();
    let alice = operator("/home/alice");
    assert!(run(&fs, &alice).is_pass());
    fs.mock_set_lookup_error("/home/alice/.config", ErrorKind::PermissionDenied);
    let result = run(&fs, &alice);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().ends_with(
            "NAILS cannot tell whether fish keeps its settings in /home/alice/.config/fish, so it \
             cannot tell whether fish writes each command line as it runs: NAILS cannot look up \
             /home/alice/.config/fish; run the command again with sudo."
        ),
        "{result:?}"
    );
}

/// A home behind an automount point that nothing is mounted on yet, as an
/// automounter serves one, is not looked into: the warning names the point
/// once and how to mount it, and nothing at or below it is looked up.
#[test]
fn a_home_behind_an_automount_point_warns_without_a_lookup() {
    let fs = MockFilesystem::new();
    with_automounts(&fs, &["/home/carol"]);
    let result = run(&fs, &operator("/home/carol"));
    assert!(result.is_warn(), "{result:?}");
    let message = result.message();
    assert!(
        message.contains(
            "it could not read /home/carol/.bash_profile (NAILS does not look up \
             /home/carol/.bash_profile, since the lookup would mount the automount point \
             /home/carol)"
        ),
        "{message}"
    );
    assert!(
        message.contains(
            "NAILS cannot tell whether fish keeps its settings in /home/carol/.config/fish"
        ),
        "{message}"
    );
    let fix = mount_fix(&[Path::new("/home/carol")]);
    assert_eq!(message.matches(fix.as_str()).count(), 1, "{message}");
    assert!(!reached(&fs, "/home/carol"), "{:?}", fs.mock_lookups());
}

/// Without a mount table nothing is looked up, and the check cannot tell.
#[test]
fn without_a_mount_table_nothing_is_looked_up() {
    let fs = MockFilesystem::new();
    fs.mock_set_mount_table_error("no mountinfo");
    let result = run(&fs, &operator("/home/alice"));
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains(
            "NAILS cannot read the mount table (/proc/self/mountinfo: no mountinfo), which shows \
             where a lookup would mount an automount point, so it looks up nothing"
        ),
        "{result:?}"
    );
    assert_eq!(fs.mock_lookups(), Vec::<PathBuf>::new());
}

/// A startup file whose type cannot be looked up after it was found, as a
/// link into a directory NAILS may not search, is named by its error, where
/// it was "not a regular file".
#[test]
fn a_startup_file_whose_type_cannot_be_looked_up_is_named_by_its_error() {
    let fs = MockFilesystem::new();
    let bashrc = Path::new("/home/alice/.bashrc");
    fs.create_symlink(Path::new("/srv/dotfiles/bashrc"), bashrc)
        .unwrap();
    fs.mock_set_inode(bashrc, 7);
    fs.mock_set_lookup_error("/srv/dotfiles", ErrorKind::PermissionDenied);
    assert_eq!(
        startup::read(&fs, bashrc),
        Err("/home/alice/.bashrc (permission denied)".to_string())
    );
}
