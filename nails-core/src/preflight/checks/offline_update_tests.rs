// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the check that refuses a decoy with a pending offline system
//! update.

use super::*;
use crate::filesystem::{MockFilesystem, PathKind};

fn check() -> OfflineUpdateCheck {
    OfflineUpdateCheck::new(PathBuf::from("/"), PathBuf::from("/mnt/hidden/upper"))
}

#[test]
fn a_clean_decoy_passes() {
    let fs = MockFilesystem::new();
    let result = check().run(&fs).unwrap();
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn a_system_update_symlink_on_the_decoy_refuses() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/system-update", PathKind::Symlink);
    let result = check().run(&fs).unwrap();
    assert!(result.is_fail(), "{result:?}");
    assert!(result.message().contains("/system-update"), "{result:?}");
    assert!(result.remediation().is_some());
}

#[test]
fn an_etc_system_update_directory_on_the_decoy_refuses() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/etc/system-update", PathKind::Dir);
    let result = check().run(&fs).unwrap();
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().contains("/etc/system-update"),
        "{result:?}"
    );
}

#[test]
fn a_marker_staged_in_the_overlay_upper_refuses() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/mnt/hidden/upper/system-update", PathKind::Symlink);
    let result = check().run(&fs).unwrap();
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().contains("in the hidden session's overlay"),
        "{result:?}"
    );
    // The refusal describes the location without naming the hidden path.
    assert!(!result.message().contains("/mnt/hidden"), "{result:?}");
}

#[test]
fn a_dangling_system_update_symlink_still_refuses() {
    // systemd's generator follows the link, but a stray /system-update symlink
    // is a tell on its own, so NAILS refuses fail-closed regardless.
    let fs = MockFilesystem::new();
    fs.mock_set_is_symlink("/system-update", true);
    fs.mock_set_path_exists("/system-update", false);
    let result = check().run(&fs).unwrap();
    assert!(result.is_fail(), "{result:?}");
}

#[test]
fn the_check_reports_its_name_and_description() {
    // The id is a status contract the preflight runner keys rows on, so pin
    // it exactly.
    assert_eq!(
        PreFlightCheck::<MockFilesystem>::name(&check()),
        "pending-offline-update"
    );
    // The description is surfaced to the user; it must be present and name
    // the offline-update hazard this check guards against.
    let description = PreFlightCheck::<MockFilesystem>::description(&check());
    assert!(!description.is_empty(), "{description:?}");
    assert!(
        description.contains("offline system update"),
        "{description:?}"
    );
}
