// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::mountinfo::{MountEntry, parse_mountinfo};
use crate::whole_root::plan::{Arm, Direction, Plan, sample};
use std::path::Path;

/// A plan whose hidden volume is `root`, mounted on device `dev`, with a switch
/// armed, so [`record`] would write.
fn armed_plan(root: &Path, dev: &str) -> Plan {
    Plan {
        hidden_root: root.to_path_buf(),
        hidden_dev: Some(dev.to_string()),
        armed: Some(Arm {
            direction: Direction::Enter,
            at: 1_000,
        }),
        ..sample()
    }
}

/// A mount table with a root filesystem and `dev` mounted at `root`, so
/// [`top_mount_at`](crate::mountinfo::top_mount_at) can climb to it as it does
/// on a live table.
fn mounts_at(root: &Path, dev: &str) -> Vec<MountEntry> {
    parse_mountinfo(&format!(
        "1 0 8:0 / / rw - ext4 /dev/sda1 rw\n\
         40 1 {dev} / {} rw - tmpfs tmpfs rw\n",
        root.display()
    ))
}

#[test]
fn a_refused_switch_is_recorded_and_read_back() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let plan = armed_plan(&root, "0:42");

    record(&mounts_at(&root, "0:42"), &plan, "failed init check", 1234);

    let back = read(&root).expect("a recorded refusal");
    assert_eq!(back.reason, "failed init check");
    assert_eq!(back.at, 1234);
}

#[test]
fn clearing_forgets_the_recorded_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let plan = armed_plan(&root, "0:42");

    record(&mounts_at(&root, "0:42"), &plan, "failed init check", 1234);
    assert!(read(&root).is_some());

    clear(&root);
    assert!(read(&root).is_none());
    // Clearing an already-absent record is success, not an error.
    clear(&root);
}

#[test]
fn an_unarmed_plan_records_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let mut plan = armed_plan(&root, "0:42");
    plan.armed = None;

    record(
        &mounts_at(&root, "0:42"),
        &plan,
        "not armed for this transition",
        1,
    );

    assert!(
        read(&root).is_none(),
        "a plain reboot that meets a leftover tree must record nothing"
    );
}

#[test]
fn a_different_device_at_the_root_records_nothing() {
    // The hidden volume is not mounted: the decoy's own filesystem is what sits
    // at the path now. The recorded device does not match, so nothing is written
    // — the record must never land on the decoy disk.
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let plan = armed_plan(&root, "0:42");

    record(&mounts_at(&root, "8:1"), &plan, "failed init check", 1);

    assert!(read(&root).is_none());
    assert!(!refusal_path(&root).exists());
}

#[test]
fn a_plan_without_a_recorded_device_records_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let mut plan = armed_plan(&root, "0:42");
    plan.hidden_dev = None;

    record(&mounts_at(&root, "0:42"), &plan, "failed init check", 1);

    assert!(read(&root).is_none());
}

#[test]
fn reading_an_absent_record_is_none() {
    let dir = tempfile::tempdir().unwrap();
    assert!(read(dir.path()).is_none());
}
