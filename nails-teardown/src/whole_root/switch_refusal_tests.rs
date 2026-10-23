// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::mountinfo::{MountEntry, parse_mountinfo};
use crate::whole_root::plan::{Arm, Direction, Plan, sample};
use std::os::unix::fs::PermissionsExt;

/// A plan that armed a switch in `direction` for the hidden volume at
/// `/mnt/data` on device `dev`, so a record would be written.
fn armed_plan(direction: Direction, dev: &str) -> Plan {
    Plan {
        hidden_root: PathBuf::from("/mnt/data"),
        hidden_dev: Some(dev.to_string()),
        armed: Some(Arm {
            direction,
            at: 1_000,
        }),
        ..sample()
    }
}

/// A next root in a scratch directory, with the hidden root's directory in it.
struct NextRoot {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl NextRoot {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap().join("nextroot");
        std::fs::create_dir_all(root.join("mnt/data")).unwrap();
        Self { _dir: dir, root }
    }

    /// The hidden root's directory in the next root.
    fn volume(&self) -> PathBuf {
        self.root.join("mnt/data")
    }
}

/// The mount table when the transition runs: the decoy root, the next root,
/// and `dev` mounted at `at` below the next root. The shutdown has unmounted
/// the hidden volume at its own path, so nothing is mounted there.
fn transition_table(next: &NextRoot, at: &Path, dev: &str) -> Vec<MountEntry> {
    parse_mountinfo(&format!(
        "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n\
         40 1 0:40 / {} rw - overlay overlay rw\n\
         63 40 {dev} / {} rw - ext4 /dev/mapper/data rw\n",
        next.root.display(),
        at.display()
    ))
}

#[test]
fn a_refused_entry_is_recorded_through_the_volume_s_bind_in_the_next_root() {
    let next = NextRoot::new();
    let mounts = transition_table(&next, &next.volume(), "254:0");
    let plan = armed_plan(Direction::Enter, "254:0");

    assert_eq!(
        volume_in_next_root(&mounts, &plan, &next.root),
        Some(next.volume())
    );
    record_on_volume(&mounts, &plan, &next.root, "failed init check", 1234);

    assert_eq!(
        read(&next.volume()),
        Some(SwitchRefusal {
            reason: "failed init check".to_string(),
            at: 1234,
        })
    );
}

#[test]
fn the_hidden_root_is_resolved_inside_the_next_root() {
    // The decoy keeps /mnt as an absolute link: inside the next root it leads
    // to the next root's /media, never to the running system's.
    let next = NextRoot::new();
    std::fs::remove_dir_all(next.root.join("mnt")).unwrap();
    std::os::unix::fs::symlink("/media", next.root.join("mnt")).unwrap();
    let volume = next.root.join("media/data");
    std::fs::create_dir_all(&volume).unwrap();
    let mounts = transition_table(&next, &volume, "254:0");

    record_on_volume(
        &mounts,
        &armed_plan(Direction::Enter, "254:0"),
        &next.root,
        "failed init check",
        1,
    );

    assert!(read(&volume).is_some(), "the record is on the bind");
}

#[test]
fn without_the_volume_s_bind_in_the_next_root_nothing_is_written() {
    // Only the volume's bind below the next root counts. Without it, the hidden
    // root's directory there is the root overlay's own, and the record must not
    // land in it, even with the volume still mounted at its own path.
    let next = NextRoot::new();
    let mounts = parse_mountinfo(&format!(
        "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n\
         40 1 0:40 / {} rw - overlay overlay rw\n\
         63 1 254:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n",
        next.root.display()
    ));
    let plan = armed_plan(Direction::Enter, "254:0");

    assert_eq!(volume_in_next_root(&mounts, &plan, &next.root), None);
    record_on_volume(&mounts, &plan, &next.root, "failed init check", 1);

    assert!(!refusal_path(&next.volume()).exists());
}

#[test]
fn another_device_at_the_hidden_root_records_nothing() {
    // A disk mounted over the bind, or a plan from another volume: the
    // recorded device does not match, so nothing is written.
    let next = NextRoot::new();
    let mounts = transition_table(&next, &next.volume(), "8:33");

    record_on_volume(
        &mounts,
        &armed_plan(Direction::Enter, "254:0"),
        &next.root,
        "failed init check",
        1,
    );

    assert!(!refusal_path(&next.volume()).exists());
}

#[test]
fn a_hidden_root_accepted_on_the_decoy_s_storage_records_nothing() {
    // `--allow-decoy-storage`: the bind is on the recorded device, but that
    // device is the decoy's own disk.
    let next = NextRoot::new();
    let mounts = transition_table(&next, &next.volume(), "8:2");
    let mut plan = armed_plan(Direction::Enter, "8:2");
    plan.accepted_decoy_storage =
        Some("/mnt/data is not a volume of its own: it is a bind mount of a folder of /".into());

    record_on_volume(&mounts, &plan, &next.root, "failed init check", 1);

    assert!(!refusal_path(&next.volume()).exists());
}

#[test]
fn a_plan_without_a_recorded_device_records_nothing() {
    let next = NextRoot::new();
    let mounts = transition_table(&next, &next.volume(), "254:0");
    let mut plan = armed_plan(Direction::Enter, "254:0");
    plan.hidden_dev = None;

    assert_eq!(volume_in_next_root(&mounts, &plan, &next.root), None);
    record_on_volume(&mounts, &plan, &next.root, "failed init check", 1);

    assert!(read(&next.volume()).is_none());
}

#[test]
fn an_unarmed_plan_records_nothing_on_either_side() {
    // A reboot that met a tree nothing armed.
    let next = NextRoot::new();
    let mounts = transition_table(&next, &next.volume(), "254:0");
    let runtime = tempfile::tempdir().unwrap();
    let mut plan = armed_plan(Direction::Enter, "254:0");
    plan.armed = None;

    record_on_volume(&mounts, &plan, &next.root, "not armed", 1);
    record_in_runtime(&plan, runtime.path(), "not armed", 1);

    assert!(read(&next.volume()).is_none());
    assert!(read(runtime.path()).is_none());
}

#[test]
fn a_refused_way_back_is_recorded_in_the_runtime_directory() {
    let runtime = tempfile::tempdir().unwrap();
    let plan = armed_plan(Direction::Leave, "254:0");

    record_in_runtime(&plan, runtime.path(), "the decoy's init is missing", 77);

    let back = read(runtime.path()).expect("a recorded refusal");
    assert_eq!(back.reason, "the decoy's init is missing");
    assert_eq!(back.at, 77);
    let mode = std::fs::metadata(refusal_path(runtime.path()))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "private to root");
}

#[test]
fn clearing_forgets_the_recorded_refusal() {
    let runtime = tempfile::tempdir().unwrap();
    record_in_runtime(
        &armed_plan(Direction::Leave, "254:0"),
        runtime.path(),
        "failed init check",
        1234,
    );
    assert!(read(runtime.path()).is_some());

    clear(runtime.path());
    assert!(read(runtime.path()).is_none());
    // Clearing an already-absent record is success, not an error.
    clear(runtime.path());
}

#[test]
fn an_absent_unreadable_or_empty_record_reads_as_none() {
    let dir = tempfile::tempdir().unwrap();
    assert!(read(dir.path()).is_none());

    std::fs::write(refusal_path(dir.path()), "{ not json").unwrap();
    assert!(read(dir.path()).is_none());

    std::fs::write(refusal_path(dir.path()), r#"{"reason":" ","at":5}"#).unwrap();
    assert!(read(dir.path()).is_none(), "a record must give a reason");

    std::fs::write(refusal_path(dir.path()), r#"{"reason":"why","at":5}"#).unwrap();
    assert_eq!(read(dir.path()).map(|record| record.at), Some(5));
}
