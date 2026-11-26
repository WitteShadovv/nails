// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use nails_teardown::whole_root::write_counters::WatchedDisk;
use std::cell::Cell;

/// A fake sysfs with one decoy disk `vda` (252:0), no partitions, `written`
/// sectors written.
fn sysfs(written: u64) -> (tempfile::TempDir, Sysfs) {
    let dir = tempfile::tempdir().unwrap();
    set(dir.path(), written);
    let sys = Sysfs {
        root: dir.path().to_path_buf(),
    };
    (dir, sys)
}

fn set(root: &Path, written: u64) {
    let disk = root.join("devices/pci0/vda");
    std::fs::create_dir_all(disk.join("device")).unwrap();
    std::fs::write(disk.join("dev"), "252:0\n").unwrap();
    std::fs::create_dir_all(disk.join("queue")).unwrap();
    std::fs::write(disk.join("queue/iostats"), "1\n").unwrap();
    std::fs::write(
        disk.join("stat"),
        format!("1 0 8 0 1 0 {written} 0 0 0 0 0 0 0 0 0 0\n"),
    )
    .unwrap();
    for dir in ["dev/block", "class/block"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    let _ = std::os::unix::fs::symlink(&disk, root.join("dev/block/252:0"));
    let _ = std::os::unix::fs::symlink(&disk, root.join("class/block/vda"));
}

fn layout() -> Layout {
    Layout {
        disks: vec![WatchedDisk {
            name: "vda".into(),
            dev: "252:0".into(),
            partitions: Vec::new(),
            allowed: Vec::new(),
        }],
    }
}

#[test]
fn the_entry_s_baseline_counts_from_the_switch() {
    let (dir, sys) = sysfs(100);
    let mut base = Baseline::default();
    base.sectors.insert("252:0".into(), 40);
    base.save(&dir.path().join(write_counters::BASELINE_NAME))
        .unwrap();
    let watch = WriteWatch::start(layout(), &sys, dir.path());
    assert_eq!(watch.since(), Since::Switch);
    assert_eq!(watch.writes(&sys), ["60 sectors written to vda"]);
}

#[test]
fn without_one_the_tripwire_fails_closed_and_still_names_later_writes() {
    let (dir, sys) = sysfs(100);
    let watch = WriteWatch::start(layout(), &sys, dir.path());
    assert_eq!(watch.since(), Since::WatcherStart);
    let missing = "the entry left no write counters from the switch: what was written since \
                   cannot be told";
    assert_eq!(watch.writes(&sys), [missing]);
    set(dir.path(), 101);
    assert_eq!(watch.writes(&sys), [missing, "1 sectors written to vda"]);
}

#[test]
fn a_counter_unreadable_at_the_start_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let sys = Sysfs {
        root: dir.path().to_path_buf(),
    };
    let watch = WriteWatch::start(layout(), &sys, dir.path());
    assert!(!watch.writes(&sys).is_empty());
}

#[test]
fn the_first_write_powers_off_once_and_a_power_off_that_failed_is_tried_again() {
    let (dir, sys) = sysfs(100);
    Baseline::take(&layout(), &sys)
        .unwrap()
        .save(&dir.path().join(write_counters::BASELINE_NAME))
        .unwrap();
    let watch = WriteWatch::start(layout(), &sys, dir.path());
    let asked = Cell::new(0);
    let refuse = |_: &[String]| {
        asked.set(asked.get() + 1);
        false
    };
    assert!(!trip(&watch, &sys, false, refuse));
    assert_eq!(asked.get(), 0, "no write, no power-off");
    set(dir.path(), 108);
    assert!(!trip(&watch, &sys, false, refuse));
    assert_eq!(asked.get(), 1);
    let seen = std::cell::RefCell::new(Vec::new());
    let take = |writes: &[String]| {
        seen.borrow_mut().extend_from_slice(writes);
        true
    };
    assert!(trip(&watch, &sys, false, take));
    assert_eq!(*seen.borrow(), ["8 sectors written to vda"]);
    assert!(trip(&watch, &sys, true, |_: &[String]| unreachable!()));
}
