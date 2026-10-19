// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for the login- and boot-record reconcile step.

use super::*;
use std::os::unix::fs::MetadataExt;

/// A classic-wtmp record of `ut_type` stamped at `tv_sec`, the other fields
/// left zero. Enough for the boot-record logic, which reads only type and time.
fn record(ut_type: i16, tv_sec: i32) -> [u8; UTMP_RECORD_SIZE] {
    let mut r = [0u8; UTMP_RECORD_SIZE];
    r[UT_TYPE_OFFSET..UT_TYPE_OFFSET + 2].copy_from_slice(&ut_type.to_le_bytes());
    r[UT_TV_SEC_OFFSET..UT_TV_SEC_OFFSET + 4].copy_from_slice(&tv_sec.to_le_bytes());
    r[UT_TV_USEC_OFFSET..UT_TV_USEC_OFFSET + 4].copy_from_slice(&500i32.to_le_bytes());
    r
}

fn wtmp(records: &[[u8; UTMP_RECORD_SIZE]]) -> Vec<u8> {
    records.iter().flatten().copied().collect()
}

const RUN_LVL: i16 = 1;
const LOGIN_PROCESS: i16 = 6;

// The times of one session on a decoy, in file (chronological) order.
const COLD_BOOT: i32 = 1_000_000;
const ACTIVATION: i32 = 1_000_600; // the shutdown written on the way in
const WAY_BACK: i32 = 1_000_630; // when the decoy actually came back

#[test]
fn a_backdated_way_back_boot_is_found_and_corrected_to_now() {
    // Cold boot, a run-level and login after it, the activation's shutdown,
    // then the way-back boot the soft-reboot stamped with the cold-boot time.
    let data = wtmp(&[
        record(BOOT_TIME, COLD_BOOT),
        record(LOGIN_PROCESS, COLD_BOOT + 5),
        record(RUN_LVL, ACTIVATION),
        record(BOOT_TIME, COLD_BOOT), // backdated
        record(LOGIN_PROCESS, WAY_BACK + 2),
    ]);
    let fix = backdated_boot_fix(&data, WAY_BACK);
    let (offset, corrected) = fix.expect("the backdated boot is found");
    // The fourth record (index 3), its tv_sec field.
    assert_eq!(offset, 3 * UTMP_RECORD_SIZE + UT_TV_SEC_OFFSET);
    assert_eq!(corrected, WAY_BACK, "corrected to when the decoy came back");
}

#[test]
fn an_ordinary_latest_boot_is_left_alone() {
    // Cold boot, shutdown, then a boot that is the newest event: a clean cycle.
    let data = wtmp(&[
        record(BOOT_TIME, COLD_BOOT),
        record(RUN_LVL, ACTIVATION),
        record(BOOT_TIME, WAY_BACK),
    ]);
    assert_eq!(backdated_boot_fix(&data, WAY_BACK + 10), None);
}

#[test]
fn a_boot_that_only_ties_an_earlier_event_is_left_alone() {
    // A boot whose time equals (not precedes) the latest earlier record is not
    // treated as backdated: equal times happen within one real boot.
    let data = wtmp(&[record(RUN_LVL, ACTIVATION), record(BOOT_TIME, ACTIVATION)]);
    assert_eq!(backdated_boot_fix(&data, ACTIVATION), None);
}

#[test]
fn with_no_boot_record_there_is_nothing_to_fix() {
    let data = wtmp(&[record(RUN_LVL, ACTIVATION), record(LOGIN_PROCESS, WAY_BACK)]);
    assert_eq!(backdated_boot_fix(&data, WAY_BACK), None);
    assert_eq!(backdated_boot_fix(&[], WAY_BACK), None);
    // A torn trailing record (not a whole 384 bytes) is ignored, not read into.
    assert_eq!(backdated_boot_fix(&[0u8; 10], WAY_BACK), None);
}

#[test]
fn a_clock_behind_the_file_still_sets_the_boot_after_the_shutdown() {
    // If the reconcile clock reads before the activation shutdown, the boot is
    // still placed one second after it, never before it.
    let data = wtmp(&[
        record(BOOT_TIME, COLD_BOOT),
        record(RUN_LVL, ACTIVATION),
        record(BOOT_TIME, COLD_BOOT),
    ]);
    let (_, corrected) = backdated_boot_fix(&data, COLD_BOOT + 1).expect("found");
    assert_eq!(corrected, ACTIVATION + 1);
}

#[test]
fn reconcile_wtmp_rewrites_in_place_and_keeps_the_inode() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wtmp");
    std::fs::write(
        &path,
        wtmp(&[
            record(BOOT_TIME, COLD_BOOT),
            record(RUN_LVL, ACTIVATION),
            record(BOOT_TIME, COLD_BOOT),
        ]),
    )
    .unwrap();
    let inode = std::fs::metadata(&path).unwrap().ino();

    assert!(reconcile_wtmp(&path, WAY_BACK).unwrap());

    let after = std::fs::read(&path).unwrap();
    let last = &after[2 * UTMP_RECORD_SIZE..];
    assert_eq!(read_i32_le(last, UT_TV_SEC_OFFSET), WAY_BACK);
    assert_eq!(read_i32_le(last, UT_TV_USEC_OFFSET), 0, "tv_usec cleared");
    assert_eq!(
        after.len(),
        3 * UTMP_RECORD_SIZE,
        "no record added or dropped"
    );
    assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode, "same file");
    // Idempotent: a second run finds nothing to change.
    assert!(!reconcile_wtmp(&path, WAY_BACK + 100).unwrap());
}

#[test]
fn reconcile_wtmp_on_an_absent_file_is_no_change() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!reconcile_wtmp(&dir.path().join("absent"), WAY_BACK).unwrap());
}

#[test]
fn decoy_with_records_is_recognised_and_one_without_is_not() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("var/log")).unwrap();
    assert!(!decoy_keeps_records(root), "empty tree keeps no records");

    std::fs::write(
        root.join(WTMP_PATH.trim_start_matches('/')),
        [0u8; UTMP_RECORD_SIZE],
    )
    .unwrap();
    assert!(decoy_keeps_records(root), "a non-empty classic wtmp counts");

    let dir2 = tempfile::tempdir().unwrap();
    let root2 = dir2.path();
    std::fs::create_dir_all(root2.join("var/log")).unwrap();
    std::fs::write(root2.join(WTMPDB_PATH), b"SQLite format 3\x00").unwrap();
    assert!(decoy_keeps_records(root2), "a wtmpdb database counts");
}

#[test]
fn install_lays_out_every_piece_and_run_removes_them_all() {
    let dir = tempfile::tempdir().unwrap();
    let run_dir = dir.path();
    // A stand-in binary; the reconcile step never executes it in the test.
    install(run_dir, b"\x7fELF-not-really", false).unwrap();

    let bin = run_dir.join(FIXUP_DIR).join(FIXUP_BINARY);
    let unit = run_dir.join(RUNTIME_UNIT_DIR).join(FIXUP_UNIT);
    let link = run_dir
        .join(RUNTIME_UNIT_DIR)
        .join(format!("{FIXUP_WANTED_BY}.wants"))
        .join(FIXUP_UNIT);
    let dropin = run_dir.join(WTMPDB_DROPIN_DIR).join(WTMPDB_DROPIN_NAME);
    for p in [&bin, &unit, &dropin] {
        assert!(p.is_file(), "{} should exist", p.display());
    }
    assert_eq!(
        std::fs::read_link(&link).unwrap(),
        Path::new("..").join(FIXUP_UNIT)
    );
    let text = std::fs::read_to_string(&unit).unwrap();
    assert!(
        text.contains(&format!("{RECONCILE_ARG}\n")),
        "no noexec flag asked"
    );
    assert!(text.contains("After=systemd-update-utmp.service"));
    assert!(
        text.contains("ExecStart=-"),
        "a failure must not mark it failed"
    );

    // The reconcile step removes every piece (root has no records to touch).
    std::fs::create_dir_all(run_dir.join("var/log")).unwrap();
    run(run_dir, run_dir, false);
    for p in [&bin, &unit, &link, &dropin] {
        assert!(!p.exists(), "{} should be gone", p.display());
    }
    assert!(!run_dir.join(FIXUP_DIR).exists());
    assert!(!run_dir.join(WTMPDB_DROPIN_DIR).exists());
}

#[test]
fn the_noexec_flag_is_added_only_when_the_way_back_cleared_it() {
    let dir = tempfile::tempdir().unwrap();
    install(dir.path(), b"x", true).unwrap();
    let text = std::fs::read_to_string(dir.path().join(RUNTIME_UNIT_DIR).join(FIXUP_UNIT)).unwrap();
    assert!(text.contains(&format!("{RECONCILE_ARG} {NOEXEC_FLAG}\n")));
}

#[test]
fn the_runtime_names_carry_no_product_name() {
    for name in [
        RECONCILE_ARG,
        NOEXEC_FLAG,
        FIXUP_DIR,
        FIXUP_BINARY,
        FIXUP_UNIT,
        FIXUP_WANTED_BY,
        WTMPDB_UNIT,
        WTMPDB_DROPIN_DIR,
        WTMPDB_DROPIN_NAME,
        WTMPDB_DROPIN_TEXT,
    ] {
        assert!(!name.to_lowercase().contains("nails"), "{name}");
    }
}
