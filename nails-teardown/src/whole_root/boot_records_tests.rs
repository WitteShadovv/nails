// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for the login- and boot-record reconcile step.

use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

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
const WAY_BACK: i32 = 1_000_630; // the switch back to the decoy

/// Debian 13's unit for the wtmpdb boot writer, as its package ships it.
const DEBIAN_WRITER_UNIT: &str = "[Unit]\n\
    Description=Write boot and shutdown times into wtmpdb\n\
    DefaultDependencies=no\n\
    RequiresMountsFor=/var/log\n\
    Wants=dbus.socket\n\
    After=dbus.socket\n\
    \n\
    [Service]\n\
    Type=oneshot\n\
    ExecStart=/usr/bin/wtmpdb boot\n\
    ExecStop=/usr/bin/wtmpdb shutdown\n\
    RemainAfterExit=true\n";

/// A decoy root under `root` whose records are in wtmpdb, as on Debian 13.
fn wtmpdb_decoy(root: &Path) {
    for dir in ["var/log", "usr/bin", "usr/lib/systemd/system"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    std::fs::write(root.join("var/log/wtmp.db"), b"SQLite format 3\x00").unwrap();
    std::fs::write(root.join("usr/bin/wtmpdb"), b"\x7fELF").unwrap();
    std::fs::write(
        root.join("usr/lib/systemd/system/wtmpdb-update-boot.service"),
        DEBIAN_WRITER_UNIT,
    )
    .unwrap();
}

/// The boot clock at a switch, as the units carry it.
const SWITCHED_AT: Duration = Duration::from_micros(1_234_567_890);

#[test]
fn a_backdated_way_back_boot_is_found_and_corrected_to_the_switch() {
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
    assert_eq!(corrected, WAY_BACK, "corrected to the switch");
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
    // If the switch reads before the activation shutdown, the boot is still
    // placed one second after it, never before it.
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

    assert!(reconcile_wtmp(&path, WAY_BACK, 654_321).unwrap());

    let after = std::fs::read(&path).unwrap();
    let last = &after[2 * UTMP_RECORD_SIZE..];
    assert_eq!(read_i32_le(last, UT_TV_SEC_OFFSET), WAY_BACK);
    assert_eq!(
        read_i32_le(last, UT_TV_USEC_OFFSET),
        654_321,
        "tv_usec stamped with the live microseconds, not a round zero"
    );
    assert_eq!(
        after.len(),
        3 * UTMP_RECORD_SIZE,
        "no record added or dropped"
    );
    assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode, "same file");
    // Idempotent: a second run finds nothing to change.
    assert!(!reconcile_wtmp(&path, WAY_BACK + 100, 1).unwrap());
}

#[test]
fn reconcile_wtmp_on_an_absent_file_is_no_change() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!reconcile_wtmp(&dir.path().join("absent"), WAY_BACK, 0).unwrap());
}

#[test]
fn the_wall_clock_at_a_boot_clock_reading_is_that_long_ago() {
    // The microseconds must be a real sub-second reading in range, never a value
    // that would overflow the 32-bit field or read as a cleared record.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (sec, usec) = wall_clock_at(boot_clock());
    assert!(
        (i64::from(sec) - now as i64).abs() <= 2,
        "the switch just now: {sec} against {now}"
    );
    assert!(
        (0..1_000_000).contains(&usec),
        "microseconds in range: {usec}"
    );

    let ago = boot_clock().min(Duration::from_secs(100));
    let (sec, _) = wall_clock_at(boot_clock() - ago);
    let expected = now as i64 - ago.as_secs() as i64;
    assert!(
        (i64::from(sec) - expected).abs() <= 2,
        "a switch {ago:?} ago: {sec} against {expected}"
    );
    // A reading from the future is taken as now, never as a later time.
    let (sec, _) = wall_clock_at(boot_clock() + Duration::from_secs(3600));
    assert!(i64::from(sec) <= now as i64 + 2);
}

#[test]
fn the_clock_argument_round_trips_and_rejects_anything_but_digits() {
    assert_eq!(clock_arg(SWITCHED_AT), "1234567890");
    assert_eq!(
        parse_clock_arg(OsStr::new(&clock_arg(SWITCHED_AT))),
        Some(SWITCHED_AT)
    );
    assert_eq!(parse_clock_arg(OsStr::new("0")), Some(Duration::ZERO));
    for bad in [
        "",
        "-1",
        "+1",
        "1.5",
        "12x",
        " 12",
        "99999999999999999999999",
    ] {
        assert_eq!(parse_clock_arg(OsStr::new(bad)), None, "{bad:?}");
    }
}

#[test]
fn a_decoy_needs_a_fix_only_for_records_a_soft_reboot_gives_away() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("var/log")).unwrap();
    assert_eq!(Fix::for_decoy(root), None, "an empty tree keeps no records");

    // A wtmpdb database alone is not enough: the writer's unit says how the
    // writer starts.
    std::fs::write(root.join("var/log/wtmp.db"), b"SQLite format 3\x00").unwrap();
    assert_eq!(Fix::for_decoy(root), None);

    std::fs::write(root.join(WTMP_PATH), [0u8; UTMP_RECORD_SIZE]).unwrap();
    assert_eq!(
        Fix::for_decoy(root),
        Some(Fix {
            writer: None,
            classic_wtmp: true
        }),
        "a non-empty classic wtmp counts"
    );

    let dir2 = tempfile::tempdir().unwrap();
    wtmpdb_decoy(dir2.path());
    assert_eq!(
        Fix::for_decoy(dir2.path()),
        Some(Fix {
            writer: Some(vec!["/usr/bin/wtmpdb".into(), "boot".into()]),
            classic_wtmp: false
        }),
        "the wtmpdb writer is found"
    );
}

/// Every path [`install`] writes under `run`.
fn pieces(run: &Path) -> [std::path::PathBuf; 4] {
    [
        run.join(FIXUP_DIR).join(FIXUP_BINARY),
        run.join(RUNTIME_UNIT_DIR).join(FIXUP_UNIT),
        run.join(RUNTIME_UNIT_DIR)
            .join(format!("{FIXUP_WANTED_BY}.wants"))
            .join(FIXUP_UNIT),
        run.join(boot_writer::DROPIN_DIR)
            .join(boot_writer::DROPIN_NAME),
    ]
}

fn writer_fix() -> Fix {
    Fix {
        writer: Some(vec!["/usr/bin/wtmpdb".into(), "boot".into()]),
        classic_wtmp: false,
    }
}

#[test]
fn install_lays_out_every_piece_and_run_removes_them_all() {
    let dir = tempfile::tempdir().unwrap();
    let run_dir = dir.path();
    // A stand-in binary; the reconcile step never executes it in the test.
    install(
        run_dir,
        b"\x7fELF-not-really",
        &writer_fix(),
        SWITCHED_AT,
        false,
    )
    .unwrap();

    let [bin, unit, link, dropin] = pieces(run_dir);
    for p in [&bin, &unit, &dropin] {
        assert!(p.is_file(), "{} should exist", p.display());
    }
    assert_eq!(
        std::fs::metadata(&bin).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::read_link(&link).unwrap(),
        Path::new("..").join(FIXUP_UNIT)
    );
    let text = std::fs::read_to_string(&unit).unwrap();
    assert!(
        text.contains(&format!(
            "ExecStart=-{} {RECONCILE_ARG} 1234567890\n",
            bin.display()
        )),
        "the switch's clock and no noexec flag: {text}"
    );
    assert!(text.contains("After=systemd-update-utmp.service wtmpdb-update-boot.service"));
    assert!(
        text.contains("Before=multi-user.target systemd-user-sessions.service\n"),
        "no login before the records are reconciled: {text}"
    );
    assert_eq!(
        std::fs::read_to_string(&dropin).unwrap(),
        format!(
            "[Service]\nExecStart=\nExecStart={} boot-writer 1234567890 /usr/bin/wtmpdb boot\n",
            bin.display()
        )
    );

    // The reconcile step removes every piece (root has no records to touch).
    std::fs::create_dir_all(run_dir.join("var/log")).unwrap();
    run(run_dir, run_dir, SWITCHED_AT, false);
    for p in [&bin, &unit, &link, &dropin] {
        assert!(!p.exists(), "{} should be gone", p.display());
    }
    assert!(!run_dir.join(FIXUP_DIR).exists());
    assert!(!run_dir.join(boot_writer::DROPIN_DIR).exists());
    assert!(
        run_dir.join(RUNTIME_UNIT_DIR).is_dir(),
        "the shared unit directory stays"
    );
}

#[test]
fn without_a_writer_no_drop_in_is_installed() {
    let dir = tempfile::tempdir().unwrap();
    let fix = Fix {
        writer: None,
        classic_wtmp: true,
    };
    install(dir.path(), b"x", &fix, SWITCHED_AT, false).unwrap();
    let [bin, unit, _, dropin] = pieces(dir.path());
    assert!(bin.is_file() && unit.is_file());
    assert!(!dropin.exists());
    assert!(!dir.path().join(boot_writer::DROPIN_DIR).exists());
}

#[test]
fn a_failed_install_removes_what_it_wrote_and_writes_no_binary_copy() {
    // The binary copy's directory cannot be made: the unit and its link are
    // already written, and must go again; the drop-in, which comes after the
    // copy, is never written.
    let dir = tempfile::tempdir().unwrap();
    let run_dir = dir.path();
    std::fs::write(run_dir.join(FIXUP_DIR), b"in the way").unwrap();
    assert!(install(run_dir, b"x", &writer_fix(), SWITCHED_AT, true).is_err());
    let [_, unit, link, dropin] = pieces(run_dir);
    for p in [&unit, &link, &dropin] {
        assert!(!p.exists(), "{} should be gone", p.display());
    }
    assert!(!run_dir.join(boot_writer::DROPIN_DIR).exists());
    assert_eq!(
        std::fs::read(run_dir.join(FIXUP_DIR)).unwrap(),
        b"in the way",
        "what was there before stays"
    );

    // Nothing can be written at all: no piece is left, the copy least of all.
    let dir = tempfile::tempdir().unwrap();
    let run_dir = dir.path();
    std::fs::write(run_dir.join("systemd"), b"not a directory").unwrap();
    assert!(install(run_dir, b"x", &writer_fix(), SWITCHED_AT, true).is_err());
    assert!(!run_dir.join(FIXUP_DIR).exists(), "no binary copy");
}

#[test]
fn a_drop_in_that_cannot_be_written_takes_the_copy_and_the_unit_with_it() {
    // The drop-in goes last: when its directory cannot be made, the unit, its
    // link and the binary copy are already written, and must go again.
    let dir = tempfile::tempdir().unwrap();
    let run_dir = dir.path();
    std::fs::create_dir_all(run_dir.join(RUNTIME_UNIT_DIR)).unwrap();
    std::fs::write(run_dir.join(boot_writer::DROPIN_DIR), b"in the way").unwrap();
    assert!(install(run_dir, b"x", &writer_fix(), SWITCHED_AT, true).is_err());
    let [bin, unit, link, _] = pieces(run_dir);
    for p in [&bin, &unit, &link] {
        assert!(!p.exists(), "{} should be gone", p.display());
    }
    assert!(!run_dir.join(FIXUP_DIR).exists(), "no binary copy");
    assert_eq!(
        std::fs::read(run_dir.join(boot_writer::DROPIN_DIR)).unwrap(),
        b"in the way",
        "what was there before stays"
    );

    // Without a writer to start there is no drop-in to fail on.
    let fix = Fix {
        writer: None,
        classic_wtmp: true,
    };
    install(run_dir, b"x", &fix, SWITCHED_AT, true).unwrap();
    assert!(bin.is_file() && unit.is_file());
}

#[test]
fn the_noexec_flag_is_added_only_when_the_way_back_cleared_it() {
    let dir = tempfile::tempdir().unwrap();
    install(dir.path(), b"x", &writer_fix(), SWITCHED_AT, true).unwrap();
    let text = std::fs::read_to_string(dir.path().join(RUNTIME_UNIT_DIR).join(FIXUP_UNIT)).unwrap();
    assert!(text.contains(&format!("{RECONCILE_ARG} 1234567890 {NOEXEC_FLAG}\n")));
    assert_eq!(
        reconcile_args(SWITCHED_AT, true),
        [RECONCILE_ARG, "1234567890", NOEXEC_FLAG]
    );
    assert_eq!(
        reconcile_args(SWITCHED_AT, false),
        [RECONCILE_ARG, "1234567890"]
    );
}

#[test]
fn the_registry_paths_are_the_pieces_install_writes() {
    let run = Path::new("/run");
    let [bin, unit, link, dropin] = pieces(run);
    assert_eq!(bin.parent().unwrap(), Path::new(FIXUP_DIR_PATH));
    assert_eq!(unit, Path::new(FIXUP_UNIT_PATH));
    assert_eq!(link, Path::new(FIXUP_LINK_PATH));
    assert_eq!(dropin, Path::new(boot_writer::DROPIN_PATH));
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
        FIXUP_BEFORE,
        &unit_text(Path::new("/run/x"), SWITCHED_AT, true),
    ] {
        assert!(!name.to_lowercase().contains("nails"), "{name}");
    }
}
