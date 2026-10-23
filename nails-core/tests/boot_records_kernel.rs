// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The way back's login- and boot-record pieces against a real kernel, without
//! root (the real-kernel tier of docs/testing-strategy.md).
//!
//! The pieces, their texts and the command lines are unit-tested in
//! `nails_teardown::whole_root::boot_records` and `boot_writer`; this proves
//! what a temporary directory cannot show: that the way back leaves `/run`
//! executable for them and the reconcile step makes it `noexec` again, that the
//! step reads the decoy's wtmp without updating its access time, and that the
//! wtmpdb writer really starts in a time namespace whose boot clock starts at
//! the switch, kept from the system bus. The soft-reboot itself and the
//! decoy's own writers need a VM: the cross-distro records test runs them.

mod kernel_tests {
    use nails_core::test_path;
    use nails_core::test_support::{Rerun, ScratchTmpfs, skip_host};
    use nails_teardown::mountinfo::read_mountinfo;
    use nails_teardown::whole_root::nextroot;
    use nails_teardown::whole_root::plan::{
        Arm, BINARY_NAME, DecoyRoot, Direction, PLAN_NAME, PLAN_VERSION, Plan, RootSide, Tools,
    };
    use nails_teardown::whole_root::transition::{self, Env, Outcome};
    use nails_teardown::whole_root::{boot_records, boot_writer};
    use std::ffi::OsString;
    use std::fs::FileTimes;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    /// Debian 13's unit for the wtmpdb boot writer, as its package ships it.
    const DEBIAN_WRITER_UNIT: &str = "[Unit]\n\
        Description=Write boot and shutdown times into wtmpdb\n\
        Wants=dbus.socket\n\
        After=dbus.socket\n\
        \n\
        [Service]\n\
        Type=oneshot\n\
        ExecStart=/usr/bin/wtmpdb boot\n\
        ExecStop=/usr/bin/wtmpdb shutdown\n\
        RemainAfterExit=true\n";

    /// A plan armed for the way back to an FHS decoy, with `/run` `noexec`
    /// cleared by the entry.
    fn way_back_plan(hidden: &Path) -> Plan {
        Plan {
            version: PLAN_VERSION,
            hidden_root: hidden.to_path_buf(),
            hidden_dev: None,
            accepted_decoy_storage: None,
            upper: hidden.join("root/upper"),
            work: hidden.join("root/work"),
            owner: None,
            decoy_root: DecoyRoot {
                source: PathBuf::from("/dev/null"),
                fstype: "ext4".to_string(),
                data: None,
            },
            decoy: RootSide {
                init: PathBuf::from("/usr/lib/systemd/systemd"),
                system: None,
            },
            hidden: RootSide {
                init: PathBuf::from("/usr/lib/systemd/systemd"),
                system: None,
            },
            policy_mounts: Vec::new(),
            masks: Vec::new(),
            boot_masks: Vec::new(),
            session_units: Vec::new(),
            backend: Vec::new(),
            tools: Tools::default(),
            armed: Some(Arm::now(Direction::Leave)),
            entered_at: Some(1),
            run_noexec: true,
            carried: Vec::new(),
            decoy_mounts: Vec::new(),
            read_only_disks: false,
            failed_at_entry: Vec::new(),
            kernel_settings: Vec::new(),
        }
    }

    /// Write `content` to `root`/`rel` with `mode`, making its directory.
    fn file(root: &Path, rel: &str, content: &[u8], mode: u32) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn the_way_back_leaves_run_executable_for_the_records_step_which_makes_it_noexec_again() {
        let _ = Rerun::new(test_path!(
            the_way_back_leaves_run_executable_for_the_records_step_which_makes_it_noexec_again
        ))
        .in_user_mount_ns()
        .run(|| {
            // An FHS decoy that keeps classic wtmp and wtmpdb, as Debian 13 can.
            let decoy = ScratchTmpfs::new("");
            let root = decoy.path();
            file(root, "etc/os-release", b"ID=debian\n", 0o644);
            file(root, "usr/lib/systemd/systemd", b"#!/bin/sh\n", 0o755);
            file(root, "var/log/wtmp", &[0u8; 384], 0o664);
            file(root, "var/log/wtmp.db", b"SQLite format 3\x00", 0o640);
            file(root, "usr/bin/wtmpdb", b"\x7fELF", 0o755);
            file(
                root,
                "usr/lib/systemd/system/wtmpdb-update-boot.service",
                DEBIAN_WRITER_UNIT.as_bytes(),
                0o644,
            );
            let hidden = ScratchTmpfs::new("");
            let run_fs = ScratchTmpfs::new("");
            let run = run_fs.path();
            let runtime = run_fs.mkdir("overlay-runtime");
            let next = run_fs.mkdir("nextroot");
            file(&runtime, BINARY_NAME, b"\x7fELF-not-really", 0o700);
            way_back_plan(hidden.path())
                .write_atomic(&runtime.join(PLAN_NAME))
                .unwrap();
            nextroot::bind(root, &next, false).unwrap();
            assert!(!nextroot::is_noexec(run).unwrap(), "the entry cleared it");

            let env = Env {
                run: run.to_path_buf(),
                nextroot: next.clone(),
                runtime_dir: runtime.clone(),
                kmsg: run.join("no-kmsg"),
                systemctl: None,
                now: nails_teardown::whole_root::plan::unix_now(),
                mounts: read_mountinfo().unwrap(),
            };
            let before = boot_records::boot_clock();
            let outcome = transition::run(&env);
            assert!(
                matches!(outcome, Outcome::Returned { failed: 0, .. }),
                "{outcome:?}"
            );

            // The pieces for the decoy's first start are in place, and /run
            // stays executable for them.
            assert!(!nextroot::is_noexec(run).unwrap(), "left executable");
            let copy = run
                .join(boot_records::FIXUP_DIR)
                .join(boot_records::FIXUP_BINARY);
            assert_eq!(std::fs::read(&copy).unwrap(), b"\x7fELF-not-really");
            let unit =
                std::fs::read_to_string(run.join("systemd/system").join(boot_records::FIXUP_UNIT))
                    .unwrap();
            let dropin = std::fs::read_to_string(
                run.join(boot_writer::DROPIN_DIR)
                    .join(boot_writer::DROPIN_NAME),
            )
            .unwrap();
            // Both carry the boot clock of the switch, taken during the way back.
            let command = unit
                .lines()
                .find_map(|line| line.strip_prefix("ExecStart=-"))
                .expect("the one-shot's command");
            let words: Vec<&str> = command.split(' ').collect();
            assert_eq!(words[0], copy.display().to_string());
            assert_eq!(words[1], boot_records::RECONCILE_ARG);
            assert_eq!(words[3], boot_records::NOEXEC_FLAG, "{command}");
            let switched_at =
                boot_records::parse_clock_arg(words[2].as_ref()).expect("a clock reading");
            // The argument holds whole microseconds.
            assert!(
                before.as_micros() <= switched_at.as_micros()
                    && switched_at <= boot_records::boot_clock(),
                "{before:?} <= {switched_at:?}"
            );
            assert!(
                dropin.ends_with(&format!(
                    "{} {} {} /usr/bin/wtmpdb boot\n",
                    copy.display(),
                    boot_writer::WRITER_ARG,
                    words[2]
                )),
                "{dropin}"
            );
            nextroot::detach_tree(&next);

            // The decoy's first start: the step removes every piece and makes
            // /run noexec again.
            boot_records::run(run, root, switched_at, true);
            assert!(nextroot::is_noexec(run).unwrap(), "noexec is back");
            for gone in [
                run.join(boot_records::FIXUP_DIR),
                run.join("systemd/system").join(boot_records::FIXUP_UNIT),
                run.join("systemd/system/multi-user.target.wants"),
                run.join(boot_writer::DROPIN_DIR),
            ] {
                assert!(!gone.exists(), "{} should be gone", gone.display());
            }
        });
    }

    #[test]
    fn the_records_step_reads_the_decoy_wtmp_without_touching_its_access_time() {
        let _ = Rerun::new(test_path!(
            the_records_step_reads_the_decoy_wtmp_without_touching_its_access_time
        ))
        .in_user_mount_ns()
        .run(|| {
            // strictatime: every plain read updates the access time, which the
            // control below proves; on a noatime host fs the check is moot.
            let decoy = ScratchTmpfs::strictatime();
            let root = decoy.path();
            // A boot and a later run-level record: nothing to correct, so the
            // step only reads.
            let mut wtmp = vec![0u8; 2 * 384];
            wtmp[..2].copy_from_slice(&2i16.to_le_bytes());
            wtmp[340..344].copy_from_slice(&1_000_000i32.to_le_bytes());
            wtmp[384..386].copy_from_slice(&1i16.to_le_bytes());
            wtmp[384 + 340..384 + 344].copy_from_slice(&1_000_600i32.to_le_bytes());
            file(root, "var/log/wtmp", &wtmp, 0o664);
            file(root, "var/log/control", b"read me plainly", 0o644);
            let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
            for rel in ["var/log/wtmp", "var/log/control"] {
                std::fs::File::options()
                    .write(true)
                    .open(root.join(rel))
                    .unwrap()
                    .set_times(FileTimes::new().set_accessed(old))
                    .unwrap();
            }
            let atime = |rel: &str| std::fs::metadata(root.join(rel)).unwrap().atime();

            let _ = std::fs::read(root.join("var/log/control")).unwrap();
            assert_ne!(atime("var/log/control"), 1_000_000, "a plain read records");

            let run = tempfile::tempdir().unwrap();
            boot_records::run(run.path(), root, boot_records::boot_clock(), false);
            assert_eq!(atime("var/log/wtmp"), 1_000_000, "the step's read did not");
            assert_eq!(std::fs::read(root.join("var/log/wtmp")).unwrap(), wtmp);
        });
    }

    /// A shell on `PATH`, for the writer to start in the test's place.
    fn shell() -> Option<PathBuf> {
        let path = std::env::var_os("PATH").unwrap_or_default();
        std::env::split_paths(&path)
            .map(|dir| dir.join("sh"))
            .find(|sh| sh.is_file())
    }

    /// What a writer started through `boot_writer::prepare` with the switch at
    /// `switched_at` sees: its uptime in seconds and the system bus address.
    fn seen_by_the_writer(sh: &Path, switched_at: Duration) -> (f64, String) {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("seen");
        let script = format!(
            "printf '%s %s' \"$(cut -d' ' -f1 /proc/uptime)\" \"$DBUS_SYSTEM_BUS_ADDRESS\" > '{}'",
            out.display()
        );
        let writer: Vec<OsString> = vec![sh.into(), "-c".into(), script.into()];
        let status = boot_writer::prepare(switched_at, &writer)
            .expect("a command")
            .status()
            .unwrap();
        assert!(status.success(), "{status}");
        let seen = std::fs::read_to_string(&out).unwrap();
        let (uptime, bus) = seen.split_once(' ').expect("two fields");
        (uptime.parse().unwrap(), bus.to_string())
    }

    #[test]
    fn the_boot_writer_starts_with_a_boot_clock_that_starts_at_the_switch() {
        let _ = Rerun::new(test_path!(
            the_boot_writer_starts_with_a_boot_clock_that_starts_at_the_switch
        ))
        .in_user_mount_ns()
        .run(|| {
            let Some(sh) = shell() else {
                skip_host("no sh on PATH to stand in for the writer");
            };
            let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
            let mut numbers = release
                .trim()
                .split(['.', '-'])
                .map(|n| n.parse::<u32>().ok());
            let version = (numbers.next().flatten(), numbers.next().flatten());
            if !matches!(version, (Some(major), Some(minor)) if (major, minor) >= (6, 2)) {
                skip_host("Linux before 6.2 starts no program in a time namespace");
            }

            // The switch 30 seconds ago (less on a host just booted): the
            // writer's uptime runs from it, and the bus is out of reach.
            let ago = boot_records::boot_clock().min(Duration::from_secs(30));
            let (uptime, bus) = seen_by_the_writer(&sh, boot_records::boot_clock() - ago);
            assert!(
                uptime >= ago.as_secs_f64() - 0.5 && uptime < ago.as_secs_f64() + 30.0,
                "the writer's uptime runs from the switch {ago:?} ago: {uptime}"
            );
            assert_eq!(bus, "unix:path=/run/overlay-runtime-boot/no-bus");

            // A switch long ago (the start of the boot clock) is shown no
            // further back than the cap, which wtmpdb still takes as an
            // uptime: it names the row soft-reboot only past 300 seconds.
            let (uptime, _) = seen_by_the_writer(&sh, Duration::ZERO);
            let real = boot_records::boot_clock().as_secs_f64();
            assert!(
                uptime < 270.0 && uptime >= real.min(240.0) - 1.0,
                "capped below 300 s: {uptime} (real uptime {real})"
            );
        });
    }

    #[test]
    fn the_decoy_s_own_atime_rule_holds_for_the_writer_s_unit() {
        // The way back reads the writer's unit on the decoy root: under
        // strictatime a plain read would stamp it with the time of the switch.
        let _ = Rerun::new(test_path!(
            the_decoy_s_own_atime_rule_holds_for_the_writer_s_unit
        ))
        .in_user_mount_ns()
        .run(|| {
            let decoy = ScratchTmpfs::strictatime();
            let root = decoy.path();
            file(root, "var/log/wtmp.db", b"SQLite format 3\x00", 0o640);
            file(root, "usr/bin/wtmpdb", b"\x7fELF", 0o755);
            let unit = "usr/lib/systemd/system/wtmpdb-update-boot.service";
            file(root, unit, DEBIAN_WRITER_UNIT.as_bytes(), 0o644);
            let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
            std::fs::File::options()
                .write(true)
                .open(root.join(unit))
                .unwrap()
                .set_times(FileTimes::new().set_accessed(old))
                .unwrap();
            assert_eq!(
                boot_writer::writer_command(root),
                Some(vec!["/usr/bin/wtmpdb".to_string(), "boot".to_string()])
            );
            assert_eq!(
                std::fs::metadata(root.join(unit)).unwrap().atime(),
                1_000_000
            );
        });
    }
}
