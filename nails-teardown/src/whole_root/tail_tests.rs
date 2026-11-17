// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The tail steps against fake `/proc`, `/sys` and `/run` trees. Nothing here
//! signals a process or calls the real `systemctl`.

use super::*;
use crate::mountinfo::parse_mountinfo;
use crate::test_support::write_executable;
use crate::whole_root::plan::sample;
use std::fs;
use std::os::unix::fs::symlink;

/// A `/proc/<pid>` with a `stat` in `state` with `flags`, a `status` with
/// `uid` and a `cmdline` of `argv`.
fn process(proc: &Path, pid: u32, state: char, flags: u64, uid: u32, argv: &[u8]) {
    let dir = proc.join(pid.to_string());
    fs::create_dir_all(&dir).unwrap();
    // Fields after comm: state ppid pgrp session tty tpgid flags ... starttime.
    let mut fields = vec![state.to_string(), "1".into(), "1".into(), "1".into()];
    fields.extend(["0".into(), "-1".into(), flags.to_string()]);
    fields.extend(std::iter::repeat_n("0".to_string(), 12));
    fields.push("4242".into());
    fs::write(
        dir.join("stat"),
        format!("{pid} (p) {}\n", fields.join(" ")),
    )
    .unwrap();
    fs::write(
        dir.join("status"),
        format!("Name:\tp\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
    )
    .unwrap();
    fs::write(dir.join("cmdline"), argv).unwrap();
    fs::write(dir.join("cgroup"), "0::/system.slice/p.service\n").unwrap();
}

#[test]
fn the_leftovers_are_every_process_pid_1_would_still_kill() {
    let world = tempfile::tempdir().unwrap();
    let proc = world.path().join("proc");
    process(&proc, 1, 'S', 0, 0, b"/sbin/init\0");
    process(&proc, 2, 'S', 0x0020_0000, 0, b"");
    process(&proc, 40, 'S', 0, 0, b"systemd-userdbd\0");
    process(&proc, 41, 'Z', 0, 0, b"");
    process(&proc, 42, 'S', 0, 0, b"@storage-daemon\0");
    process(&proc, 43, 'S', 0, 1000, b"@not-root\0");
    process(&proc, 44, 'D', 0, 0, b"sleep\0");
    process(&proc, 77, 'S', 0, 0, b"the-step\0");
    // Gone between the listing and the read.
    fs::create_dir_all(proc.join("45")).unwrap();
    fs::write(proc.join("self"), "").unwrap();

    // PID 1, the step itself, a kernel thread, a zombie and a root storage
    // daemon are left; a non-root process is killed whatever its argv.
    assert_eq!(leftovers(&proc, 77), [40, 43, 44]);
    assert!(leftovers(&world.path().join("no-proc"), 77).is_empty());
}

/// A fake `systemctl` that appends its arguments to `calls` and fails for
/// `failing`.
fn fake_systemctl(dir: &Path, calls: &Path, failing: &str) -> PathBuf {
    let systemctl = dir.join("systemctl");
    write_executable(
        &systemctl,
        format!(
            "#!/bin/sh\necho \"$*\" >> '{}'\n[ \"$2\" = '{failing}' ] && exit 5\nexit 0\n",
            calls.display()
        ),
        0o755,
    );
    systemctl
}

#[test]
fn the_journal_sockets_are_stopped_and_the_stream_store_dropped() {
    let world = tempfile::tempdir().unwrap();
    let calls = world.path().join("calls");
    let systemctl = fake_systemctl(world.path(), &calls, "syslog.socket");

    // A unit the system lacks fails alone; the others still go.
    assert_eq!(empty_journal_sockets(&systemctl), ["stop syslog.socket"]);
    assert_eq!(
        fs::read_to_string(&calls).unwrap(),
        "stop systemd-journald.socket\n\
         stop systemd-journald-dev-log.socket\n\
         stop systemd-journald-audit.socket\n\
         stop systemd-journald@*.socket\n\
         stop syslog.socket\n\
         clean --what=fdstore systemd-journald.service\n"
    );
    assert_eq!(
        empty_journal_sockets(&world.path().join("no-systemctl")).len(),
        JOURNAL_SOCKETS.len() + 1
    );
}

#[test]
fn no_unit_waiting_to_restart_settles_at_once() {
    let world = tempfile::tempdir().unwrap();
    let calls = world.path().join("calls");
    let systemctl = fake_systemctl(world.path(), &calls, "none");
    assert!(settle_units(&systemctl));
    assert_eq!(
        fs::read_to_string(&calls).unwrap(),
        "list-units --all --plain --no-legend --state=auto-restart\n"
    );
    // Without systemctl the wait gives up at once.
    assert!(!settle_units(&world.path().join("no-systemctl")));
}

/// A fake `/sys` with block device `dev` named `name` and, when `ext4`, an
/// ext4 filesystem on it with message limits `burst` and `interval`.
fn sys(dir: &Path, dev: &str, name: &str, ext4: bool, interval: &str) -> Places {
    let places = Places {
        proc: dir.join("proc"),
        sys_dev_block: dir.join("sys/dev/block"),
        sys_fs_ext4: dir.join("sys/fs/ext4"),
    };
    fs::create_dir_all(&places.sys_dev_block).unwrap();
    symlink(
        format!("../../devices/virtual/block/{name}"),
        places.sys_dev_block.join(dev),
    )
    .unwrap();
    if ext4 {
        let fs_dir = places.sys_fs_ext4.join(name);
        fs::create_dir_all(&fs_dir).unwrap();
        fs::write(fs_dir.join("msg_ratelimit_burst"), "10\n").unwrap();
        fs::write(fs_dir.join("msg_ratelimit_interval_ms"), interval).unwrap();
    }
    places
}

fn hidden_on(dev: &str) -> Plan {
    let mut plan = sample();
    plan.hidden_dev = Some(dev.to_string());
    plan
}

#[test]
fn the_hidden_ext4_volume_logs_nothing_more() {
    let world = tempfile::tempdir().unwrap();
    let places = sys(world.path(), "253:1", "dm-1", true, "5000\n");
    let nextroot = Path::new("/run/nextroot");
    let decoy = parse_mountinfo("40 1 8:3 / /run/nextroot rw - ext4 /dev/sda3 rw\n");

    let quiet = quiet_hidden_unmount(&places, &hidden_on("253:1"), &decoy, nextroot);
    let dir = places.sys_fs_ext4.join("dm-1");
    assert_eq!(quiet, Quiet::Quieted(dir.clone()));
    assert_eq!(
        fs::read_to_string(dir.join("msg_ratelimit_burst")).unwrap(),
        "0"
    );
    assert_eq!(
        fs::read_to_string(dir.join("msg_ratelimit_interval_ms")).unwrap(),
        "5000\n"
    );
}

#[test]
fn a_limit_turned_off_is_turned_on_so_that_zero_drops_every_message() {
    let world = tempfile::tempdir().unwrap();
    let places = sys(world.path(), "7:0", "loop0", true, "0\n");
    let quiet = quiet_hidden_unmount(&places, &hidden_on("7:0"), &[], Path::new("/run/nextroot"));
    let dir = places.sys_fs_ext4.join("loop0");
    assert_eq!(quiet, Quiet::Quieted(dir.clone()));
    assert_eq!(
        fs::read_to_string(dir.join("msg_ratelimit_burst")).unwrap(),
        "0"
    );
    assert_eq!(
        fs::read_to_string(dir.join("msg_ratelimit_interval_ms")).unwrap(),
        "5000"
    );
}

#[test]
fn a_filesystem_that_stays_mounted_keeps_its_messages() {
    let world = tempfile::tempdir().unwrap();
    let places = sys(world.path(), "8:3", "sda3", true, "5000\n");
    let nextroot = Path::new("/run/nextroot");
    let burst = places.sys_fs_ext4.join("sda3/msg_ratelimit_burst");

    // The decoy's tree shows it: it is the decoy's, and stays mounted.
    let decoy = parse_mountinfo("40 1 8:3 / /run/nextroot rw - ext4 /dev/sda3 rw\n");
    assert_eq!(
        quiet_hidden_unmount(&places, &hidden_on("8:3"), &decoy, nextroot),
        Quiet::NotHidden
    );
    // A hidden root on the decoy's own storage, accepted by the operator.
    let mut shared = hidden_on("8:3");
    shared.accepted_decoy_storage = Some("a folder on /".into());
    assert_eq!(
        quiet_hidden_unmount(&places, &shared, &[], nextroot),
        Quiet::NotHidden
    );
    // No device recorded.
    assert_eq!(
        quiet_hidden_unmount(&places, &sample(), &[], nextroot),
        Quiet::NotHidden
    );
    assert_eq!(fs::read_to_string(burst).unwrap(), "10\n");
}

#[test]
fn a_hidden_volume_that_is_not_ext4_is_left_alone() {
    let world = tempfile::tempdir().unwrap();
    let places = sys(world.path(), "253:2", "dm-2", false, "");
    let nextroot = Path::new("/run/nextroot");
    assert_eq!(
        quiet_hidden_unmount(&places, &hidden_on("253:2"), &[], nextroot),
        Quiet::NotExt4
    );
    // A device the kernel does not list.
    assert_eq!(
        quiet_hidden_unmount(&places, &hidden_on("9:9"), &[], nextroot),
        Quiet::NotExt4
    );
}

#[test]
fn a_read_only_limit_fails_without_a_panic() {
    let world = tempfile::tempdir().unwrap();
    let places = sys(world.path(), "253:1", "dm-1", true, "5000\n");
    let burst = places.sys_fs_ext4.join("dm-1/msg_ratelimit_burst");
    fs::remove_file(&burst).unwrap();
    fs::create_dir(&burst).unwrap();
    let quiet = quiet_hidden_unmount(&places, &hidden_on("253:1"), &[], Path::new("/x"));
    assert!(matches!(quiet, Quiet::Failed(_)), "{quiet:?}");
}
