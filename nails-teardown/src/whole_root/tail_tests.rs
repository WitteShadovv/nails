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

#[test]
fn each_leftover_s_outermost_service_is_named_once() {
    let world = tempfile::tempdir().unwrap();
    let proc = world.path().join("proc");
    for (pid, cgroup) in [
        (40, "0::/system.slice/systemd-udevd.service/udev\n"),
        (41, "0::/system.slice/systemd-udevd.service\n"),
        (
            42,
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.service\n",
        ),
        (43, "0::/user.slice/user-1000.slice/session-2.scope\n"),
        (44, "0::/\n"),
    ] {
        process(&proc, pid, 'S', 0, 0, b"p\0");
        fs::write(proc.join(pid.to_string()).join("cgroup"), cgroup).unwrap();
    }
    assert_eq!(
        services_of(&proc, &[40, 41, 42, 43, 44, 99]),
        ["systemd-udevd.service", "user@1000.service"]
    );
}

#[test]
fn udevd_s_processes_are_left_to_pid_1_and_every_other_leftover_ended() {
    let world = tempfile::tempdir().unwrap();
    let proc = world.path().join("proc");
    for (pid, cgroup) in [
        (40, "0::/system.slice/systemd-udevd.service\n"),
        (41, "0::/system.slice/systemd-udevd.service/udev\n"),
        (42, "0::/system.slice/lngr.service\n"),
        (43, "0::/system.slice/systemd-userdbd.service\n"),
        (44, "0::/user.slice/user-1000.slice/session-2.scope\n"),
        (45, "0::/system.slice/not-systemd-udevd.service\n"),
    ] {
        process(&proc, pid, 'S', 0, 0, b"p\0");
        fs::write(proc.join(pid.to_string()).join("cgroup"), cgroup).unwrap();
    }
    // A process whose cgroup cannot be read is ended, as PID 1 would end it.
    process(&proc, 46, 'S', 0, 0, b"p\0");
    fs::remove_file(proc.join("46").join("cgroup")).unwrap();

    assert_eq!(leftovers(&proc, 77), [40, 41, 42, 43, 44, 45, 46]);
    // udevd and its workers stay for the events the network restore causes.
    assert_eq!(to_end(&proc, 77), [42, 43, 44, 45, 46]);
}

/// A fake `systemctl` that appends its arguments to `calls`, lists `active`
/// for `list-units` and fails for `failing` as its second argument.
fn listing_systemctl(dir: &Path, calls: &Path, active: &str, failing: &str) -> PathBuf {
    let systemctl = dir.join("systemctl");
    write_executable(
        &systemctl,
        format!(
            "#!/bin/sh\necho \"$*\" >> '{}'\n\
             if [ \"$1\" = list-units ]; then printf '{active}'; exit 0; fi\n\
             [ \"$2\" = '{failing}' ] && exit 5\nexit 0\n",
            calls.display()
        ),
        0o755,
    );
    systemctl
}

fn units(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_string()).collect()
}

#[test]
fn the_socket_units_are_put_as_the_decoy_had_them_and_no_open_one_is_touched() {
    let world = tempfile::tempdir().unwrap();
    let calls = world.path().join("calls");
    // Now: journald's socket listens, PID 1 closed the /dev/log socket, and
    // the session started a namespace's socket; the decoy's own namespace
    // socket listens as it did at the entry.
    let systemctl = listing_systemctl(
        world.path(),
        &calls,
        "systemd-journald.socket loaded active running Journal Sockets\\n\
         systemd-journald@x.socket loaded active listening Journal Socket for Namespace x\\n\
         systemd-journald@y.socket loaded active listening Journal Socket for Namespace y\\n",
        "none",
    );
    let decoy = units(&[
        "systemd-journald.socket",
        "systemd-journald-dev-log.socket",
        "systemd-journald@y.socket",
    ]);

    assert!(settle_journal_sockets(&systemctl, Some(&decoy)).is_empty());
    assert_eq!(
        fs::read_to_string(&calls).unwrap(),
        "list-units --plain --no-legend --state=active -- systemd-journald.socket \
         systemd-journald-dev-log.socket systemd-journald@*.socket\n\
         reset-failed systemd-journald.service\n\
         clean --what=fdstore systemd-journald.service\n\
         stop systemd-journald@x.socket\n\
         start systemd-journald-dev-log.socket\n",
        "only the closed socket is started and only the session's stopped"
    );

    // Without the entry's record nothing is started or stopped, and nothing
    // asks which units are active.
    fs::remove_file(&calls).unwrap();
    assert!(settle_journal_sockets(&systemctl, None).is_empty());
    assert_eq!(
        fs::read_to_string(&calls).unwrap(),
        "reset-failed systemd-journald.service\n\
         clean --what=fdstore systemd-journald.service\n"
    );
}

#[test]
fn without_an_answer_which_units_are_active_none_is_started_or_stopped() {
    let world = tempfile::tempdir().unwrap();
    let decoy = units(&["systemd-journald.socket"]);
    let failed = settle_journal_sockets(&world.path().join("no-systemctl"), Some(&decoy));
    assert_eq!(
        failed,
        [
            "list-units --plain --no-legend --state=active -- systemd-journald.socket \
             systemd-journald-dev-log.socket systemd-journald@*.socket",
            "reset-failed systemd-journald.service",
            "clean --what=fdstore systemd-journald.service",
        ]
    );
}

#[test]
fn the_entry_keeps_the_sockets_the_decoy_had_listening() {
    let world = tempfile::tempdir().unwrap();
    let calls = world.path().join("calls");
    let systemctl = listing_systemctl(
        world.path(),
        &calls,
        "systemd-journald.socket loaded active listening Journal Sockets\\n\
         systemd-journald@n.socket loaded active listening Journal Socket\\n\
         systemd-journald-dev-log.socket loaded active listening Journal Socket\\n",
        "none",
    );
    let record = world.path().join(SOCKETS_NAME);
    assert!(record_sockets(&systemctl, &record));
    let text = fs::read_to_string(&record).unwrap();
    assert_eq!(
        text,
        "systemd-journald.socket\nsystemd-journald-dev-log.socket\nsystemd-journald@n.socket\n"
    );
    assert_eq!(
        listed_sockets(&text),
        units(&[
            "systemd-journald.socket",
            "systemd-journald-dev-log.socket",
            "systemd-journald@n.socket"
        ])
    );
    // Without an answer no record stays, an older one included.
    assert!(!record_sockets(&world.path().join("no-systemctl"), &record));
    assert!(!record.exists());
}

#[test]
fn only_journald_s_own_and_namespace_sockets_are_listed() {
    assert_eq!(
        listed_sockets(
            "systemd-journald-audit.socket loaded active running Journal Audit Socket\n\
             syslog.socket loaded active listening Syslog Socket\n\
             systemd-journald@ns.socket loaded active listening Journal Socket\n\
             systemd-journald@*.socket loaded active listening not a unit\n\
             systemd-journald@.socket loaded active listening not a unit\n\
             \n\
             systemd-journald.socket loaded active running Journal Sockets\n"
        ),
        units(&["systemd-journald.socket", "systemd-journald@ns.socket"]),
    );
    assert!(listed_sockets("").is_empty());
    assert_eq!(
        journal_socket_calls(&[], &[]),
        [
            vec!["reset-failed".to_string(), JOURNAL_SERVICE.to_string()],
            DROP_STREAMS.iter().map(|arg| (*arg).to_string()).collect(),
        ],
        "with no record, only the store goes"
    );
}

/// A fake `systemctl` that appends its arguments to `calls` and fails for
/// `failing` as its second argument.
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
fn a_store_journald_cannot_give_up_is_reported() {
    let world = tempfile::tempdir().unwrap();
    let calls = world.path().join("calls");
    // PID 1 refuses to drop the store of a service that is not dead.
    let systemctl = fake_systemctl(world.path(), &calls, "--what=fdstore");
    assert_eq!(
        settle_journal_sockets(&systemctl, None),
        ["clean --what=fdstore systemd-journald.service"]
    );
}

#[test]
fn journald_s_unix_sockets_are_found_by_their_paths() {
    let listing = "Num       RefCount Protocol Flags    Type St Inode Path\n\
        0000000000000000: 00000002 00000000 00010000 0001 01 101 /run/systemd/journal/stdout\n\
        0000000000000000: 00000003 00000000 00000000 0001 03 110 /run/systemd/journal/stdout\n\
        0000000000000000: 00000002 00000000 00000000 0002 01 102 /run/systemd/journal/socket\n\
        0000000000000000: 00000002 00000000 00000000 0002 01 103 /run/systemd/journal/dev-log\n\
        0000000000000000: 00000002 00000000 00000000 0002 01 104 /run/systemd/journal.ns/socket\n\
        0000000000000000: 00000002 00000000 00000000 0002 01 105 /run/systemd/journald.sock\n\
        0000000000000000: 00000002 00000000 00000000 0002 01 106 /run/systemd/journal.\n\
        0000000000000000: 00000002 00000000 00000000 0002 01 107 /run/systemd/notify\n\
        0000000000000000: 00000003 00000000 00000000 0001 03 108\n\
        0000000000000000: 00000002 00000000 00000000 0002 01 109 @/run/systemd/journal/socket\n";
    assert_eq!(
        journal_unix_inodes(listing, Path::new("/run/systemd")),
        [101, 102, 103, 104]
    );
}

#[test]
fn only_an_audit_socket_that_takes_the_records_is_found() {
    let listing = "sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode\n\
        0000000000000000 0   1          00000111 0        0        0     2        0        201\n\
        0000000000000000 9   1          00000000 0        0        0     2        0        202\n\
        0000000000000000 9   0          00000001 0        0        0     2        0        203\n\
        0000000000000000 9   4711       00000000 0        0        0     2        0        204\n";
    assert_eq!(audit_reader_inodes(listing), [203]);
    assert!(audit_reader_inodes("").is_empty());
}

/// [`Places`] where this process holds the journal sockets below `run`.
fn own_sockets(run: &Path) -> Places {
    Places {
        proc: PathBuf::from("/proc"),
        sys_dev_block: PathBuf::from("/nonexistent"),
        sys_fs_ext4: PathBuf::from("/nonexistent"),
        journal_holder: std::process::id(),
        journal_run: run.to_path_buf(),
    }
}

#[test]
fn the_sockets_are_emptied_in_place_through_the_holder_s_descriptors() {
    use std::io::Write;
    use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
    let world = tempfile::tempdir().unwrap();
    let run = world.path().join("systemd");
    fs::create_dir_all(run.join("journal")).unwrap();
    // journald's native socket with three datagrams, its stream socket with
    // two connections that carry a line each, and a socket elsewhere whose
    // datagram must stay.
    let native = UnixDatagram::bind(run.join("journal/socket")).unwrap();
    let stdout = UnixListener::bind(run.join("journal/stdout")).unwrap();
    let other = UnixDatagram::bind(world.path().join("other")).unwrap();
    let client = UnixDatagram::unbound().unwrap();
    for line in ["one", "two", "three"] {
        client
            .send_to(line.as_bytes(), run.join("journal/socket"))
            .unwrap();
    }
    client.send_to(b"keep", world.path().join("other")).unwrap();
    let mut streams: Vec<UnixStream> = (0..2)
        .map(|_| UnixStream::connect(run.join("journal/stdout")).unwrap())
        .collect();
    for stream in &mut streams {
        stream.write_all(b"late\nunit\n").unwrap();
    }

    let drained = drain_journal_sockets(&own_sockets(&run));

    assert_eq!(
        drained,
        Drained {
            sockets: 2,
            dropped: 5,
            failed: Vec::new()
        }
    );
    native.set_nonblocking(true).unwrap();
    stdout.set_nonblocking(true).unwrap();
    let mut buf = [0_u8; 16];
    assert_eq!(
        native.recv(&mut buf).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "the native socket holds nothing"
    );
    assert_eq!(
        stdout.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "no connection waits"
    );
    assert_eq!(
        other.recv(&mut buf).unwrap(),
        4,
        "another socket keeps its datagram"
    );
    // The same socket, still bound, takes what is sent after.
    client
        .send_to(b"after", run.join("journal/socket"))
        .unwrap();
    assert_eq!(native.recv(&mut buf).unwrap(), 5);
}

#[test]
fn a_connected_stream_is_left_as_it_is() {
    use std::io::{Read, Write};
    let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    ours.write_all(b"x").unwrap();
    drop(ours);
    let deadline = Instant::now() + Duration::from_secs(5);
    assert_eq!(drain_socket(&theirs, deadline).unwrap(), 0);
    let mut text = String::new();
    (&theirs).read_to_string(&mut text).unwrap();
    assert_eq!(text, "x");
}

#[test]
fn a_holder_without_journal_sockets_is_no_failure() {
    let world = tempfile::tempdir().unwrap();
    assert_eq!(
        drain_journal_sockets(&own_sockets(&world.path().join("systemd"))),
        Drained::default()
    );
}

#[test]
fn what_cannot_be_drained_is_reported() {
    let world = tempfile::tempdir().unwrap();
    let proc = world.path().join("proc");
    // No procfs: the sockets cannot be listed.
    let mut places = own_sockets(&world.path().join("systemd"));
    places.proc = proc.clone();
    let drained = drain_journal_sockets(&places);
    assert_eq!(drained.sockets, 0);
    assert!(
        drained.failed[0].starts_with("unix sockets: "),
        "{drained:?}"
    );
    // A holder that is gone (a number no process can have): its descriptor
    // of the native socket cannot be taken.
    places.journal_holder = 4_194_400;
    let holder = proc.join("4194400");
    fs::create_dir_all(holder.join("net")).unwrap();
    fs::create_dir_all(holder.join("fd")).unwrap();
    fs::write(
        holder.join("net/unix"),
        format!(
            "Num RefCount Protocol Flags Type St Inode Path\n\
             0: 00000002 00000000 00000000 0002 01 77 {}/journal/socket\n",
            places.journal_run.display()
        ),
    )
    .unwrap();
    symlink("socket:[77]", holder.join("fd/5")).unwrap();
    symlink("socket:[78]", holder.join("fd/6")).unwrap();
    let drained = drain_journal_sockets(&places);
    assert_eq!(drained.sockets, 0);
    assert!(drained.failed[0].starts_with("pidfd: "), "{drained:?}");
}

#[test]
fn the_entry_drops_only_the_stored_streams() {
    let world = tempfile::tempdir().unwrap();
    let calls = world.path().join("calls");
    let systemctl = fake_systemctl(world.path(), &calls, "none");
    assert!(drop_journal_streams(&systemctl));
    assert_eq!(
        fs::read_to_string(&calls).unwrap(),
        "clean --what=fdstore systemd-journald.service\n"
    );
    assert!(!drop_journal_streams(&world.path().join("no-systemctl")));
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
        journal_holder: 1,
        journal_run: dir.join("run/systemd"),
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

#[test]
fn the_tmpfiles_line_removes_the_empty_nextroot_and_itself() {
    assert_eq!(
        tmpfiles_text(false),
        "r! /run/nextroot\nr! /run/tmpfiles.d/overlay-runtime-boot.conf\n"
    );
    assert_eq!(
        tmpfiles_text(true),
        "r! /run/nextroot\nr! /run/tmpfiles.d/overlay-runtime-boot.conf\nr! /run/tmpfiles.d\n"
    );
    assert_eq!(
        TMPFILES_PATH,
        format!("/run/{TMPFILES_DIR}/{TMPFILES_NAME}")
    );
}

#[test]
fn a_decoy_without_runtime_tmpfiles_gets_the_folder_and_its_removal() {
    let run = tempfile::tempdir().unwrap();
    remove_nextroot_at_start(run.path()).unwrap();
    let file = run.path().join(TMPFILES_DIR).join(TMPFILES_NAME);
    assert_eq!(fs::read_to_string(&file).unwrap(), tmpfiles_text(true));
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o644
    );
}

#[test]
fn a_decoy_with_runtime_tmpfiles_keeps_its_folder_and_its_lines() {
    let run = tempfile::tempdir().unwrap();
    let dir = run.path().join(TMPFILES_DIR);
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("decoy.conf"), "d /run/decoy 0755 root root -\n").unwrap();
    remove_nextroot_at_start(run.path()).unwrap();
    assert_eq!(
        fs::read_to_string(dir.join(TMPFILES_NAME)).unwrap(),
        tmpfiles_text(false)
    );
    assert_eq!(
        fs::read_to_string(dir.join("decoy.conf")).unwrap(),
        "d /run/decoy 0755 root root -\n"
    );
}

#[test]
fn an_unwritable_run_leaves_no_folder() {
    let run = tempfile::tempdir().unwrap();
    // A file where the folder would go: nothing can be made there.
    fs::write(run.path().join(TMPFILES_DIR), "").unwrap();
    assert!(remove_nextroot_at_start(run.path()).is_err());
    assert!(run.path().join(TMPFILES_DIR).is_file());
}
