// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::RealFilesystem;
use crate::filesystem::{MockFilesystem, PathKind};
use std::path::PathBuf;

/// Mark a systemd unit active by creating its runtime invocation marker, a
/// link as systemd leaves it.
fn set_unit_active(fs: &MockFilesystem, unit: &str) {
    let marker = format!("/{}/invocation:{unit}", loggers::INVOCATION_DIR);
    fs.mock_set_is_symlink(&marker, true);
}

/// Run one process with the given `comm` and `cmdline` on `fs`.
fn run_process(fs: &MockFilesystem, comm: &str, cmdline: &str) {
    run_processes(fs, &[comm]);
    fs.mock_add_file("/proc/731/cmdline", cmdline);
}

/// Run one process for each `comm` on `fs`, from pid 731 on.
fn run_processes(fs: &MockFilesystem, comms: &[&str]) {
    let pids: Vec<PathBuf> = (731..)
        .take(comms.len())
        .map(|pid| PathBuf::from(format!("/proc/{pid}")))
        .collect();
    for (pid, comm) in pids.iter().zip(comms) {
        fs.mock_add_file(&format!("{}/comm", pid.display()), &format!("{comm}\n"));
    }
    fs.mock_set_directory_contents(Path::new("/proc"), pids);
}

/// The first line of `/proc/net/unix`.
const UNIX_HEADER: &str = "Num       RefCount Protocol Flags    Type St Inode Path";

/// A line of `/proc/net/unix` for a stream socket listening at `path`.
fn listening(path: &str) -> String {
    format!("0000000000000000: 00000002 00000000 00010000 0001 01 23456 {path}")
}

/// `/proc/net/unix` with `lines` below its header.
fn unix_table(lines: &[String]) -> String {
    std::iter::once(UNIX_HEADER.to_string())
        .chain(lines.iter().cloned())
        .map(|line| line + "\n")
        .collect()
}

/// Put the ticket cache's socket file in place on `fs` and list `lines` in
/// its `/proc/net/unix`.
fn kcm_socket_with(fs: &MockFilesystem, lines: &[String]) {
    fs.mock_set_path_type("/run/.heim_org.h5l.kcm-socket", PathKind::File);
    fs.mock_add_file("/proc/net/unix", &unix_table(lines));
}

/// The phrase that names a listening ticket cache.
const KCM_LISTENS: &str = "its Kerberos ticket cache listens on /run/.heim_org.h5l.kcm-socket";

/// The finding for the decoy at `/` on `fs`, outside NixOS.
fn finding(fs: &MockFilesystem) -> Option<String> {
    sssd_finding(fs, Path::new("/"), false)
}

/// The finding for the decoy at `/` on `fs`, on NixOS.
fn finding_on_nixos(fs: &MockFilesystem) -> Option<String> {
    sssd_finding(fs, Path::new("/"), true)
}

/// The paths the `rm` in the advice of `message` deletes; none without one.
fn deleted_by_advice(message: &str) -> Vec<String> {
    message
        .split_once("(rm ")
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(paths, _)| paths.split(' ').map(str::to_string).collect())
        .unwrap_or_default()
}

/// The advice outside NixOS, with nothing left to delete: one command for
/// each unit, so a missing `sssd-kcm.socket` does not stop the other.
const DISABLE: &str = "where nothing on it needs sssd, disable it (systemctl disable --now \
                       sssd.service, and systemctl disable --now sssd-kcm.socket where that \
                       unit exists)";

#[test]
fn a_decoy_without_sssd_has_no_finding() {
    let fs = MockFilesystem::new();
    assert_eq!(finding(&fs), None);
}

#[test]
fn every_active_sssd_unit_warns_by_name() {
    for unit in UNITS {
        let fs = MockFilesystem::new();
        set_unit_active(&fs, unit);
        let message = finding(&fs).unwrap_or_else(|| panic!("{unit} must warn"));
        assert!(
            message.starts_with(&format!("sssd is in use on the decoy ({unit} is active)")),
            "{message}"
        );
        assert!(
            message.contains("NAILS is not tested on a decoy joined to a domain"),
            "{message}"
        );
        assert!(
            message.contains("the domain controller records the hidden session's logins"),
            "{message}"
        );
        // A unit stops with the advice and leaves nothing to delete.
        assert!(message.ends_with(DISABLE), "{message}");
        assert!(deleted_by_advice(&message).is_empty(), "{message}");
        assert!(!message.contains("services.sssd"), "{message}");
    }
}

#[test]
fn on_nixos_the_advice_turns_sssd_off_through_its_options() {
    // The configuration owns the units there, so systemctl cannot disable them.
    let fs = MockFilesystem::new();
    set_unit_active(&fs, "sssd.service");
    let message = finding_on_nixos(&fs).expect("must warn");
    assert!(
        message.ends_with(
            "where nothing on it needs sssd, turn it off (set services.sssd.enable and \
             services.sssd.kcm to false, then run nixos-rebuild switch)"
        ),
        "{message}"
    );
    assert!(!message.contains("systemctl"), "{message}");

    // What sssd leaves behind is deleted on NixOS as elsewhere.
    fs.mock_set_path_type("/var/lib/sss/db/config.ldb", PathKind::File);
    let message = finding_on_nixos(&fs).expect("must warn");
    assert!(
        message.ends_with(
            "then run nixos-rebuild switch), then delete the files it leaves behind, which \
             keep this warning (rm /var/lib/sss/db/config.ldb): sssd makes each again when \
             it starts"
        ),
        "{message}"
    );
}

#[test]
fn a_unit_seen_only_by_its_populated_cgroup_warns() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/sys/fs/cgroup/system.slice/sssd.service/cgroup.events",
        "populated 1\nfrozen 0\n",
    );
    let message = finding(&fs).expect("a running sssd.service must warn");
    assert!(message.contains("(sssd.service is active)"), "{message}");

    // An emptied cgroup is a unit that stopped.
    let stopped = MockFilesystem::new();
    stopped.mock_add_file(
        "/sys/fs/cgroup/system.slice/sssd.service/cgroup.events",
        "populated 0\nfrozen 0\n",
    );
    assert_eq!(finding(&stopped), None);
}

#[test]
fn an_unrelated_active_unit_is_no_sign() {
    let fs = MockFilesystem::new();
    set_unit_active(&fs, "sshd.service");
    set_unit_active(&fs, "systemd-journald.service");
    assert_eq!(finding(&fs), None);
}

#[test]
fn a_running_daemon_warns_when_no_unit_shows_it() {
    // The monitor, a back end and a responder, each by its comm.
    for comm in ["sssd", "sssd_be", "sssd_nss", "sssd_kcm"] {
        let fs = MockFilesystem::new();
        run_process(&fs, comm, "");
        let message = finding(&fs).unwrap_or_else(|| panic!("{comm} must warn"));
        assert!(
            message.starts_with(&format!("sssd is in use on the decoy ({comm} runs)")),
            "{message}"
        );
    }
    // A renamed comm still shows the daemon by argv[0].
    let fs = MockFilesystem::new();
    run_process(
        &fs,
        "renamed",
        "/usr/libexec/sssd/sssd_kcm\0--logger=files\0",
    );
    let message = finding(&fs).expect("argv[0] must show sssd_kcm");
    assert!(message.contains("(sssd_kcm runs)"), "{message}");
}

#[test]
fn a_process_named_only_like_sssd_is_no_sign() {
    for comm in ["sssdump", "sss", "my_sssd", "sssd-helper"] {
        let fs = MockFilesystem::new();
        run_process(&fs, comm, "");
        assert_eq!(finding(&fs), None, "{comm}");
    }
}

#[test]
fn a_daemon_is_not_repeated_beside_its_active_unit() {
    let fs = MockFilesystem::new();
    set_unit_active(&fs, "sssd.service");
    run_process(&fs, "sssd", "");
    let message = finding(&fs).expect("must warn");
    assert!(message.contains("(sssd.service is active)"), "{message}");
    assert!(!message.contains(" runs"), "{message}");
}

#[test]
fn the_listening_ticket_cache_alone_warns_as_on_fedora() {
    // Fedora 44 Cloud: sssd.service is enabled but skipped (no domain is
    // configured), and only sssd-kcm.socket listens. The socket unit runs no
    // program, so its listening socket is all there is to see.
    let fs = MockFilesystem::new();
    kcm_socket_with(&fs, &[listening("/run/.heim_org.h5l.kcm-socket")]);
    let message = finding(&fs).expect("the listening ticket cache must warn");
    assert!(
        message.starts_with(&format!("sssd is in use on the decoy ({KCM_LISTENS}). ")),
        "{message}"
    );
    assert!(!message.contains("is active"), "{message}");
    // Disabling sssd-kcm.socket stops it listening, which clears the sign:
    // the advice never deletes the socket.
    assert!(message.ends_with(DISABLE), "{message}");
    assert!(deleted_by_advice(&message).is_empty(), "{message}");

    // A daemon that names the socket by the /var/run link to /run is seen too.
    let fs = MockFilesystem::new();
    kcm_socket_with(&fs, &[listening("/var/run/.heim_org.h5l.kcm-socket")]);
    let message = finding(&fs).expect("a socket bound through /var/run must warn");
    assert!(message.contains(KCM_LISTENS), "{message}");
}

#[test]
fn a_ticket_cache_socket_nothing_listens_on_is_no_sign() {
    // What a stopped socket leaves in /run until the next boot.
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/run/.heim_org.h5l.kcm-socket", PathKind::File);
    assert_eq!(finding(&fs), None);

    // The table lists other listeners, a connection accepted on the socket,
    // which is not the listener, and an abstract socket of the same name.
    let fs = MockFilesystem::new();
    kcm_socket_with(
        &fs,
        &[
            listening("/run/systemd/journal/stdout"),
            "0000000000000000: 00000003 00000000 00000000 0001 03 23457 \
             /run/.heim_org.h5l.kcm-socket"
                .to_string(),
            listening("@/run/.heim_org.h5l.kcm-socket"),
        ],
    );
    assert_eq!(finding(&fs), None);

    // A listener whose socket file is gone is out of every client's reach.
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/proc/net/unix",
        &unix_table(&[listening("/run/.heim_org.h5l.kcm-socket")]),
    );
    assert_eq!(finding(&fs), None);
}

#[test]
fn a_socket_another_ticket_cache_daemon_serves_is_not_sssd() {
    // Heimdal's kcm binds the same socket itself and runs while it is its.
    let fs = MockFilesystem::new();
    kcm_socket_with(&fs, &[listening("/var/run/.heim_org.h5l.kcm-socket")]);
    run_processes(&fs, &["systemd", "kcm"]);
    assert_eq!(finding(&fs), None);

    // Beside an active sssd the warning names sssd's own signs, never that
    // socket, and its advice deletes nothing a daemon listens on.
    set_unit_active(&fs, "sssd.service");
    let message = finding(&fs).expect("the active unit must warn");
    assert!(
        message.starts_with("sssd is in use on the decoy (sssd.service is active). "),
        "{message}"
    );
    assert!(!message.contains("heim_org"), "{message}");
    assert!(message.ends_with(DISABLE), "{message}");
}

#[test]
fn only_a_daemon_named_kcm_takes_the_socket_from_sssd() {
    // sssd's own responder and names that only begin like Heimdal's daemon
    // leave the socket sssd's.
    for comms in [&["sssd_kcm"][..], &["kcminit", "kcmshell6", "kcm_"]] {
        let fs = MockFilesystem::new();
        kcm_socket_with(&fs, &[listening("/run/.heim_org.h5l.kcm-socket")]);
        run_processes(&fs, comms);
        let message = finding(&fs).unwrap_or_else(|| panic!("{comms:?} must warn"));
        assert!(message.contains(KCM_LISTENS), "{comms:?}: {message}");
    }
}

#[test]
fn a_line_of_the_socket_table_counts_only_as_a_listener_at_the_kcm_socket() {
    assert!(listens_on_kcm(&listening("/run/.heim_org.h5l.kcm-socket")));
    assert!(listens_on_kcm(&listening(
        "/var/run/.heim_org.h5l.kcm-socket"
    )));
    // Any listening flag counts, whatever else the flags hold.
    assert!(listens_on_kcm(
        "0000000000000000: 00000002 00000000 00030000 0001 01 23456 \
         /run/.heim_org.h5l.kcm-socket"
    ));
    for line in [
        UNIX_HEADER.to_string(),
        String::new(),
        listening("/run/.heim_org.h5l.kcm-socket.old"),
        listening("/run/.heim_org.h5l.kcm-socket trailing"),
        "0000000000000000: 00000002 00000000 0001000Z 0001 01 23456 \
         /run/.heim_org.h5l.kcm-socket"
            .to_string(),
        // An unbound listener has no path.
        "0000000000000000: 00000002 00000000 00010000 0001 01 23456".to_string(),
    ] {
        assert!(!listens_on_kcm(&line), "{line:?}");
    }
}

#[test]
fn each_state_file_warns_by_its_path() {
    for file in STATE_FILES {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type(&format!("/{file}"), PathKind::File);
        let message = finding(&fs).unwrap_or_else(|| panic!("{file} must warn"));
        assert!(
            message.starts_with(&format!(
                "sssd is in use on the decoy (/{file} holds its state)"
            )),
            "{message}"
        );
        assert_eq!(deleted_by_advice(&message), [format!("/{file}")]);
    }
}

#[test]
fn the_directories_its_package_installs_are_no_sign() {
    let fs = MockFilesystem::new();
    for dir in [
        "/var/lib/sss",
        "/var/lib/sss/db",
        "/var/lib/sss/mc",
        "/var/lib/sss/pipes",
        "/var/lib/sss/pipes/private",
        "/var/lib/sss/pubconf",
        "/var/lib/sss/secrets",
        "/var/log/sssd",
    ] {
        fs.mock_set_path_type(dir, PathKind::Dir);
    }
    assert_eq!(finding(&fs), None);
}

#[test]
fn a_dangling_symlink_counts_as_there() {
    // A link is counted as itself, without following it.
    let fs = MockFilesystem::new();
    fs.mock_set_is_symlink("/var/lib/sss/mc/passwd", true);
    fs.mock_set_path_exists("/var/lib/sss/mc/passwd", false);
    let message = finding(&fs).expect("a dangling link must count");
    assert!(
        message.contains("(/var/lib/sss/mc/passwd holds its state)"),
        "{message}"
    );
    assert_eq!(deleted_by_advice(&message), ["/var/lib/sss/mc/passwd"]);
}

#[test]
fn every_sign_is_named_in_one_finding() {
    let fs = MockFilesystem::new();
    set_unit_active(&fs, "sssd.service");
    set_unit_active(&fs, "sssd-kcm.service");
    kcm_socket_with(&fs, &[listening("/run/.heim_org.h5l.kcm-socket")]);
    fs.mock_set_path_type("/var/lib/sss/db/config.ldb", PathKind::File);
    fs.mock_set_path_type("/var/lib/sss/secrets/secrets.ldb", PathKind::File);
    let message = finding(&fs).expect("must warn");
    assert!(
        message.starts_with(&format!(
            "sssd is in use on the decoy (sssd.service is active, sssd-kcm.service is \
             active, {KCM_LISTENS}, /var/lib/sss/db/config.ldb holds its state). "
        )),
        "{message}"
    );
    // One state file is enough to show it, so the phrase names the first
    // found; the advice deletes every state file found, and never the socket.
    assert_eq!(
        deleted_by_advice(&message),
        [
            "/var/lib/sss/db/config.ldb",
            "/var/lib/sss/secrets/secrets.ldb",
        ]
    );
    assert_eq!(message.matches("secrets.ldb").count(), 1, "{message}");
}

#[test]
fn the_decoy_persistence_check_warns_and_never_refuses_for_sssd() {
    use super::super::{DecoyPersistenceCheck, MOUNTINFO, PreFlightCheck};

    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(
        MOUNTINFO,
        "36 35 0:32 / / rw,noatime shared:1 - ext4 /dev/sda1 rw\n",
    );
    assert!(
        DecoyPersistenceCheck::new(false, false)
            .run(&fs)
            .unwrap()
            .is_pass()
    );

    set_unit_active(&fs, "sssd.service");
    let before = fs.mock_ops().len();
    let result = DecoyPersistenceCheck::new(false, false).run(&fs).unwrap();
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result
            .message()
            .contains("sssd is in use on the decoy (sssd.service is active)"),
        "{result:?}"
    );
    assert!(!DecoyPersistenceCheck::decoy_is_persistent(&fs));
    assert_eq!(fs.mock_ops().len(), before, "the probe writes nothing");
    assert!(fs.mock_written_paths().is_empty());

    // On NixOS the check hands the advice its options.
    let result = DecoyPersistenceCheck::new(false, true).run(&fs).unwrap();
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result
            .message()
            .contains("turn it off (set services.sssd.enable and services.sssd.kcm to false"),
        "{result:?}"
    );
}

/// Backdate the access time of `path` itself, a symlink included, well behind
/// its other times, so `relatime` would update it on the next read.
fn backdate_atime(path: &Path) {
    use nix::fcntl::AT_FDCWD;
    use nix::sys::stat::{UtimensatFlags, utimensat};
    use nix::sys::time::TimeSpec;
    let old = TimeSpec::new(1_000_000_000, 0);
    utimensat(
        AT_FDCWD,
        path,
        &old,
        &TimeSpec::UTIME_OMIT,
        UtimensatFlags::NoFollowSymlink,
    )
    .unwrap();
}

/// The access time of `path` itself, a symlink included.
fn atime(path: &Path) -> (i64, i64) {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path).unwrap();
    (meta.atime(), meta.atime_nsec())
}

/// Whether the filesystem holding `dir` records atime updates at all; under
/// `noatime` the comparison below would prove nothing.
fn records_atime(dir: &Path) -> bool {
    let probe = dir.join("probe");
    std::fs::write(&probe, b"probe").unwrap();
    backdate_atime(&probe);
    let before = atime(&probe);
    let _ = std::fs::read(&probe).unwrap();
    let recorded = atime(&probe) != before;
    std::fs::remove_file(&probe).unwrap();
    recorded
}

#[test]
fn the_probes_leave_the_decoy_access_times_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    if !records_atime(root) {
        eprintln!("skipping: the temp filesystem does not record atime updates");
        return;
    }
    let state = root.join("var/lib/sss");
    std::fs::create_dir_all(state.join("db")).unwrap();
    std::fs::create_dir_all(state.join("mc")).unwrap();
    std::fs::create_dir_all(root.join("run")).unwrap();
    std::fs::create_dir_all(root.join("proc/net")).unwrap();
    std::fs::write(state.join("db/config.ldb"), b"ldb").unwrap();
    std::fs::write(state.join("mc/cache"), b"map").unwrap();
    // A state file that is a link: counted as itself, never followed.
    std::os::unix::fs::symlink("cache", state.join("mc/passwd")).unwrap();
    std::fs::write(root.join("run/.heim_org.h5l.kcm-socket"), b"").unwrap();
    std::fs::write(
        root.join("proc/net/unix"),
        unix_table(&[listening("/run/.heim_org.h5l.kcm-socket")]),
    )
    .unwrap();

    let watched: Vec<PathBuf> = [
        "var/lib/sss",
        "var/lib/sss/db",
        "var/lib/sss/db/config.ldb",
        "var/lib/sss/mc",
        "var/lib/sss/mc/cache",
        "var/lib/sss/mc/passwd",
    ]
    .iter()
    .map(|path| root.join(path))
    .collect();
    for path in &watched {
        backdate_atime(path);
    }
    let before: Vec<_> = watched.iter().map(|path| atime(path)).collect();

    let message = sssd_finding(&RealFilesystem, root, false).expect("the decoy shows sssd");
    assert!(
        message.contains("/var/lib/sss/db/config.ldb holds its state"),
        "{message}"
    );
    assert!(message.contains(KCM_LISTENS), "{message}");

    let after: Vec<_> = watched.iter().map(|path| atime(path)).collect();
    assert_eq!(after, before, "no access time on the decoy may change");

    // With the database gone, the link is what shows the state, still unread.
    std::fs::remove_file(state.join("db/config.ldb")).unwrap();
    let message = sssd_finding(&RealFilesystem, root, false).expect("the link shows sssd");
    assert!(
        message.contains("/var/lib/sss/mc/passwd holds its state"),
        "{message}"
    );
    assert_eq!(
        atime(&state.join("mc/passwd")),
        before[5],
        "the link is not followed"
    );
    assert_eq!(atime(&state.join("mc/cache")), before[4]);
}

#[test]
fn following_the_advice_clears_the_warning() {
    // A decoy where sssd runs, its ticket cache listens and it has written
    // every state file the check looks for.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let cgroup = root.join("sys/fs/cgroup/system.slice/sssd.service");
    std::fs::create_dir_all(&cgroup).unwrap();
    std::fs::write(cgroup.join("cgroup.events"), "populated 1\nfrozen 0\n").unwrap();
    for dir in [
        "run",
        "proc/net",
        "var/lib/sss/db",
        "var/lib/sss/mc",
        "var/lib/sss/secrets",
        "var/lib/sss/pipes/private",
    ] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    for file in std::iter::once(&KCM_SOCKET).chain(STATE_FILES) {
        std::fs::write(root.join(file), b"").unwrap();
    }
    let table = root.join("proc/net/unix");
    std::fs::write(
        &table,
        unix_table(&[listening("/run/.heim_org.h5l.kcm-socket")]),
    )
    .unwrap();
    let message = sssd_finding(&RealFilesystem, root, false).expect("sssd runs");
    assert!(
        message.contains(&format!("(sssd.service is active, {KCM_LISTENS}, ")),
        "{message}"
    );

    // `systemctl disable --now`: the units stop and nothing listens on the
    // socket, but its file and every state file stay.
    std::fs::write(cgroup.join("cgroup.events"), "populated 0\nfrozen 0\n").unwrap();
    std::fs::write(&table, unix_table(&[])).unwrap();
    let message =
        sssd_finding(&RealFilesystem, root, false).expect("its state files keep the warning");
    assert!(!message.contains("is active"), "{message}");
    assert!(!message.contains("listens"), "{message}");
    let deleted = deleted_by_advice(&message);
    let state: Vec<String> = STATE_FILES.iter().map(|file| format!("/{file}")).collect();
    assert_eq!(deleted, state, "{message}");

    // The `rm` the advice names clears it. The socket file stays until the
    // next boot, as do the directories its package installs.
    for path in &deleted {
        std::fs::remove_file(root.join(path.trim_start_matches('/'))).unwrap();
    }
    assert_eq!(sssd_finding(&RealFilesystem, root, false), None);
    assert!(root.join(KCM_SOCKET).exists());
    assert!(root.join("var/lib/sss/pipes/private").is_dir());
}

#[test]
fn the_docs_delete_every_file_the_warning_names() {
    // docs/decoy-requirements.md gives one `rm` for every decoy, which must
    // clear the warning as the warning's own advice does: every state file
    // the check looks for, and no socket.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/decoy-requirements.md");
    let docs = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let section = docs
        .split_once("\n## Decoys joined to a domain\n")
        .and_then(|(_, rest)| rest.split("\n## ").next())
        .expect("the section on decoys joined to a domain");
    let command = section
        .split_once("sudo rm -f ")
        .and_then(|(_, rest)| rest.split_once("\n```"))
        .map(|(command, _)| command.replace("\\\n", " "))
        .expect("the rm in that section");
    let named: Vec<&str> = command.split_whitespace().collect();
    let left: Vec<String> = STATE_FILES.iter().map(|file| format!("/{file}")).collect();
    assert_eq!(named, left, "{command}");
}
