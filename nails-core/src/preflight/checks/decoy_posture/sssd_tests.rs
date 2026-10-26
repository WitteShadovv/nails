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
    fs.mock_set_directory_contents(Path::new("/proc"), vec![PathBuf::from("/proc/731")]);
    fs.mock_add_file("/proc/731/comm", &format!("{comm}\n"));
    fs.mock_add_file("/proc/731/cmdline", cmdline);
}

/// The finding for the decoy at `/` on `fs`.
fn finding(fs: &MockFilesystem) -> Option<String> {
    sssd_finding(fs, Path::new("/"))
}

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
        assert!(
            message.contains("systemctl disable --now sssd.service sssd-kcm.socket"),
            "{message}"
        );
    }
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
fn the_ticket_cache_socket_alone_warns_as_on_fedora() {
    // Fedora 44 Cloud: sssd.service is enabled but skipped (no domain is
    // configured), and only sssd-kcm.socket listens. The socket unit runs no
    // program, so its socket file is all there is to see.
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/run/.heim_org.h5l.kcm-socket", PathKind::File);
    let message = finding(&fs).expect("the ticket cache socket must warn");
    assert!(
        message.starts_with(
            "sssd is in use on the decoy (the socket of its Kerberos ticket cache, \
             /run/.heim_org.h5l.kcm-socket, is in place (a stopped socket leaves it until \
             the next boot))"
        ),
        "{message}"
    );
    assert!(!message.contains("is active"), "{message}");
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
}

#[test]
fn every_sign_is_named_in_one_finding() {
    let fs = MockFilesystem::new();
    set_unit_active(&fs, "sssd.service");
    set_unit_active(&fs, "sssd-kcm.service");
    fs.mock_set_path_type("/run/.heim_org.h5l.kcm-socket", PathKind::File);
    fs.mock_set_path_type("/var/lib/sss/db/config.ldb", PathKind::File);
    fs.mock_set_path_type("/var/lib/sss/secrets/secrets.ldb", PathKind::File);
    let message = finding(&fs).expect("must warn");
    assert!(
        message.starts_with(
            "sssd is in use on the decoy (sssd.service is active, sssd-kcm.service is \
             active, the socket of its Kerberos ticket cache, /run/.heim_org.h5l.kcm-socket, \
             is in place (a stopped socket leaves it until the next boot), \
             /var/lib/sss/db/config.ldb holds its state). "
        ),
        "{message}"
    );
    // One state file is enough to show it: the first found is named.
    assert!(!message.contains("secrets.ldb"), "{message}");
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
    std::fs::write(state.join("db/config.ldb"), b"ldb").unwrap();
    std::fs::write(state.join("mc/cache"), b"map").unwrap();
    // A state file that is a link: counted as itself, never followed.
    std::os::unix::fs::symlink("cache", state.join("mc/passwd")).unwrap();
    std::fs::write(root.join("run/.heim_org.h5l.kcm-socket"), b"").unwrap();

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

    let message = sssd_finding(&RealFilesystem, root).expect("the decoy shows sssd");
    assert!(
        message.contains("/var/lib/sss/db/config.ldb holds its state"),
        "{message}"
    );
    assert!(
        message.contains("/run/.heim_org.h5l.kcm-socket, is in place"),
        "{message}"
    );

    let after: Vec<_> = watched.iter().map(|path| atime(path)).collect();
    assert_eq!(after, before, "no access time on the decoy may change");

    // With the database gone, the link is what shows the state, still unread.
    std::fs::remove_file(state.join("db/config.ldb")).unwrap();
    let message = sssd_finding(&RealFilesystem, root).expect("the link shows sssd");
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
