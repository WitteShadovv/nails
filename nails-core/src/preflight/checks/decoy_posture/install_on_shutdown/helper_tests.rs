// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::filesystem::{MockFilesystem, PathKind};

#[test]
fn apt_config_is_the_first_entry_of_its_name_as_getenv_takes_it() {
    let block = b"LANG=C.UTF-8\0APT_CONFIG=/etc/a.conf\0APT_CONFIG=/etc/b.conf\0";
    assert_eq!(apt_config_of(block), Some(b"/etc/a.conf".to_vec()));
    // A value may hold `=`, and the block may end without its last NUL.
    assert_eq!(
        apt_config_of(b"APT_CONFIG=/etc/a=b.conf"),
        Some(b"/etc/a=b.conf".to_vec())
    );
    // An empty value is none to apt, and so is a longer name or a name in
    // another case.
    for block in [
        &b"APT_CONFIG=\0"[..],
        b"APT_CONFIGS=/etc/a.conf\0",
        b"apt_config=/etc/a.conf\0",
        b"XAPT_CONFIG=/etc/a.conf\0",
        b"APT_CONFIG\0",
        b"",
    ] {
        assert_eq!(apt_config_of(block), None, "{block:?}");
    }
    // Bytes beyond ASCII are kept as they are.
    assert_eq!(
        apt_config_of(b"APT_CONFIG=/etc/caf\xe9.conf\0"),
        Some(b"/etc/caf\xe9.conf".to_vec())
    );
}

#[test]
fn an_apt_config_path_is_read_below_the_root_only_when_absolute() {
    assert_eq!(
        apt_config_path(b"/etc/nails-apt.conf"),
        Some(PathBuf::from("etc/nails-apt.conf"))
    );
    assert_eq!(apt_config_path(b"etc/nails-apt.conf"), None);
    assert_eq!(apt_config_path(b"./apt.conf"), None);
}

#[test]
fn the_boot_time_is_the_btime_line() {
    let stat = "cpu  10 0 10 100 0 0 0 0 0 0\nintr 1 2 3\nctxt 99\nbtime 1793950000\n\
                processes 900\n";
    assert_eq!(boot_time(stat), Some(1_793_950_000));
    assert_eq!(boot_time("cpu  1 2 3\n"), None);
    assert_eq!(boot_time("btime soon\n"), None);
}

#[test]
fn a_change_in_the_second_the_helper_started_or_later_counts() {
    let at = |secs: u64, nanos: u32| UNIX_EPOCH + Duration::new(secs, nanos);
    let started = at(1000, 700_000_000);
    assert!(changed_since(at(1001, 0), started));
    // The same second, before or after the start within it: a filesystem
    // that keeps change times to the second cannot tell them apart.
    assert!(changed_since(at(1000, 100_000_000), started));
    assert!(changed_since(at(1000, 900_000_000), started));
    assert!(!changed_since(at(999, 999_999_999), started));
}

/// A mock whose helper unit lists `procs` in its cgroup.
fn mock_procs(procs: &str) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/sys/fs/cgroup/system.slice/unattended-upgrades.service/cgroup.procs",
        procs,
    );
    fs
}

#[test]
fn the_processes_are_those_of_the_units_cgroup() {
    let fs = mock_procs("412\n\n413\n");
    assert_eq!(processes(&fs, Path::new("/")), Ok(vec![412, 413]));
    let fs = mock_procs("412\nnot-a-pid\n");
    let err = processes(&fs, Path::new("/")).unwrap_err();
    assert!(
        err.contains("lists \"not-a-pid\", which is no process number"),
        "{err}"
    );
    let fs = mock_procs("");
    let err = processes(&fs, Path::new("/")).unwrap_err();
    assert!(err.contains("lists no process"), "{err}");
    let err = processes(&MockFilesystem::new(), Path::new("/")).unwrap_err();
    assert!(
        err.starts_with("the processes of unattended-upgrades.service cannot be listed"),
        "{err}"
    );
}

#[test]
fn the_start_is_the_earliest_of_the_marker_and_each_process() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/proc/stat", "btime 1000000\n");
    // `comm` may hold spaces and parentheses: the fields are counted from
    // past its last `)`.
    fs.mock_add_file(
        "/proc/412/stat",
        "412 (a) (b c) S 1 412 412 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 12345 0 0\n",
    );
    fs.mock_add_file(
        "/proc/413/stat",
        "413 (unattended-upgr) S 1 412 412 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 99999 0 0\n",
    );
    let at = |secs: u64, millis: u64| {
        UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_millis(millis)
    };
    // 12345 ticks after the boot: 123.45 s.
    assert_eq!(
        started(&fs, Path::new("/"), &[412, 413]),
        Ok(at(1_000_123, 450))
    );
    // The marker, earlier still.
    let marker = "/run/systemd/units/invocation:unattended-upgrades.service";
    fs.create_symlink(Path::new("8028a172"), Path::new(marker))
        .unwrap();
    fs.mock_set_change_time(marker, at(1_000_100, 0));
    assert_eq!(
        started(&fs, Path::new("/"), &[412, 413]),
        Ok(at(1_000_100, 0))
    );
    // A process whose stat NAILS cannot read leaves it unknown.
    let err = started(&fs, Path::new("/"), &[412, 414]).unwrap_err();
    assert!(err.contains("/proc/414/stat"), "{err}");
    fs.mock_set_path_type("/proc/stat", PathKind::File);
    fs.mock_set_file_content("/proc/stat", "cpu 1 2 3\n");
    let err = started(&fs, Path::new("/"), &[412]).unwrap_err();
    assert!(err.contains("/proc/stat has no btime"), "{err}");
}

#[test]
fn an_environment_is_read_for_its_apt_config_alone() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_bytes(
        "/proc/412/environ",
        b"LANG=C.UTF-8\0APT_CONFIG=/etc/nails-apt.conf\0SECRET=kept-out\0",
    );
    fs.mock_set_file_bytes("/proc/413/environ", b"APT_CONFIG=/etc/nails-apt.conf\0");
    assert_eq!(
        apt_config(&fs, Path::new("/"), &[412, 413]),
        Ok(Some(b"/etc/nails-apt.conf".to_vec()))
    );
    fs.mock_set_file_bytes("/proc/413/environ", b"LANG=C.UTF-8\0");
    let err = apt_config(&fs, Path::new("/"), &[412, 413]).unwrap_err();
    assert!(
        err.why.contains("different values of APT_CONFIG"),
        "{err:?}"
    );
    assert!(!err.why.contains("kept-out"), "{err:?}");
    assert!(!err.needs_root);
    // A read that fails but for want of permission: no claim that root can
    // read it.
    fs.mock_set_path_type("/proc/414/environ", PathKind::File);
    let err = apt_config(&fs, Path::new("/"), &[414]).unwrap_err();
    assert!(
        err.why.starts_with(
            "the environment of unattended-upgrades.service (PID 414), where apt takes \
             APT_CONFIG from, cannot be read ("
        ),
        "{err:?}"
    );
    assert!(!err.why.contains("only root"), "{err:?}");
    assert!(!err.needs_root);
}

#[test]
fn an_environment_the_kernel_refuses_needs_root() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let environ = tmp.path().join("proc/412/environ");
    std::fs::create_dir_all(environ.parent().unwrap()).unwrap();
    std::fs::write(&environ, b"APT_CONFIG=/etc/nails-apt.conf\0").unwrap();
    std::fs::set_permissions(&environ, std::fs::Permissions::from_mode(0o000)).unwrap();
    let read = apt_config(&crate::RealFilesystem, tmp.path(), &[412]);
    if nix::unistd::geteuid().is_root() {
        // Root reads it whatever its mode.
        assert_eq!(read, Ok(Some(b"/etc/nails-apt.conf".to_vec())));
        return;
    }
    let err = read.unwrap_err();
    assert!(err.needs_root, "{err:?}");
    assert!(err.why.ends_with("; only root can read it"), "{err:?}");
}
