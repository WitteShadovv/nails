use super::*;
use std::collections::HashSet;
use std::os::unix::fs::symlink;

/// Build a `ProcessInfo` with the capability flags defaulted to false, so tests
/// that only care about a few fields stay readable.
fn sample_info(name: &str, pid: u32) -> ProcessInfo {
    ProcessInfo {
        pid,
        name: name.to_string(),
        cmdline: String::new(),
        cwd: PathBuf::from("/"),
        has_cwd_in_target: false,
        has_open_fds_in_target: false,
        has_writable_fd_in_target: false,
        has_dir_fd_in_target: false,
        has_mmap_in_target: false,
        has_shared_write_map_in_target: false,
        has_root_in_target: false,
        is_unverifiable_writer: false,
        service_name: None,
        is_interactive: false,
    }
}

#[test]
fn test_processinfo_struct() {
    let mut info = sample_info("firefox", 1234);
    info.cwd = PathBuf::from("/home/user");
    info.has_cwd_in_target = true;
    info.has_mmap_in_target = true;

    assert_eq!(info.pid, 1234);
    assert_eq!(info.name, "firefox");
    assert!(info.has_cwd_in_target);
    assert!(!info.has_open_fds_in_target);
    assert!(info.has_mmap_in_target);
    assert_eq!(info.service_name, None);
}

#[test]
fn write_blocking_distinguishes_writers_from_readers() {
    // cwd in target -> writer
    let mut cwd = sample_info("bash", 1);
    cwd.has_cwd_in_target = true;
    assert!(cwd.is_write_blocking());
    assert!(!cwd.is_read_only_consumer());

    // writable fd -> writer
    let mut wfd = sample_info("logger", 2);
    wfd.has_open_fds_in_target = true;
    wfd.has_writable_fd_in_target = true;
    assert!(wfd.is_write_blocking());

    // directory fd -> writer (blocks the mount)
    let mut dfd = sample_info("fm", 3);
    dfd.has_open_fds_in_target = true;
    dfd.has_dir_fd_in_target = true;
    assert!(dfd.is_write_blocking());

    // shared-write map -> writer
    let mut smap = sample_info("db", 4);
    smap.has_mmap_in_target = true;
    smap.has_shared_write_map_in_target = true;
    assert!(smap.is_write_blocking());

    // read-only fd + private map only -> read-only consumer
    let mut ro = sample_info("cat", 5);
    ro.has_open_fds_in_target = true;
    ro.has_mmap_in_target = true;
    assert!(!ro.is_write_blocking());
    assert!(ro.is_read_only_consumer());
}

#[test]
fn test_extract_service_name_from_cgroup() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cgroup_path = temp_dir.path().join("cgroup");
    fs::write(&cgroup_path, "0::/system.slice/systemd-journald.service\n").unwrap();

    let service_name = extract_service_name(temp_dir.path()).unwrap();
    assert_eq!(service_name, Some("systemd-journald".to_string()));
}

#[test]
fn test_extract_service_name_no_service() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cgroup_path = temp_dir.path().join("cgroup");
    fs::write(&cgroup_path, "0::/user.slice/user-1000.slice\n").unwrap();

    let service_name = extract_service_name(temp_dir.path()).unwrap();
    assert_eq!(service_name, None);
}

#[test]
fn test_extract_service_name_ignores_user_units() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cgroup_path = temp_dir.path().join("cgroup");
    fs::write(
        &cgroup_path,
        "0::/user.slice/user-1000.slice/user@1000.service/app.slice/pipewire.service\n",
    )
    .unwrap();

    let service_name = extract_service_name(temp_dir.path()).unwrap();
    assert_eq!(service_name, None);
}

#[test]
fn test_extract_service_name_accepts_system_sub_slice() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cgroup_path = temp_dir.path().join("cgroup");
    fs::write(
        &cgroup_path,
        "0::/system.slice/system-getty.slice/getty@tty1.service\n",
    )
    .unwrap();

    let service_name = extract_service_name(temp_dir.path()).unwrap();
    assert_eq!(service_name, Some("getty@tty1".to_string()));
}

#[test]
fn system_unit_from_cgroup_line_maps_only_system_slice() {
    assert_eq!(
        system_unit_from_cgroup_line("0::/system.slice/systemd-journald.service"),
        Some("systemd-journald")
    );
    assert_eq!(
        system_unit_from_cgroup_line("1:name=systemd:/system.slice/cron.service"),
        Some("cron")
    );
    assert_eq!(
        system_unit_from_cgroup_line(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/pipewire.service"
        ),
        None
    );
    assert_eq!(
        system_unit_from_cgroup_line("0::/user.slice/user-1000.slice"),
        None
    );
}

#[test]
fn test_read_comm() {
    let temp_dir = tempfile::tempdir().unwrap();
    fs::write(temp_dir.path().join("comm"), "firefox\n").unwrap();
    assert_eq!(read_comm(temp_dir.path()).unwrap(), "firefox");
}

#[test]
fn test_read_cmdline() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cmdline_bytes = b"/usr/bin/firefox\0--profile\0/home/user/.firefox\0";
    fs::write(temp_dir.path().join("cmdline"), cmdline_bytes).unwrap();

    let cmdline = read_cmdline(temp_dir.path()).unwrap();
    assert_eq!(cmdline, "/usr/bin/firefox --profile /home/user/.firefox");
}

#[test]
fn test_read_cmdline_empty_file_returns_empty_string() {
    let temp_dir = tempfile::tempdir().unwrap();
    fs::write(temp_dir.path().join("cmdline"), []).unwrap();
    assert_eq!(read_cmdline(temp_dir.path()).unwrap(), "");
}

#[test]
fn parse_fdinfo_flags_reads_octal() {
    assert_eq!(
        parse_fdinfo_flags("pos:\t0\nflags:\t0100002\n"),
        Some(0o100002)
    );
    assert_eq!(parse_fdinfo_flags("flags:\t0\n"), Some(0));
    assert_eq!(parse_fdinfo_flags("pos:\t0\n"), None);
}

#[test]
fn map_is_shared_write_detects_rw_s_only() {
    assert!(map_is_shared_write("rw-s"));
    assert!(!map_is_shared_write("rw-p")); // private: copy-on-write
    assert!(!map_is_shared_write("r--s")); // shared but read-only
    assert!(!map_is_shared_write("r-xp"));
}

#[test]
fn strip_deleted_removes_suffix() {
    assert_eq!(strip_deleted("/home/user/db (deleted)"), "/home/user/db");
    assert_eq!(strip_deleted("/home/user/db"), "/home/user/db");
}

/// Write a minimal `/proc/<pid>` fixture into `dir`, returning its path.
struct ProcFixture {
    dir: tempfile::TempDir,
}

impl ProcFixture {
    fn new(comm: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("comm"), format!("{comm}\n")).unwrap();
        fs::write(dir.path().join("cmdline"), format!("{comm}\0").as_bytes()).unwrap();
        fs::create_dir(dir.path().join("fd")).unwrap();
        fs::create_dir(dir.path().join("fdinfo")).unwrap();
        Self { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn root(self, target: &Path) -> Self {
        symlink(target, self.dir.path().join("root")).unwrap();
        self
    }

    /// Add an fd `n` resolving to `path` with the given octal open flags.
    fn fd(self, n: u32, path: &Path, flags: &str) -> Self {
        symlink(path, self.dir.path().join("fd").join(n.to_string())).unwrap();
        fs::write(
            self.dir.path().join("fdinfo").join(n.to_string()),
            format!("pos:\t0\nflags:\t{flags}\n"),
        )
        .unwrap();
        self
    }

    fn maps(self, contents: &str) -> Self {
        fs::write(self.dir.path().join("maps"), contents).unwrap();
        self
    }

    fn entry(&self, pid: u32) -> ProcEntry {
        read_proc_entry(self.path(), pid, None).unwrap()
    }
}

#[test]
fn read_only_fd_holder_is_not_write_blocking() {
    let target = PathBuf::from("/data");
    let fixture = ProcFixture::new("reader").fd(7, &target.join("file"), "0"); // O_RDONLY
    let info = fixture.entry(10).info_for(&target).unwrap();

    assert!(info.has_open_fds_in_target);
    assert!(!info.has_writable_fd_in_target);
    assert!(info.is_read_only_consumer());
    assert!(!info.is_write_blocking());
}

#[test]
fn writable_fd_holder_is_write_blocking() {
    let target = PathBuf::from("/data");
    for flags in ["0100001", "0100002", "02001"] {
        // O_WRONLY, O_RDWR, O_APPEND|O_WRONLY
        let fixture = ProcFixture::new("writer").fd(3, &target.join("out.log"), flags);
        let info = fixture.entry(11).info_for(&target).unwrap();
        assert!(
            info.has_writable_fd_in_target,
            "flags {flags} should be writable"
        );
        assert!(info.is_write_blocking());
    }
}

#[test]
fn directory_fd_in_target_is_write_blocking() {
    let holder = tempfile::tempdir().unwrap();
    let target = holder.path().join("target");
    let subdir = target.join("sub");
    fs::create_dir_all(&subdir).unwrap();

    let fixture = ProcFixture::new("fm").fd(5, &subdir, "0"); // read-only fd, but a directory
    let info = fixture.entry(12).info_for(&target).unwrap();

    assert!(info.has_dir_fd_in_target);
    assert!(info.is_write_blocking());
}

#[test]
fn shared_write_mapping_is_write_blocking_but_private_is_not() {
    let target = PathBuf::from("/data");

    let shared = ProcFixture::new("db").maps(&format!(
        "7f00-7f01 rw-s 00000000 08:01 42 {}/store.db\n",
        target.display()
    ));
    let shared_info = shared.entry(20).info_for(&target).unwrap();
    assert!(shared_info.has_shared_write_map_in_target);
    assert!(shared_info.is_write_blocking());

    let private = ProcFixture::new("app").maps(&format!(
        "7f00-7f01 rw-p 00000000 08:01 42 {}/lib.so\n",
        target.display()
    ));
    let private_info = private.entry(21).info_for(&target).unwrap();
    assert!(private_info.has_mmap_in_target);
    assert!(!private_info.has_shared_write_map_in_target);
    assert!(private_info.is_read_only_consumer());
}

#[test]
fn maps_prefix_does_not_match_sibling_directory() {
    // The classic bug: "/opt2/..." must not match target "/opt".
    let target = PathBuf::from("/opt");
    let fixture = ProcFixture::new("app").maps("7f00-7f01 r-xp 0 08:01 42 /opt2/app/lib.so\n");
    assert!(fixture.entry(30).info_for(&target).is_none());

    let real = ProcFixture::new("app").maps("7f00-7f01 r-xp 0 08:01 42 /opt/app/lib.so\n");
    assert!(real.entry(31).info_for(&target).is_some());
}

#[test]
fn fd_prefix_does_not_match_sibling_directory() {
    let target = PathBuf::from("/opt");
    let fixture = ProcFixture::new("app").fd(4, Path::new("/opt2/app/data"), "0100002");
    assert!(fixture.entry(32).info_for(&target).is_none());
}

#[test]
fn deleted_suffix_is_stripped_before_matching() {
    let target = PathBuf::from("/data");
    // The kernel appends " (deleted)" to an unlinked-but-open file.
    let fixture = ProcFixture::new("writer")
        .maps("7f00-7f01 rw-s 00000000 08:01 42 /data/tmp.db (deleted)\n");
    let info = fixture.entry(40).info_for(&target).unwrap();
    assert!(info.has_shared_write_map_in_target);
}

#[test]
fn chrooted_process_is_flagged_unverifiable() {
    let jail = tempfile::tempdir().unwrap();
    let root = jail.path().join("jail");
    fs::create_dir_all(root.join("data")).unwrap();

    // root points inside /home-equivalent; cwd inside the jail's data dir.
    let fixture = ProcFixture::new("jailed").root(&root);
    let entry = read_proc_entry(fixture.path(), 50, None).unwrap();
    assert!(entry.unverifiable, "a chrooted process is unverifiable");

    // Classifying against the jail root surfaces both root-in-target and the flag.
    let info = entry.info_for(&root).unwrap();
    assert!(info.has_root_in_target);
    assert!(info.is_unverifiable_writer);
    assert!(info.is_write_blocking());
}

#[test]
fn unconfined_root_is_not_in_target() {
    // root "/" must not be treated as being inside "/data".
    let fixture =
        ProcFixture::new("normal")
            .root(Path::new("/"))
            .fd(3, Path::new("/data/file"), "0");
    let entry = read_proc_entry(fixture.path(), 51, None).unwrap();
    assert!(!entry.unverifiable);
    let info = entry.info_for(Path::new("/data")).unwrap();
    assert!(!info.has_root_in_target);
}

#[test]
fn snapshot_classifies_many_targets_from_one_capture() {
    // A snapshot built from fixtures answers several targets without re-reading.
    let a = ProcFixture::new("writer-a").fd(3, Path::new("/alpha/x"), "0100002");
    let b = ProcFixture::new("writer-b").fd(3, Path::new("/beta/y"), "0100002");
    let snapshot = ProcSnapshot {
        entries: vec![a.entry(60), b.entry(61)],
    };

    let alpha = snapshot.processes_using(Path::new("/alpha"));
    assert_eq!(alpha.len(), 1);
    assert_eq!(alpha[0].pid, 60);

    let beta = snapshot.processes_using(Path::new("/beta"));
    assert_eq!(beta.len(), 1);
    assert_eq!(beta[0].pid, 61);

    assert!(snapshot.processes_using(Path::new("/gamma")).is_empty());
}

#[test]
fn test_detect_processes_using_returns_empty_for_nonexistent_target() {
    let result = detect_processes_using(Path::new("/nonexistent-directory-xyz123"));
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn test_extract_service_name_missing_cgroup_file_returns_none() {
    let temp_dir = tempfile::tempdir().unwrap();
    assert_eq!(extract_service_name(temp_dir.path()).unwrap(), None);
}

#[test]
fn test_extract_service_name_returns_first_matching_service() {
    let temp_dir = tempfile::tempdir().unwrap();
    fs::write(
        temp_dir.path().join("cgroup"),
        "0::/user.slice/user-1000.slice\n1::/system.slice/foo.service\n2::/system.slice/bar.service\n",
    )
    .unwrap();

    assert_eq!(
        extract_service_name(temp_dir.path()).unwrap(),
        Some("foo".to_string())
    );
}

#[test]
fn test_read_ppid_nonexistent_pid_returns_none() {
    assert_eq!(read_ppid(99_999_999), None);
}

#[test]
fn test_collect_ancestor_pids_contains_current_pid() {
    let ancestors: HashSet<u32> = collect_ancestor_pids();
    assert!(ancestors.contains(&std::process::id()));
}

#[test]
fn test_detect_processes_using_excludes_current_pid_for_root_target() {
    let result = detect_processes_using(Path::new("/")).unwrap();
    assert!(result.iter().all(|proc| proc.pid != std::process::id()));
}

#[test]
fn is_terminal_device_recognizes_ttys_and_ptys() {
    assert!(is_terminal_device(Path::new("/dev/pts/3")));
    assert!(is_terminal_device(Path::new("/dev/tty1")));
    assert!(is_terminal_device(Path::new("/dev/tty")));
    assert!(is_terminal_device(Path::new("/dev/console")));

    assert!(!is_terminal_device(Path::new("/dev/null")));
    assert!(!is_terminal_device(Path::new("/home/user/log.txt")));
    assert!(!is_terminal_device(Path::new("/var/log/syslog")));
}

#[test]
fn check_interactive_detects_a_pty_on_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let fd_dir = dir.path().join("fd");
    std::fs::create_dir(&fd_dir).unwrap();
    symlink("/dev/pts/7", fd_dir.join("0")).unwrap();

    assert!(check_interactive(dir.path()));
}

#[test]
fn check_interactive_is_false_for_non_terminal_fds() {
    let dir = tempfile::tempdir().unwrap();
    let fd_dir = dir.path().join("fd");
    std::fs::create_dir(&fd_dir).unwrap();
    symlink("/var/log/app.log", fd_dir.join("1")).unwrap();

    assert!(!check_interactive(dir.path()));
}

/// A fake `/proc/<pid>` for a `tail -f` a user started on a terminal: stdin is a
/// pty, fd 3 is the followed log under `target`, and the cgroup is a login
/// session scope rather than a service.
fn fake_tty_tail(target: &Path) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let fd_dir = dir.path().join("fd");
    fs::create_dir(&fd_dir).unwrap();
    fs::create_dir(dir.path().join("fdinfo")).unwrap();
    symlink("/dev/pts/7", fd_dir.join("0")).unwrap();
    symlink(target.join("log/app.log"), fd_dir.join("3")).unwrap();
    fs::write(dir.path().join("fdinfo").join("3"), "pos:\t0\nflags:\t0\n").unwrap();
    fs::write(dir.path().join("comm"), "tail\n").unwrap();
    fs::write(dir.path().join("cmdline"), b"tail\0-f\0app.log\0").unwrap();
    fs::write(
        dir.path().join("cgroup"),
        "0::/user.slice/user-0.slice/session-1.scope\n",
    )
    .unwrap();
    dir
}

#[test]
fn entry_describes_a_terminal_program_using_the_target() {
    let target = Path::new("/var");
    let proc_dir = fake_tty_tail(target);

    let entry = read_proc_entry(proc_dir.path(), 812, None).unwrap();
    let info = entry.info_for(target).expect("tail uses /var");

    assert_eq!(info.pid, 812);
    assert_eq!(info.name, "tail");
    assert_eq!(info.cmdline, "tail -f app.log");
    assert!(info.has_open_fds_in_target);
    assert!(info.is_interactive);
    assert_eq!(info.service_name, None, "a session scope is not a service");
}

#[test]
fn entry_ignores_a_process_not_using_the_target() {
    let proc_dir = fake_tty_tail(Path::new("/var"));
    let entry = read_proc_entry(proc_dir.path(), 812, None).unwrap();
    assert!(entry.info_for(Path::new("/srv")).is_none());
}

#[test]
fn detect_interactive_processes_using_no_targets_finds_nothing() {
    assert!(detect_interactive_processes_using(&[]).unwrap().is_empty());
}
