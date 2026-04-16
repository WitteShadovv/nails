use super::*;
use std::collections::HashSet;
use std::os::unix::fs::symlink;

#[test]
fn test_processinfo_struct() {
    // Verify ProcessInfo can be constructed with all fields
    let info = ProcessInfo {
        pid: 1234,
        name: "firefox".to_string(),
        cmdline: "/usr/bin/firefox".to_string(),
        cwd: PathBuf::from("/home/user"),
        has_cwd_in_target: true,
        has_open_fds_in_target: false,
        has_mmap_in_target: true,
        service_name: None,
    };

    assert_eq!(info.pid, 1234);
    assert_eq!(info.name, "firefox");
    assert!(info.has_cwd_in_target);
    assert!(!info.has_open_fds_in_target);
    assert!(info.has_mmap_in_target);
    assert_eq!(info.service_name, None);
}

#[test]
fn test_processinfo_with_systemd_service() {
    let info = ProcessInfo {
        pid: 234,
        name: "systemd-journald".to_string(),
        cmdline: "/usr/lib/systemd/systemd-journald".to_string(),
        cwd: PathBuf::from("/"),
        has_cwd_in_target: false,
        has_open_fds_in_target: true,
        has_mmap_in_target: false,
        service_name: Some("systemd-journald".to_string()),
    };

    assert_eq!(info.service_name, Some("systemd-journald".to_string()));
}

#[test]
fn test_extract_service_name_from_cgroup() {
    // Create a temporary test file simulating /proc/{pid}/cgroup
    let temp_dir = tempfile::tempdir().unwrap();
    let cgroup_path = temp_dir.path().join("cgroup");

    // Write cgroup content
    fs::write(&cgroup_path, "0::/system.slice/systemd-journald.service\n").unwrap();

    // Test extraction
    let proc_path = temp_dir.path();
    let service_name = extract_service_name(proc_path).unwrap();
    assert_eq!(service_name, Some("systemd-journald".to_string()));
}

#[test]
fn test_extract_service_name_no_service() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cgroup_path = temp_dir.path().join("cgroup");

    // Write cgroup content without service
    fs::write(&cgroup_path, "0::/user.slice/user-1000.slice\n").unwrap();

    let proc_path = temp_dir.path();
    let service_name = extract_service_name(proc_path).unwrap();
    assert_eq!(service_name, None);
}

#[test]
fn test_read_comm() {
    let temp_dir = tempfile::tempdir().unwrap();
    let comm_path = temp_dir.path().join("comm");

    fs::write(&comm_path, "firefox\n").unwrap();

    let name = read_comm(temp_dir.path()).unwrap();
    assert_eq!(name, "firefox");
}

#[test]
fn test_read_cmdline() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cmdline_path = temp_dir.path().join("cmdline");

    // Null-separated command line
    let cmdline_bytes = b"/usr/bin/firefox\0--profile\0/home/user/.firefox\0";
    fs::write(&cmdline_path, cmdline_bytes).unwrap();

    let cmdline = read_cmdline(temp_dir.path()).unwrap();
    assert_eq!(cmdline, "/usr/bin/firefox --profile /home/user/.firefox");
}

#[test]
fn test_read_cmdline_empty_file_returns_empty_string() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cmdline_path = temp_dir.path().join("cmdline");

    fs::write(&cmdline_path, []).unwrap();

    let cmdline = read_cmdline(temp_dir.path()).unwrap();
    assert_eq!(cmdline, "");
}

#[test]
fn test_check_cwd_in_target() {
    // Note: This test requires actual /proc filesystem with symlinks
    // We'll test the logic with a real process or skip if unavailable

    // Test with a path that doesn't exist (should return false)
    let proc_path = PathBuf::from("/proc/99999999"); // Unlikely PID
    let target = Path::new("/home");

    let (in_target, _cwd) = check_cwd_in_target(&proc_path, target);
    assert!(!in_target);
}

#[test]
fn test_check_cwd_in_target_true_for_symlink_under_target() {
    let temp_dir = tempfile::tempdir().unwrap();
    let target = temp_dir.path().join("target");
    let cwd = target.join("workspace");
    fs::create_dir_all(&cwd).unwrap();
    symlink(&cwd, temp_dir.path().join("cwd")).unwrap();

    let (in_target, detected_cwd) = check_cwd_in_target(temp_dir.path(), &target);

    assert!(in_target);
    assert_eq!(detected_cwd, cwd);
}

#[test]
fn test_check_cwd_in_target_false_for_symlink_outside_target() {
    let temp_dir = tempfile::tempdir().unwrap();
    let target = temp_dir.path().join("target");
    let outside = temp_dir.path().join("outside");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(&outside).unwrap();
    symlink(&outside, temp_dir.path().join("cwd")).unwrap();

    let (in_target, detected_cwd) = check_cwd_in_target(temp_dir.path(), &target);

    assert!(!in_target);
    assert_eq!(detected_cwd, outside);
}

#[test]
fn test_check_fds_in_target() {
    // Test with non-existent process
    let proc_path = PathBuf::from("/proc/99999999");
    let target = Path::new("/home");

    let has_fds = check_fds_in_target(&proc_path, target);
    assert!(!has_fds);
}

#[test]
fn test_check_fds_in_target_true_when_any_fd_points_into_target() {
    let temp_dir = tempfile::tempdir().unwrap();
    let target = temp_dir.path().join("target");
    let outside = temp_dir.path().join("outside");
    let fd_dir = temp_dir.path().join("fd");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::create_dir_all(&fd_dir).unwrap();
    fs::write(target.join("inside.txt"), "in").unwrap();
    fs::write(outside.join("outside.txt"), "out").unwrap();
    symlink(target.join("inside.txt"), fd_dir.join("0")).unwrap();
    symlink(outside.join("outside.txt"), fd_dir.join("1")).unwrap();

    assert!(check_fds_in_target(temp_dir.path(), &target));
}

#[test]
fn test_check_fds_in_target_false_when_all_fds_are_outside_target() {
    let temp_dir = tempfile::tempdir().unwrap();
    let target = temp_dir.path().join("target");
    let outside = temp_dir.path().join("outside");
    let fd_dir = temp_dir.path().join("fd");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::create_dir_all(&fd_dir).unwrap();
    fs::write(outside.join("outside.txt"), "out").unwrap();
    symlink(outside.join("outside.txt"), fd_dir.join("0")).unwrap();

    assert!(!check_fds_in_target(temp_dir.path(), &target));
}

#[test]
fn test_check_maps_in_target() {
    let temp_dir = tempfile::tempdir().unwrap();
    let maps_path = temp_dir.path().join("maps");

    // Simulate maps file content
    let maps_content = "\
7f1234567000-7f1234568000 r-xp 00000000 08:01 12345 /home/user/lib.so
7f1234568000-7f1234569000 r--p 00001000 08:01 12345 /home/user/lib.so
7f1234569000-7f123456a000 rw-p 00002000 08:01 12345 /home/user/lib.so
";
    fs::write(&maps_path, maps_content).unwrap();

    let has_mmap = check_maps_in_target(temp_dir.path(), Path::new("/home"));
    assert!(has_mmap);

    let has_mmap_other = check_maps_in_target(temp_dir.path(), Path::new("/etc"));
    assert!(!has_mmap_other);
}

#[test]
fn test_check_maps_in_target_ignores_lines_without_pathname() {
    let temp_dir = tempfile::tempdir().unwrap();
    let maps_path = temp_dir.path().join("maps");

    let maps_content =
        "7f1234-7f5678 rw-p 00000000 00:00 0\n7f5678-7f9abc rw-p 00000000 00:00 0 [heap]\n";
    fs::write(&maps_path, maps_content).unwrap();

    assert!(!check_maps_in_target(temp_dir.path(), Path::new("/home")));
}

#[test]
fn test_detect_processes_using_returns_empty_for_nonexistent_target() {
    // Test detection against a target that no processes are using
    // This verifies the function doesn't panic and returns empty list
    let result = detect_processes_using(Path::new("/nonexistent-directory-xyz123"));
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn test_extract_service_name_missing_cgroup_file_returns_none() {
    let temp_dir = tempfile::tempdir().unwrap();

    let service_name = extract_service_name(temp_dir.path()).unwrap();

    assert_eq!(service_name, None);
}

#[test]
fn test_extract_service_name_returns_first_matching_service() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cgroup_path = temp_dir.path().join("cgroup");

    fs::write(
        &cgroup_path,
        "0::/user.slice/user-1000.slice\n1::/system.slice/foo.service\n2::/system.slice/bar.service\n",
    )
    .unwrap();

    let service_name = extract_service_name(temp_dir.path()).unwrap();

    assert_eq!(service_name, Some("foo".to_string()));
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
