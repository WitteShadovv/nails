// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
fn test_fstype_supports_overlay_compatible() {
    assert!(fstype_supports_overlay("ext4"));
    assert!(fstype_supports_overlay("xfs"));
    assert!(fstype_supports_overlay("btrfs"));
    assert!(fstype_supports_overlay("tmpfs"));
    assert!(fstype_supports_overlay("overlay"));
}

#[test]
fn test_fstype_supports_overlay_incompatible() {
    assert!(!fstype_supports_overlay("vfat"));
    assert!(!fstype_supports_overlay("fat"));
    assert!(!fstype_supports_overlay("msdos"));
    assert!(!fstype_supports_overlay("exfat"));
    assert!(!fstype_supports_overlay("ntfs"));
    assert!(!fstype_supports_overlay("ntfs3"));
    assert!(!fstype_supports_overlay("fuse.ntfs-3g"));
}

fn setup_vfat_boot(fs: &crate::filesystem::MockFilesystem) {
    use std::path::Path;

    fs.mock_set_filesystem_type(Path::new("/boot"), "vfat");
    fs.mock_set_path_exists("/boot", true);
    fs.mock_set_path_exists("/mnt/hidden/boot/.upper", true);
    fs.mock_set_path_exists("/mnt/hidden/boot/.work", true);
    fs.mock_set_directory_creatable("/run/nails-pivot/boot-snapshot", true);
    fs.mock_set_directory_creatable("/run/nails-pivot/boot", true);
}

#[test]
fn test_vfat_boot_uses_snapshot_pivot_bypassing_no_pivot() {
    use crate::filesystem::MockFilesystem;

    let fs = MockFilesystem::new();
    setup_vfat_boot(&fs);

    let options = OverlayStrategyOptions {
        allow_pivot: false,
        auto_accept_pivot: false,
        skip_process_detection: true,
        ..Default::default()
    };

    let result = mount_overlay_with_strategy(
        &fs,
        &[std::path::Path::new("/boot")],
        std::path::Path::new("/mnt/hidden/boot/.upper"),
        std::path::Path::new("/mnt/hidden/boot/.work"),
        std::path::Path::new("/boot"),
        &options,
        &crate::process::detection::ProcSnapshot::empty(),
    );

    assert!(
        result.is_ok(),
        "vfat target should use snapshot pivot: {:?}",
        result.err()
    );
    assert_eq!(result.unwrap().method, MountMethod::SnapshotPivot);
}

#[test]
fn test_exfat_target_uses_snapshot_pivot() {
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    let fs = MockFilesystem::new();
    fs.mock_set_filesystem_type(Path::new("/boot"), "exfat");
    fs.mock_set_path_exists("/boot", true);
    fs.mock_set_path_exists("/mnt/hidden/boot/.upper", true);
    fs.mock_set_path_exists("/mnt/hidden/boot/.work", true);
    fs.mock_set_directory_creatable("/run/nails-pivot/boot-snapshot", true);
    fs.mock_set_directory_creatable("/run/nails-pivot/boot", true);

    let options = OverlayStrategyOptions {
        allow_pivot: false,
        skip_process_detection: true,
        ..Default::default()
    };

    let result = mount_overlay_with_strategy(
        &fs,
        &[Path::new("/boot")],
        Path::new("/mnt/hidden/boot/.upper"),
        Path::new("/mnt/hidden/boot/.work"),
        Path::new("/boot"),
        &options,
        &crate::process::detection::ProcSnapshot::empty(),
    );

    assert!(result.is_ok());
    assert_eq!(result.unwrap().method, MountMethod::SnapshotPivot);
}

#[test]
fn test_ext4_target_uses_direct_mount() {
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    let fs = MockFilesystem::new();
    fs.mock_set_filesystem_type(Path::new("/home"), "ext4");
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/mnt/hidden/home/.upper", true);
    fs.mock_set_path_exists("/mnt/hidden/home/.work", true);

    let options = OverlayStrategyOptions {
        allow_pivot: false,
        skip_process_detection: true,
        ..Default::default()
    };

    let result = mount_overlay_with_strategy(
        &fs,
        &[Path::new("/home")],
        Path::new("/mnt/hidden/home/.upper"),
        Path::new("/mnt/hidden/home/.work"),
        Path::new("/home"),
        &options,
        &crate::process::detection::ProcSnapshot::empty(),
    );

    assert!(result.is_ok());
    assert_eq!(result.unwrap().method, MountMethod::Direct);
}

#[test]
fn test_no_fstype_info_attempts_direct_mount() {
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/data", true);
    fs.mock_set_path_exists("/mnt/hidden/data/.upper", true);
    fs.mock_set_path_exists("/mnt/hidden/data/.work", true);

    let options = OverlayStrategyOptions {
        skip_process_detection: true,
        ..Default::default()
    };

    let result = mount_overlay_with_strategy(
        &fs,
        &[Path::new("/data")],
        Path::new("/mnt/hidden/data/.upper"),
        Path::new("/mnt/hidden/data/.work"),
        Path::new("/data"),
        &options,
        &crate::process::detection::ProcSnapshot::empty(),
    );

    assert!(result.is_ok());
    assert_eq!(result.unwrap().method, MountMethod::Direct);
}

#[test]
fn test_ntfs_target_uses_snapshot_pivot() {
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    let fs = MockFilesystem::new();
    fs.mock_set_filesystem_type(Path::new("/mnt/windows"), "ntfs3");
    fs.mock_set_path_exists("/mnt/windows", true);
    fs.mock_set_path_exists("/mnt/hidden/windows/.upper", true);
    fs.mock_set_path_exists("/mnt/hidden/windows/.work", true);
    fs.mock_set_directory_creatable("/run/nails-pivot/windows-snapshot", true);
    fs.mock_set_directory_creatable("/run/nails-pivot/windows", true);

    let options = OverlayStrategyOptions {
        allow_pivot: false,
        skip_process_detection: true,
        ..Default::default()
    };

    let result = mount_overlay_with_strategy(
        &fs,
        &[Path::new("/mnt/windows")],
        Path::new("/mnt/hidden/windows/.upper"),
        Path::new("/mnt/hidden/windows/.work"),
        Path::new("/mnt/windows"),
        &options,
        &crate::process::detection::ProcSnapshot::empty(),
    );

    assert!(result.is_ok());
    assert_eq!(result.unwrap().method, MountMethod::SnapshotPivot);
}

#[test]
fn test_restart_services_after_failure_empty_list() {
    restart_services_after_failure(&[]);
}

#[test]
fn test_overlay_incompatible_fstypes_constant_not_empty() {
    assert!(!OVERLAY_INCOMPATIBLE_FSTYPES.is_empty());
    assert!(OVERLAY_INCOMPATIBLE_FSTYPES.contains(&"vfat"));
    assert!(OVERLAY_INCOMPATIBLE_FSTYPES.contains(&"ntfs3"));
}

#[test]
fn test_mount_overlay_with_strategy_direct_mount_succeeds_when_no_fstype() {
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/data", true);
    fs.mock_set_path_exists("/mnt/upper", true);
    fs.mock_set_path_exists("/mnt/work", true);

    let options = super::OverlayStrategyOptions {
        skip_process_detection: true,
        allow_pivot: false,
        ..Default::default()
    };

    let result = mount_overlay_with_strategy(
        &fs,
        &[Path::new("/data")],
        Path::new("/mnt/upper"),
        Path::new("/mnt/work"),
        Path::new("/data"),
        &options,
        &crate::process::detection::ProcSnapshot::empty(),
    );

    assert!(result.is_ok());
    assert_eq!(result.unwrap().method, MountMethod::Direct);
}

#[test]
fn test_direct_mount_fatal_errno_is_returned_without_pivot_fallback() {
    use crate::filesystem::MockFilesystem;
    use nix::errno::Errno;
    use std::path::Path;

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/data", true);
    fs.mock_set_path_exists("/mnt/upper", true);
    fs.mock_set_path_exists("/mnt/work", true);
    fs.mock_set_filesystem_type(Path::new("/data"), "ext4");
    // ENOSPC is not a busy/unsupported errno, so it stays fatal even though
    // the pivot fallback is allowed and auto-accepted.
    fs.mock_set_mount_fail_errno("/data", Errno::ENOSPC);

    let options = OverlayStrategyOptions {
        skip_process_detection: false,
        allow_pivot: true,
        auto_accept_pivot: true,
        ..Default::default()
    };

    let result = mount_overlay_with_strategy(
        &fs,
        &[Path::new("/data")],
        Path::new("/mnt/upper"),
        Path::new("/mnt/work"),
        Path::new("/data"),
        &options,
        &crate::process::detection::ProcSnapshot::empty(),
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        NailsError::Mount { target, errno } => {
            assert_eq!(target, Path::new("/data"));
            assert_eq!(errno, Errno::ENOSPC);
        }
        other => panic!("expected Mount error, got {other:?}"),
    }
}

#[test]
fn test_busy_direct_mount_without_pivot_returns_invalid_state() {
    use crate::filesystem::MockFilesystem;
    use nix::errno::Errno;
    use std::path::Path;

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/data", true);
    fs.mock_set_path_exists("/mnt/upper", true);
    fs.mock_set_path_exists("/mnt/work", true);
    fs.mock_set_filesystem_type(Path::new("/data"), "ext4");
    // EINVAL is one of the recoverable errnos, so the strategy treats /data as a
    // busy target that needs the pivot fallback.
    fs.mock_set_mount_fail_errno("/data", Errno::EINVAL);

    let options = OverlayStrategyOptions {
        skip_process_detection: false,
        allow_pivot: false,
        auto_accept_pivot: false,
        ..Default::default()
    };

    let result = mount_overlay_with_strategy(
        &fs,
        &[Path::new("/data")],
        Path::new("/mnt/upper"),
        Path::new("/mnt/work"),
        Path::new("/data"),
        &options,
        &crate::process::detection::ProcSnapshot::empty(),
    );

    assert!(result.is_err());
    // EINVAL routed into Phase 4; --no-pivot then rejects the pivot fallback.
    match result.unwrap_err() {
        NailsError::InvalidState(msg) => {
            assert!(msg.contains("Pivot mount required"), "{msg}");
            assert!(msg.contains("--no-pivot"), "{msg}");
        }
        other => panic!("expected InvalidState, got {other:?}"),
    }
}

#[test]
fn test_busy_direct_mount_with_auto_accept_enters_pivot_fallback() {
    use crate::filesystem::MockFilesystem;
    use nix::errno::Errno;
    use std::path::Path;

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/data", true);
    fs.mock_set_path_exists("/mnt/upper", true);
    fs.mock_set_path_exists("/mnt/work", true);
    fs.mock_set_filesystem_type(Path::new("/data"), "ext4");
    // EINVAL marks /data as a busy target, so the direct mount fails and, with the
    // pivot auto-accepted, Phase 4 runs the pivot.
    fs.mock_set_mount_fail_errno("/data", Errno::EINVAL);
    fs.mock_set_directory_creatable("/run/nails-pivot/data", true);

    let options = OverlayStrategyOptions {
        skip_process_detection: false,
        allow_pivot: true,
        auto_accept_pivot: true,
        ..Default::default()
    };

    let result = mount_overlay_with_strategy(
        &fs,
        &[Path::new("/data")],
        Path::new("/mnt/upper"),
        Path::new("/mnt/work"),
        Path::new("/data"),
        &options,
        &crate::process::detection::ProcSnapshot::empty(),
    );

    // The pivot is entered: its staging directory is created and the staging
    // overlay is mounted. The mock then fails the bind back onto /data (the
    // target is still in the mount-fail set), so the operation surfaces that
    // bind failure rather than the --no-pivot InvalidState of the no-pivot case.
    assert!(
        fs.path_exists(Path::new("/run/nails-pivot/data")).unwrap(),
        "pivot staging directory should be created when Phase 4 runs"
    );
    assert!(result.is_err());
    assert!(
        !matches!(result.unwrap_err(), NailsError::InvalidState(_)),
        "auto-accepted pivot must not short-circuit as InvalidState"
    );
}

// ── Phase 2 process handling (run_process_phase) ────────────────────────────

use crate::process::restart::CommandExecutor;
use crate::process::{ProcessInfo, RiskyServicePolicy};

/// Command executor that records every systemctl and kill call so tests can
/// assert exactly what the phase did (and, crucially, what it did not do).
struct RecordingExecutor {
    systemctl_calls: std::sync::Mutex<Vec<Vec<String>>>,
    kill_calls: std::sync::Mutex<Vec<(u32, String)>>,
    systemctl_success: bool,
    kill_success: bool,
}

impl RecordingExecutor {
    fn new() -> Self {
        Self {
            systemctl_calls: std::sync::Mutex::new(Vec::new()),
            kill_calls: std::sync::Mutex::new(Vec::new()),
            systemctl_success: true,
            kill_success: true,
        }
    }

    fn kill_calls(&self) -> Vec<(u32, String)> {
        self.kill_calls.lock().unwrap().clone()
    }

    fn systemctl_calls(&self) -> Vec<Vec<String>> {
        self.systemctl_calls.lock().unwrap().clone()
    }
}

impl CommandExecutor for RecordingExecutor {
    fn execute_systemctl(&self, args: &[&str]) -> crate::error::Result<(bool, String, String)> {
        self.systemctl_calls
            .lock()
            .unwrap()
            .push(args.iter().map(|s| s.to_string()).collect());
        Ok((self.systemctl_success, String::new(), String::new()))
    }

    fn execute_kill(&self, pid: u32, signal: &str) -> crate::error::Result<bool> {
        self.kill_calls
            .lock()
            .unwrap()
            .push((pid, signal.to_string()));
        Ok(self.kill_success)
    }
}

fn proc(name: &str, pid: u32, service: Option<&str>, interactive: bool) -> ProcessInfo {
    ProcessInfo {
        pid,
        name: name.to_string(),
        cmdline: format!("/usr/bin/{name}"),
        cwd: std::path::PathBuf::from("/"),
        has_cwd_in_target: false,
        has_open_fds_in_target: true,
        has_mmap_in_target: false,
        // A writable fd makes these fixtures blocking writers (not read-only
        // consumers), so classification routes them to Safe/Risky/NoRestart.
        has_writable_fd_in_target: true,
        has_dir_fd_in_target: false,
        has_shared_write_map_in_target: false,
        has_root_in_target: false,
        is_unverifiable_writer: false,
        service_name: service.map(str::to_string),
        is_interactive: interactive,
    }
}

#[test]
fn run_process_phase_restarts_risky_services_when_policy_restart() {
    let options = OverlayStrategyOptions {
        risky_services: Some(RiskyServicePolicy::Restart),
        ..Default::default()
    };
    let executor = RecordingExecutor::new();

    let blocking = vec![proc("NetworkManager", 500, Some("NetworkManager"), false)];
    let (stopped, survivors) =
        run_process_phase(blocking, std::path::Path::new("/var"), &options, &executor).unwrap();

    assert_eq!(stopped, vec!["NetworkManager".to_string()]);
    assert!(survivors.is_empty());
    // Service stopped through systemctl, never by signal.
    assert!(executor.kill_calls().is_empty());
    assert!(
        executor
            .systemctl_calls()
            .iter()
            .any(|c| c == &vec!["stop".to_string(), "NetworkManager".to_string()])
    );
}

#[test]
fn run_process_phase_skip_policy_lists_risky_as_survivors() {
    let options = OverlayStrategyOptions {
        risky_services: Some(RiskyServicePolicy::Skip),
        ..Default::default()
    };
    let executor = RecordingExecutor::new();

    let blocking = vec![proc("NetworkManager", 500, Some("NetworkManager"), false)];
    let (stopped, survivors) =
        run_process_phase(blocking, std::path::Path::new("/var"), &options, &executor).unwrap();

    assert!(stopped.is_empty());
    assert_eq!(survivors.len(), 1);
    assert_eq!(survivors[0].pid, 500);
    assert_eq!(survivors[0].name, "NetworkManager");
    assert_eq!(survivors[0].service.as_deref(), Some("NetworkManager"));
    // Skipping must not touch the process at all.
    assert!(executor.kill_calls().is_empty());
    assert!(executor.systemctl_calls().is_empty());
}

#[test]
fn run_process_phase_aborts_on_interactive_process_without_opt_in() {
    // A serviceless, terminal-attached user program on /var classifies Safe, so
    // without the gate it would be SIGKILLed. The gate must abort first.
    let options = OverlayStrategyOptions {
        risky_services: Some(RiskyServicePolicy::Restart),
        terminate_interactive: false,
        ..Default::default()
    };
    let executor = RecordingExecutor::new();

    let blocking = vec![proc("tail", 4242, None, true)];
    let result = run_process_phase(blocking, std::path::Path::new("/var"), &options, &executor);

    let err = result.expect_err("interactive process must abort the phase");
    let message = err.to_string();
    assert!(
        message.contains("tail"),
        "error names the process: {message}"
    );
    assert!(message.contains("4242"), "error names the pid: {message}");
    // No signal was sent — the user's program was left alone.
    assert!(executor.kill_calls().is_empty());
}

#[test]
fn run_process_phase_terminates_interactive_process_when_opted_in() {
    let options = OverlayStrategyOptions {
        risky_services: Some(RiskyServicePolicy::Restart),
        terminate_interactive: true,
        ..Default::default()
    };
    let executor = RecordingExecutor::new();

    // A PID that does not exist, so the SIGTERM path reports a clean stop.
    let blocking = vec![proc("tail", 99_999_999, None, true)];
    let (stopped, survivors) =
        run_process_phase(blocking, std::path::Path::new("/var"), &options, &executor).unwrap();

    assert!(stopped.is_empty(), "a serviceless process stops no service");
    assert!(survivors.is_empty());
    // Opting in does send the terminating signal.
    assert_eq!(
        executor.kill_calls(),
        vec![(99_999_999, "TERM".to_string())]
    );
}

#[test]
fn run_process_phase_counts_unrestartable_processes_as_survivors() {
    let options = OverlayStrategyOptions::default();
    let executor = RecordingExecutor::new();

    // A browser on /home classifies NoRestart: it cannot be restarted and keeps
    // writing to the decoy, so it is a survivor and nothing is signalled.
    let blocking = vec![proc("firefox", 700, None, false)];
    let (stopped, survivors) =
        run_process_phase(blocking, std::path::Path::new("/home"), &options, &executor).unwrap();

    assert!(stopped.is_empty());
    assert_eq!(survivors.len(), 1);
    assert_eq!(survivors[0].name, "firefox");
    assert!(executor.kill_calls().is_empty());
}

// The pre-mount sweep: refuse before any target is mounted or any process is
// signalled when a user's terminal program would have to be force-terminated.

fn on(target: &str, proc: ProcessInfo) -> (std::path::PathBuf, ProcessInfo) {
    (std::path::PathBuf::from(target), proc)
}

fn noninteractive_keep_session() -> OverlayStrategyOptions {
    OverlayStrategyOptions {
        risky_services: Some(RiskyServicePolicy::Skip),
        ..Default::default()
    }
}

#[test]
fn sweep_refuses_a_tty_tail_on_var_naming_process_and_target() {
    let found = vec![on("/var", proc("tail", 812, None, true))];

    let err = check_interactive_terminations(&found, &noninteractive_keep_session())
        .expect_err("a terminal-attached tail on /var must block activation");
    let message = err.to_string();
    assert!(message.contains("before mounting"), "{message}");
    assert!(message.contains("tail (PID 812) on /var"), "{message}");
    assert!(message.contains("--terminate-interactive"), "{message}");
}

#[test]
fn sweep_lists_one_process_once_with_every_target() {
    let found = vec![
        on("/etc", proc("less", 77, None, true)),
        on("/var", proc("less", 77, None, true)),
        on("/var", proc("tail", 812, None, true)),
    ];

    let message = check_interactive_terminations(&found, &noninteractive_keep_session())
        .unwrap_err()
        .to_string();
    assert!(message.contains("less (PID 77) on /etc, /var"), "{message}");
    assert!(message.contains("tail (PID 812) on /var"), "{message}");
}

#[test]
fn sweep_allows_processes_that_would_not_be_terminated() {
    let found = vec![
        // A shell in /home classifies NoRestart: it is left running (and later
        // reported as a writer), never killed.
        on("/home", proc("bash", 100, None, true)),
        // A service is stopped through systemd, not by signal.
        on("/var", proc("journal-tty", 200, Some("journal-tty"), true)),
        // Not attached to a terminal.
        on("/var", proc("logger", 300, None, false)),
    ];

    assert!(check_interactive_terminations(&found, &noninteractive_keep_session()).is_ok());
}

#[test]
fn sweep_counts_risky_processes_only_under_an_explicit_restart() {
    // A shell whose cwd is in /srv classifies Risky on that generic target.
    let mut shell = proc("bash", 400, None, true);
    shell.has_cwd_in_target = true;
    let found = vec![on("/srv", shell)];

    let restart = OverlayStrategyOptions {
        risky_services: Some(RiskyServicePolicy::Restart),
        ..Default::default()
    };
    assert!(check_interactive_terminations(&found, &restart).is_err());

    // Skipped risky processes stay running as reported writers.
    assert!(check_interactive_terminations(&found, &noninteractive_keep_session()).is_ok());

    // Left to a prompt, the per-target guard decides after the answer.
    let prompt = OverlayStrategyOptions {
        risky_services: None,
        ..Default::default()
    };
    assert!(check_interactive_terminations(&found, &prompt).is_ok());
}

#[test]
fn sweep_allows_terminating_when_opted_in() {
    let found = vec![on("/var", proc("tail", 812, None, true))];
    let options = OverlayStrategyOptions {
        terminate_interactive: true,
        ..noninteractive_keep_session()
    };
    assert!(check_interactive_terminations(&found, &options).is_ok());
}

#[test]
fn sweep_is_skipped_without_process_detection() {
    let options = OverlayStrategyOptions {
        skip_process_detection: true,
        ..noninteractive_keep_session()
    };
    assert!(refuse_interactive_terminations(&[std::path::PathBuf::from("/var")], &options).is_ok());
}
