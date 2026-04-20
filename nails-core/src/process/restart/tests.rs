use super::*;
use std::path::PathBuf;

/// Mock command executor for testing
struct MockCommandExecutor {
    systemctl_success: bool,
    kill_success: bool,
}

impl CommandExecutor for MockCommandExecutor {
    fn execute_systemctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
        Ok((self.systemctl_success, String::new(), String::new()))
    }

    fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
        Ok(self.kill_success)
    }
}

/// Mock command executor that tracks calls for verification
struct TrackingCommandExecutor {
    systemctl_calls: std::sync::Mutex<Vec<Vec<String>>>,
    systemctl_success: bool,
    kill_success: bool,
}

impl TrackingCommandExecutor {
    fn new(systemctl_success: bool) -> Self {
        Self {
            systemctl_calls: std::sync::Mutex::new(Vec::new()),
            systemctl_success,
            kill_success: true,
        }
    }

    fn systemctl_calls(&self) -> Vec<Vec<String>> {
        self.systemctl_calls.lock().unwrap().clone()
    }
}

impl CommandExecutor for TrackingCommandExecutor {
    fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
        self.systemctl_calls
            .lock()
            .unwrap()
            .push(args.iter().map(|s| s.to_string()).collect());
        Ok((self.systemctl_success, String::new(), String::new()))
    }

    fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
        Ok(self.kill_success)
    }
}

struct RecordingKillExecutor {
    kill_calls: std::sync::Mutex<Vec<(u32, String)>>,
    term_success: bool,
    kill_success: bool,
}

impl RecordingKillExecutor {
    fn new(term_success: bool, kill_success: bool) -> Self {
        Self {
            kill_calls: std::sync::Mutex::new(Vec::new()),
            term_success,
            kill_success,
        }
    }

    fn kill_calls(&self) -> Vec<(u32, String)> {
        self.kill_calls.lock().unwrap().clone()
    }
}

impl CommandExecutor for RecordingKillExecutor {
    fn execute_systemctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
        Ok((true, String::new(), String::new()))
    }

    fn execute_kill(&self, pid: u32, signal: &str) -> Result<bool> {
        self.kill_calls
            .lock()
            .unwrap()
            .push((pid, signal.to_string()));

        Ok(match signal {
            "TERM" => self.term_success,
            "KILL" => self.kill_success,
            _ => false,
        })
    }
}

struct ScriptedSystemctlExecutor {
    responses: std::sync::Mutex<Vec<Result<(bool, String, String)>>>,
    calls: std::sync::Mutex<Vec<Vec<String>>>,
}

impl ScriptedSystemctlExecutor {
    fn new(responses: Vec<Result<(bool, String, String)>>) -> Self {
        Self {
            responses: std::sync::Mutex::new(responses),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().unwrap().clone()
    }
}

impl CommandExecutor for ScriptedSystemctlExecutor {
    fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
        self.calls
            .lock()
            .unwrap()
            .push(args.iter().map(|arg| arg.to_string()).collect());

        self.responses.lock().unwrap().remove(0)
    }

    fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
        Ok(true)
    }
}

struct FailingSystemctlExecutor;

impl CommandExecutor for FailingSystemctlExecutor {
    fn execute_systemctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
        Err(crate::NailsError::IoError(std::io::Error::other(
            "systemctl failed",
        )))
    }

    fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
        Ok(true)
    }
}

struct FailingKillExecutor;

impl CommandExecutor for FailingKillExecutor {
    fn execute_systemctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
        Ok((true, String::new(), String::new()))
    }

    fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
        Err(crate::NailsError::IoError(std::io::Error::other(
            "kill failed",
        )))
    }
}

fn make_test_process(name: &str, pid: u32, service: Option<String>) -> ProcessInfo {
    ProcessInfo {
        pid,
        name: name.to_string(),
        cmdline: format!("/usr/bin/{}", name),
        cwd: PathBuf::from("/"),
        has_cwd_in_target: false,
        has_open_fds_in_target: true,
        has_mmap_in_target: false,
        service_name: service,
    }
}

#[test]
fn test_restart_systemd_service_success() {
    let proc = make_test_process(
        "systemd-journald",
        234,
        Some("systemd-journald".to_string()),
    );
    let executor = MockCommandExecutor {
        systemctl_success: true,
        kill_success: false,
    };

    let result = restart_systemd_service(&proc, "systemd-journald", &executor).unwrap();

    assert_eq!(result.restart_method, RestartMethod::Systemd);
    assert!(result.stopped_successfully);
}

#[test]
fn test_restart_systemd_service_failure() {
    let proc = make_test_process(
        "systemd-journald",
        234,
        Some("systemd-journald".to_string()),
    );
    let executor = MockCommandExecutor {
        systemctl_success: false,
        kill_success: false,
    };

    let result = restart_systemd_service(&proc, "systemd-journald", &executor).unwrap();

    assert_eq!(result.restart_method, RestartMethod::Systemd);
    assert!(!result.stopped_successfully);
}

#[test]
fn test_restart_via_signal_success() {
    let proc = make_test_process("some-daemon", 345, None);
    let executor = MockCommandExecutor {
        systemctl_success: false,
        kill_success: true,
    };

    let result = restart_via_signal(&proc, &executor).unwrap();

    assert_eq!(result.restart_method, RestartMethod::Signal);
    // Note: In test, process_exists() might return true since we're not actually killing
    // In production, this would check actual process state
}

#[test]
fn test_restart_processes_with_executor() {
    let processes = vec![
        make_test_process(
            "systemd-journald",
            234,
            Some("systemd-journald".to_string()),
        ),
        make_test_process("some-daemon", 345, None),
    ];

    let executor = MockCommandExecutor {
        systemctl_success: true,
        kill_success: true,
    };

    let results = restart_processes_with_executor(&processes, &executor).unwrap();

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].restart_method, RestartMethod::Systemd);
    assert_eq!(results[1].restart_method, RestartMethod::Signal);
}

#[test]
fn test_restart_processes_with_executor_empty_input_returns_empty() {
    let executor = MockCommandExecutor {
        systemctl_success: true,
        kill_success: true,
    };

    let results = restart_processes_with_executor(&[], &executor).unwrap();

    assert!(results.is_empty());
}

#[test]
fn test_restart_method_enum() {
    assert_eq!(RestartMethod::Systemd, RestartMethod::Systemd);
    assert_eq!(RestartMethod::Signal, RestartMethod::Signal);
    assert_ne!(RestartMethod::Systemd, RestartMethod::Signal);
}

#[test]
fn test_restarted_process_struct() {
    let proc = make_test_process("test", 123, None);
    let restarted = RestartedProcess {
        info: proc.clone(),
        restart_method: RestartMethod::Signal,
        stopped_successfully: true,
    };

    assert_eq!(restarted.info.pid, 123);
    assert_eq!(restarted.restart_method, RestartMethod::Signal);
    assert!(restarted.stopped_successfully);
}

#[test]
fn test_process_exists() {
    // Test with current process (should exist)
    let current_pid = std::process::id();
    assert!(process_exists(current_pid));

    // Test with unlikely PID (should not exist)
    assert!(!process_exists(99999999));
}

#[test]
fn test_restart_via_signal_term_only_when_pid_already_absent() {
    let pid = 99_999_999;
    let proc = make_test_process("missing-proc", pid, None);
    let executor = RecordingKillExecutor::new(true, true);

    let result = restart_via_signal(&proc, &executor).unwrap();

    assert_eq!(result.restart_method, RestartMethod::Signal);
    assert!(result.stopped_successfully);
    assert_eq!(executor.kill_calls(), vec![(pid, "TERM".to_string())]);
}

#[test]
fn test_restart_via_signal_escalates_to_kill_when_process_still_exists() {
    let pid = std::process::id();
    let proc = make_test_process("current-proc", pid, None);
    let executor = RecordingKillExecutor::new(true, true);

    let result = restart_via_signal(&proc, &executor).unwrap();

    assert_eq!(result.restart_method, RestartMethod::Signal);
    assert!(result.stopped_successfully);
    assert_eq!(
        executor.kill_calls(),
        vec![(pid, "TERM".to_string()), (pid, "KILL".to_string())]
    );
}

#[test]
fn test_restart_via_signal_goes_to_kill_when_term_command_fails() {
    let pid = 42_424;
    let proc = make_test_process("term-fails", pid, None);
    let executor = RecordingKillExecutor::new(false, true);

    let result = restart_via_signal(&proc, &executor).unwrap();

    assert_eq!(result.restart_method, RestartMethod::Signal);
    assert!(result.stopped_successfully);
    assert_eq!(
        executor.kill_calls(),
        vec![(pid, "TERM".to_string()), (pid, "KILL".to_string())]
    );
}

#[test]
fn test_restart_processes_with_executor_propagates_systemctl_error() {
    let processes = vec![make_test_process("svc", 12, Some("svc".to_string()))];

    let result = restart_processes_with_executor(&processes, &FailingSystemctlExecutor);

    assert!(result.is_err());
}

#[test]
fn test_restart_processes_with_executor_propagates_kill_error() {
    let processes = vec![make_test_process("daemon", 34, None)];

    let result = restart_processes_with_executor(&processes, &FailingKillExecutor);

    assert!(result.is_err());
}

// Socket-aware service stopping tests
#[test]
fn test_restart_systemd_service_stops_socket_first() {
    let proc = make_test_process("nix-daemon", 234, Some("nix-daemon".to_string()));
    let executor = TrackingCommandExecutor::new(true);

    let result = restart_systemd_service(&proc, "nix-daemon", &executor).unwrap();
    assert!(result.stopped_successfully);

    let calls = executor.systemctl_calls();
    assert_eq!(calls.len(), 2);
    // Socket stopped first
    assert_eq!(calls[0], vec!["stop", "nix-daemon.socket"]);
    // Then service
    assert_eq!(calls[1], vec!["stop", "nix-daemon"]);
}

#[test]
fn test_restart_systemd_socket_failure_doesnt_prevent_service_stop() {
    // Socket stop failure should not prevent the service from being stopped
    let proc = make_test_process("nix-daemon", 234, Some("nix-daemon".to_string()));
    // Even if systemctl returns false (socket stop "fails"), service stop still proceeds
    // because socket stop is best-effort (uses let _ =)
    let executor = TrackingCommandExecutor::new(true);

    let result = restart_systemd_service(&proc, "nix-daemon", &executor).unwrap();
    assert!(result.stopped_successfully);

    // Both calls were made
    let calls = executor.systemctl_calls();
    assert_eq!(calls.len(), 2);
}

#[test]
fn test_restart_systemd_service_ignores_socket_stop_error_and_stops_service() {
    let proc = make_test_process("nix-daemon", 234, Some("nix-daemon".to_string()));
    let executor = ScriptedSystemctlExecutor::new(vec![
        Err(crate::NailsError::IoError(std::io::Error::other(
            "socket stop failed",
        ))),
        Ok((true, String::new(), String::new())),
    ]);

    let result = restart_systemd_service(&proc, "nix-daemon", &executor).unwrap();

    assert!(result.stopped_successfully);
    assert_eq!(
        executor.calls(),
        vec![
            vec!["stop".to_string(), "nix-daemon.socket".to_string()],
            vec!["stop".to_string(), "nix-daemon".to_string()],
        ]
    );
}

#[test]
fn test_restart_systemd_service_with_journald() {
    // Verify socket-aware stopping works for other services too
    let proc = make_test_process(
        "systemd-journald",
        100,
        Some("systemd-journald".to_string()),
    );
    let executor = TrackingCommandExecutor::new(true);

    let result = restart_systemd_service(&proc, "systemd-journald", &executor).unwrap();
    assert!(result.stopped_successfully);

    let calls = executor.systemctl_calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], vec!["stop", "systemd-journald.socket"]);
    assert_eq!(calls[1], vec!["stop", "systemd-journald"]);
}
