//! Session Detection and Management
//!
//! Provides logind-first session termination for the `--kill-session` flag.
//! The goal is to stop the display manager, terminate the user's graphical
//! session (and all user processes that could leak to underlays), then
//! restart the display manager and user manager after activation.
//!
//! Fallback behavior is included for non-logind environments.

use crate::{NailsError, Result, obfuscate};
use nix::unistd::{Uid, User, getuid};
use std::env;
use std::fs;
use std::thread;
use std::time::{Duration, Instant};

/// Kind of session currently running
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionKind {
    /// Running in TTY (no graphical session)
    Tty,
    /// Running in user's graphical session
    GraphicalUser,
    /// Running as root in graphical session without a target user
    GraphicalRoot,
    /// Running over SSH
    Ssh,
    /// Cannot determine session type
    Unknown,
}

/// Context about the current session and target user
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionContext {
    /// Session classification
    pub kind: SessionKind,
    /// logind session id, if available
    pub session_id: Option<String>,
    /// Display manager service to stop/start
    pub display_manager: Option<String>,
    /// Target user uid to terminate
    pub target_uid: Option<u32>,
    /// Target user name (best-effort)
    pub target_user: Option<String>,
    /// Whether logind is available
    pub logind_available: bool,
}

/// Plan for restart after session kill
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionRestartPlan {
    /// Display manager service to restart
    pub display_manager: Option<String>,
    /// User uid to restart user manager for
    pub target_uid: Option<u32>,
}

/// Result of session kill operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKillResult {
    /// Display manager was successfully stopped
    pub display_manager_stopped: bool,
    /// logind was used for termination
    pub logind_used: bool,
    /// Session termination attempted and succeeded
    pub session_terminated: bool,
    /// User termination attempted and succeeded
    pub user_terminated: bool,
    /// Number of processes terminated in fallback mode
    pub fallback_processes_terminated: u32,
    /// Number of processes force-killed in fallback mode
    pub fallback_processes_force_killed: u32,
    /// Time taken for operation
    pub duration: Duration,
    /// Plan for restart after activation
    pub restart_plan: SessionRestartPlan,
}

impl Default for SessionKillResult {
    fn default() -> Self {
        Self {
            display_manager_stopped: false,
            logind_used: false,
            session_terminated: false,
            user_terminated: false,
            fallback_processes_terminated: 0,
            fallback_processes_force_killed: 0,
            duration: Duration::from_secs(0),
            restart_plan: SessionRestartPlan::default(),
        }
    }
}

/// Command executor for session operations
pub trait SessionCommandExecutor {
    /// Execute systemctl command
    fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)>;

    /// Execute loginctl command
    fn execute_loginctl(&self, args: &[&str]) -> Result<(bool, String, String)>;

    /// Send a signal to a process (e.g., TERM, KILL)
    fn execute_kill(&self, pid: u32, signal: &str) -> Result<bool>;

    /// Check whether loginctl is available
    fn loginctl_available(&self) -> bool;
}

/// Real command executor using system commands
pub struct RealSessionCommandExecutor;

impl SessionCommandExecutor for RealSessionCommandExecutor {
    #[cfg(not(test))]
    fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
        use std::process::Command;
        let output = Command::new("systemctl").args(args).output()?;

        let success = output.status.success();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        Ok((success, stdout, stderr))
    }

    #[cfg(test)]
    fn execute_systemctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
        panic!(
            "RealSessionCommandExecutor::execute_systemctl called in test context - use a mock executor instead"
        )
    }

    #[cfg(not(test))]
    fn execute_loginctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
        use std::process::Command;
        let output = Command::new("loginctl").args(args).output()?;

        let success = output.status.success();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        Ok((success, stdout, stderr))
    }

    #[cfg(test)]
    fn execute_loginctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
        panic!(
            "RealSessionCommandExecutor::execute_loginctl called in test context - use a mock executor instead"
        )
    }

    #[cfg(not(test))]
    fn execute_kill(&self, pid: u32, signal: &str) -> Result<bool> {
        use std::process::Command;
        Command::new("kill")
            .arg(format!("-{}", signal))
            .arg(pid.to_string())
            .status()
            .map(|s| s.success())
            .map_err(|e| e.into())
    }

    #[cfg(test)]
    fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
        panic!(
            "RealSessionCommandExecutor::execute_kill called in test context - use a mock executor instead"
        )
    }

    #[cfg(not(test))]
    fn loginctl_available(&self) -> bool {
        use std::process::Command;
        Command::new("loginctl").arg("--version").output().is_ok()
    }

    #[cfg(test)]
    fn loginctl_available(&self) -> bool {
        panic!(
            "RealSessionCommandExecutor::loginctl_available called in test context - use a mock executor instead"
        )
    }
}

/// Detect the current session context
///
/// # Safety
/// This function executes real system commands (loginctl, systemctl).
/// In test builds, use `detect_session_context_with_executor` with a mock executor.
#[cfg(not(test))]
pub fn detect_session_context() -> Result<SessionContext> {
    detect_session_context_with_executor(&RealSessionCommandExecutor)
}

/// Detect the current session context (test-only stub that panics)
#[cfg(test)]
pub fn detect_session_context() -> Result<SessionContext> {
    panic!(
        "detect_session_context() cannot be called in tests - use detect_session_context_with_executor() with a mock"
    )
}

/// Detect the current session context (with injectable executor for testing)
///
/// This function is public for testing purposes. Production code should use
/// `detect_session_context()` which uses the real executor.
pub fn detect_session_context_with_executor<E: SessionCommandExecutor>(
    executor: &E,
) -> Result<SessionContext> {
    let logind_available = match env::var(obfuscate::env_logind_available()) {
        Ok(val) => val != "0",
        Err(_) => executor.loginctl_available(),
    };
    let session_id = env::var("XDG_SESSION_ID").ok();
    let override_session_id = env::var(obfuscate::env_session_id()).ok();
    let override_dm = env::var(obfuscate::env_display_manager()).ok();
    let override_uid = env::var(obfuscate::env_target_uid())
        .ok()
        .and_then(|v| v.parse::<u32>().ok());
    let override_user = env::var(obfuscate::env_target_user()).ok();

    // Check for SSH first
    if env::var("SSH_TTY").is_ok() || env::var("SSH_CONNECTION").is_ok() {
        return Ok(SessionContext {
            kind: SessionKind::Ssh,
            session_id: override_session_id.or(session_id),
            display_manager: None,
            target_uid: None,
            target_user: None,
            logind_available,
        });
    }

    // If overrides were provided by the pre-detach environment, trust them.
    if override_session_id.is_some() || override_uid.is_some() || override_dm.is_some() {
        return Ok(SessionContext {
            kind: SessionKind::GraphicalUser,
            session_id: override_session_id.or(session_id),
            display_manager: override_dm,
            target_uid: override_uid,
            target_user: override_user,
            logind_available,
        });
    }

    // Check for graphical session indicators
    let session_type = env::var("XDG_SESSION_TYPE").ok();
    let has_display = env::var("DISPLAY").is_ok();
    let has_wayland = env::var("WAYLAND_DISPLAY").is_ok();

    let is_graphical = match session_type.as_deref() {
        Some("wayland") | Some("x11") => true,
        Some("tty") => false,
        _ => has_display || has_wayland,
    };

    let target_uid = resolve_target_uid();
    let target_user = resolve_target_user(target_uid);

    if !is_graphical {
        return Ok(SessionContext {
            kind: SessionKind::Tty,
            session_id,
            display_manager: None,
            target_uid,
            target_user,
            logind_available,
        });
    }

    let display_manager = detect_display_manager(executor)?;

    let kind = if target_uid.is_some() {
        SessionKind::GraphicalUser
    } else {
        SessionKind::GraphicalRoot
    };

    Ok(SessionContext {
        kind,
        session_id,
        display_manager,
        target_uid,
        target_user,
        logind_available,
    })
}

fn resolve_target_uid() -> Option<u32> {
    let uid = getuid();

    if uid.is_root() {
        if let Ok(val) = env::var("SUDO_UID")
            && let Ok(parsed) = val.parse::<u32>()
        {
            return Some(parsed);
        }
        if let Ok(val) = env::var("PKEXEC_UID")
            && let Ok(parsed) = val.parse::<u32>()
        {
            return Some(parsed);
        }
        None
    } else {
        Some(uid.as_raw())
    }
}

fn resolve_target_user(uid: Option<u32>) -> Option<String> {
    if let Ok(user) = env::var("SUDO_USER") {
        return Some(user);
    }

    let uid = uid?;
    User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name.to_string())
}

/// Detect which display manager is currently active
fn detect_display_manager<E: SessionCommandExecutor>(executor: &E) -> Result<Option<String>> {
    if let Ok((true, stdout, _)) = executor.execute_systemctl(&["is-active", "display-manager"])
        && stdout.trim() == "active"
    {
        return Ok(Some("display-manager".to_string()));
    }

    let dms = ["gdm", "sddm", "lightdm", "greetd", "ly"];
    for dm in dms {
        if let Ok((true, stdout, _)) = executor.execute_systemctl(&["is-active", dm])
            && stdout.trim() == "active"
        {
            return Ok(Some(dm.to_string()));
        }
    }

    Ok(None)
}

/// Prompt user for confirmation before killing graphical session
pub fn prompt_session_kill_confirmation(ctx: &SessionContext, yes_flag: bool) -> Result<()> {
    prompt_session_kill_confirmation_with_reader(ctx, yes_flag, &mut std::io::stdin().lock())
}

/// Prompt user for confirmation before killing graphical session (with injectable reader)
fn prompt_session_kill_confirmation_with_reader<R: std::io::BufRead>(
    ctx: &SessionContext,
    yes_flag: bool,
    reader: &mut R,
) -> Result<()> {
    if yes_flag {
        return Ok(());
    }

    if ctx.kind != SessionKind::GraphicalUser {
        return Err(NailsError::InvalidState(
            "Cannot confirm session kill - not a graphical user session".to_string(),
        ));
    }

    let dm = ctx.display_manager.as_deref().unwrap_or("display-manager");

    println!("⚠️  This will terminate your graphical session!");
    println!("    All unsaved work in open applications will be LOST.");
    println!();
    println!("    The system will:");
    println!("    1. Stop display manager ({})", dm);
    println!("    2. Terminate your logind session and user processes");
    println!("    3. Mount hidden environment overlays");
    println!("    4. Restart display manager and user manager");
    println!();
    println!("    You will need to log in again after activation.");
    println!();

    // Prompt for confirmation
    use std::io::Write;
    print!("    Continue? [y/N]: ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    reader.read_line(&mut input)?;

    let response = input.trim().to_lowercase();
    if response == "y" || response == "yes" {
        Ok(())
    } else {
        Err(NailsError::InvalidState(
            "User declined session kill confirmation".to_string(),
        ))
    }
}

/// Kill the graphical session (logind-first)
///
/// # Safety
/// This function executes real system commands (systemctl, loginctl, kill).
/// In test builds, use `kill_graphical_session_with_executor` with a mock executor.
#[cfg(not(test))]
pub fn kill_graphical_session(ctx: &SessionContext) -> Result<SessionKillResult> {
    kill_graphical_session_with_executor(ctx, &RealSessionCommandExecutor)
}

/// Kill the graphical session (test-only stub that panics)
#[cfg(test)]
pub fn kill_graphical_session(_ctx: &SessionContext) -> Result<SessionKillResult> {
    panic!(
        "kill_graphical_session() cannot be called in tests - use kill_graphical_session_with_executor() with a mock"
    )
}

fn kill_graphical_session_with_executor<E: SessionCommandExecutor>(
    ctx: &SessionContext,
    executor: &E,
) -> Result<SessionKillResult> {
    if ctx.kind != SessionKind::GraphicalUser {
        return Err(NailsError::InvalidState(
            "Not running in a graphical user session".to_string(),
        ));
    }

    if !nix::unistd::getuid().is_root() {
        return Err(NailsError::PermissionDenied(
            "Session kill requires root privileges".to_string(),
        ));
    }

    let target_uid = ctx.target_uid.ok_or_else(|| {
        NailsError::InvalidState(
            "Unable to determine target user for --kill-session. Run via sudo from the GUI session"
                .to_string(),
        )
    })?;

    if target_uid == 0 {
        return Err(NailsError::InvalidState(
            "Refusing to terminate root user session".to_string(),
        ));
    }

    // Safety guard: avoid terminating the session while still inside its cgroup.
    if ctx.logind_available && process_in_user_slice(target_uid) {
        if try_move_self_to_system_slice() && !process_in_user_slice(target_uid) {
            // moved out successfully, proceed
        } else {
            return Err(NailsError::InvalidState(
                "Refusing to terminate user session from within that session. The CLI must detach into system.slice first"
                    .to_string(),
            ));
        }
    }

    let start = Instant::now();
    let mut result = SessionKillResult {
        restart_plan: SessionRestartPlan {
            display_manager: ctx.display_manager.clone(),
            target_uid: Some(target_uid),
        },
        ..Default::default()
    };

    // Step 1: Stop display manager
    if let Some(ref dm) = ctx.display_manager {
        tracing::info!("DEBUG: About to stop display manager: {}", dm);
        let (success, _stdout, stderr) = executor.execute_systemctl(&["stop", dm])?;
        tracing::info!("DEBUG: Display manager stop completed, success={}", success);
        if !success {
            return Err(NailsError::OverlayError(format!(
                "Failed to stop display manager {}: {}",
                dm, stderr
            )));
        }
        result.display_manager_stopped = true;
    }

    // Step 2: Terminate session/user via logind
    if ctx.logind_available {
        result.logind_used = true;

        if let Some(ref session_id) = ctx.session_id {
            tracing::info!("DEBUG: About to terminate session: {}", session_id);
            let (success, _stdout, _stderr) =
                executor.execute_loginctl(&["terminate-session", session_id])?;
            tracing::info!("DEBUG: Session termination completed, success={}", success);
            result.session_terminated = success;
        }

        tracing::info!("DEBUG: About to terminate user: {}", target_uid);
        let (success, _stdout, _stderr) =
            executor.execute_loginctl(&["terminate-user", &target_uid.to_string()])?;
        tracing::info!("DEBUG: User termination completed, success={}", success);
        result.user_terminated = success;

        // Wait for user manager to stop (max 5 seconds)
        if !wait_for_user_manager_exit(executor, target_uid, Duration::from_secs(5))? {
            let (terminated, force_killed) = kill_user_processes(target_uid, executor)?;
            result.fallback_processes_terminated = terminated;
            result.fallback_processes_force_killed = force_killed;
        }
    } else {
        let (terminated, force_killed) = kill_user_processes(target_uid, executor)?;
        result.fallback_processes_terminated = terminated;
        result.fallback_processes_force_killed = force_killed;
    }

    result.duration = start.elapsed();
    Ok(result)
}

fn wait_for_user_manager_exit<E: SessionCommandExecutor>(
    executor: &E,
    uid: u32,
    timeout: Duration,
) -> Result<bool> {
    let unit = format!("user@{}.service", uid);
    let deadline = Instant::now() + timeout;

    loop {
        let (success, stdout, _stderr) = executor.execute_systemctl(&["is-active", &unit])?;
        let active = success && stdout.trim() == "active";

        if !active {
            return Ok(true);
        }

        if Instant::now() > deadline {
            return Ok(false);
        }

        thread::sleep(Duration::from_millis(200));
    }
}

fn process_in_user_slice(uid: u32) -> bool {
    let cgroup_path = "/proc/self/cgroup";
    let contents = match fs::read_to_string(cgroup_path) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let needle = format!("user-{}.slice", uid);
    contents.lines().any(|line| line.contains(&needle))
}

fn try_move_self_to_system_slice() -> bool {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::Path;

    if !nix::unistd::getuid().is_root() {
        return false;
    }

    let path = Path::new("/sys/fs/cgroup/system.slice/cgroup.procs");
    if !path.exists() {
        return false;
    }

    if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
        return writeln!(file, "{}", std::process::id()).is_ok();
    }

    false
}

fn kill_user_processes<E: SessionCommandExecutor>(uid: u32, executor: &E) -> Result<(u32, u32)> {
    let mut pids = Vec::new();
    let proc_dir = fs::read_dir("/proc");

    let entries = match proc_dir {
        Ok(entries) => entries,
        Err(_) => {
            return Err(NailsError::ConfigError(
                "/proc filesystem not available. This is required for process termination"
                    .to_string(),
            ));
        }
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let pid_str = file_name.to_string_lossy();
        if !pid_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        if pid == std::process::id() {
            continue;
        }

        if let Some(proc_uid) = read_uid_from_status(pid)
            && proc_uid == uid
        {
            pids.push(pid);
        }
    }

    let mut terminated = 0;
    for pid in &pids {
        if executor.execute_kill(*pid, "TERM").unwrap_or(false) {
            terminated += 1;
        }
    }

    thread::sleep(Duration::from_millis(300));

    let mut force_killed = 0;
    for pid in pids {
        if process_exists(pid) && executor.execute_kill(pid, "KILL").unwrap_or(false) {
            force_killed += 1;
        }
    }

    Ok((terminated, force_killed))
}

fn read_uid_from_status(pid: u32) -> Option<u32> {
    let status_path = format!("/proc/{}/status", pid);
    let content = fs::read_to_string(status_path).ok()?;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:\t") {
            let first = rest.split_whitespace().next()?;
            return first.parse::<u32>().ok();
        }
    }

    None
}

fn process_exists(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{}", pid)).exists()
}

/// Restart the display manager (best-effort)
///
/// # Safety
/// This function executes real systemctl commands.
/// In test builds, use `restart_display_manager_with_executor` with a mock executor.
#[cfg(not(test))]
pub fn restart_display_manager(service: &str) -> Result<()> {
    restart_display_manager_with_executor(service, &RealSessionCommandExecutor)
}

/// Restart the display manager (test-only stub that panics)
#[cfg(test)]
pub fn restart_display_manager(_service: &str) -> Result<()> {
    panic!(
        "restart_display_manager() cannot be called in tests - use restart_display_manager_with_executor() with a mock"
    )
}

fn restart_display_manager_with_executor<E: SessionCommandExecutor>(
    service: &str,
    executor: &E,
) -> Result<()> {
    let (success, _stdout, stderr) = executor.execute_systemctl(&["start", service])?;

    if !success {
        return Err(NailsError::OverlayError(format!(
            "Failed to start display manager {}: {}",
            service, stderr
        )));
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (is_active, stdout, _stderr) = executor.execute_systemctl(&["is-active", service])?;
        if is_active && stdout.trim() == "active" {
            return Ok(());
        }

        if Instant::now() > deadline {
            return Err(NailsError::OverlayError(format!(
                "Display manager {} failed to start within 10 seconds",
                service
            )));
        }

        thread::sleep(Duration::from_millis(500));
    }
}

/// Restart the user manager (best-effort)
///
/// # Safety
/// This function executes real systemctl commands.
/// In test builds, use `restart_user_manager_with_executor` with a mock executor.
#[cfg(not(test))]
pub fn restart_user_manager(uid: u32) -> Result<()> {
    restart_user_manager_with_executor(uid, &RealSessionCommandExecutor)
}

/// Restart the user manager (test-only stub that panics)
#[cfg(test)]
pub fn restart_user_manager(_uid: u32) -> Result<()> {
    panic!(
        "restart_user_manager() cannot be called in tests - use restart_user_manager_with_executor() with a mock"
    )
}

fn restart_user_manager_with_executor<E: SessionCommandExecutor>(
    uid: u32,
    executor: &E,
) -> Result<()> {
    let runtime_service = format!("user-runtime-dir@{}.service", uid);
    let user_service = format!("user@{}.service", uid);

    let _ = executor.execute_systemctl(&["start", &runtime_service]);
    let (success, _stdout, stderr) = executor.execute_systemctl(&["start", &user_service])?;

    if !success {
        return Err(NailsError::OverlayError(format!(
            "Failed to start user manager {}: {}",
            user_service, stderr
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;
    use std::sync::Mutex;

    struct MockSessionCommandExecutor {
        systemctl_success: bool,
        loginctl_success: bool,
        loginctl_available: bool,
        kill_success: bool,
    }

    impl MockSessionCommandExecutor {
        fn new(systemctl_success: bool, loginctl_success: bool, loginctl_available: bool) -> Self {
            Self {
                systemctl_success,
                loginctl_success,
                loginctl_available,
                kill_success: true,
            }
        }
    }

    impl SessionCommandExecutor for MockSessionCommandExecutor {
        fn execute_systemctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
            Ok((self.systemctl_success, "active".to_string(), "".to_string()))
        }

        fn execute_loginctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
            Ok((self.loginctl_success, "".to_string(), "".to_string()))
        }

        fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
            Ok(self.kill_success)
        }

        fn loginctl_available(&self) -> bool {
            self.loginctl_available
        }
    }

    struct ScriptedSessionCommandExecutor {
        systemctl_responses: Mutex<Vec<Result<(bool, String, String)>>>,
        loginctl_responses: Mutex<Vec<Result<(bool, String, String)>>>,
        loginctl_available: bool,
        kill_success: bool,
    }

    impl ScriptedSessionCommandExecutor {
        fn new(
            systemctl_responses: Vec<Result<(bool, String, String)>>,
            loginctl_responses: Vec<Result<(bool, String, String)>>,
            loginctl_available: bool,
        ) -> Self {
            Self {
                systemctl_responses: Mutex::new(systemctl_responses),
                loginctl_responses: Mutex::new(loginctl_responses),
                loginctl_available,
                kill_success: true,
            }
        }
    }

    impl SessionCommandExecutor for ScriptedSessionCommandExecutor {
        fn execute_systemctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
            self.systemctl_responses.lock().unwrap().remove(0)
        }

        fn execute_loginctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
            self.loginctl_responses.lock().unwrap().remove(0)
        }

        fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
            Ok(self.kill_success)
        }

        fn loginctl_available(&self) -> bool {
            self.loginctl_available
        }
    }

    struct RecordingScriptedSessionCommandExecutor {
        systemctl_responses: Mutex<Vec<Result<(bool, String, String)>>>,
        loginctl_responses: Mutex<Vec<Result<(bool, String, String)>>>,
        systemctl_calls: Mutex<Vec<Vec<String>>>,
        loginctl_calls: Mutex<Vec<Vec<String>>>,
        loginctl_available: bool,
        kill_success: bool,
    }

    impl RecordingScriptedSessionCommandExecutor {
        fn new(
            systemctl_responses: Vec<Result<(bool, String, String)>>,
            loginctl_responses: Vec<Result<(bool, String, String)>>,
            loginctl_available: bool,
        ) -> Self {
            Self {
                systemctl_responses: Mutex::new(systemctl_responses),
                loginctl_responses: Mutex::new(loginctl_responses),
                systemctl_calls: Mutex::new(Vec::new()),
                loginctl_calls: Mutex::new(Vec::new()),
                loginctl_available,
                kill_success: true,
            }
        }

        fn systemctl_calls(&self) -> Vec<Vec<String>> {
            self.systemctl_calls.lock().unwrap().clone()
        }
    }

    impl SessionCommandExecutor for RecordingScriptedSessionCommandExecutor {
        fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
            self.systemctl_calls
                .lock()
                .unwrap()
                .push(args.iter().map(|arg| arg.to_string()).collect());
            self.systemctl_responses.lock().unwrap().remove(0)
        }

        fn execute_loginctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
            self.loginctl_calls
                .lock()
                .unwrap()
                .push(args.iter().map(|arg| arg.to_string()).collect());
            self.loginctl_responses.lock().unwrap().remove(0)
        }

        fn loginctl_available(&self) -> bool {
            self.loginctl_available
        }

        fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
            Ok(self.kill_success)
        }
    }

    fn clear_session_env() {
        for key in [
            "SSH_TTY",
            "SSH_CONNECTION",
            "NAILS_LOGIND_AVAILABLE",
            "XDG_SESSION_ID",
            "NAILS_SESSION_ID",
            "NAILS_DISPLAY_MANAGER",
            "NAILS_TARGET_UID",
            "NAILS_TARGET_USER",
            "XDG_SESSION_TYPE",
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "SUDO_UID",
            "SUDO_USER",
            "PKEXEC_UID",
        ] {
            unsafe {
                env::remove_var(key);
            }
        }
    }

    #[test]
    fn session_kill_result_default() {
        let result = SessionKillResult::default();
        assert!(!result.display_manager_stopped);
        assert!(!result.logind_used);
        assert_eq!(result.fallback_processes_terminated, 0);
        assert_eq!(result.fallback_processes_force_killed, 0);
    }

    #[test]
    fn detect_display_manager_none() {
        let exec = MockSessionCommandExecutor::new(false, true, true);
        let dm = detect_display_manager(&exec).unwrap();
        assert!(dm.is_none());
    }

    #[test]
    fn detect_display_manager_prefers_generic_display_manager() {
        let exec = ScriptedSessionCommandExecutor::new(
            vec![Ok((true, "active".to_string(), String::new()))],
            vec![],
            true,
        );

        let dm = detect_display_manager(&exec).unwrap();

        assert_eq!(dm, Some("display-manager".to_string()));
    }

    #[test]
    fn detect_display_manager_falls_back_to_named_service() {
        let exec = ScriptedSessionCommandExecutor::new(
            vec![
                Ok((false, "inactive".to_string(), String::new())),
                Ok((true, "active".to_string(), String::new())),
            ],
            vec![],
            true,
        );

        let dm = detect_display_manager(&exec).unwrap();

        assert_eq!(dm, Some("gdm".to_string()));
    }

    #[test]
    fn detect_display_manager_skips_failed_probes_and_returns_later_active_service() {
        let exec = RecordingScriptedSessionCommandExecutor::new(
            vec![
                Err(NailsError::IoError(std::io::Error::other(
                    "display-manager failed",
                ))),
                Ok((false, "inactive".to_string(), String::new())),
                Ok((true, "active".to_string(), String::new())),
            ],
            vec![],
            true,
        );

        let dm = detect_display_manager(&exec).unwrap();

        assert_eq!(dm, Some("sddm".to_string()));
        assert_eq!(
            exec.systemctl_calls(),
            vec![
                vec!["is-active".to_string(), "display-manager".to_string()],
                vec!["is-active".to_string(), "gdm".to_string()],
                vec!["is-active".to_string(), "sddm".to_string()],
            ]
        );
    }

    #[test]
    #[serial]
    fn detect_session_context_detects_ssh() {
        clear_session_env();
        unsafe {
            env::set_var("SSH_CONNECTION", "1 2 3 4");
            env::set_var("NAILS_LOGIND_AVAILABLE", "0");
        }

        let exec = MockSessionCommandExecutor::new(true, true, true);

        let ctx = detect_session_context_with_executor(&exec).unwrap();

        assert_eq!(ctx.kind, SessionKind::Ssh);
        assert_eq!(ctx.display_manager, None);
        assert_eq!(ctx.target_uid, None);
        assert!(!ctx.logind_available);

        clear_session_env();
    }

    #[test]
    #[serial]
    fn detect_session_context_uses_override_values() {
        clear_session_env();
        unsafe {
            env::set_var("NAILS_SESSION_ID", "c2");
            env::set_var("NAILS_DISPLAY_MANAGER", "gdm");
            env::set_var("NAILS_TARGET_UID", "1000");
            env::set_var("NAILS_TARGET_USER", "alice");
        }

        let exec = MockSessionCommandExecutor::new(false, true, true);

        let ctx = detect_session_context_with_executor(&exec).unwrap();

        assert_eq!(ctx.kind, SessionKind::GraphicalUser);
        assert_eq!(ctx.session_id, Some("c2".to_string()));
        assert_eq!(ctx.display_manager, Some("gdm".to_string()));
        assert_eq!(ctx.target_uid, Some(1000));
        assert_eq!(ctx.target_user, Some("alice".to_string()));

        clear_session_env();
    }

    #[test]
    #[serial]
    fn detect_session_context_detects_tty_when_not_graphical() {
        clear_session_env();
        unsafe {
            env::set_var("XDG_SESSION_TYPE", "tty");
            env::set_var("NAILS_LOGIND_AVAILABLE", "0");
        }

        let exec = MockSessionCommandExecutor::new(true, true, true);

        let ctx = detect_session_context_with_executor(&exec).unwrap();

        assert_eq!(ctx.kind, SessionKind::Tty);
        assert_eq!(ctx.display_manager, None);
        assert!(!ctx.logind_available);

        clear_session_env();
    }

    #[test]
    #[serial]
    fn detect_session_context_detects_graphical_user_and_display_manager() {
        clear_session_env();
        unsafe {
            env::set_var("DISPLAY", ":0");
            env::set_var("SUDO_UID", "1000");
            env::set_var("SUDO_USER", "alice");
        }

        let exec = ScriptedSessionCommandExecutor::new(
            vec![Ok((true, "active".to_string(), String::new()))],
            vec![],
            true,
        );

        let ctx = detect_session_context_with_executor(&exec).unwrap();

        assert_eq!(ctx.kind, SessionKind::GraphicalUser);
        assert_eq!(ctx.display_manager, Some("display-manager".to_string()));
        assert!(ctx.target_uid.is_some());

        clear_session_env();
    }

    #[test]
    #[serial]
    fn detect_session_context_honors_logind_override() {
        clear_session_env();
        unsafe {
            env::set_var("XDG_SESSION_TYPE", "tty");
            env::set_var("NAILS_LOGIND_AVAILABLE", "0");
        }

        let exec = MockSessionCommandExecutor::new(true, true, true);

        let ctx = detect_session_context_with_executor(&exec).unwrap();

        assert!(!ctx.logind_available);

        clear_session_env();
    }

    #[test]
    #[serial]
    fn detect_session_context_uses_executor_logind_availability_when_not_overridden() {
        clear_session_env();
        unsafe {
            env::set_var("XDG_SESSION_TYPE", "tty");
        }

        let exec = MockSessionCommandExecutor::new(true, true, true);

        let ctx = detect_session_context_with_executor(&exec).unwrap();

        assert_eq!(ctx.kind, SessionKind::Tty);
        assert!(ctx.logind_available);

        clear_session_env();
    }

    #[test]
    #[serial]
    fn detect_session_context_uses_xdg_session_id_when_override_missing() {
        clear_session_env();
        unsafe {
            env::set_var("XDG_SESSION_ID", "c7");
            env::set_var("NAILS_TARGET_UID", "1000");
            env::set_var("NAILS_DISPLAY_MANAGER", "gdm");
        }

        let exec = MockSessionCommandExecutor::new(true, true, true);

        let ctx = detect_session_context_with_executor(&exec).unwrap();

        assert_eq!(ctx.session_id, Some("c7".to_string()));
        assert_eq!(ctx.display_manager, Some("gdm".to_string()));
        assert_eq!(ctx.target_uid, Some(1000));

        clear_session_env();
    }

    #[test]
    #[serial]
    fn detect_session_context_ignores_invalid_override_target_uid() {
        clear_session_env();
        unsafe {
            env::set_var("NAILS_SESSION_ID", "c2");
            env::set_var("NAILS_TARGET_UID", "not-a-number");
            env::set_var("NAILS_TARGET_USER", "alice");
        }

        let exec = MockSessionCommandExecutor::new(true, true, true);

        let ctx = detect_session_context_with_executor(&exec).unwrap();

        assert_eq!(ctx.kind, SessionKind::GraphicalUser);
        assert_eq!(ctx.session_id, Some("c2".to_string()));
        assert_eq!(ctx.target_uid, None);
        assert_eq!(ctx.target_user, Some("alice".to_string()));

        clear_session_env();
    }

    #[test]
    #[serial]
    fn detect_session_context_uses_wayland_display_when_session_type_unset() {
        clear_session_env();
        unsafe {
            env::set_var("WAYLAND_DISPLAY", "wayland-0");
            env::set_var("SUDO_UID", "1000");
            env::set_var("SUDO_USER", "alice");
        }

        let exec = ScriptedSessionCommandExecutor::new(
            vec![Ok((true, "active".to_string(), String::new()))],
            vec![],
            true,
        );

        let ctx = detect_session_context_with_executor(&exec).unwrap();

        assert_eq!(ctx.kind, SessionKind::GraphicalUser);
        assert_eq!(ctx.display_manager, Some("display-manager".to_string()));
        assert_eq!(ctx.target_user, Some("alice".to_string()));

        clear_session_env();
    }

    #[test]
    fn prompt_session_kill_confirmation_yes_flag_bypasses_validation() {
        let ctx = SessionContext {
            kind: SessionKind::Tty,
            session_id: None,
            display_manager: None,
            target_uid: None,
            target_user: None,
            logind_available: false,
        };

        assert!(prompt_session_kill_confirmation(&ctx, true).is_ok());
    }

    #[test]
    fn prompt_session_kill_confirmation_requires_graphical_user_session() {
        let ctx = SessionContext {
            kind: SessionKind::Tty,
            session_id: None,
            display_manager: None,
            target_uid: None,
            target_user: None,
            logind_available: false,
        };

        let err = prompt_session_kill_confirmation(&ctx, false).unwrap_err();
        assert!(
            err.to_string()
                .contains("Cannot confirm session kill - not a graphical user session")
        );
    }

    #[test]
    fn prompt_session_kill_confirmation_accepts_y_input() {
        let ctx = SessionContext {
            kind: SessionKind::GraphicalUser,
            session_id: Some("c1".to_string()),
            display_manager: Some("gdm".to_string()),
            target_uid: Some(1000),
            target_user: Some("alice".to_string()),
            logind_available: true,
        };

        let mut reader = std::io::Cursor::new("y\n");
        assert!(prompt_session_kill_confirmation_with_reader(&ctx, false, &mut reader).is_ok());
    }

    #[test]
    fn prompt_session_kill_confirmation_accepts_yes_input() {
        let ctx = SessionContext {
            kind: SessionKind::GraphicalUser,
            session_id: Some("c1".to_string()),
            display_manager: Some("gdm".to_string()),
            target_uid: Some(1000),
            target_user: Some("alice".to_string()),
            logind_available: true,
        };

        let mut reader = std::io::Cursor::new("yes\n");
        assert!(prompt_session_kill_confirmation_with_reader(&ctx, false, &mut reader).is_ok());
    }

    #[test]
    fn prompt_session_kill_confirmation_rejects_n_input() {
        let ctx = SessionContext {
            kind: SessionKind::GraphicalUser,
            session_id: Some("c1".to_string()),
            display_manager: Some("gdm".to_string()),
            target_uid: Some(1000),
            target_user: Some("alice".to_string()),
            logind_available: true,
        };

        let mut reader = std::io::Cursor::new("n\n");
        let err =
            prompt_session_kill_confirmation_with_reader(&ctx, false, &mut reader).unwrap_err();
        assert!(
            err.to_string()
                .contains("User declined session kill confirmation")
        );
    }

    #[test]
    fn prompt_session_kill_confirmation_rejects_empty_input() {
        let ctx = SessionContext {
            kind: SessionKind::GraphicalUser,
            session_id: Some("c1".to_string()),
            display_manager: Some("gdm".to_string()),
            target_uid: Some(1000),
            target_user: Some("alice".to_string()),
            logind_available: true,
        };

        let mut reader = std::io::Cursor::new("\n");
        let err =
            prompt_session_kill_confirmation_with_reader(&ctx, false, &mut reader).unwrap_err();
        assert!(
            err.to_string()
                .contains("User declined session kill confirmation")
        );
    }

    #[test]
    fn prompt_session_kill_confirmation_case_insensitive() {
        let ctx = SessionContext {
            kind: SessionKind::GraphicalUser,
            session_id: Some("c1".to_string()),
            display_manager: Some("gdm".to_string()),
            target_uid: Some(1000),
            target_user: Some("alice".to_string()),
            logind_available: true,
        };

        let mut reader = std::io::Cursor::new("Y\n");
        assert!(prompt_session_kill_confirmation_with_reader(&ctx, false, &mut reader).is_ok());

        let mut reader = std::io::Cursor::new("YES\n");
        assert!(prompt_session_kill_confirmation_with_reader(&ctx, false, &mut reader).is_ok());
    }

    #[test]
    fn kill_graphical_session_rejects_non_graphical_session() {
        let ctx = SessionContext {
            kind: SessionKind::Tty,
            session_id: None,
            display_manager: None,
            target_uid: None,
            target_user: None,
            logind_available: false,
        };
        let exec = MockSessionCommandExecutor::new(true, true, true);

        let err = kill_graphical_session_with_executor(&ctx, &exec).unwrap_err();
        assert!(
            err.to_string()
                .contains("Not running in a graphical user session")
        );
    }

    #[test]
    fn wait_for_user_manager_exit_returns_true_when_unit_is_inactive() {
        let exec = ScriptedSessionCommandExecutor::new(
            vec![Ok((false, "inactive".to_string(), String::new()))],
            vec![],
            true,
        );

        let exited = wait_for_user_manager_exit(&exec, 1000, Duration::from_millis(1)).unwrap();

        assert!(exited);
    }

    #[test]
    fn wait_for_user_manager_exit_returns_false_after_timeout() {
        let exec = ScriptedSessionCommandExecutor::new(
            vec![
                Ok((true, "active".to_string(), String::new())),
                Ok((true, "active".to_string(), String::new())),
            ],
            vec![],
            true,
        );

        let exited = wait_for_user_manager_exit(&exec, 1000, Duration::from_millis(1)).unwrap();

        assert!(!exited);
    }

    #[test]
    fn wait_for_user_manager_exit_propagates_systemctl_error() {
        let exec = ScriptedSessionCommandExecutor::new(
            vec![Err(NailsError::IoError(std::io::Error::other(
                "systemctl failed",
            )))],
            vec![],
            true,
        );

        assert!(wait_for_user_manager_exit(&exec, 1000, Duration::from_millis(1)).is_err());
    }

    #[test]
    fn wait_for_user_manager_exit_retries_until_inactive() {
        let exec = RecordingScriptedSessionCommandExecutor::new(
            vec![
                Ok((true, "active".to_string(), String::new())),
                Ok((false, "inactive".to_string(), String::new())),
            ],
            vec![],
            true,
        );

        let exited = wait_for_user_manager_exit(&exec, 1000, Duration::from_millis(500)).unwrap();

        assert!(exited);
        assert_eq!(exec.systemctl_calls().len(), 2);
    }

    #[test]
    fn wait_for_user_manager_exit_treats_non_active_success_output_as_exited() {
        let exec = ScriptedSessionCommandExecutor::new(
            vec![Ok((true, "failed".to_string(), String::new()))],
            vec![],
            true,
        );

        let exited = wait_for_user_manager_exit(&exec, 1000, Duration::from_millis(1)).unwrap();

        assert!(exited);
    }

    #[test]
    fn restart_display_manager_returns_error_when_start_fails() {
        let exec = ScriptedSessionCommandExecutor::new(
            vec![Ok((false, String::new(), "boom".to_string()))],
            vec![],
            true,
        );

        let err = restart_display_manager_with_executor("display-manager", &exec).unwrap_err();
        assert!(
            err.to_string()
                .contains("Failed to start display manager display-manager: boom")
        );
    }

    #[test]
    fn restart_display_manager_retries_until_service_becomes_active() {
        let exec = RecordingScriptedSessionCommandExecutor::new(
            vec![
                Ok((true, String::new(), String::new())),
                Ok((false, "inactive".to_string(), String::new())),
                Ok((true, "active".to_string(), String::new())),
            ],
            vec![],
            true,
        );

        assert!(restart_display_manager_with_executor("display-manager", &exec).is_ok());
        assert_eq!(
            exec.systemctl_calls(),
            vec![
                vec!["start".to_string(), "display-manager".to_string()],
                vec!["is-active".to_string(), "display-manager".to_string()],
                vec!["is-active".to_string(), "display-manager".to_string()],
            ]
        );
    }

    #[test]
    fn restart_display_manager_propagates_is_active_error_after_start() {
        let exec = ScriptedSessionCommandExecutor::new(
            vec![
                Ok((true, String::new(), String::new())),
                Err(NailsError::IoError(std::io::Error::other(
                    "systemctl failed",
                ))),
            ],
            vec![],
            true,
        );

        let err = restart_display_manager_with_executor("display-manager", &exec).unwrap_err();
        assert!(err.to_string().contains("systemctl failed"));
    }

    #[test]
    fn restart_user_manager_returns_error_when_user_service_fails() {
        let exec = ScriptedSessionCommandExecutor::new(
            vec![
                Ok((true, String::new(), String::new())),
                Ok((false, String::new(), "boom".to_string())),
            ],
            vec![],
            true,
        );

        let err = restart_user_manager_with_executor(1000, &exec).unwrap_err();
        assert!(
            err.to_string()
                .contains("Failed to start user manager user@1000.service: boom")
        );
    }

    #[test]
    fn restart_user_manager_succeeds_even_if_runtime_dir_start_fails() {
        let exec = ScriptedSessionCommandExecutor::new(
            vec![
                Err(NailsError::IoError(std::io::Error::other(
                    "runtime-dir failed",
                ))),
                Ok((true, String::new(), String::new())),
            ],
            vec![],
            true,
        );

        assert!(restart_user_manager_with_executor(1000, &exec).is_ok());
    }

    #[test]
    fn restart_user_manager_starts_runtime_service_before_user_service() {
        let exec = RecordingScriptedSessionCommandExecutor::new(
            vec![
                Ok((true, String::new(), String::new())),
                Ok((true, String::new(), String::new())),
            ],
            vec![],
            true,
        );

        assert!(restart_user_manager_with_executor(1000, &exec).is_ok());
        assert_eq!(
            exec.systemctl_calls(),
            vec![
                vec![
                    "start".to_string(),
                    "user-runtime-dir@1000.service".to_string()
                ],
                vec!["start".to_string(), "user@1000.service".to_string()],
            ]
        );
    }

    #[test]
    fn restart_display_manager_uses_systemctl() {
        let exec = MockSessionCommandExecutor::new(true, true, true);
        let res = restart_display_manager_with_executor("display-manager", &exec);
        assert!(res.is_ok());
    }
}
