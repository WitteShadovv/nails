//! Session management — killing sessions, cleanup, restart

use crate::{NailsError, Result};
use std::fs;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(not(test))]
use super::types::RealSessionCommandExecutor;
use super::types::{
    SessionCommandExecutor, SessionContext, SessionKillResult, SessionKind, SessionRestartPlan,
};

/// Prompt user for confirmation before killing graphical session
pub fn prompt_session_kill_confirmation(ctx: &SessionContext, yes_flag: bool) -> Result<()> {
    if !yes_flag && ctx.kind != SessionKind::GraphicalUser {
        return Err(NailsError::InvalidState(
            "Cannot confirm session kill - not a graphical user session".to_string(),
        ));
    }

    if !yes_flag && crate::runtime_safety::should_skip_host_interaction() {
        tracing::debug!(
            session = ?ctx.session_id,
            target_user = ?ctx.target_user,
            "Auto-declining session kill confirmation in test/test-like runtime"
        );
        return Err(NailsError::InvalidState(
            "User declined session kill confirmation in test/test-like runtime".to_string(),
        ));
    }

    prompt_session_kill_confirmation_with_io(
        ctx,
        yes_flag,
        &mut std::io::stdin().lock(),
        &mut std::io::stderr(),
    )
}

/// Prompt user for confirmation before killing graphical session (with injectable I/O)
pub(crate) fn prompt_session_kill_confirmation_with_io<R: std::io::BufRead, W: std::io::Write>(
    ctx: &SessionContext,
    yes_flag: bool,
    reader: &mut R,
    writer: &mut W,
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

    writeln!(writer, "⚠️  This will terminate your graphical session!")?;
    writeln!(
        writer,
        "    All unsaved work in open applications will be LOST."
    )?;
    writeln!(writer)?;
    writeln!(writer, "    The system will:")?;
    writeln!(writer, "    1. Stop display manager ({})", dm)?;
    writeln!(
        writer,
        "    2. Terminate your logind session and user processes"
    )?;
    writeln!(writer, "    3. Mount hidden environment overlays")?;
    writeln!(writer, "    4. Restart display manager and user manager")?;
    writeln!(writer)?;
    writeln!(
        writer,
        "    You will need to log in again after activation."
    )?;
    writeln!(writer)?;

    // Prompt for confirmation
    write!(writer, "    Continue? [y/N]: ")?;
    writer.flush()?;

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
        if executor.execute_kill(*pid, "TERM")? {
            terminated += 1;
        }
    }

    thread::sleep(Duration::from_millis(300));

    let mut force_killed = 0;
    for pid in pids {
        if process_exists(pid) && executor.execute_kill(pid, "KILL")? {
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
mod tests;
