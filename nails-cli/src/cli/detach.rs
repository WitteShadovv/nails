use std::env;
use std::fs::File;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use nails_core::{NailsError, SessionContext, SessionKind, detect_session_context};

/// Detach using systemd-run to create a transient service in system.slice.
///
/// Creates a proper one-shot service that runs independently of any user session.
pub fn maybe_detach_for_session_kill(
    kill_session: bool,
    args: &[OsString],
    session_ctx: Option<&SessionContext>,
) -> Result<(), NailsError> {
    // Testing override: allow tests to bypass actual detaching/spawn.
    if env::var_os("NAILS_SKIP_DETACH").is_some() {
        return Ok(());
    }

    // Only detach when --kill-session is requested and we look like a GUI session.
    if !kill_session {
        return Ok(());
    }

    // Prevent recursion - if already detached, just continue.
    if env::var_os("NAILS_DETACHED").is_some() {
        eprintln!("DEBUG: Already detached, continuing...");
        return Ok(());
    }

    // Allow integration tests or users to force detaching for safety.
    let force_detach = env::var_os("NAILS_FORCE_DETACH").is_some();

    if !force_detach {
        // Prefer logind-aware detection to avoid detaching from TTY/SSH.
        if let Some(ctx) = session_ctx {
            if ctx.kind != SessionKind::GraphicalUser {
                return Ok(());
            }
        } else if let Ok(ctx) = detect_session_context() {
            if ctx.kind != SessionKind::GraphicalUser {
                return Ok(());
            }
        } else {
            // If detection fails, fall back to env markers.
            if env::var_os("DISPLAY").is_none() && env::var_os("WAYLAND_DISPLAY").is_none() {
                return Ok(());
            }
        }
    }

    // Create log file for detached service
    let (_, log_path) = open_detached_log().map_err(|e| {
        NailsError::InvalidState(format!("Failed to create log file: {}", e))
    })?;

    // Get the current binary path
    let exe_path = std::env::current_exe().map_err(|e| {
        NailsError::InvalidState(format!("Failed to get current executable path: {}", e))
    })?;

    // Generate unique unit name
    let unit_name = format!("nails-activate-{}.service", std::process::id());

    // Build systemd-run command
    // Using no --scope flag creates a proper transient service
    let mut cmd = Command::new("systemd-run");
    cmd.arg("--unit").arg(&unit_name)
        .arg("--slice=system.slice")
        .arg("--same-dir") // Keep current working directory
        .arg("--collect") // Clean up unit after it finishes
        .arg("--quiet");

    // Set environment variables for the service
    cmd.arg("--setenv=NAILS_DETACHED=1");
    cmd.arg("--setenv=XDG_SESSION_ID="); // Clear session tracking

    // Set PATH to include NixOS binaries (nixos-rebuild, etc.)
    cmd.arg("--setenv=PATH=/run/current-system/sw/bin:/run/wrappers/bin:/usr/bin:/bin");

    // Capture and pass through all NIX_* environment variables from current environment
    // This ensures nixos-rebuild has all the Nix configuration it needs
    for (key, value) in env::vars() {
        if key.starts_with("NIX_") {
            cmd.arg(format!("--setenv={}={}", key, value));
        }
    }

    if let Some(ctx) = session_ctx {
        if ctx.kind == SessionKind::GraphicalUser {
            if let Some(ref session_id) = ctx.session_id {
                cmd.arg(format!("--setenv=NAILS_SESSION_ID={}", session_id));
            }
            if let Some(ref dm) = ctx.display_manager {
                cmd.arg(format!("--setenv=NAILS_DISPLAY_MANAGER={}", dm));
            }
            if let Some(uid) = ctx.target_uid {
                cmd.arg(format!("--setenv=NAILS_TARGET_UID={}", uid));
            }
            if let Some(ref user) = ctx.target_user {
                cmd.arg(format!("--setenv=NAILS_TARGET_USER={}", user));
            }
            cmd.arg(format!(
                "--setenv=NAILS_LOGIND_AVAILABLE={}",
                if ctx.logind_available { "1" } else { "0" }
            ));
        }
    }

    // Redirect output to log file
    cmd.arg(format!("--property=StandardOutput=append:{}", log_path.display()));
    cmd.arg(format!("--property=StandardError=append:{}", log_path.display()));

    // Add the command to execute
    cmd.arg("--");
    cmd.arg(&exe_path);
    cmd.args(args.iter().skip(1));

    // Execute systemd-run
    let output = cmd.output().map_err(|e| {
        NailsError::InvalidState(format!("Failed to execute systemd-run: {}", e))
    })?;

    if !output.status.success() {
        return Err(NailsError::InvalidState(format!(
            "systemd-run failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    eprintln!(
        "Detached to background via systemd transient service. Logs: {}",
        log_path.display()
    );
    eprintln!("Handoff complete; activation continues in background.");

    std::process::exit(0);
}

fn open_detached_log() -> io::Result<(File, PathBuf)> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let path = PathBuf::from(format!(
        "/tmp/nails-activate-{}-{}.log",
        std::process::id(),
        ts
    ));
    let file = File::create(&path)?;
    Ok((file, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn with_env<K: AsRef<str>, V: AsRef<str>, F: FnOnce()>(key: K, val: V, f: F) {
        unsafe {
            env::set_var(key.as_ref(), val.as_ref());
        }
        f();
        unsafe {
            env::remove_var(key.as_ref());
        }
    }

    #[test]
    fn does_nothing_when_kill_session_false() {
        with_env("NAILS_SKIP_DETACH", "1", || {
            unsafe { env::set_var("DISPLAY", ":0") };
            let res = maybe_detach_for_session_kill(false, &[OsString::from("nails")], None);
            unsafe { env::remove_var("DISPLAY") };
            assert!(res.is_ok());
        });
    }

    #[test]
    fn does_nothing_without_graphical_env() {
        with_env("NAILS_SKIP_DETACH", "1", || {
            unsafe { env::remove_var("DISPLAY") };
            unsafe { env::remove_var("WAYLAND_DISPLAY") };
            let res = maybe_detach_for_session_kill(true, &[OsString::from("nails")], None);
            assert!(res.is_ok());
        });
    }

    #[test]
    fn skips_when_already_detached() {
        with_env("NAILS_SKIP_DETACH", "1", || {
            unsafe { env::set_var("DISPLAY", ":1") };
            unsafe { env::set_var("NAILS_DETACHED", "1") };
            let res = maybe_detach_for_session_kill(true, &[OsString::from("nails")], None);
            unsafe { env::remove_var("DISPLAY") };
            unsafe { env::remove_var("NAILS_DETACHED") };
            assert!(res.is_ok());
        });
    }
}
