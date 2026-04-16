//! Session detection — detecting active sessions, display servers, and session context

use crate::{Result, obfuscate};
use nix::unistd::{Uid, User, getuid};
use std::env;

#[cfg(not(test))]
use super::types::RealSessionCommandExecutor;
use super::types::{SessionCommandExecutor, SessionContext, SessionKind};

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
        // If display manager override wasn't provided, try to detect it
        let display_manager =
            override_dm.or_else(|| detect_display_manager(executor).ok().flatten());

        return Ok(SessionContext {
            kind: SessionKind::GraphicalUser,
            session_id: override_session_id.or(session_id),
            display_manager,
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
pub(super) fn detect_display_manager<E: SessionCommandExecutor>(
    executor: &E,
) -> Result<Option<String>> {
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

#[cfg(test)]
mod tests {
    use super::super::tests_common::*;
    use super::*;
    use serial_test::serial;
    use std::env;

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
                Err(crate::NailsError::IoError(std::io::Error::other(
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
    fn detect_session_context_detects_dm_when_override_missing() {
        clear_session_env();
        unsafe {
            env::set_var("NAILS_SESSION_ID", "c2");
            env::set_var("NAILS_TARGET_UID", "1000");
            env::set_var("NAILS_TARGET_USER", "alice");
        }

        let exec = ScriptedSessionCommandExecutor::new(
            vec![Ok((true, "active".to_string(), String::new()))],
            vec![],
            true,
        );

        let ctx = detect_session_context_with_executor(&exec).unwrap();

        assert_eq!(ctx.kind, SessionKind::GraphicalUser);
        assert_eq!(ctx.session_id, Some("c2".to_string()));
        assert_eq!(ctx.display_manager, Some("display-manager".to_string()));
        assert_eq!(ctx.target_uid, Some(1000));
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
}
