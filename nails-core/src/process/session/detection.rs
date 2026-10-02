//! Session detection — detecting active sessions, display servers, and session context

use crate::Result;
use crate::constants::{
    ENV_DISPLAY_MANAGER, ENV_LOGIND_AVAILABLE, ENV_SESSION_ID, ENV_TARGET_UID, ENV_TARGET_USER,
};
use nix::unistd::{User, getuid};
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
    let logind_available = match env::var(ENV_LOGIND_AVAILABLE) {
        Ok(val) => val != "0",
        Err(_) => executor.loginctl_available(),
    };
    let session_id = env::var("XDG_SESSION_ID").ok();
    let override_session_id = env::var(ENV_SESSION_ID).ok();
    let override_dm = env::var(ENV_DISPLAY_MANAGER).ok();
    let override_uid = env::var(ENV_TARGET_UID)
        .ok()
        .and_then(|v| v.parse::<u32>().ok());
    let override_user = env::var(ENV_TARGET_USER).ok();

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

        // GraphicalUser requires a valid target_uid; fall back to GraphicalRoot if missing
        let kind = if override_uid.is_some() {
            SessionKind::GraphicalUser
        } else {
            tracing::warn!(
                "Override environment present but target UID is missing or invalid; \
                 falling back to GraphicalRoot"
            );
            SessionKind::GraphicalRoot
        };

        return Ok(SessionContext {
            kind,
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

    let (target_uid, target_user) = resolve_target_identity();

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

/// Resolve the operator this session acts on behalf of.
///
/// Prefers the shared [`crate::TargetUser`] resolver so detection agrees with
/// every other subsystem on who the operator is and honours the full precedence
/// of escalation variables. When no escalation context identifies an operator,
/// NAILS is running directly as the user: fall back to the current account,
/// treating root as "no target user" so a root session is never reported as a
/// graphical user.
fn resolve_target_identity() -> (Option<u32>, Option<String>) {
    if let Ok(user) = crate::TargetUser::resolve() {
        return (Some(user.uid), Some(user.name));
    }

    let uid = getuid();
    if uid.is_root() {
        (None, None)
    } else {
        let name = User::from_uid(uid).ok().flatten().map(|u| u.name);
        (Some(uid.as_raw()), name)
    }
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
        let mut env = cleared_session_env();
        env.set("SSH_CONNECTION", "1 2 3 4")
            .set("NAILS_LOGIND_AVAILABLE", "0");

        let exec = MockSessionCommandExecutor::new(true, true, true);

        let ctx = detect_session_context_with_executor(&exec).unwrap();

        assert_eq!(ctx.kind, SessionKind::Ssh);
        assert_eq!(ctx.display_manager, None);
        assert_eq!(ctx.target_uid, None);
        assert!(!ctx.logind_available);
    }

    #[test]
    #[serial]
    fn detect_session_context_uses_override_values() {
        let mut env = cleared_session_env();
        env.set("NAILS_SESSION_ID", "c2")
            .set("NAILS_DISPLAY_MANAGER", "gdm")
            .set("NAILS_TARGET_UID", "1000")
            .set("NAILS_TARGET_USER", "alice");

        let exec = MockSessionCommandExecutor::new(false, true, true);

        let ctx = detect_session_context_with_executor(&exec).unwrap();

        assert_eq!(ctx.kind, SessionKind::GraphicalUser);
        assert_eq!(ctx.session_id, Some("c2".to_string()));
        assert_eq!(ctx.display_manager, Some("gdm".to_string()));
        assert_eq!(ctx.target_uid, Some(1000));
        assert_eq!(ctx.target_user, Some("alice".to_string()));
    }

    #[test]
    #[serial]
    fn detect_session_context_detects_tty_when_not_graphical() {
        let mut env = cleared_session_env();
        env.set("XDG_SESSION_TYPE", "tty")
            .set("NAILS_LOGIND_AVAILABLE", "0");

        let exec = MockSessionCommandExecutor::new(true, true, true);

        let ctx = detect_session_context_with_executor(&exec).unwrap();

        assert_eq!(ctx.kind, SessionKind::Tty);
        assert_eq!(ctx.display_manager, None);
        assert!(!ctx.logind_available);
    }

    #[test]
    #[serial]
    fn detect_session_context_detects_graphical_user_and_display_manager() {
        // Drive the shared resolver through SUDO_UID pointing at a real passwd
        // entry — the current account — so the test is hermetic across hosts.
        let me = current_user();
        let mut env = cleared_session_env();
        env.set("DISPLAY", ":0").set("SUDO_UID", &me.uid);

        let exec = ScriptedSessionCommandExecutor::new(
            vec![Ok((true, "active".to_string(), String::new()))],
            vec![],
            true,
        );

        let ctx = detect_session_context_with_executor(&exec).unwrap();

        assert_eq!(ctx.kind, SessionKind::GraphicalUser);
        assert_eq!(ctx.display_manager, Some("display-manager".to_string()));
        assert_eq!(ctx.target_uid, Some(me.uid.parse::<u32>().unwrap()));
        assert_eq!(ctx.target_user, Some(me.name));
    }

    #[test]
    #[serial]
    fn detect_session_context_honors_logind_override() {
        let mut env = cleared_session_env();
        env.set("XDG_SESSION_TYPE", "tty")
            .set("NAILS_LOGIND_AVAILABLE", "0");

        let exec = MockSessionCommandExecutor::new(true, true, true);

        let ctx = detect_session_context_with_executor(&exec).unwrap();

        assert!(!ctx.logind_available);
    }

    #[test]
    #[serial]
    fn detect_session_context_uses_executor_logind_availability_when_not_overridden() {
        let mut env = cleared_session_env();
        env.set("XDG_SESSION_TYPE", "tty");

        let exec = MockSessionCommandExecutor::new(true, true, true);

        let ctx = detect_session_context_with_executor(&exec).unwrap();

        assert_eq!(ctx.kind, SessionKind::Tty);
        assert!(ctx.logind_available);
    }

    #[test]
    #[serial]
    fn detect_session_context_uses_xdg_session_id_when_override_missing() {
        let mut env = cleared_session_env();
        env.set("XDG_SESSION_ID", "c7")
            .set("NAILS_TARGET_UID", "1000")
            .set("NAILS_DISPLAY_MANAGER", "gdm");

        let exec = MockSessionCommandExecutor::new(true, true, true);

        let ctx = detect_session_context_with_executor(&exec).unwrap();

        assert_eq!(ctx.session_id, Some("c7".to_string()));
        assert_eq!(ctx.display_manager, Some("gdm".to_string()));
        assert_eq!(ctx.target_uid, Some(1000));
    }

    #[test]
    #[serial]
    fn detect_session_context_ignores_invalid_override_target_uid() {
        let mut env = cleared_session_env();
        env.set("NAILS_SESSION_ID", "c2")
            .set("NAILS_TARGET_UID", "not-a-number")
            .set("NAILS_TARGET_USER", "alice");

        let exec = MockSessionCommandExecutor::new(true, true, true);

        let ctx = detect_session_context_with_executor(&exec).unwrap();

        // Invalid UID means we fall back to GraphicalRoot, not GraphicalUser
        assert_eq!(ctx.kind, SessionKind::GraphicalRoot);
        assert_eq!(ctx.session_id, Some("c2".to_string()));
        assert_eq!(ctx.target_uid, None);
        assert_eq!(ctx.target_user, Some("alice".to_string()));
    }

    #[test]
    #[serial]
    fn detect_session_context_detects_dm_when_override_missing() {
        let mut env = cleared_session_env();
        env.set("NAILS_SESSION_ID", "c2")
            .set("NAILS_TARGET_UID", "1000")
            .set("NAILS_TARGET_USER", "alice");

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
    }

    #[test]
    #[serial]
    fn detect_session_context_override_without_uid_returns_graphical_root() {
        let mut env = cleared_session_env();
        // No NAILS_TARGET_UID set
        env.set("NAILS_SESSION_ID", "c5")
            .set("NAILS_DISPLAY_MANAGER", "sddm");

        let exec = MockSessionCommandExecutor::new(true, true, true);
        let ctx = detect_session_context_with_executor(&exec).unwrap();

        // Without a valid target UID, must NOT be GraphicalUser
        assert_eq!(ctx.kind, SessionKind::GraphicalRoot);
        assert_eq!(ctx.target_uid, None);
        assert_eq!(ctx.session_id, Some("c5".to_string()));
        assert_eq!(ctx.display_manager, Some("sddm".to_string()));
    }

    #[test]
    #[serial]
    fn detect_session_context_uses_wayland_display_when_session_type_unset() {
        let me = current_user();
        let mut env = cleared_session_env();
        env.set("WAYLAND_DISPLAY", "wayland-0")
            .set("SUDO_UID", &me.uid);

        let exec = ScriptedSessionCommandExecutor::new(
            vec![Ok((true, "active".to_string(), String::new()))],
            vec![],
            true,
        );

        let ctx = detect_session_context_with_executor(&exec).unwrap();

        assert_eq!(ctx.kind, SessionKind::GraphicalUser);
        assert_eq!(ctx.display_manager, Some("display-manager".to_string()));
        assert_eq!(ctx.target_user, Some(me.name));
    }

    /// The account running the test suite, as a (uid-string, name) pair, used to
    /// drive the shared resolver against a passwd entry that is guaranteed to
    /// exist on whatever host the tests run on.
    struct CurrentUser {
        uid: String,
        name: String,
    }

    fn current_user() -> CurrentUser {
        let uid = getuid();
        let entry = User::from_uid(uid)
            .ok()
            .flatten()
            .expect("the account running the tests must have a passwd entry");
        CurrentUser {
            uid: uid.as_raw().to_string(),
            name: entry.name,
        }
    }
}
