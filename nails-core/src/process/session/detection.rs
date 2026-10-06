// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Session detection — detecting active sessions, display servers, and session context

use crate::Result;
use crate::RuntimeEnv;
use nix::unistd::{User, getuid};

use super::types::{SessionCommandExecutor, SessionContext, SessionKind};

/// Detect the current session context, running its probes through `executor`
/// and reading every environment value off the startup snapshot `env`.
///
/// Production passes [`RealSessionCommandExecutor`](super::types::RealSessionCommandExecutor),
/// which shells out to `loginctl`/`systemctl`, and the [`RuntimeEnv`](crate::RuntimeEnv)
/// `main` captured once; tests pass a scripted executor and a built `RuntimeEnv`,
/// so the same code path is exercised in both without a build-time fork and
/// without mutating the shared process environment.
pub fn detect_session_context<E: SessionCommandExecutor>(
    executor: &E,
    env: &RuntimeEnv,
) -> Result<SessionContext> {
    let logind_available = match env.nails_logind_available.as_deref() {
        Some(val) => val != "0",
        None => executor.loginctl_available(),
    };
    let session_id = env.xdg_session_id.clone();
    let override_session_id = env.nails_session_id.clone();
    let override_dm = env.nails_display_manager.clone();
    let override_uid = env
        .nails_target_uid
        .as_deref()
        .and_then(|v| v.parse::<u32>().ok());
    let override_user = env.nails_target_user.clone();

    // Check for SSH first
    if env.ssh_tty.is_some() || env.ssh_connection.is_some() {
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
    let session_type = env.xdg_session_type.clone();
    let has_display = env.display.is_some();
    let has_wayland = env.wayland_display.is_some();

    let is_graphical = match session_type.as_deref() {
        Some("wayland") | Some("x11") => true,
        Some("tty") => false,
        _ => has_display || has_wayland,
    };

    let (target_uid, target_user) = resolve_target_identity(env);

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
fn resolve_target_identity(env: &RuntimeEnv) -> (Option<u32>, Option<String>) {
    if let Ok(user) = crate::TargetUser::resolve_with(env) {
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

/// Detect which display manager is currently active.
///
/// The generic `display-manager.service` alias is probed first; when it is not
/// active the per-host fallback list ([`host_display_manager_units`]) is tried in
/// order. The list is platform data so Debian/Ubuntu's `gdm3` is probed there.
pub(super) fn detect_display_manager<E: SessionCommandExecutor>(
    executor: &E,
) -> Result<Option<String>> {
    detect_display_manager_in(executor, executor.display_manager_units())
}

/// Probe the generic alias, then each unit in `fallback_units`, returning the
/// first active display manager. Split out from [`detect_display_manager`] so the
/// fallback list can be driven directly in tests.
fn detect_display_manager_in<E: SessionCommandExecutor>(
    executor: &E,
    fallback_units: &[&str],
) -> Result<Option<String>> {
    if let Ok((true, stdout, _)) = executor.execute_systemctl(&["is-active", "display-manager"])
        && stdout.trim() == "active"
    {
        return Ok(Some("display-manager".to_string()));
    }

    for dm in fallback_units {
        if let Ok((true, stdout, _)) = executor.execute_systemctl(&["is-active", dm])
            && stdout.trim() == "active"
        {
            return Ok(Some((*dm).to_string()));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::super::tests_common::*;
    use super::*;

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
                Err(crate::NailsError::io(
                    "systemctl",
                    std::io::Error::other("display-manager failed"),
                )),
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
    fn detect_display_manager_consumes_platform_fallback_list() {
        use crate::filesystem::MockFilesystem;
        use crate::platform::{FhsPlatform, Platform};

        // The fallback list is platform data: the Debian/Ubuntu backend names
        // `gdm3` and probes it before the upstream `gdm` unit.
        let units = Platform::<MockFilesystem>::display_manager_units(&FhsPlatform);
        assert_eq!(units.first().copied(), Some("gdm3"));

        // Alias inactive, then `gdm3` active: the probe must use the platform's
        // first fallback unit verbatim, not a hard-coded `gdm`.
        let exec = RecordingScriptedSessionCommandExecutor::new(
            vec![
                Ok((false, "inactive".to_string(), String::new())),
                Ok((true, "active".to_string(), String::new())),
            ],
            vec![],
            true,
        );

        let dm = detect_display_manager_in(&exec, units).unwrap();

        assert_eq!(dm, Some("gdm3".to_string()));
        assert_eq!(
            exec.systemctl_calls(),
            vec![
                vec!["is-active".to_string(), "display-manager".to_string()],
                vec!["is-active".to_string(), "gdm3".to_string()],
            ]
        );
    }

    #[test]
    fn detect_session_context_detects_ssh() {
        let env = RuntimeEnv {
            ssh_connection: Some("1 2 3 4".to_string()),
            nails_logind_available: Some("0".to_string()),
            ..RuntimeEnv::empty()
        };

        let exec = MockSessionCommandExecutor::new(true, true, true);

        let ctx = detect_session_context(&exec, &env).unwrap();

        assert_eq!(ctx.kind, SessionKind::Ssh);
        assert_eq!(ctx.display_manager, None);
        assert_eq!(ctx.target_uid, None);
        assert!(!ctx.logind_available);
    }

    #[test]
    fn detect_session_context_uses_override_values() {
        let env = RuntimeEnv {
            nails_session_id: Some("c2".to_string()),
            nails_display_manager: Some("gdm".to_string()),
            nails_target_uid: Some("1000".to_string()),
            nails_target_user: Some("alice".to_string()),
            ..RuntimeEnv::empty()
        };

        let exec = MockSessionCommandExecutor::new(false, true, true);

        let ctx = detect_session_context(&exec, &env).unwrap();

        assert_eq!(ctx.kind, SessionKind::GraphicalUser);
        assert_eq!(ctx.session_id, Some("c2".to_string()));
        assert_eq!(ctx.display_manager, Some("gdm".to_string()));
        assert_eq!(ctx.target_uid, Some(1000));
        assert_eq!(ctx.target_user, Some("alice".to_string()));
    }

    #[test]
    fn detect_session_context_detects_tty_when_not_graphical() {
        let env = RuntimeEnv {
            xdg_session_type: Some("tty".to_string()),
            nails_logind_available: Some("0".to_string()),
            ..RuntimeEnv::empty()
        };

        let exec = MockSessionCommandExecutor::new(true, true, true);

        let ctx = detect_session_context(&exec, &env).unwrap();

        assert_eq!(ctx.kind, SessionKind::Tty);
        assert_eq!(ctx.display_manager, None);
        assert!(!ctx.logind_available);
    }

    #[test]
    fn detect_session_context_detects_graphical_user_and_display_manager() {
        // Drive the shared resolver through SUDO_UID pointing at a real passwd
        // entry — the current account — so the test is hermetic across hosts.
        let me = current_user();
        let env = RuntimeEnv::empty()
            .with_display(":0")
            .with_sudo_uid(me.uid.clone());

        let exec = ScriptedSessionCommandExecutor::new(
            vec![Ok((true, "active".to_string(), String::new()))],
            vec![],
            true,
        );

        let ctx = detect_session_context(&exec, &env).unwrap();

        assert_eq!(ctx.kind, SessionKind::GraphicalUser);
        assert_eq!(ctx.display_manager, Some("display-manager".to_string()));
        assert_eq!(ctx.target_uid, Some(me.uid.parse::<u32>().unwrap()));
        assert_eq!(ctx.target_user, Some(me.name));
    }

    #[test]
    fn detect_session_context_honors_logind_override() {
        let env = RuntimeEnv {
            xdg_session_type: Some("tty".to_string()),
            nails_logind_available: Some("0".to_string()),
            ..RuntimeEnv::empty()
        };

        let exec = MockSessionCommandExecutor::new(true, true, true);

        let ctx = detect_session_context(&exec, &env).unwrap();

        assert!(!ctx.logind_available);
    }

    #[test]
    fn detect_session_context_uses_executor_logind_availability_when_not_overridden() {
        let env = RuntimeEnv {
            xdg_session_type: Some("tty".to_string()),
            ..RuntimeEnv::empty()
        };

        let exec = MockSessionCommandExecutor::new(true, true, true);

        let ctx = detect_session_context(&exec, &env).unwrap();

        assert_eq!(ctx.kind, SessionKind::Tty);
        assert!(ctx.logind_available);
    }

    #[test]
    fn detect_session_context_uses_xdg_session_id_when_override_missing() {
        let env = RuntimeEnv {
            xdg_session_id: Some("c7".to_string()),
            nails_target_uid: Some("1000".to_string()),
            nails_display_manager: Some("gdm".to_string()),
            ..RuntimeEnv::empty()
        };

        let exec = MockSessionCommandExecutor::new(true, true, true);

        let ctx = detect_session_context(&exec, &env).unwrap();

        assert_eq!(ctx.session_id, Some("c7".to_string()));
        assert_eq!(ctx.display_manager, Some("gdm".to_string()));
        assert_eq!(ctx.target_uid, Some(1000));
    }

    #[test]
    fn detect_session_context_ignores_invalid_override_target_uid() {
        let env = RuntimeEnv {
            nails_session_id: Some("c2".to_string()),
            nails_target_uid: Some("not-a-number".to_string()),
            nails_target_user: Some("alice".to_string()),
            ..RuntimeEnv::empty()
        };

        let exec = MockSessionCommandExecutor::new(true, true, true);

        let ctx = detect_session_context(&exec, &env).unwrap();

        // Invalid UID means we fall back to GraphicalRoot, not GraphicalUser
        assert_eq!(ctx.kind, SessionKind::GraphicalRoot);
        assert_eq!(ctx.session_id, Some("c2".to_string()));
        assert_eq!(ctx.target_uid, None);
        assert_eq!(ctx.target_user, Some("alice".to_string()));
    }

    #[test]
    fn detect_session_context_detects_dm_when_override_missing() {
        let env = RuntimeEnv {
            nails_session_id: Some("c2".to_string()),
            nails_target_uid: Some("1000".to_string()),
            nails_target_user: Some("alice".to_string()),
            ..RuntimeEnv::empty()
        };

        let exec = ScriptedSessionCommandExecutor::new(
            vec![Ok((true, "active".to_string(), String::new()))],
            vec![],
            true,
        );

        let ctx = detect_session_context(&exec, &env).unwrap();

        assert_eq!(ctx.kind, SessionKind::GraphicalUser);
        assert_eq!(ctx.session_id, Some("c2".to_string()));
        assert_eq!(ctx.display_manager, Some("display-manager".to_string()));
        assert_eq!(ctx.target_uid, Some(1000));
        assert_eq!(ctx.target_user, Some("alice".to_string()));
    }

    #[test]
    fn detect_session_context_override_without_uid_returns_graphical_root() {
        // No NAILS_TARGET_UID set.
        let env = RuntimeEnv {
            nails_session_id: Some("c5".to_string()),
            nails_display_manager: Some("sddm".to_string()),
            ..RuntimeEnv::empty()
        };

        let exec = MockSessionCommandExecutor::new(true, true, true);
        let ctx = detect_session_context(&exec, &env).unwrap();

        // Without a valid target UID, must NOT be GraphicalUser
        assert_eq!(ctx.kind, SessionKind::GraphicalRoot);
        assert_eq!(ctx.target_uid, None);
        assert_eq!(ctx.session_id, Some("c5".to_string()));
        assert_eq!(ctx.display_manager, Some("sddm".to_string()));
    }

    #[test]
    fn detect_session_context_uses_wayland_display_when_session_type_unset() {
        let me = current_user();
        let env = RuntimeEnv::empty()
            .with_wayland_display("wayland-0")
            .with_sudo_uid(me.uid.clone());

        let exec = ScriptedSessionCommandExecutor::new(
            vec![Ok((true, "active".to_string(), String::new()))],
            vec![],
            true,
        );

        let ctx = detect_session_context(&exec, &env).unwrap();

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
