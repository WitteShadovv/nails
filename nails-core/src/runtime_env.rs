// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A single, startup-time snapshot of the process environment NAILS depends on.
//!
//! Historically every subsystem reached into [`std::env`] wherever it needed a
//! value — the shell detector read `SHELL`, the session detector read
//! `XDG_SESSION_TYPE`/`DISPLAY`, the notification dispatcher read `DISPLAY` and
//! `WAYLAND_DISPLAY`, the target-user resolver read the escalation variables,
//! and so on. That spread the environment across the whole crate, made the order
//! in which code ran observable (two reads of `HOME` could disagree if something
//! changed it in between), and forced the tests to mutate the one process
//! environment they all share — the order-dependent races this item removes.
//!
//! [`RuntimeEnv`] replaces that with one read: `nails-cli` `main` builds it once
//! with [`RuntimeEnv::from_process_env`], before anything else runs, and passes
//! it down. Every subsystem reads the value it needs off this struct instead of
//! the live environment, so a value is read exactly once and is identical
//! everywhere it is consulted. Tests construct a [`RuntimeEnv`] with the fields
//! they want set and inject it, instead of mutating the shared process
//! environment.
//!
//! Only the variables NAILS actually reads are captured. The names are the same
//! literals the code used before; the detached-worker and child-process paths
//! (`systemd-run`, `sudo -u`, `notify-send`) still receive exactly the values
//! they did, now sourced from this snapshot.

use crate::constants::{
    ENV_DISABLE_NOTIFICATIONS, ENV_DISPLAY_MANAGER, ENV_LOGIND_AVAILABLE, ENV_SESSION_ID,
    ENV_SYSTEM_PROFILE_PATH, ENV_TARGET_UID, ENV_TARGET_USER,
};
use std::ffi::OsString;
use std::path::PathBuf;

/// Escalation variable names consulted for target-user resolution. These are the
/// standard names a privilege-escalation tool sets; the literals live here and in
/// [`crate::target_user`] only.
const ENV_SUDO_USER: &str = "SUDO_USER";
const ENV_SUDO_UID: &str = "SUDO_UID";
const ENV_PKEXEC_UID: &str = "PKEXEC_UID";
const ENV_DOAS_UID: &str = "DOAS_UID";
const ENV_DOAS_USER: &str = "DOAS_USER";

/// Snapshot of the environment NAILS reads, captured once at startup.
///
/// Every field is the verbatim value of the matching variable at the moment the
/// snapshot was taken, or `None` when the variable was unset. Build it in
/// production with [`Self::from_process_env`]; build it in tests with
/// [`Self::empty`] plus the `with_*` setters, or the field literals directly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeEnv {
    /// `HOME` — the invoking account's home directory.
    pub home: Option<PathBuf>,
    /// `PATH` — the caller's executable search path (used to find `notify-send`
    /// in the operator's own login session).
    pub path: Option<OsString>,
    /// `SHELL` — the caller's login shell, used to detect the shell type.
    pub shell: Option<String>,
    /// `USER` — the invoking account's login name.
    pub user: Option<String>,

    /// `SUDO_USER` — operator login name set by `sudo`.
    pub sudo_user: Option<String>,
    /// `SUDO_UID` — operator uid set by `sudo`.
    pub sudo_uid: Option<String>,
    /// `PKEXEC_UID` — operator uid set by `pkexec`.
    pub pkexec_uid: Option<String>,
    /// `DOAS_UID` — operator uid set by `doas`.
    pub doas_uid: Option<String>,
    /// `DOAS_USER` — operator login name set by `doas`.
    pub doas_user: Option<String>,
    /// `NAILS_TARGET_UID` — operator uid forwarded across the detach boundary.
    pub nails_target_uid: Option<String>,
    /// `NAILS_TARGET_USER` — operator login name forwarded across the detach boundary.
    pub nails_target_user: Option<String>,

    /// `DISPLAY` — X11 display, forwarded to `notify-send`.
    pub display: Option<String>,
    /// `WAYLAND_DISPLAY` — Wayland display, forwarded to `notify-send`.
    pub wayland_display: Option<String>,
    /// `XDG_SESSION_ID` — the logind session id.
    pub xdg_session_id: Option<String>,
    /// `XDG_SESSION_TYPE` — `wayland`/`x11`/`tty`.
    pub xdg_session_type: Option<String>,
    /// `SSH_TTY` — present when the session arrived over SSH.
    pub ssh_tty: Option<String>,
    /// `SSH_CONNECTION` — present when the session arrived over SSH.
    pub ssh_connection: Option<String>,

    /// `NAILS_LOGIND_AVAILABLE` — session-detection override.
    pub nails_logind_available: Option<String>,
    /// `NAILS_SESSION_ID` — session-detection override.
    pub nails_session_id: Option<String>,
    /// `NAILS_DISPLAY_MANAGER` — session-detection override.
    pub nails_display_manager: Option<String>,
    /// `NAILS_DISABLE_NOTIFICATIONS` — suppress desktop notifications when set.
    pub nails_disable_notifications: Option<String>,
    /// `NAILS_SYSTEM_PROFILE_PATH` — overrides the NixOS system profile path.
    pub nails_system_profile_path: Option<OsString>,
}

impl RuntimeEnv {
    /// Read the snapshot from the live process environment. Called once, in
    /// `nails-cli` `main`, before any handler runs.
    #[must_use]
    pub fn from_process_env() -> Self {
        Self {
            home: std::env::var_os("HOME").map(PathBuf::from),
            path: std::env::var_os("PATH"),
            shell: str_var("SHELL"),
            user: str_var("USER"),

            sudo_user: str_var(ENV_SUDO_USER),
            sudo_uid: str_var(ENV_SUDO_UID),
            pkexec_uid: str_var(ENV_PKEXEC_UID),
            doas_uid: str_var(ENV_DOAS_UID),
            doas_user: str_var(ENV_DOAS_USER),
            nails_target_uid: str_var(ENV_TARGET_UID),
            nails_target_user: str_var(ENV_TARGET_USER),

            display: str_var("DISPLAY"),
            wayland_display: str_var("WAYLAND_DISPLAY"),
            xdg_session_id: str_var("XDG_SESSION_ID"),
            xdg_session_type: str_var("XDG_SESSION_TYPE"),
            ssh_tty: str_var("SSH_TTY"),
            ssh_connection: str_var("SSH_CONNECTION"),

            nails_logind_available: str_var(ENV_LOGIND_AVAILABLE),
            nails_session_id: str_var(ENV_SESSION_ID),
            nails_display_manager: str_var(ENV_DISPLAY_MANAGER),
            nails_disable_notifications: str_var(ENV_DISABLE_NOTIFICATIONS),
            nails_system_profile_path: std::env::var_os(ENV_SYSTEM_PROFILE_PATH),
        }
    }

    /// An all-unset snapshot. The starting point for test fixtures that set only
    /// the variables they care about.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Look a value up by variable name, as the target-user resolver's
    /// [`EnvSource`](crate::target_user) does. Returns only the escalation and
    /// target variables it consults; any other name is `None`.
    #[must_use]
    pub fn lookup(&self, key: &str) -> Option<&str> {
        let value = match key {
            ENV_TARGET_UID => &self.nails_target_uid,
            ENV_TARGET_USER => &self.nails_target_user,
            ENV_SUDO_UID => &self.sudo_uid,
            ENV_SUDO_USER => &self.sudo_user,
            ENV_PKEXEC_UID => &self.pkexec_uid,
            ENV_DOAS_UID => &self.doas_uid,
            ENV_DOAS_USER => &self.doas_user,
            _ => &None,
        };
        value.as_deref()
    }

    /// Set `HOME`.
    #[must_use]
    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Set `SHELL`.
    #[must_use]
    pub fn with_shell(mut self, shell: impl Into<String>) -> Self {
        self.shell = Some(shell.into());
        self
    }

    /// Set `USER`.
    #[must_use]
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Set `SUDO_USER`.
    #[must_use]
    pub fn with_sudo_user(mut self, user: impl Into<String>) -> Self {
        self.sudo_user = Some(user.into());
        self
    }

    /// Set `SUDO_UID`.
    #[must_use]
    pub fn with_sudo_uid(mut self, uid: impl Into<String>) -> Self {
        self.sudo_uid = Some(uid.into());
        self
    }

    /// Set `NAILS_TARGET_USER`.
    #[must_use]
    pub fn with_target_user(mut self, user: impl Into<String>) -> Self {
        self.nails_target_user = Some(user.into());
        self
    }

    /// Set `NAILS_TARGET_UID`.
    #[must_use]
    pub fn with_target_uid(mut self, uid: impl Into<String>) -> Self {
        self.nails_target_uid = Some(uid.into());
        self
    }

    /// Set `DISPLAY`.
    #[must_use]
    pub fn with_display(mut self, display: impl Into<String>) -> Self {
        self.display = Some(display.into());
        self
    }

    /// Set `WAYLAND_DISPLAY`.
    #[must_use]
    pub fn with_wayland_display(mut self, display: impl Into<String>) -> Self {
        self.wayland_display = Some(display.into());
        self
    }
}

/// Read a variable as a `String`, discarding non-UTF-8 values (NAILS treats the
/// variables it reads as text; a non-UTF-8 value is as good as unset).
fn str_var(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_snapshot_has_every_field_unset() {
        let env = RuntimeEnv::empty();
        assert_eq!(env, RuntimeEnv::default());
        assert!(env.home.is_none());
        assert!(env.shell.is_none());
        assert!(env.display.is_none());
    }

    #[test]
    fn builders_set_only_their_field() {
        let env = RuntimeEnv::empty()
            .with_home("/home/alice")
            .with_shell("/bin/zsh")
            .with_sudo_uid("1000");

        assert_eq!(
            env.home.as_deref(),
            Some(std::path::Path::new("/home/alice"))
        );
        assert_eq!(env.shell.as_deref(), Some("/bin/zsh"));
        assert_eq!(env.sudo_uid.as_deref(), Some("1000"));
        assert!(env.sudo_user.is_none());
        assert!(env.display.is_none());
    }

    #[test]
    fn lookup_returns_escalation_variables_by_name() {
        let env = RuntimeEnv::empty()
            .with_sudo_uid("1000")
            .with_target_user("alice");

        assert_eq!(env.lookup("SUDO_UID"), Some("1000"));
        assert_eq!(env.lookup("NAILS_TARGET_USER"), Some("alice"));
        assert_eq!(env.lookup("PKEXEC_UID"), None);
        assert_eq!(env.lookup("HOME"), None);
    }
}
