// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Which live processes the emergency overlay-rooted kill must spare because they
//! keep the operator's graphical desktop session alive.
//!
//! Emergency tears the NAILS overlays out from under a running desktop without
//! logging the operator out: it never stops or restarts the display manager or X
//! server, and it must not kill the processes whose exit would end the logind
//! session and so bounce the greeter back. Activation brings the hidden session
//! up with the user's home (and more) on overlays and restarts the display
//! manager so the session re-logs in under them, so the whole desktop — the
//! display manager, the X server, the logind session leader and its session
//! wrapper, the window/session manager and its clients, and the user's systemd
//! manager — reads as "overlay-rooted" and would otherwise be signalled. Killing
//! any link of that chain (in the configured e2e session the chain is
//! `lightdm → session-child → Xsession → xterm`, where `xterm` is the client the
//! session waits on) ends the logind session, so lightdm restarts X and shows a
//! greeter — i.e. logs the operator out.
//!
//! # Policy: spare the whole graphical session (kill-policy "option 2")
//!
//! Two policies were considered:
//!
//!   * **Option 3** — still kill overlay-rooted *applications* inside the
//!     graphical session, sparing only the session-critical "spine" (leader,
//!     session wrapper, the client the session waits on / the window manager).
//!   * **Option 2** — spare *everything* in the operator's graphical session and
//!     kill overlay-rooted processes only outside it.
//!
//! Option 3 cannot be made reliable here. The configured session has **no window
//! manager** — the "desktop" is a single `xterm` the `Xsession` script waits on —
//! so the only session-critical in-scope process is that foreground client, and
//! there is no WM-agnostic structural signal that separates "the client the
//! session waits on" from an ordinary application in the same scope without
//! probing X properties such as `_NET_SUPPORTING_WM_CHECK` (heavy, X-only, and
//! absent for a bare `xterm`). A misclassification kills the client, which ends
//! the session — exactly the "logs the operator out" failure the policy forbids.
//! Since the overriding requirement is that the operator still ends up with a
//! running desktop, this guard implements option 2: the whole graphical session
//! is spared, and overlay-rooted processes **outside** it are still killed.
//!
//! # Residual exposure
//!
//! A spared process survives the lazy overlay detach. After that detach the
//! overlay is gone from the mount table, but a spared process that later opens an
//! *absolute* path onto the now-exposed decoy could still write to it. Emergency
//! accepts that residual exposure as the price of not logging the operator out;
//! the honest post-teardown report (hidden root still mounted, backend not
//! closed) tells the operator to finish by rebooting or powering off.
//!
//! # How the set is identified
//!
//! Structurally, from cgroup membership — never from a process name or any
//! test-specific marker:
//!   * the `display-manager.service` system cgroup (display manager + X server);
//!   * each graphical logind session's scope (`session-<id>.scope`), covering its
//!     leader, the session wrapper / `Xsession`, the window/session manager and
//!     every client;
//!   * the matching `user@<uid>.service` user-manager cgroup (`systemd --user`
//!     and its core services such as the user D-Bus).
//!
//! The graphical sessions are enumerated with `loginctl`. If that enumeration
//! fails entirely, the guard falls back to sparing *any* user session scope and
//! user manager, so a detection failure can never silently log a desktop out.

use crate::process::session::SessionCommandExecutor;
use std::collections::HashMap;

/// The cgroup-path fragment of the display manager (and, on systemd hosts, the X
/// server it starts). Present on every systemd host, graphical or not; it simply
/// matches nothing when no display manager runs.
const DISPLAY_MANAGER_FRAGMENT: &str = "/display-manager.service";

/// The set of processes the emergency overlay-rooted kill spares because they
/// belong to the operator's graphical desktop session.
#[derive(Debug, Default, Clone)]
pub(super) struct GraphicalSessionGuard {
    /// cgroup-path fragments whose presence in a process's `/proc/<pid>/cgroup`
    /// marks it as part of the operator's graphical session.
    fragments: Vec<String>,
    /// Safe-default fallback: when the graphical sessions could not be enumerated
    /// at all (loginctl missing or erroring), spare *any* user session scope and
    /// user manager so a detection failure never logs a desktop out. Set only in
    /// that degraded case; when enumeration succeeds but finds no graphical
    /// session (e.g. a headless host) this stays `false` and the kill is not
    /// broadened.
    spare_all_user_sessions: bool,
}

impl GraphicalSessionGuard {
    /// Enumerate the operator's graphical logind sessions and build the spare set.
    pub(super) fn detect<E: SessionCommandExecutor>(executor: &E) -> Self {
        // The display manager and X server are spared on every host.
        let mut fragments = vec![DISPLAY_MANAGER_FRAGMENT.to_string()];

        let Some(session_ids) = list_session_ids(executor) else {
            // loginctl could not be run — fall back to the broad, desktop-safe
            // rule rather than risk logging the operator out.
            return Self {
                fragments,
                spare_all_user_sessions: true,
            };
        };

        for id in &session_ids {
            let Some(props) = show_session(executor, id) else {
                continue;
            };
            if is_graphical_user_session(&props) {
                fragments.push(session_scope_fragment(id));
                if let Some(uid) = props.get("User") {
                    fragments.push(user_manager_fragment(uid));
                }
            }
        }

        Self {
            fragments,
            spare_all_user_sessions: false,
        }
    }

    /// Whether a process with this `/proc/<pid>/cgroup` content belongs to the
    /// protected graphical session and must be spared.
    pub(super) fn covers(&self, cgroup_content: &str) -> bool {
        if self
            .fragments
            .iter()
            .any(|fragment| cgroup_content.contains(fragment.as_str()))
        {
            return true;
        }
        self.spare_all_user_sessions && is_any_user_session_cgroup(cgroup_content)
    }
}

/// The broad, desktop-safe fallback: a cgroup that belongs to any user systemd
/// manager or any logind session scope.
fn is_any_user_session_cgroup(cgroup: &str) -> bool {
    cgroup.contains("/user@") || (cgroup.contains("/session-") && cgroup.contains(".scope"))
}

/// The session ids `loginctl list-sessions` reports, or `None` when the call
/// could not be run (so the caller falls back to the broad rule).
fn list_session_ids<E: SessionCommandExecutor>(executor: &E) -> Option<Vec<String>> {
    match executor.execute_loginctl(&["list-sessions", "--no-legend"]) {
        Ok((true, stdout, _)) => Some(parse_session_ids(&stdout)),
        _ => None,
    }
}

/// The `Key=Value` properties of one session, or `None` when the lookup failed.
fn show_session<E: SessionCommandExecutor>(
    executor: &E,
    id: &str,
) -> Option<HashMap<String, String>> {
    match executor.execute_loginctl(&[
        "show-session",
        id,
        "-p",
        "Class",
        "-p",
        "Type",
        "-p",
        "User",
    ]) {
        Ok((true, stdout, _)) => Some(parse_properties(&stdout)),
        _ => None,
    }
}

/// The first whitespace-delimited column (the session id) of each non-empty line
/// of `loginctl list-sessions --no-legend` output.
fn parse_session_ids(list_output: &str) -> Vec<String> {
    list_output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

/// Parse `loginctl show-session -p …` `Key=Value` lines into a map.
fn parse_properties(output: &str) -> HashMap<String, String> {
    output
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

/// Whether a session's properties describe the operator's graphical session: a
/// `user`-class session running on an X11 or Wayland (or Mir) display.
fn is_graphical_user_session(props: &HashMap<String, String>) -> bool {
    let class = props.get("Class").map(String::as_str).unwrap_or("");
    let session_type = props.get("Type").map(String::as_str).unwrap_or("");
    class == "user" && matches!(session_type, "x11" | "wayland" | "mir")
}

/// systemd names a logind session's scope `session-<id>.scope`.
fn session_scope_fragment(id: &str) -> String {
    format!("/session-{id}.scope")
}

/// The user systemd manager unit for `uid`.
fn user_manager_fragment(uid: &str) -> String {
    format!("/user@{uid}.service")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Result;
    use std::cell::RefCell;

    /// A `loginctl` stub: answers `list-sessions` with a fixed id list and
    /// `show-session <id>` from a per-id property map. `list_ok = false` makes the
    /// list call fail, exercising the broad fallback.
    struct FakeLoginctl {
        list_ok: bool,
        ids: Vec<String>,
        props: HashMap<String, Vec<(&'static str, &'static str)>>,
        calls: RefCell<Vec<String>>,
    }

    impl FakeLoginctl {
        fn new() -> Self {
            Self {
                list_ok: true,
                ids: Vec::new(),
                props: HashMap::new(),
                calls: RefCell::new(Vec::new()),
            }
        }

        fn with_session(mut self, id: &str, props: &[(&'static str, &'static str)]) -> Self {
            self.ids.push(id.to_string());
            self.props.insert(id.to_string(), props.to_vec());
            self
        }

        fn with_list_failure(mut self) -> Self {
            self.list_ok = false;
            self
        }
    }

    impl SessionCommandExecutor for FakeLoginctl {
        fn execute_systemctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
            Ok((true, String::new(), String::new()))
        }

        fn execute_loginctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
            self.calls.borrow_mut().push(args.join(" "));
            match args.first().copied() {
                Some("list-sessions") => {
                    if !self.list_ok {
                        return Ok((false, String::new(), "boom".to_string()));
                    }
                    // `list-sessions --no-legend`: "<id> <uid> <user> <seat> <tty>".
                    let body = self
                        .ids
                        .iter()
                        .map(|id| format!("{id} 1000 testuser seat0 tty7"))
                        .collect::<Vec<_>>()
                        .join("\n");
                    Ok((true, body, String::new()))
                }
                Some("show-session") => {
                    let id = args.get(1).copied().unwrap_or("");
                    let Some(props) = self.props.get(id) else {
                        return Ok((false, String::new(), String::new()));
                    };
                    let body = props
                        .iter()
                        .map(|(key, value)| format!("{key}={value}"))
                        .collect::<Vec<_>>()
                        .join("\n");
                    Ok((true, body, String::new()))
                }
                _ => Ok((true, String::new(), String::new())),
            }
        }

        fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
            Ok(true)
        }

        fn loginctl_available(&self) -> bool {
            true
        }
    }

    #[test]
    fn spares_display_manager_on_every_host() {
        let guard = GraphicalSessionGuard::detect(&FakeLoginctl::new());
        assert!(guard.covers("0::/system.slice/display-manager.service"));
    }

    #[test]
    fn spares_the_graphical_session_scope_leader_and_clients() {
        let guard = GraphicalSessionGuard::detect(&FakeLoginctl::new().with_session(
            "c1",
            &[("Class", "user"), ("Type", "x11"), ("User", "1000")],
        ));
        // The session wrapper / Xsession / xterm all live in the session scope.
        assert!(guard.covers("0::/user.slice/user-1000.slice/session-c1.scope"));
        assert!(
            guard.covers("0::/user.slice/user-1000.slice/session-c1.scope/init.scope/whatever")
        );
        // The user systemd manager and its D-Bus.
        assert!(guard.covers("0::/user.slice/user-1000.slice/user@1000.service/dbus.service"));
    }

    #[test]
    fn kills_overlay_rooted_apps_outside_the_graphical_session() {
        let guard = GraphicalSessionGuard::detect(&FakeLoginctl::new().with_session(
            "c1",
            &[("Class", "user"), ("Type", "x11"), ("User", "1000")],
        ));
        // An overlay-rooted app in a *different* session scope (e.g. a console or
        // su session the operator launched something from) is not spared.
        assert!(!guard.covers("0::/user.slice/user-1000.slice/session-c7.scope/app"));
        // A plain system-slice service that is not the display manager.
        assert!(!guard.covers("0::/system.slice/some-daemon.service"));
    }

    #[test]
    fn does_not_spare_non_graphical_sessions() {
        // A tty (non-graphical) session must not broaden the spare set.
        let guard = GraphicalSessionGuard::detect(
            &FakeLoginctl::new()
                .with_session("5", &[("Class", "user"), ("Type", "tty"), ("User", "1000")]),
        );
        assert!(!guard.covers("0::/user.slice/user-1000.slice/session-5.scope/bash"));
        // ...but the display manager is still spared.
        assert!(guard.covers("0::/system.slice/display-manager.service"));
    }

    #[test]
    fn falls_back_to_sparing_all_user_sessions_when_loginctl_fails() {
        let guard = GraphicalSessionGuard::detect(&FakeLoginctl::new().with_list_failure());
        assert!(guard.covers("0::/user.slice/user-1000.slice/session-c1.scope/x"));
        assert!(guard.covers("0::/user.slice/user-1000.slice/user@1000.service/dbus.service"));
        assert!(guard.covers("0::/system.slice/display-manager.service"));
        // Even in the fallback, a plain system service is still killable.
        assert!(!guard.covers("0::/system.slice/some-daemon.service"));
    }

    #[test]
    fn parses_session_ids_from_list_output() {
        let out = "c1 1000 testuser seat0 tty7\n 5 1000 testuser  pts/0\n\n";
        assert_eq!(
            parse_session_ids(out),
            vec!["c1".to_string(), "5".to_string()]
        );
    }
}
