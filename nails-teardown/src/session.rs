// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The operator's graphical session, which the emergency kill always spares.
//!
//! Emergency never logs the operator out: it does not stop the display manager
//! or the X server, and it does not kill any process of the graphical login
//! session, whose exit would end that session. The whole session is spared
//! (policy "option 2", see ADR 0007): the display manager's cgroup, each
//! graphical session's `session-<id>.scope` and the matching
//! `user@<uid>.service`. Overlay-rooted processes outside it are still killed.
//!
//! Part of this is decided at activation and recorded in the plan (the display
//! manager and the operator's user manager). The session scope cannot be: the
//! activation restarts the display manager, and the session the operator logs
//! back into gets a new id afterwards. So at panic time the scopes are read
//! from logind's own session records under `/run/systemd/sessions`, the files
//! `sd_session_get_type(3)` reads, without running `loginctl` or talking to
//! D-Bus. When those records cannot be read, every user session is spared, the
//! answer that can never log a desktop out.

use std::collections::HashMap;
use std::path::Path;

/// The display manager's cgroup fragment (and the X server it starts).
pub const DISPLAY_MANAGER_FRAGMENT: &str = "/display-manager.service";

/// logind's per-session records.
pub const SESSIONS_DIR: &str = "/run/systemd/sessions";

/// The `user@<uid>.service` fragment of `uid`'s user manager.
pub fn user_manager_fragment(uid: u32) -> String {
    format!("/user@{uid}.service")
}

/// The processes the kill spares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpareSet {
    fragments: Vec<String>,
    spare_all_user_sessions: bool,
}

/// Parse a logind session record (`KEY=value` lines).
fn parse_record(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

impl SpareSet {
    /// The spare set from the fragments recorded at activation plus the
    /// graphical sessions logind records in `sessions_dir` now.
    pub fn at_panic(recorded: &[String], sessions_dir: &Path) -> Self {
        let mut fragments = vec![DISPLAY_MANAGER_FRAGMENT.to_string()];
        for fragment in recorded {
            if !fragments.contains(fragment) {
                fragments.push(fragment.clone());
            }
        }
        let Ok(dir) = std::fs::read_dir(sessions_dir) else {
            return Self {
                fragments,
                spare_all_user_sessions: true,
            };
        };
        for entry in dir.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            // logind keeps `<id>.ref` FIFOs next to the records.
            if name.contains('.') {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                return Self {
                    fragments,
                    spare_all_user_sessions: true,
                };
            };
            let record = parse_record(&text);
            let class = record.get("CLASS").map(String::as_str).unwrap_or("");
            let kind = record.get("TYPE").map(String::as_str).unwrap_or("");
            if class == "user" && matches!(kind, "x11" | "wayland" | "mir") {
                let scope = record
                    .get("SCOPE")
                    .cloned()
                    .unwrap_or_else(|| format!("session-{name}.scope"));
                fragments.push(format!("/{scope}"));
                if let Some(uid) = record.get("UID").and_then(|u| u.parse().ok()) {
                    let fragment = user_manager_fragment(uid);
                    if !fragments.contains(&fragment) {
                        fragments.push(fragment);
                    }
                }
            }
        }
        Self {
            fragments,
            spare_all_user_sessions: false,
        }
    }

    /// Whether a process with this `/proc/<pid>/cgroup` body is spared.
    pub fn covers(&self, cgroup: &str) -> bool {
        // A fragment must match a whole path segment: `/session-2.scope` must
        // not spare `/session-20.scope`.
        let segment_match = |fragment: &str| {
            cgroup.match_indices(fragment).any(|(at, _)| {
                let end = at + fragment.len();
                cgroup[end..]
                    .chars()
                    .next()
                    .is_none_or(|c| c == '/' || c == '\n')
            })
        };
        if self.fragments.iter().any(|f| segment_match(f)) {
            return true;
        }
        self.spare_all_user_sessions
            && (cgroup.contains("/user@")
                || (cgroup.contains("/session-") && cgroup.contains(".scope")))
    }

    /// Whether the session records could not be read and every user session
    /// is spared.
    pub fn spares_all_user_sessions(&self) -> bool {
        self.spare_all_user_sessions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).unwrap();
    }

    #[test]
    fn a_graphical_session_and_its_user_manager_are_spared_a_tty_session_is_not() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "2",
            "UID=1000\nCLASS=user\nTYPE=x11\nSCOPE=session-2.scope\n",
        );
        write(
            dir.path(),
            "5",
            "UID=0\nCLASS=user\nTYPE=tty\nSCOPE=session-5.scope\n",
        );
        write(dir.path(), "2.ref", "");
        let spare = SpareSet::at_panic(&[], dir.path());
        assert!(spare.covers("0::/user.slice/user-1000.slice/session-2.scope\n"));
        assert!(
            spare.covers("0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.service\n")
        );
        assert!(spare.covers("0::/system.slice/display-manager.service\n"));
        assert!(!spare.covers("0::/user.slice/user-0.slice/session-5.scope\n"));
        assert!(!spare.covers("0::/user.slice/user-1000.slice/session-20.scope\n"));
        assert!(!spare.covers("0::/system.slice/worker.service\n"));
    }

    #[test]
    fn unreadable_session_records_spare_every_user_session() {
        let spare = SpareSet::at_panic(&[], Path::new("/nonexistent/sessions"));
        assert!(spare.spares_all_user_sessions());
        assert!(spare.covers("0::/user.slice/user-0.slice/session-5.scope\n"));
        assert!(!spare.covers("0::/system.slice/worker.service\n"));
    }

    #[test]
    fn recorded_fragments_are_spared() {
        let dir = tempfile::tempdir().unwrap();
        let spare = SpareSet::at_panic(&[user_manager_fragment(1000)], dir.path());
        assert!(spare.covers("0::/user.slice/user-1000.slice/user@1000.service\n"));
    }
}
