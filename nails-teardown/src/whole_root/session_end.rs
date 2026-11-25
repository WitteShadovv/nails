// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! How a hidden session ends: the one place that decides it.
//!
//! A hidden session never hands the machine back to the decoy's kernel. That
//! kernel has run the hidden session: its memory, its kernel log, its network
//! state, its process counter and what it keeps in `/run` all carry traces of
//! it, and a decoy that starts again on it would take them in. Every ending
//! of a hidden session goes here instead: `deactivate`, the emergency without
//! a flag, the watcher, the sleep guard, the window's controls, and the last
//! step before a switch when it cannot do its work. They power the machine
//! off, which ends that kernel.
//!
//! The ending is one value ([`session_end`]) so that another one, such as a
//! kexec into a freshly booted decoy kernel, can replace the power-off here
//! alone. A full reboot through the firmware, which the emergency's
//! `--reboot` asks for, is no return either: the decoy then boots afresh.

use crate::whole_root::tools;
use std::path::Path;
use std::time::Duration;

/// How a hidden session ends ([`session_end`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// Power the machine off.
    PowerOff,
}

/// How every hidden session ends.
#[must_use]
pub const fn session_end() -> SessionEnd {
    SessionEnd::PowerOff
}

impl SessionEnd {
    /// The systemd target that ends the session the orderly way, every unit
    /// stopped first.
    #[must_use]
    pub const fn target(self) -> &'static str {
        match self {
            SessionEnd::PowerOff => "poweroff.target",
        }
    }

    /// The `systemctl` verb that ends it at once with `--force`, past the
    /// job queue, as PID 1's final stage does (`systemctl --force poweroff`).
    #[must_use]
    pub const fn verb(self) -> &'static str {
        match self {
            SessionEnd::PowerOff => "poweroff",
        }
    }

    /// The emergency action that ends it where PID 1 acts on its own, as a
    /// unit's `FailureAction=` or `JobTimeoutAction=` spells it. The forced
    /// form: systemd skips a plain `poweroff` while `shutdown.target` is
    /// active, and during a switch it always is.
    #[must_use]
    pub const fn emergency_action(self) -> &'static str {
        match self {
            SessionEnd::PowerOff => "poweroff-force",
        }
    }

    /// End the session at once, from a step that PID 1's shutdown may not
    /// wait for: ask PID 1 with `systemctl --force <verb>` (`systemctl`, when
    /// there is one), which goes straight to its final stage, and wait
    /// `grace` for that stage to end this process; when there is no
    /// `systemctl`, PID 1 refuses, or this process still runs after `grace`,
    /// ask the kernel (`kernel`: sync, then power off). Nothing goes to the
    /// screen. Returns only when neither ended the session, with whether
    /// PID 1 had taken it.
    pub fn now(
        self,
        systemctl: Option<&Path>,
        grace: Duration,
        kernel: impl FnOnce() -> bool,
    ) -> bool {
        let taken = systemctl.is_some_and(|systemctl| {
            tools::run(systemctl, &["--force", self.verb()], tools::TOOL_BUDGET)
                != tools::Outcome::Refused
        });
        if taken {
            std::thread::sleep(grace);
        }
        let _ = kernel();
        taken
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::write_executable;
    use std::path::PathBuf;

    /// A fake `systemctl` in `dir` that logs its arguments and exits `code`.
    fn fake_systemctl(dir: &Path, code: i32) -> PathBuf {
        let tool = dir.join("systemctl");
        write_executable(
            &tool,
            format!(
                "#!/bin/sh\necho \"$*\" >> '{}'\nexit {code}\n",
                dir.join("calls").display()
            ),
            0o755,
        );
        tool
    }

    #[test]
    fn every_session_ends_in_a_power_off() {
        let end = session_end();
        assert_eq!(end, SessionEnd::PowerOff);
        assert_eq!(end.target(), "poweroff.target");
        assert_eq!(end.verb(), "poweroff");
        assert_eq!(end.emergency_action(), "poweroff-force");
    }

    /// The forced end asks PID 1 at once and, should this process still run
    /// after the grace, asks the kernel.
    #[test]
    fn the_forced_end_asks_pid_1_and_then_the_kernel() {
        let dir = tempfile::tempdir().unwrap();
        let systemctl = fake_systemctl(dir.path(), 0);
        let kernel = std::cell::Cell::new(false);

        let taken = session_end().now(Some(&systemctl), Duration::ZERO, || {
            kernel.set(true);
            false
        });

        assert!(taken);
        assert!(
            kernel.get(),
            "the kernel is asked when this process still runs"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("calls")).unwrap(),
            "--force poweroff\n"
        );
    }

    /// When PID 1 refuses, or there is no `systemctl`, the kernel is asked
    /// at once, without the grace.
    #[test]
    fn the_forced_end_asks_the_kernel_when_pid_1_cannot_be_asked() {
        let dir = tempfile::tempdir().unwrap();
        let refusing = fake_systemctl(dir.path(), 1);
        for systemctl in [Some(refusing.as_path()), None] {
            let kernel = std::cell::Cell::new(false);
            let taken = session_end().now(systemctl, Duration::from_secs(3600), || {
                kernel.set(true);
                false
            });
            assert!(!taken, "{systemctl:?}");
            assert!(kernel.get(), "{systemctl:?}");
        }
    }
}
