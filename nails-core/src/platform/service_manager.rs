// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The host service- and session-control seam.
//!
//! nails drives a handful of systemd units (the display manager, `nix-daemon`)
//! and logind operations (terminating a session or a user) while a hidden
//! session is set up or torn down. Historically each call site spelled its own
//! `systemctl`/`loginctl` sequence. [`ServiceManager`] and [`SessionManager`]
//! collect those operations behind one small, host-resolved seam so the ordering
//! rules live in a single place and tests can script them without a real host.
//!
//! The one ordering rule that matters is **socket before service**: a
//! socket-activated unit (`nix-daemon`, and any other `*.socket` pair) is
//! restarted by systemd the instant anything touches its socket, so the socket
//! must be stopped before the service when bringing a unit down, and started
//! before the service when bringing it back up. [`ServiceManager`] enforces that
//! for every unit; a unit with no socket simply has the best-effort socket step
//! do nothing.
//!
//! The tools are resolved from the platform's own command directories
//! ([`host_command_dirs`]) through the trust-checked [`HostCommands`] resolver,
//! never the caller's `PATH`, and host interaction is skipped in test/test-like
//! runtimes the same way [`nix_foreign`](super::nix_foreign) skips it.
//!
//! [`host_command_dirs`]: super::Platform::host_command_dirs

use std::path::PathBuf;

use crate::platform::HostCommands;
use crate::process::run::{
    LOGINCTL_BUDGET, ProcessCommand, ProcessRunner, RealProcessRunner, systemctl_budget,
};
use crate::{NailsError, Result};

/// Starting and stopping systemd units, socket before service.
pub trait ServiceManager {
    /// Stop `unit`. The matching `<unit>.socket` is stopped first (best-effort,
    /// so a unit with no socket is fine) to keep socket activation from
    /// immediately restarting it, then the service itself. Returns whether the
    /// service stop succeeded.
    fn stop_unit(&self, unit: &str) -> Result<bool>;

    /// Start `unit`, socket first (so socket activation can bring up the service),
    /// then the service. Returns whether the service start succeeded.
    fn start_unit(&self, unit: &str) -> Result<bool>;

    /// Whether `systemctl is-active <unit>` reports the unit active.
    fn is_active(&self, unit: &str) -> Result<bool>;
}

/// Terminating logind sessions and users.
pub trait SessionManager {
    /// Whether `loginctl` is usable on this host.
    fn loginctl_available(&self) -> bool;

    /// `loginctl terminate-session <id>`; returns whether it succeeded.
    fn terminate_session(&self, session_id: &str) -> Result<bool>;

    /// `loginctl terminate-user <uid>`; returns whether it succeeded.
    fn terminate_user(&self, uid: u32) -> Result<bool>;
}

/// Host-backed [`ServiceManager`] and [`SessionManager`].
///
/// Drives the host's own `systemctl`/`loginctl`, resolved from the platform
/// command directories passed to [`for_host`](Self::for_host). The raw command
/// invocations sit behind a private seam so the socket-before-service ordering
/// and the `is-active` mapping are unit-tested against a recorder.
pub struct SystemdControl {
    commands: Box<dyn UnitCommands>,
}

impl SystemdControl {
    /// Build a control seam over the host tools found in `command_dirs`, the list
    /// a backend exposes through
    /// [`Platform::host_command_dirs`](super::Platform::host_command_dirs).
    pub fn for_host(command_dirs: &'static [&'static str]) -> Self {
        Self {
            commands: Box::new(HostUnitCommands { command_dirs }),
        }
    }

    #[cfg(test)]
    fn with_commands(commands: impl UnitCommands + 'static) -> Self {
        Self {
            commands: Box::new(commands),
        }
    }
}

/// The base unit name used to derive the paired `*.socket`, stripping a trailing
/// `.service` so both `nix-daemon` and `nix-daemon.service` yield
/// `nix-daemon.socket`.
fn socket_for(unit: &str) -> String {
    let base = unit.strip_suffix(".service").unwrap_or(unit);
    format!("{base}.socket")
}

impl ServiceManager for SystemdControl {
    fn stop_unit(&self, unit: &str) -> Result<bool> {
        // Socket first so socket activation does not restart the service; its
        // outcome does not matter (the unit may have no socket).
        let _ = self.commands.systemctl(&["stop", &socket_for(unit)]);
        let (success, _stdout, _stderr) = self.commands.systemctl(&["stop", unit])?;
        Ok(success)
    }

    fn start_unit(&self, unit: &str) -> Result<bool> {
        let _ = self.commands.systemctl(&["start", &socket_for(unit)]);
        let (success, _stdout, _stderr) = self.commands.systemctl(&["start", unit])?;
        Ok(success)
    }

    fn is_active(&self, unit: &str) -> Result<bool> {
        let (success, stdout, _stderr) = self.commands.systemctl(&["is-active", unit])?;
        Ok(success && stdout.trim() == "active")
    }
}

impl SessionManager for SystemdControl {
    fn loginctl_available(&self) -> bool {
        self.commands.loginctl_available()
    }

    fn terminate_session(&self, session_id: &str) -> Result<bool> {
        let (success, _stdout, _stderr) =
            self.commands.loginctl(&["terminate-session", session_id])?;
        Ok(success)
    }

    fn terminate_user(&self, uid: u32) -> Result<bool> {
        let (success, _stdout, _stderr) = self
            .commands
            .loginctl(&["terminate-user", &uid.to_string()])?;
        Ok(success)
    }
}

/// The raw `systemctl`/`loginctl` invocations [`SystemdControl`] builds on.
///
/// Split from the ordering logic so a recorder can stand in for a real host in
/// unit tests.
trait UnitCommands {
    fn systemctl(&self, args: &[&str]) -> Result<(bool, String, String)>;
    fn loginctl(&self, args: &[&str]) -> Result<(bool, String, String)>;
    fn loginctl_available(&self) -> bool;
}

/// Resolves the host's own `systemctl`/`loginctl` from the platform command
/// directories and runs them under the shared budgets. Host interaction is
/// skipped in test/test-like runtimes, where the commands report success without
/// touching the host.
struct HostUnitCommands {
    command_dirs: &'static [&'static str],
}

impl HostUnitCommands {
    fn resolve(&self, tool: &str) -> Result<PathBuf> {
        HostCommands::new(self.command_dirs.iter().copied())
            .resolve(tool)
            .map_err(|err| {
                NailsError::InvalidState(format!(
                    "Cannot resolve {tool} to manage host services: {err}"
                ))
            })
    }
}

impl UnitCommands for HostUnitCommands {
    fn systemctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
        if crate::runtime_safety::should_skip_host_interaction() {
            return Ok((true, String::new(), String::new()));
        }
        let systemctl = self.resolve("systemctl")?;
        RealProcessRunner.run_text(
            &ProcessCommand::exact(systemctl)
                .args(args)
                .deadline(systemctl_budget(args)),
        )
    }

    fn loginctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
        if crate::runtime_safety::should_skip_host_interaction() {
            return Ok((true, String::new(), String::new()));
        }
        let loginctl = self.resolve("loginctl")?;
        RealProcessRunner.run_text(
            &ProcessCommand::exact(loginctl)
                .args(args)
                .deadline(LOGINCTL_BUDGET),
        )
    }

    fn loginctl_available(&self) -> bool {
        if crate::runtime_safety::should_skip_host_interaction() {
            return false;
        }
        let Ok(loginctl) = self.resolve("loginctl") else {
            return false;
        };
        RealProcessRunner
            .run(
                &ProcessCommand::exact(loginctl)
                    .arg("--version")
                    .deadline(LOGINCTL_BUDGET),
            )
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Shared recording state. The control owns one `RecordingCommands` handle to
    /// the same state the test keeps, so argv can be asserted after the boxed
    /// seam has run.
    #[derive(Default)]
    struct RecordingState {
        systemctl_calls: RefCell<Vec<Vec<String>>>,
        loginctl_calls: RefCell<Vec<Vec<String>>>,
        active: bool,
        loginctl_present: bool,
    }

    /// A [`UnitCommands`] that records every argv and answers `is-active` from the
    /// shared state.
    struct RecordingCommands(Rc<RecordingState>);

    impl UnitCommands for RecordingCommands {
        fn systemctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
            self.0
                .systemctl_calls
                .borrow_mut()
                .push(args.iter().map(|a| a.to_string()).collect());
            let stdout = if args.first().copied() == Some("is-active") {
                if self.0.active { "active" } else { "inactive" }.to_string()
            } else {
                String::new()
            };
            Ok((true, stdout, String::new()))
        }

        fn loginctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
            self.0
                .loginctl_calls
                .borrow_mut()
                .push(args.iter().map(|a| a.to_string()).collect());
            Ok((true, String::new(), String::new()))
        }

        fn loginctl_available(&self) -> bool {
            self.0.loginctl_present
        }
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| p.to_string()).collect()
    }

    /// A control plus the shared state its recorder writes to.
    fn control_with(state: RecordingState) -> (SystemdControl, Rc<RecordingState>) {
        let state = Rc::new(state);
        let control = SystemdControl::with_commands(RecordingCommands(Rc::clone(&state)));
        (control, state)
    }

    #[test]
    fn stop_unit_stops_socket_before_service() {
        let (control, state) = control_with(RecordingState::default());
        assert!(control.stop_unit("nix-daemon").unwrap());

        assert_eq!(
            *state.systemctl_calls.borrow(),
            vec![
                argv(&["stop", "nix-daemon.socket"]),
                argv(&["stop", "nix-daemon"]),
            ]
        );
    }

    #[test]
    fn start_unit_starts_socket_before_service() {
        let (control, state) = control_with(RecordingState::default());
        assert!(control.start_unit("nix-daemon.service").unwrap());

        assert_eq!(
            *state.systemctl_calls.borrow(),
            vec![
                // The `.service` suffix is stripped before deriving the socket.
                argv(&["start", "nix-daemon.socket"]),
                argv(&["start", "nix-daemon.service"]),
            ]
        );
    }

    #[test]
    fn is_active_maps_systemctl_output() {
        let (active, _) = control_with(RecordingState {
            active: true,
            ..RecordingState::default()
        });
        assert!(active.is_active("gdm").unwrap());

        let (inactive, state) = control_with(RecordingState::default());
        assert!(!inactive.is_active("gdm").unwrap());
        assert_eq!(
            *state.systemctl_calls.borrow(),
            vec![argv(&["is-active", "gdm"])]
        );
    }

    #[test]
    fn session_manager_calls_loginctl_with_the_right_argv() {
        let (control, state) = control_with(RecordingState {
            loginctl_present: true,
            ..RecordingState::default()
        });

        assert!(control.loginctl_available());
        assert!(control.terminate_session("c2").unwrap());
        assert!(control.terminate_user(1000).unwrap());

        assert_eq!(
            *state.loginctl_calls.borrow(),
            vec![
                argv(&["terminate-session", "c2"]),
                argv(&["terminate-user", "1000"]),
            ]
        );
    }

    #[test]
    fn host_backed_control_is_a_no_op_in_the_test_runtime() {
        // The runtime guard must short-circuit before resolving any host tool, so
        // the real seam is safe to construct and call under the test runtime.
        let control = SystemdControl::for_host(&["/run/current-system/sw/bin", "/usr/bin"]);
        assert!(control.stop_unit("gdm").unwrap());
        assert!(control.start_unit("gdm").unwrap());
        assert!(!control.is_active("gdm").unwrap());
        assert!(!control.loginctl_available());
    }

    #[test]
    fn socket_for_strips_a_service_suffix() {
        assert_eq!(socket_for("nix-daemon"), "nix-daemon.socket");
        assert_eq!(socket_for("nix-daemon.service"), "nix-daemon.socket");
    }
}
