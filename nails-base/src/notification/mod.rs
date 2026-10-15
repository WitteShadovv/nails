// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Immediate desktop alerts on the operator's session bus.
//!
//! The in-session watcher alerts the operator when the hidden volume stops
//! responding, when a disk is mounted read-write and when a disk is mounted
//! over the hidden root; `rehearse plant` shows a notification as one of its
//! canary channels. Each alert goes out through `notify-send` and is
//! attributed to a neutral application name, so nothing on screen names the
//! tool. Where `notify-send` is not installed (libnotify-bin is not part of
//! Debian's GNOME or KDE desktops), the same notification goes out through
//! systemd's `busctl`, which every supported host has.
//!
//! Both run as root's children, but a session bus admits only the account that
//! owns it. So the alert runs as the operator: their uid and primary gid, no
//! supplementary groups (see
//! [`ProcessCommand::run_as`](crate::process::ProcessCommand::run_as)), with the
//! bus and display variables pointed at their session. When no operator can be
//! resolved, nothing is started.

use crate::Result;
use crate::process::{ProcessCommand, ProcessRunner};
use serde::{Deserialize, Serialize};

/// Build the environment overrides an alert needs to reach the session bus of
/// the operator `uid`: a pure function of the uid and the display variables.
fn build_runtime_environment(
    uid: u32,
    display: Option<String>,
    wayland_display: Option<String>,
) -> Vec<(&'static str, String)> {
    let runtime_dir = format!("/run/user/{uid}");
    let mut env = vec![
        ("XDG_RUNTIME_DIR", runtime_dir.clone()),
        (
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={runtime_dir}/bus"),
        ),
    ];
    if let Some(display) = display {
        env.push(("DISPLAY", display));
    }
    if let Some(wayland_display) = wayland_display {
        env.push(("WAYLAND_DISPLAY", wayland_display));
    }
    env
}

/// A desktop notification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Notification {
    /// Short title (shown as notification heading)
    pub title: String,
    /// Body text
    pub body: String,
    /// Urgency level for `notify-send`: "low", "normal", or "critical"
    pub urgency: String,
    /// Freedesktop icon name
    pub icon: Option<String>,
    /// ISO 8601 timestamp when the notification was created
    pub created_at: String,
}

/// Neutral application name for immediate alerts.
const NEUTRAL_APP_NAME: &str = "System";

/// The operator's desktop session an alert goes to: the account it runs as and
/// the environment that points it at that account's session bus.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AlertSession {
    uid: u32,
    gid: u32,
    env: Vec<(&'static str, String)>,
}

impl AlertSession {
    /// The session of `operator`, with the display variables of `env`.
    fn of(operator: &crate::TargetUser, env: &crate::RuntimeEnv) -> Self {
        Self {
            uid: operator.uid,
            gid: operator.gid,
            env: build_runtime_environment(
                operator.uid,
                env.display.clone(),
                env.wayland_display.clone(),
            ),
        }
    }

    /// `command`, run as the operator on their session bus.
    fn command(&self, mut command: ProcessCommand) -> ProcessCommand {
        for (key, value) in &self.env {
            command = command.set_env(key, value);
        }
        command.run_as(self.uid, self.gid)
    }
}

/// The `notify-send` command for an immediate alert. `notify-send` is a host
/// tool from the fixed system directories: the alert is started by root.
fn immediate_alert_command(notification: &Notification, session: &AlertSession) -> ProcessCommand {
    let mut command = ProcessCommand::tool("notify-send")
        .arg("--urgency")
        .arg(&notification.urgency)
        .arg("--app-name")
        .arg(NEUTRAL_APP_NAME);
    if let Some(ref icon) = notification.icon {
        command = command.arg("--icon").arg(icon);
    }
    session.command(command.arg(&notification.title).arg(&notification.body))
}

/// The same alert as a direct `org.freedesktop.Notifications.Notify` call on
/// the operator's session bus, for hosts without `notify-send`.
///
/// `--` ends busctl's options before the call: the arguments that follow are
/// the call's, and the expiry timeout `-1` among them would otherwise be read
/// as an unknown option.
fn bus_alert_command(notification: &Notification, session: &AlertSession) -> ProcessCommand {
    // The freedesktop urgency hint is a byte: 0 low, 1 normal, 2 critical.
    let urgency = match notification.urgency.as_str() {
        "low" => "0",
        "critical" => "2",
        _ => "1",
    };
    let command = ProcessCommand::tool("busctl")
        .args(["--user", "--", "call", "org.freedesktop.Notifications"])
        .args([
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
        ])
        // app_name, replaces_id, app_icon, summary, body, actions, hints,
        // expire_timeout.
        .args(["Notify", "susssasa{sv}i", NEUTRAL_APP_NAME, "0"])
        .arg(notification.icon.as_deref().unwrap_or(""))
        .arg(&notification.title)
        .arg(&notification.body)
        .args(["0", "1", "urgency", "y", urgency, "-1"]);
    session.command(command)
}

/// Show `notification` in `session` through `runner`: `notify-send`, or
/// `busctl` where `notify-send` is not installed.
fn deliver(
    runner: &impl ProcessRunner,
    notification: &Notification,
    session: &AlertSession,
) -> Result<()> {
    let (tool, output) = match runner.run(&immediate_alert_command(notification, session)) {
        Err(e) if e.io_kind() == Some(std::io::ErrorKind::NotFound) => (
            "busctl",
            runner.run(&bus_alert_command(notification, session))?,
        ),
        other => ("notify-send", other?),
    };
    if !output.status.success() {
        return Err(crate::NailsError::io(
            tool,
            std::io::Error::other(format!(
                "{tool} exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )),
        ));
    }
    Ok(())
}

/// The error for an alert with no operator to show it to.
fn no_operator_session() -> crate::NailsError {
    const WHAT: &str = "operator session";
    crate::NailsError::io(
        WHAT,
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no {WHAT} could be resolved"),
        ),
    )
}

/// Send a desktop notification to the operator's session now.
///
/// The operator is resolved from `env` (see
/// [`TargetUser::resolve_with`](crate::TargetUser::resolve_with)): the account
/// that ran sudo, or the owner of the active session on seat0. Without one
/// there is no session to alert, and nothing is started.
///
/// In a unit-test binary of a NAILS library crate
/// ([`in_unit_tests`](crate::runtime_safety::in_unit_tests)) immediate alerts
/// never reach a real session bus.
pub fn send_immediate(notification: &Notification, env: &crate::RuntimeEnv) -> Result<()> {
    if crate::runtime_safety::in_unit_tests() {
        return Ok(());
    }
    let operator = crate::TargetUser::resolve_with(env).map_err(|_| no_operator_session())?;
    deliver(
        &crate::process::RealProcessRunner,
        notification,
        &AlertSession::of(&operator, env),
    )
}

#[cfg(test)]
mod tests;
