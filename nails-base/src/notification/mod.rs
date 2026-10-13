// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Immediate desktop alerts for the in-session backend watcher.
//!
//! When the hidden volume stops responding, the watcher (a runtime unit of the
//! hidden session) raises one alert on the operator's session bus through
//! `notify-send`. It is attributed to a neutral application name, so nothing on
//! screen names the tool. Where `notify-send` is not installed (libnotify-bin
//! is not part of Debian's GNOME or KDE desktops), the same notification goes
//! out through systemd's `busctl`, which every supported host has.

use crate::Result;
use serde::{Deserialize, Serialize};

/// Build the environment overrides handed to `notify-send` so it reaches the
/// operator's session bus: a pure function of the operator's uid and the
/// display variables.
fn build_runtime_environment(
    uid: Option<u32>,
    display: Option<String>,
    wayland_display: Option<String>,
) -> Vec<(&'static str, String)> {
    let mut env = Vec::new();
    if let Some(uid) = uid {
        let runtime_dir = format!("/run/user/{uid}");
        env.push(("XDG_RUNTIME_DIR", runtime_dir.clone()));
        env.push((
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={runtime_dir}/bus"),
        ));
    }
    if let Some(display) = display {
        env.push(("DISPLAY", display));
    }
    if let Some(wayland_display) = wayland_display {
        env.push(("WAYLAND_DISPLAY", wayland_display));
    }
    env
}

/// Environment overrides for `notify-send`, for the operator resolved through
/// [`crate::TargetUser::resolve_with`].
pub fn notification_runtime_environment(env: &crate::RuntimeEnv) -> Vec<(&'static str, String)> {
    let uid = crate::TargetUser::resolve_with(env)
        .ok()
        .map(|user| user.uid);
    build_runtime_environment(uid, env.display.clone(), env.wayland_display.clone())
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

/// The `notify-send` command for an immediate alert. The watcher runs as root
/// from a system unit, so `notify-send` is a host tool from the fixed system
/// directories.
fn immediate_alert_command(
    notification: &Notification,
    session_env: &[(&'static str, String)],
) -> crate::process::ProcessCommand {
    let mut command = crate::process::ProcessCommand::tool("notify-send")
        .arg("--urgency")
        .arg(&notification.urgency)
        .arg("--app-name")
        .arg(NEUTRAL_APP_NAME);
    for (key, value) in session_env {
        command = command.set_env(key, value);
    }
    if let Some(ref icon) = notification.icon {
        command = command.arg("--icon").arg(icon);
    }
    command.arg(&notification.title).arg(&notification.body)
}

/// The same alert as a direct `org.freedesktop.Notifications.Notify` call on
/// the operator's session bus, for hosts without `notify-send`.
fn bus_alert_command(
    notification: &Notification,
    session_env: &[(&'static str, String)],
) -> crate::process::ProcessCommand {
    // The freedesktop urgency hint is a byte: 0 low, 1 normal, 2 critical.
    let urgency = match notification.urgency.as_str() {
        "low" => "0",
        "critical" => "2",
        _ => "1",
    };
    let mut command = crate::process::ProcessCommand::tool("busctl")
        .args(["--user", "call", "org.freedesktop.Notifications"])
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
    for (key, value) in session_env {
        command = command.set_env(key, value);
    }
    command
}

/// Send a desktop notification to the operator's session now.
///
/// In a unit-test binary of a NAILS library crate
/// ([`in_unit_tests`](crate::runtime_safety::in_unit_tests)) immediate alerts
/// never reach a real session bus.
pub fn send_immediate(notification: &Notification, env: &crate::RuntimeEnv) -> Result<()> {
    use crate::process::{ProcessRunner, RealProcessRunner};
    if crate::runtime_safety::in_unit_tests() {
        return Ok(());
    }
    let session_env = notification_runtime_environment(env);
    let (tool, output) =
        match RealProcessRunner.run(&immediate_alert_command(notification, &session_env)) {
            Err(e) if e.io_kind() == Some(std::io::ErrorKind::NotFound) => (
                "busctl",
                RealProcessRunner.run(&bus_alert_command(notification, &session_env))?,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_session_environment_points_at_the_operators_bus() {
        let env = build_runtime_environment(Some(1000), Some(":0".into()), None);
        assert!(env.contains(&("XDG_RUNTIME_DIR", "/run/user/1000".to_string())));
        assert!(env.contains(&(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/run/user/1000/bus".to_string()
        )));
        assert!(env.contains(&("DISPLAY", ":0".to_string())));
        assert!(build_runtime_environment(None, None, None).is_empty());
    }

    #[test]
    fn the_bus_fallback_sends_the_same_neutral_alert() {
        let alert = Notification {
            title: "Disk mounted with write access".into(),
            body: "/mnt/x (/dev/sdb1) is mounted read-write.".into(),
            urgency: "critical".into(),
            icon: Some("drive-removable-media".into()),
            created_at: String::new(),
        };
        let env = build_runtime_environment(Some(1000), None, None);
        let text = format!("{}", bus_alert_command(&alert, &env));
        assert!(
            text.contains("--user call org.freedesktop.Notifications"),
            "{text}"
        );
        assert!(
            text.contains("Notify susssasa{sv}i System 0 drive-removable-media"),
            "{text}"
        );
        assert!(text.contains("0 1 urgency y 2 -1"), "{text}");
        assert!(!text.to_lowercase().contains("nails"), "{text}");
        let normal = Notification {
            urgency: "normal".into(),
            icon: None,
            ..alert
        };
        let text = format!("{}", bus_alert_command(&normal, &env));
        assert!(text.contains("urgency y 1 -1"), "{text}");
    }

    #[test]
    fn the_alert_is_attributed_to_a_neutral_application() {
        let alert = Notification {
            title: "Storage unavailable".into(),
            body: "A mounted volume stopped responding.".into(),
            urgency: "critical".into(),
            icon: Some("drive-harddisk".into()),
            created_at: String::new(),
        };
        let text = format!("{}", immediate_alert_command(&alert, &[]));
        assert!(text.contains("--app-name System"), "{text}");
        assert!(!text.to_lowercase().contains("nails"), "{text}");
    }
}
