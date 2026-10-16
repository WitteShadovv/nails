// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::process::run::{Account, MockProcessRunner, exited};

/// The operator alice: uid 1000, primary group `users` (100), as on NixOS.
fn alice() -> AlertSession {
    let operator = crate::TargetUser::for_test(1000, 100, "alice", "/home/alice", "/bin/bash");
    AlertSession::of(&operator, &crate::RuntimeEnv::empty())
}

fn disk_alert(urgency: &str, icon: Option<&str>) -> Notification {
    Notification {
        title: "Disk mounted with write access".into(),
        body: "/mnt/x (/dev/sdb1) is mounted read-write.".into(),
        urgency: urgency.into(),
        icon: icon.map(str::to_string),
        created_at: String::new(),
    }
}

#[test]
fn the_session_environment_points_at_the_operators_bus() {
    let env = build_runtime_environment(1000, Some(":0".into()), None);
    assert_eq!(
        env,
        vec![
            ("XDG_RUNTIME_DIR", "/run/user/1000".to_string()),
            (
                "DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/run/user/1000/bus".to_string()
            ),
            ("DISPLAY", ":0".to_string()),
        ]
    );
    let wayland = build_runtime_environment(1000, None, Some("wayland-0".into()));
    assert!(wayland.contains(&("WAYLAND_DISPLAY", "wayland-0".to_string())));
}

#[test]
fn every_alert_runs_as_the_operator_without_extra_groups() {
    let session = alice();
    let alert = disk_alert("critical", Some("drive-removable-media"));
    let operator = Some(Account {
        uid: 1000,
        gid: 100,
    });
    assert_eq!(
        immediate_alert_command(&alert, &session).account(),
        operator
    );
    assert_eq!(bus_alert_command(&alert, &session).account(), operator);
}

#[test]
fn the_bus_fallback_is_one_notify_call_on_the_operators_bus() {
    let alert = disk_alert("critical", Some("drive-removable-media"));
    let expected = ProcessCommand::tool("busctl")
        .args(["--user", "--", "call", "org.freedesktop.Notifications"])
        .args([
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
        ])
        .args(["Notify", "susssasa{sv}i", "System", "0"])
        .args(["drive-removable-media", &alert.title, &alert.body])
        .args(["0", "1", "urgency", "y", "2", "-1"])
        .set_env("XDG_RUNTIME_DIR", "/run/user/1000")
        .set_env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
        .run_as(1000, 100)
        .deadline(ALERT_BUDGET);
    assert_eq!(bus_alert_command(&alert, &alice()), expected);
}

#[test]
fn busctl_reads_no_option_after_its_double_dash() {
    // busctl's option parser takes every argument that starts with `-` for an
    // option, the expiry timeout `-1` included, until a `--` ends the options.
    for (urgency, byte) in [("low", "0"), ("normal", "1"), ("critical", "2")] {
        let text = bus_alert_command(&disk_alert(urgency, None), &alice()).to_string();
        let (options, call) = text.split_once(" -- ").expect("a `--` before the call");
        assert_eq!(options, "busctl --user", "{text}");
        assert!(
            call.starts_with(
                "call org.freedesktop.Notifications /org/freedesktop/Notifications \
                 org.freedesktop.Notifications Notify susssasa{sv}i System 0  "
            ),
            "{text}"
        );
        assert!(
            call.ends_with(&format!(" 0 1 urgency y {byte} -1")),
            "{text}"
        );
        assert!(!text.to_lowercase().contains("nails"), "{text}");
    }
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
    let text = immediate_alert_command(&alert, &alice()).to_string();
    assert_eq!(
        text,
        "notify-send --urgency critical --app-name System --icon drive-harddisk -- \
         Storage unavailable A mounted volume stopped responding."
    );
}

/// A body that begins with `-` (a cover alert names the mount source first)
/// follows the `--`, so notify-send shows it instead of taking it for an
/// option; and every alert waits for the daemon for a bounded time only.
#[test]
fn notify_send_reads_no_option_after_its_double_dash_and_waits_a_bounded_time() {
    let alert = Notification {
        title: "Disk mounted over a folder in use".into(),
        body: "-weird-source is mounted over /mnt/data".into(),
        urgency: "critical".into(),
        icon: None,
        created_at: String::new(),
    };
    let expected = ProcessCommand::tool("notify-send")
        .args(["--urgency", "critical", "--app-name", "System", "--"])
        .args([&alert.title, &alert.body])
        .set_env("XDG_RUNTIME_DIR", "/run/user/1000")
        .set_env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
        .run_as(1000, 100)
        .deadline(ALERT_BUDGET);
    assert_eq!(immediate_alert_command(&alert, &alice()), expected);
    assert!(ALERT_BUDGET <= std::time::Duration::from_secs(10));
}

#[test]
fn delivery_falls_back_to_busctl_where_notify_send_is_missing() {
    let missing = std::io::Error::new(std::io::ErrorKind::NotFound, "notify-send not found");
    let runner = MockProcessRunner::new()
        .with_response(Err(crate::NailsError::io("notify-send", missing)))
        .with_response(Ok(exited(0, "u 7\n", "")));
    let alert = disk_alert("low", None);

    deliver(&runner, &alert, &alice()).unwrap();

    assert_eq!(
        runner.calls(),
        vec![
            immediate_alert_command(&alert, &alice()),
            bus_alert_command(&alert, &alice())
        ]
    );
}

#[test]
fn a_refused_alert_reports_the_tool_and_its_message() {
    let runner = MockProcessRunner::new().with_response(Ok(exited(
        1,
        "",
        "GDBus.Error: Connection refused\n",
    )));

    let err = deliver(&runner, &disk_alert("critical", None), &alice()).unwrap_err();

    let message = err.to_string();
    assert!(message.contains("notify-send exited with"), "{message}");
    assert!(
        message.ends_with(": GDBus.Error: Connection refused"),
        "{message}"
    );
    // notify-send is installed: its failure is the result, not a reason to
    // try the bus a second way.
    assert_eq!(runner.calls().len(), 1);
}

#[test]
fn without_an_operator_there_is_no_session_to_alert() {
    let err = no_operator_session();
    assert_eq!(err.to_string(), "no operator session could be resolved");
    assert_eq!(err.io_kind(), Some(std::io::ErrorKind::NotFound));
}
