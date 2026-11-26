// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
fn a_unit_name_is_escaped_into_its_object_path_as_systemd_does() {
    assert_eq!(
        object_path("systemd-soft-reboot.service"),
        "/org/freedesktop/systemd1/unit/systemd_2dsoft_2dreboot_2eservice"
    );
    assert_eq!(
        object_path("a_b@1.service"),
        "/org/freedesktop/systemd1/unit/a_5fb_401_2eservice"
    );
    assert_eq!(object_path(""), "/org/freedesktop/systemd1/unit/_");
}

/// What `busctl --json=short get-property` prints for a service's
/// `ExecStart` (systemd 260): each command's program and arguments set apart,
/// so an argument that holds the text of another field stays one argument.
#[test]
fn the_commands_are_read_from_the_json_reply_with_each_argument_apart() {
    let reply: Value = serde_json::from_str(
        r#"{"type":"a(sasbttttuii)","data":[
            ["/opt/x",["/opt/x} { path=/run/overlay-runtime/control","transition"],false,0,0,0,0,0,0,0],
            ["/usr/bin/true",["/usr/bin/true"],true,0,0,0,0,0,0,0]]}"#,
    )
    .unwrap();
    assert_eq!(
        parse_commands(&reply["data"]),
        Some(vec![
            ExecCommand {
                path: "/opt/x".to_string(),
                argv: vec![
                    "/opt/x} { path=/run/overlay-runtime/control".to_string(),
                    "transition".to_string()
                ],
                ignores: false,
            },
            ExecCommand {
                path: "/usr/bin/true".to_string(),
                argv: vec!["/usr/bin/true".to_string()],
                ignores: true,
            },
        ])
    );
    assert_eq!(parse_commands(&serde_json::json!([])), Some(Vec::new()));
}

/// A reply of another shape reads as no answer, which refuses the entry.
#[test]
fn a_reply_of_another_shape_reads_as_none() {
    for data in [
        serde_json::json!("x"),
        serde_json::json!([["/opt/x"]]),
        serde_json::json!([["/opt/x", "/opt/x", false]]),
        serde_json::json!([["/opt/x", [1], false]]),
        serde_json::json!([["/opt/x", ["/opt/x"], "no"]]),
    ] {
        assert_eq!(parse_commands(&data), None, "{data}");
    }
}

/// Without a `busctl` that answers there are no commands to read.
#[test]
fn a_busctl_that_does_not_answer_gives_none() {
    assert_eq!(
        commands(
            Path::new("/nonexistent/busctl"),
            "systemd-soft-reboot.service",
            "ExecStart"
        ),
        None
    );
}
