// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the JSON envelope and the human error lines.

use super::*;

#[test]
fn success_envelope_has_schema_version_command_and_ok() {
    let env = Envelope::success("status", serde_json::json!({"state": "ok"}));
    let value: serde_json::Value = serde_json::from_str(&env.to_line()).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "status");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["state"], "ok");
    assert!(value.get("error").is_none());
}

#[test]
fn error_envelope_carries_code_message_hint() {
    let env = error_envelope(
        "activate",
        ErrorBody::new("preflight", "checks failed").with_hint("mount the volume"),
    );
    let value: serde_json::Value = serde_json::from_str(&env.to_line()).unwrap();
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], "preflight");
    assert_eq!(value["error"]["message"], "checks failed");
    assert_eq!(value["error"]["hint"], "mount the volume");
    assert!(value.get("data").is_none());
}

#[test]
fn human_error_survives_a_closed_stderr_pipe() {
    // A real pipe whose reader is gone: the write fails with EPIPE, which must
    // be swallowed rather than panic as eprintln! would.
    let (reader, mut writer) = std::io::pipe().unwrap();
    drop(reader);
    write_human_error(
        &mut writer,
        &ErrorBody::new("teardown_incomplete", "busy").with_hint("reboot"),
    );

    let (mut reader, mut writer) = std::io::pipe().unwrap();
    write_human_error(&mut writer, &ErrorBody::new("x", "boom").with_hint("retry"));
    drop(writer);
    let mut text = String::new();
    std::io::Read::read_to_string(&mut reader, &mut text).unwrap();
    assert_eq!(text, "error: boom\n  retry\n");
}

#[test]
fn every_hint_line_is_indented() {
    let mut out = Vec::new();
    write_human_error(
        &mut out,
        &ErrorBody::new("x", "boom").with_hint("first\nsecond"),
    );
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "error: boom\n  first\n  second\n"
    );
}

#[test]
fn a_newline_in_a_message_stays_one_parseable_line() {
    let env = error_envelope("deactivate", ErrorBody::new("mount_busy", "busy\nretry"));
    let line = env.to_line();
    assert_eq!(line.lines().count(), 1, "one physical line: {line}");
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(value["error"]["message"], "busy\nretry");
}

/// A cancel at a prompt reads as `activate`'s does: a neutral notice, not an
/// error.
#[test]
fn a_cancel_is_a_neutral_notice() {
    let style = crate::cli::output::OutputSettings::default().stderr_style();
    for message in [
        "Deactivation cancelled; nothing was changed.",
        "Reset cancelled; nothing was removed.",
    ] {
        let mut out = Vec::new();
        write_cancelled(&mut out, style, message);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("\u{25cb} {message}\n")
        );
    }
}
