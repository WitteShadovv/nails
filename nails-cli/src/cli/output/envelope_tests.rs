// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the human error lines and the cancel notice. The wire-type
//! tests (the JSON envelope itself) live in `nails-api`.

use super::*;

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

/// A cancel at a prompt reads as `activate`'s does: a neutral notice, not an
/// error.
#[test]
fn a_cancel_is_a_neutral_notice() {
    let style = crate::cli::output::OutputSettings::default().stderr_style();
    for message in [
        "Deactivation cancelled; nothing was changed.",
        "Discard cancelled; nothing was removed.",
    ] {
        let mut out = Vec::new();
        write_cancelled(&mut out, style, message);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("\u{25cb} {message}\n")
        );
    }
}

/// A captured command prints nothing and hands its one envelope back; a second
/// envelope of the same command is dropped, and the next command is captured
/// as well.
#[cfg(feature = "gui")]
#[test]
fn a_capture_takes_the_first_envelope_of_its_command_only() {
    let (status, line) = capture(|| {
        report_error(
            true,
            "recover",
            ExitStatus::Failed,
            ErrorBody::new("first", "the one envelope"),
        );
        report_error(
            true,
            "recover",
            ExitStatus::Failed,
            ErrorBody::new("second", "dropped"),
        )
    });
    assert_eq!(status, ExitStatus::Failed);
    let line = line.expect("the envelope was captured");
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(value["error"]["code"], "first", "{line}");

    let ((), again) = capture(|| {
        error_envelope("verify", ErrorBody::new("next", "a later command")).print();
    });
    assert!(again.is_some_and(|line| line.contains("\"next\"")));
    let ((), none) = capture(|| ());
    assert_eq!(none, None, "a command that prints nothing captures nothing");
}
