// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::execute;
use crate::cli::args::DeactivateArgs;
use crate::cli::output::{ExitStatus, OutputMode, OutputSettings};

fn json() -> OutputSettings {
    OutputSettings {
        mode: OutputMode::Json,
        ..OutputSettings::default()
    }
}

#[test]
fn outside_a_hidden_session_deactivate_refuses_with_invalid_state() {
    // The test process runs on its host's own root, never in a hidden root.
    let config = tempfile::tempdir().unwrap();
    let missing = config.path().join("absent.toml");
    for args in [
        DeactivateArgs::default(),
        DeactivateArgs {
            yes: true,
            poweroff: true,
        },
    ] {
        let status = execute(
            &json(),
            &nails_core::RuntimeEnv::default(),
            &args,
            Some(&missing),
        );
        assert_eq!(status, ExitStatus::InvalidState, "{args:?}");
    }
}

/// Run the confirmation with `answer` typed, returning the verdict and the
/// text shown.
fn confirm(poweroff: bool, answer: &[u8]) -> (bool, String) {
    let settings = OutputSettings {
        ascii: true,
        ..OutputSettings::default()
    };
    let mut out = Vec::new();
    let verdict = super::confirm_deactivate(
        &settings,
        poweroff,
        &mut out,
        &mut std::io::Cursor::new(answer),
    );
    (verdict, String::from_utf8(out).unwrap())
}

#[test]
fn the_prompt_says_where_the_session_ends_before_asking() {
    let (_, to_decoy) = confirm(false, b"n\n");
    assert_eq!(
        to_decoy,
        "[WARN] This ends the hidden session and returns to the decoy now.\n\
         \x20   Every hidden program is closed; unsaved work is lost.\n\
         \x20   Continue? [y/N]: "
    );
    let (_, to_poweroff) = confirm(true, b"n\n");
    assert!(
        to_poweroff.starts_with("[WARN] This ends the hidden session and powers off now.\n"),
        "{to_poweroff}"
    );
}

#[test]
fn only_yes_in_any_case_confirms_deactivation() {
    for answer in ["y\n", "Yes\n", " YES \n"] {
        assert!(confirm(false, answer.as_bytes()).0, "{answer:?}");
    }
    for answer in ["\n", "no\n", "sure\n", ""] {
        assert!(!confirm(false, answer.as_bytes()).0, "{answer:?}");
    }
    // Input that is not UTF-8 is a read error, and declines.
    assert!(!confirm(true, b"\xff\n").0);
}

/// An answer other than yes reads as `activate`'s cancel: the neutral notice
/// after the prompt, no error, and exit 1. A yes goes on without one.
#[test]
fn a_declined_deactivation_is_a_neutral_notice_and_exits_1() {
    let ask = |answer: &[u8]| {
        let mut err = Vec::new();
        let status = super::confirm_or_cancel(
            &OutputSettings::default(),
            false,
            &mut err,
            &mut std::io::Cursor::new(answer),
        );
        (status, String::from_utf8(err).unwrap())
    };
    for answer in ["n\n", "\n", ""] {
        let (status, shown) = ask(answer.as_bytes());
        assert_eq!(status, Some(ExitStatus::Failed), "{answer:?}");
        assert!(
            shown.ends_with(
                "Continue? [y/N]: \u{25cb} Deactivation cancelled; nothing was changed.\n"
            ),
            "{shown}"
        );
        assert!(!shown.contains("error:"), "{shown}");
    }
    let (status, shown) = ask(b"y\n");
    assert_eq!(status, None);
    assert!(!shown.contains("cancelled"), "{shown}");
}
