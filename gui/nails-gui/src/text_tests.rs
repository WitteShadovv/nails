// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

use super::*;
use nails_api::protocol::Hello;
use std::path::Path;

#[test]
fn a_duration_has_a_space_before_its_unit() {
    for (seconds, words) in [
        (-5, "less than 1 min"),
        (59, "less than 1 min"),
        (60, "1 min"),
        (2400, "40 min"),
        (3600, "1 h"),
        (7800, "2 h 10 min"),
        (90061, "25 h 1 min"),
    ] {
        assert_eq!(duration(seconds), words, "{seconds}");
    }
    assert_eq!(
        hidden_active(Some(7800)),
        "Hidden session active for 2 h 10 min."
    );
    assert_eq!(hidden_active(None), "Hidden session active.");
}

#[test]
fn counts_agree_with_their_nouns() {
    assert_eq!(checks_passed(1), "1 check passed");
    assert_eq!(checks_passed(24), "24 checks passed");
    assert_eq!(problems(1), "1 problem. Nothing was changed.");
    assert_eq!(problems(2), "2 problems. Nothing was changed.");
}

#[test]
fn the_engines_reasons_end_the_sentence_they_are_put_in() {
    assert_eq!(
        decoy_switch_refused(Some("the next root has no os-release.")),
        "Decoy. The last activation stopped at the switch: the next root has no os-release."
    );
    assert_eq!(
        decoy_switch_refused(None),
        "Decoy. The last activation stopped at the switch."
    );
    // The reason as the engine gives it, its opening words left out, since
    // the page's sentence says them already.
    assert_eq!(
        no_way_back_reason(
            "in the hidden root without a way back: no session plan in /run (upper /mnt/data/root/upper)"
        ),
        "No session plan in /run (upper /mnt/data/root/upper)."
    );
    assert_eq!(
        no_way_back_reason("the plan in /run names another upper."),
        "The plan in /run names another upper."
    );
    assert_eq!(
        hidden_volume_covered(Some(120), "/mnt/data"),
        "Hidden session active for 2 min. A disk is mounted over the hidden volume: \
         files saved under /mnt/data go to that disk."
    );
}

#[test]
fn every_outcome_has_a_word() {
    use nails_api::CheckOutcome;
    let words: Vec<&str> = [
        CheckOutcome::Pass,
        CheckOutcome::Warn,
        CheckOutcome::Fail,
        CheckOutcome::Skipped,
    ]
    .into_iter()
    .map(outcome_word)
    .collect();
    assert_eq!(words, ["Passed", "Warning", "Failed", "Not checked"]);
}

#[test]
fn terminal_lines_name_the_engine_on_the_hidden_volume() {
    let engine = Path::new("/mnt/data/nails");
    assert_eq!(
        next_step(Some(engine), "recover"),
        "Next: sudo /mnt/data/nails recover"
    );
    assert_eq!(
        next_step(None, "recover"),
        "Next: sudo <hidden volume>/nails recover"
    );
    assert_eq!(
        open_from_terminal(Some(engine)),
        "Open a terminal and run: sudo /mnt/data/nails gui"
    );
    assert_eq!(
        open_again(Some(engine)),
        "To go on, open the window again from a terminal: sudo /mnt/data/nails gui"
    );
    assert_eq!(
        next_step(Some(Path::new("/mnt/a gui/nails")), "deactivate"),
        "Next: sudo '/mnt/a gui/nails' deactivate"
    );
    assert_eq!(
        engine_fix("Run `sudo /mnt/data/nails recover` to reset the record"),
        "Run sudo /mnt/data/nails recover to reset the record"
    );
}

#[test]
fn an_allowed_risk_is_named_and_its_word_prompted() {
    assert_eq!(
        allowed_by_you(RISK_PERSISTENT_DECOY),
        "Allowed by you: a persistent record on this computer's disk."
    );
    assert_eq!(type_to_continue(ALLOW_WORD), "Type allow to continue");
    // The buttons that open a question end in the ellipsis character.
    for label in [ACTIVATE, ALLOW] {
        assert!(label.ends_with('\u{2026}'), "{label}");
    }
}

#[test]
fn a_mismatch_names_what_differs() {
    let hello = |protocol, engine: &str| Hello {
        protocol,
        engine: engine.to_string(),
    };
    assert_eq!(
        mismatch(&hello(1, "0.4.0"), &hello(1, "0.3.0")),
        "This window is from release 0.4.0 and NAILS on the hidden volume from release 0.3.0. \
         They work together only when both come from one release."
    );
    assert!(
        mismatch(&hello(2, "0.4.0"), &hello(1, "0.4.0"))
            .contains("protocol 2 and NAILS on the hidden volume protocol 1")
    );
}

#[test]
fn an_engine_sentence_gets_its_capital_and_its_full_stop() {
    assert_eq!(
        sentence("the token names no plan"),
        "The token names no plan."
    );
    assert_eq!(sentence("  Done.  "), "Done.");
    assert_eq!(sentence("Why?"), "Why?");
    assert_eq!(sentence(""), "");
}

#[test]
fn the_window_title_and_app_id_name_nothing_about_the_tool_or_the_storage() {
    for neutral in [WINDOW_TITLE, APP_ID] {
        let lowered = neutral.to_lowercase();
        for word in [
            "nails",
            "hidden",
            "decoy",
            "emergency",
            "rehearsal",
            "veracrypt",
            "luks",
            "cryptsetup",
            "/mnt",
        ] {
            assert!(!lowered.contains(word), "{neutral} names {word}");
        }
    }
    assert_eq!(
        APP_ID, "session",
        "the menu entry of a hidden session is session.desktop"
    );
}
