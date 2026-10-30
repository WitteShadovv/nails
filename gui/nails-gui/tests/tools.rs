// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The window's tools on Slint's headless platform: the rows of a settled
//! page that open them, Back and Escape, and the pages of Verify and
//! Rehearsal from envelopes recorded from the real CLI (which the helper
//! answers with word for word), for the keyboard and the screen reader.

mod screen;
mod support;

use i_slint_backend_testing::{AccessibleLiveness, AccessibleRole};
use nails_api::protocol::{RehearseScanArgs, VerifyArgs};
use nails_gui::client::{Answer, ours};
use nails_gui::text;
use nails_gui::worker::{Ask, Kind, Rehearse, Update};
use screen::Screen;
use serde_json::{Value, json};
use slint::platform::Key;
use support::fixture;

fn answered(kind: Kind, exit: u8, envelope: Value) -> Update {
    Update::Answered(kind, Answer { exit, envelope })
}

fn status(place: &str) -> Update {
    answered(
        Kind::Status,
        0,
        json!({"schema_version": 2, "command": "status", "ok": true, "data": {
            "place": place, "attention": null, "hidden_root": "/mnt/data"}}),
    )
}

/// A decoy's window whose check passed.
fn decoy() -> Screen {
    let screen = Screen::new(false);
    screen.tall();
    screen.update(Update::Connected(ours()));
    screen.update(status("decoy"));
    screen.update(answered(
        Kind::Check,
        0,
        json!({"schema_version": 2, "command": "check", "ok": true, "data": {
            "ready": true, "checks": [], "summary": {"passed": 3, "warnings": 0, "failed": 0}}}),
    ));
    screen.asks();
    screen
}

/// A hidden session's window.
fn hidden() -> Screen {
    let screen = Screen::in_hidden_session();
    screen.tall();
    screen.update(Update::Connected(ours()));
    screen.update(status("hidden"));
    screen.asks();
    screen
}

/// Press the button labelled `label`.
fn press(screen: &Screen, label: &str) {
    screen
        .find_with(label, AccessibleRole::Button)
        .invoke_accessible_default_action();
}

#[test]
fn a_tools_row_opens_its_page_and_back_returns_to_the_session() {
    let screen = decoy();
    let row = screen.find_with(text::VERIFY, AccessibleRole::Button);
    assert_eq!(
        row.accessible_description().as_deref(),
        Some(text::VERIFY_WHAT)
    );
    row.invoke_accessible_default_action();
    assert!(screen.asks().is_empty(), "Verify waits for the person");
    assert!(screen.shows(text::VERIFY_WHAT));
    assert_eq!(
        screen.labels(AccessibleRole::Button),
        ["Close", text::BACK, text::VERIFY, text::DEEP_SCAN]
    );
    // The focus starts again at the page's start: Back is the first stop.
    assert_eq!(screen.focused(), "");
    assert_eq!(screen.walk(Key::Tab, 1), [text::BACK]);

    screen.press(Key::Return);
    assert_eq!(screen.asks(), vec![Ask::Status]);
    assert!(screen.shows(text::READY));
    assert!(screen.shows(text::REHEARSAL), "the session's page again");

    // Escape goes back too.
    press(&screen, text::REHEARSAL);
    assert_eq!(screen.asks(), vec![Ask::Rehearse(Rehearse::Status)]);
    screen.press(Key::Escape);
    assert_eq!(screen.asks(), vec![Ask::Status]);
    assert!(screen.shows(text::READY));
}

#[test]
fn verify_runs_and_shows_the_verdict_what_it_found_and_what_it_did_not_check() {
    let screen = hidden();
    press(&screen, text::VERIFY);
    press(&screen, text::VERIFY);
    assert_eq!(screen.asks(), vec![Ask::Verify(VerifyArgs::default())]);
    screen.update(Update::Running(Kind::Verify));
    let busy = screen.with_role(AccessibleRole::ProgressIndicator);
    assert_eq!(
        busy[0].accessible_label().as_deref(),
        Some(text::LOOKING_FOR_TRACES)
    );
    // Nothing acts while it runs but Close and the Emergency control.
    assert_eq!(
        screen.labels(AccessibleRole::Button),
        ["Close", text::EMERGENCY]
    );

    screen.update(answered(Kind::Verify, 11, fixture("verify-findings")));
    let heading = screen.find_with(text::TRACES_FOUND, AccessibleRole::Text);
    assert_eq!(
        heading.accessible_live_region(),
        Some(AccessibleLiveness::Assertive)
    );
    assert!(screen.shows(text::GROUP_FOUND));
    assert!(screen.shows(text::GROUP_NOT_CHECKED_RUN));
    let trace = screen.find_with(
        "Critical: Artifact file found: /mnt/nails-pivot.",
        AccessibleRole::ListItem,
    );
    assert_eq!(
        trace.accessible_description().as_deref(),
        Some("Fix: Trace on the decoy filesystem; remove it: rm -rf /mnt/nails-pivot")
    );
    screen.find_with(
        "Not checked: The systemd journal (not searched by verify).",
        AccessibleRole::ListItem,
    );

    press(&screen, text::DEEP_SCAN);
    assert_eq!(
        screen.asks(),
        vec![Ask::Verify(VerifyArgs {
            deep: true,
            ..VerifyArgs::default()
        })]
    );
}

#[test]
fn a_clean_verify_says_it_is_no_proof() {
    let screen = hidden();
    press(&screen, text::VERIFY);
    press(&screen, text::VERIFY);
    screen.update(answered(Kind::Verify, 0, fixture("verify-clean")));
    assert!(screen.shows(text::NO_KNOWN_TRACES));
    assert!(screen.shows(
        "A standard scan of 2 checks found no known trace. This is not proof that there is none."
    ));
    assert!(!screen.shows(text::GROUP_FOUND));
    assert!(screen.shows(text::GROUP_NOT_CHECKED_RUN));
    assert!(screen.shows(text::VERIFY_AGAIN));
}

/// A rehearsal page on `screen` whose status said `status`.
fn rehearsal(screen: &Screen, status: &str) {
    press(screen, text::REHEARSAL);
    assert_eq!(screen.asks(), vec![Ask::Rehearse(Rehearse::Status)]);
    screen.update(Update::Running(Kind::Rehearse));
    assert!(screen.shows(text::READING_REHEARSAL));
    screen.update(answered(Kind::Rehearse, 0, fixture(status)));
}

/// The state each step row shows, by its label.
fn step_states(screen: &Screen) -> Vec<String> {
    [text::STEP_PLANT, text::STEP_END, text::STEP_SCAN]
        .iter()
        .map(|label| {
            screen
                .find_with(label, AccessibleRole::ListItem)
                .accessible_description()
                .unwrap_or_default()
                .to_string()
        })
        .collect()
}

#[test]
fn a_rehearsal_shows_its_steps_and_the_action_of_the_next_one() {
    let screen = hidden();
    rehearsal(&screen, "rehearse-status-none");
    assert_eq!(
        step_states(&screen),
        [text::STEP_NOW, text::STEP_NEXT, text::STEP_NEXT]
    );
    press(&screen, text::PLANT);
    assert!(matches!(
        &screen.asks()[..],
        [Ask::Rehearse(Rehearse::Plant(_))]
    ));
    screen.update(Update::Running(Kind::Rehearse));
    assert!(screen.shows(text::PLANTING));
    screen.update(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    assert!(screen.shows(text::PLANTED));
    assert!(screen.shows(&text::planted_in(5)));
    screen.find_with(
        "Planted: File in a system folder: /etc/(test words)",
        AccessibleRole::ListItem,
    );
    screen.find_with(
        "Not tested: Desktop notification: no session bus to send it on",
        AccessibleRole::ListItem,
    );
    assert_eq!(
        step_states(&screen),
        [text::STEP_DONE, text::STEP_NOW, text::STEP_NEXT]
    );
    assert!(screen.shows(text::AFTER_PLANT));
    assert!(
        !screen.shows(text::SCAN),
        "no scan in the session that planted"
    );
}

#[test]
fn a_scan_whose_disk_can_hide_the_test_words_reads_not_checked_first_and_never_passed() {
    let screen = decoy();
    rehearsal(&screen, "rehearse-status-planted");
    assert_eq!(
        step_states(&screen),
        [text::STEP_DONE, text::STEP_DONE, text::STEP_NOW]
    );
    press(&screen, text::SCAN);
    assert_eq!(
        screen.asks(),
        vec![Ask::Rehearse(Rehearse::Scan(RehearseScanArgs::default()))]
    );
    screen.update(Update::Running(Kind::Rehearse));
    assert!(screen.shows(text::SCANNING));
    assert!(screen.shows(text::SCAN_HOW_LONG));
    screen.update(answered(Kind::Rehearse, 9, fixture("rehearse-scan-blind")));
    assert!(screen.shows(text::NOT_A_CLEAN_RESULT));
    assert!(screen.shows(&text::blind_spots(1)));
    assert!(!screen.shows(text::PASSED));
    // Right under the verdict: what the scan did not check, that disk first.
    let texts = screen.texts();
    let verdict = texts
        .iter()
        .position(|text| text == &text::blind_spots(1))
        .unwrap();
    assert_eq!(
        texts[verdict + 1],
        text::GROUP_NOT_CHECKED_SCAN,
        "{texts:?}"
    );
    let rows = screen.labels(AccessibleRole::ListItem);
    assert!(
        rows[0]
            .starts_with("Not checked: /tmp/scratch/plain.img: The scan identifies no filesystem"),
        "{rows:?}"
    );
    assert_eq!(
        rows.iter()
            .filter(|row| row.starts_with("Not checked: "))
            .count(),
        7
    );
    assert!(screen.shows(text::SCAN_AGAIN));
    assert!(screen.shows(text::REMOVE_TEST_WORDS));
}

#[test]
fn a_scan_that_found_the_test_words_is_announced_with_where() {
    let screen = decoy();
    rehearsal(&screen, "rehearse-status-planted");
    press(&screen, text::SCAN);
    screen.update(answered(Kind::Rehearse, 11, fixture("rehearse-scan-found")));
    let heading = screen.find_with(text::TEST_WORDS_FOUND, AccessibleRole::Text);
    assert_eq!(
        heading.accessible_live_region(),
        Some(AccessibleLiveness::Assertive)
    );
    screen.find_with(
        "Found: /tmp/scratch/hit.img, byte 524288",
        AccessibleRole::ListItem,
    );
}
