// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The window's tools on Slint's headless platform: the rows of a settled
//! page that open them, Back and Escape, the pages of Verify and Rehearsal
//! from envelopes recorded from the real CLI (which the helper answers with
//! word for word), and the questions of Discard Hidden Changes and Set Up
//! Hidden Volume with their typed folder, keyboard and screen reader.

mod screen;
mod support;

use i_slint_backend_testing::{AccessibleLiveness, AccessibleRole};
use nails_api::protocol::{
    DiscardPlanArgs, DiscardPlanData, InitArgs, InitPlanData, RehearseScanArgs, VerifyArgs,
};
use nails_gui::client::{Answer, Plan, PlanData, ours};
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

fn type_into(screen: &Screen, label: &str, typed: &str) {
    while screen.focused() != label {
        screen.press(Key::Tab);
    }
    screen.type_text(typed);
}

#[test]
fn a_discard_of_a_home_lists_what_goes_and_waits_for_the_folder_typed() {
    let screen = decoy();
    press(&screen, text::DISCARD);
    let field = screen.find_with(text::FIELD_FOLDER, AccessibleRole::TextInput);
    assert_eq!(field.accessible_value().as_deref(), Some(""));
    assert!(screen.shows(text::FOLDER_HINT));
    let discard = screen.find_with(text::DISCARD_ACTION, AccessibleRole::Button);
    assert_eq!(
        discard.accessible_enabled(),
        Some(false),
        "nothing typed yet"
    );

    type_into(&screen, text::FIELD_FOLDER, "home");
    assert!(screen.shows(text::FOLDER_NOT_ABSOLUTE));
    screen.press(Key::Home);
    screen.type_text("/");
    assert!(screen.shows(text::FOLDER_HINT));
    assert_eq!(discard.accessible_enabled(), Some(true));
    // Return in the field does nothing: only the button acts.
    screen.press(Key::Return);
    assert!(screen.asks().is_empty());
    discard.invoke_accessible_default_action();
    assert_eq!(
        screen.asks(),
        vec![Ask::Plan(Plan::Discard(DiscardPlanArgs {
            target: "/home".to_string(),
            allow_decoy_storage: false,
        }))]
    );
    screen.update(Update::Running(Kind::Plan));
    assert!(screen.shows(text::LOOKING_AT_CHANGES));
    screen.update(Update::Planned(PlanData::Discard(DiscardPlanData {
        target: "/home".to_string(),
        removals: vec!["/mnt/data/root/upper/home".to_string()],
        resets_nix_store: false,
        token: "d".repeat(32),
    })));
    let dialog = screen.find_with(text::DISCARD_QUESTION, AccessibleRole::Groupbox);
    let body = dialog.accessible_description().unwrap_or_default();
    assert_eq!(
        body.lines().collect::<Vec<_>>(),
        [
            text::discard_consequence("/home").as_str(),
            text::DISCARD_LIST,
            "/mnt/data/root/upper/home"
        ]
    );
    let prompt = text::discard_type("/home", true);
    assert_eq!(screen.focused(), prompt, "the field takes the focus");
    let delete = screen.find_with(text::DELETE, AccessibleRole::Button);
    assert_eq!(delete.accessible_enabled(), Some(false));
    screen.type_text("/home");
    assert_eq!(delete.accessible_enabled(), Some(true));
    delete.invoke_accessible_default_action();
    assert_eq!(screen.asks(), vec![Ask::Apply]);
    screen.update(Update::Running(Kind::Apply));
    assert!(screen.shows(text::DELETING));
    screen.update(answered(
        Kind::Apply,
        0,
        json!({"schema_version": 2, "command": "discard", "ok": true,
            "data": {"target": "/home", "removed": ["/mnt/data/root/upper/home"]}}),
    ));
    assert!(screen.shows(text::DISCARDED));
    screen.find_with(
        "Deleted: /mnt/data/root/upper/home",
        AccessibleRole::ListItem,
    );
}

#[test]
fn set_up_asks_first_and_lists_each_part_it_wrote() {
    let screen = decoy();
    press(&screen, text::SET_UP);
    assert!(screen.shows(&text::set_up_what("/mnt/data")));
    press(&screen, text::SET_UP_ACTION);
    assert_eq!(
        screen.asks(),
        vec![Ask::Plan(Plan::Init(InitArgs {
            path: "/mnt/data".to_string(),
            allow_decoy_storage: false,
            hardware_config: None,
            no_hardware_config: false,
        }))]
    );
    screen.update(Update::Planned(PlanData::Init(InitPlanData {
        path: "/mnt/data".to_string(),
        hardware_config: None,
        skipped: Some("host 'debian' has no NixOS config layer".to_string()),
        warnings: vec![],
        token: "e".repeat(32),
    })));
    let dialog = screen.find_with(text::SET_UP_QUESTION, AccessibleRole::Groupbox);
    assert_eq!(
        dialog.accessible_description().as_deref(),
        Some(text::set_up_consequence("/mnt/data").as_str())
    );
    assert_eq!(screen.focused(), "Cancel", "the focus starts on Cancel");
    press(&screen, text::SET_UP_CONFIRM);
    assert_eq!(screen.asks(), vec![Ask::Apply]);
    screen.update(answered(
        Kind::Apply,
        0,
        json!({"schema_version": 2, "command": "init", "ok": true, "data": {
            "root": "/mnt/data",
            "items": [{"path": "/mnt/data/logs", "status": "created"}],
            "next_steps": ["check readiness"]}}),
    ));
    assert!(screen.shows(text::SET_UP_DONE));
    screen.find_with("Created: /mnt/data/logs", AccessibleRole::ListItem);
    assert!(screen.shows(text::SET_UP_NEXT));
    press(&screen, text::BACK);
    assert_eq!(screen.asks(), vec![Ask::Status]);
}
