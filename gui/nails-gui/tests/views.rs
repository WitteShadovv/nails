// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The pages as the window draws them, from envelopes and events the real
//! helper gave (`tests/fixtures/`, recorded from `nails helper --stdio` on a
//! decoy with no hidden volume mounted) and from the shapes the schemas
//! allow.

mod screen;
mod support;

use i_slint_backend_testing::AccessibleRole;
use nails_api::Event;
use nails_api::protocol::{CheckArgs, Hello};
use nails_gui::client::{Answer, ours};
use nails_gui::text;
use nails_gui::worker::{Ask, Failure, Kind, Update};
use screen::Screen;
use serde_json::json;
use support::{fixture, fixture_events};

fn answered(kind: Kind, envelope: serde_json::Value) -> Update {
    Update::Answered(kind, Answer { exit: 0, envelope })
}

/// The window connected and given the recorded decoy status.
fn decoy() -> Screen {
    let screen = Screen::new(false);
    screen.update(Update::Connected(ours()));
    assert_eq!(screen.asks(), vec![Ask::Status]);
    screen.update(Update::Running(Kind::Status));
    screen.update(answered(Kind::Status, fixture("status-decoy")));
    screen
}

#[test]
fn the_recorded_decoy_status_runs_the_check_and_shows_where_things_stand() {
    let screen = decoy();
    assert_eq!(screen.asks(), vec![Ask::Check(CheckArgs::default())]);
    assert!(screen.shows("Checking This Computer"));
    assert!(screen.shows("Decoy. No hidden session is active."));
    let fact = screen.find("Hidden volume");
    assert_eq!(fact.accessible_role(), Some(AccessibleRole::ListItem));
    assert_eq!(fact.accessible_description().as_deref(), Some("/mnt/data"));
    let busy = screen.with_role(AccessibleRole::ProgressIndicator);
    assert_eq!(busy.len(), 1);
    assert_eq!(
        busy[0].accessible_label().as_deref(),
        Some("Checking This Computer")
    );
}

#[test]
fn each_recorded_check_event_shows_as_it_comes_and_the_answer_gives_the_verdict() {
    let screen = decoy();
    screen.tall();
    screen.asks();
    screen.update(Update::Running(Kind::Check));
    let events = fixture_events("check-decoy");
    let checks: Vec<(nails_api::CheckOutcome, String)> = events
        .iter()
        .filter_map(|event| match event {
            Event::Check {
                outcome, message, ..
            } => Some((*outcome, message.clone())),
            _ => None,
        })
        .collect();
    assert!(
        checks.len() >= 3,
        "the recording holds the checks: {events:?}"
    );
    for (shown, event) in events.into_iter().enumerate() {
        screen.update(Update::Event(event));
        let rows = screen.labels(AccessibleRole::ListItem);
        // The fact row, and one row for each check event so far.
        let so_far = checks.len().min(shown + 1);
        assert!(rows.len() <= so_far + 1, "{rows:?}");
    }
    let rows = screen.labels(AccessibleRole::ListItem);
    for (outcome, message) in &checks {
        let word = nails_gui::text::outcome_word(*outcome);
        let label = format!("{word}: {}", nails_gui::text::sentence(message));
        assert!(rows.contains(&label), "{label} is not among {rows:?}");
    }
    assert!(screen.shows("Checking This Computer"));

    let envelope = fixture("check-decoy");
    let report = &envelope["data"];
    let ready = report["ready"].as_bool().unwrap();
    screen.update(answered(Kind::Check, envelope.clone()));
    let heading = if ready {
        "Ready to Activate"
    } else {
        "Not Ready to Activate"
    };
    assert!(screen.shows(heading), "{:?}", screen.texts());
    assert!(
        screen
            .with_role(AccessibleRole::ProgressIndicator)
            .is_empty()
    );
    // The failures, each with the engine's fix when it gives one, and the
    // passed checks counted under the facts.
    let failed: Vec<&serde_json::Value> = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["status"] == "fail")
        .collect();
    assert_eq!(
        failed.len() as u64,
        report["summary"]["failed"].as_u64().unwrap()
    );
    for row in failed {
        let label = format!(
            "Failed: {}",
            nails_gui::text::sentence(row["message"].as_str().unwrap())
        );
        let element = screen.find(&label);
        let fix = row["remediation"]
            .as_str()
            .map(|fix| format!("Fix: {}", nails_gui::text::engine_fix(fix)))
            .unwrap_or_default();
        assert_eq!(
            element.accessible_description().as_deref(),
            Some(fix.as_str()),
            "{label}"
        );
    }
    let passed = report["summary"]["passed"].as_u64().unwrap() as usize;
    let tally = screen.find("This computer");
    assert_eq!(
        tally.accessible_description().as_deref(),
        Some(nails_gui::text::checks_passed(passed).as_str())
    );
    let again = screen.find("Check Again");
    assert_eq!(again.accessible_role(), Some(AccessibleRole::Button));
    again.invoke_accessible_default_action();
    assert_eq!(screen.asks(), vec![Ask::Check(CheckArgs::default())]);
}

#[test]
fn a_hidden_session_page_shows_its_time_and_the_way_out() {
    let screen = Screen::new(false);
    screen.update(Update::Connected(ours()));
    screen.update(answered(
        Kind::Status,
        json!({"schema_version": 2, "command": "status", "ok": true, "data": {
            "place": "hidden", "attention": null, "uptime_seconds": 7800,
            "hidden_root": "/mnt/data", "hidden_root_mounted": true}}),
    ));
    assert!(
        screen.asks().iter().all(|ask| *ask == Ask::Status),
        "no check in a hidden session"
    );
    assert!(screen.shows("Hidden Session"));
    assert!(screen.shows("Hidden session active for 2 h 10 min."));
    // The way out is the window's own: no terminal line.
    screen.find_with(text::DEACTIVATE, AccessibleRole::Button);
    assert!(!screen.texts().iter().any(|line| line.contains("sudo")));
    assert!(!screen.shows("Check Again"));
}

#[test]
fn a_refusal_replaces_the_page_and_is_announced_at_once() {
    let screen = Screen::new(false);
    let theirs = Hello {
        protocol: ours().protocol,
        engine: "0.0.1".to_string(),
    };
    screen.update(Update::Ended(Failure::Mismatch {
        window: ours(),
        engine: theirs,
    }));
    assert!(screen.shows("Different Releases"));
    assert!(screen.shows("Nothing was changed."));
    assert!(screen.shows("Fix: use the window and NAILS from one release."));
    let heading = screen.find_with("Different Releases", AccessibleRole::Text);
    assert_eq!(
        heading.accessible_live_region(),
        Some(i_slint_backend_testing::AccessibleLiveness::Assertive)
    );
    assert!(
        screen
            .with_role(AccessibleRole::ProgressIndicator)
            .is_empty()
    );
}

#[test]
fn the_page_while_pkexec_asks_says_why_it_asks() {
    let screen = Screen::new(true);
    assert!(screen.shows("Waiting for Your Password"));
    assert!(screen.shows(nails_gui::text::WAITING_FOR_PASSWORD_WHY));
    let heading = screen.find_with("Waiting for Your Password", AccessibleRole::Text);
    assert_eq!(
        heading.accessible_live_region(),
        Some(i_slint_backend_testing::AccessibleLiveness::Polite)
    );
    screen.update(Update::Ended(Failure::PasswordUnavailable));
    assert!(screen.shows("Password Needed"));
    assert!(screen.shows("Open a terminal and run: sudo /mnt/data/nails gui"));
    assert!(!screen.closed());
}

#[test]
fn a_dismissed_password_dialog_closes_the_window() {
    let screen = Screen::new(true);
    screen.update(Update::Ended(Failure::PasswordDismissed));
    assert!(screen.closed());
}

#[test]
fn a_status_the_engine_could_not_build_names_no_place() {
    let screen = Screen::new(false);
    screen.update(Update::Connected(ours()));
    screen.update(Update::Answered(
        Kind::Status,
        Answer {
            exit: 3,
            envelope: json!({"schema_version": 2, "command": "status", "ok": false, "error": {
                "code": "config", "message": "invalid configuration in /mnt/data/config/nails.toml",
                "next": null}}),
        },
    ));
    assert!(screen.shows("Settings Cannot Be Read"));
    assert!(screen.shows("Next: sudo /mnt/data/nails config validate"));
    assert!(!screen.shows(nails_gui::text::DECOY_RECORD_UNREADABLE));
    let heading = screen.find_with("Settings Cannot Be Read", AccessibleRole::Text);
    assert_eq!(
        heading.accessible_live_region(),
        Some(i_slint_backend_testing::AccessibleLiveness::Assertive)
    );
}

fn decoy_with(attention: &str) -> Screen {
    let screen = Screen::new(false);
    screen.update(Update::Connected(ours()));
    screen.update(answered(
        Kind::Status,
        json!({"schema_version": 2, "command": "status", "ok": false, "data": {
            "place": "decoy", "attention": attention, "hidden_root": "/mnt/data",
            "reason": "an interrupted activation left its runtime files in /run",
            "remediation": "Run `sudo /mnt/data/nails recover` to remove them"}}),
    ));
    assert_eq!(screen.asks(), vec![Ask::Status], "no check before it");
    screen
}

#[test]
fn an_interrupted_activation_is_cleaned_up_from_its_page() {
    let screen = decoy_with("interrupted");
    assert!(screen.shows(nails_gui::text::INTERRUPTED));
    assert_eq!(
        screen.labels(AccessibleRole::Button),
        ["Close", nails_gui::text::CLEAN_UP]
    );
    screen
        .find_with(nails_gui::text::CLEAN_UP, AccessibleRole::Button)
        .invoke_accessible_default_action();
    assert_eq!(screen.asks(), vec![Ask::Recover]);
    screen.update(Update::Running(Kind::Recover));
    assert_eq!(screen.labels(AccessibleRole::Button), ["Close"]);
    let busy = screen.with_role(AccessibleRole::ProgressIndicator);
    assert_eq!(
        busy[0].accessible_label().as_deref(),
        Some(nails_gui::text::CLEANING_UP)
    );
    screen.update(answered(
        Kind::Recover,
        json!({"schema_version": 2, "command": "recover", "ok": true, "data": {
            "outcome": "rolled_back", "remaining_mounts": [], "backend": []}}),
    ));
    assert_eq!(screen.asks(), vec![Ask::Status]);
    screen.update(answered(Kind::Status, fixture("status-decoy")));
    assert_eq!(screen.asks(), vec![Ask::Check(CheckArgs::default())]);
    assert!(screen.shows(nails_gui::text::CLEANED_UP));
}

#[test]
fn a_record_that_cannot_be_read_is_reset_from_its_page() {
    let screen = decoy_with("record_unreadable");
    assert!(screen.shows(nails_gui::text::RECORD_UNREADABLE));
    screen
        .find_with(nails_gui::text::RESET_RECORD, AccessibleRole::Button)
        .invoke_accessible_default_action();
    assert_eq!(screen.asks(), vec![Ask::Recover]);
    screen.update(Update::Running(Kind::Recover));
    screen.update(answered(
        Kind::Recover,
        json!({"schema_version": 2, "command": "recover", "ok": true, "data": {
            "outcome": "record_reset", "remaining_mounts": [], "backend": []}}),
    ));
    screen.update(answered(Kind::Status, fixture("status-decoy")));
    assert!(screen.shows(nails_gui::text::RECORD_RESET));
}
