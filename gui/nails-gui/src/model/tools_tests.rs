// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The tools through the model: the rows that open them, each tool's asks
//! and pages from envelopes recorded from the real CLI (which the helper
//! answers with word for word), and Back and Escape.

use std::path::PathBuf;

use nails_api::CheckOutcome;
use nails_api::protocol::{RehearsePlantArgs, RehearseScanArgs, VerifyArgs};
use serde_json::{Value, json};

use super::*;
use crate::client::Answer;
use crate::model::{Group, View};
use crate::worker::{Ask, Kind, Rehearse, Update};

fn fixture(name: &str) -> Value {
    let text = match name {
        "verify-findings" => include_str!("../../tests/fixtures/verify-findings.json"),
        "verify-clean" => include_str!("../../tests/fixtures/verify-clean.json"),
        "verify-live" => include_str!("../../tests/fixtures/verify-live.json"),
        "rehearse-status-none" => include_str!("../../tests/fixtures/rehearse-status-none.json"),
        "rehearse-status-planted" => {
            include_str!("../../tests/fixtures/rehearse-status-planted.json")
        }
        "rehearse-scan-found" => include_str!("../../tests/fixtures/rehearse-scan-found.json"),
        "rehearse-scan-blind" => include_str!("../../tests/fixtures/rehearse-scan-blind.json"),
        "rehearse-scan-clean" => include_str!("../../tests/fixtures/rehearse-scan-clean.json"),
        "rehearse-scan-incomplete" => {
            include_str!("../../tests/fixtures/rehearse-scan-incomplete.json")
        }
        other => panic!("no fixture {other}"),
    };
    serde_json::from_str(text).unwrap()
}

fn answered(kind: Kind, exit: u8, envelope: Value) -> Update {
    Update::Answered(kind, Answer { exit, envelope })
}

fn status(place: &str, attention: Value) -> Update {
    answered(
        Kind::Status,
        0,
        json!({"schema_version": 2, "command": "status", "ok": true, "data": {
            "place": place, "attention": attention, "hidden_root": "/mnt/data"}}),
    )
}

fn ready() -> Update {
    answered(
        Kind::Check,
        0,
        json!({"schema_version": 2, "command": "check", "ok": true, "data": {
            "ready": true, "checks": [], "summary": {"passed": 3, "warnings": 0, "failed": 0}}}),
    )
}

/// A decoy's window whose check passed.
fn decoy() -> Model {
    let mut model = Model::new(Some(PathBuf::from("/mnt/data/nails")), false);
    model.apply(Update::Connected(crate::client::ours()));
    assert_eq!(model.apply(status("decoy", Value::Null)).len(), 1);
    model.apply(ready());
    model
}

/// A hidden session's window.
fn hidden() -> Model {
    let mut model =
        Model::new(Some(PathBuf::from("/mnt/data/nails")), false).in_hidden_session(true);
    model.apply(Update::Connected(crate::client::ours()));
    assert!(model.apply(status("hidden", Value::Null)).is_empty());
    model
}

/// Open `tool` from the session page's rows: what it asks for first.
fn open(model: &mut Model, tool: ToolKind) -> Option<Ask> {
    let index = model
        .page()
        .links
        .iter()
        .position(|link| link.tool == tool)
        .unwrap_or_else(|| panic!("{tool:?} is offered"));
    let first = model.open(index);
    assert_eq!(model.page().view, View::Tool(tool));
    first
}

fn titles(groups: &[Group]) -> Vec<&str> {
    groups.iter().map(|group| group.title.as_str()).collect()
}

fn words(group: &Group) -> Vec<&str> {
    group.rows.iter().map(|row| row.word.as_str()).collect()
}

#[test]
fn a_settled_session_page_offers_the_tools_of_its_side() {
    let tools = |model: &Model| -> Vec<ToolKind> {
        model.page().links.iter().map(|link| link.tool).collect()
    };
    let model = decoy();
    assert_eq!(tools(&model), [ToolKind::Verify, ToolKind::Rehearsal]);
    assert_eq!(model.page().links[1].title, text::REHEARSAL);
    assert_eq!(model.page().links[1].subtitle, text::REHEARSAL_WHAT);
    assert_eq!(tools(&hidden()), [ToolKind::Verify, ToolKind::Rehearsal]);

    // None while the check runs, nor while anything runs.
    let mut model = Model::new(Some(PathBuf::from("/mnt/data/nails")), false);
    model.apply(Update::Connected(crate::client::ours()));
    model.apply(status("decoy", Value::Null));
    assert!(model.page().links.is_empty(), "the check runs");
    let mut model = hidden();
    model.apply(Update::Running(Kind::Status));
    assert!(model.page().links.is_empty());
    // None where something else comes first, or without the hidden volume.
    let mut model = Model::new(Some(PathBuf::from("/mnt/data/nails")), false);
    model.apply(Update::Connected(crate::client::ours()));
    model.apply(status("decoy", json!("interrupted")));
    assert!(model.page().links.is_empty());
    let mut model = hidden();
    model.apply(status("hidden", json!("volume_lost")));
    assert!(model.page().links.is_empty());
    model.apply(status("hidden", json!("no_way_back")));
    assert!(model.page().links.is_empty());
}

#[test]
fn verify_runs_standard_or_deep_and_shows_what_it_found_and_did_not_check() {
    let mut model = hidden();
    assert_eq!(
        open(&mut model, ToolKind::Verify),
        None,
        "it waits for the person"
    );
    let page = model.page();
    assert_eq!(page.heading, text::VERIFY);
    assert_eq!(page.description, text::VERIFY_WHAT);
    assert!(page.back);
    assert!(
        page.emergency,
        "the Emergency control stays on a tool's page"
    );
    assert_eq!(
        (page.action, page.secondary),
        (Some(text::VERIFY), Some(text::DEEP_SCAN))
    );

    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Verify(VerifyArgs::default())))
    );
    model.apply(Update::Running(Kind::Verify));
    let page = model.page();
    assert_eq!(page.heading, text::VERIFYING);
    assert_eq!(page.busy.as_deref(), Some(text::LOOKING_FOR_TRACES));
    assert_eq!(
        (page.action, page.secondary, page.back),
        (None, None, false)
    );
    assert_eq!(model.back(), None, "Back waits for the answer");

    model.apply(answered(Kind::Verify, 11, fixture("verify-findings")));
    let page = model.page();
    assert_eq!(page.heading, text::TRACES_FOUND);
    assert!(page.urgent);
    assert_eq!(page.description, text::traces_found(2));
    assert_eq!(
        titles(&page.groups),
        [text::GROUP_FOUND, text::GROUP_NOT_CHECKED_RUN]
    );
    // The trace first, then what may be one, each with the engine's fix.
    assert_eq!(
        words(&page.groups[0]),
        [text::SEVERITY_CRITICAL, text::SEVERITY_WARN]
    );
    assert_eq!(page.groups[0].rows[0].outcome, CheckOutcome::Fail);
    assert_eq!(
        page.groups[0].rows[0].message,
        "Artifact file found: /mnt/nails-pivot."
    );
    assert_eq!(
        page.groups[0].rows[0].fix,
        "Fix: Trace on the decoy filesystem; remove it: rm -rf /mnt/nails-pivot"
    );
    // Every area the run did not check, as the engine lists it.
    assert_eq!(page.groups[1].rows.len(), 20);
    assert_eq!(
        page.groups[1].rows[0].message,
        "The systemd journal (not searched by verify)."
    );
    assert_eq!(page.action, Some(text::VERIFY_AGAIN));

    assert_eq!(
        model.secondary(),
        Some(Effect::Ask(Ask::Verify(VerifyArgs {
            deep: true,
            ..VerifyArgs::default()
        })))
    );
    model.apply(Update::Running(Kind::Verify));
    assert_eq!(model.page().note, text::DEEP_SCAN_WHAT);
}

#[test]
fn a_clean_verify_is_no_proof_and_still_lists_what_it_did_not_check() {
    let mut model = hidden();
    open(&mut model, ToolKind::Verify);
    model.action();
    model.apply(answered(Kind::Verify, 0, fixture("verify-clean")));
    let page = model.page();
    assert_eq!(page.heading, text::NO_KNOWN_TRACES);
    assert!(!page.urgent);
    assert_eq!(
        page.description,
        "A standard scan of 2 checks found no known trace. This is not proof that there is none."
    );
    assert_eq!(titles(&page.groups), [text::GROUP_NOT_CHECKED_RUN]);
    assert!(
        page.groups[0]
            .rows
            .iter()
            .all(|row| row.word == text::NOT_CHECKED)
    );

    // Possible traces count what is no note.
    model.apply(answered(Kind::Verify, 10, fixture("verify-live")));
    let page = model.page();
    assert_eq!(page.heading, text::POSSIBLE_TRACES);
    assert_eq!(page.description, text::possible_traces(1));
    assert_eq!(page.groups[0].rows[0].word, text::SEVERITY_WARN);
    assert_eq!(
        page.groups[0].rows.last().unwrap().word,
        text::SEVERITY_NOTE
    );
}

#[test]
fn a_verify_that_could_not_run_says_why() {
    let mut model = hidden();
    open(&mut model, ToolKind::Verify);
    model.action();
    model.apply(answered(
        Kind::Verify,
        1,
        json!({"schema_version": 2, "command": "verify", "ok": false, "error": {
            "code": "verify_error", "message": "Error running verification: no /proc",
            "next": null}}),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::VERIFY_FAILED);
    assert_eq!(page.note, "Error running verification: no /proc.");
    assert_eq!(page.action, Some(text::VERIFY_AGAIN));
    // An answer the window cannot read is said as such.
    model.apply(answered(Kind::Verify, 0, json!({"command": "verify"})));
    assert_eq!(model.page().heading, text::VERIFY_FAILED);
}

#[test]
fn back_and_escape_leave_a_tool_and_bring_the_session_page_up_to_date() {
    let mut model = decoy();
    open(&mut model, ToolKind::Verify);
    assert_eq!(model.escape(), Some(Effect::Ask(Ask::Status)));
    assert_eq!(model.page().view, View::Session);
    assert_eq!(model.open_tool(), None);
    // The check stands: Verify changed nothing.
    assert!(model.apply(status("decoy", Value::Null)).is_empty());
    assert_eq!(model.page().heading, text::READY);

    open(&mut model, ToolKind::Verify);
    assert_eq!(model.back(), Some(Ask::Status));
    assert_eq!(model.back(), None, "nothing is open any more");
}

#[test]
fn a_rehearsal_in_a_hidden_session_plants_and_says_what_comes_next() {
    let mut model = hidden();
    assert_eq!(
        open(&mut model, ToolKind::Rehearsal),
        Some(Ask::Rehearse(Rehearse::Status))
    );
    model.apply(Update::Running(Kind::Rehearse));
    assert_eq!(model.page().busy.as_deref(), Some(text::READING_REHEARSAL));
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-status-none")));
    let page = model.page();
    assert_eq!(page.heading, text::REHEARSAL);
    let states: Vec<&str> = page.steps.iter().map(|step| step.state).collect();
    assert_eq!(states, [text::STEP_NOW, text::STEP_NEXT, text::STEP_NEXT]);
    assert_eq!(page.action, Some(text::PLANT));
    assert_eq!(page.secondary, None);

    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Rehearse(Rehearse::Plant(
            RehearsePlantArgs::default()
        ))))
    );
    model.apply(Update::Running(Kind::Rehearse));
    assert_eq!(model.page().busy.as_deref(), Some(text::PLANTING));
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::PLANTED);
    assert_eq!(page.description, text::planted_in(5));
    assert_eq!(
        titles(&page.groups),
        [text::GROUP_PLANTED, text::GROUP_NOT_TESTED]
    );
    assert_eq!(
        page.groups[0].rows[0].message,
        "File in a system folder: /etc/(test words)"
    );
    assert_eq!(
        page.groups[1].rows[0].message,
        "Desktop notification: no session bus to send it on"
    );
    let states: Vec<&str> = page.steps.iter().map(|step| step.state).collect();
    assert_eq!(states, [text::STEP_DONE, text::STEP_NOW, text::STEP_NEXT]);
    assert_eq!(page.fix, text::AFTER_PLANT);
    // No scan in the session that planted: the engine would refuse it.
    assert_eq!(page.action, None);
}

#[test]
fn a_rehearsal_on_the_decoy_scans_and_removes_but_never_plants() {
    let mut model = decoy();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-status-none")));
    let page = model.page();
    assert_eq!(page.action, None);
    assert_eq!(page.fix, text::REHEARSAL_STARTS_HIDDEN);
    assert_eq!(model.tool_action(text::PLANT), None);

    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::REHEARSAL);
    assert_eq!(
        (page.action, page.secondary),
        (Some(text::SCAN), Some(text::REMOVE_TEST_WORDS))
    );
    assert_eq!(page.fix, text::REHEARSAL_PLANTED_DECOY);
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Rehearse(Rehearse::Scan(
            RehearseScanArgs::default()
        ))))
    );
    model.apply(Update::Running(Kind::Rehearse));
    let page = model.page();
    assert_eq!(page.heading, text::SCANNING);
    assert_eq!(page.description, text::SCAN_HOW_LONG);
    assert_eq!(page.busy.as_deref(), Some(text::READING_DISKS));

    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-scan-clean")));
    assert_eq!(
        model.secondary(),
        Some(Effect::Ask(Ask::Rehearse(Rehearse::Reset)))
    );
    model.apply(answered(
        Kind::Rehearse,
        0,
        json!({"schema_version": 2, "command": "rehearse", "ok": true, "data": {
            "phase": "none", "fingerprint": "012345\u{2026}", "channels": [],
            "removed": ["/mnt/data/rehearse/state.json", "/mnt/data/root/upper/etc/<canary>"],
            "next_step": "Step 1 of 3: activate a hidden session, then run `sudo /mnt/data/nails rehearse plant`."}}),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::TEST_WORDS_REMOVED);
    assert_eq!(
        page.groups[0].rows[1].message,
        "/mnt/data/root/upper/etc/(test words)"
    );
    assert!(page.steps.is_empty(), "the result takes the steps' place");
}

#[test]
fn a_scan_that_found_the_test_words_says_where_first() {
    let mut model = decoy();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    model.action();
    model.apply(answered(Kind::Rehearse, 11, fixture("rehearse-scan-found")));
    let page = model.page();
    assert_eq!(page.heading, text::TEST_WORDS_FOUND);
    assert!(page.urgent);
    assert_eq!(
        page.description,
        text::test_words_found("/tmp/scratch/hit.img", 524_288)
    );
    assert_eq!(
        titles(&page.groups),
        [
            text::GROUP_DISKS,
            text::GROUP_NOT_CHECKED_SCAN,
            text::GROUP_NOT_TESTED
        ]
    );
    assert_eq!(page.groups[0].rows[0].word, text::FOUND_WORD);
    assert_eq!(
        page.groups[0].rows[0].message,
        "/tmp/scratch/hit.img, byte 524288"
    );
    assert_eq!(page.action, Some(text::SCAN_AGAIN));
}

#[test]
fn a_scan_whose_disk_can_hide_the_test_words_is_never_a_pass() {
    let mut model = decoy();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    model.action();
    model.apply(answered(Kind::Rehearse, 9, fixture("rehearse-scan-blind")));
    let page = model.page();
    assert_eq!(page.heading, text::NOT_A_CLEAN_RESULT);
    assert_eq!(page.description, text::blind_spots(1));
    // What the scan did not check comes first: that disk, then each blind
    // spot of every such scan.
    assert_eq!(page.groups[0].title, text::GROUP_NOT_CHECKED_SCAN);
    let first = &page.groups[0].rows[0];
    assert_eq!(first.word, text::NOT_CHECKED);
    assert_eq!(first.outcome, CheckOutcome::Warn);
    assert!(
        first
            .message
            .starts_with("/tmp/scratch/plain.img: The scan identifies no filesystem here"),
        "{}",
        first.message
    );
    assert_eq!(page.groups[0].rows.len(), 1 + 6);
    assert!(
        page.groups
            .iter()
            .all(|group| group.title != text::GROUP_DISKS),
        "the disk is not listed as read"
    );
    for group in &page.groups {
        for row in &group.rows {
            assert_ne!(row.word, text::READ_WORD);
        }
    }
}

#[test]
fn a_scan_reads_as_a_pass_only_when_the_engine_and_every_disk_say_so() {
    let mut model = decoy();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    model.action();
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-scan-clean")));
    let page = model.page();
    assert_eq!(page.heading, text::PASSED);
    assert_eq!(page.description, text::passed(1, 8_388_608));
    assert_eq!(
        titles(&page.groups),
        [
            text::GROUP_NOT_CHECKED_SCAN,
            text::GROUP_DISKS,
            text::GROUP_NOT_TESTED
        ]
    );
    assert_eq!(page.groups[0].rows.len(), 6, "every blind spot of the scan");
    assert_eq!(
        page.groups[1].rows[0].message,
        "/tmp/scratch/ext4.img: 8.4 MB read in full"
    );

    // A disk not read in full makes it incomplete.
    model.action();
    model.apply(answered(
        Kind::Rehearse,
        9,
        fixture("rehearse-scan-incomplete"),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::SCAN_INCOMPLETE);
    assert_eq!(page.description, text::incomplete(1));
    assert_eq!(
        words(&page.groups[1]),
        [text::READ_WORD, text::INCOMPLETE_WORD]
    );

    // The same clean disks, but the engine did not end it clean: no pass.
    model.action();
    model.apply(answered(Kind::Rehearse, 9, fixture("rehearse-scan-clean")));
    assert_eq!(model.page().heading, text::NOT_A_CLEAN_RESULT);
    assert_eq!(model.page().description, text::NOT_CLEAN_UNEXPLAINED);
}

#[test]
fn a_scan_refused_in_the_planting_session_offers_no_scan_until_it_ended() {
    let mut model = hidden();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    assert_eq!(model.page().action, Some(text::SCAN));
    assert_eq!(model.page().secondary, None, "no reset in a hidden session");
    assert_eq!(model.tool_action(text::REMOVE_TEST_WORDS), None);
    model.action();
    model.apply(answered(
        Kind::Rehearse,
        6,
        json!({"schema_version": 2, "command": "rehearse", "ok": false, "error": {
            "code": "same_boot", "message": "the canary was planted in this session",
            "next": null}}),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::SCAN_FAILED);
    assert_eq!(page.note, text::REHEARSAL_SAME_SESSION);
    assert_eq!(page.action, None);
    assert_eq!(page.fix, text::AFTER_PLANT);
    // Closed and opened again, the page still knows.
    assert_eq!(model.back(), Some(Ask::Status));
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    let page = model.page();
    assert_eq!(page.action, None, "no scan in the session that planted");
    assert_eq!(page.fix, text::AFTER_PLANT);

    // Any other refusal is said in the engine's words.
    let mut model = hidden();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-status-none")));
    model.action();
    model.apply(answered(
        Kind::Rehearse,
        6,
        json!({"schema_version": 2, "command": "rehearse", "ok": false, "error": {
            "code": "not_active", "message": "no hidden session is active",
            "next": null}}),
    ));
    assert_eq!(model.page().note, "No hidden session is active.");
    assert_eq!(model.page().action, Some(text::PLANT));
}

#[test]
fn a_plant_is_remembered_when_the_page_opens_again_in_its_session() {
    let mut model = hidden();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-status-none")));
    model.action();
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    assert_eq!(model.back(), Some(Ask::Status));
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    let page = model.page();
    let states: Vec<&str> = page.steps.iter().map(|step| step.state).collect();
    assert_eq!(states, [text::STEP_DONE, text::STEP_NOW, text::STEP_NEXT]);
    assert_eq!(page.action, None);
    assert_eq!(page.fix, text::AFTER_PLANT);
    assert!(!page.fix.contains("decoy"), "{}", page.fix);
    // A rehearsal removed since is no rehearsal of this session's.
    model.back();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-status-none")));
    model.back();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    assert_eq!(model.page().action, Some(text::SCAN));
}

#[test]
fn a_scan_that_could_not_run_never_reads_as_the_scan_before_it() {
    let mut model = decoy();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    model.action();
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-scan-clean")));
    assert_eq!(model.page().heading, text::PASSED);
    model.action();
    model.apply(answered(
        Kind::Rehearse,
        6,
        json!({"schema_version": 2, "command": "rehearse", "ok": false, "error": {
            "code": "no_token", "message": "no rehearsal state under /mnt/data",
            "next": null}}),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::SCAN_FAILED);
    assert!(page.urgent);
    assert_eq!(page.description, text::REHEARSAL_WHAT);
    assert_eq!(page.note, "No rehearsal state under /mnt/data.");
    assert!(page.groups.is_empty(), "nothing of the scan before");
    assert_eq!(page.action, Some(text::SCAN_AGAIN));
    // An answer the window cannot read is no verdict either.
    model.action();
    model.apply(answered(Kind::Rehearse, 0, json!({"command": "rehearse"})));
    assert_eq!(model.page().heading, text::SCAN_FAILED);
    // Nor a reset that failed.
    model.secondary();
    model.apply(answered(
        Kind::Rehearse,
        1,
        json!({"schema_version": 2, "command": "rehearse", "ok": false, "error": {
            "code": "reset", "message": "Permission denied", "next": null}}),
    ));
    assert_eq!(model.page().heading, text::REMOVE_FAILED);
    assert_eq!(model.page().note, "Permission denied.");
}

#[test]
fn a_hidden_sessions_page_gives_the_line_that_removes_the_test_words() {
    let mut model = hidden();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    assert_eq!(model.page().fix, text::REHEARSAL_PLANTED);
    model.action();
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-scan-clean")));
    let page = model.page();
    assert_eq!(page.secondary, None, "no reset in a hidden session");
    assert_eq!(
        page.fix.lines().collect::<Vec<_>>(),
        [
            text::REHEARSAL_SCANNED,
            "Once you are done, remove the test words on the decoy, with the hidden volume \
             mounted: sudo /mnt/data/nails rehearse reset",
        ]
    );
}

#[test]
fn a_rehearsal_whose_status_failed_offers_nothing_but_back() {
    let mut model = hidden();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        6,
        json!({"schema_version": 2, "command": "rehearse", "ok": false, "error": {
            "code": "rehearse_state", "message": "the rehearsal state is unreadable",
            "next": null}}),
    ));
    let page = model.page();
    assert_eq!(page.note, "The rehearsal state is unreadable.");
    assert_eq!(page.action, None);
    assert!(page.back);
}
