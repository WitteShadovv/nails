// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The tools through the model: the rows that open them, each tool's asks
//! and pages from envelopes recorded from the real CLI (which the helper
//! answers with word for word), Back and Escape, and the plans of a discard
//! and a set up with their questions, typed word and apply.

use std::path::PathBuf;

use nails_api::CheckOutcome;
use nails_api::protocol::{
    DiscardPlanArgs, DiscardPlanData, InitArgs, InitPlanData, RehearsePlantArgs, RehearseScanArgs,
    VerifyArgs,
};
use serde_json::{Value, json};

use super::*;
use crate::client::{Answer, Plan, PlanData};
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
        "discard-refused" => include_str!("../../tests/fixtures/discard-refused.json"),
        "init-refused" => include_str!("../../tests/fixtures/init-refused.json"),
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
    assert_eq!(
        tools(&model),
        [
            ToolKind::Verify,
            ToolKind::Rehearsal,
            ToolKind::Discard,
            ToolKind::SetUp
        ]
    );
    assert_eq!(model.page().links[2].title, text::DISCARD);
    assert_eq!(model.page().links[2].subtitle, text::DISCARD_WHAT);
    // The engine refuses a discard in a hidden session, and the window
    // withholds Set Up there: the engine would run it. Settings change there.
    assert_eq!(
        tools(&hidden()),
        [ToolKind::Verify, ToolKind::Rehearsal, ToolKind::Settings]
    );

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
        "/tmp/scratch/ext4.img: 8.4\u{a0}MB read in full"
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

fn discard_plan(target: &str, removals: &[&str], nix: bool) -> Update {
    Update::Planned(PlanData::Discard(DiscardPlanData {
        target: target.to_string(),
        removals: removals.iter().map(|path| (*path).to_string()).collect(),
        resets_nix_store: nix,
        token: "d".repeat(32),
    }))
}

fn discarded(target: &str, removed: &[&str]) -> Value {
    json!({"schema_version": 2, "command": "discard", "ok": true,
        "data": {"target": target, "removed": removed}})
}

#[test]
fn a_discard_asks_for_a_full_path_and_says_exactly_what_goes() {
    let mut model = decoy();
    assert_eq!(open(&mut model, ToolKind::Discard), None);
    let page = model.page();
    let field = page.field.unwrap();
    assert_eq!(
        (field.label.as_str(), field.hint.as_str()),
        (text::FIELD_FOLDER, text::FOLDER_HINT)
    );
    assert_eq!(page.action, Some(text::DISCARD_ACTION));
    assert_eq!(page.action_kind, crate::model::ActionKind::Destructive);
    assert!(page.action_locked);
    assert_eq!(model.action(), None, "nothing to discard yet");

    model.edited("etc/apt");
    assert_eq!(model.page().field.unwrap().hint, text::FOLDER_NOT_ABSOLUTE);
    assert_eq!(model.action(), None, "the helper takes only a full path");
    model.edited("/etc/apt");
    assert!(!model.page().action_locked);
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Discard(DiscardPlanArgs {
            target: "/etc/apt".to_string(),
            allow_decoy_storage: false,
        }))))
    );
    model.apply(Update::Running(Kind::Plan));
    assert_eq!(model.page().busy.as_deref(), Some(text::LOOKING_AT_CHANGES));
    let removals = [
        "/mnt/data/root/upper/etc/apt",
        "/mnt/data/root/mounts/etc-apt",
    ];
    assert!(
        model
            .apply(discard_plan("/etc/apt", &removals, false))
            .is_empty()
    );
    let question = model.page().question.unwrap();
    assert_eq!(question.heading, text::DISCARD_QUESTION);
    assert_eq!(
        question.body.lines().collect::<Vec<_>>(),
        [
            text::discard_consequence("/etc/apt").as_str(),
            text::DISCARD_LIST,
            removals[0],
            removals[1],
        ]
    );
    assert!(question.destructive);
    assert_eq!(question.confirm, text::DELETE);
    assert_eq!(question.prompt, None, "no warning, no word to type");

    assert_eq!(model.answer(true), Some(Ask::Apply));
    model.apply(Update::Running(Kind::Apply));
    assert_eq!(model.page().busy.as_deref(), Some(text::DELETING));
    model.apply(answered(Kind::Apply, 0, discarded("/etc/apt", &removals)));
    let page = model.page();
    assert_eq!(page.heading, text::DISCARDED);
    assert_eq!(page.description, text::discarded("/etc/apt"));
    assert_eq!(
        words(&page.groups[0]),
        [text::DELETED_WORD, text::DELETED_WORD]
    );

    // Back brings the check again: what it finds may have changed.
    assert_eq!(model.back(), Some(Ask::Status));
    assert_eq!(model.apply(status("decoy", Value::Null)).len(), 1);
}

#[test]
fn a_discard_that_takes_a_home_or_nix_asks_for_the_folder_typed() {
    for (target, nix, home) in [
        ("/home", false, true),
        ("/home/alice/notes", false, true),
        ("/var", false, true),
        ("/nix", true, false),
    ] {
        let mut model = decoy();
        open(&mut model, ToolKind::Discard);
        model.edited(target);
        model.action();
        model.apply(discard_plan(target, &["/mnt/data/root/upper/x"], nix));
        let question = model.page().question.unwrap();
        assert_eq!(
            question.prompt.as_deref(),
            Some(text::discard_type(target, home).as_str()),
            "{target}"
        );
        assert!(question.locked, "{target}");
        assert_eq!(question.body.contains(text::DISCARD_NIX), nix, "{target}");
        // Delete waits for the folder; without it the answer withdraws.
        model.typed("/hom");
        assert!(model.page().question.unwrap().locked);
        model.typed(&format!(" {target}/ "));
        assert!(!model.page().question.unwrap().locked, "{target}");
        assert_eq!(model.answer(true), Some(Ask::Apply), "{target}");
    }
    let mut model = decoy();
    open(&mut model, ToolKind::Discard);
    model.edited("/home");
    model.action();
    model.apply(discard_plan("/home", &["/mnt/data/root/upper/home"], false));
    assert_eq!(model.answer(true), Some(Ask::Withdraw), "not typed");
}

#[test]
fn a_discard_with_nothing_to_delete_or_refused_says_so() {
    let mut model = decoy();
    open(&mut model, ToolKind::Discard);
    model.edited("/srv/notes");
    model.action();
    model.apply(answered(Kind::Plan, 0, discarded("/srv/notes", &[])));
    let page = model.page();
    assert_eq!(page.note, text::nothing_to_discard("/srv/notes"));
    assert_eq!(page.question, None);
    assert_eq!(model.back(), Some(Ask::Status));
    assert!(
        model.apply(status("decoy", Value::Null)).is_empty(),
        "nothing changed, so the check stands"
    );

    let mut model = decoy();
    open(&mut model, ToolKind::Discard);
    model.edited("/etc/apt");
    model.action();
    model.apply(answered(Kind::Plan, 4, fixture("discard-refused")));
    let page = model.page();
    assert_eq!(page.heading, text::NOT_DISCARDED);
    assert!(
        page.note
            .starts_with("/mnt/data is not a volume of its own"),
        "{}",
        page.note
    );
    assert_eq!(page.field.unwrap().text, "/etc/apt", "the folder stays");
}

#[test]
fn an_apply_that_failed_says_so_and_a_cancel_withdraws() {
    let mut model = decoy();
    open(&mut model, ToolKind::Discard);
    model.edited("/etc/apt");
    model.action();
    model.apply(discard_plan(
        "/etc/apt",
        &["/mnt/data/root/upper/etc/apt"],
        false,
    ));
    assert_eq!(model.answer(false), Some(Ask::Withdraw));
    model.apply(Update::Withdrawn);
    assert_eq!(model.page().question, None);
    assert_eq!(model.page().view, View::Tool(ToolKind::Discard));

    model.action();
    model.apply(discard_plan(
        "/etc/apt",
        &["/mnt/data/root/upper/etc/apt"],
        false,
    ));
    model.answer(true);
    model.apply(answered(
        Kind::Apply,
        1,
        json!({"schema_version": 2, "command": "discard", "ok": false, "error": {
            "code": "discard", "message": "Permission denied", "next": null}}),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::DISCARD_FAILED);
    assert!(page.urgent);
    assert_eq!(page.note, "Permission denied.");
}

fn init_plan(warnings: &[&str]) -> Update {
    Update::Planned(PlanData::Init(InitPlanData {
        path: "/mnt/data".to_string(),
        hardware_config: Some("/etc/nixos/hardware-configuration.nix".to_string()),
        skipped: None,
        warnings: warnings.iter().map(|w| (*w).to_string()).collect(),
        token: "e".repeat(32),
    }))
}

#[test]
fn set_up_plans_asks_and_lists_each_part_it_wrote() {
    let mut model = decoy();
    assert_eq!(open(&mut model, ToolKind::SetUp), None);
    let page = model.page();
    assert_eq!(page.heading, text::SET_UP);
    assert_eq!(page.description, text::set_up_what("/mnt/data"));
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Init(InitArgs {
            path: "/mnt/data".to_string(),
            allow_decoy_storage: false,
            hardware_config: None,
            no_hardware_config: false,
        }))))
    );
    model.apply(Update::Running(Kind::Plan));
    assert_eq!(model.page().busy.as_deref(), Some(text::CHECKING_VOLUME));
    model.apply(init_plan(&["NAILS was not tested on this release"]));
    let question = model.page().question.unwrap();
    assert_eq!(question.heading, text::SET_UP_QUESTION);
    assert_eq!(
        question.body.lines().collect::<Vec<_>>(),
        [
            text::set_up_consequence("/mnt/data").as_str(),
            text::set_up_nixos("/etc/nixos/hardware-configuration.nix").as_str(),
            "NAILS was not tested on this release.",
        ]
    );
    assert!(!question.destructive);
    assert_eq!(model.answer(true), Some(Ask::Apply));
    model.apply(Update::Running(Kind::Apply));
    assert_eq!(model.page().busy.as_deref(), Some(text::SETTING_UP));
    model.apply(answered(
        Kind::Apply,
        0,
        json!({"schema_version": 2, "command": "init", "ok": true, "data": {
            "root": "/mnt/data",
            "items": [
                {"path": "/mnt/data/logs", "status": "created"},
                {"path": "/mnt/data/config/nails.toml", "status": "already_present"}],
            "notes": ["host 'debian' has no NixOS config layer (overlay-only); skipping the hidden NixOS layout"],
            "next_steps": ["check readiness"]}}),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::SET_UP_DONE);
    assert_eq!(page.description, text::set_up_done("/mnt/data"));
    assert_eq!(
        titles(&page.groups),
        [text::GROUP_NOTES, text::GROUP_LAYOUT]
    );
    assert_eq!(
        words(&page.groups[1]),
        [text::CREATED_WORD, text::ALREADY_THERE]
    );
    assert_eq!(page.fix, text::SET_UP_NEXT);
    assert_eq!(page.action, None);
    assert_eq!(model.back(), Some(Ask::Status));
    assert_eq!(
        model.apply(status("decoy", Value::Null)).len(),
        1,
        "the check runs again"
    );
}

#[test]
fn a_set_up_the_engine_refused_says_why_and_can_be_asked_again() {
    let mut model = Model::new(Some(PathBuf::from("/mnt/stick/nails")), false);
    model.apply(Update::Connected(crate::client::ours()));
    model.apply(answered(
        Kind::Status,
        0,
        json!({"schema_version": 2, "command": "status", "ok": true, "data": {
            "place": "decoy", "attention": null}}),
    ));
    model.apply(ready());
    open(&mut model, ToolKind::SetUp);
    // Without a hidden volume in the status, the engine's own folder.
    assert_eq!(model.page().description, text::set_up_what("/mnt/stick"));
    model.action();
    model.apply(answered(Kind::Plan, 4, fixture("init-refused")));
    let page = model.page();
    assert_eq!(page.heading, text::SET_UP_FAILED);
    assert!(
        page.note
            .starts_with("/mnt/data is not a volume of its own")
    );
    assert_eq!(page.action, Some(text::SET_UP_ACTION));
    // A plan the tool did not ask for is dropped.
    model.action();
    assert_eq!(
        model.apply(discard_plan("/etc", &[], false)),
        vec![Ask::Withdraw]
    );
}

#[test]
fn a_folder_written_another_way_is_planned_and_asked_for_as_the_engine_reads_it() {
    for (typed, canonical) in [
        ("//home", "/home"),
        ("/./home", "/home"),
        ("/var//home", "/var/home"),
        ("/./var", "/var"),
        ("//root", "/root"),
        ("/home/alice/./notes/", "/home/alice/notes"),
    ] {
        let mut model = decoy();
        open(&mut model, ToolKind::Discard);
        model.edited(typed);
        assert_eq!(
            model.action(),
            Some(Effect::Ask(Ask::Plan(Plan::Discard(DiscardPlanArgs {
                target: canonical.to_string(),
                allow_decoy_storage: false,
            })))),
            "{typed}"
        );
        // The helper names the target the window sent.
        model.apply(discard_plan(canonical, &["/mnt/data/root/upper/x"], false));
        let question = model.page().question.unwrap();
        assert!(question.locked, "{typed}: it holds a home");
        assert_eq!(
            question.prompt.as_deref(),
            Some(text::discard_type(canonical, true).as_str()),
            "{typed}"
        );
        assert_eq!(
            model.answer(true),
            Some(Ask::Withdraw),
            "{typed}: not typed"
        );
    }
    // A plan that names a home in another spelling still asks for it.
    for target in ["//home", "/./var", "/var//home", "//root/"] {
        assert!(holds_a_home(target), "{target}");
    }
    // The engine refuses a `..`, so the window sends none.
    assert_eq!(canonical_folder("/etc/../home"), None);
    assert!(is_the_folder("/home", "//home/"));
}

#[test]
fn discard_and_set_up_fail_closed_where_the_two_readings_disagree() {
    // The window's own reading says hidden session, the status the decoy.
    let mut model =
        Model::new(Some(PathBuf::from("/mnt/data/nails")), false).in_hidden_session(true);
    model.apply(Update::Connected(crate::client::ours()));
    model.apply(status("decoy", Value::Null));
    model.apply(ready());
    let tools: Vec<ToolKind> = model.page().links.iter().map(|link| link.tool).collect();
    assert_eq!(
        tools,
        [ToolKind::Verify, ToolKind::Rehearsal, ToolKind::Settings]
    );

    // A status that turns to a hidden session under an open tool.
    let mut model = decoy();
    open(&mut model, ToolKind::Discard);
    model.edited("/etc/apt");
    model.apply(status("hidden", Value::Null));
    assert_eq!(model.page().action, None);
    assert_eq!(model.tool_action(text::DISCARD_ACTION), None);
    let mut model = decoy();
    open(&mut model, ToolKind::SetUp);
    model.apply(status("hidden", Value::Null));
    assert_eq!(model.page().action, None);
    assert_eq!(model.tool_action(text::SET_UP_ACTION), None);
}

#[test]
fn a_folder_is_typed_as_written_and_a_home_is_known_by_its_place() {
    assert!(is_the_folder("/home", "/home"));
    assert!(is_the_folder("/home", "  /home/ "));
    assert!(!is_the_folder("/home", "/Home"));
    assert!(!is_the_folder("/home", "/home/alice"));
    assert!(!is_the_folder("", ""));
    for home in [
        "/home",
        "/home/alice",
        "/root",
        "/var/home/bob",
        "/var",
        "/home/",
    ] {
        assert!(holds_a_home(home), "{home}");
    }
    for other in ["/etc/apt", "/homework", "/var/lib", "/nix", "/rootfs"] {
        assert!(!holds_a_home(other), "{other}");
    }
    for folder in ["/etc/apt", " /srv/notes "] {
        assert!(valid_folder(folder), "{folder}");
    }
    for folder in ["", "etc", "/", "/etc/\napt", " "] {
        assert!(!valid_folder(folder), "{folder:?}");
    }
}
