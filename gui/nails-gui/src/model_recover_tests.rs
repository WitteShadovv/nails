// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Clean Up and Reset Record through the model: both run `recover`, say what
//! it did over the status that follows, and the check runs once the decoy
//! has nothing more to deal with.

use super::*;
use crate::client::Answer;
use nails_api::protocol::CheckArgs;
use serde_json::{Value, json};

fn answered(kind: Kind, exit: u8, envelope: Value) -> Update {
    Update::Answered(kind, Answer { exit, envelope })
}

fn status(attention: Value) -> Update {
    answered(
        Kind::Status,
        0,
        json!({"schema_version": 2, "command": "status", "ok": true, "data": {
            "place": "decoy", "attention": attention, "hidden_root": "/mnt/data"}}),
    )
}

fn on(attention: &str) -> Model {
    let mut model = Model::new(Some(PathBuf::from("/mnt/data/nails")), false);
    model.apply(Update::Connected(crate::client::ours()));
    assert!(model.apply(status(json!(attention))).is_empty());
    model
}

fn recovered(data: Value) -> Update {
    let ok = data["remaining_mounts"]
        .as_array()
        .is_none_or(|mounts| mounts.is_empty());
    answered(
        Kind::Recover,
        if ok { 0 } else { 7 },
        json!({"schema_version": 2, "command": "recover", "ok": ok, "data": data}),
    )
}

#[test]
fn clean_up_runs_recover_and_the_check_follows() {
    let mut model = on("interrupted");
    assert_eq!(model.action(), Some(Effect::Ask(Ask::Recover)));
    model.apply(Update::Running(Kind::Recover));
    let page = model.page();
    assert_eq!(page.busy.as_deref(), Some("Cleaning Up"));
    assert_eq!(page.action, None, "nothing to press while it runs");

    let asks = model.apply(recovered(
        json!({"outcome": "rolled_back", "remaining_mounts": [], "backend": [
            {"name": "cargo", "state": "closed"}]}),
    ));
    assert_eq!(asks, vec![Ask::Status]);
    assert_eq!(
        model.apply(status(Value::Null)),
        vec![Ask::Check(CheckArgs::default())],
        "the decoy is idle now, so its check runs"
    );
    let page = model.page();
    assert_eq!(page.heading, text::CHECKING);
    assert_eq!(page.note, text::CLEANED_UP);
}

#[test]
fn what_a_clean_up_had_to_leave_is_said_without_a_device_name() {
    let mut model = on("interrupted");
    model.action();
    model.apply(recovered(json!({
        "outcome": "rolled_back",
        "remaining_mounts": ["/run/nextroot/home"],
        "backend": [{"name": "cargo", "state": "in_use"}],
    })));
    model.apply(status(Value::Null));
    let note = model.page().note;
    assert_eq!(
        note.lines().collect::<Vec<_>>(),
        [
            text::CLEANED_UP,
            "Still mounted until this computer restarts: /run/nextroot/home.",
            text::DEVICE_IN_USE,
        ]
    );
    assert!(!note.contains("cargo"), "{note}");
}

#[test]
fn reset_record_runs_recover_and_says_the_record_was_reset() {
    let mut model = on("record_unreadable");
    assert_eq!(model.page().action, Some(text::RESET_RECORD));
    assert_eq!(model.action(), Some(Effect::Ask(Ask::Recover)));
    model.apply(Update::Running(Kind::Recover));
    assert_eq!(model.page().busy.as_deref(), Some("Resetting the Record"));
    model.apply(recovered(
        json!({"outcome": "record_reset", "remaining_mounts": [], "backend": []}),
    ));
    model.apply(status(Value::Null));
    assert_eq!(model.page().note, text::RECORD_RESET);
}

#[test]
fn a_recovery_the_engine_refuses_says_why_and_the_status_follows() {
    let mut model = on("interrupted");
    model.action();
    let asks = model.apply(answered(
        Kind::Recover,
        6,
        json!({"schema_version": 2, "command": "recover", "ok": false, "error": {
            "code": "invalid_state", "message": "an activation is entering the hidden root right now",
            "next": null}}),
    ));
    assert_eq!(asks, vec![Ask::Status]);
    model.apply(status(json!("interrupted")));
    let page = model.page();
    assert_eq!(page.heading, text::INTERRUPTED);
    assert_eq!(
        page.note,
        "An activation is entering the hidden root right now."
    );
    assert_eq!(page.action, Some(text::CLEAN_UP));

    // An answer the window cannot read is said as such.
    let mut model = on("interrupted");
    model.action();
    model.apply(answered(Kind::Recover, 0, json!({"command": "recover"})));
    model.apply(status(Value::Null));
    assert!(
        model
            .page()
            .note
            .starts_with("The recover answer is not an envelope"),
        "{}",
        model.page().note
    );
}

#[test]
fn a_clean_up_with_nothing_left_says_so() {
    let mut model = on("interrupted");
    model.action();
    model.apply(recovered(
        json!({"outcome": "clean", "remaining_mounts": [], "backend": []}),
    ));
    model.apply(status(Value::Null));
    assert_eq!(model.page().note, text::NOTHING_TO_CLEAN_UP);
}
