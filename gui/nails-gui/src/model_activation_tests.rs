// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The activation through the model: a risk allowed behind its word, the
//! question with the plan's own lines, the steps as they stream, Cancel
//! before the point of no return, and the page past it.

use super::*;
use crate::client::Answer;
use nails_api::protocol::{ActivateArgs, ActivatePlanData, CheckArgs};
use serde_json::{Value, json};

fn answered(kind: Kind, envelope: Value) -> Update {
    Update::Answered(kind, Answer { exit: 0, envelope })
}

fn decoy() -> Model {
    let mut model = Model::new(Some(PathBuf::from("/mnt/data/nails")), false);
    model.apply(Update::Connected(crate::client::ours()));
    let asks = model.apply(answered(
        Kind::Status,
        json!({"schema_version": 2, "command": "status", "ok": true,
            "data": {"place": "decoy", "attention": null, "hidden_root": "/mnt/data"}}),
    ));
    assert_eq!(asks, vec![Ask::Check(CheckArgs::default())]);
    model
}

fn checked(model: &mut Model, checks: Value, failed: usize, persona: &str) {
    model.apply(Update::Running(Kind::Check));
    model.apply(answered(
        Kind::Check,
        json!({"schema_version": 2, "command": "check", "ok": failed == 0, "data": {
            "ready": failed == 0, "checks": checks,
            "summary": {"passed": 1, "warnings": 0, "failed": failed},
            "config": {"persona_mode": persona}}}),
    ));
}

/// A decoy whose check passed.
fn ready() -> Model {
    let mut model = decoy();
    checked(
        &mut model,
        json!([{"name": "swap", "status": "pass", "message": "swap is off"}]),
        0,
        "fresh-home",
    );
    model
}

fn plan(warning: Option<&str>, notice: Option<&str>, builds: bool) -> Update {
    Update::Planned(PlanData::Activate(ActivatePlanData {
        warning: warning.map(str::to_string),
        defaults_notice: notice.map(str::to_string),
        builds_hidden_system: builds,
        token: "0".repeat(32),
    }))
}

/// `model` with its activation planned, asked, confirmed and running.
fn activating(model: &mut Model) {
    assert!(matches!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Activate(_))))
    ));
    model.apply(Update::Running(Kind::Plan));
    model.apply(plan(None, None, false));
    assert_eq!(model.answer(true), Some(Ask::Apply));
    model.apply(Update::Running(Kind::Apply));
}

fn step(label: &str, index: u32) -> Update {
    Update::Event(Event::Step {
        phase: "x".to_string(),
        label: label.to_string(),
        index,
        total: 6,
    })
}

fn steps(page: &Page) -> Vec<(&str, &str)> {
    page.steps
        .iter()
        .map(|step| (step.label.as_str(), step.state))
        .collect()
}

#[test]
fn the_question_before_an_activation_says_what_its_plan_says() {
    let mut model = decoy();
    checked(
        &mut model,
        json!([{"name": "swap", "status": "pass", "message": "swap is off"}]),
        0,
        "shared-home",
    );
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Activate(
            ActivateArgs::default()
        ))))
    );
    model.apply(Update::Running(Kind::Plan));
    assert_eq!(model.page().action, None, "nothing to press while it plans");
    model.apply(plan(
        Some("--allow-decoy-storage: using /mnt/data although it is a subvolume"),
        Some(
            "No config file at /mnt/data/config/nails.toml: activation uses the built-in defaults.",
        ),
        true,
    ));
    let question = model.page().question.expect("the question is open");
    assert_eq!(question.heading, "Activate Hidden Session?");
    assert_eq!(question.confirm, "Log Out and Activate");
    assert!(!question.destructive && !question.locked && question.prompt.is_none());
    assert_eq!(
        question.body.lines().collect::<Vec<_>>(),
        [
            text::ACTIVATE_CONSEQUENCE,
            "--allow-decoy-storage: using /mnt/data although it is a subvolume.",
            text::DECOY_HOME,
            text::BUILDS_HIDDEN_SYSTEM,
            "No config file at /mnt/data/config/nails.toml: activation uses the built-in defaults.",
        ]
    );
    // Cancel withdraws the plan, and its lock with it.
    assert_eq!(model.answer(false), Some(Ask::Withdraw));
    model.apply(Update::Withdrawn);
    assert_eq!(model.page().heading, text::READY);
    assert_eq!(model.page().question, None);
}

#[test]
fn the_steps_stream_and_the_point_of_no_return_takes_every_input_away() {
    let mut model = ready();
    activating(&mut model);
    let page = model.page();
    assert_eq!(page.heading, "Activating");
    assert_eq!(page.description, text::ACTIVATING_WHERE);
    assert_eq!(steps(&page), [("Checking this computer", "Now")]);
    assert_eq!(page.busy.as_deref(), Some("Checking this computer"));
    assert_eq!(page.action, Some("Cancel"));
    assert_eq!(page.action_kind, ActionKind::Plain);
    assert!(!page.no_input);

    // The checks the entry runs again are its first step, not rows.
    model.apply(Update::Event(Event::Check {
        name: "swap".to_string(),
        outcome: CheckOutcome::Pass,
        message: "swap is off".to_string(),
    }));
    model.apply(step("Staging the runtime", 1));
    model.apply(step("Mounting the root overlay", 2));
    model.apply(Update::Event(Event::Heartbeat {
        phase: "overlay".to_string(),
        elapsed_seconds: 30,
    }));
    let page = model.page();
    assert_eq!(
        steps(&page),
        [
            ("Checking this computer", "Done"),
            ("Staging the runtime", "Done"),
            ("Mounting the root overlay", "Now"),
        ]
    );
    assert!(page.checks.is_empty());
    assert_eq!(page.busy.as_deref(), Some("Mounting the root overlay"));

    model.apply(Update::Event(Event::PointOfNoReturn));
    let page = model.page();
    assert_eq!(page.heading, "Logging Out");
    assert_eq!(page.description, "Log in again at the login screen.");
    assert!(page.no_input && page.urgent);
    assert_eq!((page.action, page.busy), (None, None));
    assert_eq!(model.escape(), None, "nothing cancels it now");
    assert_eq!(model.action(), None);

    // The switch ends the session: the page stays.
    assert!(
        model
            .apply(answered(
                Kind::Apply,
                json!({"command": "activate", "ok": true, "data": {"status": "entering"}}),
            ))
            .is_empty()
    );
    model.apply(Update::Ended(Failure::Lost { in_flight: false }));
    assert_eq!(model.page().heading, "Logging Out");
}

#[test]
fn cancel_before_the_point_of_no_return_hangs_up_and_the_answer_is_the_last_word() {
    let mut model = ready();
    activating(&mut model);
    model.apply(step("Staging the runtime", 1));
    assert_eq!(model.action(), Some(Effect::HangUp));
    let page = model.page();
    assert_eq!(page.busy.as_deref(), Some("Cancelling"));
    assert_eq!(page.action, None);
    assert_eq!(model.escape(), None, "it hangs up once");

    let asks = model.apply(answered(
        Kind::Apply,
        json!({"schema_version": 2, "command": "activate", "ok": false, "error": {
            "code": "cancelled", "message": "Activation cancelled; nothing was changed.", "next": null}}),
    ));
    assert!(
        asks.is_empty(),
        "the session is over: nothing more is asked"
    );
    let page = model.page();
    assert_eq!(page.heading, "Activation Cancelled");
    assert_eq!(
        page.description,
        "Activation cancelled; nothing was changed."
    );
    assert_eq!(
        page.fix,
        "To go on, open the window again from a terminal: sudo /mnt/data/nails gui"
    );
    assert!(page.action.is_none() && !page.urgent);
    // The helper ends once it answered: nothing changes the page now.
    model.apply(Update::Ended(Failure::Lost { in_flight: false }));
    assert_eq!(model.page(), page);
}

#[test]
fn escape_cancels_as_the_button_does() {
    let mut model = ready();
    activating(&mut model);
    assert_eq!(model.escape(), Some(Effect::HangUp));
    assert_eq!(model.page().busy.as_deref(), Some("Cancelling"));
}

#[test]
fn a_cancel_too_late_for_the_point_of_no_return_changes_nothing() {
    let mut model = ready();
    activating(&mut model);
    assert_eq!(model.action(), Some(Effect::HangUp));
    // The helper was past the point already: it finishes the switch.
    model.apply(Update::Event(Event::PointOfNoReturn));
    assert_eq!(model.page().heading, "Logging Out");
    model.apply(answered(
        Kind::Apply,
        json!({"command": "activate", "ok": true, "data": {"status": "entering_with_warnings"}}),
    ));
    assert_eq!(model.page().heading, "Logging Out");
    // Even had the point gone unheard, an answer that enters is the switch.
    let mut model = ready();
    activating(&mut model);
    model.action();
    model.apply(answered(
        Kind::Apply,
        json!({"command": "activate", "ok": true, "data": {"status": "entering"}}),
    ));
    assert_eq!(model.page().heading, "Logging Out");
}

#[test]
fn an_activation_that_stops_on_its_own_says_why_and_checks_again() {
    let mut model = ready();
    activating(&mut model);
    let asks = model.apply(answered(
        Kind::Apply,
        json!({"schema_version": 2, "command": "activate", "ok": false,
            "data": {"status": "failed"},
            "error": {"code": "not_ready", "message": "Pre-flight checks failed", "next": null}}),
    ));
    assert_eq!(asks, vec![Ask::Status]);
    let asks = model.apply(answered(
        Kind::Status,
        json!({"schema_version": 2, "command": "status", "ok": true,
            "data": {"place": "decoy", "attention": null, "hidden_root": "/mnt/data"}}),
    ));
    assert_eq!(
        asks,
        vec![Ask::Check(CheckArgs::default())],
        "the check runs again"
    );
    let page = model.page();
    assert_eq!(page.heading, text::CHECKING);
    assert!(
        page.note.starts_with("Pre-flight checks failed."),
        "{}",
        page.note
    );

    // A session already active is the status's to show.
    let mut model = ready();
    activating(&mut model);
    let asks = model.apply(answered(
        Kind::Apply,
        json!({"command": "activate", "ok": true, "data": {"status": "already_active",
            "message": "Already in the hidden session; nothing to do"}}),
    ));
    assert_eq!(asks, vec![Ask::Status]);
    assert_eq!(model.page().note, "");
}

#[test]
fn an_activation_whose_plan_was_gone_never_started() {
    let mut model = ready();
    activating(&mut model);
    model.apply(Update::Withdrawn);
    let page = model.page();
    assert_eq!(page.heading, text::READY);
    assert_eq!(page.action, Some(text::ACTIVATE));
}

/// A decoy that keeps a persistent record, and one more problem.
fn persistent(model: &mut Model, more: bool) {
    let mut checks = vec![json!({"name": "decoy-persistence", "status": "fail",
        "message": "decoy keeps a persistent record of the hidden session: a journal on disk",
        "remediation": "make the decoy amnesic, or pass --allow-persistent-decoy"})];
    if more {
        checks.push(json!({"name": "swap", "status": "fail", "message": "swap is on"}));
    }
    let failed = checks.len();
    checked(model, Value::Array(checks), failed, "fresh-home");
}

#[test]
fn a_risk_the_cli_lets_one_allow_is_allowed_only_behind_its_word() {
    let mut model = decoy();
    persistent(&mut model, true);
    let page = model.page();
    assert_eq!(page.heading, text::NOT_READY);
    assert_eq!(page.checks[0].allow, Some(Risk::PersistentDecoy));
    assert_eq!(page.checks[1].allow, None, "swap cannot be allowed");

    model.allow(0);
    let question = model.page().question.expect("the question is open");
    assert_eq!(question.heading, "Allow for This Activation?");
    assert_eq!(
        question.body,
        "Decoy keeps a persistent record of the hidden session: a journal on disk.\n\
         This is allowed for one activation only."
    );
    assert_eq!(question.prompt.as_deref(), Some("Type allow to continue"));
    assert_eq!(question.confirm, "Allow");
    assert!(question.destructive && question.locked);

    for (typed, locked) in [
        ("all", true),
        ("allowed", true),
        (" Allow ", false),
        ("", true),
    ] {
        model.typed(typed);
        assert_eq!(model.page().question.unwrap().locked, locked, "{typed:?}");
    }
    // Without the word the button does nothing.
    assert_eq!(model.answer(true), None);
    assert_eq!(model.page().question, None);
    assert_eq!(model.page().checks[0].allow, Some(Risk::PersistentDecoy));

    model.allow(0);
    model.typed("allow");
    assert_eq!(
        model.answer(true),
        Some(Ask::Check(CheckArgs {
            allow_persistent_decoy: true,
            ..CheckArgs::default()
        }))
    );
    // The check with the flag turns the refusal into a warning; swap still
    // refuses.
    checked(
        &mut model,
        json!([
            {"name": "decoy-persistence", "status": "warn", "message": "persistent decoy posture allowed"},
            {"name": "swap", "status": "fail", "message": "swap is on"},
        ]),
        1,
        "fresh-home",
    );
    let page = model.page();
    assert_eq!(page.heading, text::NOT_READY);
    assert!(page.checks.iter().all(|check| check.allow.is_none()));
    assert!(page.facts.contains(&(
        "Allowed by you".to_string(),
        text::RISK_PERSISTENT_DECOY.to_string()
    )));
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Check(CheckArgs {
            allow_persistent_decoy: true,
            ..CheckArgs::default()
        }))),
        "Check Again keeps what was allowed"
    );
}

#[test]
fn an_allowed_risk_reaches_the_activation_and_its_question() {
    let mut model = decoy();
    persistent(&mut model, false);
    model.allow(0);
    model.typed("ALLOW");
    model.answer(true);
    checked(
        &mut model,
        json!([{"name": "decoy-persistence", "status": "warn", "message": "allowed"}]),
        0,
        "fresh-home",
    );
    assert_eq!(model.page().heading, text::READY);
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Activate(ActivateArgs {
            allow_persistent_decoy: true,
            ..ActivateArgs::default()
        }))))
    );
    model.apply(plan(None, None, false));
    let body = model.page().question.unwrap().body;
    assert_eq!(
        body.lines().collect::<Vec<_>>(),
        [
            text::ACTIVATE_CONSEQUENCE,
            "Allowed by you: a persistent record on this computer's disk."
        ]
    );
}

#[test]
fn cancelling_the_risk_allows_nothing() {
    let mut model = decoy();
    persistent(&mut model, false);
    model.allow(0);
    model.typed("allow");
    assert_eq!(model.answer(false), None);
    assert_eq!(model.page().checks[0].allow, Some(Risk::PersistentDecoy));
    // Rows that cannot be allowed, or are not there, open nothing.
    model.allow(7);
    assert_eq!(model.page().question, None);
}

/// A decoy whose check passed with the persistent record allowed behind the
/// word.
fn allowed() -> Model {
    let mut model = decoy();
    persistent(&mut model, false);
    model.allow(0);
    model.typed("allow");
    model.answer(true);
    checked(
        &mut model,
        json!([{"name": "decoy-persistence", "status": "warn", "message": "allowed"}]),
        0,
        "fresh-home",
    );
    assert_eq!(model.page().heading, text::READY);
    model
}

fn decoy_status() -> Update {
    answered(
        Kind::Status,
        json!({"schema_version": 2, "command": "status", "ok": true,
            "data": {"place": "decoy", "attention": null, "hidden_root": "/mnt/data"}}),
    )
}

/// After whatever ended what was allowed: the check runs again without it,
/// refuses again and offers Allow again, and the next Activate… carries no
/// flag.
fn allowed_no_more(model: &mut Model) {
    assert_eq!(
        model.apply(decoy_status()),
        vec![Ask::Check(CheckArgs::default())],
        "the check runs again without the flag"
    );
    persistent(model, false);
    let page = model.page();
    assert_eq!(page.checks[0].allow, Some(Risk::PersistentDecoy));
    assert!(
        !page
            .facts
            .iter()
            .any(|(title, _)| title == text::FACT_ALLOWED),
        "{:?}",
        page.facts
    );
    // Had the decoy changed in between, its activation would still carry
    // nothing allowed.
    checked(
        model,
        json!([{"name": "decoy-persistence", "status": "pass", "message": "amnesic"}]),
        0,
        "fresh-home",
    );
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Activate(
            ActivateArgs::default()
        ))))
    );
}

#[test]
fn what_was_allowed_holds_for_one_activation_that_failed() {
    let mut model = allowed();
    activating(&mut model);
    let asks = model.apply(answered(
        Kind::Apply,
        json!({"schema_version": 2, "command": "activate", "ok": false,
            "data": {"status": "failed"},
            "error": {"code": "not_ready", "message": "Pre-flight checks failed", "next": null}}),
    ));
    assert_eq!(asks, vec![Ask::Status]);
    allowed_no_more(&mut model);
}

#[test]
fn what_was_allowed_goes_with_an_activation_withdrawn() {
    // The person declined the activation's question: the status of the
    // withdrawal comes next.
    let mut model = allowed();
    assert!(matches!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Activate(ActivateArgs {
            allow_persistent_decoy: true,
            ..
        }))))
    ));
    model.apply(plan(None, None, false));
    assert_eq!(model.answer(false), Some(Ask::Withdraw));
    assert!(model.apply(Update::Withdrawn).is_empty());
    allowed_no_more(&mut model);

    // The helper withdrew it, a token it refused: the window asks for the
    // status itself.
    let mut model = allowed();
    activating(&mut model);
    assert_eq!(model.apply(Update::Withdrawn), vec![Ask::Status]);
    allowed_no_more(&mut model);
}

#[test]
fn what_was_allowed_goes_with_a_recovery() {
    let mut model = allowed();
    let asks = model.apply(answered(
        Kind::Recover,
        json!({"schema_version": 2, "command": "recover", "ok": true,
            "data": {"outcome": "clean", "remaining_mounts": [], "backend": []}}),
    ));
    assert_eq!(asks, vec![Ask::Status]);
    allowed_no_more(&mut model);
}
