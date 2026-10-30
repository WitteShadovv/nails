// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

use super::*;
use crate::client::Answer;
use nails_api::protocol::{
    ActivateArgs, CheckArgs, DiscardPlanArgs, DiscardPlanData, ErrorCode, Hello, ProtocolError,
};
use serde_json::{Value, json};

fn engine() -> Option<PathBuf> {
    Some(PathBuf::from("/mnt/data/nails"))
}

fn answered(kind: Kind, envelope: Value) -> Update {
    Update::Answered(kind, Answer { exit: 0, envelope })
}

fn status(data: Value) -> Update {
    answered(
        Kind::Status,
        json!({"schema_version": 2, "command": "status", "ok": true, "data": data}),
    )
}

/// A decoy's status; the engine gives a reason and a fix only with an
/// attention.
fn decoy(attention: Value) -> Update {
    let mut data = json!({
        "place": "decoy", "attention": attention, "hidden_root": "/mnt/data",
        "hidden_root_mounted": true,
    });
    if !data["attention"].is_null() {
        data["reason"] = json!("the next root has neither /etc/os-release nor /usr/lib/os-release");
        data["remediation"] = json!("Run `sudo /mnt/data/nails recover` to reset the record");
    }
    status(data)
}

fn check(ready: bool, checks: Value, summary: Value) -> Update {
    answered(
        Kind::Check,
        json!({"schema_version": 2, "command": "check", "ok": ready, "data": {"ready": ready, "checks": checks, "summary": summary}}),
    )
}

fn connected() -> Model {
    let mut model = Model::new(engine(), false);
    assert_eq!(
        model.apply(Update::Connected(crate::client::ours())),
        vec![Ask::Status]
    );
    model
}

fn on_the_decoy() -> Model {
    let mut model = connected();
    model.apply(Update::Running(Kind::Status));
    assert_eq!(
        model.apply(decoy(Value::Null)),
        vec![Ask::Check(CheckArgs::default())]
    );
    model
}

#[test]
fn the_window_starts_busy_or_waiting_for_the_password() {
    let page = Model::new(engine(), false).page();
    assert_eq!(page.heading, "Starting");
    assert_eq!(page.busy.as_deref(), Some("Starting"));
    let page = Model::new(engine(), true).page();
    assert_eq!(page.heading, "Waiting for Your Password");
    assert_eq!(page.description, text::WAITING_FOR_PASSWORD_WHY);
    assert!(page.busy.is_some());
}

#[test]
fn the_decoys_page_is_its_check_which_runs_when_the_window_opens() {
    let mut model = on_the_decoy();
    let page = model.page();
    assert_eq!(page.heading, "Checking This Computer");
    assert_eq!(page.description, "Decoy. No hidden session is active.");
    assert_eq!(
        page.facts,
        vec![("Hidden volume".to_string(), "/mnt/data".to_string())]
    );
    assert_eq!(page.action, None);

    model.apply(Update::Running(Kind::Check));
    for (name, outcome) in [
        ("journal", CheckOutcome::Pass),
        ("swap", CheckOutcome::Fail),
    ] {
        model.apply(Update::Event(Event::Check {
            name: name.to_string(),
            outcome,
            message: format!("{name} looked at"),
        }));
    }
    model.apply(Update::Event(Event::Finished { success: true }));
    let page = model.page();
    let rows: Vec<(&str, &str)> = page
        .checks
        .iter()
        .map(|c| (c.word.as_str(), c.message.as_str()))
        .collect();
    assert_eq!(
        rows,
        [
            ("Passed", "Journal looked at."),
            ("Failed", "Swap looked at.")
        ]
    );
    assert!(page.busy.is_some());
}

#[test]
fn a_ready_decoy_counts_its_checks_lists_its_warnings_and_offers_to_activate() {
    let mut model = on_the_decoy();
    model.apply(Update::Running(Kind::Check));
    model.apply(check(
        true,
        json!([
            {"name": "journal", "status": "pass", "message": "the journal is volatile"},
            {"name": "space", "status": "warn", "message": "1.8 GB free"},
        ]),
        json!({"passed": 1, "warnings": 1, "failed": 0}),
    ));
    let page = model.page();
    assert_eq!(page.heading, "Ready to Activate");
    assert_eq!(page.note, "");
    assert_eq!(
        page.facts[1],
        ("This computer".to_string(), "1 check passed".to_string())
    );
    assert_eq!(page.checks.len(), 1);
    assert_eq!(page.checks[0].word, "Warning");
    assert_eq!(page.fix, "");
    assert_eq!(page.action, Some("Activate\u{2026}"));
    assert_eq!(page.action_kind, ActionKind::Suggested);
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Activate(
            ActivateArgs::default()
        ))))
    );
}

#[test]
fn a_decoy_that_is_not_ready_lists_its_problems_first_each_with_its_fix() {
    let mut model = on_the_decoy();
    model.apply(Update::Running(Kind::Check));
    model.apply(check(
        false,
        json!([
            {"name": "space", "status": "warn", "message": "1.8 GB free"},
            {"name": "swap", "status": "fail", "message": "swap is on", "remediation": "turn `swapoff -a` on"},
            {"name": "journal", "status": "fail", "message": "the journal is on disk"},
            {"name": "selinux", "status": "skipped", "message": "no SELinux"},
        ]),
        json!({"passed": 0, "warnings": 1, "failed": 2, "skipped": 1}),
    ));
    let page = model.page();
    assert_eq!(page.heading, "Not Ready to Activate");
    assert_eq!(page.note, "2 problems. Nothing was changed.");
    let rows: Vec<(&str, &str, &str)> = page
        .checks
        .iter()
        .map(|c| (c.word.as_str(), c.message.as_str(), c.fix.as_str()))
        .collect();
    assert_eq!(
        rows,
        [
            ("Failed", "Swap is on.", "Fix: turn swapoff -a on"),
            ("Failed", "The journal is on disk.", ""),
            ("Warning", "1.8 GB free.", ""),
        ]
    );
    assert_eq!(page.fix, "", "nothing to activate");
    assert_eq!(page.action, Some("Check Again"));
    assert!(
        page.checks.iter().all(|check| check.allow.is_none()),
        "neither problem can be allowed"
    );
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Check(CheckArgs::default())))
    );
}

#[test]
fn a_check_that_could_not_run_says_why_and_offers_to_check_again() {
    let mut model = on_the_decoy();
    model.apply(Update::Running(Kind::Check));
    model.apply(answered(
        Kind::Check,
        json!({"schema_version": 2, "command": "check", "ok": false, "error": {
            "code": "config", "message": "the settings file cannot be read", "next": {"command": "config validate"}}}),
    ));
    let page = model.page();
    assert_eq!(page.heading, "Check Failed");
    assert_eq!(page.note, "The settings file cannot be read.");
    assert_eq!(page.fix, "Next: sudo /mnt/data/nails config validate");
    assert_eq!(page.action, Some("Check Again"));
}

#[test]
fn while_a_request_runs_the_main_action_is_not_offered() {
    let mut model = on_the_decoy();
    model.apply(Update::Running(Kind::Check));
    model.apply(check(
        true,
        json!([]),
        json!({"passed": 0, "warnings": 0, "failed": 0}),
    ));
    model.apply(Update::Running(Kind::Check));
    assert_eq!(model.page().action, None);
    assert_eq!(model.action(), None);
}

#[test]
fn an_interrupted_activation_or_an_unreadable_record_comes_before_the_check() {
    let mut model = connected();
    assert!(
        model.apply(decoy(json!("interrupted"))).is_empty(),
        "no check"
    );
    let page = model.page();
    assert_eq!(page.heading, "Activation Interrupted");
    assert_eq!(page.description, text::DECOY_INTERRUPTED);
    assert_eq!(
        page.fix,
        "Run sudo /mnt/data/nails recover to reset the record"
    );
    assert_eq!(page.action, Some("Clean Up"));

    let mut model = connected();
    assert!(model.apply(decoy(json!("record_unreadable"))).is_empty());
    assert_eq!(model.page().heading, "Record Cannot Be Read");
    // Here the status says the machine is the decoy, so the page does too.
    assert_eq!(model.page().description, text::DECOY_RECORD_UNREADABLE);
    assert_eq!(model.page().action, Some("Reset Record"));
}

#[test]
fn a_status_that_could_not_be_built_is_an_unreadable_record() {
    // The envelope the helper's status gives then (the CLI's
    // status_unknown_envelope): no next step.
    let mut model = connected();
    model.apply(answered(
        Kind::Status,
        json!({"schema_version": 2, "command": "status", "ok": false,
            "data": {"place": "unknown", "attention": "record_unreadable"},
            "error": {"code": "record_unreadable", "message": "the record is damaged", "next": null}}),
    ));
    let page = model.page();
    assert_eq!(page.heading, "Record Cannot Be Read");
    assert_eq!(
        page.description,
        "The record on the hidden volume cannot be read, so it is not known whether a hidden \
         session is active."
    );
    assert!(
        !page.description.contains("Decoy"),
        "the engine does not guess the place, and neither does the page"
    );
    assert_eq!(page.note, "The record is damaged.");
    assert_eq!(
        page.fix, "",
        "the engine names no next step, nor does the page"
    );
    assert_eq!(
        page.action, None,
        "nothing shows that no session is active, so the record is not reset"
    );
}

#[test]
fn settings_that_cannot_be_read_are_said_wherever_the_window_runs() {
    // The helper's status answer when it cannot load the settings: an error
    // and no data, so nothing says where the machine is, in a hidden session
    // as on the decoy.
    let mut model = connected();
    assert!(
        model
            .apply(answered(
                Kind::Status,
                json!({"schema_version": 2, "command": "status", "ok": false, "error": {
                    "code": "config",
                    "message": "invalid configuration in /mnt/data/config/nails.toml: unknown field `accept_persistent_decoy`",
                    "next": null}}),
            ))
            .is_empty(),
        "no check without a status"
    );
    let page = model.page();
    assert_eq!(page.heading, "Settings Cannot Be Read");
    assert_eq!(
        page.description,
        "Invalid configuration in /mnt/data/config/nails.toml: unknown field `accept_persistent_decoy`."
    );
    assert_eq!(page.note, "Nothing was changed.");
    assert_eq!(page.fix, "Next: sudo /mnt/data/nails config validate");
    assert!(page.urgent);
    assert!(!page.description.contains("Decoy") && !page.heading.contains("Record"));

    // Any other failure of the status names no place either, and gives the
    // engine's next step when there is one.
    let mut model = connected();
    model.apply(answered(
        Kind::Status,
        json!({"schema_version": 2, "command": "status", "ok": false, "error": {
            "code": "internal_error", "message": "the status could not be built", "next": {"command": "status"}}}),
    ));
    let page = model.page();
    assert_eq!(page.heading, "Status Not Available");
    assert_eq!(page.description, "The status could not be built.");
    assert_eq!(page.fix, "Next: sudo /mnt/data/nails status");
}

#[test]
fn a_refused_switch_or_an_abnormal_end_is_said_above_the_check() {
    let mut model = connected();
    assert_eq!(
        model.apply(decoy(json!("switch_refused"))).len(),
        1,
        "the check runs"
    );
    let page = model.page();
    assert_eq!(
        page.description,
        "Decoy. The last activation stopped at the switch: the next root has neither /etc/os-release nor /usr/lib/os-release."
    );
    assert_eq!(
        page.fix,
        "Run sudo /mnt/data/nails recover to reset the record"
    );

    let mut model = connected();
    model.apply(decoy(json!("ended_abnormally")));
    model.apply(check(
        true,
        json!([]),
        json!({"passed": 3, "warnings": 0, "failed": 0}),
    ));
    let page = model.page();
    assert_eq!(page.description, text::DECOY_ENDED_ABNORMALLY);
    assert_eq!(
        page.fix,
        "Run sudo /mnt/data/nails recover to reset the record"
    );
    assert_eq!(page.action, Some(text::ACTIVATE));
}

#[test]
fn a_hidden_session_says_how_long_it_has_run() {
    let mut model = connected();
    assert!(model.apply(status(json!({"place": "hidden", "attention": null, "uptime_seconds": 7800, "hidden_root": "/mnt/data"}))).is_empty());
    let page = model.page();
    assert_eq!(page.heading, "Hidden Session");
    assert_eq!(page.description, "Hidden session active for 2 h 10 min.");
    assert_eq!(
        page.facts,
        vec![("Hidden volume".to_string(), "/mnt/data".to_string())]
    );
    assert_eq!(
        page.fix,
        "Deactivate from a terminal: sudo /mnt/data/nails deactivate"
    );
    assert_eq!(page.action, None);
}

#[test]
fn a_hidden_session_without_a_way_back_names_the_power_button() {
    // The reason as the engine's status gives it for a hidden root without
    // a plan.
    let mut model = connected();
    model.apply(status(json!({"place": "hidden", "attention": "no_way_back",
        "reason": "in the hidden root without a way back: no session plan in /run (upper /mnt/data/root/upper)"})));
    let page = model.page();
    assert_eq!(page.heading, "No Way Back");
    assert_eq!(page.description, "Hidden session without a way back.");
    assert_eq!(
        page.note,
        "No session plan in /run (upper /mnt/data/root/upper)."
    );
    assert_eq!(
        format!("{} {}", page.description, page.note)
            .matches("without a way back")
            .count(),
        1,
        "the page says it once"
    );
    assert_eq!(page.fix, text::HOLD_POWER_BUTTON);
    assert!(page.urgent);
}

#[test]
fn a_covered_volume_and_other_hidden_attentions_show_the_engines_words() {
    let mut model = connected();
    model.apply(status(
        json!({"place": "hidden", "attention": "volume_covered", "uptime_seconds": 60,
        "hidden_root": "/mnt/data", "remediation": "Run `sudo umount /mnt/data`"}),
    ));
    let page = model.page();
    assert!(
        page.description
            .ends_with("files saved under /mnt/data go to that disk."),
        "{}",
        page.description
    );
    assert_eq!(page.fix, "Run sudo umount /mnt/data");

    let mut model = connected();
    model.apply(status(
        json!({"place": "hidden", "attention": "almost_full", "reason": "1.8 GB free"}),
    ));
    assert_eq!(model.page().note, "1.8 GB free.");
}

#[test]
fn an_activation_under_way_says_so() {
    let mut model = connected();
    model.apply(status(json!({"place": "activating", "attention": null})));
    let page = model.page();
    assert_eq!(page.heading, "Activating");
    assert_eq!(page.description, text::ACTIVATING_WHERE);
}

#[test]
fn an_answer_the_window_cannot_read_gets_a_page_of_its_own() {
    let mut model = connected();
    model.apply(answered(
        Kind::Status,
        json!({"schema_version": 3, "command": "status", "ok": true}),
    ));
    let page = model.page();
    assert_eq!(page.heading, "Unexpected Answer");
    assert!(page.note.contains("contract 3"), "{}", page.note);
    assert!(page.urgent);

    let mut model = on_the_decoy();
    model.apply(answered(Kind::Check, json!({"command": "check"})));
    assert_eq!(model.page().heading, "Unexpected Answer");
}

fn ended(failure: Failure) -> Page {
    let mut model = connected();
    model.apply(Update::Ended(failure));
    model.page()
}

#[test]
fn every_end_of_the_session_says_what_happened_and_what_fixes_it() {
    let hello = |engine: &str| Hello {
        protocol: 1,
        engine: engine.to_string(),
    };
    let page = ended(Failure::Mismatch {
        window: hello("0.4.0"),
        engine: hello("0.3.0"),
    });
    assert_eq!(page.heading, "Different Releases");
    assert!(
        page.description.contains("release 0.4.0") && page.description.contains("release 0.3.0")
    );
    assert_eq!(page.note, "Nothing was changed.");
    assert_eq!(page.fix, text::MISMATCH_FIX);

    let page = ended(Failure::Refused(ProtocolError {
        code: ErrorCode::Malformed,
        message: "not a request".to_string(),
    }));
    assert_eq!(
        (page.heading.as_str(), page.description.as_str()),
        ("Request Refused", "Not a request.")
    );

    let page = ended(Failure::Lost { in_flight: true });
    assert_eq!(page.heading, "Connection Lost");
    assert_eq!(page.note, text::LOST_IN_FLIGHT);
    assert_eq!(
        page.fix,
        "Open a terminal and run: sudo /mnt/data/nails gui"
    );
    assert_eq!(
        ended(Failure::Lost { in_flight: false }).note,
        "Nothing was changed."
    );

    let page = ended(Failure::PasswordUnavailable);
    assert_eq!(page.heading, "Password Needed");
    assert_eq!(page.description, text::PASSWORD_NEEDED_WHY);

    let page = ended(Failure::NotStarted(
        "pkexec could not be started".to_string(),
    ));
    assert_eq!(
        page.description,
        "The window could not start its controls: Pkexec could not be started."
    );

    assert_eq!(
        ended(Failure::Unreadable("x".to_string())).heading,
        "Unexpected Answer"
    );

    for failure in [
        Failure::Lost { in_flight: false },
        Failure::PasswordUnavailable,
    ] {
        let page = ended(failure);
        assert!(
            page.urgent && page.action.is_none() && page.busy.is_none(),
            "{page:?}"
        );
    }
}

#[test]
fn a_dismissed_password_dialog_closes_the_window_and_nothing_else_does() {
    let mut model = Model::new(engine(), true);
    assert!(!model.quits());
    model.apply(Update::Ended(Failure::PasswordDismissed));
    assert!(model.quits());
    let mut model = Model::new(engine(), true);
    model.apply(Update::Ended(Failure::PasswordUnavailable));
    assert!(!model.quits());
}

fn discard_question(data: &PlanData) -> Question {
    let PlanData::Discard(data) = data else {
        panic!("{data:?}");
    };
    Question {
        heading: "Discard?".to_string(),
        body: format!("{} goes.", data.target),
        confirm: "Discard".to_string(),
        destructive: true,
        ..Question::default()
    }
}

fn discard_data() -> PlanData {
    PlanData::Discard(DiscardPlanData {
        target: "/srv/notes".to_string(),
        removals: vec![],
        resets_nix_store: false,
        token: "0".repeat(32),
    })
}

#[test]
fn a_plan_asks_its_question_once_it_holds_and_the_answer_applies_or_withdraws_it() {
    let mut model = on_the_decoy();
    let plan = Plan::Discard(DiscardPlanArgs {
        target: "/srv/notes".to_string(),
        allow_decoy_storage: false,
    });
    assert_eq!(model.plan(plan.clone(), discard_question), Ask::Plan(plan));
    model.apply(Update::Running(Kind::Plan));
    assert!(model.apply(Update::Planned(discard_data())).is_empty());
    let question = model.page().question.unwrap();
    assert_eq!(
        (question.heading.as_str(), question.body.as_str()),
        ("Discard?", "/srv/notes goes.")
    );
    assert!(question.destructive);

    assert_eq!(model.answer(true), Some(Ask::Apply));
    assert_eq!(model.page().question, None);
    model.apply(Update::Running(Kind::Apply));
    let follow = model.apply(answered(
        Kind::Apply,
        json!({"command": "discard", "ok": false, "error": {"code": "discard", "message": "the folder is busy", "next": null}}),
    ));
    assert_eq!(follow, vec![Ask::Status], "the page is brought up to date");
    assert!(
        model.page().note.starts_with("The folder is busy."),
        "{}",
        model.page().note
    );
}

#[test]
fn a_withdrawn_or_unasked_plan_leaves_no_question() {
    let mut model = on_the_decoy();
    model.plan(
        Plan::Discard(DiscardPlanArgs {
            target: "/srv/notes".to_string(),
            allow_decoy_storage: false,
        }),
        discard_question,
    );
    model.apply(Update::Planned(discard_data()));
    assert_eq!(model.answer(false), Some(Ask::Withdraw));
    model.apply(Update::Withdrawn);
    assert_eq!(model.page().question, None);
    // A plan no screen asked for is dropped at once.
    assert_eq!(
        model.apply(Update::Planned(discard_data())),
        vec![Ask::Withdraw]
    );
    assert_eq!(model.page().question, None);
}

#[test]
fn a_session_that_ends_takes_the_question_with_it() {
    let mut model = on_the_decoy();
    model.plan(
        Plan::Discard(DiscardPlanArgs {
            target: "/srv/notes".to_string(),
            allow_decoy_storage: false,
        }),
        discard_question,
    );
    model.apply(Update::Planned(discard_data()));
    model.apply(Update::Ended(Failure::Lost { in_flight: false }));
    assert_eq!(model.page().question, None);
    assert_eq!(model.page().heading, "Connection Lost");
}
