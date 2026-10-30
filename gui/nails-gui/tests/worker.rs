// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The worker against a fake helper: what the window hears for each ask,
//! the plan that waits for its apply or is withdrawn, the session that ends,
//! an activation the window hangs up on before and after its point of no
//! return, and pkexec's own way of ending before the helper speaks.

mod support;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::Duration;

use nails_api::protocol::{
    ActivateArgs, CheckArgs, DiscardPlanArgs, Frame, Hello, Op, PROTOCOL_VERSION, Request, Token,
};
use nails_api::{CheckOutcome, Event};
use nails_gui::client::{Plan, PlanData, ours};
use nails_gui::worker::{Ask, Connect, Failure, HangUp, Kind, Update, Worker, spawn};
use serde_json::json;
use support::{Act, FakeHelper, event, hello_answer, result};

/// How long the window waits to hear from the worker before the test fails.
const PATIENCE: Duration = Duration::from_secs(10);

/// The window's side of a worker: its asks and what it hears.
struct Window {
    worker: Worker,
    heard: Receiver<Update>,
}

impl Window {
    fn on(connect: Connect) -> Self {
        let (tell, heard) = channel();
        let worker = spawn(connect, move |update| {
            let _ = tell.send(update);
        });
        Self { worker, heard }
    }

    fn next(&self) -> Update {
        self.heard
            .recv_timeout(PATIENCE)
            .expect("the worker reports")
    }

    fn ask(&self, ask: Ask) {
        assert!(self.worker.ask(ask), "the worker listens");
    }

    /// Whether the worker has ended: it reports nothing more and drops its
    /// end of the channel.
    fn worker_ended(&self) -> bool {
        matches!(
            self.heard.recv_timeout(PATIENCE),
            Err(RecvTimeoutError::Disconnected)
        )
    }
}

fn helper<F>(mut respond: F) -> (Window, FakeHelper)
where
    F: FnMut(&Request) -> Option<Vec<Frame>> + Send + 'static,
{
    let (stream, helper) = FakeHelper::start(ours(), move |request| match &request.op {
        Op::Hello(hello) => Some(vec![hello_answer(request.id, hello)]),
        _ => respond(request),
    });
    let window = Window::on(Connect::Stream(stream));
    assert_eq!(window.next(), Update::Connected(ours()));
    (window, helper)
}

fn token() -> String {
    "fedcba9876543210".repeat(2) // pragma: allowlist secret
}

#[test]
fn a_status_is_running_and_then_answered() {
    let (window, helper) =
        helper(|request| Some(vec![result(request.id, 0, json!({"command": "status"}))]));
    window.ask(Ask::Status);
    assert_eq!(window.next(), Update::Running(Kind::Status));
    match window.next() {
        Update::Answered(Kind::Status, answer) => assert_eq!(answer.envelope["command"], "status"),
        other => panic!("{other:?}"),
    }
    drop(window);
    let ops: Vec<Op> = helper.requests().into_iter().map(|r| r.op).collect();
    assert_eq!(ops, vec![Op::Hello(ours()), Op::Status]);
}

#[test]
fn each_check_is_heard_as_it_finishes_before_the_answer() {
    let (window, _helper) = helper(|request| {
        let id = request.id;
        let check = |name: &str, outcome| {
            event(
                id,
                Event::Check {
                    name: name.to_string(),
                    outcome,
                    message: format!("{name} checked"),
                },
            )
        };
        Some(vec![
            check("journal", CheckOutcome::Pass),
            check("swap", CheckOutcome::Fail),
            result(id, 4, json!({"command": "check"})),
        ])
    });
    window.ask(Ask::Check(CheckArgs::default()));
    assert_eq!(window.next(), Update::Running(Kind::Check));
    let mut names = Vec::new();
    loop {
        match window.next() {
            Update::Event(Event::Check { name, .. }) => names.push(name),
            Update::Answered(Kind::Check, answer) => {
                assert_eq!(answer.exit, 4);
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(names, ["journal", "swap"]);
}

#[test]
fn a_helper_of_another_release_ends_the_session_at_once() {
    let theirs = Hello {
        protocol: PROTOCOL_VERSION,
        engine: "0.0.1".to_string(),
    };
    let (stream, helper) = FakeHelper::start(theirs.clone(), |_| None);
    let window = Window::on(Connect::Stream(stream));
    assert_eq!(
        window.next(),
        Update::Ended(Failure::Mismatch {
            window: ours(),
            engine: theirs
        })
    );
    assert!(helper.requests().is_empty());
}

#[test]
fn a_helper_that_goes_away_while_a_request_waits_ends_the_session() {
    let (window, _helper) = helper(|_| None);
    window.ask(Ask::Status);
    assert_eq!(window.next(), Update::Running(Kind::Status));
    assert_eq!(
        window.next(),
        Update::Ended(Failure::Lost { in_flight: true })
    );
}

fn discard_helper() -> (Window, FakeHelper) {
    helper(|request| {
        let id = request.id;
        Some(match &request.op {
            Op::DiscardPlan(_) => vec![result(
                id,
                0,
                json!({"schema_version": 2, "command": "discard", "ok": true, "data": {
                    "target": "/srv/notes", "removals": ["/mnt/data/root/upper/srv/notes"],
                    "resets_nix_store": false, "token": token(),
                }}),
            )],
            Op::DiscardApply(_) => vec![result(id, 0, json!({"command": "discard", "ok": true}))],
            Op::Status => vec![result(id, 0, json!({"command": "status"}))],
            _ => return None,
        })
    })
}

fn discard() -> Ask {
    Ask::Plan(Plan::Discard(DiscardPlanArgs {
        target: "/srv/notes".to_string(),
        allow_decoy_storage: false,
    }))
}

#[test]
fn a_plan_waits_for_its_apply_which_carries_its_token() {
    let (window, helper) = discard_helper();
    window.ask(discard());
    assert_eq!(window.next(), Update::Running(Kind::Plan));
    match window.next() {
        Update::Planned(PlanData::Discard(data)) => assert_eq!(data.target, "/srv/notes"),
        other => panic!("{other:?}"),
    }
    window.ask(Ask::Apply);
    assert_eq!(window.next(), Update::Running(Kind::Apply));
    assert!(matches!(window.next(), Update::Answered(Kind::Apply, _)));
    drop(window);
    let ops: Vec<Op> = helper.requests().into_iter().map(|r| r.op).collect();
    assert_eq!(ops[2], Op::DiscardApply(Token { token: token() }));
}

#[test]
fn a_withdrawn_plan_is_dropped_with_a_status_request_and_never_applied() {
    let (window, helper) = discard_helper();
    window.ask(discard());
    assert_eq!(window.next(), Update::Running(Kind::Plan));
    assert!(matches!(window.next(), Update::Planned(_)));
    window.ask(Ask::Withdraw);
    assert_eq!(window.next(), Update::Withdrawn);
    assert_eq!(window.next(), Update::Running(Kind::Status));
    assert!(matches!(window.next(), Update::Answered(Kind::Status, _)));
    // An apply after the withdrawal finds no plan.
    window.ask(Ask::Apply);
    assert_eq!(window.next(), Update::Withdrawn);
    drop(window);
    let ops: Vec<Op> = helper.requests().into_iter().map(|r| r.op).collect();
    assert_eq!(ops.len(), 3, "hello, plan, status: {ops:?}");
    assert!(ops.iter().all(|op| op.apply_token().is_none()), "{ops:?}");
}

#[test]
fn another_request_after_a_plan_withdraws_it() {
    let (window, helper) = discard_helper();
    window.ask(discard());
    assert_eq!(window.next(), Update::Running(Kind::Plan));
    assert!(matches!(window.next(), Update::Planned(_)));
    window.ask(Ask::Status);
    assert_eq!(window.next(), Update::Running(Kind::Status));
    assert!(matches!(window.next(), Update::Answered(Kind::Status, _)));
    window.ask(Ask::Apply);
    assert_eq!(window.next(), Update::Withdrawn);
    drop(window);
    assert_eq!(helper.requests().len(), 3);
}

#[test]
fn a_plan_with_nothing_to_apply_is_answered_as_the_operation() {
    let (window, _helper) = helper(|request| {
        Some(vec![result(
            request.id,
            7,
            json!({"command": "discard", "ok": false}),
        )])
    });
    window.ask(discard());
    assert_eq!(window.next(), Update::Running(Kind::Plan));
    match window.next() {
        Update::Answered(Kind::Plan, answer) => assert_eq!(answer.exit, 7),
        other => panic!("{other:?}"),
    }
}

/// A stand-in for pkexec: a shell script with `body`, in a directory of its
/// own that goes with the returned guard.
struct FakePkexec {
    dir: PathBuf,
    program: PathBuf,
}

impl FakePkexec {
    fn new(name: &str, body: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("nails-gui-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("pkexec");
        std::fs::write(&program, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self { dir, program }
    }

    fn connect(&self) -> Connect {
        Connect::Pkexec {
            program: self.program.clone(),
            engine: PathBuf::from("/mnt/data/nails"),
        }
    }
}

impl Drop for FakePkexec {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn pkexec_ending_before_the_helper_speaks_says_why() {
    for (name, body, failure) in [
        ("dismissed", "exit 126", Failure::PasswordDismissed),
        ("unavailable", "exit 127", Failure::PasswordUnavailable),
        (
            "failed",
            "exit 3",
            Failure::NotStarted("the helper ended with exit code 3 before it spoke".to_string()),
        ),
        (
            "signalled",
            "kill -9 $$",
            Failure::NotStarted("the helper was ended by a signal before it spoke".to_string()),
        ),
    ] {
        let pkexec = FakePkexec::new(name, body);
        let window = Window::on(pkexec.connect());
        assert_eq!(window.next(), Update::Ended(failure), "{name}");
    }
}

#[test]
fn a_helper_started_through_pkexec_gets_the_same_handshake() {
    let pkexec = FakePkexec::new(
        "mismatch",
        r#"echo '{"hello":{"protocol":1,"engine":"0.0.1"}}'; read line"#,
    );
    let window = Window::on(pkexec.connect());
    match window.next() {
        Update::Ended(Failure::Mismatch { engine, .. }) => assert_eq!(engine.engine, "0.0.1"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn pkexec_that_cannot_be_started_is_said_so() {
    let window = Window::on(Connect::Pkexec {
        program: PathBuf::from("/nonexistent/pkexec"),
        engine: PathBuf::from("/mnt/data/nails"),
    });
    match window.next() {
        Update::Ended(Failure::NotStarted(why)) => {
            assert!(why.starts_with("pkexec could not be started"), "{why}")
        }
        other => panic!("{other:?}"),
    }
}

fn activate_plan() -> serde_json::Value {
    json!({"schema_version": 2, "command": "activate", "ok": true, "data": {
        "warning": null, "defaults_notice": null, "builds_hidden_system": false, "token": token(),
    }})
}

fn step(id: u64) -> Act {
    Act::Send(event(
        id,
        Event::Step {
            phase: "runtime".to_string(),
            label: "Staging the runtime".to_string(),
            index: 1,
            total: 6,
        },
    ))
}

/// A helper whose activation's apply plays `apply` (given the request's id).
fn activation_helper(apply: fn(u64) -> Vec<Act>) -> (Window, FakeHelper) {
    let (stream, helper) = FakeHelper::scripted(ours(), move |request| {
        let id = request.id;
        Some(match &request.op {
            Op::Hello(hello) => vec![Act::Send(hello_answer(id, hello))],
            Op::ActivatePlan(_) => vec![Act::Send(result(id, 0, activate_plan()))],
            Op::ActivateApply(_) => apply(id),
            _ => return None,
        })
    });
    let window = Window::on(Connect::Stream(stream));
    assert_eq!(window.next(), Update::Connected(ours()));
    window.ask(Ask::Plan(Plan::Activate(ActivateArgs::default())));
    assert_eq!(window.next(), Update::Running(Kind::Plan));
    assert!(matches!(
        window.next(),
        Update::Planned(PlanData::Activate(_))
    ));
    window.ask(Ask::Apply);
    assert_eq!(window.next(), Update::Running(Kind::Apply));
    (window, helper)
}

#[test]
fn a_hang_up_before_the_point_of_no_return_cancels_and_its_answer_is_the_last() {
    let (window, helper) = activation_helper(|id| {
        vec![
            step(id),
            // The real helper's watch on its pipe trips the cancel here.
            Act::AwaitHangUp,
            Act::Send(result(
                id,
                130,
                json!({"schema_version": 2, "command": "activate", "ok": false, "error": {
                    "code": "cancelled", "message": "Activation cancelled; nothing was changed.",
                    "next": null}}),
            )),
        ]
    });
    assert!(matches!(window.next(), Update::Event(Event::Step { .. })));
    let line = window.worker.hang_up();
    assert!(line.hang_up(), "the window hangs up");
    assert!(!line.hang_up(), "once");
    match window.next() {
        Update::Answered(Kind::Apply, answer) => {
            assert_eq!(answer.exit, 130);
            assert_eq!(answer.envelope["error"]["code"], "cancelled");
        }
        other => panic!("{other:?}"),
    }
    assert!(window.worker_ended(), "the answer was the session's last");
    let ops: Vec<Op> = helper.requests().into_iter().map(|r| r.op).collect();
    assert_eq!(ops.len(), 3, "hello, plan, apply and nothing more: {ops:?}");
}

#[test]
fn a_hang_up_past_the_point_of_no_return_changes_nothing() {
    let (window, helper) = activation_helper(|id| {
        vec![
            Act::Send(event(id, Event::PointOfNoReturn)),
            // Past the point, the helper finishes the switch all the same.
            Act::AwaitHangUp,
            Act::Send(result(
                id,
                0,
                json!({"schema_version": 2, "command": "activate", "ok": true,
                    "data": {"status": "entering"}}),
            )),
        ]
    });
    assert_eq!(window.next(), Update::Event(Event::PointOfNoReturn));
    assert!(window.worker.hang_up().hang_up());
    match window.next() {
        Update::Answered(Kind::Apply, answer) => {
            assert_eq!(answer.exit, 0);
            assert_eq!(answer.envelope["data"]["status"], "entering");
        }
        other => panic!("{other:?}"),
    }
    assert!(window.worker_ended());
    assert_eq!(helper.requests().len(), 3);
}

#[test]
fn an_activation_the_window_does_not_hang_up_on_keeps_its_session() {
    let (window, _helper) = activation_helper(|id| {
        vec![Act::Send(result(
            id,
            4,
            json!({"schema_version": 2, "command": "activate", "ok": false,
                "data": {"status": "failed"},
                "error": {"code": "not_ready", "message": "Pre-flight checks failed", "next": null}}),
        ))]
    });
    assert!(matches!(
        window.next(),
        Update::Answered(Kind::Apply, answer) if answer.exit == 4
    ));
    // The session goes on: the next ask is served (here, the helper of this
    // test closes on a status).
    window.ask(Ask::Status);
    assert_eq!(window.next(), Update::Running(Kind::Status));
    assert_eq!(
        window.next(),
        Update::Ended(Failure::Lost { in_flight: true })
    );
}

#[test]
fn a_hang_up_does_nothing_without_a_session() {
    assert!(!HangUp::default().hang_up());
    let window = Window::on(Connect::Pkexec {
        program: PathBuf::from("/nonexistent/pkexec"),
        engine: PathBuf::from("/mnt/data/nails"),
    });
    assert!(matches!(
        window.next(),
        Update::Ended(Failure::NotStarted(_))
    ));
    assert!(!window.worker.hang_up().hang_up());
}
