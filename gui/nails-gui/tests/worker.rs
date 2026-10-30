// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The worker against a fake helper: what the window hears for each ask,
//! the plan that waits for its apply or is withdrawn, the session that ends,
//! and pkexec's own way of ending before the helper speaks.

mod support;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use nails_api::protocol::{
    CheckArgs, DiscardPlanArgs, Frame, Hello, Op, PROTOCOL_VERSION, Request, Token,
};
use nails_api::{CheckOutcome, Event};
use nails_gui::client::{Plan, PlanData, ours};
use nails_gui::worker::{Ask, Connect, Failure, Kind, Update, spawn};
use serde_json::json;
use support::{FakeHelper, event, hello_answer, result};

/// The window's side of a worker: its asks and what it hears.
struct Window {
    asks: std::sync::mpsc::Sender<Ask>,
    heard: Receiver<Update>,
}

impl Window {
    fn on(connect: Connect) -> Self {
        let (tell, heard) = channel();
        let asks = spawn(connect, move |update| {
            let _ = tell.send(update);
        });
        Self { asks, heard }
    }

    fn next(&self) -> Update {
        self.heard
            .recv_timeout(Duration::from_secs(10))
            .expect("the worker reports")
    }

    fn ask(&self, ask: Ask) {
        self.asks.send(ask).expect("the worker listens");
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
