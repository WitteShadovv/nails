// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The protocol client against a fake helper on a socket pair: the
//! handshake, one request at a time with its events, a refused request, and
//! a plan's token taken back by its apply.

mod support;

use nails_api::protocol::{
    ActivateArgs, CheckArgs, DeactivateArgs, DiscardPlanArgs, ErrorCode, Frame, Hello, InitArgs,
    Op, PROTOCOL_VERSION, ProtocolError, RELEASE, Token,
};
use nails_api::{CheckOutcome, Event};
use nails_gui::client::{Answer, Client, ClientError, Plan, PlanAnswer, PlanData, ours};
use serde_json::json;
use support::{FakeHelper, event, hello_answer, result};

/// A helper of the window's own release that answers the hello and then
/// whatever `respond` scripts.
fn greeted<F>(mut respond: F) -> (Client, FakeHelper)
where
    F: FnMut(&nails_api::protocol::Request) -> Option<Vec<Frame>> + Send + 'static,
{
    let (window, helper) = FakeHelper::start(ours(), move |request| match &request.op {
        Op::Hello(hello) => Some(vec![hello_answer(request.id, hello)]),
        _ => respond(request),
    });
    let client = Client::connect(window).expect("the handshake passes");
    (client, helper)
}

fn other(protocol: u32, engine: &str) -> Hello {
    Hello {
        protocol,
        engine: engine.to_string(),
    }
}

fn token() -> String {
    "0123456789abcdef".repeat(2)
}

#[test]
fn the_window_names_this_protocol_and_the_engine_release_it_was_built_for() {
    assert_eq!(ours(), other(PROTOCOL_VERSION, RELEASE));
}

#[test]
fn a_helper_of_the_same_release_gets_the_windows_hello_and_nothing_else() {
    let (client, helper) = greeted(|_| None);
    assert_eq!(client.engine(), &ours());
    drop(client);
    let requests = helper.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(requests[0].id, 1);
    assert_eq!(requests[0].op, Op::Hello(ours()));
}

#[test]
fn a_helper_of_another_release_or_protocol_is_refused_before_anything_is_sent() {
    for theirs in [
        other(PROTOCOL_VERSION, "0.0.1"),
        other(PROTOCOL_VERSION + 1, RELEASE),
    ] {
        let (window, helper) = FakeHelper::start(theirs.clone(), |_| None);
        match Client::connect(window) {
            Err(ClientError::Mismatch { window, engine }) => {
                assert_eq!(window, ours());
                assert_eq!(engine, theirs);
            }
            Err(other) => panic!("{other:?}"),
            Ok(_) => panic!("a helper of {theirs:?} was taken"),
        }
        assert!(
            helper.requests().is_empty(),
            "nothing was sent to {theirs:?}"
        );
    }
}

#[test]
fn a_hello_the_helper_refuses_ends_the_session() {
    let (window, helper) = FakeHelper::start(ours(), |request| {
        Some(vec![Frame::Error {
            id: Some(request.id),
            error: ProtocolError {
                code: ErrorCode::Handshake,
                message: "use the window and the engine of one release".to_string(),
            },
        }])
    });
    match Client::connect(window) {
        Err(ClientError::Refused(error)) => assert_eq!(error.code, ErrorCode::Handshake),
        Err(other) => panic!("{other:?}"),
        Ok(_) => panic!("a refused hello opened a session"),
    }
    assert_eq!(helper.requests().len(), 1);
}

#[test]
fn a_helper_that_closes_before_its_hello_is_gone() {
    let (window, helper) = support::pair();
    drop(helper);
    assert!(matches!(Client::connect(window), Err(ClientError::Closed)));
}

#[test]
fn a_helper_that_opens_with_anything_but_its_hello_is_not_a_helper() {
    for opening in [
        "not json".to_string(),
        event(1, Event::PointOfNoReturn).to_line(),
    ] {
        let (window, helper) = FakeHelper::start_raw(vec![opening.clone()], |_| None);
        match Client::connect(window) {
            Err(ClientError::Broken(_)) => {}
            Err(other) => panic!("{opening}: {other:?}"),
            Ok(_) => panic!("a session opened on {opening}"),
        }
        assert!(
            helper.requests().is_empty(),
            "nothing was sent after {opening}"
        );
    }
}

#[test]
fn a_hello_answered_with_something_else_is_not_a_session() {
    let (window, _helper) = FakeHelper::start(ours(), |request| {
        Some(vec![result(
            request.id,
            0,
            json!({"data": {"engine": "x"}}),
        )])
    });
    assert!(matches!(
        Client::connect(window),
        Err(ClientError::Broken(_))
    ));
}

#[test]
fn a_request_gets_its_events_in_order_and_then_its_answer() {
    let (mut client, helper) = greeted(|request| {
        let id = request.id;
        Some(match &request.op {
            Op::Check(_) => vec![
                event(
                    id,
                    Event::Check {
                        name: "swap".to_string(),
                        outcome: CheckOutcome::Pass,
                        message: "swap is off".to_string(),
                    },
                ),
                event(id, Event::Finished { success: true }),
                result(id, 0, json!({"command": "check"})),
            ],
            Op::Status => vec![result(id, 3, json!({"command": "status"}))],
            _ => return None,
        })
    });
    let mut events = Vec::new();
    let answer = client
        .call(Op::Check(CheckArgs::default()), &mut |e| events.push(e))
        .unwrap();
    assert_eq!(
        answer,
        Answer {
            exit: 0,
            envelope: json!({"command": "check"})
        }
    );
    assert_eq!(events.len(), 2, "{events:?}");
    assert!(matches!(&events[0], Event::Check { name, .. } if name == "swap"));
    let status = client
        .call(Op::Status, &mut |_| panic!("no event"))
        .unwrap();
    assert_eq!(status.exit, 3);
    drop(client);
    let ids: Vec<u64> = helper.requests().iter().map(|r| r.id).collect();
    assert_eq!(ids, vec![1, 2, 3], "one number a request, in order");
}

#[test]
fn a_frame_of_another_request_breaks_the_session() {
    for stray in [
        event(99, Event::PointOfNoReturn),
        result(99, 0, json!({})),
        Frame::Hello(ours()),
    ] {
        let (mut client, _helper) = greeted(move |_| Some(vec![stray.clone()]));
        let error = client.call(Op::Status, &mut |_| {}).unwrap_err();
        assert!(matches!(error, ClientError::Broken(_)), "{error:?}");
        assert!(error.ends_session());
        assert!(matches!(
            client.call(Op::Status, &mut |_| {}),
            Err(ClientError::Closed)
        ));
    }
}

#[test]
fn a_refused_request_ends_the_session_unless_only_its_token_was_refused() {
    let (mut client, _helper) = greeted(|request| {
        Some(vec![Frame::Error {
            id: Some(request.id),
            error: ProtocolError {
                code: ErrorCode::Malformed,
                message: "not a request".to_string(),
            },
        }])
    });
    let error = client.call(Op::Status, &mut |_| {}).unwrap_err();
    assert!(matches!(&error, ClientError::Refused(e) if e.code == ErrorCode::Malformed));
    assert!(error.ends_session());
    assert!(matches!(
        client.call(Op::Status, &mut |_| {}),
        Err(ClientError::Closed)
    ));

    let bad_token = ClientError::Refused(ProtocolError {
        code: ErrorCode::BadToken,
        message: "make the plan again".to_string(),
    });
    assert!(!bad_token.ends_session());
    assert!(!ClientError::PlanWithdrawn.ends_session());
}

#[test]
fn a_helper_that_closes_while_a_request_runs_ends_the_session() {
    let (mut client, _helper) = greeted(|_| None);
    assert!(matches!(
        client.call(Op::Status, &mut |_| {}),
        Err(ClientError::Closed)
    ));
    assert!(matches!(
        client.call(Op::Status, &mut |_| {}),
        Err(ClientError::Closed)
    ));
}

#[test]
fn hellos_plans_and_applies_are_not_sent_as_plain_requests() {
    let (mut client, helper) = greeted(|_| None);
    for op in [
        Op::Hello(ours()),
        Op::ActivatePlan(ActivateArgs::default()),
        Op::DeactivatePlan(DeactivateArgs::default()),
        Op::ActivateApply(Token { token: token() }),
    ] {
        let error = client.call(op.clone(), &mut |_| {}).unwrap_err();
        assert!(matches!(error, ClientError::Broken(_)), "{op:?}");
    }
    drop(client);
    assert_eq!(helper.requests().len(), 1, "only the hello went out");
}

fn discard_plan_answer(id: u64) -> Frame {
    result(
        id,
        0,
        json!({
            "schema_version": 2,
            "command": "discard",
            "ok": true,
            "data": {
                "target": "/home/op/notes",
                "removals": ["/mnt/data/root/upper/home/op/notes"],
                "resets_nix_store": false,
                "token": token(),
            },
        }),
    )
}

#[test]
fn a_plan_hands_out_its_data_and_its_apply_carries_the_token_back() {
    let (mut client, helper) = greeted(|request| {
        let id = request.id;
        Some(match &request.op {
            Op::DiscardPlan(_) => vec![discard_plan_answer(id)],
            Op::DiscardApply(_) => vec![result(id, 0, json!({"command": "discard", "ok": true}))],
            _ => return None,
        })
    });
    let args = DiscardPlanArgs {
        target: "/home/op/notes".to_string(),
        allow_decoy_storage: false,
    };
    let planned = match client
        .plan(Plan::Discard(args.clone()), &mut |_| {})
        .unwrap()
    {
        PlanAnswer::Ready(planned) => planned,
        other => panic!("{other:?}"),
    };
    match planned.data() {
        PlanData::Discard(data) => {
            assert_eq!(data.target, "/home/op/notes");
            assert_eq!(data.token, token());
        }
        other => panic!("{other:?}"),
    }
    let answer = client.apply(planned, &mut |_| {}).unwrap();
    assert_eq!(answer.envelope["ok"], true);
    drop(client);
    let ops: Vec<Op> = helper.requests().into_iter().map(|r| r.op).collect();
    assert_eq!(
        ops[1..],
        [
            Op::DiscardPlan(args),
            Op::DiscardApply(Token { token: token() }),
        ]
    );
}

#[test]
fn every_kind_of_plan_applies_with_its_own_apply() {
    let plans = [
        (
            Plan::Activate(ActivateArgs::default()),
            json!({"warning": null, "defaults_notice": null, "builds_hidden_system": false, "token": token()}),
        ),
        (
            Plan::Deactivate(DeactivateArgs { poweroff: true }),
            json!({"poweroff": true, "warnings": ["the network stays"], "token": token()}),
        ),
        (
            Plan::Init(InitArgs {
                path: "/mnt/data".to_string(),
                allow_decoy_storage: false,
                hardware_config: None,
                no_hardware_config: true,
            }),
            json!({"path": "/mnt/data", "hardware_config": null, "skipped": "no NixOS", "warnings": [], "token": token()}),
        ),
    ];
    for (plan, data) in plans {
        let answer = data.clone();
        let (mut client, helper) = greeted(move |request| {
            let id = request.id;
            Some(if request.op.apply_token().is_some() {
                vec![result(id, 0, json!({"ok": true}))]
            } else {
                vec![result(id, 0, json!({"ok": true, "data": answer.clone()}))]
            })
        });
        let Ok(PlanAnswer::Ready(planned)) = client.plan(plan.clone(), &mut |_| {}) else {
            panic!("{plan:?} did not hold");
        };
        client.apply(planned, &mut |_| {}).unwrap();
        drop(client);
        let ops: Vec<Op> = helper.requests().into_iter().map(|r| r.op).collect();
        let expected = match plan {
            Plan::Activate(_) => Op::ActivateApply(Token { token: token() }),
            Plan::Deactivate(_) => Op::DeactivateApply(Token { token: token() }),
            Plan::Init(_) => Op::InitApply(Token { token: token() }),
            Plan::Discard(_) => unreachable!(),
        };
        assert_eq!(ops[2], expected);
    }
}

#[test]
fn a_plan_with_nothing_to_apply_is_the_operations_own_answer() {
    let settled = json!({"schema_version": 2, "command": "deactivate", "ok": false, "error": {"code": "invalid_state", "message": "no hidden session", "next": null}});
    let answer = settled.clone();
    let (mut client, _helper) =
        greeted(move |request| Some(vec![result(request.id, 7, answer.clone())]));
    match client
        .plan(Plan::Deactivate(DeactivateArgs::default()), &mut |_| {})
        .unwrap()
    {
        PlanAnswer::Settled(answer) => assert_eq!(
            answer,
            Answer {
                exit: 7,
                envelope: settled
            }
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_plan_withdrawn_by_another_request_is_not_applied() {
    let (mut client, helper) = greeted(|request| {
        let id = request.id;
        Some(match &request.op {
            Op::DiscardPlan(_) => vec![discard_plan_answer(id)],
            _ => vec![result(id, 0, json!({"command": "status"}))],
        })
    });
    let args = DiscardPlanArgs {
        target: "/home/op/notes".to_string(),
        allow_decoy_storage: false,
    };
    let Ok(PlanAnswer::Ready(planned)) = client.plan(Plan::Discard(args), &mut |_| {}) else {
        panic!("the plan did not hold");
    };
    client.call(Op::Status, &mut |_| {}).unwrap();
    assert!(matches!(
        client.apply(planned, &mut |_| {}),
        Err(ClientError::PlanWithdrawn)
    ));
    drop(client);
    let requests = helper.requests();
    assert_eq!(requests.len(), 3, "the apply was never sent: {requests:?}");
}

#[test]
fn a_plan_answer_whose_data_is_not_that_plans_breaks_the_session() {
    let (mut client, _helper) = greeted(|request| {
        Some(vec![result(
            request.id,
            0,
            json!({"ok": true, "data": {"token": "x", "unknown": 1}}),
        )])
    });
    let error = client
        .plan(Plan::Activate(ActivateArgs::default()), &mut |_| {})
        .unwrap_err();
    assert!(matches!(error, ClientError::Broken(_)), "{error:?}");
}
