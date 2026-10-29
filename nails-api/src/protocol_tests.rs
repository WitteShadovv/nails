// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

fn decode(line: &str) -> Result<Request, DecodeError> {
    decode_request(line.as_bytes())
}

fn code(line: &str) -> ErrorCode {
    decode(line).expect_err(line).error.code
}

fn token() -> String {
    "0123456789abcdef".repeat(2)
}

/// Every operation a window can send survives the trip through its own line.
#[test]
fn every_operation_round_trips_through_its_line() {
    let ops = [
        Op::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            engine: "0.3.0-rc.3".to_string(),
        }),
        Op::Status,
        Op::Check(CheckArgs {
            overlay_only: false,
            nixos_flake: Some("/mnt/data/nixos#host".to_string()),
            allow_persistent_decoy: true,
            allow_decoy_storage: true,
            allow_discards: true,
        }),
        Op::ConfigPath,
        Op::ConfigShow(ConfigShowArgs {
            nixos_flake: Some("/srv/cfg#host".to_string()),
        }),
        Op::ConfigValidate,
        Op::DiscardPlan(DiscardPlanArgs {
            target: "/home".to_string(),
            allow_decoy_storage: true,
        }),
        Op::DiscardApply(Token { token: token() }),
        Op::ActivatePlan(ActivateArgs {
            overlay_only: true,
            nixos_flake: None,
            allow_persistent_decoy: true,
            allow_decoy_storage: true,
            allow_discards: true,
        }),
        Op::ActivateApply(Token { token: token() }),
        Op::DeactivatePlan(DeactivateArgs { poweroff: true }),
        Op::DeactivateApply(Token { token: token() }),
        Op::Emergency(EmergencyArgs {
            poweroff: false,
            reboot: true,
        }),
        Op::Recover,
        Op::Verify(VerifyArgs {
            deep: true,
            offline: true,
            root: Some("/mnt/decoy".to_string()),
            examiner: true,
            disk: Some("/dev/sdb".to_string()),
        }),
        Op::RehearseStatus,
        Op::RehearsePlant(RehearsePlantArgs {
            user: Some("alice".to_string()),
        }),
        Op::RehearseScan(RehearseScanArgs {
            devices: Vec::new(),
            offline: true,
            images: vec!["/srv/decoy.raw".to_string()],
            token_file: Some("/mnt/data/token".to_string()),
            allow_same_boot: true,
            max_bytes: Some(1 << 30),
        }),
        Op::RehearseReset,
        Op::InitPlan(InitArgs {
            path: "/mnt/data".to_string(),
            allow_decoy_storage: true,
            hardware_config: Some("/etc/nixos/hardware-configuration.nix".to_string()),
            no_hardware_config: false,
        }),
        Op::InitApply(Token { token: token() }),
    ];
    for (id, op) in ops.into_iter().enumerate() {
        let request = Request {
            v: PROTOCOL_VERSION,
            id: id as u64,
            op,
        };
        let line = request.to_line();
        assert!(!line.contains('\n'), "{line}");
        assert_eq!(decode(&line).as_ref(), Ok(&request), "{line}");
        assert_eq!(request.op.name(), op_name_on_the_wire(&line), "{line}");
    }
}

/// The name an operation goes by in `line`: the string itself, or the one key
/// of its object.
fn op_name_on_the_wire(line: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(line).unwrap();
    match &value["op"] {
        serde_json::Value::String(name) => name.clone(),
        serde_json::Value::Object(map) => {
            assert_eq!(map.len(), 1);
            map.keys().next().unwrap().clone()
        }
        other => panic!("op is {other}"),
    }
}

#[test]
fn the_wire_shapes_are_the_documented_ones() {
    let status = decode(r#"{"v":1,"id":7,"op":"status"}"#).unwrap();
    assert_eq!(status.id, 7);
    assert_eq!(status.op, Op::Status);
    let check = decode(r#"{"v":1,"id":8,"op":{"check":{}}}"#).unwrap();
    assert_eq!(check.op, Op::Check(CheckArgs::default()));
    let plan = decode(r#"{"v":1,"id":9,"op":{"discard_plan":{"target":"/home"}}}"#).unwrap();
    assert_eq!(
        plan.op,
        Op::DiscardPlan(DiscardPlanArgs {
            target: "/home".to_string(),
            allow_decoy_storage: false,
        })
    );
}

#[test]
fn a_line_longer_than_the_limit_is_refused_before_it_is_parsed() {
    let padding = " ".repeat(MAX_LINE_BYTES);
    let line = format!(r#"{{"v":1,"id":1,"op":"status"}}{padding}"#);
    assert_eq!(code(&line), ErrorCode::TooLong);
    // At the limit exactly, trailing blanks are still one request.
    let request = r#"{"v":1,"id":1,"op":"status"}"#;
    let fits = format!("{request}{}", " ".repeat(MAX_LINE_BYTES - request.len()));
    assert_eq!(fits.len(), MAX_LINE_BYTES);
    assert!(decode(&fits).is_ok());
}

#[test]
fn a_newline_inside_the_line_is_refused() {
    assert_eq!(
        code("{\"v\":1,\n\"id\":1,\"op\":\"status\"}"),
        ErrorCode::Malformed
    );
}

#[test]
fn anything_but_exactly_a_request_is_malformed() {
    for line in [
        "",
        "not json",
        "[]",
        "null",
        r#"{"v":1,"id":1}"#,
        r#"{"v":1,"op":"status"}"#,
        r#"{"id":1,"op":"status"}"#,
        r#"{"v":1,"id":1,"op":"status","extra":true}"#,
        r#"{"v":1,"id":1,"op":"reboot"}"#,
        r#"{"v":1,"id":1,"op":{"check":{"force":true}}}"#,
        r#"{"v":1,"id":1,"op":{"check":{},"status":null}}"#,
        r#"{"v":1,"id":1,"id":2,"op":"status"}"#,
        r#"{"v":1,"id":1,"op":{"discard_plan":{"target":"/a","target":"/b"}}}"#,
        r#"{"v":1,"id":1,"op":{"discard_plan":{}}}"#,
        r#"{"v":1,"id":-1,"op":"status"}"#,
        r#"{"v":1,"id":1.5,"op":"status"}"#,
        r#"{"v":"1","id":1,"op":"status"}"#,
        r#"{"v":1,"id":1,"op":{"check":{"overlay_only":"yes"}}}"#,
        r#"{"v":1,"id":1,"op":{"hello":{"protocol":1}}}"#,
        r#"{"v":1,"id":1,"op":"status"} {"v":1,"id":2,"op":"status"}"#,
    ] {
        assert_eq!(code(line), ErrorCode::Malformed, "{line}");
        assert_eq!(decode(line).unwrap_err().id, None, "{line}");
    }
}

#[test]
fn a_request_of_another_protocol_version_is_refused_with_its_id() {
    let error = decode(r#"{"v":2,"id":5,"op":"status"}"#).unwrap_err();
    assert_eq!(error.id, Some(5));
    assert_eq!(error.error.code, ErrorCode::UnsupportedVersion);
}

#[test]
fn arguments_of_the_wrong_shape_are_refused_with_the_id() {
    let token_of =
        |token: &str| format!(r#"{{"v":1,"id":3,"op":{{"discard_apply":{{"token":"{token}"}}}}}}"#);
    let lines = [
        r#"{"v":1,"id":3,"op":{"discard_plan":{"target":"home"}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"discard_plan":{"target":""}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"discard_plan":{"target":"/home\u0000x"}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"check":{"nixos_flake":""}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"config_show":{"nixos_flake":"a\nb"}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"hello":{"protocol":1,"engine":""}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"hello":{"protocol":1,"engine":"0.3 rc"}}}"#.to_string(),
        format!(
            r#"{{"v":1,"id":3,"op":{{"hello":{{"protocol":1,"engine":"{}"}}}}}}"#,
            "9".repeat(MAX_ENGINE_BYTES + 1)
        ),
        token_of(&token()[1..]),
        token_of(&format!("{}0", token())),
        token_of(&token().to_uppercase()),
        token_of(&format!("{}g", &token()[1..])),
        // What the CLI refuses together, or one option without the one it
        // needs.
        r#"{"v":1,"id":3,"op":{"check":{"overlay_only":true,"nixos_flake":"/f#h"}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"activate_plan":{"overlay_only":true,"nixos_flake":"/f#h"}}}"#
            .to_string(),
        r#"{"v":1,"id":3,"op":{"activate_plan":{"nixos_flake":""}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"emergency":{"poweroff":true,"reboot":true}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"verify":{"offline":true}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"verify":{"root":"/mnt"}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"verify":{"offline":true,"root":"mnt"}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"verify":{"examiner":true}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"verify":{"offline":true,"root":"/m","disk":"/dev/sdb"}}}"#
            .to_string(),
        r#"{"v":1,"id":3,"op":{"rehearse_plant":{"user":""}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"rehearse_plant":{"user":"../root"}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"rehearse_plant":{"user":"a\u0007"}}}"#.to_string(),
        format!(
            r#"{{"v":1,"id":3,"op":{{"rehearse_plant":{{"user":"{}"}}}}}}"#,
            "a".repeat(MAX_USER_BYTES + 1)
        ),
        r#"{"v":1,"id":3,"op":{"rehearse_scan":{"devices":["/dev/sda"],"offline":true,"images":["/i"]}}}"#
            .to_string(),
        r#"{"v":1,"id":3,"op":{"rehearse_scan":{"offline":true}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"rehearse_scan":{"images":["/i"]}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"rehearse_scan":{"token_file":"/t"}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"rehearse_scan":{"devices":["sda"]}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"rehearse_scan":{"offline":true,"images":["i.raw"]}}}"#
            .to_string(),
        r#"{"v":1,"id":3,"op":{"init_plan":{"path":"data"}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"init_plan":{"path":"/d","hardware_config":"hw.nix"}}}"#
            .to_string(),
        r#"{"v":1,"id":3,"op":{"init_plan":{"path":"/d","hardware_config":"/h","no_hardware_config":true}}}"#
            .to_string(),
        token_of("x").replace("discard_apply", "activate_apply"),
        token_of("x").replace("discard_apply", "deactivate_apply"),
        token_of("x").replace("discard_apply", "init_apply"),
    ];
    for line in &lines {
        let error = decode(line).expect_err(line);
        assert_eq!(error.id, Some(3), "{line}");
        assert_eq!(error.error.code, ErrorCode::InvalidArgument, "{line}");
    }
    let longest = "9".repeat(MAX_ENGINE_BYTES);
    assert!(valid_engine(&longest).is_ok());
}

/// The shapes the CLI accepts are accepted: an option with the one it needs,
/// a longest account name, and every apply's token.
#[test]
fn arguments_of_the_right_shape_are_accepted() {
    for line in [
        r#"{"v":1,"id":3,"op":{"activate_plan":{}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"activate_plan":{"nixos_flake":"/f#h"}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"deactivate_plan":{}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"emergency":{}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"emergency":{"poweroff":true}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"verify":{}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"verify":{"deep":true}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"verify":{"offline":true,"root":"/m","examiner":true}}}"#
            .to_string(),
        r#"{"v":1,"id":3,"op":{"rehearse_plant":{}}}"#.to_string(),
        format!(
            r#"{{"v":1,"id":3,"op":{{"rehearse_plant":{{"user":"{}"}}}}}}"#,
            "a".repeat(MAX_USER_BYTES)
        ),
        r#"{"v":1,"id":3,"op":{"rehearse_scan":{}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"rehearse_scan":{"devices":["/dev/sda","/dev/sdb"]}}}"#.to_string(),
        r#"{"v":1,"id":3,"op":{"init_plan":{"path":"/mnt/data","no_hardware_config":true}}}"#
            .to_string(),
        r#"{"v":1,"id":3,"op":"recover"}"#.to_string(),
        r#"{"v":1,"id":3,"op":"rehearse_status"}"#.to_string(),
        r#"{"v":1,"id":3,"op":"rehearse_reset"}"#.to_string(),
    ] {
        assert!(decode(&line).is_ok(), "{line}");
    }
}

/// Exactly the apply halves carry a token.
#[test]
fn only_an_apply_carries_a_token() {
    let token = Token { token: token() };
    for op in [
        Op::DiscardApply(token.clone()),
        Op::ActivateApply(token.clone()),
        Op::DeactivateApply(token.clone()),
        Op::InitApply(token.clone()),
    ] {
        assert_eq!(op.apply_token(), Some(token.token.as_str()), "{op:?}");
    }
    for op in [
        Op::Status,
        Op::Recover,
        Op::DeactivatePlan(DeactivateArgs::default()),
        Op::Emergency(EmergencyArgs::default()),
    ] {
        assert_eq!(op.apply_token(), None, "{op:?}");
    }
}

#[test]
fn every_frame_round_trips_and_names_its_kind() {
    let frames = [
        (
            Frame::Hello(Hello {
                protocol: PROTOCOL_VERSION,
                engine: "0.3.0".to_string(),
            }),
            "hello",
        ),
        (
            Frame::Event {
                id: 1,
                event: Event::Finished { success: true },
            },
            "event",
        ),
        (
            Frame::Result {
                id: 1,
                exit: 4,
                envelope: serde_json::json!({"schema_version": 2, "ok": false}),
            },
            "result",
        ),
        (
            Frame::Error {
                id: None,
                error: ProtocolError {
                    code: ErrorCode::BadToken,
                    message: "no such plan".to_string(),
                },
            },
            "error",
        ),
    ];
    for (frame, kind) in frames {
        let line = frame.to_line();
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!(value.get(kind).is_some(), "{line}");
        assert_eq!(serde_json::from_str::<Frame>(&line).unwrap(), frame);
    }
}

#[test]
fn every_error_code_has_a_snake_case_name() {
    for (code, name) in [
        (ErrorCode::TooLong, "\"too_long\""),
        (ErrorCode::Malformed, "\"malformed\""),
        (ErrorCode::UnsupportedVersion, "\"unsupported_version\""),
        (ErrorCode::InvalidArgument, "\"invalid_argument\""),
        (ErrorCode::Handshake, "\"handshake\""),
        (ErrorCode::BadToken, "\"bad_token\""),
    ] {
        assert_eq!(serde_json::to_string(&code).unwrap(), name);
    }
}
