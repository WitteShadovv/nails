// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A request line from a window, as the engine's root helper decodes it
//! (`nails_api::protocol::decode_request`). The helper runs as root and the
//! window as the operator, so these are bytes from a less trusted process.
//!
//! The input is one line, up to past the helper's length limit
//! (`fuzz/options/helper_request.options`). The target checks that a line
//! past that limit or holding a newline is always refused, that an accepted
//! request follows the protocol's version and has arguments of the shape the
//! protocol states, checked here on their own rather than by the decoder's
//! own validation (every path absolute with no control character, a token of
//! 32 lowercase hexadecimal digits, no two options the CLI refuses together,
//! a configuration change of 1 to 32 keys shaped as keys of `nails.toml`,
//! each named once, with bounded values free of control characters),
//! and that an accepted request, written back as the window writes it, is
//! read again as the same request: through the decoder where the written form
//! fits, and past its length check where that form, which names every field,
//! no longer does.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_api::protocol::{
    ConfigEditArgs, ErrorCode, MAX_KEY_BYTES, MAX_LINE_BYTES, MAX_LIST_ENTRIES, MAX_SETTING_BYTES,
    MAX_SETTINGS, Op, PROTOCOL_VERSION, RehearseScanArgs, Request, SettingValue, VerifyArgs,
    decode_request, validate,
};

/// A path the helper may hand the engine.
fn path_ok(path: &str) -> bool {
    path.starts_with('/') && !path.chars().any(char::is_control)
}

fn flake_ok(flake: Option<&String>) -> bool {
    flake.is_none_or(|flake| !flake.is_empty() && !flake.chars().any(char::is_control))
}

fn token_ok(token: &str) -> bool {
    token.len() == 32
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn verify_ok(args: &VerifyArgs) -> bool {
    args.offline == args.root.is_some()
        && (args.offline || !args.examiner)
        && (args.examiner || args.disk.is_none())
        && args.root.as_deref().is_none_or(path_ok)
        && args.disk.as_deref().is_none_or(path_ok)
}

fn scan_ok(args: &RehearseScanArgs) -> bool {
    !(args.offline && !args.devices.is_empty())
        && args.offline == !args.images.is_empty()
        && (args.offline || args.token_file.is_none())
        && args.devices.iter().all(|path| path_ok(path))
        && args.images.iter().all(|path| path_ok(path))
        && args.token_file.as_deref().is_none_or(path_ok)
}

/// A key of `nails.toml` as a change names it: lowercase letters, digits and
/// `_`, with one `.` between a table and its key.
fn key_ok(key: &str) -> bool {
    let part = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    };
    key.len() <= MAX_KEY_BYTES
        && match key.split_once('.') {
            Some((table, name)) => part(table) && part(name),
            None => part(key),
        }
}

fn value_ok(value: &SettingValue) -> bool {
    let text =
        |text: &String| text.len() <= MAX_SETTING_BYTES && !text.chars().any(char::is_control);
    match value {
        SettingValue::Bool(_) | SettingValue::Integer(_) => true,
        SettingValue::Text(value) => text(value),
        SettingValue::List(values) => values.len() <= MAX_LIST_ENTRIES && values.iter().all(text),
    }
}

/// A configuration change: 1 to 32 keys, each named once, each value bounded.
fn edit_ok(args: &ConfigEditArgs) -> bool {
    let keys: Vec<&str> = args
        .set
        .iter()
        .map(|setting| setting.key.as_str())
        .chain(args.unset.iter().map(String::as_str))
        .collect();
    (1..=MAX_SETTINGS).contains(&keys.len())
        && keys.iter().all(|key| key_ok(key))
        && keys
            .iter()
            .enumerate()
            .all(|(index, key)| !keys[..index].contains(key))
        && args.set.iter().all(|setting| value_ok(&setting.value))
}

/// Whether `op` has the shape the protocol states for its arguments.
fn shaped(op: &Op) -> bool {
    match op {
        Op::Hello(hello) => {
            !hello.engine.is_empty()
                && hello.engine.len() <= 64
                && hello.engine.bytes().all(|b| b.is_ascii_graphic())
        }
        Op::Check(args) => {
            !(args.overlay_only && args.nixos_flake.is_some())
                && flake_ok(args.nixos_flake.as_ref())
        }
        Op::ActivatePlan(args) => {
            !(args.overlay_only && args.nixos_flake.is_some())
                && flake_ok(args.nixos_flake.as_ref())
        }
        Op::ConfigShow(args) => flake_ok(args.nixos_flake.as_ref()),
        Op::DiscardPlan(args) => path_ok(&args.target),
        Op::Emergency(args) => !(args.poweroff && args.reboot),
        Op::Verify(args) => verify_ok(args),
        Op::RehearsePlant(args) => args.user.as_deref().is_none_or(|user| {
            !user.is_empty()
                && user.len() <= 256
                && !user.chars().any(|c| c.is_control() || c == '/' || c == ':')
        }),
        Op::RehearseScan(args) => scan_ok(args),
        Op::InitPlan(args) => {
            path_ok(&args.path)
                && args.hardware_config.as_deref().is_none_or(path_ok)
                && !(args.no_hardware_config && args.hardware_config.is_some())
        }
        Op::ConfigEditPlan(args) => edit_ok(args),
        Op::DiscardApply(token)
        | Op::ActivateApply(token)
        | Op::DeactivateApply(token)
        | Op::InitApply(token)
        | Op::ConfigEditApply(token) => token_ok(&token.token),
        Op::Status
        | Op::ConfigPath
        | Op::ConfigValidate
        | Op::DeactivatePlan(_)
        | Op::Recover
        | Op::RehearseStatus
        | Op::RehearseReset => true,
    }
}

fuzz_target!(|data: &[u8]| {
    let decoded = decode_request(data);
    if data.len() > MAX_LINE_BYTES {
        let refused = decoded
            .as_ref()
            .expect_err("an overlong request was accepted");
        assert_eq!(refused.error.code, ErrorCode::TooLong);
        return;
    }
    if data.contains(&b'\n') {
        assert!(decoded.is_err(), "a multi-line request was accepted");
    }
    let Ok(request) = decoded else {
        return;
    };
    assert_eq!(request.v, PROTOCOL_VERSION);
    assert!(shaped(&request.op), "accepted out of shape: {request:?}");
    let line = request.to_line();
    assert!(!line.contains('\n'), "{line}");
    let again = decode_request(line.as_bytes());
    if line.len() > MAX_LINE_BYTES {
        // Written back with every field, a request accepted close to the limit
        // can be longer than the form it came in. The helper refuses that line
        // as too long before it parses it, so it is read here past the length
        // check: it must still be the same request, of the same shape.
        let refused = again.map_err(|refusal| refusal.error.code);
        assert_eq!(refused, Err(ErrorCode::TooLong), "{line}");
        let parsed: Request =
            serde_json::from_str(&line).unwrap_or_else(|error| panic!("{error}: {line}"));
        assert_eq!(parsed, request, "{line}");
        assert_eq!(validate(&parsed.op), Ok(()), "{line}");
        assert!(shaped(&parsed.op), "{line}");
    } else {
        assert_eq!(again.as_ref(), Ok(&request), "{line}");
    }
});
