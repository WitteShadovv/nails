// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The wire protocol between a window and the engine's root helper.
//!
//! A window runs as the operator and never as root. It drives the static
//! `nails` engine through a helper that runs as root on the other end of a
//! private pipe (the helper's stdin and stdout), one JSON document per line:
//!
//! 1. The helper writes [`Frame::Hello`] with its [`PROTOCOL_VERSION`] and
//!    engine version.
//! 2. The window's first request is [`Op::Hello`] with its own two versions.
//!    The helper answers only when both are equal and otherwise ends the
//!    session: a window and an engine from different releases never talk.
//! 3. Then one request at a time. The helper reads the next request only once
//!    it has answered the last: zero or more [`Frame::Event`]s, then exactly one
//!    [`Frame::Result`] (the envelope the CLI prints under `--json` for the same
//!    operation, and its exit code) or one [`Frame::Error`].
//!
//! An operation the CLI asks the operator to confirm (activate, deactivate,
//! discard), that writes a new layout (init) or that changes the
//! configuration (config set and unset) runs in two requests. The plan
//! request says what the apply would do and hands out a single-use token; only
//! the apply request carrying that token does it, and any other request in
//! between withdraws the plan. Emergency is one request: it is the way out,
//! and the CLI asks nothing either.
//!
//! While an activation's apply runs, the helper watches the window's end of
//! the pipe. A window that closes it before the point of no return cancels
//! the activation, which unwinds as a Ctrl+C would; from the
//! [`Event::PointOfNoReturn`] on, the helper finishes the switch alone.
//!
//! The helper reads bytes from a process less trusted than itself, so its
//! decoder ([`decode_request`]) is strict: a bounded line, no unknown field or
//! operation, no duplicate key, the exact protocol version, and arguments
//! checked for shape before any of them reaches the engine. A request it
//! refuses ends the session. The decoder is the target of a libFuzzer target
//! (`fuzz/fuzz_targets/helper_request.rs`).

use serde::{Deserialize, Serialize};

use crate::events::Event;

mod args;

pub use args::{
    ActivateArgs, ActivatePlanData, CheckArgs, ConfigChange, ConfigEditArgs, ConfigEditPlanData,
    ConfigShowArgs, DeactivateArgs, DeactivatePlanData, DiscardPlanArgs, DiscardPlanData,
    EmergencyArgs, InitArgs, InitPlanData, PlanAdvisory, PowerOffInstead, RehearsePlantArgs,
    RehearseScanArgs, SettingArg, SettingValue, Token, VerifyArgs,
};

/// The version of this protocol. A window and a helper talk only when theirs
/// are equal.
pub const PROTOCOL_VERSION: u32 = 1;

/// The release this contract belongs to: the version of the NAILS workspace
/// the engine is built from, which `nails --version` prints. Both ends name it
/// in their [`Hello`] as `engine`. The window is built in a workspace of its
/// own with a version of its own, and links this crate from the engine's
/// tree, so this constant is how it names the engine release it was built
/// for.
pub const RELEASE: &str = env!("CARGO_PKG_VERSION");

/// The longest request line the helper reads, in bytes, without its newline.
/// No request needs more than a few hundred; a longer line ends the session
/// before it is parsed.
pub const MAX_LINE_BYTES: usize = 16 * 1024;

/// The longest version string either side may name in its hello.
pub const MAX_ENGINE_BYTES: usize = 64;

/// The length of a plan token, in lowercase hexadecimal digits.
pub const TOKEN_HEX_DIGITS: usize = 32;

/// The most keys one configuration change names, set and unset together.
pub const MAX_SETTINGS: usize = 32;

/// The longest key of a configuration change, in bytes.
pub const MAX_KEY_BYTES: usize = 64;

/// The longest string of a configuration value, or of one entry of a list, in
/// bytes.
pub const MAX_SETTING_BYTES: usize = 4096;

/// The most entries of a list value.
pub const MAX_LIST_ENTRIES: usize = 64;

/// The versions one side of the pipe speaks. The helper's first frame and the
/// window's first request both carry one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    /// The protocol version ([`PROTOCOL_VERSION`] of that side's build).
    pub protocol: u32,
    /// The release of that side's build (the engine's `nails --version`).
    pub engine: String,
}

/// One request from the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// The protocol version this request follows; must be [`PROTOCOL_VERSION`].
    pub v: u32,
    /// The window's number for this request, echoed by every frame that
    /// answers it.
    pub id: u64,
    /// The operation and its arguments.
    pub op: Op,
}

/// The operations a window can ask of the helper, each with the arguments the
/// matching CLI command takes.
///
/// On the wire an operation without arguments is its name (`"status"`) and
/// one with arguments is an object with one key, its name (`{"check":{}}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Op {
    /// The window's half of the handshake.
    Hello(Hello),
    /// `nails status`.
    Status,
    /// `nails check`.
    Check(CheckArgs),
    /// `nails config path`.
    ConfigPath,
    /// `nails config show`.
    ConfigShow(ConfigShowArgs),
    /// `nails config validate`, of the configuration the helper resolved. It
    /// takes no path: the helper reads no file a window names.
    ConfigValidate,
    /// The plan half of `nails discard`: what it would delete, and the token
    /// that applies it.
    DiscardPlan(DiscardPlanArgs),
    /// The apply half of `nails discard`, for the plan the token names.
    DiscardApply(Token),
    /// The plan half of `nails activate`: its gates and the state lock, and
    /// the token that enters.
    ActivatePlan(ActivateArgs),
    /// The apply half of `nails activate`, with each step streamed.
    ActivateApply(Token),
    /// The plan half of `nails deactivate`: whether a way back exists and what
    /// it will not put back.
    DeactivatePlan(DeactivateArgs),
    /// The apply half of `nails deactivate`.
    DeactivateApply(Token),
    /// `nails emergency`, at once.
    Emergency(EmergencyArgs),
    /// `nails recover`: the window's Clean Up and Reset Record.
    Recover,
    /// `nails verify`.
    Verify(VerifyArgs),
    /// `nails rehearse status`.
    RehearseStatus,
    /// `nails rehearse plant`.
    RehearsePlant(RehearsePlantArgs),
    /// `nails rehearse scan`.
    RehearseScan(RehearseScanArgs),
    /// `nails rehearse reset`.
    RehearseReset,
    /// The plan half of `nails init`: every precondition that can be read.
    InitPlan(InitArgs),
    /// The apply half of `nails init`.
    InitApply(Token),
    /// The plan half of `nails config set` and `nails config unset`: what each
    /// key named would hold, and the token that writes it.
    ConfigEditPlan(ConfigEditArgs),
    /// The apply half of a configuration change.
    ConfigEditApply(Token),
}

impl Op {
    /// The operation's name on the wire.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Op::Hello(_) => "hello",
            Op::Status => "status",
            Op::Check(_) => "check",
            Op::ConfigPath => "config_path",
            Op::ConfigShow(_) => "config_show",
            Op::ConfigValidate => "config_validate",
            Op::DiscardPlan(_) => "discard_plan",
            Op::DiscardApply(_) => "discard_apply",
            Op::ActivatePlan(_) => "activate_plan",
            Op::ActivateApply(_) => "activate_apply",
            Op::DeactivatePlan(_) => "deactivate_plan",
            Op::DeactivateApply(_) => "deactivate_apply",
            Op::Emergency(_) => "emergency",
            Op::Recover => "recover",
            Op::Verify(_) => "verify",
            Op::RehearseStatus => "rehearse_status",
            Op::RehearsePlant(_) => "rehearse_plant",
            Op::RehearseScan(_) => "rehearse_scan",
            Op::RehearseReset => "rehearse_reset",
            Op::InitPlan(_) => "init_plan",
            Op::InitApply(_) => "init_apply",
            Op::ConfigEditPlan(_) => "config_edit_plan",
            Op::ConfigEditApply(_) => "config_edit_apply",
        }
    }

    /// The token, when this is the apply half of a plan.
    #[must_use]
    pub fn apply_token(&self) -> Option<&str> {
        match self {
            Op::DiscardApply(token)
            | Op::ActivateApply(token)
            | Op::DeactivateApply(token)
            | Op::InitApply(token)
            | Op::ConfigEditApply(token) => Some(&token.token),
            _ => None,
        }
    }
}

/// One frame from the helper.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Frame {
    /// The helper's half of the handshake, always its first frame.
    Hello(Hello),
    /// Progress of the request `id`, as the CLI's progress lines show it.
    Event {
        /// The request this event belongs to.
        id: u64,
        /// The event.
        event: Event,
    },
    /// The outcome of the request `id`: the exit code and the envelope the
    /// CLI gives for the same operation.
    Result {
        /// The request this answers.
        id: u64,
        /// The exit code the CLI exits with for this outcome.
        exit: u8,
        /// The envelope, as the CLI prints it under `--json`.
        envelope: serde_json::Value,
    },
    /// The helper refused the request `id` (absent when the line could not be
    /// read as a request at all). Every refusal but a refused token ends the
    /// session.
    Error {
        /// The request this answers, when it could be read.
        id: Option<u64>,
        /// Why it was refused.
        error: ProtocolError,
    },
}

/// Why the helper refused a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolError {
    /// What kind of refusal it is.
    pub code: ErrorCode,
    /// A sentence for the person at the window.
    pub message: String,
}

/// The kinds of refusal, stable for a window to branch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The line was longer than [`MAX_LINE_BYTES`].
    TooLong,
    /// The line is not a request: not JSON, an unknown field or operation, a
    /// duplicate key, or a value of the wrong type.
    Malformed,
    /// The request follows another protocol version.
    UnsupportedVersion,
    /// An argument has the right type but not the right shape (a relative
    /// path, a malformed token, two options the CLI refuses together).
    InvalidArgument,
    /// The handshake failed: the first request was not a hello, a second hello
    /// came, or the two sides are from different releases.
    Handshake,
    /// An apply named no plan the helper holds.
    BadToken,
}

/// Why [`decode_request`] refused a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    /// The request's id, when the line was a request of the right version.
    pub id: Option<u64>,
    /// The refusal, as the error frame carries it.
    pub error: ProtocolError,
}

impl DecodeError {
    fn new(id: Option<u64>, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            id,
            error: ProtocolError {
                code,
                message: message.into(),
            },
        }
    }
}

/// Read one request line (without its newline), strictly.
///
/// # Errors
///
/// A [`DecodeError`] for a line longer than [`MAX_LINE_BYTES`] or holding a
/// newline, a line that is not exactly a [`Request`] (unknown or duplicate
/// fields included), a request of another [`PROTOCOL_VERSION`], or an argument
/// of the wrong shape ([`validate`]).
pub fn decode_request(line: &[u8]) -> Result<Request, DecodeError> {
    if line.len() > MAX_LINE_BYTES {
        return Err(DecodeError::new(
            None,
            ErrorCode::TooLong,
            format!("a request is at most {MAX_LINE_BYTES} bytes"),
        ));
    }
    if line.contains(&b'\n') {
        return Err(DecodeError::new(
            None,
            ErrorCode::Malformed,
            "a request is one line",
        ));
    }
    let request: Request = serde_json::from_slice(line).map_err(|error| {
        DecodeError::new(
            None,
            ErrorCode::Malformed,
            format!("not a request: {error}"),
        )
    })?;
    if request.v != PROTOCOL_VERSION {
        return Err(DecodeError::new(
            Some(request.id),
            ErrorCode::UnsupportedVersion,
            format!(
                "the request follows protocol {}, this helper speaks {PROTOCOL_VERSION}",
                request.v
            ),
        ));
    }
    validate(&request.op).map_err(|message| {
        DecodeError::new(Some(request.id), ErrorCode::InvalidArgument, message)
    })?;
    Ok(request)
}

/// Check the shape of an operation's arguments, beyond their types.
///
/// # Errors
///
/// The sentence that names the argument and what it must be.
pub fn validate(op: &Op) -> Result<(), String> {
    match op {
        Op::Hello(hello) => valid_engine(&hello.engine),
        Op::Check(args) => valid_build(args.overlay_only, args.nixos_flake.as_deref()),
        Op::ConfigShow(args) => valid_flake(args.nixos_flake.as_deref()),
        Op::DiscardPlan(args) => valid_target(&args.target),
        Op::ActivatePlan(args) => valid_build(args.overlay_only, args.nixos_flake.as_deref()),
        Op::Emergency(args) => conflict(args.poweroff && args.reboot, "--poweroff", "--reboot"),
        Op::Verify(args) => valid_verify(args),
        Op::RehearsePlant(args) => args.user.as_deref().map_or(Ok(()), valid_user),
        Op::RehearseScan(args) => valid_scan(args),
        Op::InitPlan(args) => valid_init(args),
        Op::ConfigEditPlan(args) => valid_config_edit(args),
        Op::DiscardApply(token)
        | Op::ActivateApply(token)
        | Op::DeactivateApply(token)
        | Op::InitApply(token)
        | Op::ConfigEditApply(token) => valid_token(&token.token),
        Op::Status
        | Op::ConfigPath
        | Op::ConfigValidate
        | Op::DeactivatePlan(_)
        | Op::Recover
        | Op::RehearseStatus
        | Op::RehearseReset => Ok(()),
    }
}

/// The longest account name a rehearsal plant takes.
const MAX_USER_BYTES: usize = 256;

/// A hidden NixOS build target and `--overlay-only`, which the CLI refuses
/// together.
fn valid_build(overlay_only: bool, flake: Option<&str>) -> Result<(), String> {
    conflict(
        overlay_only && flake.is_some(),
        "--overlay-only",
        "--nixos-flake",
    )?;
    valid_flake(flake)
}

/// Refuse two options the CLI refuses together.
fn conflict(both: bool, one: &str, other: &str) -> Result<(), String> {
    if both {
        return Err(format!("{one} and {other} cannot be given together"));
    }
    Ok(())
}

/// Refuse an option given without the one it needs, as the CLI does.
fn requires(given: bool, needed: bool, option: &str, needs: &str) -> Result<(), String> {
    if given && !needed {
        return Err(format!("{option} needs {needs}"));
    }
    Ok(())
}

/// A path the helper hands the engine: absolute, with no control character.
fn valid_path(what: &str, path: &str) -> Result<(), String> {
    if !path.starts_with('/') || path.chars().any(char::is_control) {
        return Err(format!(
            "the {what} is an absolute path with no control character"
        ));
    }
    Ok(())
}

fn valid_verify(args: &VerifyArgs) -> Result<(), String> {
    requires(args.offline, args.root.is_some(), "--offline", "--root")?;
    requires(args.root.is_some(), args.offline, "--root", "--offline")?;
    requires(args.examiner, args.offline, "--examiner", "--offline")?;
    requires(args.disk.is_some(), args.examiner, "--disk", "--examiner")?;
    if let Some(root) = &args.root {
        valid_path("offline root", root)?;
    }
    if let Some(disk) = &args.disk {
        valid_path("examiner's disk", disk)?;
    }
    Ok(())
}

fn valid_user(user: &str) -> Result<(), String> {
    let shaped = !user.is_empty()
        && user.len() <= MAX_USER_BYTES
        && !user.chars().any(|c| c.is_control() || c == '/' || c == ':');
    if !shaped {
        return Err(format!(
            "the user is 1 to {MAX_USER_BYTES} bytes with no control character, slash or colon"
        ));
    }
    Ok(())
}

fn valid_scan(args: &RehearseScanArgs) -> Result<(), String> {
    conflict(
        !args.devices.is_empty() && args.offline,
        "--device",
        "--offline",
    )?;
    requires(
        args.offline,
        !args.images.is_empty(),
        "--offline",
        "--image",
    )?;
    requires(
        !args.images.is_empty(),
        args.offline,
        "--image",
        "--offline",
    )?;
    requires(
        args.token_file.is_some(),
        args.offline,
        "--token-file",
        "--offline",
    )?;
    for device in &args.devices {
        valid_path("device", device)?;
    }
    for image in &args.images {
        valid_path("image", image)?;
    }
    if let Some(file) = &args.token_file {
        valid_path("token file", file)?;
    }
    Ok(())
}

fn valid_init(args: &InitArgs) -> Result<(), String> {
    conflict(
        args.no_hardware_config && args.hardware_config.is_some(),
        "--hardware-config",
        "--no-hardware-config",
    )?;
    valid_path("hidden volume", &args.path)?;
    if let Some(hardware) = &args.hardware_config {
        valid_path("hardware configuration", hardware)?;
    }
    Ok(())
}

/// A configuration change: at least one key, at most [`MAX_SETTINGS`], each
/// named once and shaped as a key of `nails.toml` is (lowercase letters,
/// digits, `_`, and a `.` between a table and its key), each string value
/// bounded and free of control characters. Which keys exist and what each
/// takes is the engine's to check, as it is for the CLI.
fn valid_config_edit(args: &ConfigEditArgs) -> Result<(), String> {
    let keys: Vec<&str> = args
        .set
        .iter()
        .map(|setting| setting.key.as_str())
        .chain(args.unset.iter().map(String::as_str))
        .collect();
    if keys.is_empty() || keys.len() > MAX_SETTINGS {
        return Err(format!(
            "a configuration change names 1 to {MAX_SETTINGS} keys"
        ));
    }
    for (index, key) in keys.iter().enumerate() {
        valid_key(key)?;
        if keys[..index].contains(key) {
            return Err(format!("the key {key} is named twice"));
        }
    }
    args.set
        .iter()
        .try_for_each(|setting| valid_setting_value(&setting.value))
}

fn valid_key(key: &str) -> Result<(), String> {
    let part = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    };
    let shaped = key.len() <= MAX_KEY_BYTES
        && match key.split_once('.') {
            Some((table, name)) => part(table) && part(name),
            None => part(key),
        };
    if !shaped {
        return Err(format!(
            "a key is at most {MAX_KEY_BYTES} bytes of lowercase letters, digits and `_`, with \
             one `.` between a table and its key"
        ));
    }
    Ok(())
}

fn valid_setting_value(value: &SettingValue) -> Result<(), String> {
    let text =
        |text: &String| text.len() <= MAX_SETTING_BYTES && !text.chars().any(char::is_control);
    let shaped = match value {
        SettingValue::Bool(_) | SettingValue::Integer(_) => true,
        SettingValue::Text(value) => text(value),
        SettingValue::List(values) => values.len() <= MAX_LIST_ENTRIES && values.iter().all(text),
    };
    if !shaped {
        return Err(format!(
            "a value is at most {MAX_SETTING_BYTES} bytes with no control character, and a list \
             at most {MAX_LIST_ENTRIES} of them"
        ));
    }
    Ok(())
}

fn valid_engine(engine: &str) -> Result<(), String> {
    let printable = engine.bytes().all(|b| b.is_ascii_graphic());
    if engine.is_empty() || engine.len() > MAX_ENGINE_BYTES || !printable {
        return Err(format!(
            "the engine version is 1 to {MAX_ENGINE_BYTES} printable ASCII characters"
        ));
    }
    Ok(())
}

fn valid_flake(flake: Option<&str>) -> Result<(), String> {
    match flake {
        Some(flake) if flake.is_empty() || flake.chars().any(char::is_control) => {
            Err("the flake reference is not empty and holds no control character".to_string())
        }
        _ => Ok(()),
    }
}

fn valid_target(target: &str) -> Result<(), String> {
    valid_path("discard target", target)
}

fn valid_token(token: &str) -> Result<(), String> {
    let hex = token
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if token.len() != TOKEN_HEX_DIGITS || !hex {
        return Err(format!(
            "a token is {TOKEN_HEX_DIGITS} lowercase hexadecimal digits"
        ));
    }
    Ok(())
}

impl Request {
    /// The request as one line, without its newline: what a window writes.
    #[must_use]
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).expect("a request always serializes")
    }
}

impl Frame {
    /// The frame as one line, without its newline: what the helper writes.
    #[must_use]
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).expect("a frame always serializes")
    }
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;
