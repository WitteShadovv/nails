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
//! A destructive operation runs in two requests. The plan request names what
//! it would delete and hands out a single-use token; only the apply request
//! carrying that token deletes it, and any other request in between withdraws
//! the plan.
//!
//! The helper reads bytes from a process less trusted than itself, so its
//! decoder ([`decode_request`]) is strict: a bounded line, no unknown field or
//! operation, no duplicate key, the exact protocol version, and arguments
//! checked for shape before any of them reaches the engine. A request it
//! refuses ends the session. The decoder is the target of a libFuzzer target
//! (`fuzz/fuzz_targets/helper_request.rs`).

use serde::{Deserialize, Serialize};

use crate::events::Event;

/// The version of this protocol. A window and a helper talk only when theirs
/// are equal.
pub const PROTOCOL_VERSION: u32 = 1;

/// The longest request line the helper reads, in bytes, without its newline.
/// No request needs more than a few hundred; a longer line ends the session
/// before it is parsed.
pub const MAX_LINE_BYTES: usize = 16 * 1024;

/// The longest version string either side may name in its hello.
pub const MAX_ENGINE_BYTES: usize = 64;

/// The length of a plan token, in lowercase hexadecimal digits.
pub const TOKEN_HEX_DIGITS: usize = 32;

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
        }
    }
}

/// The options of `nails check`, each absent one off.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CheckArgs {
    /// `--overlay-only`.
    pub overlay_only: bool,
    /// `--nixos-flake`.
    pub nixos_flake: Option<String>,
    /// `--allow-persistent-decoy`.
    pub allow_persistent_decoy: bool,
    /// `--allow-decoy-storage`.
    pub allow_decoy_storage: bool,
    /// `--allow-discards`.
    pub allow_discards: bool,
}

/// The options of `nails config show` a window can give. The commented
/// example (`--example`) is not one: the CLI prints it only as TOML.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConfigShowArgs {
    /// `--nixos-flake`.
    pub nixos_flake: Option<String>,
}

/// The arguments of `nails discard` a plan takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscardPlanArgs {
    /// The absolute path whose hidden copy is discarded.
    pub target: String,
    /// `--allow-decoy-storage`.
    #[serde(default)]
    pub allow_decoy_storage: bool,
}

/// The token of a plan, which its apply request carries back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    /// [`TOKEN_HEX_DIGITS`] lowercase hexadecimal digits.
    pub token: String,
}

/// The data of the answer to [`Op::DiscardPlan`] when there is something to
/// delete: what the apply would remove, and the token that applies it. (With
/// nothing to delete the answer is the envelope `nails discard` prints, and
/// there is no token.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscardPlanData {
    /// The path whose hidden copy the apply discards.
    pub target: String,
    /// The directories and files the apply removes.
    pub removals: Vec<String>,
    /// Whether the apply drops the hidden Nix database and store paths.
    pub resets_nix_store: bool,
    /// The token the apply request carries back.
    pub token: String,
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
    /// path, a malformed token).
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
        Op::Check(args) => valid_flake(args.nixos_flake.as_deref()),
        Op::ConfigShow(args) => valid_flake(args.nixos_flake.as_deref()),
        Op::DiscardPlan(args) => valid_target(&args.target),
        Op::DiscardApply(token) => valid_token(&token.token),
        Op::Status | Op::ConfigPath | Op::ConfigValidate => Ok(()),
    }
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
    if !target.starts_with('/') || target.chars().any(char::is_control) {
        return Err("the discard target is an absolute path with no control character".to_string());
    }
    Ok(())
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
