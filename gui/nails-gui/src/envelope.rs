// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Reading the envelopes the window shows.
//!
//! The helper answers each request with the envelope the CLI prints under
//! `--json` (`docs/schemas/`). The engine's own envelope types only
//! serialize: they borrow their codes and much of their data from the
//! engine. So the window reads them through owned types of its own here, as
//! strictly as the schemas are where they are strict: the envelope and its
//! error body take no unknown field, and a contract version other than
//! [`SCHEMA_VERSION`] is refused. A command's data is read for the fields the
//! window shows, and the fields it does not show are left alone.

use nails_api::SCHEMA_VERSION;
use serde::Deserialize;
use serde::de::DeserializeOwned;

/// A machine-readable result.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope<T> {
    /// The contract version.
    pub schema_version: u32,
    /// The command that answered.
    pub command: String,
    /// Whether it succeeded (exit 0 or 9).
    pub ok: bool,
    /// Its data, when it has any.
    #[serde(default = "none")]
    pub data: Option<T>,
    /// Its failure, when it failed.
    #[serde(default)]
    pub error: Option<ErrorBody>,
}

fn none<T>() -> Option<T> {
    None
}

/// Why a command failed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    /// A stable code.
    pub code: String,
    /// The sentence a person reads, which may run to several lines.
    pub message: String,
    /// The NAILS command to run next, when the fix is one. Always present,
    /// `null` when there is none.
    #[serde(deserialize_with = "Option::deserialize")]
    pub next: Option<NextStep>,
}

/// The command to run next: the words after the binary.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NextStep {
    /// The subcommand words (`recover`, `deactivate`).
    pub command: String,
}

/// Why an envelope could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadError(pub String);

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Read `value` as the envelope of `command`.
///
/// # Errors
///
/// A [`ReadError`] for a value that is not such an envelope: another shape,
/// another contract version or another command.
pub fn read<T: DeserializeOwned>(
    value: &serde_json::Value,
    command: &str,
) -> Result<Envelope<T>, ReadError> {
    let envelope: Envelope<T> = serde_json::from_value(value.clone())
        .map_err(|error| ReadError(format!("the {command} answer is not an envelope: {error}")))?;
    if envelope.schema_version != SCHEMA_VERSION {
        return Err(ReadError(format!(
            "the {command} answer follows contract {}, the window reads {SCHEMA_VERSION}",
            envelope.schema_version
        )));
    }
    if envelope.command != command {
        return Err(ReadError(format!(
            "the answer to {command} came from {}",
            envelope.command
        )));
    }
    Ok(envelope)
}

/// Where the machine is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Place {
    /// The decoy.
    Decoy,
    /// A hidden session.
    Hidden,
    /// An activation is under way.
    Activating,
    /// The record could not be read, so nothing is known.
    Unknown,
}

/// The one thing that needs the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Attention {
    /// An activation was interrupted and left files in memory.
    Interrupted,
    /// The last hidden session ended without updating the record.
    EndedAbnormally,
    /// The last switch was refused.
    SwitchRefused,
    /// The record on the hidden volume cannot be read.
    RecordUnreadable,
    /// The hidden session has no way back.
    NoWayBack,
    /// The hidden volume is gone.
    VolumeLost,
    /// A disk is mounted over the hidden volume.
    VolumeCovered,
    /// The hidden volume is almost full.
    AlmostFull,
}

/// The data of `status` the window shows (`docs/schemas/status.schema.json`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StatusData {
    /// Where the machine is.
    pub place: Place,
    /// What needs the operator, if anything.
    pub attention: Option<Attention>,
    /// Why, when a reason is known.
    #[serde(default)]
    pub reason: Option<String>,
    /// What to do about it.
    #[serde(default)]
    pub remediation: Option<String>,
    /// How long the hidden session has run.
    #[serde(default)]
    pub uptime_seconds: Option<i64>,
    /// The hidden volume.
    #[serde(default)]
    pub hidden_root: Option<String>,
    /// Whether the hidden volume is mounted at its own path.
    #[serde(default)]
    pub hidden_root_mounted: bool,
}

/// The data of `check` the window shows (`docs/schemas/check.schema.json`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Readiness {
    /// Whether no check failed.
    pub ready: bool,
    /// Each check, in the order they ran.
    pub checks: Vec<CheckRow>,
    /// The tally.
    pub summary: Summary,
    /// The effective configuration, as far as the question before an
    /// activation names it.
    #[serde(default)]
    pub config: Option<ReadinessConfig>,
}

/// What the window reads of the configuration a check reports.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ReadinessConfig {
    /// Whose home the session runs in: `shared-home` (the decoy's) or
    /// `fresh-home`.
    #[serde(default)]
    pub persona_mode: Option<String>,
}

impl Readiness {
    /// Whether the session would run in the decoy's home, where its accounts
    /// and keys are live.
    #[must_use]
    pub fn in_decoy_home(&self) -> bool {
        self.config
            .as_ref()
            .and_then(|config| config.persona_mode.as_deref())
            == Some("shared-home")
    }
}

/// One check of a readiness report.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CheckRow {
    /// Its stable name.
    pub name: String,
    /// How it came out.
    pub status: CheckStatus,
    /// Its sentence.
    pub message: String,
    /// What fixes a failure, when the check says.
    #[serde(default)]
    pub remediation: Option<String>,
}

/// How one check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// It passed.
    Pass,
    /// It warned.
    Warn,
    /// It failed: activation refuses.
    Fail,
    /// It did not run.
    Skipped,
}

/// The data of `recover` the window shows
/// (`docs/schemas/recover.schema.json`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RecoverData {
    /// `clean`, `rolled_back` or `record_reset`.
    pub outcome: String,
    /// Mounts still below the next root, which a restart clears.
    #[serde(default)]
    pub remaining_mounts: Vec<String>,
    /// The hidden volume's devices that were still open.
    #[serde(default)]
    pub backend: Vec<BackendDevice>,
}

/// A device of the hidden volume a recovery found open.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BackendDevice {
    /// Its device-mapper name, which the window does not show.
    pub name: String,
    /// `closed` now, or `in_use` and left open.
    pub state: String,
}

/// The tally of a readiness report.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Summary {
    /// Checks that passed.
    pub passed: usize,
    /// Checks that warned.
    pub warnings: usize,
    /// Checks that failed.
    pub failed: usize,
    /// Checks that did not run.
    #[serde(default)]
    pub skipped: usize,
}

#[cfg(test)]
#[path = "envelope_tests.rs"]
mod tests;
