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

/// The data of `deactivate` the window shows
/// (`docs/schemas/deactivate.schema.json`): it comes only once the switch is
/// enqueued.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeactivateData {
    /// Which switch was enqueued.
    pub status: DeactivateStatus,
    /// What the return does not put back, as a person reads it, and each
    /// device of the hidden volume left open, by its name.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// The devices of the hidden volume that could not be marked to close,
    /// which the window does not name.
    #[serde(default)]
    pub backend_left_open: Vec<String>,
}

/// Which switch a deactivation enqueued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeactivateStatus {
    /// The soft-reboot back to the decoy.
    ReturnRequested,
    /// The power-off.
    PoweroffRequested,
}

/// The data of `verify` the window shows (`docs/schemas/verify.schema.json`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct VerifyData {
    /// The verdict.
    pub status: VerifyStatus,
    /// What it found, notes included.
    pub findings: Vec<Finding>,
    /// A standard or a deep scan.
    pub scan_depth: ScanDepth,
    /// How many checks ran.
    pub checks_run: usize,
    /// What this run did not look at, one sentence each.
    pub areas_not_checked: Vec<String>,
}

/// A verdict of `verify`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyStatus {
    /// No known trace was found.
    Secure,
    /// A possible trace was found.
    Warning,
    /// A trace was found.
    Critical,
}

/// How deep `verify` looked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanDepth {
    /// The standard checks.
    Standard,
    /// `--deep`: homes, histories, temporary folders and the journal too.
    Deep,
}

/// One finding of `verify`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Finding {
    /// How much it weighs.
    pub severity: Severity,
    /// What kind of thing it is.
    pub category: String,
    /// What was found.
    pub message: String,
    /// How to deal with it, when the engine says.
    #[serde(default)]
    pub fix_guidance: Option<String>,
}

/// The weight of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// A note: not a trace.
    Info,
    /// A possible trace.
    Warn,
    /// A trace.
    Critical,
}

/// The data of every step of `rehearse` the window shows
/// (`docs/schemas/rehearse.schema.json`; the payload is the command's own,
/// `nails-cli/src/cli/commands/rehearse.rs`). The test words themselves are
/// never in it: only a fingerprint, and `<canary>` where a path holds them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RehearseData {
    /// Where the rehearsal stands.
    pub phase: Phase,
    /// Where the test words went at plant time, planted or skipped.
    #[serde(default)]
    pub channels: Vec<Channel>,
    /// A scan's result, from `rehearse scan`.
    #[serde(default)]
    pub scan: Option<ScanReport>,
    /// What `rehearse reset` removed.
    #[serde(default)]
    pub removed: Vec<String>,
}

/// Where a rehearsal stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// No rehearsal on the hidden volume.
    None,
    /// The test words are planted; no scan ran yet.
    Planted,
    /// At least one scan ran.
    Scanned,
}

/// One place the test words were planted in, or why not.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Channel {
    /// Which kind of place (`overlay-file`, `home-file`, `recent-files`,
    /// `system-log`, `process-cmdline`, `notification`).
    pub kind: String,
    /// Where, as the session saw it.
    pub location: String,
    /// Why it was not planted there, when it was not.
    #[serde(default)]
    pub skipped: Option<String>,
}

/// What a scan for the test words read and found.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ScanReport {
    /// Each device or image the scan read, or could not.
    pub devices: Vec<DeviceScan>,
    /// What no scan of this kind can see, one sentence each.
    pub not_visible: Vec<String>,
}

/// The scan of one device.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeviceScan {
    /// The device or image.
    pub device: String,
    /// Its size in bytes.
    pub size: u64,
    /// The bytes read.
    pub bytes_scanned: u64,
    /// Where the test words were found on it.
    pub hits: Vec<Hit>,
    /// More hits exist than are listed.
    #[serde(default)]
    pub hits_capped: bool,
    /// A byte limit stopped the scan early.
    #[serde(default)]
    pub limit_reached: bool,
    /// Why it could not be read.
    #[serde(default)]
    pub error: Option<String>,
    /// Why a clean read of it is not a clean result: its storage can hide
    /// the test words from this scan.
    #[serde(default)]
    pub blind_spot: Option<String>,
}

/// Where the test words were found.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Hit {
    /// The byte offset of the match.
    pub offset: u64,
}

/// The data of `discard` (`docs/schemas/discard.schema.json`), for a plan
/// with nothing to delete and for an apply.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DiscardData {
    /// The folder whose hidden changes were discarded.
    pub target: String,
    /// What was removed from the hidden volume; empty for nothing.
    pub removed: Vec<String>,
}

/// The data of `init` (`docs/schemas/init.schema.json`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct InitData {
    /// The hidden volume the layout was written to.
    pub root: String,
    /// Each part of the layout, created or already there.
    pub items: Vec<InitItem>,
    /// What the person should know about it.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Lines of information (the hidden NixOS layout was skipped).
    #[serde(default)]
    pub notes: Vec<String>,
}

/// One part of an init's layout.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct InitItem {
    /// Its path.
    pub path: String,
    /// `created` or `already_present`.
    pub status: InitItemStatus,
}

/// Whether init made a part of the layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InitItemStatus {
    /// Init made it.
    Created,
    /// It was there already.
    AlreadyPresent,
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
