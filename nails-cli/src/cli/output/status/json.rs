// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! JSON output for the status command.
//!
//! The version-2 envelope says two things a reader branches on: `place` is
//! where the machine is (`decoy`, `hidden` or `activating`, or `unknown` when
//! the report could not be built), and `attention` names the one thing, if
//! any, that needs the operator. Together they replace the version-1
//! `posture`, `session`, `state` and `state_source` fields: the live view and
//! the record are folded into one verdict, and the record's own read outcome
//! shows only as the `record_unreadable` attention, wherever the machine is.

use serde::Serialize;

use crate::cli::output::envelope::{Envelope, EnvelopePrint};
use nails_core::SystemState;
use nails_core::status::{PolicyMountView, Posture, ReminderSeverity, StatusReport};

/// The `data` payload for `status --json`.
#[derive(Debug, Serialize)]
pub struct StatusData<'a> {
    /// Where the machine is: `decoy`, `hidden` or `activating`.
    place: &'static str,
    /// The one thing that needs the operator, or `null` when nothing does:
    /// `interrupted`, `ended_abnormally`, `switch_refused`, `record_unreadable`,
    /// `no_way_back`, `volume_lost`, `volume_covered` or `almost_full`.
    attention: Option<&'static str>,
    /// Why the place needs attention, when a reason is known; for
    /// `switch_refused`, the reason the switch gave.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    /// What to do about it.
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<&'a str>,
    /// When the hidden root was entered (ISO 8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    entered_at: Option<String>,
    /// Uptime of the hidden session in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime_seconds: Option<i64>,
    /// Human-readable uptime.
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime_formatted: Option<String>,
    /// The hidden NixOS toplevel.
    #[serde(skip_serializing_if = "Option::is_none")]
    hidden_system: Option<&'a str>,
    /// The decoy NixOS toplevel the way back returns to.
    #[serde(skip_serializing_if = "Option::is_none")]
    decoy_system: Option<&'a str>,
    /// The hidden volume root.
    hidden_root: String,
    /// Whether the hidden volume is mounted at its own path.
    hidden_root_mounted: bool,
    /// Why the hidden root is not a volume of its own, when the session's
    /// activation accepted that with `--allow-decoy-storage`.
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_decoy_storage: Option<&'a str>,
    /// The source of a filesystem mounted over the hidden volume.
    #[serde(skip_serializing_if = "Option::is_none")]
    hidden_root_covered_by: Option<&'a str>,
    /// The decoy filesystems placed in the hidden root.
    policy_mounts: &'a [PolicyMountView],
    /// The decoy units masked in the hidden root.
    masked_units: &'a [String],
    /// Whether `/run/nextroot` is populated.
    nextroot_mounted: bool,
    /// Whether the decoy keeps a persistent journal or syslog.
    decoy_persistent: bool,
    /// Whether kdump is armed on the decoy, or its state cannot be read.
    decoy_kdump_armed: bool,
    /// The persona mode.
    persona_mode: &'static str,
    /// How long the last successful activation took, and when it finished.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_activation: Option<&'a nails_core::LastActivation>,
    /// Why and when the last session switch was refused, while a record of it
    /// is kept.
    #[serde(skip_serializing_if = "Option::is_none")]
    switch_refusal: Option<RefusalJson<'a>>,
    /// Uptime-based reminders.
    opsec_reminders: Vec<ReminderJson<'a>>,
}

/// A refused session switch.
#[derive(Debug, Serialize)]
struct RefusalJson<'a> {
    /// The reason the soft-reboot gave for staying on the root it was on.
    reason: &'a str,
    /// When (ISO 8601).
    at: String,
}

/// One OpSec reminder.
#[derive(Debug, Serialize)]
struct ReminderJson<'a> {
    /// `info`, `warning` or `critical`.
    severity: &'static str,
    message: &'a str,
}

/// Where the machine is, folded from the live view: a session entering is
/// `activating`, a hidden root (with or without a way back) is `hidden`, and
/// everything else — the plain decoy and an interrupted activation seen from the
/// decoy — is `decoy`.
fn place_of(report: &StatusReport) -> &'static str {
    match report.session {
        "hidden" | "hidden_without_plan" => "hidden",
        "entering" => "activating",
        _ => "decoy",
    }
}

/// The one thing that needs the operator, or `None`. What the live view says
/// needs action now comes first, with the `reason` and `remediation` that go
/// with it: a hidden root without a way back, then an interrupted activation.
/// Then the record being unreadable or untrusted, in every place (nothing it
/// says can be trusted), and after it a refused switch, a session that ended
/// without updating the record, and a disk mounted over the volume.
/// `volume_lost` and `almost_full` are reported by the window and the alert,
/// where the live figures are to hand.
fn attention_of(report: &StatusReport) -> Option<&'static str> {
    if report.session == "hidden_without_plan" {
        return Some("no_way_back");
    }
    if report.session == "interrupted" {
        return Some("interrupted");
    }
    if report.record_unreadable() {
        return Some("record_unreadable");
    }
    if report.switch_refusal.is_some() {
        return Some("switch_refused");
    }
    if report.posture == Posture::Decoy && matches!(report.state, SystemState::Active { .. }) {
        return Some("ended_abnormally");
    }
    if report.hidden_root_covered_by.is_some() {
        return Some("volume_covered");
    }
    None
}

fn data(report: &StatusReport) -> StatusData<'_> {
    let attention = attention_of(report);
    let refused = report.switch_refusal.as_ref();
    // A refused switch is reported with its own reason, not the posture's (an
    // entry recorded before its refused switch reads as a session that ended
    // without updating the record).
    let reason = match refused {
        Some(refused) if attention == Some("switch_refused") => Some(refused.reason.as_str()),
        _ => report.reason.as_deref(),
    };
    StatusData {
        place: place_of(report),
        attention,
        reason,
        remediation: report.remediation.as_deref(),
        entered_at: report.entered_at.map(|t| t.to_rfc3339()),
        uptime_seconds: report.uptime.map(|u| u.num_seconds()),
        uptime_formatted: report.uptime.map(nails_core::status::format_uptime),
        hidden_system: report.hidden_system.as_deref(),
        decoy_system: report.decoy_system.as_deref(),
        hidden_root: report.hidden_root.display().to_string(),
        hidden_root_mounted: report.hidden_root_mounted,
        accepted_decoy_storage: report.accepted_decoy_storage.as_deref(),
        hidden_root_covered_by: report
            .hidden_root_covered_by
            .as_ref()
            .map(|cover| cover.source.as_str()),
        policy_mounts: &report.policy_mounts,
        masked_units: &report.masked_units,
        nextroot_mounted: report.nextroot_mounted,
        decoy_persistent: report.decoy_persistent,
        decoy_kdump_armed: report.decoy_kdump_armed,
        persona_mode: report.persona_mode.as_str(),
        last_activation: report.last_activation.as_ref(),
        switch_refusal: refused.map(|refused| RefusalJson {
            reason: &refused.reason,
            at: refused.at.to_rfc3339(),
        }),
        opsec_reminders: report
            .opsec_reminders
            .iter()
            .map(|r| ReminderJson {
                severity: match r.severity {
                    ReminderSeverity::Info => "info",
                    ReminderSeverity::Warning => "warning",
                    ReminderSeverity::Critical => "critical",
                },
                message: &r.message,
            })
            .collect(),
    }
}

/// The envelope for a report, with `ok` taken from the posture: a safe place
/// (decoy, active or transitioning) is `ok`, a degraded or unknown one is not.
pub fn status_envelope(report: &StatusReport) -> Envelope<StatusData<'_>> {
    Envelope::outcome("status", report.posture.is_safe(), data(report))
}

/// Print the status report as one JSON envelope.
pub fn print_status_json(report: &StatusReport) {
    status_envelope(report).print();
}

/// The failure data when the status could not be built at all: reading the
/// record on the hidden volume was refused, so nothing was established about
/// where the machine is. The place is `unknown`, never a guess, and the
/// attention names the unreadable record.
#[derive(Debug, Serialize)]
struct UnknownData {
    place: &'static str,
    attention: &'static str,
}

/// The failure envelope of a status that could not be built. `sudo` is the
/// line that runs status as root, when the state file was unreadable for lack
/// of permission.
pub fn status_unknown_envelope(error: String, sudo: Option<String>) -> Envelope<impl Serialize> {
    let mut body = crate::cli::output::envelope::ErrorBody::new("record_unreadable", error);
    if let Some(line) = sudo {
        body = body.with_hint(format!("run it as root: {line}"));
    }
    Envelope::failure_with_data(
        "status",
        body,
        UnknownData {
            place: "unknown",
            attention: "record_unreadable",
        },
    )
}

/// Print an unknown status (the report could not be built) as its failure
/// envelope ([`status_unknown_envelope`]).
pub fn print_status_json_unknown(error: String, sudo: Option<String>) {
    status_unknown_envelope(error, sudo).print();
}
