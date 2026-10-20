// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! rehearse command handler: plant a canary, then scan the raw decoy for it.
//!
//! The token never reaches stdout, stderr or a log: only its fingerprint is
//! printed, so the rehearsal's own output cannot put the canary on the decoy.

use std::path::Path;

use nails_core::app::rehearse::{
    PlantError, Rehearsal, RehearseFailure, ScanOptions, next_step, phase_name,
};
use nails_core::output::{Mark, Style};
use nails_core::rehearse::{ChannelRecord, Here, RehearsalState, ScanReport};
use serde::Serialize;

use crate::cli::args::{RehearseArgs, RehearsePlantArgs, RehearseScanArgs, RehearseStep};
use crate::cli::output::envelope::{Envelope, EnvelopePrint, ErrorBody, report_error};
use crate::cli::output::refusal::report_refusal;
use crate::cli::output::rehearse::{print_channels, print_scan};
use crate::cli::output::{ExitStatus, OutputSettings};

const COMMAND: &str = "rehearse";

/// The `data` payload of every rehearse step.
#[derive(Debug, Serialize)]
struct RehearseData<'a> {
    /// `none`, `planted` or `scanned`.
    phase: &'static str,
    /// The token's fingerprint, never the token.
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    planted_at: Option<&'a str>,
    /// The channels, with the token redacted from every path.
    channels: Vec<ChannelRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan: Option<&'a ScanReport>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    removed: Vec<String>,
    next_step: String,
}

/// Execute `nails rehearse`.
pub fn execute(
    settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    args: &RehearseArgs,
    config_override: Option<&Path>,
) -> ExitStatus {
    let json = settings.is_json();
    let config = match super::load_config_or_report(config_override, COMMAND, json) {
        Ok(loaded) => loaded.into_config(),
        Err(status) => return status,
    };
    let rehearsal = Rehearsal::new(config);
    match &args.step {
        None | Some(RehearseStep::Status) => status(settings, &rehearsal),
        Some(RehearseStep::Plant(plant_args)) => plant(settings, env, &rehearsal, plant_args),
        Some(RehearseStep::Scan(scan_args)) => scan(settings, &rehearsal, scan_args),
        Some(RehearseStep::Reset) => reset(settings, &rehearsal),
    }
}

/// Report a step failure as the error envelope or the human error line.
fn report_fail(json: bool, failure: RehearseFailure) -> ExitStatus {
    report_error(
        json,
        COMMAND,
        failure.exit,
        ErrorBody::new(failure.code, failure.message),
    )
}

fn emit(settings: &OutputSettings, data: &RehearseData<'_>, human: impl FnOnce(Style)) {
    if settings.is_json() {
        Envelope::success(COMMAND, data).print();
    } else {
        let style = settings.stdout_style();
        human(style);
        println!();
        println!("{} {}", style.glyph(Mark::Arrow), data.next_step);
    }
}

fn status(settings: &OutputSettings, rehearsal: &Rehearsal) -> ExitStatus {
    let outcome = match rehearsal.status() {
        Ok(outcome) => outcome,
        Err(failure) => return report_fail(settings.is_json(), failure),
    };
    let state = outcome.state;
    let here = outcome.here;
    let data = RehearseData {
        phase: phase_name(state.as_ref()),
        fingerprint: state.as_ref().map(RehearsalState::fingerprint),
        planted_at: state.as_ref().map(|s| s.planted_at.as_str()),
        channels: state
            .as_ref()
            .map(RehearsalState::redacted_channels)
            .unwrap_or_default(),
        scan: None,
        removed: Vec::new(),
        next_step: next_step(state.as_ref(), &here),
    };
    emit(settings, &data, |style| match &state {
        None => println!(
            "{}",
            style.marked(Mark::Info, "No rehearsal on this hidden volume.")
        ),
        Some(s) => {
            println!(
                "{}",
                style.marked(
                    Mark::Info,
                    format_args!(
                        "Rehearsal {} planted at {} ({})",
                        s.fingerprint(),
                        s.planted_at,
                        data.phase
                    )
                )
            );
            print_channels(style, &data.channels);
            for summary in &s.scans {
                println!(
                    "  {} scan at {}: {} on {}",
                    style.glyph(Mark::Bullet),
                    summary.at,
                    crate::cli::output::count_noun(summary.hits, "hit", "hits"),
                    summary.devices.join(", ")
                );
            }
        }
    });
    ExitStatus::Ok
}

fn plant(
    settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    rehearsal: &Rehearsal,
    args: &RehearsePlantArgs,
) -> ExitStatus {
    let (state, here) = match rehearsal.plant(env, args.user.as_deref()) {
        Ok(outcome) => (outcome.state, outcome.here),
        Err(PlantError::Refused(refusal)) => {
            return report_refusal(settings.is_json(), COMMAND, &refusal);
        }
        Err(PlantError::Fail(failure)) => return report_fail(settings.is_json(), failure),
    };
    let data = RehearseData {
        phase: "planted",
        fingerprint: Some(state.fingerprint()),
        planted_at: Some(&state.planted_at),
        channels: state.redacted_channels(),
        scan: None,
        removed: Vec::new(),
        next_step: next_step(Some(&state), &here),
    };
    emit(settings, &data, |style| {
        println!(
            "{}",
            style.marked(
                Mark::Pass,
                format_args!("Planted canary {}", state.fingerprint())
            )
        );
        print_channels(style, &data.channels);
    });
    ExitStatus::Ok
}

fn scan_options(args: &RehearseScanArgs) -> ScanOptions {
    ScanOptions {
        token_file: args.token_file.clone(),
        offline: args.offline,
        images: args.images.clone(),
        devices: args.devices.clone(),
        allow_same_boot: args.allow_same_boot,
        max_bytes: args.max_bytes,
    }
}

fn scan(settings: &OutputSettings, rehearsal: &Rehearsal, args: &RehearseScanArgs) -> ExitStatus {
    let outcome = match rehearsal.scan(&scan_options(args)) {
        Ok(outcome) => outcome,
        Err(failure) => return report_fail(settings.is_json(), failure),
    };
    let report = outcome.report;
    let state = outcome.state;
    let here = outcome.here;
    let fingerprint = outcome.fingerprint;
    let exit = outcome.exit;
    let data = RehearseData {
        phase: phase_name(state.as_ref()),
        fingerprint: Some(fingerprint.clone()),
        planted_at: state.as_ref().map(|s| s.planted_at.as_str()),
        channels: state
            .as_ref()
            .map(RehearsalState::redacted_channels)
            .unwrap_or_default(),
        scan: Some(&report),
        removed: Vec::new(),
        next_step: next_step(state.as_ref(), &here),
    };
    emit(settings, &data, |style| {
        print_scan(style, &report, &fingerprint, &data.channels);
    });
    exit
}

fn reset(settings: &OutputSettings, rehearsal: &Rehearsal) -> ExitStatus {
    let outcome = match rehearsal.reset() {
        Ok(outcome) => outcome,
        Err(failure) => return report_fail(settings.is_json(), failure),
    };
    let state = outcome.state;
    let removed = outcome.removed;
    let data = RehearseData {
        phase: "none",
        fingerprint: Some(state.fingerprint()),
        planted_at: None,
        channels: Vec::new(),
        scan: None,
        removed: removed
            .iter()
            .map(|p| p.display().to_string().replace(&state.token, "<canary>"))
            .collect(),
        next_step: next_step(None, &Here::default()),
    };
    emit(settings, &data, |style| {
        println!(
            "{}",
            style.marked(
                Mark::Pass,
                format_args!("Removed rehearsal {}", state.fingerprint())
            )
        );
        for path in &data.removed {
            println!("  removed {path}");
        }
    });
    ExitStatus::Ok
}
