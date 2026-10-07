// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! rehearse command handler: plant a canary, then scan the raw decoy for it.
//!
//! The token never reaches stdout, stderr or a log: only its fingerprint is
//! printed, so the rehearsal's own output cannot put the canary on the decoy.

use std::path::{Path, PathBuf};

use nails_core::output::{Mark, Style};
use nails_core::rehearse::{self, ChannelRecord, Phase, RehearsalState, ScanReport};
use nails_core::{Config, RealFilesystem, StateFile, SystemState};
use serde::Serialize;

use crate::cli::args::{RehearseArgs, RehearsePlantArgs, RehearseScanArgs, RehearseStep};
use crate::cli::output::envelope::{Envelope, ErrorBody, report_error};
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
    match &args.step {
        None | Some(RehearseStep::Status) => status(settings, &config),
        Some(RehearseStep::Plant(plant_args)) => plant(settings, env, &config, plant_args),
        Some(RehearseStep::Scan(scan_args)) => scan(settings, &config, scan_args),
        Some(RehearseStep::Reset) => reset(settings, &config),
    }
}

fn fail(
    json: bool,
    status: ExitStatus,
    code: &'static str,
    message: impl Into<String>,
) -> ExitStatus {
    report_error(json, COMMAND, status, ErrorBody::new(code, message))
}

/// Whether the recorded system state is an active hidden session.
fn session_active(config: &Config) -> bool {
    StateFile::load(&config.state_file_path)
        .map(|file| matches!(file.state, SystemState::Active { .. }))
        .unwrap_or(false)
}

fn load(config: &Config) -> Result<Option<RehearsalState>, String> {
    rehearse::load_state(&RealFilesystem, &config.hidden_volume_root).map_err(|e| e.to_string())
}

fn phase_name(state: Option<&RehearsalState>) -> &'static str {
    match state.map(|s| s.phase) {
        None => "none",
        Some(Phase::Planted) => "planted",
        Some(Phase::Scanned) => "scanned",
    }
}

/// The guided next step for where the rehearsal stands.
fn next_step(state: Option<&RehearsalState>, active: bool) -> String {
    let same_boot = |s: &RehearsalState| {
        s.planted_boot_id.is_some() && s.planted_boot_id == rehearse::current_boot_id()
    };
    match state {
        None if active => "Step 1 of 3: run `nails rehearse plant` in this hidden session.".into(),
        None => "Step 1 of 3: activate a hidden session, then run `nails rehearse plant`.".into(),
        Some(s) if s.phase == Phase::Planted && same_boot(s) => {
            "Step 2 of 3: deactivate as usual (`nails deactivate`, which reboots), then unlock and \
             mount the hidden volume again and run `nails rehearse scan`."
                .into()
        }
        Some(s) if s.phase == Phase::Planted => "Step 3 of 3: run `nails rehearse scan`.".into(),
        Some(_) => "Done. Scan again any time, or run `nails rehearse reset` to remove the \
                    rehearsal from the hidden volume."
            .into(),
    }
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

fn status(settings: &OutputSettings, config: &Config) -> ExitStatus {
    let state = match load(config) {
        Ok(state) => state,
        Err(e) => {
            return fail(
                settings.is_json(),
                ExitStatus::InvalidState,
                "rehearse_state",
                e,
            );
        }
    };
    let active = session_active(config);
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
        next_step: next_step(state.as_ref(), active),
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
                    "  {} scan at {}: {} hit(s) on {}",
                    style.glyph(Mark::Bullet),
                    summary.at,
                    summary.hits,
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
    config: &Config,
    args: &RehearsePlantArgs,
) -> ExitStatus {
    let json = settings.is_json();
    let hidden_root = &config.hidden_volume_root;
    match nails_core::HiddenRoot::verify_attached(&RealFilesystem, hidden_root, true) {
        Ok(attach) if attach.is_attached() => {}
        Ok(attach) => {
            let reason = attach.reason().unwrap_or("not attached").to_string();
            return fail(json, ExitStatus::InvalidState, "not_attached", reason);
        }
        Err(e) => return fail(json, ExitStatus::Failed, "not_attached", e.to_string()),
    }
    if !session_active(config) {
        return fail(
            json,
            ExitStatus::InvalidState,
            "not_active",
            "no hidden session is active; activate first, then plant the canary inside it",
        );
    }
    match load(config) {
        Ok(None) => {}
        Ok(Some(existing)) => {
            return fail(
                json,
                ExitStatus::InvalidState,
                "already_planted",
                format!(
                    "rehearsal {} is already planted; scan it, or run `nails rehearse reset` first",
                    existing.fingerprint()
                ),
            );
        }
        Err(e) => return fail(json, ExitStatus::InvalidState, "rehearse_state", e),
    }
    let mounts = match nails_core::filesystem::read_mountinfo() {
        Ok(mounts) => mounts,
        Err(e) => return fail(json, ExitStatus::Failed, "mountinfo", e.to_string()),
    };
    let token = match rehearse::generate_token() {
        Ok(token) => token,
        Err(e) => return fail(json, ExitStatus::Failed, "token", e.to_string()),
    };
    let mut operator_env = env.clone();
    if let Some(user) = &args.user {
        operator_env.sudo_user = Some(user.clone());
        operator_env.sudo_uid = None;
    }
    let operator = nails_core::TargetUser::resolve_with(&operator_env).ok();
    let hidden = hidden_root
        .canonicalize()
        .unwrap_or_else(|_| hidden_root.clone());
    let channels = rehearse::plant(&rehearse::PlantContext {
        token: &token,
        hidden_root: &hidden,
        mounts: &mounts,
        operator: operator.as_ref(),
        env: Some(&operator_env),
        host_channels: true,
    });
    if !channels
        .iter()
        .any(|c| c.planted() && c.kind == rehearse::ChannelKind::OverlayFile)
    {
        return fail(
            json,
            ExitStatus::InvalidState,
            "nothing_planted",
            "no overlaid tree took the canary, so a scan could prove nothing; is the session active?",
        );
    }
    let state = RehearsalState {
        schema_version: rehearse::STATE_SCHEMA_VERSION,
        token,
        phase: Phase::Planted,
        planted_at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        planted_boot_id: rehearse::current_boot_id(),
        channels,
        scans: Vec::new(),
    };
    if let Err(e) = rehearse::save_state(&RealFilesystem, hidden_root, &state) {
        return fail(json, ExitStatus::Failed, "rehearse_state", e.to_string());
    }
    let data = RehearseData {
        phase: "planted",
        fingerprint: Some(state.fingerprint()),
        planted_at: Some(&state.planted_at),
        channels: state.redacted_channels(),
        scan: None,
        removed: Vec::new(),
        next_step: next_step(Some(&state), true),
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

/// The token for a scan, and the state it came from when it came from one.
fn scan_token(
    config: &Config,
    args: &RehearseScanArgs,
) -> Result<(String, Option<RehearsalState>), String> {
    if let Some(path) = &args.token_file {
        let token = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?
            .trim()
            .to_string();
        if !rehearse::valid_token(&token) {
            return Err(format!("{} holds no valid token", path.display()));
        }
        return Ok((token, None));
    }
    match load(config)? {
        Some(state) => Ok((state.token.clone(), Some(state))),
        None => Err(format!(
            "no rehearsal state under {}; mount the hidden volume that holds it, or pass \
             --offline --token-file",
            config.hidden_volume_root.display()
        )),
    }
}

fn scan_devices(config: &Config, args: &RehearseScanArgs) -> Result<Vec<PathBuf>, String> {
    if args.offline {
        return Ok(args.images.clone());
    }
    if !args.devices.is_empty() {
        return Ok(args.devices.clone());
    }
    let mounts = nails_core::filesystem::read_mountinfo().map_err(|e| e.to_string())?;
    let swaps = std::fs::read_to_string("/proc/swaps").unwrap_or_default();
    let root = &config.hidden_volume_root;
    let hidden = root.canonicalize().unwrap_or_else(|_| root.clone());
    Ok(rehearse::default_scan_targets(&mounts, &swaps, &hidden))
}

fn scan(settings: &OutputSettings, config: &Config, args: &RehearseScanArgs) -> ExitStatus {
    let json = settings.is_json();
    let (token, state) = match scan_token(config, args) {
        Ok(found) => found,
        Err(e) => return fail(json, ExitStatus::InvalidState, "no_token", e),
    };
    if let Some(s) = &state
        && !args.offline
        && !args.allow_same_boot
        && s.planted_boot_id.is_some()
        && s.planted_boot_id == rehearse::current_boot_id()
    {
        return fail(
            json,
            ExitStatus::InvalidState,
            "same_boot",
            "the canary was planted in this boot, so the session's writes may not have reached \
             the disk; deactivate first (it reboots), or pass --allow-same-boot",
        );
    }
    let devices = match scan_devices(config, args) {
        Ok(devices) if !devices.is_empty() => devices,
        Ok(_) => {
            return fail(
                json,
                ExitStatus::Failed,
                "no_devices",
                "no decoy device to scan",
            );
        }
        Err(e) => return fail(json, ExitStatus::Failed, "no_devices", e),
    };
    let report = match rehearse::scan(&token, &devices, args.max_bytes) {
        Ok(report) => report,
        Err(e) => return fail(json, ExitStatus::Failed, "scan", e.to_string()),
    };
    let mut state = state;
    if let Some(s) = state.as_mut() {
        s.phase = Phase::Scanned;
        s.scans.push(rehearse::ScanSummary {
            at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            boot_id: rehearse::current_boot_id(),
            devices: devices.iter().map(|d| d.display().to_string()).collect(),
            hits: report.total_hits(),
        });
        if let Err(e) = rehearse::save_state(&RealFilesystem, &config.hidden_volume_root, s) {
            tracing::warn!(error = %e, "could not record the scan in the rehearsal state");
        }
    }
    let data = RehearseData {
        phase: phase_name(state.as_ref()),
        fingerprint: Some(rehearse::fingerprint(&token)),
        planted_at: state.as_ref().map(|s| s.planted_at.as_str()),
        channels: state
            .as_ref()
            .map(RehearsalState::redacted_channels)
            .unwrap_or_default(),
        scan: Some(&report),
        removed: Vec::new(),
        next_step: next_step(state.as_ref(), session_active(config)),
    };
    emit(settings, &data, |style| print_scan(style, &report, &token));
    if report.total_hits() > 0 {
        ExitStatus::VerifyCritical
    } else if report.incomplete() {
        ExitStatus::SuccessWithWarnings
    } else {
        ExitStatus::Ok
    }
}

fn reset(settings: &OutputSettings, config: &Config) -> ExitStatus {
    let json = settings.is_json();
    if session_active(config) {
        return fail(
            json,
            ExitStatus::InvalidState,
            "active",
            "a hidden session is active; deactivate first, so the overlay uppers are not changed \
             under a mounted overlay",
        );
    }
    let state = match load(config) {
        Ok(Some(state)) => state,
        Ok(None) => {
            return fail(
                json,
                ExitStatus::InvalidState,
                "no_rehearsal",
                "no rehearsal to reset",
            );
        }
        Err(e) => return fail(json, ExitStatus::InvalidState, "rehearse_state", e),
    };
    let root = &config.hidden_volume_root;
    let hidden = root.canonicalize().unwrap_or_else(|_| root.clone());
    let removed = match rehearse::reset(&hidden, &state) {
        Ok(removed) => removed,
        Err(e) => return fail(json, ExitStatus::Failed, "reset", e.to_string()),
    };
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
        next_step: next_step(None, false),
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
