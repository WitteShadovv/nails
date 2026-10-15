// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! rehearse command handler: plant a canary, then scan the raw decoy for it.
//!
//! The token never reaches stdout, stderr or a log: only its fingerprint is
//! printed, so the rehearsal's own output cannot put the canary on the decoy.

use std::path::{Path, PathBuf};

use nails_core::output::{Mark, Style};
use nails_core::rehearse::{
    self, ChannelRecord, Here, LiveSession, Phase, RehearsalState, ScanReport,
};
use nails_core::{Config, RealFilesystem};
use serde::Serialize;

use crate::cli::args::{RehearseArgs, RehearsePlantArgs, RehearseScanArgs, RehearseStep};
use crate::cli::output::envelope::{Envelope, ErrorBody, report_error};
use crate::cli::output::refusal::report_refusal;
use crate::cli::output::rehearse::{print_channels, print_scan};
use crate::cli::output::{ExitStatus, OutputSettings};
use nails_core::hidden_root::{Assessment, refusal};

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

/// The live hidden session this runs in, from the live mount table and plan;
/// `None` outside one.
fn live_session(config: &Config) -> Option<LiveSession> {
    use nails_core::session::SessionView;
    match nails_core::session::probe(
        &nails_core::session::Paths::system(),
        &config.hidden_volume_root,
    ) {
        SessionView::Hidden(plan) => Some(LiveSession {
            entered_at: plan.entered_at,
        }),
        SessionView::HiddenWithoutPlan(_) => Some(LiveSession { entered_at: None }),
        _ => None,
    }
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

/// The guided next step for where the rehearsal stands, run `here`.
fn next_step(state: Option<&RehearsalState>, here: &Here) -> String {
    match state {
        None if here.session.is_some() => {
            "Step 1 of 3: run `nails rehearse plant` in this hidden session.".into()
        }
        None => "Step 1 of 3: activate a hidden session, then run `nails rehearse plant`.".into(),
        Some(s) if s.phase == Phase::Planted && s.planted_in_this_session(here) => {
            "Step 2 of 3: deactivate as usual (`nails deactivate`, it soft-reboots back to the \
             decoy), then unlock and mount the hidden volume again and run `nails rehearse scan`."
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
    let here = Here::read(live_session(config));
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
    match nails_core::HiddenRoot::assess(&RealFilesystem, hidden_root) {
        Ok(Assessment::Refused(refusal)) => return report_refusal(json, COMMAND, &refusal),
        Ok(_) => {}
        Err(e) => return fail(json, ExitStatus::Failed, "not_attached", e.to_string()),
    }
    // A session that runs on storage the decoy uses, because its activation
    // accepted that, leaves the canary on the decoy's disk: the rehearsal
    // cannot pass there, and no override changes that.
    if let Some(reason) = nails_core::hidden_root::recorded_acceptance(&RealFilesystem) {
        return fail(
            json,
            ExitStatus::PreflightRefused,
            refusal::NOT_SEPARATE_VOLUME,
            format!(
                "a rehearsal on this storage cannot pass: {reason} (accepted with \
                 --allow-decoy-storage). Nothing was written."
            ),
        );
    }
    match nails_core::HiddenRoot::verify_attached(&RealFilesystem, hidden_root, true) {
        Ok(attach) if attach.is_attached() => {}
        Ok(attach) => {
            let reason = attach.reason().unwrap_or("not attached").to_string();
            return fail(json, ExitStatus::InvalidState, "not_attached", reason);
        }
        Err(e) => return fail(json, ExitStatus::Failed, "not_attached", e.to_string()),
    }
    let Some(session) = live_session(config) else {
        return fail(
            json,
            ExitStatus::InvalidState,
            "not_active",
            "no hidden session is active; activate first, then plant the canary inside it",
        );
    };
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
    let here = Here::read(Some(session));
    let state = RehearsalState {
        schema_version: rehearse::STATE_SCHEMA_VERSION,
        token,
        phase: Phase::Planted,
        planted_at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        planted_boot_id: here.boot_id.clone(),
        planted_entered_at: session.entered_at,
        planted_soft_reboots: here.soft_reboots,
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

/// Whether a scan must be refused: it would read the disks from the hidden
/// session that planted the canary (`state`, run `here`), whose writes may not
/// have reached them yet. An offline scan of images never runs there, and
/// `--allow-same-boot` accepts the risk.
fn refuses_same_session(
    state: Option<&RehearsalState>,
    here: &Here,
    offline: bool,
    allow_same_boot: bool,
) -> bool {
    !offline && !allow_same_boot && state.is_some_and(|s| s.planted_in_this_session(here))
}

fn scan(settings: &OutputSettings, config: &Config, args: &RehearseScanArgs) -> ExitStatus {
    let json = settings.is_json();
    let (token, state) = match scan_token(config, args) {
        Ok(found) => found,
        Err(e) => return fail(json, ExitStatus::InvalidState, "no_token", e),
    };
    let here = Here::read(live_session(config));
    if refuses_same_session(state.as_ref(), &here, args.offline, args.allow_same_boot) {
        return fail(
            json,
            ExitStatus::InvalidState,
            "same_boot",
            "the canary was planted in this session, so its writes may not have reached the \
             disk; deactivate first (it soft-reboots back to the decoy), then scan from the \
             decoy or a later session, or pass --allow-same-boot",
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
        next_step: next_step(state.as_ref(), &here),
    };
    emit(settings, &data, |style| {
        print_scan(style, &report, &token, &data.channels);
    });
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
    if live_session(config).is_some() {
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
    let removed = match rehearse::reset(&RealFilesystem, &hidden, &state) {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A canary planted in the session entered at 100, in boot `b1`.
    fn planted() -> RehearsalState {
        RehearsalState {
            schema_version: 1,
            token: "0".repeat(32),
            phase: Phase::Planted,
            planted_at: "2026-10-15T20:00:00Z".to_string(),
            planted_boot_id: Some("b1".to_string()),
            planted_entered_at: Some(100),
            planted_soft_reboots: None,
            channels: Vec::new(),
            scans: Vec::new(),
        }
    }

    fn in_session(entered_at: u64) -> Here {
        Here {
            session: Some(LiveSession {
                entered_at: Some(entered_at),
            }),
            boot_id: Some("b1".to_string()),
            soft_reboots: None,
        }
    }

    #[test]
    fn a_scan_in_the_planting_session_is_refused_unless_allowed() {
        let state = planted();
        let here = in_session(100);
        assert!(refuses_same_session(Some(&state), &here, false, false));
        assert!(
            !refuses_same_session(Some(&state), &here, false, true),
            "--allow-same-boot"
        );
        assert!(
            !refuses_same_session(Some(&state), &here, true, false),
            "an offline scan of images"
        );
    }

    #[test]
    fn a_scan_elsewhere_or_without_a_state_is_not_refused() {
        let state = planted();
        assert!(!refuses_same_session(
            Some(&state),
            &in_session(200),
            false,
            false
        ));
        assert!(!refuses_same_session(
            Some(&state),
            &Here::default(),
            false,
            false
        ));
        assert!(!refuses_same_session(None, &in_session(100), false, false));
    }
}
