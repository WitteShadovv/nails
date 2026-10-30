// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `rehearse` operation: plant a canary in a hidden session, then scan the
//! raw decoy for it to prove the session left nothing behind.
//!
//! The four steps (status, plant, scan, reset) and the preconditions, state
//! transitions, same-boot refusal, target selection and guided next step live
//! here as a small service; a front end renders the outcome and never holds the
//! orchestration.
//!
//! The token never leaves this module: an outcome carries a
//! [`RehearsalView`] of the recorded rehearsal, with the token's fingerprint
//! in its place and the token redacted from the channels, and the removed
//! paths with the token redacted. A front end can log, serialize or forward
//! an outcome without planting the canary in a log on the decoy, where the
//! next scan would find it.

use std::path::PathBuf;

use nails_api::ExitStatus;

use crate::hidden_root::{Assessment, Refusal, recorded_acceptance, refusal};
use crate::rehearse::{
    self, ChannelRecord, Here, LiveSession, Phase, RehearsalState, ScanReport, ScanSummary,
    ScanTarget,
};
use crate::session::SessionView;
use crate::{Config, HiddenRoot, RealFilesystem, RuntimeEnv, TargetUser};

/// A rehearse step that could not run: the exit status, the stable code and the
/// message a front end reports.
pub struct RehearseFailure {
    /// The exit status the step earns.
    pub exit: ExitStatus,
    /// The stable, snake_case code a caller can branch on.
    pub code: &'static str,
    /// The human-readable explanation.
    pub message: String,
}

impl RehearseFailure {
    fn new(exit: ExitStatus, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            exit,
            code,
            message: message.into(),
        }
    }
}

/// Why `plant` could not run: an ordinary failure, or the attach gate's refusal
/// (which a front end renders with its own text and hint).
pub enum PlantError {
    /// An ordinary failure with a code and message.
    Fail(RehearseFailure),
    /// The attach gate refused the hidden root.
    Refused(Box<Refusal>),
}

/// What stands in for the token in what an outcome carries.
const REDACTED: &str = "<canary>";

/// A recorded rehearsal as a front end may show, log or forward it: the
/// token's fingerprint in its place and the token redacted from the channels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RehearsalView {
    /// A short stand-in for the token, safe to print.
    pub fingerprint: String,
    /// Where the rehearsal stands.
    pub phase: Phase,
    /// When the canary was planted.
    pub planted_at: String,
    /// The channels, planted or skipped, with the token redacted.
    pub channels: Vec<ChannelRecord>,
    /// The scans run so far.
    pub scans: Vec<ScanSummary>,
    /// Whether the command that read it runs in the hidden session the canary
    /// was planted in, where a scan is refused.
    pub planted_here: bool,
}

impl RehearsalView {
    /// The view of `state` for a command that runs `here`.
    fn of(state: &RehearsalState, here: &Here) -> Self {
        Self {
            fingerprint: state.fingerprint(),
            phase: state.phase,
            planted_at: state.planted_at.clone(),
            channels: state.redacted_channels(),
            scans: state.scans.clone(),
            planted_here: state.planted_in_this_session(here),
        }
    }
}

/// The status of a rehearsal on the hidden volume.
pub struct StatusOutcome {
    /// The recorded rehearsal, if any.
    pub rehearsal: Option<RehearsalView>,
    /// Where the command runs (session, boot id, soft-reboots), for the next step.
    pub here: Here,
}

/// A freshly planted canary.
pub struct PlantOutcome {
    /// The recorded rehearsal.
    pub rehearsal: RehearsalView,
    /// Where the plant ran, for the next step.
    pub here: Here,
}

/// A completed scan.
pub struct ScanOutcome {
    /// The scan report.
    pub report: ScanReport,
    /// The rehearsal the scan ran against (absent for an offline token scan).
    pub rehearsal: Option<RehearsalView>,
    /// Where the scan ran, for the next step.
    pub here: Here,
    /// The token's fingerprint.
    pub fingerprint: String,
    /// The exit status the scan earns (critical on a hit, warning when incomplete).
    pub exit: ExitStatus,
}

/// A removed rehearsal.
pub struct ResetOutcome {
    /// The removed rehearsal's fingerprint.
    pub fingerprint: String,
    /// The paths removed, with the token redacted from them.
    pub removed: Vec<PathBuf>,
}

/// What `scan` should read.
#[derive(Debug, Default, Clone)]
pub struct ScanOptions {
    /// Read the token from this file instead of the rehearsal state.
    pub token_file: Option<PathBuf>,
    /// Scan images instead of the live host's block devices.
    pub offline: bool,
    /// The images to scan under `offline`.
    pub images: Vec<PathBuf>,
    /// Explicit devices to scan (live).
    pub devices: Vec<PathBuf>,
    /// Scan even though the canary was planted in this very session.
    pub allow_same_boot: bool,
    /// Cap on bytes read per device.
    pub max_bytes: Option<u64>,
}

/// The phase name for a rehearsal.
pub fn phase_name(rehearsal: Option<&RehearsalView>) -> &'static str {
    match rehearsal.map(|r| r.phase) {
        None => "none",
        Some(Phase::Planted) => "planted",
        Some(Phase::Scanned) => "scanned",
    }
}

/// The guided next step for where the rehearsal stands, run `here`. Each nails
/// command is named with the real binary path, through the one renderer.
pub fn next_step(rehearsal: Option<&RehearsalView>, here: &Here) -> String {
    use crate::catalog;
    use crate::next_step::{NextStep, sudo_line};
    match rehearsal {
        None if here.session.is_some() => catalog::REHEARSE_GUIDE_PLANT_ACTIVE
            .render(&[("command", sudo_line(NextStep::RehearsePlant).as_str())]),
        None => catalog::REHEARSE_GUIDE_PLANT_INACTIVE
            .render(&[("command", sudo_line(NextStep::RehearsePlant).as_str())]),
        Some(r) if r.phase == Phase::Planted && r.planted_here => {
            catalog::REHEARSE_GUIDE_SCAN_NEXT_SESSION.render(&[
                ("deactivate", sudo_line(NextStep::Deactivate).as_str()),
                ("scan", sudo_line(NextStep::RehearseScan).as_str()),
            ])
        }
        Some(r) if r.phase == Phase::Planted => catalog::REHEARSE_GUIDE_SCAN_NOW
            .render(&[("command", sudo_line(NextStep::RehearseScan).as_str())]),
        Some(_) => catalog::REHEARSE_GUIDE_DONE
            .render(&[("command", sudo_line(NextStep::RehearseReset).as_str())]),
    }
}

/// The environment a plant resolves its operator from, and alerts with: the
/// caller's own, or, when `user` names an account, one in which that name is
/// the only source. Every uid source is cleared, the ones `nails gui` and
/// pkexec set as well (`NAILS_TARGET_UID`, `PKEXEC_UID`), because any of them
/// would win over a name, and so are the other names.
pub(crate) fn operator_env(env: &RuntimeEnv, user: Option<&str>) -> RuntimeEnv {
    let mut env = env.clone();
    if let Some(user) = user {
        env.nails_target_uid = None;
        env.pkexec_uid = None;
        env.sudo_uid = None;
        env.doas_uid = None;
        env.nails_target_user = Some(user.to_string());
        env.sudo_user = None;
        env.doas_user = None;
    }
    env
}

/// The account `user` names, resolved from `env` as [`operator_env`] makes
/// it. A name no account has is refused rather than replaced by whoever else
/// the environment or the active seat names: a plant for the wrong home would
/// make the later scan prove nothing about the one asked for.
pub(crate) fn named_operator(env: &RuntimeEnv, user: &str) -> Result<TargetUser, RehearseFailure> {
    match TargetUser::resolve_with(env) {
        Ok(operator) if operator.name == user => Ok(operator),
        _ => Err(RehearseFailure::new(
            ExitStatus::Usage,
            "no_such_user",
            format!(
                "no account is named {user}: name an account of this system, or leave out \
                 --user to plant for the account that ran this"
            ),
        )),
    }
}

/// The rehearsal service for a resolved configuration.
pub struct Rehearsal {
    config: Config,
}

impl Rehearsal {
    /// The service for `config`.
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// The live hidden session this runs in, from the live mount table and plan;
    /// `None` outside one.
    fn live_session(&self) -> Option<LiveSession> {
        live_session_of(crate::session::probe(
            &crate::session::Paths::system(),
            &self.config.hidden_volume_root,
        ))
    }

    fn load(&self) -> Result<Option<RehearsalState>, String> {
        rehearse::load_state(&RealFilesystem, &self.config.hidden_volume_root)
            .map_err(|e| e.to_string())
    }

    /// Read the rehearsal state and where the command runs.
    pub fn status(&self) -> Result<StatusOutcome, RehearseFailure> {
        let state = self
            .load()
            .map_err(|e| RehearseFailure::new(ExitStatus::InvalidState, "rehearse_state", e))?;
        let here = Here::read(self.live_session());
        Ok(StatusOutcome {
            rehearsal: state.as_ref().map(|state| RehearsalView::of(state, &here)),
            here,
        })
    }

    /// Plant a canary in the active hidden session, for the account `user`
    /// names, or for the operator the environment names.
    pub fn plant(&self, env: &RuntimeEnv, user: Option<&str>) -> Result<PlantOutcome, PlantError> {
        // A named account is looked up first, before anything is touched: a
        // name no account has is refused, never replaced by the operator.
        let operator_env = operator_env(env, user);
        let named = match user {
            Some(user) => Some(named_operator(&operator_env, user).map_err(PlantError::Fail)?),
            None => None,
        };
        let hidden_root = &self.config.hidden_volume_root;
        match HiddenRoot::assess(&RealFilesystem, hidden_root) {
            Ok(Assessment::Refused(refusal)) => return Err(PlantError::Refused(Box::new(refusal))),
            Ok(_) => {}
            Err(e) => {
                return Err(PlantError::Fail(RehearseFailure::new(
                    ExitStatus::Failed,
                    "not_attached",
                    e.to_string(),
                )));
            }
        }
        // A session that runs on storage the decoy uses, because its activation
        // accepted that, leaves the canary on the decoy's disk: the rehearsal
        // cannot pass there, and no override changes that.
        if let Some(reason) = recorded_acceptance(&RealFilesystem) {
            return Err(PlantError::Fail(RehearseFailure::new(
                ExitStatus::PreflightRefused,
                refusal::NOT_SEPARATE_VOLUME,
                format!(
                    "a rehearsal on this storage cannot pass: {reason} (accepted with \
                     --allow-decoy-storage). Nothing was written."
                ),
            )));
        }
        match HiddenRoot::verify_attached(&RealFilesystem, hidden_root, true) {
            Ok(attach) if attach.is_attached() => {}
            Ok(attach) => {
                let reason = attach.reason().unwrap_or("not attached").to_string();
                return Err(PlantError::Fail(RehearseFailure::new(
                    ExitStatus::InvalidState,
                    "not_attached",
                    reason,
                )));
            }
            Err(e) => {
                return Err(PlantError::Fail(RehearseFailure::new(
                    ExitStatus::Failed,
                    "not_attached",
                    e.to_string(),
                )));
            }
        }
        let Some(session) = self.live_session() else {
            return Err(PlantError::Fail(RehearseFailure::new(
                ExitStatus::InvalidState,
                "not_active",
                "no hidden session is active; activate first, then plant the canary inside it",
            )));
        };
        match self.load() {
            Ok(None) => {}
            Ok(Some(existing)) => {
                return Err(PlantError::Fail(RehearseFailure::new(
                    ExitStatus::InvalidState,
                    "already_planted",
                    format!(
                        "rehearsal {} is already planted; scan it, or run `{}` first",
                        existing.fingerprint(),
                        crate::next_step::sudo_line(crate::next_step::NextStep::RehearseReset)
                    ),
                )));
            }
            Err(e) => {
                return Err(PlantError::Fail(RehearseFailure::new(
                    ExitStatus::InvalidState,
                    "rehearse_state",
                    e,
                )));
            }
        }
        let mounts = match crate::filesystem::read_mountinfo() {
            Ok(mounts) => mounts,
            Err(e) => {
                return Err(PlantError::Fail(RehearseFailure::new(
                    ExitStatus::Failed,
                    "mountinfo",
                    e.to_string(),
                )));
            }
        };
        let token = match rehearse::generate_token() {
            Ok(token) => token,
            Err(e) => {
                return Err(PlantError::Fail(RehearseFailure::new(
                    ExitStatus::Failed,
                    "token",
                    e.to_string(),
                )));
            }
        };
        let operator = named.or_else(|| TargetUser::resolve_with(&operator_env).ok());
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
        if nothing_planted(&channels) {
            return Err(PlantError::Fail(RehearseFailure::new(
                ExitStatus::InvalidState,
                "nothing_planted",
                "no overlaid tree took the canary, so a scan could prove nothing; is the session active?",
            )));
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
            return Err(PlantError::Fail(RehearseFailure::new(
                ExitStatus::Failed,
                "rehearse_state",
                e.to_string(),
            )));
        }
        Ok(PlantOutcome {
            rehearsal: RehearsalView::of(&state, &here),
            here,
        })
    }

    /// Scan the decoy's storage for the canary.
    pub fn scan(&self, options: &ScanOptions) -> Result<ScanOutcome, RehearseFailure> {
        let (token, state) = self
            .scan_token(options)
            .map_err(|e| RehearseFailure::new(ExitStatus::InvalidState, "no_token", e))?;
        let here = Here::read(self.live_session());
        if refuses_same_session(
            state.as_ref(),
            &here,
            options.offline,
            options.allow_same_boot,
        ) {
            return Err(RehearseFailure::new(
                ExitStatus::InvalidState,
                "same_boot",
                "the canary was planted in this session, so its writes may not have reached the \
                 disk; deactivate first (it soft-reboots back to the decoy), then scan from the \
                 decoy or a later session, or pass --allow-same-boot",
            ));
        }
        let targets = match self.scan_targets(options) {
            Ok(targets) if !targets.is_empty() => targets,
            Ok(_) => {
                return Err(RehearseFailure::new(
                    ExitStatus::Failed,
                    "no_devices",
                    "no decoy device to scan",
                ));
            }
            Err(e) => return Err(RehearseFailure::new(ExitStatus::Failed, "no_devices", e)),
        };
        let report = rehearse::scan(&token, &targets, options.max_bytes)
            .map_err(|e| RehearseFailure::new(ExitStatus::Failed, "scan", e.to_string()))?;
        let mut state = state;
        if let Some(s) = state.as_mut() {
            s.phase = Phase::Scanned;
            s.scans.push(rehearse::ScanSummary {
                at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                boot_id: rehearse::current_boot_id(),
                devices: targets
                    .iter()
                    .map(|t| t.device.display().to_string())
                    .collect(),
                hits: report.total_hits(),
            });
            if let Err(e) =
                rehearse::save_state(&RealFilesystem, &self.config.hidden_volume_root, s)
            {
                tracing::warn!(error = %e, "could not record the scan in the rehearsal state");
            }
        }
        // A hit is critical. Otherwise a device that could not be read (an
        // error, an empty source or a byte cap) or one whose storage hides data
        // from a raw scan (compressed, copy-on-write, encrypted or not
        // identified) is a warning, never a clean pass.
        let exit = if report.total_hits() > 0 {
            ExitStatus::VerifyCritical
        } else if report.incomplete() || report.inconclusive() {
            ExitStatus::SuccessWithWarnings
        } else {
            ExitStatus::Ok
        };
        Ok(ScanOutcome {
            fingerprint: rehearse::fingerprint(&token),
            report,
            rehearsal: state.as_ref().map(|state| RehearsalView::of(state, &here)),
            here,
            exit,
        })
    }

    /// Remove the rehearsal from the hidden volume.
    pub fn reset(&self) -> Result<ResetOutcome, RehearseFailure> {
        if self.live_session().is_some() {
            return Err(RehearseFailure::new(
                ExitStatus::InvalidState,
                "active",
                "a hidden session is active; deactivate first, so the overlay uppers are not \
                 changed under a mounted overlay",
            ));
        }
        let state = match self.load() {
            Ok(Some(state)) => state,
            Ok(None) => {
                return Err(RehearseFailure::new(
                    ExitStatus::InvalidState,
                    "no_rehearsal",
                    "no rehearsal to reset",
                ));
            }
            Err(e) => {
                return Err(RehearseFailure::new(
                    ExitStatus::InvalidState,
                    "rehearse_state",
                    e,
                ));
            }
        };
        let root = &self.config.hidden_volume_root;
        let hidden = root.canonicalize().unwrap_or_else(|_| root.clone());
        let removed = rehearse::reset(&RealFilesystem, &hidden, &state)
            .map_err(|e| RehearseFailure::new(ExitStatus::Failed, "reset", e.to_string()))?;
        Ok(ResetOutcome {
            fingerprint: state.fingerprint(),
            removed: redacted(removed, &state.token),
        })
    }

    /// The token for a scan, and the state it came from when it came from one.
    fn scan_token(
        &self,
        options: &ScanOptions,
    ) -> Result<(String, Option<RehearsalState>), String> {
        if let Some(path) = &options.token_file {
            let token = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?
                .trim()
                .to_string();
            if !rehearse::valid_token(&token) {
                return Err(format!("{} holds no valid token", path.display()));
            }
            return Ok((token, None));
        }
        match self.load()? {
            Some(state) => Ok((state.token.clone(), Some(state))),
            None => Err(format!(
                "no rehearsal state under {}; mount the hidden volume that holds it, or pass \
                 --offline --token-file",
                self.config.hidden_volume_root.display()
            )),
        }
    }

    fn scan_targets(&self, options: &ScanOptions) -> Result<Vec<ScanTarget>, String> {
        // An image file and an unmounted --device carry no mount-table entry, so
        // the scan step identifies them from their on-disk superblock and
        // partition table; a live device is classified from the mount table.
        // Either way a compressed or copy-on-write decoy, an encrypted
        // container, or storage the scan does not identify reports "not
        // checked", and so does a --device that holds the folder of an
        // eCryptfs mount, which sysfs shows for a whole disk too. An offline
        // scan reads no mount table, so no eCryptfs mount reaches it.
        if options.offline {
            return Ok(options
                .images
                .iter()
                .cloned()
                .map(ScanTarget::new)
                .collect());
        }
        let mounts = crate::filesystem::read_mountinfo().map_err(|e| e.to_string())?;
        if !options.devices.is_empty() {
            return Ok(options
                .devices
                .iter()
                .map(|device| ScanTarget::classified(&RealFilesystem, device.clone(), &mounts))
                .collect());
        }
        let swaps = std::fs::read_to_string("/proc/swaps").unwrap_or_default();
        let root = &self.config.hidden_volume_root;
        let hidden = root.canonicalize().unwrap_or_else(|_| root.clone());
        Ok(rehearse::default_scan_targets(&mounts, &swaps, &hidden))
    }
}

/// The live hidden session in `view`, `None` outside one. A hidden root whose
/// plan cannot be read is still a live session, one with no entry time, so a
/// scan there is refused as in the planting session and a reset is refused as
/// in any session, rather than either reading it as the decoy.
fn live_session_of(view: SessionView) -> Option<LiveSession> {
    match view {
        SessionView::Hidden(plan) => Some(LiveSession {
            entered_at: plan.entered_at,
        }),
        SessionView::HiddenWithoutPlan(_) => Some(LiveSession { entered_at: None }),
        _ => None,
    }
}

/// Whether no overlaid tree took the canary. The canary file in an overlay
/// whose upper is on the hidden volume is what shows the session's writes
/// stayed off the decoy's disk; with only the other channels planted (the
/// home, the log, a process) a scan could prove nothing, so the plant is
/// refused.
fn nothing_planted(channels: &[rehearse::ChannelRecord]) -> bool {
    !channels
        .iter()
        .any(|c| c.planted() && c.kind == rehearse::ChannelKind::OverlayFile)
}

/// `paths` with `token` replaced in each by [`REDACTED`].
fn redacted(paths: Vec<PathBuf>, token: &str) -> Vec<PathBuf> {
    paths
        .into_iter()
        .map(|path| PathBuf::from(path.to_string_lossy().replace(token, REDACTED)))
        .collect()
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

#[cfg(test)]
#[path = "rehearse_tests.rs"]
mod tests;
