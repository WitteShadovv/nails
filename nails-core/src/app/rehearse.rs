// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `rehearse` operation: plant a canary in a hidden session, then scan the
//! raw decoy for it to prove the session left nothing behind.
//!
//! The four steps (status, plant, scan, reset) and the preconditions, state
//! transitions, same-boot refusal, target selection and guided next step live
//! here as a small service; a front end renders the outcome and never holds the
//! orchestration. The token never leaves this crate's state file: an outcome
//! carries only the fingerprint and the redacted channels.

use std::path::PathBuf;

use nails_api::ExitStatus;

use crate::hidden_root::{Assessment, Refusal, recorded_acceptance, refusal};
use crate::rehearse::{self, Here, LiveSession, Phase, RehearsalState, ScanReport, ScanTarget};
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

/// The status of a rehearsal on the hidden volume.
pub struct StatusOutcome {
    /// The recorded rehearsal, if any.
    pub state: Option<RehearsalState>,
    /// Where the command runs (session, boot id, soft-reboots), for the next step.
    pub here: Here,
}

/// A freshly planted canary.
pub struct PlantOutcome {
    /// The recorded rehearsal state.
    pub state: RehearsalState,
    /// Where the plant ran, for the next step.
    pub here: Here,
}

/// A completed scan.
pub struct ScanOutcome {
    /// The scan report.
    pub report: ScanReport,
    /// The rehearsal state the scan ran against (absent for an offline token scan).
    pub state: Option<RehearsalState>,
    /// Where the scan ran, for the next step.
    pub here: Here,
    /// The token's fingerprint.
    pub fingerprint: String,
    /// The exit status the scan earns (critical on a hit, warning when incomplete).
    pub exit: ExitStatus,
}

/// A removed rehearsal.
pub struct ResetOutcome {
    /// The rehearsal that was removed.
    pub state: RehearsalState,
    /// The paths removed, with the token still in them (a front end redacts it).
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

/// The phase name for a rehearsal state.
pub fn phase_name(state: Option<&RehearsalState>) -> &'static str {
    match state.map(|s| s.phase) {
        None => "none",
        Some(Phase::Planted) => "planted",
        Some(Phase::Scanned) => "scanned",
    }
}

/// The guided next step for where the rehearsal stands, run `here`. Each nails
/// command is named with the real binary path, through the one renderer.
pub fn next_step(state: Option<&RehearsalState>, here: &Here) -> String {
    use crate::catalog;
    use crate::next_step::{NextStep, sudo_line};
    match state {
        None if here.session.is_some() => catalog::REHEARSE_GUIDE_PLANT_ACTIVE
            .render(&[("command", sudo_line(NextStep::RehearsePlant).as_str())]),
        None => catalog::REHEARSE_GUIDE_PLANT_INACTIVE
            .render(&[("command", sudo_line(NextStep::RehearsePlant).as_str())]),
        Some(s) if s.phase == Phase::Planted && s.planted_in_this_session(here) => {
            catalog::REHEARSE_GUIDE_SCAN_NEXT_SESSION.render(&[
                ("deactivate", sudo_line(NextStep::Deactivate).as_str()),
                ("scan", sudo_line(NextStep::RehearseScan).as_str()),
            ])
        }
        Some(s) if s.phase == Phase::Planted => catalog::REHEARSE_GUIDE_SCAN_NOW
            .render(&[("command", sudo_line(NextStep::RehearseScan).as_str())]),
        Some(_) => catalog::REHEARSE_GUIDE_DONE
            .render(&[("command", sudo_line(NextStep::RehearseReset).as_str())]),
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
        Ok(StatusOutcome { state, here })
    }

    /// Plant a canary in the active hidden session.
    pub fn plant(&self, env: &RuntimeEnv, user: Option<&str>) -> Result<PlantOutcome, PlantError> {
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
        let mut operator_env = env.clone();
        if let Some(user) = user {
            operator_env.sudo_user = Some(user.to_string());
            operator_env.sudo_uid = None;
        }
        let operator = TargetUser::resolve_with(&operator_env).ok();
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
        Ok(PlantOutcome { state, here })
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
            state,
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
        Ok(ResetOutcome { state, removed })
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
        // checked".
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
                .map(|device| ScanTarget::classified(device.clone(), &mounts))
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

    /// The same canary, after a scan has run.
    fn scanned() -> RehearsalState {
        RehearsalState {
            phase: Phase::Scanned,
            ..planted()
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

    /// A well-formed rehearsal token (32 hex digits).
    const HEX_TOKEN: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"; // pragma: allowlist secret

    /// A rehearsal service whose hidden root is an empty scratch directory, so
    /// the offline scan and token paths never touch a real hidden volume.
    fn rooted_at(root: &std::path::Path) -> Rehearsal {
        Rehearsal::new(Config {
            hidden_volume_root: root.to_path_buf(),
            ..Config::test_default()
        })
    }

    #[test]
    fn phase_name_is_the_exact_contract_string_for_every_state() {
        assert_eq!(phase_name(None), "none");
        assert_eq!(phase_name(Some(&planted())), "planted");
        assert_eq!(phase_name(Some(&scanned())), "scanned");
    }

    #[test]
    fn next_step_with_no_canary_in_a_session_guides_plant_in_this_session() {
        let guide = next_step(None, &in_session(100));
        assert!(
            guide.contains("in this hidden session"),
            "plant-active guidance: {guide}"
        );
    }

    #[test]
    fn next_step_with_no_canary_on_the_decoy_guides_activate_first() {
        let guide = next_step(None, &Here::default());
        assert!(
            guide.contains("activate a hidden session"),
            "plant-inactive guidance: {guide}"
        );
    }

    #[test]
    fn next_step_after_planting_in_this_session_guides_deactivate_then_scan() {
        let guide = next_step(Some(&planted()), &in_session(100));
        assert!(
            guide.contains("Step 2 of 3"),
            "scan-next-session guidance: {guide}"
        );
    }

    #[test]
    fn next_step_after_planting_in_an_earlier_session_guides_scan_now() {
        let guide = next_step(Some(&planted()), &in_session(200));
        assert!(guide.contains("Step 3 of 3"), "scan-now guidance: {guide}");
    }

    #[test]
    fn next_step_after_a_scan_guides_done_and_reset() {
        let guide = next_step(Some(&scanned()), &in_session(100));
        assert!(guide.contains("Done. Scan again"), "done guidance: {guide}");
    }

    #[test]
    fn load_reads_the_rehearsal_state_written_under_the_hidden_root() {
        let dir = tempfile::tempdir().unwrap();
        let state = planted();
        std::fs::create_dir_all(dir.path().join(rehearse::REHEARSE_DIR)).unwrap();
        std::fs::write(
            dir.path().join(rehearse::state_relative_path()),
            serde_json::to_string(&state).unwrap(),
        )
        .unwrap();
        let loaded = rooted_at(dir.path()).load().unwrap();
        assert_eq!(loaded.expect("a state file is present").token, state.token);
    }

    #[test]
    fn status_outside_a_hidden_session_reports_no_live_session() {
        // The hidden root is an unmounted scratch directory, so the live probe
        // of the real system finds the decoy, not a hidden session: `status`
        // must carry no live session. This pins `live_session`'s `None` result
        // outside a session against a mutant that always reports one.
        let dir = tempfile::tempdir().unwrap();
        // RehearseFailure is not Debug, so carry only its message into unwrap.
        let outcome = rooted_at(dir.path())
            .status()
            .map_err(|e| e.message)
            .unwrap();
        assert!(
            outcome.here.session.is_none(),
            "no hidden session is mounted at the scratch root, so none is reported"
        );
    }

    #[test]
    fn scan_token_reads_and_trims_a_valid_token_from_the_token_file() {
        let dir = tempfile::tempdir().unwrap();
        let token_file = dir.path().join("token");
        std::fs::write(&token_file, format!("  {HEX_TOKEN}\n")).unwrap();
        let options = ScanOptions {
            token_file: Some(token_file),
            offline: true,
            ..ScanOptions::default()
        };
        let (token, state) = rooted_at(dir.path()).scan_token(&options).unwrap();
        assert_eq!(token, HEX_TOKEN);
        assert!(state.is_none(), "a token-file scan carries no state");
    }

    #[test]
    fn scan_token_rejects_a_token_file_that_holds_no_valid_token() {
        let dir = tempfile::tempdir().unwrap();
        let token_file = dir.path().join("token");
        std::fs::write(&token_file, "not-a-valid-token!!").unwrap();
        let options = ScanOptions {
            token_file: Some(token_file),
            offline: true,
            ..ScanOptions::default()
        };
        let err = rooted_at(dir.path())
            .scan_token(&options)
            .expect_err("an invalid token must be refused");
        assert!(err.contains("no valid token"), "{err}");
    }

    #[test]
    fn scan_targets_offline_reads_the_given_images() {
        let dir = tempfile::tempdir().unwrap();
        let images = vec![PathBuf::from("/x/a.img"), PathBuf::from("/x/b.img")];
        let options = ScanOptions {
            offline: true,
            images: images.clone(),
            ..ScanOptions::default()
        };
        let targets = rooted_at(dir.path()).scan_targets(&options).unwrap();
        assert_eq!(
            targets.iter().map(|t| t.device.clone()).collect::<Vec<_>>(),
            images
        );
    }

    #[test]
    fn scan_targets_live_uses_the_explicit_devices_when_given() {
        let dir = tempfile::tempdir().unwrap();
        let device = PathBuf::from("/dev/nails-mutant-canary-device");
        let options = ScanOptions {
            offline: false,
            devices: vec![device.clone()],
            ..ScanOptions::default()
        };
        let targets = rooted_at(dir.path()).scan_targets(&options).unwrap();
        assert!(
            targets.iter().any(|t| t.device == device),
            "the explicit device is scanned, not the default set: {targets:?}"
        );
    }

    /// Run an offline scan over `images`, reading the token from a file.
    fn offline_scan(images: Vec<PathBuf>) -> Result<ScanOutcome, RehearseFailure> {
        let dir = tempfile::tempdir().unwrap();
        let token_file = dir.path().join("token");
        std::fs::write(&token_file, HEX_TOKEN).unwrap();
        let options = ScanOptions {
            token_file: Some(token_file),
            offline: true,
            images,
            ..ScanOptions::default()
        };
        rooted_at(dir.path()).scan(&options)
    }

    #[test]
    fn a_scan_that_finds_the_canary_is_critical() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("leaky.img");
        std::fs::write(&image, format!("padding {HEX_TOKEN} padding")).unwrap();
        let outcome = offline_scan(vec![image]).map_err(|e| e.message).unwrap();
        assert!(outcome.report.total_hits() >= 1, "the canary is found");
        assert_eq!(outcome.exit, ExitStatus::VerifyCritical);
    }

    /// Write an image the scan identifies as ext4 (its superblock magic at
    /// 0x438), which keeps file contents verbatim, followed by `text`.
    fn ext4_image(path: &std::path::Path, text: &str) {
        let mut bytes = vec![0u8; 4096];
        bytes[0x438..0x43A].copy_from_slice(&[0x53, 0xEF]);
        bytes.extend_from_slice(text.as_bytes());
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn a_clean_fully_read_scan_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("clean.img");
        ext4_image(&image, "nothing to see here");
        let outcome = offline_scan(vec![image]).map_err(|e| e.message).unwrap();
        assert_eq!(outcome.report.total_hits(), 0);
        assert!(!outcome.report.incomplete());
        assert!(!outcome.report.inconclusive());
        assert_eq!(outcome.exit, ExitStatus::Ok);
    }

    #[test]
    fn a_clean_scan_of_storage_the_scan_does_not_identify_only_warns() {
        // No filesystem the scan knows: zfs, an encrypted volume or raw data
        // may hold the canary where a raw scan cannot see it.
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("raw.img");
        std::fs::write(&image, "nothing to see here").unwrap();
        let outcome = offline_scan(vec![image]).map_err(|e| e.message).unwrap();
        assert_eq!(outcome.report.total_hits(), 0);
        assert!(outcome.report.inconclusive());
        assert_eq!(outcome.exit, ExitStatus::SuccessWithWarnings);
    }

    #[test]
    fn a_scan_of_an_empty_image_only_warns() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("empty.img");
        std::fs::write(&image, "").unwrap();
        let outcome = offline_scan(vec![image]).map_err(|e| e.message).unwrap();
        assert!(outcome.report.incomplete(), "nothing was read");
        assert_eq!(outcome.exit, ExitStatus::SuccessWithWarnings);
    }

    #[test]
    fn a_clean_scan_that_could_not_read_a_device_only_warns() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.img");
        let outcome = offline_scan(vec![missing]).map_err(|e| e.message).unwrap();
        assert_eq!(outcome.report.total_hits(), 0);
        assert!(outcome.report.incomplete(), "the device could not be read");
        assert!(!outcome.report.inconclusive());
        assert_eq!(outcome.exit, ExitStatus::SuccessWithWarnings);
    }

    #[test]
    fn a_scan_with_no_device_to_read_fails() {
        // ScanOutcome is not Debug, so discard it before expect_err.
        let err = offline_scan(Vec::new())
            .map(|_| ())
            .expect_err("no device, no scan");
        assert_eq!(err.code, "no_devices");
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

    /// A plan for the live-session view, entered at `entered_at`.
    fn plan(entered_at: u64) -> Box<nails_teardown::whole_root::plan::Plan> {
        use nails_teardown::whole_root::plan::{PLAN_VERSION, Plan};
        let json = serde_json::json!({
            "version": PLAN_VERSION,
            "hidden_root": "/mnt/data",
            "upper": "/mnt/data/root/upper",
            "work": "/mnt/data/root/work",
            "decoy_root": {"source": "/dev/vda2", "fstype": "ext4"},
            "decoy": {"init": "/sbin/init"},
            "hidden": {"init": "/sbin/init"},
            "entered_at": entered_at,
        });
        Box::new(Plan::from_json(&json.to_string()).expect("a minimal plan"))
    }

    #[test]
    fn a_hidden_root_is_a_live_session_with_its_entry_time() {
        assert_eq!(
            live_session_of(SessionView::Hidden(plan(100))),
            Some(LiveSession {
                entered_at: Some(100)
            })
        );
    }

    /// A hidden root whose `/run` plan cannot be read is still a live session:
    /// read as the decoy, a scan there would read the disks before the
    /// session's writes reach them and a reset would change the uppers under
    /// the mounted overlay.
    #[test]
    fn a_hidden_root_without_its_plan_is_still_a_live_session() {
        let session = live_session_of(SessionView::HiddenWithoutPlan(
            "no session plan in /run (upper /mnt/data/root/upper)".to_string(),
        ));
        assert_eq!(session, Some(LiveSession { entered_at: None }));

        // A canary planted there, in this boot: the scan is refused.
        let state = RehearsalState {
            planted_entered_at: None,
            ..planted()
        };
        let here = Here {
            session,
            boot_id: Some("b1".to_string()),
            soft_reboots: None,
        };
        assert!(refuses_same_session(Some(&state), &here, false, false));
    }

    #[test]
    fn the_decoy_and_an_entry_under_way_are_no_live_session() {
        assert_eq!(live_session_of(SessionView::Decoy), None);
        assert_eq!(live_session_of(SessionView::Entering(plan(100))), None);
        assert_eq!(
            live_session_of(SessionView::Interrupted {
                plan: Some(plan(100)),
                nextroot_mounted: true,
            }),
            None
        );
    }

    /// A channel record of `kind`, planted or skipped.
    fn channel(kind: rehearse::ChannelKind, planted: bool) -> rehearse::ChannelRecord {
        rehearse::ChannelRecord {
            kind,
            location: "/somewhere".to_string(),
            upper_copy: None,
            skipped: (!planted).then(|| "not planted".to_string()),
        }
    }

    /// A plant that no overlaid tree took is refused, however many of the
    /// other channels took the canary: a scan of the log, a process or the
    /// home alone could prove nothing.
    #[test]
    fn a_plant_without_an_overlay_file_is_nothing_planted() {
        use rehearse::ChannelKind::{
            HomeFile, Notification, OverlayFile, ProcessCmdline, RecentFiles, SystemLog,
        };
        assert!(nothing_planted(&[]));
        assert!(nothing_planted(&[
            channel(OverlayFile, false),
            channel(HomeFile, true),
            channel(RecentFiles, true),
            channel(SystemLog, true),
            channel(ProcessCmdline, true),
            channel(Notification, true),
        ]));
    }

    /// One overlaid tree that took the canary is enough, whatever else was
    /// skipped.
    #[test]
    fn a_plant_with_an_overlay_file_is_planted() {
        use rehearse::ChannelKind::{HomeFile, OverlayFile, SystemLog};
        assert!(!nothing_planted(&[
            channel(OverlayFile, false),
            channel(OverlayFile, true),
            channel(HomeFile, false),
            channel(SystemLog, false),
        ]));
    }
}
