// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # Status
//!
//! Where the machine is, from live facts ([`crate::session::probe`]): the
//! hidden root, an entry under way, an interrupted entry, or the plain decoy.
//! A soft-reboot keeps the boot ID, so the state file cannot tell; it is
//! reported next to the live view as a record.

use crate::config::PersonaMode;
use crate::session::{Paths, SessionView};
use crate::state::LastActivation;
use crate::{Config, Filesystem, LoadOutcome, Result, StateFile, SystemState};
use chrono::{DateTime, Duration, Utc};
use nails_teardown::mountinfo::{MountEntry, read_mountinfo, top_mount_at};
use nails_teardown::whole_root::plan::{MaskCause, Plan, PolicyMountKind};
use nails_teardown::whole_root::{skips, switch_refusal};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

mod reminders;

pub use reminders::{OpSecReminder, ReminderSeverity, format_uptime, generate_opsec_reminders};

/// The verdict `status` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Posture {
    /// The plain decoy.
    Decoy,
    /// In the hidden session.
    Active,
    /// An activation is entering the hidden root right now.
    Transitioning,
    /// Something needs the operator: an interrupted entry, or a hidden root
    /// without a way back.
    Degraded,
    /// The state file cannot be read, so the record is unknown.
    Unknown,
}

impl Posture {
    /// Whether this posture is safe to leave as it is.
    pub fn is_safe(&self) -> bool {
        matches!(
            self,
            Posture::Decoy | Posture::Active | Posture::Transitioning
        )
    }

    /// The output mark.
    pub fn mark(&self) -> crate::output::Mark {
        use crate::output::Mark;
        match self {
            Posture::Decoy | Posture::Transitioning => Mark::Neutral,
            Posture::Active => Mark::Pass,
            Posture::Degraded => Mark::Fail,
            Posture::Unknown => Mark::Warn,
        }
    }

    /// The upper-case level.
    pub fn level(&self) -> &'static str {
        match self {
            Posture::Decoy => "DECOY",
            Posture::Active => "ACTIVE",
            Posture::Transitioning => "TRANSITIONING",
            Posture::Degraded => "DEGRADED",
            Posture::Unknown => "UNKNOWN",
        }
    }

    /// The machine name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Posture::Decoy => "decoy",
            Posture::Active => "active",
            Posture::Transitioning => "transitioning",
            Posture::Degraded => "degraded",
            Posture::Unknown => "unknown",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            Posture::Decoy => "Decoy system in use - no hidden session",
            Posture::Active => "Hidden session active - the root is the hidden overlay",
            Posture::Transitioning => "An activation is entering the hidden session",
            Posture::Degraded => "The session needs attention",
            Posture::Unknown => "State file could not be read - the record is unknown",
        }
    }

    /// The plain-text rendering.
    pub fn to_plain(&self) -> String {
        format!("[{}] {}", self.level(), self.description())
    }

    /// The styled rendering.
    pub fn render(&self, style: crate::output::Style) -> String {
        if style.ascii {
            self.to_plain()
        } else {
            format!(
                "{} {}: {}",
                style.mark(self.mark()),
                self.level(),
                self.description()
            )
        }
    }
}

impl fmt::Display for Posture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render(crate::output::Style::default()))
    }
}

/// One mount the fstab policy placed in the hidden root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyMountView {
    /// The mount point inside the hidden root.
    pub target: PathBuf,
    /// `read-only`, `overlay` or `hidden-volume`.
    pub kind: &'static str,
}

/// A unit a boot target requires (`local-fs.target`, `remote-fs.target`,
/// `swap.target`) that the session keeps from starting, and how.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequiredUnitView {
    /// The unit.
    pub unit: String,
    /// `skipped` (its start condition never holds, and the target is still
    /// reached) or `masked` (the target is not reached unless nothing else
    /// requires the unit).
    pub action: &'static str,
    /// Why: `required_at_boot` for a skip; for a mask `device_absent`,
    /// `undetermined` or `conflicting_lines`.
    pub reason: &'static str,
    /// The device that was not there, for `device_absent`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<PathBuf>,
}

/// The units of `plan` that a boot target requires and the session keeps
/// from starting: its skips, then the masks it recorded with their cause.
/// After the switch (`switched`) a skip whose device was gone by then is
/// shown masked, as the switch did ([`skips::masked_at_switch`] under
/// `run`).
fn required_units(plan: &Plan, run: &Path, switched: bool) -> Vec<RequiredUnitView> {
    let skipped = plan.skips.iter().flat_map(|skip| {
        skip.units.iter().map(|unit| match &skip.device {
            Some(device) if switched && skips::masked_at_switch(run, unit) => RequiredUnitView {
                unit: unit.clone(),
                action: "masked",
                reason: "device_absent",
                device: Some(device.clone()),
            },
            _ => RequiredUnitView {
                unit: unit.clone(),
                action: "skipped",
                reason: "required_at_boot",
                device: None,
            },
        })
    });
    let masked = plan.required_masks.iter().map(|mask| RequiredUnitView {
        unit: mask.unit.clone(),
        action: "masked",
        reason: match mask.cause {
            MaskCause::DeviceAbsent => "device_absent",
            MaskCause::Undetermined => "undetermined",
            MaskCause::ConflictingLines => "conflicting_lines",
        },
        device: mask.device.clone(),
    });
    skipped.chain(masked).collect()
}

/// The last session switch, when the soft-reboot refused it and stayed on the
/// root it was on (see `nails_teardown::whole_root::switch_refusal`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedSwitch {
    /// The reason the switch gave: a failed init check, failed unit masks, or
    /// an arming that did not run in time.
    pub reason: String,
    /// When it was refused.
    pub at: DateTime<Utc>,
}

impl RefusedSwitch {
    /// The record kept in the runtime directory `runtime_dir` (a refused way
    /// back, read in the hidden session), else the one on the hidden volume at
    /// `hidden_root` (a refused entry, read once the volume is open again).
    /// Both are never left at once: arming a switch clears them, and every
    /// path back to the decoy removes the runtime directory.
    fn read(runtime_dir: &Path, hidden_root: &Path) -> Option<Self> {
        let record =
            switch_refusal::read(runtime_dir).or_else(|| switch_refusal::read(hidden_root))?;
        Some(Self {
            at: DateTime::<Utc>::from_timestamp(i64::try_from(record.at).ok()?, 0)?,
            reason: record.reason,
        })
    }
}

/// A filesystem mounted over the hidden volume, at the hidden root or on one
/// of its parents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverView {
    /// Its source, which now receives every file saved under the hidden root.
    pub source: String,
    /// Where it is mounted: what `umount` takes.
    pub mount_point: PathBuf,
}

/// What `status` reports.
#[derive(Debug, Clone, PartialEq)]
pub struct StatusReport {
    /// The verdict.
    pub posture: Posture,
    /// The live view: `decoy`, `hidden`, `entering`, `interrupted` or
    /// `hidden_without_plan`.
    pub session: &'static str,
    /// Why the posture is degraded, if it is.
    pub reason: Option<String>,
    /// What to do about it, with the real binary path (never a bare `nails …`).
    pub remediation: Option<String>,
    /// The recorded state.
    pub state: SystemState,
    /// How the state file was read: `loaded`, `missing`, `unreadable` or
    /// `corrupt`.
    pub state_source: &'static str,
    /// When the hidden root was entered.
    pub entered_at: Option<DateTime<Utc>>,
    /// How long the hidden session has run.
    pub uptime: Option<Duration>,
    /// The hidden NixOS toplevel the session runs.
    pub hidden_system: Option<String>,
    /// The decoy NixOS toplevel the way back returns to.
    pub decoy_system: Option<String>,
    /// The hidden volume root.
    pub hidden_root: PathBuf,
    /// Whether the hidden volume is mounted (at its own path).
    pub hidden_root_mounted: bool,
    /// The device the hidden volume is mounted from.
    pub hidden_root_source: Option<String>,
    /// Why the hidden root is not a volume of its own, when the session's
    /// activation accepted that with `--allow-decoy-storage`.
    pub accepted_decoy_storage: Option<String>,
    /// A filesystem mounted over the hidden volume (see
    /// [`shadowing_mount`](crate::hidden_root::shadowing_mount)).
    pub hidden_root_covered_by: Option<CoverView>,
    /// The mounts the fstab policy placed in the hidden root.
    pub policy_mounts: Vec<PolicyMountView>,
    /// The decoy units masked in the hidden root.
    pub masked_units: Vec<String>,
    /// The units a boot target requires that the session skips or masks,
    /// each with why.
    pub required_units: Vec<RequiredUnitView>,
    /// Whether `/run/nextroot` is populated.
    pub nextroot_mounted: bool,
    /// The last successful activation.
    pub last_activation: Option<LastActivation>,
    /// Whether the decoy keeps a persistent posture (journal, syslog).
    pub decoy_persistent: bool,
    /// Whether kdump is armed on the decoy, or its state cannot be read.
    pub decoy_kdump_armed: bool,
    /// The persona mode.
    pub persona_mode: PersonaMode,
    /// Why and when the last switch was refused, when it was and the record is
    /// readable: on the hidden volume (an entry), or in `/run` (a way back,
    /// in the hidden session). `None` once a new switch is armed, or while the
    /// volume holding the record is not mounted.
    pub switch_refusal: Option<RefusedSwitch>,
    /// Uptime-based OpSec reminders.
    pub opsec_reminders: Vec<OpSecReminder>,
}

impl StatusReport {
    /// The verdict.
    pub fn posture(&self) -> Posture {
        self.posture
    }

    /// Whether the state file could not be read or trusted, so the recorded
    /// [`state`](Self::state) is the safe default rather than the record.
    pub fn record_unreadable(&self) -> bool {
        matches!(self.state_source, "unreadable" | "corrupt")
    }
}

fn load_outcome_name(outcome: &LoadOutcome) -> &'static str {
    match outcome {
        LoadOutcome::Loaded => "loaded",
        LoadOutcome::Missing => "missing",
        LoadOutcome::Unreadable => "unreadable",
        LoadOutcome::Corrupt => "corrupt",
    }
}

fn kind_name(kind: PolicyMountKind) -> &'static str {
    match kind {
        PolicyMountKind::ReadOnlyBind => "read-only",
        PolicyMountKind::Overlay => "overlay",
        PolicyMountKind::HiddenVolume => "hidden-volume",
    }
}

/// The posture, reason and remediation for a live view. The remediation names
/// the real binary path (`sudo <path> …`), through the one next-step renderer.
pub fn posture_of(
    view: &SessionView,
    state_unknown: bool,
) -> (Posture, Option<String>, Option<String>) {
    use crate::next_step::{NextStep, sudo_line};
    match view {
        SessionView::Hidden(_) => (Posture::Active, None, None),
        SessionView::Entering(_) => (Posture::Transitioning, None, None),
        SessionView::Interrupted {
            nextroot_mounted, ..
        } => (
            Posture::Degraded,
            Some(if *nextroot_mounted {
                "an interrupted activation left a populated /run/nextroot".to_string()
            } else {
                "an interrupted activation left its runtime files in /run".to_string()
            }),
            Some(format!(
                "Run `{}` to remove them",
                sudo_line(NextStep::Recover)
            )),
        ),
        SessionView::HiddenWithoutPlan(why) => (
            Posture::Degraded,
            Some(format!("in the hidden root without a way back: {why}")),
            Some("Power off to end the session".to_string()),
        ),
        SessionView::Decoy if state_unknown => {
            (Posture::Unknown, None, Some(unreadable_record_remedy()))
        }
        SessionView::Decoy => (Posture::Decoy, None, None),
    }
}

/// What to do about a state file that could not be read or trusted.
fn unreadable_record_remedy() -> String {
    use crate::next_step::{NextStep, sudo_line};
    format!(
        "Run `{}` and check the hidden volume before activating again",
        sudo_line(NextStep::Verify)
    )
}

fn view_name(view: &SessionView) -> &'static str {
    match view {
        SessionView::Decoy => "decoy",
        SessionView::Hidden(_) => "hidden",
        SessionView::HiddenWithoutPlan(_) => "hidden_without_plan",
        SessionView::Entering(_) => "entering",
        SessionView::Interrupted { .. } => "interrupted",
    }
}

fn plan_of(view: &SessionView) -> Option<&Plan> {
    match view {
        SessionView::Hidden(plan) | SessionView::Entering(plan) => Some(plan),
        SessionView::Interrupted { plan, .. } => plan.as_deref(),
        _ => None,
    }
}

/// Executes `nails status`.
pub struct StatusCommand<F: Filesystem> {
    filesystem: F,
    config: Config,
    state_file_path: PathBuf,
    paths: Paths,
}

impl<F: Filesystem> StatusCommand<F> {
    /// A status query for `config`, reading the state file at `state_file_path`.
    pub fn new(filesystem: F, config: Config, state_file_path: PathBuf) -> Self {
        Self {
            filesystem,
            config,
            state_file_path,
            paths: Paths::system(),
        }
    }

    /// Read the session's runtime files (the plan, a refused way back) under
    /// `paths` instead of the system's `/run`: tests give a scratch tree.
    #[must_use]
    pub fn with_paths(mut self, paths: Paths) -> Self {
        self.paths = paths;
        self
    }

    /// Build the report from the live system.
    pub fn run(&self) -> Result<StatusReport> {
        let entries = read_mountinfo().unwrap_or_default();
        let view = crate::session::probe::probe_with(
            &self.paths,
            &self.config.hidden_volume_root,
            &entries,
        );
        self.report(&view, &entries, Utc::now())
    }

    /// Build the report for a given live view and mount table.
    pub fn report(
        &self,
        view: &SessionView,
        entries: &[MountEntry],
        now: DateTime<Utc>,
    ) -> Result<StatusReport> {
        let loaded = StateFile::load_with_outcome(&self.state_file_path)?;
        let state_file = loaded.state_file;
        let (posture, mut reason, mut remediation) = posture_of(view, loaded.outcome.is_unknown());
        let hidden_root = &self.config.hidden_volume_root;
        let switch_refusal = RefusedSwitch::read(&self.paths.runtime(), hidden_root);
        // A power loss or a reset in the session leaves the record at Active
        // while the machine boots the plain decoy, and so does an entry the
        // soft-reboot refused, recorded before the switch: say which, rather
        // than show an active state next to a decoy posture without a word.
        if posture == Posture::Decoy && matches!(state_file.state, SystemState::Active { .. }) {
            reason = Some(if switch_refusal.is_some() {
                "the record still holds an active session, but none is running: the switch \
                 into it was refused"
                    .to_string()
            } else {
                "the record still holds an active session, but none is running: it ended \
                 without updating the record (a power loss, a reset or a failed hidden volume)"
                    .to_string()
            });
            remediation = Some(format!(
                "Run `{}` to reset the record",
                crate::next_step::sudo_line(crate::next_step::NextStep::Recover)
            ));
        }
        // Wherever the machine is, a record that cannot be read or trusted is
        // no guide for the next activation: say what to do about it when the
        // place needs nothing else.
        if loaded.outcome.is_unknown() && remediation.is_none() {
            remediation = Some(unreadable_record_remedy());
        }
        let plan = plan_of(view);
        let entered_at = plan
            .and_then(|p| p.entered_at)
            .and_then(|secs| DateTime::<Utc>::from_timestamp(i64::try_from(secs).ok()?, 0))
            .or(match &state_file.state {
                SystemState::Active { activated_at } if view.is_hidden() => Some(*activated_at),
                _ => None,
            });
        let uptime = entered_at.filter(|_| view.is_hidden()).map(|t| now - t);
        // The mount table names the root with its symlinks resolved.
        let resolved = self
            .filesystem
            .canonicalize(hidden_root)
            .unwrap_or_else(|_| hidden_root.clone());
        let hidden_mount = top_mount_at(entries, &resolved);
        let opsec_reminders = uptime
            .map(|u| generate_opsec_reminders(u, self.config.show_opsec_reminders))
            .unwrap_or_default();
        Ok(StatusReport {
            posture,
            session: view_name(view),
            reason,
            remediation,
            state_source: load_outcome_name(&loaded.outcome),
            entered_at,
            uptime,
            hidden_system: plan
                .and_then(|p| p.hidden.system.as_ref())
                .map(|p| p.display().to_string())
                .or_else(|| state_file.hidden_toplevel().map(str::to_string)),
            decoy_system: plan
                .and_then(|p| p.decoy.system.as_ref())
                .map(|p| p.display().to_string()),
            hidden_root: hidden_root.clone(),
            hidden_root_mounted: hidden_mount.is_some(),
            hidden_root_source: hidden_mount.map(|m| m.source.display().to_string()),
            accepted_decoy_storage: plan.and_then(|p| p.accepted_decoy_storage.clone()),
            hidden_root_covered_by: crate::hidden_root::shadowing_mount(
                entries,
                &resolved,
                plan.and_then(|p| p.hidden_dev.as_deref()),
            )
            .map(|cover| CoverView {
                source: cover.source.display().to_string(),
                mount_point: cover.mount_point.clone(),
            }),
            policy_mounts: plan
                .map(|p| {
                    p.policy_mounts
                        .iter()
                        .map(|m| PolicyMountView {
                            target: m.target.clone(),
                            kind: kind_name(m.kind),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            masked_units: plan
                .map(|p| p.masks.iter().chain(&p.boot_masks).cloned().collect())
                .unwrap_or_default(),
            required_units: plan
                .map(|p| required_units(p, &self.paths.run, view.is_hidden()))
                .unwrap_or_default(),
            nextroot_mounted: entries.iter().any(|e| {
                e.mount_point == Path::new(nails_teardown::whole_root::nextroot::NEXTROOT)
            }),
            last_activation: state_file.last_activation.clone(),
            decoy_persistent: !view.is_hidden()
                && crate::preflight::DecoyPersistenceCheck::decoy_is_persistent(&self.filesystem),
            decoy_kdump_armed: !view.is_hidden()
                && crate::preflight::DecoyPersistenceCheck::decoy_kdump_armed(&self.filesystem),
            persona_mode: self.config.persona.mode,
            switch_refusal,
            opsec_reminders,
            state: state_file.state,
        })
    }
}

#[cfg(test)]
mod tests;
