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
use nails_teardown::whole_root::plan::{Plan, PolicyMountKind};
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
    /// What to do about it.
    pub remediation: Option<&'static str>,
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
    /// Whether `/run/nextroot` is populated.
    pub nextroot_mounted: bool,
    /// The last successful activation.
    pub last_activation: Option<LastActivation>,
    /// Whether the decoy keeps a persistent posture (journal, syslog).
    pub decoy_persistent: bool,
    /// The persona mode.
    pub persona_mode: PersonaMode,
    /// Uptime-based OpSec reminders.
    pub opsec_reminders: Vec<OpSecReminder>,
}

impl StatusReport {
    /// The verdict.
    pub fn posture(&self) -> Posture {
        self.posture
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

/// The posture, reason and remediation for a live view.
pub fn posture_of(
    view: &SessionView,
    state_unknown: bool,
) -> (Posture, Option<String>, Option<&'static str>) {
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
            Some("Run `nails recover` to remove them"),
        ),
        SessionView::HiddenWithoutPlan(why) => (
            Posture::Degraded,
            Some(format!("in the hidden root without a way back: {why}")),
            Some("Power off to end the session"),
        ),
        SessionView::Decoy if state_unknown => (
            Posture::Unknown,
            None,
            Some("Run `nails verify` and check the hidden volume before activating again"),
        ),
        SessionView::Decoy => (Posture::Decoy, None, None),
    }
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
}

impl<F: Filesystem> StatusCommand<F> {
    /// A status query for `config`, reading the state file at `state_file_path`.
    pub fn new(filesystem: F, config: Config, state_file_path: PathBuf) -> Self {
        Self {
            filesystem,
            config,
            state_file_path,
        }
    }

    /// Build the report from the live system.
    pub fn run(&self) -> Result<StatusReport> {
        let entries = read_mountinfo().unwrap_or_default();
        let view = crate::session::probe::probe_with(
            &Paths::system(),
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
        // A power loss or a reset in the session leaves the record at Active
        // while the machine boots the plain decoy: say so, rather than show an
        // active state next to a decoy posture without a word.
        if posture == Posture::Decoy && matches!(state_file.state, SystemState::Active { .. }) {
            reason = Some(
                "the record still holds an active session, but none is running: it ended \
                 without updating the record (a power loss, a reset or a failed hidden volume)"
                    .to_string(),
            );
            remediation = Some("Run `nails recover` to reset the record");
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
        let hidden_root = &self.config.hidden_volume_root;
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
            masked_units: plan.map(|p| p.masks.clone()).unwrap_or_default(),
            nextroot_mounted: entries.iter().any(|e| {
                e.mount_point == Path::new(nails_teardown::whole_root::nextroot::NEXTROOT)
            }),
            last_activation: state_file.last_activation.clone(),
            decoy_persistent: !view.is_hidden()
                && crate::preflight::DecoyPersistenceCheck::decoy_is_persistent(&self.filesystem),
            persona_mode: self.config.persona.mode,
            opsec_reminders,
            state: state_file.state,
        })
    }
}

#[cfg(test)]
mod tests;
