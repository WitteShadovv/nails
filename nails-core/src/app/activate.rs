// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `activate` operation: prepare the whole-root session and enter it.
//!
//! Activation runs on the decoy: the pre-flight checks, the hidden NixOS
//! configuration, the overlay at `/run/nextroot` and the armed plan, then the
//! soft-reboot that stops every decoy program and starts the hidden userspace.
//! A front end confirms with the operator and prints before the switch (which
//! stops its terminal), so the operation is split: [`prepare`] builds the
//! manager and runs the gates (already-active, the attach gate, the trusted-state
//! check) without writing to the hidden volume, [`ReadyActivation::enter`] stages
//! the entry, and [`ReadyActivation::commit`] kills the decoy's shells and
//! enqueues the soft-reboot. The attach gate decides before anything is written.

use std::path::Path;

use nails_teardown::shells::kill_all_interactive_shells;

use crate::hidden_root::{Assessment, Refusal};
use crate::manager::{EnterOptions, EnterOutcome};
use crate::session::{Entry, RealEntryHost, RealTargetHost};
use crate::verbosity::Verbosity;
use crate::{
    Config, NailsError, NailsManager, RealFilesystem, Result, RuntimeEnv, StateFileStatus,
    Verifier, VerifyResult, write_activation_residue_report,
};

/// What `activate` should do.
#[derive(Debug, Default, Clone)]
pub struct ActivateOptions {
    /// Skip the pre-flight checks (the attach gate still runs).
    pub no_preflight: bool,
    /// Build no hidden NixOS system; run the decoy's own system under the overlay.
    pub overlay_only: bool,
    /// Proceed although the decoy keeps a persistent posture.
    pub accept_persistent_decoy: bool,
    /// Proceed on storage the decoy uses, accepting the risk.
    pub allow_decoy_storage: bool,
}

impl ActivateOptions {
    /// The session-entry options, with the activating binary recorded (it is
    /// copied into `/run` and run by the transition and the runtime units).
    pub fn enter_options(&self) -> EnterOptions {
        EnterOptions {
            skip_preflight: self.no_preflight,
            overlay_only: self.overlay_only,
            accept_persistent_decoy: self.accept_persistent_decoy,
            binary: std::env::current_exe().unwrap_or_default(),
            allow_decoy_storage: self.allow_decoy_storage,
        }
    }
}

/// The result of preparing an activation.
pub enum Prepared {
    /// Already in the hidden session; there is nothing to do.
    AlreadyActive,
    /// The detected host is one NAILS refuses, declined before anything was
    /// written: the hidden volume keeps every byte and the command exits with
    /// the unsupported-platform code. Carries the detector's typed reason.
    Unsupported(NailsError),
    /// The attach gate refused the hidden root before anything was written.
    Refused(Box<Refusal>),
    /// The attach gate could not be evaluated.
    AttachError(NailsError),
    /// The gates passed: ready to lock, confirm and enter.
    Proceed(Box<ReadyActivation>),
}

/// A pre-mount residue baseline written before the overlays go up.
pub struct Baseline {
    /// The scan result, for the summary line.
    pub result: VerifyResult,
    /// Where the report was written.
    pub path: std::path::PathBuf,
}

/// An activation whose gates have passed, ready to confirm and enter. The state
/// lock is the caller's: take it before [`is_state_trusted`](Self::is_state_trusted).
pub struct ReadyActivation {
    manager: NailsManager<RealFilesystem>,
    options: EnterOptions,
    accepted: Option<Refusal>,
    warning: Option<String>,
}

impl ReadyActivation {
    /// The hidden volume root, for taking the state lock.
    pub fn hidden_root(&self) -> &Path {
        &self.manager.config().hidden_volume_root
    }

    /// The state file path, for taking the state lock.
    pub fn state_path(&self) -> &Path {
        &self.manager.config().state_file_path
    }

    /// What the operator accepted, for the lock's allowance.
    pub fn allow(&self) -> crate::hidden_root::Allow {
        self.options.allow()
    }

    /// The warning the attach gate raised (an overridden decoy-storage warning),
    /// for the front end to print before it confirms.
    pub fn warning(&self) -> Option<&str> {
        self.warning.as_deref()
    }

    /// The refusal the operator overrode with `--allow-decoy-storage`, repeated
    /// at the confirmation prompt.
    pub fn accepted(&self) -> Option<&Refusal> {
        self.accepted.as_ref()
    }

    /// Whether the recorded state can be trusted. A corrupt or unreadable state
    /// file means the current state is unknown, so activation must refuse.
    pub fn is_state_trusted(&self) -> bool {
        match self.manager.current_state_with_outcome() {
            Ok((_, outcome)) => !outcome.is_unknown(),
            Err(_) => true,
        }
    }

    /// Whether this activation builds a hidden NixOS system (for the progress line).
    pub fn builds_hidden_system(&self) -> bool {
        self.manager.builds_hidden_system(&self.options)
    }

    /// Scan the decoy for residue and write a pre-mount baseline report, before
    /// any overlay is mounted. Best-effort: a scan or write failure is logged
    /// and `None` is returned, because the baseline is a convenience for later
    /// comparison, not a precondition for activating.
    pub fn write_residue_baseline(&self) -> Option<Baseline> {
        let config = self.manager.config().clone();
        let hidden_root = config.hidden_volume_root.clone();
        if hidden_root.as_os_str().is_empty() {
            return None;
        }
        // Pre-activation the system is Inactive, so the scan sees the decoy as it
        // is before overlays. The scan is scoped to the decoy: the hidden volume
        // is already attached for the activation about to start, so its own mount
        // and backing device are not residue.
        let verifier =
            Verifier::with_config(RealFilesystem, config, None, StateFileStatus::NotChecked)
                .with_runtime_env(self.manager.runtime_env())
                .scoped_to_decoy();
        let result = match verifier.run(false) {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "pre-activation decoy residue scan failed; continuing without a baseline report"
                );
                return None;
            }
        };
        let timestamp = chrono::Utc::now().to_rfc3339();
        match write_activation_residue_report(&RealFilesystem, &hidden_root, &result, &timestamp) {
            Ok(summary) => Some(Baseline {
                result,
                path: summary.path,
            }),
            Err(e) => {
                tracing::warn!(error = %e, "could not write pre-activation decoy residue report; continuing");
                None
            }
        }
    }

    /// Stage the entry: the pre-flight checks, the hidden system and the armed
    /// overlay. Nothing is enqueued yet.
    pub fn enter(&mut self) -> Result<EnterOutcome> {
        self.manager.enter_session(&self.options, &RealEntryHost)
    }

    /// The point of no return: kill the decoy's interactive shells (so none
    /// writes the activation command to its history), then enqueue the
    /// soft-reboot into the prepared root.
    pub fn commit(&mut self, entry: &Entry) -> Result<()> {
        // The decoy's shells write their history when they exit, bash on the
        // SIGHUP that stopping their login session sends: the soft-reboot would
        // do that the moment it is enqueued. SIGKILL them first, ours last, so
        // the activation command never reaches a history file on the decoy disk.
        kill_all_interactive_shells(&[]);
        let host = RealTargetHost::for_plan(Some(&entry.plan));
        self.manager.trigger_entry(&host, &RealEntryHost)
    }
}

/// Prepare an activation: build the manager, check for an active session and run
/// the attach gate, all before anything is written to the hidden volume.
///
/// `config` is the effective configuration (overrides already applied) and
/// `verbosity` the resolved output verbosity. The caller then takes the state
/// lock, checks [`ReadyActivation::is_state_trusted`], confirms with the operator
/// and enters.
pub fn prepare(
    env: &RuntimeEnv,
    config: Config,
    verbosity: Verbosity,
    options: &ActivateOptions,
) -> Prepared {
    let state_path = config.state_file_path.clone();
    let mut manager =
        super::engine::build_nixos_manager(config, state_path, options.overlay_only, env);
    manager.set_verbosity(verbosity);

    if manager.session_view().is_hidden() {
        return Prepared::AlreadyActive;
    }

    // The platform gate: a host NAILS refuses is declined here, before the state
    // lock, the residue baseline or any staged configuration touches the hidden
    // volume, so a refused host leaves nothing behind and the command exits 8.
    // --no-preflight does not skip it, and `check` (activate --dry-run) reports
    // the same verdict through the platform row, so the two never disagree.
    if let Some(profile) = manager.host_profile()
        && let Err(error) = profile.require_supported()
    {
        return Prepared::Unsupported(error);
    }

    // The attach gate decides before anything is written: the state lock, the
    // residue baseline and the staged configuration all land on the root.
    // --no-preflight does not skip it.
    let enter_options = options.enter_options();
    let (accepted, warning) = match crate::HiddenRoot::assess_allowing(
        manager.filesystem(),
        &manager.config().hidden_volume_root,
        enter_options.allow(),
    ) {
        Ok(Assessment::Attached) => (None, None),
        Ok(Assessment::Warned(refusal)) => {
            let warning = refusal.warning();
            let accepted = refusal.overridden().then_some(refusal);
            (accepted, Some(warning))
        }
        Ok(Assessment::Refused(refusal)) => return Prepared::Refused(Box::new(refusal)),
        Err(e) => return Prepared::AttachError(e),
    };

    Prepared::Proceed(Box::new(ReadyActivation {
        manager,
        options: enter_options,
        accepted,
        warning,
    }))
}
