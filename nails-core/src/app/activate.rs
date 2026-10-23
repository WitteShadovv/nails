// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `activate` operation: prepare the whole-root session and enter it.
//!
//! Activation runs on the decoy: the pre-flight checks, the hidden NixOS
//! configuration, the overlay at `/run/nextroot` and the armed plan, then the
//! soft-reboot that stops every decoy program and starts the hidden userspace.
//! A front end confirms with the operator and shows a person the result before
//! the switch (which stops its terminal; a machine-readable result waits for
//! the commit), so the operation is split: [`prepare`] builds the manager and
//! runs the gates that read only (already-active, the platform gate, the attach
//! gate) without writing to the hidden volume, [`ReadyActivation::enter`]
//! stages the entry, and [`ReadyActivation::commit`] kills the decoy's shells
//! and enqueues the soft-reboot. The attach gate decides before anything is
//! written.
//!
//! The state lock and the trusted-state check are the front end's, between
//! `prepare` and `enter`: it takes the exclusive lock
//! ([`acquire_mutating`](super::lock::acquire_mutating) with
//! [`ReadyActivation::allow`]), refuses while holding it when
//! [`ReadyActivation::is_state_trusted`] is false, and keeps the lock until
//! the commit. Neither `enter` nor `commit` takes the lock or makes the check,
//! so a front end that skips them activates over a state file it cannot trust
//! and can race another operation over the mounts and the state file.

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
    /// Build no hidden NixOS system; run the decoy's own system under the overlay.
    pub overlay_only: bool,
    /// Proceed although the decoy keeps a persistent posture.
    pub allow_persistent_decoy: bool,
    /// Proceed on storage the decoy uses, accepting the risk.
    pub allow_decoy_storage: bool,
    /// Accept discards over the hidden volume for this run (the buried
    /// `--allow-discards` expert flag): the backend-detect check then warns
    /// instead of refusing.
    pub allow_discards: bool,
}

impl ActivateOptions {
    /// The session-entry options, with the activating binary recorded (it is
    /// copied into `/run` and run by the transition and the runtime units).
    pub fn enter_options(&self) -> EnterOptions {
        EnterOptions {
            overlay_only: self.overlay_only,
            allow_persistent_decoy: self.allow_persistent_decoy,
            binary: std::env::current_exe().unwrap_or_default(),
            allow_decoy_storage: self.allow_decoy_storage,
            allow_discards: self.allow_discards,
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
/// lock and the trusted-state check are the caller's (see the module docs): take
/// the lock, then ask [`is_state_trusted`](Self::is_state_trusted), before
/// [`enter`](Self::enter).
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
    /// file means the current state is unknown, so activation must refuse; a
    /// state file this process is not allowed to read is unreadable too.
    pub fn is_state_trusted(&self) -> bool {
        trusted(&self.manager.current_state_with_outcome())
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

/// Whether a load of the state file can be trusted: a file that loaded and
/// passed its integrity check, or no file at all (inactive). A corrupt or
/// unreadable file, and an error reading it (a permission denied), leave the
/// real state unknown.
fn trusted(load: &Result<(crate::SystemState, crate::LoadOutcome)>) -> bool {
    match load {
        Ok((_, outcome)) => !outcome.is_unknown(),
        Err(error) => {
            tracing::warn!(%error, "the state file cannot be read; the current state is unknown");
            false
        }
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
    // `check` (activate --dry-run) reports the same verdict through the platform
    // row, so the two never disagree.
    if let Some(profile) = manager.host_profile()
        && let Err(error) = profile.require_supported()
    {
        return Prepared::Unsupported(error);
    }

    // The attach gate decides before anything is written: the state lock, the
    // residue baseline and the staged configuration all land on the root.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hidden_root::{Allow, Refusal, RefusalKind};
    use crate::manager::EnterOptions;
    use crate::nixos::NixOSBuilder;
    use crate::platform::FakePlatform;
    use crate::{Config, NailsManager, RealFilesystem};
    use std::path::PathBuf;

    /// A bare manager whose hidden volume and state file live under `dir`. The
    /// live probe still reads the real machine, which is never a hidden NAILS
    /// overlay during the tests, so the session view is the decoy.
    fn manager_at(dir: &Path) -> NailsManager<RealFilesystem> {
        let hidden = dir.to_path_buf();
        let config = Config {
            hidden_volume_root: hidden.clone(),
            state_file_path: hidden.join("state.json"),
            log_path: hidden.join("logs"),
            ..Config::test_default()
        };
        let state_path = config.state_file_path.clone();
        NailsManager::new(RealFilesystem, config, state_path)
    }

    /// A ready activation over `manager`, with the given override state.
    fn ready(
        manager: NailsManager<RealFilesystem>,
        options: EnterOptions,
        accepted: Option<Refusal>,
        warning: Option<String>,
    ) -> ReadyActivation {
        ReadyActivation {
            manager,
            options,
            accepted,
            warning,
        }
    }

    #[test]
    fn enter_options_carries_every_activate_flag_through() {
        // Each CLI flag must map to its entry option; the stubbed
        // `Default::default()` would drop all four to false.
        let options = ActivateOptions {
            overlay_only: true,
            allow_persistent_decoy: true,
            allow_decoy_storage: true,
            allow_discards: true,
        };
        let entry = options.enter_options();
        assert!(entry.overlay_only, "overlay_only -> overlay_only");
        assert!(
            entry.allow_persistent_decoy,
            "allow_persistent_decoy -> allow_persistent_decoy"
        );
        assert!(
            entry.allow_decoy_storage,
            "allow_decoy_storage -> allow_decoy_storage"
        );
        assert!(entry.allow_discards, "allow_discards -> allow_discards");
    }

    #[test]
    fn enter_options_leaves_every_flag_off_when_none_are_set() {
        // The complementary boundary: with no flags the entry options stay
        // false, so a `Default::default()` stub cannot masquerade as the real
        // mapping by matching only the all-false case.
        let entry = ActivateOptions::default().enter_options();
        assert!(!entry.overlay_only);
        assert!(!entry.allow_persistent_decoy);
        assert!(!entry.allow_decoy_storage);
        assert!(!entry.allow_discards);
    }

    #[test]
    fn allow_reflects_the_decoy_storage_override() {
        // The lock's allowance is the one the entry options ask for. With the
        // override set it must be `DecoyStorage`; the `Default::default()` stub
        // would collapse it to `Nothing` and let the lock refuse a decoy-storage
        // root the operator accepted.
        let dir = tempfile::tempdir().unwrap();
        let options = EnterOptions {
            allow_decoy_storage: true,
            ..Default::default()
        };
        let ready = ready(manager_at(dir.path()), options, None, None);
        assert_eq!(ready.allow(), Allow::DecoyStorage);
    }

    #[test]
    fn allow_is_nothing_without_the_override() {
        let dir = tempfile::tempdir().unwrap();
        let ready = ready(manager_at(dir.path()), EnterOptions::default(), None, None);
        assert_eq!(ready.allow(), Allow::Nothing);
    }

    #[test]
    fn warning_returns_the_stored_sentence_verbatim() {
        // The accessor hands the front end the exact attach-gate warning. The
        // stubs (`None`, `Some("")`, `Some("xyzzy")`) all return something other
        // than the stored sentence, so an exact-match assertion kills them.
        let dir = tempfile::tempdir().unwrap();
        let sentence =
            "--allow-decoy-storage: using /mnt/hidden although it lives on the decoy's disk"
                .to_string();
        let ready = ready(
            manager_at(dir.path()),
            EnterOptions::default(),
            None,
            Some(sentence.clone()),
        );
        assert_eq!(ready.warning(), Some(sentence.as_str()));
    }

    #[test]
    fn warning_is_none_when_the_gate_raised_none() {
        let dir = tempfile::tempdir().unwrap();
        let ready = ready(manager_at(dir.path()), EnterOptions::default(), None, None);
        assert_eq!(ready.warning(), None);
    }

    #[test]
    fn accepted_returns_the_overridden_refusal() {
        // The confirmation prompt repeats the refusal the operator overrode.
        // The stub returns `None`, which would drop the refusal from the prompt.
        let dir = tempfile::tempdir().unwrap();
        let refusal = Refusal::new(RefusalKind::SameDeviceAsRoot, Path::new("/mnt/hidden"));
        let ready = ready(
            manager_at(dir.path()),
            EnterOptions::default(),
            Some(refusal.clone()),
            None,
        );
        assert_eq!(ready.accepted(), Some(&refusal));
    }

    #[test]
    fn accepted_is_none_when_nothing_was_overridden() {
        let dir = tempfile::tempdir().unwrap();
        let ready = ready(manager_at(dir.path()), EnterOptions::default(), None, None);
        assert!(ready.accepted().is_none());
    }

    #[test]
    fn a_missing_state_file_is_trusted() {
        // No state file legitimately means inactive, not unknown, so the state
        // can be trusted. The `false` stub would refuse here, and dropping the
        // `!` would report the known state as untrusted.
        let dir = tempfile::tempdir().unwrap();
        let ready = ready(manager_at(dir.path()), EnterOptions::default(), None, None);
        assert!(
            ready.is_state_trusted(),
            "a missing state file reads as inactive, which is trusted"
        );
    }

    #[test]
    fn a_corrupt_state_file_is_not_trusted() {
        // An unparseable state file leaves the real state unknown, so activation
        // must refuse. The `true` stub would wrongly trust it, and dropping the
        // `!` would wrongly trust the unknown state.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("state.json"), b"this is not json").unwrap();
        let ready = ready(manager_at(dir.path()), EnterOptions::default(), None, None);
        assert!(
            !ready.is_state_trusted(),
            "a corrupt state file is unknown, which must not be trusted"
        );
    }

    #[test]
    fn an_error_reading_the_state_file_is_not_trusted() {
        // A state file that cannot be read at all (a permission denied, which
        // the load returns as an error) leaves the state as unknown as a
        // corrupt one. An `Err(_) => true` arm would let activation go on.
        let denied = Err(NailsError::PermissionDenied(
            "Cannot read state file /mnt/data/state.json".to_string(),
        ));
        assert!(!trusted(&denied), "an unreadable state file is unknown");
        // The two outcomes a load can be trusted with, for contrast.
        assert!(trusted(&Ok((
            crate::SystemState::Inactive,
            crate::LoadOutcome::Missing
        ))));
        assert!(trusted(&Ok((
            crate::SystemState::Inactive,
            crate::LoadOutcome::Loaded
        ))));
        assert!(!trusted(&Ok((
            crate::SystemState::Inactive,
            crate::LoadOutcome::Unreadable
        ))));
    }

    #[test]
    fn a_state_file_this_process_may_not_read_is_not_trusted() {
        use std::os::unix::fs::PermissionsExt;
        if nix::unistd::geteuid().is_root() {
            // root reads a file whatever its mode, so nothing is denied.
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state.json");
        std::fs::write(&state, b"{}").unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o000)).unwrap();
        let ready = ready(manager_at(dir.path()), EnterOptions::default(), None, None);
        let verdict = ready.is_state_trusted();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            !verdict,
            "a state file the activating process cannot read must not be trusted"
        );
    }

    #[test]
    fn builds_hidden_system_when_a_nixos_target_is_configured() {
        // On a NixOS host with a build target and no --overlay-only, the entry
        // builds a hidden system; the `false` stub would hide the build step.
        let dir = tempfile::tempdir().unwrap();
        let mut manager = manager_at(dir.path());
        manager.set_host_profile(FakePlatform::nixos().host_profile());
        manager.set_nixos_builder(NixOSBuilder::new_legacy(PathBuf::from(
            "/etc/nixos/configuration.nix",
        )));
        let ready = ready(manager, EnterOptions::default(), None, None);
        assert!(
            ready.builds_hidden_system(),
            "a configured NixOS target builds a hidden system"
        );
    }

    #[test]
    fn builds_no_hidden_system_under_overlay_only() {
        // --overlay-only runs the decoy's own system under the overlay, so no
        // hidden system is built even with a NixOS target configured; the `true`
        // stub would claim a build that never happens.
        let dir = tempfile::tempdir().unwrap();
        let mut manager = manager_at(dir.path());
        manager.set_host_profile(FakePlatform::nixos().host_profile());
        manager.set_nixos_builder(NixOSBuilder::new_legacy(PathBuf::from(
            "/etc/nixos/configuration.nix",
        )));
        let options = EnterOptions {
            overlay_only: true,
            ..Default::default()
        };
        let ready = ready(manager, options, None, None);
        assert!(
            !ready.builds_hidden_system(),
            "overlay-only builds no hidden system"
        );
    }
}
