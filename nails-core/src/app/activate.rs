// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `activate` operation: prepare the whole-root session and enter it.
//!
//! Activation runs on the decoy: the pre-flight checks, the hidden NixOS
//! configuration, the overlay at `/run/nextroot` and the armed plan, then the
//! soft-reboot that stops every decoy program and starts the hidden userspace.
//! A front end confirms with the operator and shows a person the result before
//! the switch (which stops its terminal; a machine-readable result waits for
//! the commit), so the operation is split into steps, each handing out the
//! value the next one needs:
//!
//! 1. [`prepare`] builds the manager and runs the gates that read only
//!    (already-active, the platform gate, the attach gate) without writing to
//!    the hidden volume; the attach gate decides before anything is written.
//! 2. [`ReadyActivation::lock`] takes the exclusive state lock and, holding
//!    it, refuses a state file it cannot trust ([`LockError`]). It hands out
//!    the [`LockedActivation`], which holds the lock until it is dropped.
//! 3. [`LockedActivation::enter`] stages the entry, and
//!    [`LockedActivation::commit`] kills the decoy's shells and enqueues the
//!    soft-reboot.
//!
//! Only the locked handle enters and commits, and the manager's entry and
//! commit steps are this crate's alone, so a front end that activates through
//! this facade cannot do so without the lock or over a state file it cannot
//! trust. Below the facade the session's entry mechanics and the manager's
//! state writes stay public and hold neither gate ([the facade](super) names
//! them). The confirmation and the cancel checks between the steps are the
//! front end's.

use std::path::Path;

use super::lock::LockError;
use crate::hidden_root::{Allow, Assessment, Refusal};
use crate::manager::{EnterOptions, EnterOutcome};
use crate::session::package_drift::Advisory;
use crate::session::{Entry, RealEntryHost, RealTargetHost};
use crate::verbosity::Verbosity;
use crate::{
    Config, NailsError, NailsManager, RealFilesystem, Result, RuntimeEnv, StateFileStatus,
    StateLock, Verifier, VerifyResult, write_activation_residue_report,
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
    /// The window's launcher, which the entry writes into the hidden root: its
    /// menu entry and the polkit action of its helper. Only a build with the
    /// window sets it, and only when the window's program lies beside the
    /// engine.
    pub window_launcher: Option<crate::session::WindowLauncher>,
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
            window_launcher: self.window_launcher.clone(),
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

/// An activation whose read-only gates have passed, ready to lock. It cannot
/// enter: only the [`LockedActivation`] its [`lock`](Self::lock) step hands
/// out can, once the lock is held and the recorded state trusted.
///
/// ```compile_fail
/// fn enter_unlocked(ready: &mut nails_core::app::activate::ReadyActivation) {
///     let _ = ready.enter();
/// }
/// ```
///
/// ```
/// fn enter_locked(locked: &mut nails_core::app::activate::LockedActivation) {
///     let _ = locked.enter();
/// }
/// ```
pub struct ReadyActivation {
    manager: NailsManager<RealFilesystem>,
    options: EnterOptions,
    accepted: Option<Refusal>,
    warning: Option<String>,
}

impl ReadyActivation {
    /// The hidden volume root, which the state lock is taken on.
    fn hidden_root(&self) -> &Path {
        &self.manager.config().hidden_volume_root
    }

    /// The state file path, beside which the state lock lies.
    fn state_path(&self) -> &Path {
        &self.manager.config().state_file_path
    }

    /// What the operator accepted, for the lock's allowance.
    fn allow(&self) -> Allow {
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
    /// state file this process is not allowed to read, or to look up, is
    /// unreadable too.
    fn is_state_trusted(&self) -> bool {
        trusted(&self.manager.current_state_with_outcome())
    }

    /// Take the exclusive state lock, created only on the hidden volume or the
    /// root the operator accepted, and, holding it, refuse a state file that
    /// cannot be trusted ([`LockError::UntrustedState`]): a corrupt or
    /// unreadable one leaves the current state unknown. Hands out the only
    /// handle that enters and commits, which holds the lock until it is
    /// dropped.
    pub fn lock(self) -> std::result::Result<LockedActivation, LockError> {
        self.lock_with(super::lock::acquire_mutating)
    }

    /// [`lock`](Self::lock), taking the lock with `acquire`.
    fn lock_with(
        self,
        acquire: impl FnOnce(&Path, Allow, &Path) -> std::result::Result<StateLock, LockError>,
    ) -> std::result::Result<LockedActivation, LockError> {
        let lock = acquire(self.hidden_root(), self.allow(), self.state_path())?;
        // Checked under the lock, so no other operation changes the state
        // between the check and the entry.
        if !self.is_state_trusted() {
            return Err(LockError::UntrustedState);
        }
        Ok(LockedActivation {
            ready: self,
            _lock: lock,
        })
    }
}

/// An activation that holds the exclusive state lock over a state it trusts:
/// the only handle that stages the entry and commits it. The lock is released
/// when it is dropped.
pub struct LockedActivation {
    ready: ReadyActivation,
    /// Held for its `Drop`, which releases the lock.
    _lock: StateLock,
}

impl LockedActivation {
    /// The refusal the operator overrode with `--allow-decoy-storage`, repeated
    /// at the confirmation prompt.
    pub fn accepted(&self) -> Option<&Refusal> {
        self.ready.accepted()
    }

    /// Whether this activation builds a hidden NixOS system (for the progress line).
    pub fn builds_hidden_system(&self) -> bool {
        self.ready.manager.builds_hidden_system(&self.ready.options)
    }

    /// What the operator should read before confirming: the risks that do not
    /// refuse the entry, such as hidden sessions' package database no longer
    /// following the decoy's. Read only, and reported to a watching event
    /// stream as well. The entry lists them again among its warnings.
    pub fn entry_advisories(&self) -> Vec<Advisory> {
        self.ready.manager.entry_advisories(&self.ready.options)
    }

    /// Scan the decoy for residue and write a pre-mount baseline report, before
    /// any overlay is mounted. Best-effort: a scan or write failure is logged
    /// and `None` is returned, because the baseline is a convenience for later
    /// comparison, not a precondition for activating.
    pub fn write_residue_baseline(&self) -> Option<Baseline> {
        let config = self.ready.manager.config().clone();
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
                .with_runtime_env(self.ready.manager.runtime_env())
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
        let ready = &mut self.ready;
        ready.manager.enter_session(&ready.options, &RealEntryHost)
    }

    /// The point of no return: refuse while a program blocks shutdown, kill
    /// the decoy's interactive shells (so none writes the activation command
    /// to its history), then soft-reboot into the prepared root.
    pub fn commit(&mut self, entry: &Entry) -> Result<()> {
        // The decoy's shells write their history when they exit, bash on the
        // SIGHUP that stopping their login session sends: the soft-reboot does
        // that the moment PID 1 holds its job. The entry's host SIGKILLs them,
        // ours last, right before it asks logind, and keeps killing any shell
        // opened while logind holds the soft-reboot back, so the activation
        // command never reaches a history file on the decoy disk.
        let host = RealTargetHost::for_plan(Some(&entry.plan)).killing_shells();
        self.ready.manager.trigger_entry(&host, &RealEntryHost)
    }
}

/// Whether a load of the state file can be trusted: a file that loaded and
/// passed its integrity check, or no file at all (inactive). A corrupt or
/// unreadable file, and an error looking it up or reading it (a permission
/// denied), leave the real state unknown.
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
/// `verbosity` the resolved output verbosity. The caller then takes the lock
/// step ([`ReadyActivation::lock`]), confirms with the operator and enters.
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
        let launcher = crate::session::WindowLauncher {
            engine: std::path::PathBuf::from("/mnt/data/nails"),
            window: std::path::PathBuf::from("/mnt/data/gui/bin/session"),
        };
        let options = ActivateOptions {
            overlay_only: true,
            allow_persistent_decoy: true,
            allow_decoy_storage: true,
            allow_discards: true,
            window_launcher: Some(launcher.clone()),
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
        assert_eq!(
            entry.window_launcher,
            Some(launcher),
            "window_launcher -> window_launcher"
        );
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
        assert_eq!(entry.window_launcher, None);
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
    fn a_state_file_this_process_may_not_look_up_is_not_trusted() {
        use std::os::unix::fs::PermissionsExt;
        if nix::unistd::geteuid().is_root() {
            // root searches a directory whatever its mode, so nothing is denied.
            return;
        }
        // The directory holding the state file grants no search, as a
        // security policy that denies the lookup does: the file is there, but
        // no stat of it succeeds, which must not read as no state file.
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        std::fs::create_dir(&state_dir).unwrap();
        let state = state_dir.join("state.json");
        std::fs::write(&state, b"{}").unwrap();
        let config = Config {
            hidden_volume_root: dir.path().to_path_buf(),
            state_file_path: state.clone(),
            log_path: dir.path().join("logs"),
            ..Config::test_default()
        };
        let manager = NailsManager::new(RealFilesystem, config, state);
        let ready = ready(manager, EnterOptions::default(), None, None);
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o600)).unwrap();
        let verdict = ready.is_state_trusted();
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            !verdict,
            "a state file the activating process cannot look up must not be trusted"
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
        let locked = locked(ready(manager, EnterOptions::default(), None, None));
        assert!(
            locked.builds_hidden_system(),
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
        let locked = locked(ready(manager, options, None, None));
        assert!(
            !locked.builds_hidden_system(),
            "overlay-only builds no hidden system"
        );
    }

    /// The lock step of `ready`, taking the lock beside its state file without
    /// the attach gate (the scratch directory is no mount point).
    fn lock(ready: ReadyActivation) -> std::result::Result<LockedActivation, LockError> {
        ready.lock_with(crate::app::lock::acquire_unattached)
    }

    /// The locked handle of `ready`, whose state is trusted.
    fn locked(ready: ReadyActivation) -> LockedActivation {
        lock(ready).unwrap_or_else(|error| panic!("the lock step refused: {error:?}"))
    }

    /// Whether another operation could take the state lock in `dir` now.
    fn lock_is_free(dir: &Path) -> bool {
        crate::StateLock::try_acquire(dir).is_ok()
    }

    /// The lock step hands out the handle that enters, holding the lock for as
    /// long as the handle lives: no other operation takes it meanwhile.
    #[test]
    fn the_lock_step_holds_the_lock_for_the_handle_that_enters() {
        let dir = tempfile::tempdir().unwrap();
        let ready = ready(manager_at(dir.path()), EnterOptions::default(), None, None);
        let locked = locked(ready);
        assert!(!lock_is_free(dir.path()), "the handle holds the lock");
        drop(locked);
        assert!(lock_is_free(dir.path()), "dropping the handle releases it");
    }

    /// A state file that cannot be trusted is refused under the lock, and no
    /// handle that could enter is handed out; the lock is released again.
    #[test]
    fn the_lock_step_refuses_a_state_it_cannot_trust() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("state.json"), b"this is not json").unwrap();
        let ready = ready(manager_at(dir.path()), EnterOptions::default(), None, None);
        assert!(matches!(lock(ready), Err(LockError::UntrustedState)));
        assert!(lock_is_free(dir.path()), "a refusal keeps no lock");
    }

    /// A lock another operation holds is reported, and nothing is checked or
    /// handed out without it.
    #[test]
    fn the_lock_step_reports_a_lock_another_operation_holds() {
        let dir = tempfile::tempdir().unwrap();
        let _held = crate::StateLock::try_acquire(dir.path()).unwrap();
        let ready = ready(manager_at(dir.path()), EnterOptions::default(), None, None);
        assert!(matches!(
            lock(ready),
            Err(LockError::Unavailable(
                NailsError::OperationInProgress { .. }
            ))
        ));
    }

    /// The real lock step runs the attach gate first: a root it refuses (a
    /// scratch directory is no mount point) takes no lock at all.
    #[test]
    fn the_lock_step_refuses_a_root_the_attach_gate_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let ready = ready(manager_at(dir.path()), EnterOptions::default(), None, None);
        assert!(matches!(ready.lock(), Err(LockError::Refused(_))));
        assert!(!crate::StateLock::lock_path(dir.path()).exists());
    }
}
