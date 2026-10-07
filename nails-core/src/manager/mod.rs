// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # NailsManager - Core Orchestrator for NAILS Operations
//!
//! Central orchestrator that coordinates all NAILS operations including state
//! transitions, filesystem operations, and validation logic.
//!
//! # Design Pattern: Generic Manager with Dependency Injection
//!
//! NailsManager uses generic programming to enable compile-time polymorphism:
//! - Production: `NailsManager<RealFilesystem>` uses actual syscalls
//! - Testing: `NailsManager<MockFilesystem>` uses in-memory state (no root required)
//!
//! This pattern enables 99% of tests to run without root privileges.
//!
//! # Module Structure
//!
//! - **mod.rs** - Core NailsManager struct, constructors, and helper functions
//! - **helpers.rs** - Free helper functions (overlay targets, system profiles, etc.)
//! - **mount_tracker.rs** - RAII mount tracking for automatic rollback
//! - **state_management.rs** - State transitions and verification
//! - **preflight_runner.rs** - Pre-flight check registration and execution
//! - **activation.rs** - 10-step activation flow
//! - **deactivation.rs** - Deactivation and emergency mode
//!
//! # Example
//!
//! ```rust
//! use nails_core::{NailsManager, MockFilesystem, Config};
//! use std::path::PathBuf;
//!
//! // Testing: MockFilesystem (no root required)
//! let fs = MockFilesystem::new();
//! let config = Config::default();
//! let state_path = PathBuf::from("/tmp/test-state.json");
//! let manager = NailsManager::new(fs, config, state_path);
//!
//! // Production: RealFilesystem (requires root)
//! // let fs = RealFilesystem;
//! // let manager = NailsManager::new(fs, config, state_path);
//! ```

use crate::{Config, Filesystem, NailsError, Result};
use std::cell::RefCell;
use std::path::PathBuf;

pub use activation::rollback::RollbackOutcome;

// Module declarations
pub mod activation;
pub mod deactivation;
pub(crate) mod helpers;
pub mod mount_tracker;
pub mod preflight_runner;
pub mod state_management;
pub mod teardown_plan;

// Tests live in tests/, one file per production module
#[cfg(test)]
mod tests;

// Re-export key types for convenience
pub use activation::{ActivationOutcome, HiddenConfigOutcome};
pub use deactivation::RecoverOutcome;
pub use deactivation::{HostEffects, PostTeardownPower};
#[cfg(any(test, feature = "test-hooks"))]
pub use deactivation::{SimulatedHostEffects, SimulatedReboot};
pub use mount_tracker::{MountInfo, MountTracker, MountType};
pub use state_management::ResetUpperPlan;

// Re-export public functions from helpers
pub use helpers::{apply_exclusion_filter, build_overlay_targets};
pub use preflight_runner::{RegistryInputs, build_registry};

// Re-export crate-internal helpers so sub-modules (e.g., activation) can use `super::*`
pub(crate) use helpers::{
    clean_stale_network_config, create_overlay_config, ensure_run_current_system_symlink,
    restart_service_and_socket, select_decoy_restore_target, select_system_profile,
    start_service_and_socket,
};

/// Central orchestrator for all NAILS operations
///
/// NailsManager coordinates state transitions, filesystem operations,
/// and validation logic. The generic Filesystem parameter enables
/// testing without root privileges.
///
/// # Fields
///
/// - `filesystem`: Generic filesystem implementation (real or mock)
/// - `config`: Application configuration
/// - `state_file_path`: Path to state file (on hidden volume)
/// - `cached_state`: Cached state file (lazy loaded)
///
/// # Interior mutability
///
/// `cached_state` uses `RefCell<_>` so the lazy load can populate the cache
/// through a shared reference. NAILS orchestration is single-threaded,
/// so no cross-thread synchronisation is required.
///
/// # Requirements
///
/// - Core library contains all business logic
/// - Testable without root via trait abstraction
/// - Generic NailsManager<F: Filesystem> pattern
pub struct NailsManager<F: Filesystem> {
    /// Filesystem implementation (real or mock)
    filesystem: F,

    /// Application configuration
    config: Config,

    /// Path to state file (on hidden volume)
    state_file_path: PathBuf,

    /// Cached state file (lazy loaded)
    /// `RefCell` gives interior mutability for the lazy load through `&self`.
    cached_state: RefCell<Option<crate::StateFile>>,

    /// NixOS profile builder (optional, for activation with NixOS switching)
    /// If None, activation will skip NixOS build/switch steps
    nixos_builder: Option<crate::nixos::NixOSBuilder>,

    /// Host facts from the platform seam, detected once (or injected by a test).
    ///
    /// The platform backend is derived from this on demand (see
    /// [`NailsManager::platform`]); backends are zero-sized, so nothing larger is
    /// stored. `None` until [`initialize_platform`](NailsManager::initialize_platform)
    /// or [`set_host_profile`](NailsManager::set_host_profile) runs, which keeps
    /// every existing constructor working while call sites are rewired onto the
    /// seam.
    host_profile: Option<crate::platform::HostProfile>,

    /// A backend injected by a test ([`set_fake_platform`](Self::set_fake_platform)),
    /// answering instead of the one derived from [`host_profile`](Self::host_profile).
    /// Always `None` in production.
    platform_override: Option<std::sync::Arc<dyn crate::platform::Platform<F> + Send + Sync>>,

    /// How the post-deactivation reboot touches the host.
    ///
    /// [`HostEffects::Real`] in every constructor, which dispatches the real
    /// reboot commands (skipping only while runtime-safety mode is active). A
    /// test injects [`HostEffects::Simulated`] through
    /// [`set_host_effects`](NailsManager::set_host_effects) to observe the reboot
    /// request without rebooting the machine.
    host_effects: HostEffects,

    /// What a standard deactivation does to the host once the decoy is restored:
    /// [`PostTeardownPower::Reboot`] (the default) or, when the operator asked for
    /// it, [`PostTeardownPower::Poweroff`].
    post_deactivation_power: PostTeardownPower,

    /// Verbosity level for progress output
    verbosity: crate::verbosity::Verbosity,

    /// Outcome of the most recent activation-scope overlay rollback.
    ///
    /// Written by the [`StateGuard`](crate::StateGuard) as it unwinds a failed
    /// activation (it copies in what the activation-scope rollback guard recorded
    /// in its own scope) and read by the CLI afterwards, so a failed `activate`
    /// reports the rollback truthfully instead of always claiming it completed.
    /// `RefCell` (not `Rc`) keeps `NailsManager` `Send`; reset at the start of
    /// each activation.
    last_rollback: RefCell<activation::rollback::RollbackOutcome>,

    /// Where activation reports its progress (steps, details, heartbeats).
    ///
    /// Defaults to [`TracingReporter`](crate::reporter::progress::TracingReporter);
    /// the CLI replaces it with the surface-specific reporter (terminal spinner,
    /// plain lines, JSON events, or silent when detached).
    reporter: crate::reporter::progress::SharedReporter,

    /// The startup environment snapshot (`HOME`, the escalation variables, the
    /// display/session variables, the NAILS_* knobs). The CLI reads it once in
    /// `main` and attaches it with [`with_runtime_env`](Self::with_runtime_env);
    /// activation reads the operator and session off it instead of re-reading the
    /// process environment. Defaults to the installed startup snapshot (empty
    /// when none is installed, as in unit tests); tests inject a built
    /// [`RuntimeEnv`](crate::RuntimeEnv).
    runtime_env: crate::RuntimeEnv,

    /// Where the teardown plan lives (the decoy's `/run` tmpfs). `None` keeps
    /// the plan in memory only, which is what the unit tests and the
    /// runtime-safety mode get by default.
    plan_path: Option<PathBuf>,

    /// The plan the running activation records (see [`teardown_plan`]).
    teardown_plan: RefCell<Option<teardown_plan::PlanRecorder>>,

    /// Whether the last activation restarted the operator's session, so its
    /// results may still need delivering once the new session is up.
    session_restarted: std::cell::Cell<bool>,
}

// Manual Debug implementation because NixOSBuilder contains trait objects
impl<F: Filesystem> std::fmt::Debug for NailsManager<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NailsManager")
            .field("filesystem", &"<filesystem>")
            .field("config", &self.config)
            .field("state_file_path", &self.state_file_path)
            .field("cached_state", &"<RefCell<...>>")
            .field(
                "nixos_builder",
                &self.nixos_builder.as_ref().map(|_| "<NixOSBuilder>"),
            )
            .field(
                "host_profile",
                &self.host_profile.as_ref().map(|profile| profile.kind),
            )
            .field("host_effects", &self.host_effects)
            .field("post_deactivation_power", &self.post_deactivation_power)
            .field("verbosity", &self.verbosity)
            .finish()
    }
}

/// The plan file a manager uses by default: the decoy's `/run` copy in a real
/// run, none (memory only) in a test or runtime-safety run.
fn default_plan_path() -> Option<PathBuf> {
    (!crate::runtime_safety::should_skip_host_interaction())
        .then(nails_teardown::plan::default_plan_path)
}

impl<F: Filesystem> NailsManager<F> {
    /// Create a new NailsManager with lazy loading
    ///
    /// The constructor stores all parameters but does NOT load state from disk.
    /// State is loaded lazily on first access via `current_state()`.
    ///
    /// # Arguments
    ///
    /// * `filesystem` - Filesystem implementation (RealFilesystem or MockFilesystem)
    /// * `config` - Application configuration
    /// * `state_file_path` - Path to state file (must be on hidden volume)
    ///
    /// # Returns
    ///
    /// New NailsManager instance with unloaded state (None) and no NixOS builder.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    /// let manager = NailsManager::new(fs, config, state_path);
    /// ```
    pub fn new(filesystem: F, config: Config, state_file_path: PathBuf) -> Self {
        Self {
            filesystem,
            config,
            state_file_path,
            cached_state: RefCell::new(None),
            nixos_builder: None,
            host_profile: None,
            platform_override: None,
            host_effects: HostEffects::Real,
            post_deactivation_power: PostTeardownPower::Reboot,
            verbosity: crate::verbosity::Verbosity::default(),
            last_rollback: RefCell::new(activation::rollback::RollbackOutcome::NotNeeded),
            reporter: crate::reporter::progress::shared(crate::reporter::progress::TracingReporter),
            runtime_env: (*crate::runtime_env::current()).clone(),
            plan_path: default_plan_path(),
            teardown_plan: RefCell::new(None),
            session_restarted: std::cell::Cell::new(false),
        }
    }

    /// Create a new NailsManager with NixOS builder for full activation support
    ///
    /// Use this constructor when you need NixOS profile building and switching
    /// during activation. The standard `new()` constructor creates a manager
    /// without NixOS support (activation will skip NixOS steps).
    ///
    /// # Arguments
    ///
    /// * `filesystem` - Filesystem implementation (RealFilesystem or MockFilesystem)
    /// * `config` - Application configuration
    /// * `state_file_path` - Path to state file (must be on hidden volume)
    /// * `nixos_builder` - NixOS profile builder instance
    ///
    /// # Returns
    ///
    /// New NailsManager instance with NixOS support enabled.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config, NixOSBuilder};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    /// let nixos_builder = NixOSBuilder::new(
    ///     PathBuf::from("/mnt/hidden/nixos"),
    ///     PathBuf::from("/nix/var/nix/profiles/nails-system"),
    /// );
    /// let manager = NailsManager::with_nixos(fs, config, state_path, nixos_builder);
    /// ```
    pub fn with_nixos(
        filesystem: F,
        config: Config,
        state_file_path: PathBuf,
        nixos_builder: crate::nixos::NixOSBuilder,
    ) -> Self {
        Self {
            filesystem,
            config,
            state_file_path,
            cached_state: RefCell::new(None),
            nixos_builder: Some(nixos_builder),
            host_profile: None,
            platform_override: None,
            host_effects: HostEffects::Real,
            post_deactivation_power: PostTeardownPower::Reboot,
            verbosity: crate::verbosity::Verbosity::default(),
            last_rollback: RefCell::new(activation::rollback::RollbackOutcome::NotNeeded),
            reporter: crate::reporter::progress::shared(crate::reporter::progress::TracingReporter),
            runtime_env: (*crate::runtime_env::current()).clone(),
            plan_path: default_plan_path(),
            teardown_plan: RefCell::new(None),
            session_restarted: std::cell::Cell::new(false),
        }
    }

    /// Seed the in-memory cached state without writing a state file to disk.
    ///
    /// Test-support only. It lets a fixture put the manager into a known state
    /// (for example [`SystemState::Inactive`](crate::SystemState::Inactive))
    /// before exercising a method that reads or mutates the cache, without
    /// having to stage a real state file first.
    #[cfg(any(test, feature = "test-support"))]
    pub fn seed_cached_state(&self, state: crate::StateFile) {
        *self.cached_state.borrow_mut() = Some(state);
    }

    /// Replace the post-deactivation reboot dispatcher.
    ///
    /// Test-support only. It lets a test inject a [`HostEffects::Simulated`]
    /// recorder so the post-teardown reboot can be observed without rebooting the
    /// machine; production always keeps the default [`HostEffects::Real`].
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_host_effects(&mut self, host_effects: HostEffects) {
        self.host_effects = host_effects;
    }

    /// Choose what a standard deactivation does after restoring the decoy.
    ///
    /// The default reboots into the decoy. [`PostTeardownPower::Poweroff`] powers
    /// the machine off instead: a warm reboot leaves DRAM contents in place unless
    /// the firmware honours the TCG memory-overwrite request, while a power-off
    /// lets them decay.
    pub fn set_post_deactivation_power(&mut self, action: PostTeardownPower) {
        self.post_deactivation_power = action;
    }

    /// Set verbosity level for progress output
    ///
    /// Controls the amount of detail in progress messages during operations.
    ///
    /// # Arguments
    ///
    /// * `verbosity` - Desired verbosity level
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config, Verbosity};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/tmp/state.json");
    /// let mut manager = NailsManager::new(fs, config, state_path);
    /// manager.set_verbosity(Verbosity::Verbose);
    /// ```
    pub fn set_verbosity(&mut self, verbosity: crate::verbosity::Verbosity) {
        self.verbosity = verbosity;
    }

    /// Set where activation reports its progress.
    ///
    /// The reporter receives a numbered step per activation phase, details
    /// within a phase (the overlay being mounted) and heartbeats while a long
    /// build or switch runs. Steps are only reported at Normal verbosity or
    /// above; the hidden-volume progress record is kept regardless.
    pub fn set_reporter(&mut self, reporter: crate::reporter::progress::SharedReporter) {
        self.reporter = reporter;
    }

    /// Detect the host through this manager's filesystem and store the profile.
    ///
    /// Runs the platform seam's [`detect`](crate::platform::detect) once and
    /// caches the result; the platform backend is derived from it on demand by
    /// [`platform`](Self::platform). Idempotent: a later call re-detects and
    /// replaces the stored profile.
    pub fn initialize_platform(&mut self) -> Result<()> {
        self.host_profile = Some(crate::platform::detect(&self.filesystem)?);
        self.platform_override = None;
        Ok(())
    }

    /// Store host facts detected elsewhere (or injected by a test), bypassing
    /// [`initialize_platform`](Self::initialize_platform).
    pub fn set_host_profile(&mut self, profile: crate::platform::HostProfile) {
        self.host_profile = Some(profile);
        self.platform_override = None;
    }

    /// Run this manager against a [`FakePlatform`](crate::platform::FakePlatform).
    ///
    /// Test-support only. Stores the fake as the backend and a host profile of
    /// the fake's kind, so every platform-derived decision (config layer,
    /// build-target discovery, unsupported-host refusal) agrees with it — no
    /// os-release or `/etc/nixos` fixtures needed.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_fake_platform(&mut self, fake: crate::platform::FakePlatform) {
        self.host_profile = Some(fake.host_profile());
        self.platform_override = Some(std::sync::Arc::new(fake));
    }

    /// Wire (or replace) the NixOS profile builder after construction.
    ///
    /// Lets a caller detect the host and run build-target discovery through
    /// this manager first, then attach the builder for the discovered target.
    pub fn set_nixos_builder(&mut self, builder: crate::nixos::NixOSBuilder) {
        self.nixos_builder = Some(builder);
    }

    /// Resolve the declarative build target activation would select.
    ///
    /// Asks the host's platform backend (see
    /// [`discover_host_target`](crate::platform::discover_host_target)) with this
    /// manager's hidden-volume root and configured `nixos_flake`. With no host
    /// profile detected the NixOS cascade answers, as it always has; on a host
    /// without a config layer the answer is [`HostTarget::None`](crate::HostTarget::None).
    pub fn discover_host_target(&self, overlay_only: bool) -> Result<crate::platform::HostTarget> {
        let hidden_root = &self.config.hidden_volume_root;
        let explicit = self.config.nixos_flake.as_deref();
        match self.platform_override.as_deref() {
            Some(platform) => crate::platform::discover_with_platform(
                platform,
                &self.filesystem,
                hidden_root,
                explicit,
                overlay_only,
            ),
            None => crate::platform::discover_host_target(
                &self.filesystem,
                self.host_profile.as_ref(),
                hidden_root,
                explicit,
                overlay_only,
            ),
        }
    }

    /// The detected host facts, if the platform seam has been initialised.
    pub fn host_profile(&self) -> Option<&crate::platform::HostProfile> {
        self.host_profile.as_ref()
    }

    /// The platform backend for the detected host, derived from
    /// [`host_profile`](Self::host_profile) (or the fake a test injected).
    ///
    /// Backends are zero-sized, so deriving one per call is free. Returns `None`
    /// until a profile has been set. The returned trait object refuses on an
    /// unsupported host.
    pub fn platform(
        &self,
    ) -> Option<std::sync::Arc<dyn crate::platform::Platform<F> + Send + Sync>> {
        if let Some(platform) = self.platform_override.as_ref() {
            return Some(std::sync::Arc::clone(platform));
        }
        self.host_profile
            .as_ref()
            .map(|profile| std::sync::Arc::from(crate::platform::platform_for::<F>(profile)))
    }

    /// The declarative hidden-config layer for this host, if it has one.
    ///
    /// Owned by the platform backend
    /// ([`Platform::config_layer`](crate::platform::Platform::config_layer)):
    /// `Some` only on NixOS, or whatever an injected
    /// [`FakePlatform`](crate::platform::FakePlatform) serves. When no host
    /// profile has been detected (a caller that skips detection, or a failed
    /// detection) the NixOS backend answers, preserving the historical behaviour
    /// where a configured builder meant NixOS work.
    ///
    /// The staging, the base-config gate, the config pre-flight checks, the
    /// fingerprint, the `/etc` import, the build and the switch all run through
    /// the returned layer and are skipped entirely when it is `None`, so a
    /// Debian/Ubuntu (or any FHS) host never touches `/etc/nixos`, `nixos-rebuild`
    /// or `switch-to-configuration`.
    pub(crate) fn config_layer(&self) -> Option<Box<dyn crate::platform::ConfigLayer<F>>> {
        use crate::platform::Platform;
        match self.platform() {
            Some(platform) => platform.config_layer(),
            None => crate::platform::NixOsPlatform.config_layer(),
        }
    }

    /// Stage the complete hidden declarative config through the platform config
    /// layer.
    ///
    /// The CLI calls this before the session kill and detach so staging output
    /// stays visible on the terminal; the detached worker re-stages through the
    /// same layer in its pre-flight phase, so both processes take the identical
    /// gate. A no-op when the host has no config layer (FHS / Debian) or in
    /// overlay-only mode — both are "no layer", so the hidden `/etc/nixos` tree is
    /// never touched there.
    pub fn stage_hidden_config(&self, overlay_only: bool) -> Result<()> {
        if let Some(layer) = self.config_layer().filter(|_| !overlay_only) {
            layer.stage(&self.filesystem, &self.config.hidden_volume_root, false)?;
        }
        Ok(())
    }

    /// Unmount overlays in reverse order (LIFO)
    ///
    /// Unmounts overlays in reverse of mount order to respect dependencies.
    /// Uses best-effort rollback: continues unmounting even if individual unmounts fail.
    ///
    /// # Arguments
    ///
    /// * `mounted_paths` - Vec of mounted overlay paths in mount order
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All unmounts succeeded
    /// * `Err(NailsError)` - One or more unmounts failed (with aggregate error details)
    ///
    /// # Behavior
    ///
    /// - Unmounts in LIFO order (reverse iteration)
    /// - Tries graceful unmount first, then force unmount on failure
    /// - Logs each unmount operation
    /// - Best-effort: continues even if one unmount fails
    /// - Returns aggregate error listing all failures
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let manager = NailsManager::new(fs, config, PathBuf::from("/tmp/state.json"));
    ///
    /// let mounted = vec![PathBuf::from("/home"), PathBuf::from("/etc")];
    /// manager.unmount_overlays(mounted).unwrap();
    /// // Unmounts in reverse: /etc first, then /home
    /// ```
    pub fn unmount_overlays(&self, mounted_paths: Vec<PathBuf>) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();

        // LIFO: unmount in reverse order
        for path in mounted_paths.iter().rev() {
            tracing::info!(
                path = %path.display(),
                order = "LIFO",
                "Unmounting overlay"
            );

            // Try graceful unmount first
            if let Err(e) = self.filesystem.unmount(path, false) {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    attempt = "graceful",
                    "Unmount failed, trying force unmount"
                );

                // If graceful fails, try force unmount
                if let Err(force_err) = self.filesystem.unmount(path, true) {
                    let msg = format!(
                        "Failed to unmount {} (graceful and force both failed): {}",
                        path.display(),
                        force_err
                    );
                    tracing::warn!(
                        path = %path.display(),
                        error = %force_err,
                        attempts = "both",
                        "Force unmount also failed"
                    );
                    errors.push(msg); // Collect error but continue (best-effort)
                } else {
                    tracing::info!(
                        path = %path.display(),
                        method = "force",
                        "Unmount succeeded"
                    );
                }
            } else {
                tracing::info!(
                    path = %path.display(),
                    method = "graceful",
                    "Unmount succeeded"
                );
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(NailsError::OverlayError(format!(
                "Unmount completed with errors: {}",
                errors.join("; ")
            )))
        }
    }

    /// Get reference to filesystem implementation
    ///
    /// Provides access to filesystem operations for advanced use cases like
    /// ActivationOrchestrator.
    ///
    /// # Returns
    ///
    /// Reference to the filesystem implementation (RealFilesystem or MockFilesystem)
    pub fn filesystem(&self) -> &F {
        &self.filesystem
    }

    /// Get reference to configuration
    ///
    /// Provides access to configuration for advanced use cases like
    /// ActivationOrchestrator.
    ///
    /// # Returns
    ///
    /// Reference to the configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Attach the startup environment snapshot the CLI read once in `main`.
    ///
    /// Activation resolves the operator and session off this snapshot (via
    /// [`runtime_env`](Self::runtime_env)) instead of re-reading the process
    /// environment, so every subsystem agrees on one set of values.
    #[must_use]
    pub fn with_runtime_env(mut self, runtime_env: crate::RuntimeEnv) -> Self {
        self.runtime_env = runtime_env;
        self
    }

    /// Replace the attached startup environment snapshot in place.
    pub fn set_runtime_env(&mut self, runtime_env: crate::RuntimeEnv) {
        self.runtime_env = runtime_env;
    }

    /// The attached startup environment snapshot.
    pub fn runtime_env(&self) -> &crate::RuntimeEnv {
        &self.runtime_env
    }

    /// The outcome of the most recent activation-scope overlay rollback.
    ///
    /// The CLI reads this after a failed `activate` so it reports the rollback
    /// truthfully: [`RollbackOutcome::NotNeeded`](activation::rollback::RollbackOutcome::NotNeeded)
    /// for a failure raised before any overlay was mounted (so no "rollback
    /// completed" line is printed), `Completed` when the overlays came down
    /// cleanly, and `Failed` (naming what it could not undo) otherwise.
    pub fn last_rollback(&self) -> activation::rollback::RollbackOutcome {
        self.last_rollback.borrow().clone()
    }

    /// Record the rollback outcome. Called by the [`StateGuard`](crate::StateGuard)
    /// as it unwinds a failed activation, copying in what the activation-scope
    /// rollback guard observed in its own scope.
    pub(crate) fn set_rollback_outcome(&self, outcome: activation::rollback::RollbackOutcome) {
        *self.last_rollback.borrow_mut() = outcome;
    }

    /// Reset the recorded rollback outcome at the start of an activation.
    pub(crate) fn reset_rollback_outcome(&self) {
        *self.last_rollback.borrow_mut() = activation::rollback::RollbackOutcome::NotNeeded;
    }

    /// Get current verbosity level for internal orchestration flows.
    pub(crate) fn verbosity(&self) -> crate::verbosity::Verbosity {
        self.verbosity
    }
}

#[cfg(test)]
mod platform_wiring_tests {
    use crate::filesystem::MockFilesystem;
    use crate::platform::PlatformKind;
    use crate::{Config, NailsManager, NixOSBuilder};
    use std::path::PathBuf;

    /// A mock host with a readable os-release and systemd PID 1, so detection
    /// needs no real /etc files.
    fn fhs_host() -> MockFilesystem {
        let fs = MockFilesystem::new();
        fs.mock_add_file("/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n");
        fs.mock_add_file("/proc/1/comm", "systemd");
        fs
    }

    fn manager(fs: MockFilesystem) -> NailsManager<MockFilesystem> {
        NailsManager::new(fs, Config::default(), PathBuf::from("/tmp/state.json"))
    }

    #[test]
    fn platform_is_none_until_initialised() {
        let m = manager(fhs_host());
        assert!(m.host_profile().is_none());
        assert!(m.platform().is_none());
    }

    #[test]
    fn initialize_platform_detects_and_derives_backend() {
        let mut m = manager(fhs_host());
        m.initialize_platform().unwrap();

        assert_eq!(m.host_profile().unwrap().kind, PlatformKind::Fhs);
        let backend = m.platform().expect("platform derived from profile");
        assert_eq!(backend.kind(), PlatformKind::Fhs);
    }

    #[test]
    fn set_host_profile_injects_without_fixtures() {
        // No /etc/nixos (or any fixture): inject a NixOS profile directly.
        let fs = MockFilesystem::new();
        fs.mock_add_file("/etc/os-release", "ID=nixos\n");
        fs.mock_add_file("/proc/1/comm", "systemd");
        let profile = crate::platform::detect(&fs).unwrap();

        let mut m = manager(MockFilesystem::new());
        m.set_host_profile(profile);
        assert_eq!(m.platform().unwrap().kind(), PlatformKind::NixOs);
    }

    #[test]
    fn platform_seam_coexists_with_nixos_builder() {
        // The seam is additive: a NixOS-builder manager still assembles and the
        // host profile threads through alongside it.
        let fs = fhs_host();
        let builder = NixOSBuilder::new(
            PathBuf::from("/mnt/hidden/nixos"),
            PathBuf::from("/nix/var/nix/profiles/nails-system"),
        );
        let mut m = NailsManager::with_nixos(
            fs,
            Config::default(),
            PathBuf::from("/tmp/state.json"),
            builder,
        );
        m.initialize_platform().unwrap();
        assert_eq!(m.host_profile().unwrap().kind, PlatformKind::Fhs);
    }

    #[test]
    fn fake_platform_drives_profile_backend_and_discovery() {
        use crate::platform::{FakePlatform, HostTarget};
        let mut m = NailsManager::new(
            MockFilesystem::new(),
            Config::default(),
            PathBuf::from("/tmp/state.json"),
        );
        m.set_fake_platform(
            FakePlatform::nixos().with_build_target(HostTarget::Flake(PathBuf::from("/cfg"))),
        );

        assert_eq!(m.host_profile().unwrap().kind, PlatformKind::NixOs);
        assert_eq!(m.platform().unwrap().kind(), PlatformKind::NixOs);
        assert!(m.config_layer().is_some());
        assert_eq!(
            m.discover_host_target(false).unwrap(),
            HostTarget::Flake(PathBuf::from("/cfg"))
        );
        assert_eq!(
            m.discover_host_target(true).unwrap(),
            HostTarget::OverlayOnly
        );
    }

    #[test]
    fn detection_replaces_an_injected_fake() {
        use crate::platform::{FakePlatform, HostTarget};
        let mut m = NailsManager::new(fhs_host(), Config::default(), PathBuf::from("/tmp/s.json"));
        m.set_fake_platform(
            FakePlatform::nixos().with_build_target(HostTarget::Flake(PathBuf::from("/cfg"))),
        );
        m.initialize_platform().unwrap();

        assert_eq!(m.platform().unwrap().kind(), PlatformKind::Fhs);
        assert_eq!(m.discover_host_target(false).unwrap(), HostTarget::None);
    }

    #[test]
    fn set_nixos_builder_wires_a_builder_after_construction() {
        let mut m = NailsManager::new(
            MockFilesystem::new(),
            Config::default(),
            PathBuf::from("/tmp/state.json"),
        );
        assert!(!m.hidden_switch_configured());
        m.set_nixos_builder(NixOSBuilder::new_legacy(
            PathBuf::from("/cfg/configuration.nix"),
            PathBuf::from("/nix/var/nix/profiles/nails-system"),
        ));
        assert!(m.hidden_switch_configured());
    }
}
