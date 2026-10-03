//! Preflight Check Runner for NailsManager
//!
//! Extracted from state_management.rs to keep modules under 500 lines.
//! Contains the `run_preflight_checks` method that registers and runs
//! all pre-flight validation checks before activation.

use super::NailsManager;
use crate::preflight::PreFlightRegistry;
use crate::{
    Config, Filesystem, NailsError, Result, StateFile, SystemState, build_overlay_targets,
};
use std::path::PathBuf;

/// The runtime facts the shared pre-flight registry is assembled from.
///
/// Both activation (through [`NailsManager::preflight_registry`]) and the
/// read-only `nails check` command build their registry from a value of this
/// type, so the two can never drift: the set of checks is a pure function of
/// these inputs and the configuration.
#[derive(Debug, Clone)]
pub struct RegistryInputs {
    /// Skip the NixOS config and build-target checks (overlay-only activation).
    pub overlay_only: bool,
    /// Whether the detected host carries a declarative config layer (NixOS).
    ///
    /// The NixOS config and build-target checks are registered only when the host
    /// actually has a config layer, so a non-NixOS host (FHS / Debian) never runs
    /// NixOS-only checks that would fail with NixOS-specific guidance even without
    /// the `--overlay-only` flag. Resolved from the platform seam by
    /// [`NailsManager::preflight_registry`]; unit tests that build inputs directly
    /// set it explicitly.
    pub has_config_layer: bool,
    /// Assemble a registry that only inspects the system: no check creates a
    /// directory or changes permissions. Activation leaves this `false` so the
    /// storage check still auto-creates the hidden layout; `nails check` sets it
    /// so the command is strictly read-only.
    pub read_only: bool,
    /// The current system state, validated by [`StateCheck`](crate::StateCheck).
    pub current_state: SystemState,
    /// The flake build target was already validated out of band (the read-only
    /// flake preflight activation runs before detaching), so the in-registry
    /// [`NixOSBuildTargetCheck`](crate::preflight::NixOSBuildTargetCheck) is
    /// redundant and skipped.
    pub flake_target_already_validated: bool,
    /// The flake directory auto-discovery selected, validated directly by the
    /// build-target check when it runs.
    pub selected_flake_dir: Option<PathBuf>,
    /// The operator whose inherited decoy persona state the inherited-autostart
    /// check inspects. Resolved best-effort by [`NailsManager::preflight_registry`];
    /// `None` (the default used by unit tests that build inputs directly) makes
    /// that check report a skipped Pass instead of inspecting anything.
    pub operator: Option<crate::TargetUser>,
    /// Accept a persistent decoy posture (the `--accept-persistent-decoy` flag):
    /// the decoy-persistence check then warns instead of failing. The effective
    /// value is this flag OR the `accept_persistent_decoy` config key.
    pub accept_persistent_decoy: bool,
}

/// Assemble the pre-flight check registry for a set of [`RegistryInputs`].
///
/// This is the one place the activation set of checks is defined. The registry
/// it returns is read-only to run: every check only inspects the filesystem, so
/// the same registry backs both activation and the `nails check`/`doctor`
/// command. Staging of the hidden NixOS layout happens in the activation path
/// (see [`crate::stage_hidden_nixos_config`]) before these checks run, never
/// inside a check.
///
/// # Errors
///
/// Propagates any error from [`build_overlay_targets`] when the configuration
/// uses [`OverlayMode::Auto`](crate::config::OverlayMode::Auto); the target list
/// cannot be enumerated without it.
pub fn build_registry<F: Filesystem>(
    fs: &F,
    config: &Config,
    inputs: &RegistryInputs,
) -> Result<PreFlightRegistry<F>> {
    use crate::preflight::{
        BackendDetectCheck, BinaryLocationCheck, DecoyPersistenceCheck, HiddenVolumeCheck,
        HostToolsCheck, IncrementalHistoryFlushCheck, InheritedAutostartCheck, MountNamespaceCheck,
        NixOSBuildTargetCheck, NixOSConfigCheck, OverlayCompatibilityCheck, OverlayTargetsCheck,
        SleepPolicyCheck, SnapshotMemoryCheck, SpaceCheck, StateCheck, StorageReadinessCheck,
        SuspiciousNailsReferenceCheck, SwapCheck, SymlinkSupportCheck, UpperFsCapabilityCheck,
        WritableTreesCheck,
    };

    let mut registry = PreFlightRegistry::new();

    registry.add_check(Box::new(HiddenVolumeCheck::new(
        config.hidden_volume_root.clone(),
    )));

    // Refuses an overlay target that would hide the hidden volume, its state
    // file, its logs or the binary, and an exclusion that leaks to the decoy
    // disk, while the decoy session is still intact.
    registry.add_check(Box::new(OverlayTargetsCheck::new(config.clone())));

    // Refuses activation when a base-OS tree (e.g. /usr) would be left writable on
    // the decoy — neither overlaid nor kept read-only — while the decoy session is
    // still intact, so the read-only invariant is enforced before any mount.
    registry.add_check(Box::new(WritableTreesCheck::new(config.clone())));

    // Runs before the session kill so a private mount namespace or a non-shared
    // root is caught while the decoy session is still intact.
    registry.add_check(Box::new(MountNamespaceCheck::new()));

    // Resolves every host tool nails spawns from the detected platform's search
    // list before any state is written, so a missing tool fails early with a
    // tool-to-package table instead of a late ENOENT after the session is gone.
    registry.add_check(Box::new(HostToolsCheck::new()));

    registry.add_check(Box::new(SymlinkSupportCheck::new(
        config.hidden_volume_root.clone(),
    )));

    // Runs before the session kill so an upper filesystem that cannot back an
    // overlay (NFS/FUSE/FAT, missing xattrs/d_type/whiteouts) is refused while
    // the decoy session is still intact, not after staging has begun.
    registry.add_check(Box::new(UpperFsCapabilityCheck::new(
        config.hidden_volume_root.clone(),
    )));

    // Warns, never fails: names deniability hazards of the detected backend
    // (discard-enabled tcrypt/plain mappings, file-container timestamps,
    // containers on a copy-on-write decoy) while they can still be fixed.
    registry.add_check(Box::new(BackendDetectCheck::new(
        config.hidden_volume_root.clone(),
    )));

    let overlay_dirs: Vec<crate::preflight::OverlayDirs> = match config.overlay_mode {
        crate::config::OverlayMode::Auto => {
            let targets = build_overlay_targets(fs, config)?;
            targets
                .iter()
                .map(|target| {
                    let dir_name = target
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    let upper = config.hidden_volume_root.join(&dir_name);
                    let work = config.hidden_volume_root.join(".work").join(&dir_name);

                    crate::preflight::OverlayDirs::new(dir_name, target.clone(), upper, work)
                })
                .collect()
        }
        crate::config::OverlayMode::Explicit => config
            .overlays
            .iter()
            .map(|o| {
                crate::preflight::OverlayDirs::new(
                    o.name.clone(),
                    o.lower.clone(),
                    o.upper.clone(),
                    o.work.clone(),
                )
            })
            .collect(),
    };

    let storage_check = StorageReadinessCheck::new(config.hidden_volume_root.clone(), overlay_dirs);
    registry.add_check(Box::new(if inputs.read_only {
        storage_check.read_only()
    } else {
        storage_check
    }));

    let persistent_overlay_target_paths: Vec<std::path::PathBuf> = match config.overlay_mode {
        crate::config::OverlayMode::Auto => build_overlay_targets(fs, config)?,
        crate::config::OverlayMode::Explicit => {
            config.overlays.iter().map(|o| o.lower.clone()).collect()
        }
    };

    registry.add_check(Box::new(OverlayCompatibilityCheck::new(
        persistent_overlay_target_paths.clone(),
        config.hidden_volume_root.clone(),
    )));

    // Warn-only: estimate the RAM the snapshot tmpfs filesystems for
    // overlay-incompatible targets would consume against MemAvailable. Swap is
    // disabled during a hidden session, so a large snapshot on a low-memory host
    // can cause pressure; this surfaces that before activation without blocking.
    registry.add_check(Box::new(SnapshotMemoryCheck::new(
        persistent_overlay_target_paths,
    )));

    // Reports a base `/etc/nixos` that still references the hidden environment.
    // Activation also runs this as an early gate before any staging, so a dirty
    // base aborts before side effects; keeping it in the shared registry means
    // `nails check` reports it too, and on a non-NixOS host it simply passes.
    registry.add_check(Box::new(SuspiciousNailsReferenceCheck::new(
        config.hidden_volume_root.clone(),
    )));

    // The NixOS config and build-target checks belong to the NixOS config layer,
    // so they are registered only on a host that has one and only when a
    // declarative switch will run. On an FHS / Debian host (no config layer) or in
    // overlay-only mode they are skipped entirely, so a non-NixOS host never fails
    // pre-flight with NixOS-only remediation text.
    if !inputs.overlay_only && inputs.has_config_layer {
        registry.add_check(Box::new(NixOSConfigCheck::new(
            config.hidden_volume_root.clone(),
        )));

        if !inputs.flake_target_already_validated {
            registry.add_check(Box::new(NixOSBuildTargetCheck::with_selected_flake_dir(
                config.nixos_flake.clone(),
                inputs.selected_flake_dir.clone(),
                config.hidden_volume_root.clone(),
            )));
        }
    }

    registry.add_check(Box::new(SwapCheck));

    // Reports whether the host would suspend an active session (lid switch, idle
    // auto-suspend), which would strand the hidden environment resident in RAM
    // behind the decoy lock screen. Warn-only: the runtime sleep_policy modes
    // (block/teardown) mitigate it, and the message names the configured one. The
    // check only reads logind.conf and its drop-ins; it performs no writes.
    registry.add_check(Box::new(SleepPolicyCheck::new(config.sleep_policy.mode)));

    // Refuses a persistent decoy posture (a persistent journald journal or an
    // active rsyslog/syslog-ng/auditd, where hidden-session records logged before
    // the overlays are mounted would survive on the decoy disk) unless the
    // operator accepts the risk with --accept-persistent-decoy or the config key.
    // Lower-severity findings (root fs type, atime, crash-dump channels,
    // maintenance timers) are always warnings. The check performs no writes, and
    // its maintenance-timer sub-check applies only on a NixOS host.
    let accept_persistent_decoy = inputs.accept_persistent_decoy || config.accept_persistent_decoy;
    registry.add_check(Box::new(DecoyPersistenceCheck::new(
        accept_persistent_decoy,
        inputs.has_config_layer,
    )));

    registry.add_check(Box::new(SpaceCheck::new(
        config.hidden_volume_root.clone(),
        config.minimum_space_mb,
    )));

    // Warns when the running binary, or a PATH symlink to it, is not on the
    // hidden volume.
    registry.add_check(Box::new(BinaryLocationCheck::new(
        config.hidden_volume_root.clone(),
    )));

    // Warns (never fails) about the decoy autostart entries, enabled user
    // services, lingering and autologin the hidden session would inherit. When no
    // operator could be resolved the check degrades to a skipped Pass. Fresh-home
    // mode reports only system-level inherited state.
    let fresh_home = config.persona.mode == crate::config::PersonaMode::FreshHome;
    registry.add_check(Box::new(match inputs.operator.as_ref() {
        Some(operator) => InheritedAutostartCheck::new(
            operator.home().to_path_buf(),
            operator.name.clone(),
            fresh_home,
        ),
        None => InheritedAutostartCheck::disabled(),
    }));

    // Warns (never fails) when the operator's shell flushes command history to
    // disk after every command (zsh INC_APPEND_HISTORY/SHARE_HISTORY, bash
    // `history -a` in PROMPT_COMMAND): such a shell has already written the
    // activation commands to disk before the pre-teardown shell kill can prevent
    // it. Degrades to a skipped Pass when no operator could be resolved.
    registry.add_check(Box::new(match inputs.operator.as_ref() {
        Some(operator) => IncrementalHistoryFlushCheck::new(operator.home().to_path_buf()),
        None => IncrementalHistoryFlushCheck::disabled(),
    }));

    registry.add_check(Box::new(StateCheck::new(inputs.current_state.clone())));

    Ok(registry)
}

impl<F: Filesystem> NailsManager<F> {
    /// Run read-only NixOS preflight checks that are safe before detach/session kill.
    pub fn run_read_only_nixos_preflight(&self, overlay_only: bool) -> Result<()> {
        if overlay_only {
            return Ok(());
        }

        if let Some(builder) = self.nixos_builder.as_ref()
            && builder.is_flake()
        {
            let summary = builder
                .preflight_flake_reference_fast()
                .map_err(|err| match err {
                    NailsError::NixOSPreflightError { message, .. } => {
                        NailsError::PreFlightCheckFailed(vec![(
                            "nixos-build-target".to_string(),
                            message,
                            None,
                        )])
                    }
                    other => other,
                })?;
            tracing::info!(
                metadata_checked = summary.metadata_checked,
                attr_checked = summary.attr_checked,
                "Read-only flake preflight completed"
            );
        }

        Ok(())
    }

    /// Build the pre-flight registry for this manager's current inputs.
    ///
    /// Assembles the [`RegistryInputs`] from the manager's configuration, builder
    /// and current state, then delegates to [`build_registry`]. Activation runs
    /// the result through [`run_preflight_checks`](Self::run_preflight_checks);
    /// the `nails check` command builds the same registry and runs it read-only.
    /// Routing both through this one function is what keeps their check lists
    /// identical. Activation passes `read_only = false` so the storage check still
    /// stages the hidden layout; `nails check` passes `true` to keep the command
    /// from touching the system.
    pub fn preflight_registry(
        &self,
        overlay_only: bool,
        read_only: bool,
        accept_persistent_decoy: bool,
    ) -> Result<PreFlightRegistry<F>> {
        let flake_target_already_validated = self
            .nixos_builder
            .as_ref()
            .is_some_and(|builder| builder.is_flake());
        let selected_flake_dir = self
            .nixos_builder
            .as_ref()
            .and_then(|builder| builder.flake_dir().map(|path| path.to_path_buf()));

        let inputs = RegistryInputs {
            overlay_only,
            // The host's config layer decides whether the NixOS checks belong in
            // the registry at all; `config_layer` returns `Some` only on NixOS
            // (and assumes NixOS when no host profile has been detected, as in
            // unit tests), matching the historical behaviour.
            has_config_layer: self.config_layer().is_some(),
            read_only,
            current_state: self.current_state()?,
            flake_target_already_validated,
            selected_flake_dir,
            // Resolve the operator best-effort so the inherited-autostart check
            // can inspect the decoy state; an unresolved operator simply skips it.
            operator: crate::TargetUser::resolve().ok(),
            accept_persistent_decoy,
        };

        build_registry(&self.filesystem, &self.config, &inputs)
    }

    /// Run all pre-flight checks before activation
    ///
    /// Creates a PreFlightRegistry, registers all validation checks, and executes them.
    /// Returns comprehensive error information if any checks fail.
    ///
    /// # Pre-flight Checks Executed (Stories 3.1-3.7, 4.12, 15.2)
    ///
    /// 1. **HiddenVolumeCheck** - Validates hidden volume is mounted
    /// 2. **OverlayTargetsCheck** - Validates no target hides the hidden volume
    ///    and no exclusion leaks to the decoy disk
    /// 3. **StorageReadinessCheck** - Validates directory structure + overlay accessibility
    /// 4. **NixOSConfigCheck** - Validates NixOS config overlay structure
    /// 5. **SwapCheck** - Validates swap is disabled
    /// 6. **SpaceCheck** - Validates sufficient disk space
    /// 7. **StateCheck** - Validates current state allows activation
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All checks passed (or only warnings)
    /// * `Err(NailsError::PreFlightCheckFailed)` - One or more checks failed
    ///
    /// # Example
    ///
    /// This is a private method called automatically during activation.
    /// To run preflight checks, use `activate()`:
    ///
    /// ```rust,no_run
    /// use nails_core::{NailsManager, MockFilesystem, Config};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    /// let mut manager = NailsManager::new(fs, config, state_path);
    ///
    /// // Activate with preflight checks (no_preflight = false)
    /// let result = manager.activate(false);
    /// ```
    pub fn run_preflight_checks(
        &self,
        overlay_only: bool,
        accept_persistent_decoy: bool,
    ) -> Result<()> {
        // Activation keeps the auto-creating storage check: `read_only = false`.
        let registry = self.preflight_registry(overlay_only, false, accept_persistent_decoy)?;

        // Run all checks (always get full results for display)
        let (results, all_passed) = registry.run_all_detailed(&self.filesystem);

        // Report each check and collect failures. Progress is emitted as tracing
        // events only; the subscriber the CLI installs honours `--quiet`/`--json`
        // and chooses the stream, so the core never prints check results ad hoc
        // (and never reports the same check twice).
        let mut failed_checks: crate::error::PreFlightFailures = Vec::new();

        for (name, result) in &results {
            match result {
                crate::preflight::CheckResult::Pass(msg) => {
                    tracing::info!(check = %name, result = "pass", msg = %msg, "Preflight check passed");
                }
                crate::preflight::CheckResult::Warn(msg) => {
                    tracing::warn!(check = %name, result = "warn", msg = %msg, "Preflight check warning");
                }
                crate::preflight::CheckResult::Fail {
                    message,
                    remediation,
                } => {
                    tracing::error!(check = %name, result = "fail", msg = %message, "Preflight check failed");
                    failed_checks.push((name.clone(), message.clone(), remediation.clone()));
                }
            }
        }

        if all_passed {
            self.ensure_state_file_exists()?;
            tracing::info!("All pre-flight checks passed");
            Ok(())
        } else {
            Err(crate::NailsError::PreFlightCheckFailed(failed_checks))
        }
    }

    fn ensure_state_file_exists(&self) -> Result<()> {
        if self.state_file_path.exists() {
            if !self.state_file_path.is_file() {
                return Err(NailsError::InvalidState(format!(
                    "State path must be a file, not a directory: {}",
                    self.state_file_path.display()
                )));
            }

            return Ok(());
        }

        StateFile::default()
            .save_with_custom_root(&self.state_file_path, &self.config.hidden_volume_root)
    }
}

#[cfg(test)]
#[path = "preflight_runner_tests.rs"]
mod tests;
