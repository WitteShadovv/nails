// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Preflight Check Runner for NailsManager
//!
//! Extracted from state_management.rs to keep modules under 500 lines.
//! Contains the `run_preflight_checks` method that registers and runs
//! all pre-flight validation checks before activation.

use super::NailsManager;
use crate::preflight::PreFlightRegistry;
use crate::{Config, Filesystem, NailsError, Result, StateFile, SystemState};
use std::path::PathBuf;

/// What the caller asks of a pre-flight run: the choices that shape the
/// registry, as `nails check` and activation take them from their flags.
///
/// Both pass one value of this type to [`NailsManager::preflight_registry`],
/// so the same choices always give the same checks, and an input added later
/// is a field here rather than another positional argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightOptions {
    /// Skip the config-layer and build-target checks (overlay-only activation).
    pub overlay_only: bool,
    /// Assemble a registry that only inspects the system: no check creates a
    /// directory or changes permissions. On by default, and both `nails check`
    /// and activation keep it on: a refused activation leaves nothing on the
    /// hidden volume, and the entry creates the layout itself once every check
    /// passed. Activation's [`NailsManager::run_preflight_checks`] turns it on
    /// whatever it is given.
    pub read_only: bool,
    /// Allow a persistent decoy posture (the `--allow-persistent-decoy` flag):
    /// the decoy-persistence check then warns instead of failing. Per run only;
    /// there is no stored equivalent.
    pub allow_persistent_decoy: bool,
    /// Accept a hidden root on storage the attach gate takes for the decoy's
    /// (the `--allow-decoy-storage` flag): the hidden-volume check warns
    /// instead of failing. It never covers a folder, a covered root, storage
    /// that cannot be judged, or `backend-entries`.
    pub allow_decoy_storage: bool,
    /// Accept discards over the hidden volume for this run (the buried
    /// `--allow-discards` expert flag): the backend-detect check then warns
    /// instead of failing closed. Per run only; there is no stored equivalent.
    /// Distinct from cryptsetup's open-time `--allow-discards`, which is what
    /// turns discards on in the first place.
    pub allow_discards: bool,
}

impl Default for PreflightOptions {
    /// No flag given: the full registry, read-only.
    fn default() -> Self {
        Self {
            overlay_only: false,
            read_only: true,
            allow_persistent_decoy: false,
            allow_decoy_storage: false,
            allow_discards: false,
        }
    }
}

/// The runtime facts the shared pre-flight registry is assembled from.
///
/// Both activation (through [`NailsManager::preflight_registry`]) and the
/// read-only `nails check` command build their registry from a value of this
/// type, so the two can never drift: the set of checks is a pure function of
/// these inputs and the configuration.
#[derive(Debug, Clone)]
pub struct RegistryInputs {
    /// The caller's choices.
    pub options: PreflightOptions,
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
    /// The build target the host's platform discovered (see
    /// [`NailsManager::discover_host_target`]), reported by the build-target
    /// check when neither an explicit flake nor a selected flake directory
    /// applies. Unit tests that build inputs directly pin it.
    pub discovered_target: crate::platform::HostTarget,
    /// The operator whose inherited decoy persona state the inherited-autostart
    /// check inspects. Resolved best-effort by [`NailsManager::preflight_registry`];
    /// `None` (the default used by unit tests that build inputs directly) makes
    /// that check report a skipped Pass instead of inspecting anything.
    pub operator: Option<crate::TargetUser>,
    /// The caller's `PATH` from the startup snapshot, whose directories the
    /// binary-location check probes for decoy symlinks. `None` (the default
    /// used by unit tests that build inputs directly) probes nothing.
    pub caller_path: Option<std::ffi::OsString>,
    /// The host detection found (see [`NailsManager::host_profile`]), which the
    /// platform check reports. `None` (no detection ran or it failed, and the
    /// default used by unit tests that build inputs directly) leaves that check
    /// out, as activation then refuses no host either.
    pub host_profile: Option<crate::platform::HostProfile>,
}

/// Assemble the pre-flight check registry for a set of [`RegistryInputs`].
///
/// `config_layer` is the host's declarative config layer (see
/// [`Platform::config_layer`](crate::platform::Platform::config_layer)). It
/// contributes its own checks — the base-config reference gate, and, unless
/// overlay-only, the hidden-config checks plus the build-target check — so a host
/// without a layer (FHS / Debian) never runs config checks that would fail with
/// NixOS-specific guidance.
///
/// This is the one place the activation set of checks is defined. The registry
/// it returns is read-only to run: every check only inspects the filesystem, so
/// the same registry backs both activation and the `nails check`
/// command. Staging of the hidden NixOS layout happens in the activation path
/// (see [`crate::stage_hidden_nixos_config`]) before these checks run, never
/// inside a check.
///
/// # Errors
///
/// None today; the `Result` keeps the signature stable for checks that need
/// fallible setup.
pub fn build_registry<F: Filesystem>(
    fs: &F,
    config: &Config,
    inputs: &RegistryInputs,
    config_layer: Option<&dyn crate::platform::ConfigLayer<F>>,
) -> Result<PreFlightRegistry<F>> {
    use crate::preflight::{
        BackendDetectCheck, BackendEntriesCheck, BinaryLocationCheck, DecoyPersistenceCheck,
        DmaProtectionCheck, HiddenVolumeCheck, HostToolsCheck, IncrementalHistoryFlushCheck,
        InheritedAutostartCheck, MemoryWipeCheck, MountNamespaceCheck, NixOSBuildTargetCheck,
        OfflineUpdateCheck, PlatformCheck, ResidueCatalogCheck, SleepPolicyCheck, SpaceCheck,
        StateCheck, StorageReadinessCheck, SwapCheck, SymlinkSupportCheck, UpperFsCapabilityCheck,
    };
    use crate::session::checks::{
        DecoyRootCheck, FstabPolicyCheck, SessionStateCheck, SoftRebootUnitsCheck,
        SystemdVersionCheck,
    };

    let _ = fs;
    let mut registry = PreFlightRegistry::new();
    let hidden_root = config.hidden_volume_root.clone();
    let paths = crate::session::Paths::system();

    registry.add_check(Box::new(
        HiddenVolumeCheck::new(hidden_root.clone()).allowing(
            if inputs.options.allow_decoy_storage {
                crate::hidden_root::Allow::DecoyStorage
            } else {
                crate::hidden_root::Allow::Nothing
            },
        ),
    ));

    // No decoy fstab or crypttab entry opens or mounts the hidden volume: such
    // an entry is an enabler stored on the decoy. --allow-decoy-storage never
    // covers it.
    registry.add_check(Box::new(BackendEntriesCheck::new(hidden_root.clone())));

    // Neither already in the hidden root nor with the leftovers of an
    // interrupted entry (a populated /run/nextroot must never be entered by a
    // later plain reboot).
    registry.add_check(Box::new(SessionStateCheck::new(
        paths.clone(),
        hidden_root.clone(),
    )));

    // The detected host: a supported platform passes with its name, a release
    // NAILS has not been tested on warns, and a host activation refuses fails
    // with the same reason.
    if let Some(profile) = &inputs.host_profile {
        registry.add_check(Box::new(PlatformCheck::new(profile.clone())));
    }

    // The hidden root is entered with `systemctl soft-reboot` (systemd 254),
    // through the two units that implement it. A systemd too old is told how
    // the detected host's distribution upgrades.
    registry.add_check(Box::new(SystemdVersionCheck::new(
        inputs.host_profile.clone(),
    )));
    registry.add_check(Box::new(SoftRebootUnitsCheck::new(
        paths.root.clone(),
        config_layer.is_some(),
    )));

    // The way back mounts the decoy root again by device.
    registry.add_check(Box::new(DecoyRootCheck::new(paths.root.clone())));

    // Every decoy filesystem the hidden systemd would mount has a safe decision:
    // read-only, overlaid, or masked.
    registry.add_check(Box::new(FstabPolicyCheck::new(
        paths.root.clone(),
        hidden_root.clone(),
    )));

    // PID 1 must see /run/nextroot: activation must run in its mount namespace.
    registry.add_check(Box::new(MountNamespaceCheck::new()));

    // Resolves every host tool nails spawns from the detected platform's search
    // list before anything is built: the way back's `ip` among them, and its
    // `dmsetup` when the hidden volume is (or may be) on device-mapper.
    registry.add_check(Box::new(HostToolsCheck::new(hidden_root.clone())));

    registry.add_check(Box::new(SymlinkSupportCheck::new(hidden_root.clone())));

    // The hidden filesystem must host the root overlay's upper.
    registry.add_check(Box::new(UpperFsCapabilityCheck::new(hidden_root.clone())));

    // Refuses discards reaching the hidden volume (fail-closed); the other
    // deniability hazards of the detected backend only warn. The operator can
    // accept the discard risk for this run with the buried `--allow-discards`
    // flag, which turns that one refusal into a warning.
    registry.add_check(Box::new(
        BackendDetectCheck::new(hidden_root.clone())
            .allowing_discards(inputs.options.allow_discards),
    ));

    // Check-time advice, keyed on the installed cryptsetup version: it cannot
    // open a VeraCrypt volume made with Argon2id, so one must use PBKDF2.
    registry.add_check(Box::new(crate::preflight::CryptsetupArgon2idCheck));

    let layout = crate::session::Layout::new(&hidden_root);
    let storage_check = StorageReadinessCheck::new(
        hidden_root.clone(),
        vec![crate::preflight::OverlayDirs::new(
            "root".to_string(),
            PathBuf::from("/"),
            layout.upper(),
            layout.work(),
        )],
    );
    registry.add_check(Box::new(if inputs.options.read_only {
        storage_check.read_only()
    } else {
        storage_check
    }));

    // The config layer's base-config reference gate (on NixOS: a decoy
    // `/etc/nixos` that names the hidden environment). It runs in every mode,
    // overlay-only included, and refuses before the next root is prepared;
    // the shared registry means `nails check` reports it too.
    if let Some(layer) = config_layer {
        registry.add_check(layer.base_reference_check(&config.hidden_volume_root));
    }

    // The config-layer checks and the build-target check are registered only on
    // a host that has a layer and only when a declarative switch will run. On an
    // FHS / Debian host (no config layer) or in overlay-only mode they are
    // skipped entirely, so a non-NixOS host never fails pre-flight with
    // NixOS-only remediation text.
    if let Some(layer) = config_layer.filter(|_| !inputs.options.overlay_only) {
        for check in layer.preflight_checks(&config.hidden_volume_root) {
            registry.add_check(check);
        }

        if !inputs.flake_target_already_validated {
            registry.add_check(Box::new(NixOSBuildTargetCheck::with_selected_flake_dir(
                config.nixos_flake.clone(),
                inputs.selected_flake_dir.clone(),
                inputs.discovered_target.clone(),
            )));
        }
    }

    registry.add_check(Box::new(SwapCheck));

    // Reports whether the decoy kernel zeroes freed pages, read from the command
    // line and, when it is silent, the booted kernel's config
    // (CONFIG_INIT_ON_FREE_DEFAULT_ON). Warns when freed memory is not zeroed and
    // stays an informational pass only when neither source is readable; it also
    // notes a RAM-wipe-on-shutdown mechanism. Read-only.
    registry.add_check(Box::new(MemoryWipeCheck::new()));

    // Warns (never fails) when the host lacks DMA protection against a live /
    // evil-maid memory attacker: the IOMMU is not remapping DMA (read from the
    // command line and the /sys ground truth), or a Thunderbolt/USB4 controller
    // reports iommu_dma_protection=0, so a device can read RAM over the bus. The
    // fix rides in the warning: NAILS cannot change it (firmware/BIOS/NVRAM, the
    // same MOR-bit boundary), so power off before the machine leaves the
    // operator's control. It also reports the kernel lockdown state. Read-only.
    registry.add_check(Box::new(DmaProtectionCheck::new()));

    // Reports whether the host would suspend an active session (lid switch, idle
    // auto-suspend), which would strand the hidden environment resident in RAM
    // behind the hidden session's lock screen (the decoy is not running). Warn-only: the runtime sleep_policy modes
    // (block/teardown) mitigate it, and the message names the configured one. The
    // check only reads logind.conf and its drop-ins; it performs no writes.
    registry.add_check(Box::new(SleepPolicyCheck::new(config.sleep_policy.mode)));

    // Refuses a persistent decoy posture (a persistent journald journal or an
    // active rsyslog/syslog-ng/auditd, where hidden-session records logged before
    // the overlays are mounted would survive on the decoy disk) unless the
    // operator allows the risk for this run with --allow-persistent-decoy.
    // Lower-severity findings (atime, crash-dump channels, sudo logging,
    // maintenance timers) are always warnings. The check performs no writes, and
    // its maintenance-timer sub-check applies only on a NixOS host.
    registry.add_check(Box::new(DecoyPersistenceCheck::new(
        inputs.options.allow_persistent_decoy,
        config_layer.is_some(),
    )));

    // Refuses a decoy with a pending offline (offline-update) system update
    // staged: once the overlays are mounted the decoy's updater would apply it
    // inside the hidden session and reboot into it. Read-only. The `discard`
    // it names for a marker in the upper takes --allow-decoy-storage when the
    // run does.
    registry.add_check(Box::new(
        OfflineUpdateCheck::new(paths.root.clone(), layout.upper())
            .allowing_decoy_storage(inputs.options.allow_decoy_storage),
    ));

    // Warns (never fails) about the residue channels the catalog probes by path
    // (LVM metadata archives, udisks2 state, session-time stamps): each finding
    // names the catalog row, its mitigation and its doc section. Read-only.
    registry.add_check(Box::new(ResidueCatalogCheck::new()));

    registry.add_check(Box::new(SpaceCheck::new(
        config.hidden_volume_root.clone(),
        config.minimum_space_mb,
    )));

    // Warns when the running binary, or a PATH symlink to it, is not on the
    // hidden volume.
    registry.add_check(Box::new(
        BinaryLocationCheck::new(config.hidden_volume_root.clone())
            .with_caller_path(inputs.caller_path.as_deref()),
    ));

    // Warns (never fails) about the inherited decoy autostart entries, enabled
    // user services, lingering and autologin that need review: not the desktop's
    // or distribution's own components, and not what [persona] mask_inherited
    // masks. When no operator could be resolved the check degrades to a skipped
    // Pass. Fresh-home mode reports only system-level inherited state.
    registry.add_check(Box::new(match inputs.operator.as_ref() {
        Some(operator) => InheritedAutostartCheck::new(
            operator.home().to_path_buf(),
            operator.name.clone(),
            config.persona.clone(),
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

/// The typed event outcome of a check result, for the progress event stream.
fn check_outcome(result: &crate::preflight::CheckResult) -> nails_api::CheckOutcome {
    use crate::preflight::CheckResult;
    use nails_api::CheckOutcome;
    match result {
        CheckResult::Pass(_) => CheckOutcome::Pass,
        CheckResult::Warn(_) => CheckOutcome::Warn,
        CheckResult::Fail { .. } => CheckOutcome::Fail,
        CheckResult::Skipped(_) => CheckOutcome::Skipped,
    }
}

impl<F: Filesystem> NailsManager<F> {
    /// Build the pre-flight registry for this manager's current inputs.
    ///
    /// Assembles the [`RegistryInputs`] from `options` and the manager's
    /// configuration, builder and current state, then delegates to
    /// [`build_registry`]. Activation runs the result through
    /// [`run_preflight_checks`](Self::run_preflight_checks); the `nails check`
    /// command builds the same registry and runs it itself. Routing both through
    /// this one function, with the options their flags give, is what keeps
    /// their check lists identical.
    pub fn preflight_registry(&self, options: &PreflightOptions) -> Result<PreFlightRegistry<F>> {
        // The build-target check only reads the flake layout; nothing validates
        // a flake out of band any more.
        let flake_target_already_validated = false;
        let selected_flake_dir = self
            .nixos_builder
            .as_ref()
            .and_then(|builder| builder.flake_dir().map(|path| path.to_path_buf()));

        let inputs = RegistryInputs {
            options: options.clone(),
            current_state: self.current_state()?,
            flake_target_already_validated,
            selected_flake_dir,
            // The same platform-driven discovery activation used to pick the
            // builder, so the build-target check reports that very target.
            discovered_target: self.discover_host_target(options.overlay_only)?,
            // Resolve the operator best-effort so the inherited-autostart check
            // can inspect the decoy state; an unresolved operator simply skips it.
            operator: crate::TargetUser::resolve_with(self.runtime_env()).ok(),
            caller_path: self.runtime_env().path.clone(),
            host_profile: self.host_profile().cloned(),
        };

        // The host's config layer contributes its own checks; it is `Some` only
        // on NixOS (and when no host profile has been detected), matching the
        // historical behaviour.
        let layer = self.config_layer();
        build_registry(&self.filesystem, &self.config, &inputs, layer.as_deref())
    }

    /// Run every pre-flight check of the registry `options` give, logging each
    /// result, and refuse with [`NailsError::PreFlightCheckFailed`] when any
    /// fails. Creates an empty state file when all pass.
    ///
    /// Activation passes [`EnterOptions::preflight`](super::EnterOptions::preflight).
    /// The registry is read-only whatever `options.read_only` says: a refused
    /// activation must leave nothing on the hidden volume, and the entry
    /// creates the root overlay's directories itself once every check passed.
    pub fn run_preflight_checks(&self, options: &PreflightOptions) -> Result<()> {
        let registry = self.preflight_registry(&PreflightOptions {
            read_only: true,
            ..options.clone()
        })?;

        // Run all checks (always get full results for display). A caller
        // watching the typed event stream sees each check the moment it ends,
        // in execution order; with no event reporter installed this is a no-op
        // and the tracing lines below are the only record.
        let (results, all_passed) =
            registry.run_all_detailed_with(&self.filesystem, |name, result| {
                crate::reporter::progress::check(name, check_outcome(result), result.message());
            });

        // Report each check and collect failures, as tracing events only: the
        // core never prints check results itself. A warning is the one result
        // the operator sees on the console, as `<check>: <message>` like a row
        // of `nails check`. Passes and skips are routine, and a failure comes
        // back in the error, which the caller prints as one formatted list, so
        // those go to the log at debug level and no check is reported twice.
        let mut failed_checks: crate::error::PreFlightFailures = Vec::new();

        for (name, result) in &results {
            match result {
                crate::preflight::CheckResult::Pass(msg) => {
                    tracing::debug!(check = %name, result = "pass", msg = %msg, "Preflight check passed");
                }
                crate::preflight::CheckResult::Warn(msg) => {
                    tracing::warn!("{name}: {msg}");
                }
                crate::preflight::CheckResult::Fail {
                    message,
                    remediation,
                } => {
                    tracing::debug!(check = %name, result = "fail", msg = %message, "Preflight check failed");
                    failed_checks.push((name.clone(), message.clone(), remediation.clone()));
                }
                crate::preflight::CheckResult::Skipped(reason) => {
                    // Not a failure: a prerequisite (the hidden volume) was absent,
                    // so this check never ran and contributes no remediation.
                    tracing::debug!(check = %name, result = "skipped", msg = %reason, "Preflight check skipped");
                }
            }
        }

        if all_passed {
            self.ensure_state_file_exists()?;
            tracing::debug!("All pre-flight checks passed");
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
