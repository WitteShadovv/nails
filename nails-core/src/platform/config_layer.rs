//! The declarative config layer: the NixOS-only half of activation.
//!
//! Activation has two halves. The overlay mounts are shared by every supported
//! host. The second half is a declarative *hidden configuration* that is switched
//! into place once the overlays are mounted, and it is bound entirely to NixOS
//! mechanisms — `nixos-rebuild`, `switch-to-configuration`, `/run/current-system`
//! and the `/etc/nixos` import. A Debian/Ubuntu decoy has none of these, so that
//! half cannot run there.
//!
//! [`ConfigLayer`] is the seam for the declarative half. A backend returns one
//! from [`Platform::config_layer`](super::Platform::config_layer); the manager
//! routes hidden-config staging, fingerprinting, the `/etc` import injection, the
//! build and the switch through it, and performs none of them when there is no
//! layer. The sole implementation today is [`NixOsConfigLayer`]; FHS /
//! `DebianFamily` hosts have no layer, so "overlay-only" becomes simply "no
//! layer" rather than a second, parallel code path.

use std::path::Path;

use super::RestoreOutcome;
use crate::filesystem::Filesystem;
use crate::manager::{ensure_run_current_system_symlink, select_system_profile};
use crate::nixos::{
    NixOSBuilder, SwitchAction, compute_config_fingerprint, inject_import_block,
    stage_hidden_config_symlink, stage_hidden_nixos_config,
};
use crate::process::{ProcessCommand, ProcessRunner};
use crate::{
    NailsError, Result, Stopwatch, Verbosity, classify_nixos_failure_category,
    format_classified_nixos_failure,
};

/// The fast-path plan computed from the hidden config before any overlay mounts.
///
/// Produced by [`ConfigLayer::plan`]: the manager carries it through the mount
/// phase and hands it back to [`ConfigLayer::apply`] after the overlays are in
/// place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPlan {
    /// The system generation to fast-path switch to when the stored fingerprint
    /// still matches the current one; `None` forces a full build.
    pub fast_path_generation: Option<String>,
    /// The fingerprint of the current hidden config inputs, persisted on success
    /// so the next activation can take the fast path.
    pub fingerprint: String,
}

/// The declarative, platform-specific half of activation.
///
/// Every method takes only what the manager can hand it (the filesystem, the
/// hidden-root paths, the NixOS builder and the stored cache values), so the
/// manager keeps ownership of its state cache while the layer owns the host
/// mechanism. A platform without a layer — FHS / `DebianFamily` — makes the
/// manager skip all of this, which is the whole point of the seam.
pub trait ConfigLayer<F: Filesystem>: std::fmt::Debug + Send + Sync {
    /// Stage the complete hidden config (module symlink plus hardware wrapper)
    /// before the pre-flight checks run.
    fn stage(&self, fs: &F, hidden_volume_root: &Path, overlay_only: bool) -> Result<()>;

    /// Stage only the hidden config module and its symlink, the best-effort
    /// `--no-preflight` path that skips the hardware wrapper.
    fn stage_symlink(&self, fs: &F, hidden_volume_root: &Path) -> Result<()>;

    /// Inject the NAILS import block into the overlayed
    /// `/etc/nixos/hardware-configuration.nix`, after the `/etc` overlay mounts.
    fn inject_import(&self, fs: &F) -> Result<()>;

    /// Compute the config fingerprint and check the fast-path cache.
    ///
    /// Reads nothing but the hidden config inputs, so it is safe to run before
    /// any session kill or mount. `stored_fingerprint`/`stored_generation` are
    /// the values carried forward from the previous successful activation.
    fn plan(
        &self,
        fs: &F,
        hidden_volume_root: &Path,
        stored_fingerprint: Option<&str>,
        stored_generation: Option<&str>,
        verbosity: Verbosity,
    ) -> Result<ConfigPlan>;

    /// Build the hidden configuration and switch to it.
    ///
    /// Tries the fast-path `switch-to-configuration` for `generation` first, then
    /// falls back to a full `nixos-rebuild test`. The caller has already pointed
    /// `/run/current-system` at the right profile and persists the resulting
    /// generation itself.
    fn apply(
        &self,
        builder: &NixOSBuilder,
        generation: Option<&str>,
        verbosity: Verbosity,
    ) -> Result<()>;

    /// Restore the decoy (base) configuration on deactivation.
    ///
    /// Re-points `/run/current-system` at the decoy system profile; see
    /// [`restore_decoy_system`] for the reboot semantics.
    fn restore(
        &self,
        fs: &F,
        runner: &dyn ProcessRunner,
        reboot_follows: bool,
        dispatch_reboot: &dyn Fn() -> Result<()>,
    ) -> Result<RestoreOutcome>;
}

/// The NixOS declarative config layer — the only implementation today.
///
/// Zero-sized: the manager constructs one freely whenever the detected platform
/// has a config layer.
#[derive(Debug, Clone, Copy, Default)]
pub struct NixOsConfigLayer;

impl<F: Filesystem> ConfigLayer<F> for NixOsConfigLayer {
    fn stage(&self, fs: &F, hidden_volume_root: &Path, overlay_only: bool) -> Result<()> {
        stage_hidden_nixos_config(fs, hidden_volume_root, overlay_only)
    }

    fn stage_symlink(&self, fs: &F, hidden_volume_root: &Path) -> Result<()> {
        stage_hidden_config_symlink(fs, hidden_volume_root)
    }

    fn inject_import(&self, fs: &F) -> Result<()> {
        inject_import_block(fs)
    }

    fn plan(
        &self,
        fs: &F,
        hidden_volume_root: &Path,
        stored_fingerprint: Option<&str>,
        stored_generation: Option<&str>,
        verbosity: Verbosity,
    ) -> Result<ConfigPlan> {
        if verbosity >= Verbosity::Normal {
            tracing::info!(
                "Computing NixOS config fingerprint — deferring rebuild until after overlays"
            );
        }

        // Read the config files that feed the fingerprint. hardware-configuration.nix
        // is a fixed wrapper, so the real hardware config lives in
        // hardware-configuration.base.nix; both feed the fingerprint so edits to
        // the original still trigger a rebuild.
        let hw_path = hidden_volume_root.join("etc/nixos/hardware-configuration.nix");
        let base_path = hidden_volume_root.join("etc/nixos/hardware-configuration.base.nix");
        let cfg_path = hidden_volume_root.join("config/nixos/configuration.nix");

        let wrapper_content = read_fingerprint_input(fs, &hw_path, "hardware-configuration.nix");
        let base_content =
            read_fingerprint_input(fs, &base_path, "hardware-configuration.base.nix");
        let hw_content = format!("{wrapper_content}\n{base_content}");
        let cfg_content = read_fingerprint_input(fs, &cfg_path, "configuration.nix");

        let current_fp = compute_config_fingerprint(&hw_content, &cfg_content);

        if verbosity >= Verbosity::Normal {
            tracing::info!(
                stored_fingerprint = %stored_fingerprint.unwrap_or("none"),
                current_fingerprint = %current_fp,
                stored_generation = %stored_generation.unwrap_or("none"),
                "Fast-path check"
            );
        }

        let mut fast_path_generation: Option<String> = None;
        if stored_fingerprint == Some(current_fp.as_str())
            && let Some(generation_id) = stored_generation
        {
            if verbosity >= Verbosity::Normal {
                tracing::info!(
                    generation = %generation_id,
                    "Fast path: fingerprint matches — will attempt generation switch at Step 9"
                );
            }
            fast_path_generation = Some(generation_id.to_string());
        }

        Ok(ConfigPlan {
            fast_path_generation,
            fingerprint: current_fp,
        })
    }

    fn apply(
        &self,
        builder: &NixOSBuilder,
        generation: Option<&str>,
        verbosity: Verbosity,
    ) -> Result<()> {
        if verbosity >= Verbosity::Normal {
            tracing::info!("Switching to hidden NixOS configuration...");
        }

        let step_timer = Stopwatch::start();

        // Fast path: try switching to the cached generation directly. Both flake
        // and legacy slow-paths use `nixos-rebuild test`, which writes to the
        // system profile, so a cached generation ID is always a system generation
        // number.
        let mut switched = false;
        if let Some(generation_id) = generation {
            if verbosity >= Verbosity::Normal {
                tracing::info!(
                    generation = %generation_id,
                    "Attempting fast-path switch-to-configuration"
                );
            }

            match builder.switch_system_generation(generation_id, SwitchAction::Test) {
                Ok(()) => {
                    switched = true;
                    if verbosity >= Verbosity::Normal {
                        tracing::info!(
                            step = "nixos_switch",
                            duration_ms = step_timer.elapsed().as_millis() as u64,
                            "NixOS switch complete via fast path ({})",
                            step_timer
                        );
                    }
                }
                Err(e) => {
                    if verbosity >= Verbosity::Normal {
                        tracing::warn!(
                            error = %e,
                            "Fast-path switch failed, falling back to nixos-rebuild"
                        );
                    }
                }
            }
        }

        // Slow path: nixos-rebuild test (build + switch).
        if !switched {
            builder.build_and_switch().map_err(|e| {
                let error_msg = match &e {
                    NailsError::NixOSError(message) => {
                        let category = classify_nixos_failure_category(message, "");
                        format!(
                            "NixOS build+switch failed: [{}] {}",
                            category,
                            format_classified_nixos_failure(
                                "nixos-rebuild test failed",
                                message,
                                ""
                            )
                        )
                    }
                    other => format!("NixOS build+switch failed: {}", other),
                };

                tracing::error!(
                    error = %e,
                    phase = "nixos_switch",
                    rollback = true,
                    "NixOS build+switch failed"
                );

                match e {
                    NailsError::NixOSError(_) => NailsError::NixOSError(error_msg),
                    other => other,
                }
            })?;

            if verbosity >= Verbosity::Normal {
                tracing::info!(
                    step = "nixos_switch",
                    duration_ms = step_timer.elapsed().as_millis() as u64,
                    "NixOS build+switch complete ({})",
                    step_timer
                );
            }
        }

        Ok(())
    }

    fn restore(
        &self,
        fs: &F,
        runner: &dyn ProcessRunner,
        reboot_follows: bool,
        dispatch_reboot: &dyn Fn() -> Result<()>,
    ) -> Result<RestoreOutcome> {
        restore_decoy_system(fs, runner, reboot_follows, dispatch_reboot)
    }
}

/// Read one fingerprint input file, logging and substituting empty content when
/// it is missing or unreadable (the build step fails later with a clear error if
/// the config is genuinely required).
fn read_fingerprint_input<F: Filesystem>(fs: &F, path: &Path, label: &str) -> String {
    match fs.read_file_content(path) {
        Ok(content) => content,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "Failed to read {label} for fingerprint, using empty content"
            );
            String::new()
        }
    }
}

/// Return the host to the decoy generation on deactivation.
///
/// The live `/run/current-system` symlink is always re-pointed at the decoy
/// system profile. What happens next depends on the reboot:
///
/// - With no reboot (emergency teardown), the symlink restore is all that is
///   done.
/// - With a reboot that is dispatched successfully, nothing else runs: the reboot
///   boots the decoy from the bootloader default.
/// - Only when the reboot *fails* is the decoy activated for the running session,
///   with `switch-to-configuration test`.
///
/// `switch-to-configuration` is never run with `switch`/`boot` here — only
/// `test`, which the [`SwitchAction`] type is the sole way to express. A real
/// switch would reinstall the bootloader and write the ESP and EFI NVRAM, leaving
/// evidence that the hidden mode existed; using `test` keeps the threat model
/// intact.
pub(crate) fn restore_decoy_system<F: Filesystem>(
    fs: &F,
    runner: &dyn ProcessRunner,
    reboot_follows: bool,
    dispatch_reboot: &dyn Fn() -> Result<()>,
) -> Result<RestoreOutcome> {
    let system_profile = select_system_profile(fs)?.ok_or_else(|| {
        NailsError::NixOSError("No system profile available for decoy restore".into())
    })?;

    tracing::info!("Restoring /run/current-system to the decoy profile...");
    ensure_run_current_system_symlink(fs, &system_profile).map_err(|e| {
        NailsError::NixOSError(format!(
            "Failed to restore /run/current-system to the decoy profile: {e}"
        ))
    })?;

    if !reboot_follows {
        return Ok(RestoreOutcome::SymlinkRestored);
    }

    match dispatch_reboot() {
        Ok(()) => Ok(RestoreOutcome::SymlinkRestored),
        Err(reboot_error) => {
            tracing::warn!(
                error = %reboot_error,
                "Reboot command failed; restoring the decoy for the running session with switch-to-configuration test"
            );
            switch_to_decoy_for_session(fs, runner, &system_profile)?;
            Ok(RestoreOutcome::FellBackToSessionSwitch)
        }
    }
}

/// Run the decoy generation's `switch-to-configuration test` through the shared
/// process runner (reboot fallback only).
fn switch_to_decoy_for_session<F: Filesystem>(
    fs: &F,
    runner: &dyn ProcessRunner,
    system_profile: &Path,
) -> Result<()> {
    let switch_script = system_profile.join("bin/switch-to-configuration");
    if !fs.path_exists(&switch_script)? {
        return Err(NailsError::NixOSError(format!(
            "System profile switch script missing: {}",
            switch_script.display()
        )));
    }

    // No deadline and a progress heartbeat: a `switch-to-configuration` must run
    // to completion, never be killed part-way.
    let command = ProcessCommand::exact(&switch_script).arg(SwitchAction::Test.as_arg());
    let (succeeded, _stdout, stderr) = runner.run_streaming_text(
        &command,
        crate::process::run::BUILD_PROGRESS_INTERVAL,
        &mut |elapsed| {
            tracing::info!(
                "still restoring the decoy configuration, {}",
                crate::process::run::format_elapsed(elapsed)
            );
        },
    )?;
    if succeeded {
        Ok(())
    } else {
        Err(NailsError::NixOSError(format!(
            "Decoy session switch failed: {stderr}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::{MockFilesystem, PathKind};
    use crate::process::run::MockProcessRunner;
    use crate::test_support::EnvGuard;

    const PROFILE: &str = "/nix/var/nix/profiles/system";
    const SWITCH_SCRIPT: &str = "/nix/var/nix/profiles/system/bin/switch-to-configuration";

    /// A mock host whose decoy system profile (and its switch script) exist.
    fn host() -> MockFilesystem {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type(PROFILE, PathKind::Dir);
        fs.mock_set_path_type(SWITCH_SCRIPT, PathKind::File);
        fs
    }

    /// The config layer's `restore` only re-points `/run/current-system` when no
    /// reboot follows: no `switch-to-configuration` runs (that would rewrite the
    /// ESP and leave evidence the hidden mode existed).
    #[test]
    fn restore_without_reboot_runs_no_switch() {
        // `restore_decoy_system` resolves the profile through
        // `NAILS_SYSTEM_PROFILE_PATH`; hold the env lock with it cleared.
        let _env = EnvGuard::lock();
        let fs = host();
        let runner = MockProcessRunner::new();
        let layer = NixOsConfigLayer;

        let outcome =
            ConfigLayer::<MockFilesystem>::restore(&layer, &fs, &runner, false, &|| Ok(()))
                .unwrap();

        assert_eq!(outcome, RestoreOutcome::SymlinkRestored);
        assert!(
            runner.calls().is_empty(),
            "a restore with no reboot must not invoke switch-to-configuration"
        );
    }

    /// When a reboot is requested but fails, the layer falls back to activating the
    /// decoy for the running session with `switch-to-configuration test`.
    #[test]
    fn restore_falls_back_to_session_switch_on_failed_reboot() {
        let _env = EnvGuard::lock();
        let fs = host();
        let runner = MockProcessRunner::new();
        let layer = NixOsConfigLayer;

        let outcome = ConfigLayer::<MockFilesystem>::restore(&layer, &fs, &runner, true, &|| {
            Err(NailsError::NixOSError("reboot unavailable".into()))
        })
        .unwrap();

        assert_eq!(outcome, RestoreOutcome::FellBackToSessionSwitch);
        let commands: Vec<String> = runner.calls().iter().map(|c| format!("{c}")).collect();
        assert_eq!(
            commands.len(),
            1,
            "exactly one fallback command: {commands:?}"
        );
        assert!(
            commands[0].contains("switch-to-configuration") && commands[0].ends_with(" test"),
            "{commands:?}"
        );
    }
}
