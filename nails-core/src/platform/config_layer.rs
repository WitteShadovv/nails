// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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
//! layer. The layer also contributes the pre-flight checks that inspect its own
//! configuration (the base-config reference gate and the hidden-config overlay
//! check), so a host without a layer never runs them. The sole implementation today is [`NixOsConfigLayer`]; FHS /
//! `DebianFamily` hosts have no layer, so "overlay-only" becomes simply "no
//! layer" rather than a second, parallel code path.

use std::path::Path;

use super::RestoreOutcome;
use crate::filesystem::Filesystem;
use crate::manager::{ensure_run_current_system_symlink, select_system_profile};
use crate::nixos::{
    NixOSBuilder, SwitchAction, collect_config_tree, compute_config_fingerprint,
    inject_import_block, stage_hidden_config_symlink, stage_hidden_nixos_config,
};
use crate::preflight::{NixOSConfigCheck, PreFlightCheck, SuspiciousNailsReferenceCheck};
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
    /// The cached hidden-system toplevel store path to fast-path switch to, set
    /// only when the stored fingerprint still matches the current one *and* that
    /// store path still exists on disk; `None` forces a full build.
    pub fast_path_toplevel: Option<String>,
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
    /// The gate that refuses activation when the decoy's base configuration
    /// already references the hidden environment.
    ///
    /// Activation runs it before any side effect (even in overlay-only mode),
    /// and the shared pre-flight registry lists it so `nails check` reports it.
    fn base_reference_check(&self, hidden_volume_root: &Path) -> Box<dyn PreFlightCheck<F>>;

    /// The checks validating the staged hidden configuration, registered when a
    /// declarative switch will run (not in overlay-only mode).
    fn preflight_checks(&self, hidden_volume_root: &Path) -> Vec<Box<dyn PreFlightCheck<F>>>;

    /// Stage the complete hidden config (module symlink plus hardware wrapper)
    /// before the pre-flight checks run.
    fn stage(&self, fs: &F, hidden_volume_root: &Path, overlay_only: bool) -> Result<()>;

    /// Stage only the hidden config module and its symlink, the best-effort
    /// `--no-preflight` path that skips the hardware wrapper.
    fn stage_symlink(&self, fs: &F, hidden_volume_root: &Path) -> Result<()>;

    /// Inject the NAILS import block into the overlayed
    /// `/etc/nixos/hardware-configuration.nix`, after the `/etc` overlay mounts.
    fn inject_import(&self, fs: &F) -> Result<()>;

    /// Compute the config fingerprint over the whole hidden config tree and check
    /// the fast-path cache.
    ///
    /// Reads nothing but the hidden config inputs, so it is safe to run before
    /// any session kill or mount. `stored_fingerprint`/`stored_toplevel` are the
    /// values carried forward from the previous successful activation;
    /// `flake_ref`/`config_name` fold the build target into the fingerprint so a
    /// changed flake reference or attribute name also forces a rebuild.
    #[allow(clippy::too_many_arguments)]
    fn plan(
        &self,
        fs: &F,
        hidden_volume_root: &Path,
        stored_fingerprint: Option<&str>,
        stored_toplevel: Option<&str>,
        flake_ref: Option<&str>,
        config_name: Option<&str>,
        flake_source: Option<&Path>,
        verbosity: Verbosity,
    ) -> Result<ConfigPlan>;

    /// Build the hidden system toplevel and switch to it.
    ///
    /// Runs after the overlays are mounted. On the fast path (`fast_path_toplevel`
    /// is `Some` and the path still exists on the now-overlaid `/nix`) the cached
    /// toplevel is switched to directly; otherwise the toplevel is built explicitly
    /// and then switched to. The caller has already pointed `/run/current-system`
    /// at the right profile and persists the returned store path itself. Returns
    /// the toplevel store path that was switched to, or `None` for the legacy
    /// `nixos-rebuild test` path, which activates without yielding a store path.
    fn apply(
        &self,
        fs: &F,
        builder: &NixOSBuilder,
        fast_path_toplevel: Option<&str>,
        verbosity: Verbosity,
    ) -> Result<Option<String>>;

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
    fn base_reference_check(&self, hidden_volume_root: &Path) -> Box<dyn PreFlightCheck<F>> {
        Box::new(SuspiciousNailsReferenceCheck::new(
            hidden_volume_root.to_path_buf(),
        ))
    }

    fn preflight_checks(&self, hidden_volume_root: &Path) -> Vec<Box<dyn PreFlightCheck<F>>> {
        vec![Box::new(NixOSConfigCheck::new(
            hidden_volume_root.to_path_buf(),
        ))]
    }

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
        stored_toplevel: Option<&str>,
        flake_ref: Option<&str>,
        config_name: Option<&str>,
        flake_source: Option<&Path>,
        verbosity: Verbosity,
    ) -> Result<ConfigPlan> {
        if verbosity >= Verbosity::Normal {
            tracing::info!(
                "Computing NixOS config fingerprint — deferring rebuild until after overlays"
            );
        }

        // Fingerprint the inputs the build actually reads (the flake source for a
        // flake build, the staged hidden config trees for a legacy build) plus the
        // flake reference and configuration name, so any change a build depends on
        // invalidates the fast path while incidental `/etc` overlay churn does not.
        let entries =
            collect_config_tree(fs, hidden_volume_root, flake_ref, config_name, flake_source);
        let current_fp = compute_config_fingerprint(&entries);

        if verbosity >= Verbosity::Normal {
            tracing::info!(
                stored_fingerprint = %stored_fingerprint.unwrap_or("none"),
                current_fingerprint = %current_fp,
                stored_toplevel = %stored_toplevel.unwrap_or("none"),
                "Fast-path check"
            );
        }

        // Carry the cached toplevel forward as the fast-path candidate when the
        // fingerprint still matches. Whether the closure actually survived on the
        // hidden `/nix` upper is checked in `apply`, after the overlays are
        // mounted — the cached toplevel lives on that upper and is not visible on
        // the decoy `/nix` that is live here, before the mount phase.
        let mut fast_path_toplevel: Option<String> = None;
        if stored_fingerprint == Some(current_fp.as_str())
            && let Some(toplevel) = stored_toplevel
        {
            if verbosity >= Verbosity::Normal {
                tracing::info!(
                    toplevel = %toplevel,
                    "Fast path: fingerprint matches — will reuse the cached toplevel if it is still present after the overlays mount"
                );
            }
            fast_path_toplevel = Some(toplevel.to_string());
        }

        Ok(ConfigPlan {
            fast_path_toplevel,
            fingerprint: current_fp,
        })
    }

    fn apply(
        &self,
        fs: &F,
        builder: &NixOSBuilder,
        fast_path_toplevel: Option<&str>,
        verbosity: Verbosity,
    ) -> Result<Option<String>> {
        if verbosity >= Verbosity::Normal {
            tracing::info!("Switching to hidden NixOS configuration...");
        }

        let step_timer = Stopwatch::start();

        // Fast path: switch directly to the cached toplevel when it is still on
        // the now-overlaid `/nix`. The fingerprint matching does not prove the
        // closure survived the decoy's garbage collector between sessions, so the
        // path is checked here, after the overlays are mounted; if it is gone the
        // fast path is dropped and a full rebuild runs.
        if let Some(toplevel) = fast_path_toplevel {
            if fs.path_exists(Path::new(toplevel)).unwrap_or(false) {
                builder
                    .switch_to_toplevel(toplevel, SwitchAction::Test)
                    .map_err(|e| {
                        wrap_nixos_failure(e, "switching to the cached hidden toplevel")
                    })?;
                if verbosity >= Verbosity::Normal {
                    tracing::info!(
                        step = "nixos_switch",
                        duration_ms = step_timer.elapsed().as_millis() as u64,
                        toplevel = %toplevel,
                        "NixOS switch complete via fast path ({})",
                        step_timer
                    );
                }
                return Ok(Some(toplevel.to_string()));
            }
            tracing::warn!(
                toplevel = %toplevel,
                "Cached hidden toplevel is gone from /nix; forcing a full rebuild"
            );
        }

        // Full path. A flake builds the toplevel explicitly then switches to it,
        // so the built store path is cached for the next fast path. A legacy
        // config has no toplevel attribute, so it is built and activated in one
        // `nixos-rebuild test` step and yields no store path.
        if builder.is_flake() {
            let toplevel = builder
                .build_toplevel()
                .map_err(|e| wrap_nixos_failure(e, "building the hidden NixOS toplevel"))?;
            builder
                .switch_to_toplevel(&toplevel, SwitchAction::Test)
                .map_err(|e| wrap_nixos_failure(e, "switching to the hidden NixOS toplevel"))?;
            if verbosity >= Verbosity::Normal {
                tracing::info!(
                    step = "nixos_switch",
                    duration_ms = step_timer.elapsed().as_millis() as u64,
                    toplevel = %toplevel,
                    "NixOS build+switch complete ({})",
                    step_timer
                );
            }
            Ok(Some(toplevel))
        } else {
            builder
                .build_and_switch()
                .map_err(|e| wrap_nixos_failure(e, "nixos-rebuild test failed"))?;
            if verbosity >= Verbosity::Normal {
                tracing::info!(
                    step = "nixos_switch",
                    duration_ms = step_timer.elapsed().as_millis() as u64,
                    "NixOS build+switch complete ({})",
                    step_timer
                );
            }
            Ok(None)
        }
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

/// Wrap a build/switch failure with a classified, operator-facing message while
/// preserving non-NixOS errors untouched.
fn wrap_nixos_failure(e: NailsError, context: &str) -> NailsError {
    tracing::error!(
        error = %e,
        phase = "nixos_switch",
        rollback = true,
        "{context}"
    );
    match e {
        NailsError::NixOSError(message) => {
            let category = classify_nixos_failure_category(&message, "");
            NailsError::NixOSError(format!(
                "NixOS switch failed: [{}] {}",
                category,
                format_classified_nixos_failure(context, &message, "")
            ))
        }
        other => other,
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
        &mut |elapsed, last_line| {
            tracing::info!(
                "{}",
                crate::process::run::progress_line(
                    "restoring the decoy configuration",
                    elapsed,
                    last_line
                )
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

/// The NixOS layer's own steps against NixOS host fixtures. Manager tests drive
/// the layer through a `FakeConfigLayer` instead; what the real layer writes and
/// checks is pinned here.
#[cfg(test)]
mod nixos_layer_tests {
    use super::*;
    use crate::filesystem::{MockFilesystem, MockOp, PathKind};
    use std::path::PathBuf;

    const LIVE_HARDWARE: &str = "/etc/nixos/hardware-configuration.nix";

    /// The import targets the overlaid live path; the hidden underlay copy of the
    /// hardware configuration is never written.
    #[test]
    fn inject_import_targets_the_overlaid_path_not_the_underlay() {
        let fs = MockFilesystem::new();
        let clean = "{ config, lib, pkgs, ... }:\n{ }";
        fs.mock_set_path_type(LIVE_HARDWARE, PathKind::File);
        fs.mock_set_file_content(LIVE_HARDWARE, clean);
        let underlay = PathBuf::from("/mnt/hidden/etc/nixos/hardware-configuration.nix");
        fs.mock_set_path_type(underlay.to_str().unwrap(), PathKind::File);
        fs.mock_set_file_content(underlay.to_str().unwrap(), clean);

        ConfigLayer::<MockFilesystem>::inject_import(&NixOsConfigLayer, &fs).unwrap();

        let live = fs.read_file_content(Path::new(LIVE_HARDWARE)).unwrap();
        assert!(live.contains("./nails/configuration.nix"), "{live}");
        assert_eq!(fs.read_file_content(&underlay).unwrap(), clean);
        let ops = fs.mock_ops();
        assert!(ops.contains(&MockOp::WriteFile {
            path: PathBuf::from(LIVE_HARDWARE)
        }));
        assert!(!ops.contains(&MockOp::WriteFile { path: underlay }));
    }

    /// The layer's base-config gate refuses a base configuration that already
    /// references the hidden environment, and passes a clean one.
    #[test]
    fn base_reference_check_refuses_a_dirty_base() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type(LIVE_HARDWARE, PathKind::File);
        fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[Path::new(LIVE_HARDWARE)]);
        let gate = ConfigLayer::<MockFilesystem>::base_reference_check(
            &NixOsConfigLayer,
            Path::new("/mnt/hidden"),
        );
        assert_eq!(gate.name(), "suspicious-nails-reference");

        fs.mock_set_file_content(LIVE_HARDWARE, "{ config, lib, pkgs, ... }:\n{ }");
        assert!(gate.run(&fs).unwrap().is_pass());

        fs.mock_set_file_content(
            LIVE_HARDWARE,
            "{ imports = [ /mnt/hidden/nixos/configuration.nix ]; }",
        );
        assert!(gate.run(&fs).unwrap().is_fail());
    }

    #[test]
    fn preflight_checks_validate_the_staged_hidden_config() {
        let checks = ConfigLayer::<MockFilesystem>::preflight_checks(
            &NixOsConfigLayer,
            Path::new("/mnt/hidden"),
        );
        let names: Vec<_> = checks.iter().map(|check| check.name()).collect();
        assert_eq!(names, vec!["nixos-config"]);
    }
}

#[cfg(test)]
mod plan_tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use crate::nixos::{collect_config_tree, compute_config_fingerprint};

    const FLAKE_REF: &str = "/etc/nixos#host";
    const FLAKE_SOURCE: &str = "/etc/nixos";
    const TOPLEVEL: &str = "/nix/store/0000000000000000000000000000000a-nixos-system-host";

    fn current_fp(fs: &MockFilesystem, root: &Path) -> String {
        compute_config_fingerprint(&collect_config_tree(
            fs,
            root,
            Some(FLAKE_REF),
            Some("host"),
            Some(Path::new(FLAKE_SOURCE)),
        ))
    }

    fn plan_with(
        fs: &MockFilesystem,
        root: &Path,
        stored_fp: Option<&str>,
        stored_toplevel: Option<&str>,
    ) -> ConfigPlan {
        ConfigLayer::<MockFilesystem>::plan(
            &NixOsConfigLayer,
            fs,
            root,
            stored_fp,
            stored_toplevel,
            Some(FLAKE_REF),
            Some("host"),
            Some(Path::new(FLAKE_SOURCE)),
            Verbosity::Quiet,
        )
        .unwrap()
    }

    #[test]
    fn fast_path_candidate_when_fingerprint_matches() {
        // plan carries the cached toplevel forward on a fingerprint match; the
        // on-disk existence of that path is checked later in `apply`, after the
        // overlays mount.
        let fs = MockFilesystem::new();
        let root = Path::new("/mnt/hidden");
        let fp = current_fp(&fs, root);

        let plan = plan_with(&fs, root, Some(&fp), Some(TOPLEVEL));
        assert_eq!(plan.fingerprint, fp);
        assert_eq!(plan.fast_path_toplevel, Some(TOPLEVEL.to_string()));
    }

    #[test]
    fn no_fast_path_when_fingerprint_differs() {
        let fs = MockFilesystem::new();
        let root = Path::new("/mnt/hidden");

        let plan = plan_with(&fs, root, Some("ffffffffffffffff"), Some(TOPLEVEL));
        assert_eq!(plan.fast_path_toplevel, None);
    }

    #[test]
    fn no_fast_path_without_stored_toplevel() {
        let fs = MockFilesystem::new();
        let root = Path::new("/mnt/hidden");
        let fp = current_fp(&fs, root);

        let plan = plan_with(&fs, root, Some(&fp), None);
        assert_eq!(plan.fast_path_toplevel, None);
    }
}
