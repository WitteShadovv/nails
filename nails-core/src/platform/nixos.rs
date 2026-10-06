// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The NixOS backend: the project's first-class platform.
//!
//! It carries the behaviour that used to live inline in the manager and the
//! deactivation path: the base-system restore step and the one NixOS
//! build-target discovery cascade ([`discover_nixos_target`]).

use std::path::{Path, PathBuf};

use super::config_layer::restore_decoy_system;
use super::{
    ArtifactScanner, ConfigLayer, HostTarget, NixOsConfigLayer, NixOsStateNoteScanner,
    OverlayPolicy, Platform, PlatformKind, RestoreOutcome,
};
use crate::Result;
use crate::filesystem::Filesystem;
use crate::process::ProcessRunner;

/// Legacy NixOS configuration, probed when no flake is found.
const LEGACY_CONFIG: &str = "/etc/nixos/configuration.nix";
/// System-wide flake location.
const ETC_FLAKE_DIR: &str = "/etc/nixos";
/// Newest-generation system profile; its mere presence means the host is NixOS.
const SYSTEM_PROFILE: &str = "/nix/var/nix/profiles/system";

/// The NixOS system profile's binary directory.
///
/// The one place this store path is written as a literal; every other site that
/// needs it (the process runner's search list, the runtime-command cache) refers
/// to this constant.
pub(crate) const NIXOS_SYSTEM_PROFILE_BIN: &str = "/run/current-system/sw/bin";

/// Directories NixOS exposes host tools under.
pub(crate) const NIXOS_COMMAND_DIRS: &[&str] = &[NIXOS_SYSTEM_PROFILE_BIN, "/run/wrappers/bin"];

/// The NixOS build-target discovery cascade: the single implementation.
///
/// Run when no explicit flake is configured. In order:
///
/// 1. a `flake.nix` in `<hidden_volume_root>/nixos`.
/// 2. a `flake.nix` in `/etc/nixos`.
/// 3. a legacy `/etc/nixos/configuration.nix`, or a present system profile.
/// 4. otherwise [`HostTarget::None`].
///
/// Every probe goes through the [`Filesystem`] trait so the result is
/// deterministic under test. Callers reach this through
/// [`Platform::discover_build_target`] (see
/// [`discover_host_target`](super::discover_host_target)) rather than directly,
/// so a non-NixOS host never runs it.
pub(crate) fn discover_nixos_target<F: Filesystem>(
    fs: &F,
    hidden_volume_root: &Path,
) -> Result<HostTarget> {
    let hidden_flake_dir = hidden_volume_root.join("nixos");
    if fs.path_exists(&hidden_flake_dir.join("flake.nix"))? {
        return Ok(HostTarget::Flake(hidden_flake_dir));
    }

    let etc_flake_dir = PathBuf::from(ETC_FLAKE_DIR);
    if fs.path_exists(&etc_flake_dir.join("flake.nix"))? {
        return Ok(HostTarget::Flake(etc_flake_dir));
    }

    let legacy_config = PathBuf::from(LEGACY_CONFIG);
    if fs.path_exists(&legacy_config)? || fs.path_exists(Path::new(SYSTEM_PROFILE))? {
        return Ok(HostTarget::Legacy(legacy_config));
    }

    Ok(HostTarget::None)
}

/// First-class NixOS backend.
#[derive(Debug, Clone, Copy, Default)]
pub struct NixOsPlatform;

impl<F: Filesystem> Platform<F> for NixOsPlatform {
    fn kind(&self) -> PlatformKind {
        PlatformKind::NixOs
    }

    fn overlay_policy(&self) -> OverlayPolicy {
        OverlayPolicy::nixos()
    }

    fn host_command_dirs(&self) -> &'static [&'static str] {
        NIXOS_COMMAND_DIRS
    }

    fn config_layer(&self) -> Option<Box<dyn ConfigLayer<F>>>
    where
        F: 'static,
    {
        Some(Box::new(NixOsConfigLayer))
    }

    fn discover_build_target(&self, fs: &F, hidden_volume_root: &Path) -> Result<HostTarget> {
        discover_nixos_target(fs, hidden_volume_root)
    }

    fn artifact_scanners(&self) -> Vec<Box<dyn ArtifactScanner<F>>>
    where
        F: 'static,
    {
        // NixOS has no package-database baseline to diff; it only records that
        // the expected /var/lib/nixos drift is deliberately not treated as a leak.
        vec![Box::new(NixOsStateNoteScanner)]
    }

    /// Return the host to the decoy generation on deactivation.
    ///
    /// The live `/run/current-system` symlink is always re-pointed at the decoy
    /// system profile. What happens next depends on the reboot:
    ///
    /// - With no reboot (emergency teardown), the symlink restore is all that is
    ///   done — exactly the current behaviour.
    /// - With a reboot that is dispatched successfully, nothing else runs: the
    ///   reboot boots the decoy from the bootloader default.
    /// - Only when the reboot *fails* is the decoy activated for the running
    ///   session, with `switch-to-configuration test`.
    ///
    /// `switch-to-configuration` is never run with `switch`/`boot` here — only
    /// `test`, which the [`SwitchAction`] type is the sole way to express. A real
    /// switch would reinstall the bootloader and write the ESP and EFI NVRAM,
    /// leaving evidence that the hidden mode existed. (The T-065 note that named
    /// `switch` predates that hardening; using `test` keeps the threat model
    /// intact.)
    fn restore_base_system(
        &self,
        fs: &F,
        runner: &dyn ProcessRunner,
        reboot_follows: bool,
        dispatch_reboot: &dyn Fn() -> Result<()>,
        env: &crate::RuntimeEnv,
    ) -> Result<RestoreOutcome> {
        // The decoy restore is the config layer's `restore`; the platform and the
        // layer share one implementation so they can never diverge.
        restore_decoy_system(fs, runner, reboot_follows, dispatch_reboot, env)
    }
}

/// Shared NixOS host fixtures for the platform module's own tests.
#[cfg(test)]
pub(super) mod tests_support {
    use crate::filesystem::{MockFilesystem, PathKind};

    /// A mock host where every discovery location is present: the hidden-volume
    /// flake (under `/mnt/hidden`), the `/etc/nixos` flake, the legacy
    /// configuration and the system profile.
    pub(in crate::platform) fn full_nixos_host() -> MockFilesystem {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/mnt/hidden/nixos/flake.nix", PathKind::File);
        fs.mock_set_path_type("/etc/nixos/flake.nix", PathKind::File);
        fs.mock_set_path_type("/etc/nixos/configuration.nix", PathKind::File);
        fs.mock_set_path_type("/nix/var/nix/profiles/system", PathKind::Dir);
        fs
    }
}

/// The discovery cascade, exercised against NixOS host fixtures. These are the
/// only `/etc/nixos` discovery fixtures: callers (manager, pre-flight, CLI) pin
/// the target with a `FakePlatform` instead.
#[cfg(test)]
mod discovery_tests {
    use super::*;
    use crate::filesystem::{MockFilesystem, PathKind};

    const HIDDEN_ROOT: &str = "/mnt/hidden";

    fn discover(fs: &MockFilesystem) -> HostTarget {
        Platform::discover_build_target(&NixOsPlatform, fs, Path::new(HIDDEN_ROOT)).unwrap()
    }

    #[test]
    fn explicit_flake_wins_over_probes() {
        let fs = tests_support::full_nixos_host();
        let target = super::super::discover_with_platform(
            &NixOsPlatform,
            &fs,
            Path::new(HIDDEN_ROOT),
            Some("gh:me/cfg#host"),
            false,
        )
        .unwrap();
        assert_eq!(
            target,
            HostTarget::ExplicitFlake("gh:me/cfg#host".to_string())
        );
    }

    #[test]
    fn hidden_volume_flake_preferred() {
        let fs = tests_support::full_nixos_host();
        assert_eq!(
            discover(&fs),
            HostTarget::Flake(PathBuf::from("/mnt/hidden/nixos"))
        );
    }

    #[test]
    fn etc_flake_when_no_hidden_flake() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/etc/nixos/flake.nix", PathKind::File);
        fs.mock_set_path_type("/etc/nixos/configuration.nix", PathKind::File);
        assert_eq!(
            discover(&fs),
            HostTarget::Flake(PathBuf::from("/etc/nixos"))
        );
    }

    #[test]
    fn legacy_config_when_present() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/etc/nixos/configuration.nix", PathKind::File);
        assert_eq!(
            discover(&fs),
            HostTarget::Legacy(PathBuf::from("/etc/nixos/configuration.nix"))
        );
    }

    /// The agreement case: with only the system profile present, every path must
    /// resolve to the same legacy target activation uses — no drift between
    /// activate, `--dry-run`/`check`, and the `nixos-build-target` pre-flight.
    #[test]
    fn only_system_profile_resolves_to_legacy() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/nix/var/nix/profiles/system", PathKind::Dir);
        assert_eq!(
            discover(&fs),
            HostTarget::Legacy(PathBuf::from("/etc/nixos/configuration.nix"))
        );
    }

    #[test]
    fn nothing_found_is_none() {
        assert_eq!(discover(&MockFilesystem::new()), HostTarget::None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NailsError;
    use crate::filesystem::{MockFilesystem, PathKind};
    use crate::process::run::{MockProcessRunner, exited};

    const PROFILE: &str = "/nix/var/nix/profiles/system";
    const SWITCH_SCRIPT: &str = "/nix/var/nix/profiles/system/bin/switch-to-configuration";

    /// A mock host whose decoy system profile (and its switch script) exist.
    fn host() -> MockFilesystem {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type(PROFILE, PathKind::Dir);
        fs.mock_set_path_type(SWITCH_SCRIPT, PathKind::File);
        fs
    }

    fn command_strings(runner: &MockProcessRunner) -> Vec<String> {
        runner.calls().iter().map(|c| format!("{c}")).collect()
    }

    #[test]
    fn successful_reboot_runs_no_switch() {
        // Profile discovery reads NAILS_SYSTEM_PROFILE_PATH; hold the lock so a
        // concurrent test cannot point it elsewhere mid-read.
        let fs = host();
        let runner = MockProcessRunner::new();
        let platform = NixOsPlatform;

        let outcome = Platform::restore_base_system(
            &platform,
            &fs,
            &runner,
            true,
            &|| Ok(()),
            &crate::RuntimeEnv::empty(),
        )
        .unwrap();

        assert_eq!(outcome, RestoreOutcome::SymlinkRestored);
        assert!(
            command_strings(&runner).is_empty(),
            "a dispatched reboot must not invoke switch-to-configuration"
        );
    }

    #[test]
    fn failed_reboot_falls_back_to_session_switch() {
        let fs = host();
        let runner = MockProcessRunner::new();
        let platform = NixOsPlatform;

        let outcome = Platform::restore_base_system(
            &platform,
            &fs,
            &runner,
            true,
            &|| Err(NailsError::NixOSError("reboot unavailable".into())),
            &crate::RuntimeEnv::empty(),
        )
        .unwrap();

        assert_eq!(outcome, RestoreOutcome::FellBackToSessionSwitch);
        let commands = command_strings(&runner);
        assert_eq!(commands.len(), 1, "exactly one fallback command");
        assert!(
            commands[0].contains("switch-to-configuration"),
            "{commands:?}"
        );
        assert!(commands[0].ends_with(" test"), "{commands:?}");
    }

    #[test]
    fn no_reboot_only_restores_symlink() {
        let fs = host();
        let runner = MockProcessRunner::new();
        let platform = NixOsPlatform;

        let outcome = Platform::restore_base_system(
            &platform,
            &fs,
            &runner,
            false,
            &|| Ok(()),
            &crate::RuntimeEnv::empty(),
        )
        .unwrap();

        assert_eq!(outcome, RestoreOutcome::SymlinkRestored);
        assert!(command_strings(&runner).is_empty());
    }

    #[test]
    fn missing_system_profile_errors() {
        let fs = MockFilesystem::new();
        let runner = MockProcessRunner::new();
        let platform = NixOsPlatform;

        let result = Platform::restore_base_system(
            &platform,
            &fs,
            &runner,
            true,
            &|| Ok(()),
            &crate::RuntimeEnv::empty(),
        );
        assert!(matches!(result, Err(NailsError::NixOSError(_))));
    }

    #[test]
    fn failed_switch_surfaces_error() {
        let fs = host();
        let runner = MockProcessRunner::new().with_response(Ok(exited(1, "", "boom")));
        let platform = NixOsPlatform;

        let result = Platform::restore_base_system(
            &platform,
            &fs,
            &runner,
            true,
            &|| Err(NailsError::NixOSError("reboot unavailable".into())),
            &crate::RuntimeEnv::empty(),
        );
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Decoy session switch failed"));
    }
}
