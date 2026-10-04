// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The NixOS backend: the project's first-class platform.
//!
//! It carries the behaviour that used to live inline in the manager and the
//! deactivation path. For now it owns the base-system restore step; the overlay
//! mount hooks and build-target selection move behind it in their owning chunks.

use super::config_layer::restore_decoy_system;
use super::{
    ArtifactScanner, ConfigLayer, NixOsConfigLayer, NixOsStateNoteScanner, OverlayPolicy, Platform,
    PlatformKind, RestoreOutcome,
};
use crate::Result;
use crate::filesystem::Filesystem;
use crate::process::ProcessRunner;

/// The NixOS system profile's binary directory.
///
/// The one place this store path is written as a literal; every other site that
/// needs it (the process runner's search list, the runtime-command cache) refers
/// to this constant.
pub(crate) const NIXOS_SYSTEM_PROFILE_BIN: &str = "/run/current-system/sw/bin";

/// Directories NixOS exposes host tools under.
pub(crate) const NIXOS_COMMAND_DIRS: &[&str] = &[NIXOS_SYSTEM_PROFILE_BIN, "/run/wrappers/bin"];

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
    ) -> Result<RestoreOutcome> {
        // The decoy restore is the config layer's `restore`; the platform and the
        // layer share one implementation so they can never diverge.
        restore_decoy_system(fs, runner, reboot_follows, dispatch_reboot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NailsError;
    use crate::filesystem::{MockFilesystem, PathKind};
    use crate::process::run::{MockProcessRunner, exited};
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

    fn command_strings(runner: &MockProcessRunner) -> Vec<String> {
        runner.calls().iter().map(|c| format!("{c}")).collect()
    }

    #[test]
    fn successful_reboot_runs_no_switch() {
        // Profile discovery reads NAILS_SYSTEM_PROFILE_PATH; hold the lock so a
        // concurrent test cannot point it elsewhere mid-read.
        let _env = EnvGuard::lock();
        let fs = host();
        let runner = MockProcessRunner::new();
        let platform = NixOsPlatform;

        let outcome =
            Platform::restore_base_system(&platform, &fs, &runner, true, &|| Ok(())).unwrap();

        assert_eq!(outcome, RestoreOutcome::SymlinkRestored);
        assert!(
            command_strings(&runner).is_empty(),
            "a dispatched reboot must not invoke switch-to-configuration"
        );
    }

    #[test]
    fn failed_reboot_falls_back_to_session_switch() {
        let _env = EnvGuard::lock();
        let fs = host();
        let runner = MockProcessRunner::new();
        let platform = NixOsPlatform;

        let outcome = Platform::restore_base_system(&platform, &fs, &runner, true, &|| {
            Err(NailsError::NixOSError("reboot unavailable".into()))
        })
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
        let _env = EnvGuard::lock();
        let fs = host();
        let runner = MockProcessRunner::new();
        let platform = NixOsPlatform;

        let outcome =
            Platform::restore_base_system(&platform, &fs, &runner, false, &|| Ok(())).unwrap();

        assert_eq!(outcome, RestoreOutcome::SymlinkRestored);
        assert!(command_strings(&runner).is_empty());
    }

    #[test]
    fn missing_system_profile_errors() {
        let _env = EnvGuard::lock();
        let fs = MockFilesystem::new();
        let runner = MockProcessRunner::new();
        let platform = NixOsPlatform;

        let result = Platform::restore_base_system(&platform, &fs, &runner, true, &|| Ok(()));
        assert!(matches!(result, Err(NailsError::NixOSError(_))));
    }

    #[test]
    fn failed_switch_surfaces_error() {
        let _env = EnvGuard::lock();
        let fs = host();
        let runner = MockProcessRunner::new().with_response(Ok(exited(1, "", "boom")));
        let platform = NixOsPlatform;

        let result = Platform::restore_base_system(&platform, &fs, &runner, true, &|| {
            Err(NailsError::NixOSError("reboot unavailable".into()))
        });
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Decoy session switch failed"));
    }
}
