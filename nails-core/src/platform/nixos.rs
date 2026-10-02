//! The NixOS backend: the project's first-class platform.
//!
//! It carries the behaviour that used to live inline in the manager and the
//! deactivation path. For now it owns the base-system restore step; the overlay
//! mount hooks and build-target selection move behind it in their owning chunks.

use std::path::Path;

use super::{OverlayPolicy, Platform, PlatformKind, RestoreOutcome};
use crate::filesystem::Filesystem;
use crate::manager::{ensure_run_current_system_symlink, select_system_profile};
use crate::nixos::SwitchAction;
use crate::process::{ProcessCommand, ProcessRunner};
use crate::{NailsError, Result};

/// Directories NixOS exposes host tools under.
const NIXOS_COMMAND_DIRS: &[&str] = &["/run/current-system/sw/bin", "/run/wrappers/bin"];

/// First-class NixOS backend.
#[derive(Debug, Clone, Copy, Default)]
pub struct NixOsPlatform;

impl<F: Filesystem> Platform<F> for NixOsPlatform {
    fn kind(&self) -> PlatformKind {
        PlatformKind::NixOs
    }

    fn overlay_policy(&self) -> OverlayPolicy {
        OverlayPolicy::NixOs
    }

    fn host_command_dirs(&self) -> &'static [&'static str] {
        NIXOS_COMMAND_DIRS
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
        let fs = MockFilesystem::new();
        let runner = MockProcessRunner::new();
        let platform = NixOsPlatform;

        let result = Platform::restore_base_system(&platform, &fs, &runner, true, &|| Ok(()));
        assert!(matches!(result, Err(NailsError::NixOSError(_))));
    }

    #[test]
    fn failed_switch_surfaces_error() {
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
