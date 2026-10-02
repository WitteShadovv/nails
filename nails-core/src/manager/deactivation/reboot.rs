//! Post-deactivation reboot dispatch and its decoy-restore fallback.
//!
//! A standard deactivation ends with a reboot into the decoy. When no reboot
//! command can be dispatched, the decoy generation is re-activated for the
//! running session with a non-installing `switch-to-configuration test`.

use crate::manager::select_system_profile;
use crate::nixos::SwitchAction;
use crate::process::{ProcessCommand, ProcessRunner, Program, RealProcessRunner};
use crate::{Filesystem, NailsError, Result};

// Test-only reboot-dispatch overrides. Compiled in only under the `test-hooks`
// feature (and this crate's own `cfg(test)` builds), so a shipped binary carries
// neither the strings nor the branch that reads them, and always dispatches the
// real reboot commands.
#[cfg(any(test, feature = "test-hooks"))]
pub(super) const SYSTEMCTL_REBOOT_OVERRIDE_ENV: &str = "NAILS_SYSTEMCTL_PATH";
#[cfg(any(test, feature = "test-hooks"))]
pub(super) const REBOOT_BINARY_OVERRIDE_ENV: &str = "NAILS_REBOOT_PATH";

#[derive(Debug, Clone)]
pub(super) struct RebootCommand {
    program: Program,
    args: Vec<std::ffi::OsString>,
}

impl RebootCommand {
    fn systemctl(program: Program) -> Self {
        Self {
            program,
            args: vec![std::ffi::OsString::from("reboot")],
        }
    }

    fn reboot(program: Program) -> Self {
        Self {
            program,
            args: Vec::new(),
        }
    }

    fn display(&self) -> String {
        let program = self.program.to_string();
        if self.args.is_empty() {
            program
        } else {
            format!(
                "{} {}",
                program,
                self.args
                    .iter()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        }
    }
}

pub(super) fn reboot_candidates() -> Vec<RebootCommand> {
    #[cfg(any(test, feature = "test-hooks"))]
    {
        let systemctl_override = std::env::var_os(SYSTEMCTL_REBOOT_OVERRIDE_ENV);
        let reboot_override = std::env::var_os(REBOOT_BINARY_OVERRIDE_ENV);

        if systemctl_override.is_some() || reboot_override.is_some() {
            let mut candidates = Vec::new();

            if let Some(path) = systemctl_override {
                candidates.push(RebootCommand::systemctl(Program::Exact(path.into())));
            }

            if let Some(path) = reboot_override {
                candidates.push(RebootCommand::reboot(Program::Exact(path.into())));
            }

            return candidates;
        }
    }

    // The runner resolves each tool from the fixed system directories (which lead
    // with `/run/current-system/sw/bin`), so a single `systemctl`/`reboot` covers
    // NixOS and the FHS distros without a hardcoded store path.
    vec![
        RebootCommand::systemctl(Program::Tool("systemctl")),
        RebootCommand::reboot(Program::Tool("reboot")),
    ]
}

fn format_command_failure(command: &RebootCommand, output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    let mut details = vec![format!(
        "{} exited with status {}",
        command.display(),
        output.status
    )];

    if !stdout.is_empty() {
        details.push(format!("stdout: {}", stdout));
    }

    if !stderr.is_empty() {
        details.push(format!("stderr: {}", stderr));
    }

    details.join("; ")
}

pub(super) fn dispatch_reboot_candidates(candidates: Vec<RebootCommand>) -> Result<()> {
    let mut failures = Vec::new();

    for candidate in candidates {
        let command_display = candidate.display();

        // Dispatch is bounded so a hung `systemctl reboot` cannot wedge
        // deactivation; the whole-host guard lives in `request_reboot`, so the
        // runner itself is allowed to run here (the override tests drive stubs).
        let command = ProcessCommand::new(candidate.program.clone())
            .args(&candidate.args)
            .deadline(crate::process::run::REBOOT_DISPATCH_BUDGET)
            .allow_in_test_runtime();

        match RealProcessRunner.run(&command) {
            Ok(output) if output.status.success() => {
                tracing::info!(command = %command_display, "Reboot command dispatched");
                return Ok(());
            }
            Ok(output) => {
                let failure = format_command_failure(&candidate, &output);
                tracing::warn!(command = %command_display, error = %failure, "Reboot command failed");
                failures.push(failure);
            }
            Err(NailsError::IoError(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(command = %command_display, "Reboot command not available");
            }
            Err(error) => {
                let failure = format!("{} failed to execute: {}", command_display, error);
                tracing::warn!(command = %command_display, error = %error, "Reboot command execution failed");
                failures.push(failure);
            }
        }
    }

    if failures.is_empty() {
        Err(NailsError::NixOSError(
            "Failed to trigger reboot: no usable reboot command was found".to_string(),
        ))
    } else {
        Err(NailsError::NixOSError(format!(
            "Failed to trigger reboot: {}",
            failures.join(" | ")
        )))
    }
}

pub(super) fn request_reboot() -> Result<()> {
    if crate::runtime_safety::should_skip_host_interaction() {
        return Err(NailsError::NixOSError(
            "Refusing to trigger reboot in test or runtime-safety mode".to_string(),
        ));
    }

    dispatch_reboot_candidates(reboot_candidates())
}

/// What the post-deactivation reboot step ended up doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PostDeactivationReboot {
    /// A reboot command was dispatched; the host restarts and boots the decoy.
    Dispatched,
    /// The reboot command failed, so a non-installing `switch-to-configuration
    /// test` restored the decoy for the running session instead.
    FellBackToTest,
}

/// Request a reboot and, if the reboot command fails, fall back to a
/// non-installing `switch-to-configuration test`.
///
/// A failed reboot must never leave the hidden generation active, but the
/// fallback must also never reinstall the bootloader or write EFI NVRAM, so it
/// uses [`SwitchAction::Test`] (the only action the type can express). The
/// decision is kept in a small, closure-driven function so the fallback path is
/// unit-testable without dispatching a real reboot.
pub(super) fn reboot_then_restore_decoy_on_failure(
    reboot: impl FnOnce() -> Result<()>,
    restore_decoy: impl FnOnce() -> Result<()>,
) -> Result<PostDeactivationReboot> {
    match reboot() {
        Ok(()) => Ok(PostDeactivationReboot::Dispatched),
        Err(reboot_error) => {
            tracing::warn!(
                error = %reboot_error,
                "Reboot command failed; falling back to switch-to-configuration test to restore the decoy for this session"
            );
            restore_decoy()?;
            Ok(PostDeactivationReboot::FellBackToTest)
        }
    }
}

/// Run the decoy generation's `switch-to-configuration test` for the running
/// session (reboot fallback only).
///
/// This re-points the live system at the decoy without reinstalling the
/// bootloader or writing the ESP / EFI NVRAM. The action is built from
/// [`SwitchAction`], so it can only ever be `test`, never `switch`/`boot`.
pub(super) fn switch_to_decoy_for_session<F: Filesystem>(filesystem: &F) -> Result<()> {
    let Some(system_profile) = select_system_profile(filesystem)? else {
        return Err(NailsError::NixOSError(
            "No system profile available for decoy restore".into(),
        ));
    };

    let switch_script = system_profile.join("bin/switch-to-configuration");
    if !filesystem.path_exists(&switch_script)? {
        return Err(NailsError::NixOSError(format!(
            "System profile switch script missing: {}",
            switch_script.display()
        )));
    }

    // Run the generation's own script through the shared runner with a progress
    // heartbeat and no deadline: a `switch-to-configuration` must never be killed
    // part-way, or the live system is left in an undefined state.
    let command = ProcessCommand::exact(&switch_script).arg(SwitchAction::Test.as_arg());
    let (succeeded, _stdout, stderr) = RealProcessRunner
        .run_streaming_text(
            &command,
            crate::process::run::BUILD_PROGRESS_INTERVAL,
            &mut |elapsed| {
                tracing::info!(
                    "still restoring the decoy configuration, {}",
                    crate::process::run::format_elapsed(elapsed)
                );
            },
        )
        .map_err(|e| {
            NailsError::NixOSError(format!("Decoy session switch failed to start: {}", e))
        })?;

    if succeeded {
        Ok(())
    } else {
        Err(NailsError::NixOSError(format!(
            "Decoy session switch failed: {}",
            stderr
        )))
    }
}
