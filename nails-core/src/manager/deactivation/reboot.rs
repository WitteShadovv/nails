// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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

    fn systemctl_poweroff(program: Program) -> Self {
        Self {
            program,
            args: vec![std::ffi::OsString::from("poweroff")],
        }
    }

    fn poweroff(program: Program) -> Self {
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
            Err(error) if error.io_kind() == Some(std::io::ErrorKind::NotFound) => {
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
        Err(NailsError::RebootFailed(
            "no usable reboot command was found".to_string(),
        ))
    } else {
        Err(NailsError::RebootFailed(failures.join(" | ")))
    }
}

pub(super) fn request_reboot() -> Result<()> {
    if crate::runtime_safety::should_skip_host_interaction() {
        return Err(NailsError::RebootFailed(
            "Refusing to trigger reboot in test or runtime-safety mode".to_string(),
        ));
    }

    dispatch_reboot_candidates(reboot_candidates())
}

pub(super) fn poweroff_candidates() -> Vec<RebootCommand> {
    vec![
        RebootCommand::systemctl_poweroff(Program::Tool("systemctl")),
        RebootCommand::poweroff(Program::Tool("poweroff")),
    ]
}

/// What the post-deactivation reboot step ended up doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PostDeactivationReboot {
    /// A reboot command was dispatched; the host restarts and boots the decoy.
    Dispatched,
    /// The reboot command failed, so a non-installing `switch-to-configuration
    /// test` restored the decoy for the running session instead.
    FellBackToTest,
    /// Runtime-safety mode was active, so no reboot was dispatched and the decoy
    /// was not switched. A compile-time-impossible outcome in shipped builds,
    /// where [`should_skip_host_interaction`](crate::runtime_safety::should_skip_host_interaction)
    /// is `false`.
    Skipped,
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
            &mut |elapsed, last_line| {
                crate::reporter::progress::heartbeat(
                    "restoring the decoy configuration",
                    elapsed,
                    last_line,
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

/// How a deactivation performs the post-teardown reboot into the decoy.
///
/// Production always uses [`HostEffects::Real`], which dispatches the real reboot
/// commands and falls back to a non-installing `switch-to-configuration test`
/// when none can be dispatched. The seam exists so the reboot step is always
/// *reached* by `run_deactivation` — the per-site runtime-safety skip now lives
/// inside [`HostEffects::Real`] rather than wrapping the call — and so tests can
/// inject [`HostEffects::Simulated`] to observe the reboot request. That is the
/// only way to exercise the dispatch under this crate's own `cfg(test)` builds,
/// where [`should_skip_host_interaction`](crate::runtime_safety::should_skip_host_interaction)
/// is unconditionally `true`.
#[derive(Debug, Clone, Default)]
pub enum HostEffects {
    /// Dispatch the real reboot commands, skipping only while runtime-safety mode
    /// is active (a compile-time `false` in shipped builds).
    #[default]
    Real,
    /// Record the reboot request instead of touching the host (tests, dry runs).
    #[cfg(any(test, feature = "test-hooks"))]
    Simulated(std::sync::Arc<SimulatedHostEffects>),
}

impl HostEffects {
    /// Perform the post-deactivation reboot into the decoy.
    ///
    /// [`HostEffects::Real`] keeps the per-site runtime-safety skip: shipped
    /// builds compile it to `false` and always dispatch, while this crate's own
    /// tests (and a `NAILS_TEST_RUNTIME` nails-e2e run) skip the real reboot.
    /// A [`HostEffects::Simulated`] dispatcher records the request regardless and
    /// reports back whatever it was configured with.
    pub(crate) fn reboot_into_decoy<F: Filesystem>(
        &self,
        filesystem: &F,
    ) -> Result<PostDeactivationReboot> {
        match self {
            Self::Real => {
                if crate::runtime_safety::should_skip_host_interaction() {
                    tracing::info!("Skipping reboot dispatch: runtime-safety mode is active");
                    return Ok(PostDeactivationReboot::Skipped);
                }

                reboot_then_restore_decoy_on_failure(request_reboot, || {
                    switch_to_decoy_for_session(filesystem)
                })
            }
            #[cfg(any(test, feature = "test-hooks"))]
            Self::Simulated(simulated) => simulated.record_reboot_request(),
        }
    }

    /// Dispatch a power action requested after an emergency teardown
    /// (`--poweroff`/`--reboot`).
    ///
    /// A power-off clears RAM, the only complete remedy for residue the teardown
    /// cannot remove; a reboot into the decoy does the same and comes back up on
    /// the decoy. [`HostEffects::Real`] skips the dispatch while runtime-safety
    /// mode is active (a compile-time `false` in shipped builds), so the request
    /// is observable in tests without touching the host.
    pub(crate) fn run_post_teardown_power(
        &self,
        action: PostTeardownPower,
    ) -> Result<PowerDispatch> {
        match self {
            Self::Real => {
                if crate::runtime_safety::should_skip_host_interaction() {
                    tracing::info!(
                        ?action,
                        "Skipping post-teardown power action: runtime-safety mode is active"
                    );
                    return Ok(PowerDispatch::Skipped);
                }

                let candidates = match action {
                    PostTeardownPower::Poweroff => poweroff_candidates(),
                    PostTeardownPower::Reboot => reboot_candidates(),
                };
                dispatch_reboot_candidates(candidates).map(|()| PowerDispatch::Dispatched)
            }
            #[cfg(any(test, feature = "test-hooks"))]
            Self::Simulated(simulated) => simulated.record_power_request(action),
        }
    }
}

/// A power action to run after an emergency teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostTeardownPower {
    /// Power the machine off (clears RAM).
    Poweroff,
    /// Reboot into the decoy (clears RAM).
    Reboot,
}

/// Whether a post-teardown power action was dispatched or skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PowerDispatch {
    /// The power command was dispatched.
    Dispatched,
    /// Runtime-safety mode was active, so nothing was dispatched.
    Skipped,
}

/// A recording stand-in for [`HostEffects::Real`] used by tests and dry runs.
///
/// It never touches the host: every reboot request is counted, and the
/// configured [`SimulatedReboot`] decides what the dispatch reports back. This
/// makes the post-deactivation reboot observable even though
/// [`should_skip_host_interaction`](crate::runtime_safety::should_skip_host_interaction)
/// is unconditionally `true` in this crate's own test builds.
#[cfg(any(test, feature = "test-hooks"))]
#[derive(Debug)]
pub struct SimulatedHostEffects {
    reboot_requests: std::sync::atomic::AtomicUsize,
    power_requests: std::sync::atomic::AtomicUsize,
    outcome: SimulatedReboot,
}

/// What an injected [`SimulatedHostEffects`] reports for a reboot request.
#[cfg(any(test, feature = "test-hooks"))]
#[derive(Debug, Clone)]
pub enum SimulatedReboot {
    /// Record the request and report the reboot as dispatched.
    Dispatched,
    /// Record the request and then refuse with an error, standing in for a guard
    /// that still skips the destructive step — surfaced instead of swallowed.
    Refuse(String),
}

#[cfg(any(test, feature = "test-hooks"))]
impl SimulatedHostEffects {
    /// Build a recorder wrapped in the [`std::sync::Arc`] that
    /// [`HostEffects::Simulated`] holds, so a caller can keep a handle to inspect
    /// it after the deactivation runs.
    pub fn new(outcome: SimulatedReboot) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            reboot_requests: std::sync::atomic::AtomicUsize::new(0),
            power_requests: std::sync::atomic::AtomicUsize::new(0),
            outcome,
        })
    }

    /// How many reboot requests the dispatcher has recorded.
    pub fn reboot_requests(&self) -> usize {
        self.reboot_requests
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// How many post-teardown power requests (`--poweroff`/`--reboot`) the
    /// dispatcher has recorded.
    pub fn power_requests(&self) -> usize {
        self.power_requests
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn record_reboot_request(&self) -> Result<PostDeactivationReboot> {
        self.reboot_requests
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match &self.outcome {
            SimulatedReboot::Dispatched => Ok(PostDeactivationReboot::Dispatched),
            SimulatedReboot::Refuse(message) => Err(NailsError::NixOSError(message.clone())),
        }
    }

    fn record_power_request(&self, _action: PostTeardownPower) -> Result<PowerDispatch> {
        self.power_requests
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match &self.outcome {
            SimulatedReboot::Dispatched => Ok(PowerDispatch::Dispatched),
            SimulatedReboot::Refuse(message) => Err(NailsError::NixOSError(message.clone())),
        }
    }
}
