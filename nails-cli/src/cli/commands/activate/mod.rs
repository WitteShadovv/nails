//! Activate command handler
//!
//! This module contains the standalone handler for the `activate` command, which:
//! - Loads configuration with CLI overrides
//! - Runs pre-flight checks (unless skipped)
//! - Optionally detaches to a background service when killing GUI sessions
//! - Activates the hidden NixOS environment (mounts overlayfs, switches profiles)
//! - Configures shell instrumentation for the active state
//!
//! The handler is extracted from the main CLI dispatch logic to improve modularity
//! and testability.

use crate::cli::args::ActivateArgs;
use crate::cli::detach::maybe_detach_for_session_kill;
use crate::cli::output::envelope::{ErrorBody, report_error};
use crate::cli::output::{self, ExitStatus, OutputSettings};

use nails_core::{ActivateOptions, CliOverrides, Filesystem, PreFlightCheck, Verbosity};
use std::io::IsTerminal;
use std::time::Instant;

fn suspicious_check_name() -> String {
    <nails_core::SuspiciousNailsReferenceCheck as nails_core::PreFlightCheck<
        nails_core::RealFilesystem,
    >>::name(&nails_core::SuspiciousNailsReferenceCheck::default())
    .to_string()
}

/// Execute the activate command
///
/// # Parameters
///
/// - `settings`: Output settings resolved once from the global flags
/// - `args`: The `activate` arguments
/// - `config_override`: Optional path to configuration file (`--config`)
/// - `check_real_ops`: Safety guard callback to verify real operations are allowed
///
/// # Returns
///
/// An [`ExitStatus`] describing the outcome: [`ExitStatus::Ok`] on success,
/// [`ExitStatus::PreflightRefused`] when a pre-flight check refuses the
/// operation, [`ExitStatus::Failed`] for an activation failure,
/// [`ExitStatus::Usage`] for conflicting flags, [`ExitStatus::NeedsRoot`] when
/// the safety guard blocks real operations, [`ExitStatus::InvalidState`] when the
/// state file cannot be trusted, and [`ExitStatus::Config`] for a missing or
/// invalid configuration file.
#[expect(
    clippy::too_many_lines,
    reason = "one linear flow from flag checks to the report; split it rather than raise the limit"
)]
pub fn execute(
    settings: &OutputSettings,
    args: &ActivateArgs,
    config_override: Option<&std::path::Path>,
    check_real_ops: impl Fn(&std::path::Path) -> Result<(), String>,
) -> ExitStatus {
    let ActivateArgs {
        no_preflight,
        session: _,
        pivot: _,
        yes: _,
        ref nixos_flake,
        dry_run,
        overlay_only,
        risky_services: _,
        terminate_interactive: _,
    } = *args;
    let verbosity = settings.verbosity;
    let json = settings.is_json();

    // Map the --session/--pivot/-y flags onto the core options, then layer the
    // resolved output settings on top.
    let mut options = ActivateOptions {
        quiet: settings.is_quiet(),
        verbosity: match verbosity {
            Verbosity::Quiet | Verbosity::Normal => 0,
            Verbosity::Verbose => 1,
            Verbosity::Debug => 2,
        },
        json,
        no_color: !settings.color_stdout,
        // The real `nix flake metadata`/eval validation is deferred until after
        // the overlays are mounted, so it never touches the decoy store. Derive
        // the opt-out from the genuine flags (not the detach-handoff skip flag):
        // the detached worker re-runs with the same argv, computes the same
        // value, and so still validates the flake post-overlay.
        skip_flake_validation: no_preflight || overlay_only,
        ..args.to_activate_options()
    };

    // Validate options (defensive: the typed CLI enums cannot produce a conflict).
    if let Err(e) = options.validate() {
        return report_error(
            json,
            "activate",
            ExitStatus::Usage,
            ErrorBody::new("usage", e.to_string()),
        );
    }

    // --dry-run is a thin alias for the read-only `check` command, so the two
    // always produce the same report and exit code. It runs before the config
    // load, the safety guard and any confirmation gate because `check` does its
    // own strict config load and never touches the system.
    if dry_run {
        let check_args = crate::cli::args::CheckArgs {
            overlay_only,
            nixos_flake: nixos_flake.clone(),
        };
        return super::check::execute(settings, &check_args, config_override);
    }

    // Activate no longer overrides clear_history; only deactivation clears it.
    let cli_overrides = CliOverrides {
        clear_history: None,
        nixos_flake: nixos_flake.clone(),
    };

    // Strict load: a missing --config file, a typo or an unknown key exits with
    // Config instead of silently activating with defaults.
    let mut loaded = match super::load_config_or_report(config_override, "activate", json) {
        Ok(loaded) => loaded,
        Err(status) => return status,
    };
    loaded.apply_cli_overrides(&cli_overrides);
    let config = loaded.into_config();

    // The --risky-services flag (already mapped into options) wins; otherwise
    // fall back to the config key, leaving None to be resolved at mount time.
    if options.risky_services.is_none() {
        options.risky_services = config.risky_services;
    }

    // TEST SAFETY GUARD (Layer 1): Check if real operations are allowed
    if let Err(msg) = check_real_ops(&config.hidden_volume_root) {
        return report_error(
            json,
            "activate",
            ExitStatus::NeedsRoot,
            ErrorBody::new("safety_guard", msg),
        );
    }

    // Confirmation gate: -y proceeds unattended; otherwise a terminal confirms
    // (the session-kill prompt below) and a non-terminal is refused here, before
    // anything is staged, mounted or switched, so activation never ends a session
    // with no one watching. A detached worker re-runs this command inside a
    // transient service with no terminal; its parent already confirmed, so it
    // must neither prompt nor refuse.
    let already_detached = std::env::var_os(nails_core::constants::ENV_DETACHED).is_some();
    if !options.yes && !already_detached && !std::io::stdin().is_terminal() {
        return report_error(
            json,
            "activate",
            ExitStatus::Usage,
            ErrorBody::new(
                "needs_confirmation",
                "activate needs confirmation but stdin is not a terminal; pass -y/--yes to run non-interactively",
            ),
        );
    }
    if already_detached {
        options.session_kill_confirmed = true;
    }

    let state_path = config.state_file_path.clone();
    // Retained for taking the inter-process state lock after any detach, since
    // `config` (and the clone above) are moved into the manager below.
    let lock_state_path = state_path.clone();

    // Build the manager with the NixOS build target activation would pick,
    // through the one discovery cascade shared with `check`/`--dry-run` and the
    // `nixos-build-target` pre-flight check, so no path can drift.
    let mut manager = super::build_nixos_manager(config, state_path, overlay_only);

    // Set verbosity level
    manager.set_verbosity(verbosity);

    // Detect the host so the activation path can refuse an unsupported one
    // (ostree / image-based, or a non-systemd PID 1). The refusal itself is
    // enforced inside `activate_with_options`, before any state is written, so it
    // runs in whichever process actually activates and never pre-empts the
    // session-kill detach handoff. A detection failure is non-fatal: the gate
    // then sees no profile and proceeds, matching the prior no-detection
    // behaviour. The detached worker re-detects the same host when it re-runs.
    if let Err(e) = manager.initialize_platform() {
        tracing::debug!(error = %e, "platform detection failed; continuing without a host profile");
    }

    // Detect a graphical session up front: it decides both whether we detach
    // and whether we must confirm the session kill, and that confirmation has
    // to come before any pre-flight staging writes to the hidden volume.
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let mut session_ctx = None;
    if options.kill_session
        && let Ok(ctx) = nails_core::detect_session_context()
        && ctx.kind == nails_core::SessionKind::GraphicalUser
    {
        session_ctx = Some(ctx);
    }

    // Confirm the session kill before anything is staged, mounted or switched.
    // With -y (or in the already-confirmed detached worker) this returns at
    // once; otherwise it prompts on the terminal and a decline aborts with the
    // state, mounts and session untouched.
    if options.kill_session
        && !options.session_kill_confirmed
        && let Some(ref ctx) = session_ctx
    {
        if let Err(e) = nails_core::prompt_session_kill_confirmation(ctx, options.yes) {
            return report_error(
                json,
                "activate",
                ExitStatus::Failed,
                ErrorBody::new("session", e.to_string()),
            );
        }
        options.session_kill_confirmed = true;
    }

    // If kill-session, run preflight before detaching so output stays visible.
    let mut skip_preflight = no_preflight;
    if options.kill_session && !no_preflight {
        if verbosity >= Verbosity::Normal {
            tracing::info!("Running pre-flight checks before session kill...");
        }

        {
            let mgr = &manager;
            // Static flake checks only before the session kill and detach: the
            // real `nix flake metadata`/eval validation is deferred to the
            // detached, overlaid phase so nothing is copied onto the decoy store.
            if let Err(e) = mgr.run_static_nixos_preflight(overlay_only) {
                return report_error(
                    json,
                    "activate",
                    ExitStatus::PreflightRefused,
                    ErrorBody::new("preflight", e.to_string()),
                );
            }

            let suspicious_check = nails_core::SuspiciousNailsReferenceCheck::new(
                mgr.config().hidden_volume_root.clone(),
            );
            match suspicious_check.run(mgr.filesystem()) {
                Ok(nails_core::CheckResult::Pass(_)) | Ok(nails_core::CheckResult::Warn(_)) => {}
                Ok(nails_core::CheckResult::Fail(message)) => {
                    return report_error(
                        json,
                        "activate",
                        ExitStatus::PreflightRefused,
                        ErrorBody::new(
                            "preflight",
                            nails_core::NailsError::PreFlightCheckFailed(vec![(
                                suspicious_check_name(),
                                message,
                            )])
                            .to_string(),
                        ),
                    );
                }
                Err(e) => {
                    return report_error(
                        json,
                        "activate",
                        ExitStatus::PreflightRefused,
                        ErrorBody::new("preflight", e.to_string()),
                    );
                }
            }
        }

        // Probe symlink support before staging (catches FAT32/exFAT early)
        {
            let mgr = &manager;
            match mgr
                .filesystem()
                .supports_symlinks(&mgr.config().hidden_volume_root)
            {
                Ok(false) => {
                    let msg = format!(
                        "Filesystem at {} does not support symbolic links. \
                         The hidden volume must be formatted with a Linux filesystem (e.g. ext4). \
                         FAT32 and exFAT do not support symlinks.",
                        mgr.config().hidden_volume_root.display()
                    );
                    return report_error(
                        json,
                        "activate",
                        ExitStatus::PreflightRefused,
                        ErrorBody::new("preflight", msg),
                    );
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Could not probe symlink support; continuing");
                }
                Ok(true) => {}
            }
        }

        {
            let mgr = &manager;
            if let Err(e) = nails_core::stage_hidden_nixos_config(
                mgr.filesystem(),
                &mgr.config().hidden_volume_root,
                overlay_only,
            ) {
                tracing::error!(
                    error = %e,
                    "Failed to stage hidden NixOS config before detach-safe pre-flight checks"
                );
                return report_error(
                    json,
                    "activate",
                    ExitStatus::Failed,
                    ErrorBody::new("staging", e.to_string()),
                );
            }
        }

        {
            let mgr = &manager;
            if let Err(e) = mgr.run_preflight_checks(overlay_only) {
                return report_error(
                    json,
                    "activate",
                    ExitStatus::PreflightRefused,
                    ErrorBody::new("preflight", e.to_string()),
                );
            }
        }

        skip_preflight = true;
    }

    // Detach to a transient service before killing the GUI session so the
    // worker survives it. The parent reports the handoff and exits inside this
    // call; a non-graphical or keep-session run returns and continues here.
    if let Err(e) =
        maybe_detach_for_session_kill(options.kill_session, &argv, session_ctx.as_ref(), json)
    {
        return report_error(
            json,
            "activate",
            ExitStatus::Failed,
            ErrorBody::new("detach", e.to_string()),
        );
    }

    // Take the exclusive state lock (after any detach, so only the process that
    // performs the activation holds it). A concurrent operation fails fast here.
    let _state_lock = match super::acquire_state_lock_or_report(&lock_state_path, "activate", json)
    {
        Ok(lock) => lock,
        Err(status) => return status,
    };

    // Refuse to activate over a state file we cannot trust: a corrupt or unreadable
    // file means the real state is unknown, and mounting on top of it could leak.
    {
        let mgr = &manager;
        if let Ok((_, outcome)) = mgr.current_state_with_outcome()
            && outcome.is_unknown()
        {
            return report_error(
                json,
                "activate",
                ExitStatus::InvalidState,
                ErrorBody::new(
                    "invalid_state",
                    "refusing to activate: the state file is corrupt or unreadable, so the \
                     current state is unknown. Run 'nails verify' and recover the hidden volume first.",
                ),
            );
        }
    }

    // Run activation with options and measure duration. Under --json the stream
    // is NDJSON: a progress line now, the result line below.
    if json {
        output::print_activate_progress("activating");
    }
    let start = Instant::now();
    let result = manager.activate_with_options(options, skip_preflight);
    let duration = start.elapsed().as_secs_f64();

    // If activation succeeded, set up shell instrumentation (non-critical)
    let shell_setup_result = if result.is_ok() {
        use nails_core::ShellInstrumentation;
        let mut shell =
            ShellInstrumentation::new(nails_core::RealFilesystem, manager.config().clone());
        // Attach the operator so rc and autostart files land symlink-safe and
        // owned by them; fall back to a best-effort root-owned write otherwise.
        match nails_core::TargetUser::resolve() {
            Ok(user) => shell = shell.with_target_user(user),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Could not resolve the operator; shell integration files will be written \
                     best-effort without ownership"
                );
            }
        }
        // shell_setup() never returns Err, only Ok(Some) or Ok(None)
        shell.shell_setup().ok().flatten()
    } else {
        None
    };

    // Output results based on flags
    if json {
        output::print_activate_json_result(
            &result,
            duration,
            &manager,
            shell_setup_result.as_ref(),
        );
    } else {
        output::print_activate_human(
            &result,
            duration,
            &manager,
            shell_setup_result.as_ref(),
            settings,
        );
    }

    // Return the appropriate exit status: a pre-flight refusal and an unsupported
    // host are each distinguished from an ordinary activation failure.
    match result {
        Ok(_) => ExitStatus::Ok,
        Err(nails_core::NailsError::PreFlightCheckFailed(_)) => ExitStatus::PreflightRefused,
        Err(nails_core::NailsError::UnsupportedPlatform { .. }) => ExitStatus::Unsupported,
        Err(_) => ExitStatus::Failed,
    }
}

#[cfg(test)]
mod tests;
