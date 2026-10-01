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

mod dry_run;

use crate::cli::args::ActivateArgs;
use crate::cli::detach::maybe_detach_for_session_kill;
use crate::cli::output::envelope::{ErrorBody, report_error};
use crate::cli::output::{self, ExitStatus, OutputSettings};

use nails_core::{
    ActivateOptions, CliOverrides, Filesystem, NailsManager, NixOSBuilder, PreFlightCheck,
    RealFilesystem, Verbosity,
};
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
pub fn execute(
    settings: &OutputSettings,
    args: &ActivateArgs,
    config_override: Option<&std::path::Path>,
    check_real_ops: impl Fn(&std::path::Path) -> Result<(), String>,
) -> ExitStatus {
    let ActivateArgs {
        no_preflight,
        no_clear_history,
        kill_session: _,
        no_kill_session,
        accept_pivot_risks,
        no_pivot: _,
        yes: _,
        interactive,
        ref nixos_flake,
        dry_run,
        overlay_only,
    } = *args;
    let verbosity = settings.verbosity;
    let json = settings.is_json();

    // Apply defaults: kill_session, yes, and no_pivot are enabled by default
    // Users must explicitly disable them with --no-kill-session, --interactive, or --accept-pivot-risks
    let kill_session = !no_kill_session; // Default true unless explicitly disabled
    let yes = !interactive; // Default true unless explicitly disabled
    let no_pivot = !accept_pivot_risks; // Default true unless explicitly disabled

    // Build ActivateOptions from CLI flags
    let mut options = ActivateOptions {
        kill_session,
        accept_pivot_risks,
        no_pivot,
        yes,
        quiet: settings.is_quiet(),
        verbosity: match verbosity {
            Verbosity::Quiet | Verbosity::Normal => 0,
            Verbosity::Verbose => 1,
            Verbosity::Debug => 2,
        },
        json,
        no_color: !settings.color_stdout,
        overlay_only,
        skip_process_detection_override: None, // Use default test behavior
        session_kill_confirmed: false,
        pre_activation_cleanup: true, // Default to running pre-activation cleanup
    };

    if options.kill_session {
        if !options.yes {
            return report_error(
                json,
                "activate",
                ExitStatus::Usage,
                ErrorBody::new(
                    "usage",
                    "--kill-session is non-interactive after detach; use --yes",
                ),
            );
        }
        if !options.accept_pivot_risks && !options.no_pivot {
            return report_error(
                json,
                "activate",
                ExitStatus::Usage,
                ErrorBody::new(
                    "usage",
                    "--kill-session requires --accept-pivot-risks or --no-pivot to avoid prompts",
                ),
            );
        }
    }

    // Validate options (check for conflicting flags)
    if let Err(e) = options.validate() {
        return report_error(
            json,
            "activate",
            ExitStatus::Usage,
            ErrorBody::new("usage", e.to_string()),
        );
    }

    // CLI flags override config file values
    let cli_overrides = CliOverrides {
        clear_history: if no_clear_history { Some(false) } else { None },
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

    // TEST SAFETY GUARD (Layer 1): Check if real operations are allowed
    if let Err(msg) = check_real_ops(&config.hidden_volume_root) {
        return report_error(
            json,
            "activate",
            ExitStatus::NeedsRoot,
            ErrorBody::new("safety_guard", msg),
        );
    }

    // --dry-run: preview activation steps without making changes
    if dry_run {
        return dry_run::execute_dry_run(
            &config,
            no_preflight,
            overlay_only,
            no_kill_session,
            settings.stdout_style(),
        );
    }

    let state_path = config.state_file_path.clone();
    // Retained for taking the inter-process state lock after any detach, since
    // `config` (and the clone above) are moved into the manager below.
    let lock_state_path = state_path.clone();

    // Create NailsManager with real filesystem (enable NixOS switching when flake is present)
    let filesystem = RealFilesystem;
    let nails_profile = std::path::PathBuf::from("/nix/var/nix/profiles/nails-system");

    let mut manager = if overlay_only {
        // --overlay-only: skip NixOS builder creation entirely
        tracing::info!("Overlay-only mode: skipping NixOS profile switch");
        NailsManager::new(filesystem, config, state_path)
    } else if let Some(ref flake_ref) = config.nixos_flake {
        // Explicit flake reference from --flake flag or config nixos_flake
        // Skip auto-discovery and use the provided reference directly
        tracing::info!(
            flake_ref = %flake_ref,
            "Using explicit NixOS flake reference"
        );
        let builder = NixOSBuilder::new_with_flake_ref(flake_ref.clone(), nails_profile);
        NailsManager::with_nixos(filesystem, config, state_path, builder)
    } else {
        // Auto-discovery cascade: hidden volume → /etc/nixos → legacy → no NixOS
        let nixos_flake_dir = config.hidden_volume_root.join("nixos");
        let nixos_flake = nixos_flake_dir.join("flake.nix");
        let etc_flake = std::path::PathBuf::from("/etc/nixos/flake.nix");
        let legacy_config = std::path::PathBuf::from("/etc/nixos/configuration.nix");
        let system_profile = std::path::PathBuf::from("/nix/var/nix/profiles/system");
        if nixos_flake.exists() {
            let builder = NixOSBuilder::new(nixos_flake_dir, nails_profile);
            NailsManager::with_nixos(filesystem, config, state_path, builder)
        } else if etc_flake.exists() {
            let builder = NixOSBuilder::new(std::path::PathBuf::from("/etc/nixos"), nails_profile);
            NailsManager::with_nixos(filesystem, config, state_path, builder)
        } else if legacy_config.exists() || system_profile.exists() {
            let builder = NixOSBuilder::new_legacy(legacy_config, nails_profile);
            NailsManager::with_nixos(filesystem, config, state_path, builder)
        } else {
            NailsManager::new(filesystem, config, state_path)
        }
    };

    // Set verbosity level
    manager.set_verbosity(verbosity);

    // If kill-session, run preflight before detaching so output stays visible.
    let mut skip_preflight = no_preflight;
    if options.kill_session && !no_preflight {
        if verbosity >= Verbosity::Normal {
            tracing::info!("Running pre-flight checks before session kill...");
        }

        {
            let mgr = &manager;
            if let Err(e) = mgr.run_read_only_nixos_preflight(overlay_only) {
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
            if let Err(e) = nails_core::stage_hidden_config_symlink(
                mgr.filesystem(),
                &mgr.config().hidden_volume_root,
            ) {
                tracing::error!(
                    error = %e,
                    "Failed to stage hidden config symlink before detach-safe pre-flight checks"
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

    // Detach if we're about to kill the GUI session so the worker survives it
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let mut session_ctx = None;
    if options.kill_session
        && let Ok(ctx) = nails_core::detect_session_context()
        && ctx.kind == nails_core::SessionKind::GraphicalUser
    {
        session_ctx = Some(ctx);
    }

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

    if let Err(e) = maybe_detach_for_session_kill(kill_session, &argv, session_ctx.as_ref()) {
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
        let shell = ShellInstrumentation::new(nails_core::RealFilesystem, manager.config().clone());
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

    // Return the appropriate exit status: a pre-flight refusal from the attached
    // path is distinguished from an ordinary activation failure.
    match result {
        Ok(_) => ExitStatus::Ok,
        Err(nails_core::NailsError::PreFlightCheckFailed(_)) => ExitStatus::PreflightRefused,
        Err(_) => ExitStatus::Failed,
    }
}

#[cfg(test)]
mod tests;
