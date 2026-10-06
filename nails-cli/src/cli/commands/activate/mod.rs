// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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

/// Run the read-only decoy residue scan and record a pre-mount baseline on the
/// hidden volume.
///
/// This is a best-effort snapshot taken before any overlay is mounted: it only
/// reads the decoy and writes its report to `<hidden-root>/reports/`, which is
/// torn down with the session. A scan or write failure is logged and activation
/// continues, because the baseline is a convenience for later comparison, not a
/// precondition for activating.
fn write_activation_residue_baseline(
    manager: &nails_core::NailsManager<nails_core::RealFilesystem>,
    json: bool,
    settings: &OutputSettings,
) {
    use nails_core::{RealFilesystem, StateFileStatus, Verifier, VerifyStatus};

    let config = manager.config().clone();
    let hidden_root = config.hidden_volume_root.clone();
    if hidden_root.as_os_str().is_empty() {
        return;
    }

    // Pre-activation: the system is Inactive, so the scan sees the decoy as it is
    // before overlays. Standard depth keeps activation responsive; the scanners
    // and artifact checks run at either depth. The scan is scoped to the decoy:
    // the hidden volume is already attached for the activation about to start, so
    // its own mount, on-volume files and backing device are deliberately attached,
    // not residue, and must not show up as findings in the decoy baseline.
    let verifier = Verifier::with_config(RealFilesystem, config, None, StateFileStatus::NotChecked)
        .with_runtime_env(manager.runtime_env())
        .scoped_to_decoy();
    let result = match verifier.run(false) {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "pre-activation decoy residue scan failed; continuing without a baseline report"
            );
            return;
        }
    };

    let timestamp = chrono::Utc::now().to_rfc3339();
    match nails_core::write_activation_residue_report(
        &RealFilesystem,
        &hidden_root,
        &result,
        &timestamp,
    ) {
        Ok(summary) => {
            let status = match summary.status {
                VerifyStatus::Secure => "clean",
                VerifyStatus::Warning => "warnings",
                VerifyStatus::Critical => "critical findings",
            };
            if json {
                tracing::debug!(
                    path = %summary.path.display(),
                    "wrote pre-activation decoy residue report"
                );
            } else if settings.verbosity >= Verbosity::Normal {
                println!(
                    "Pre-activation decoy residue baseline: {status} ({} finding{}) -> {}",
                    summary.finding_count,
                    if summary.finding_count == 1 { "" } else { "s" },
                    summary.path.display()
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "could not write pre-activation decoy residue report; continuing"
            );
        }
    }
}

/// Execute the activate command
///
/// # Parameters
///
/// - `settings`: Output settings resolved once from the global flags
/// - `args`: The `activate` arguments
/// - `config_override`: Optional path to configuration file (`--config`)
///
/// # Returns
///
/// An [`ExitStatus`] describing the outcome: [`ExitStatus::Ok`] on success,
/// [`ExitStatus::PreflightRefused`] when a pre-flight check refuses the
/// operation, [`ExitStatus::Failed`] for an activation failure,
/// [`ExitStatus::Usage`] for conflicting flags, [`ExitStatus::InvalidState`] when
/// the state file cannot be trusted, and [`ExitStatus::Config`] for a missing or
/// invalid configuration file.
#[expect(
    clippy::too_many_lines,
    reason = "one linear flow from flag checks to the report; split it rather than raise the limit"
)]
pub fn execute(
    settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    args: &ActivateArgs,
    config_override: Option<&std::path::Path>,
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
        terminate_processes: _,
        accept_persistent_decoy,
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
    // load and any confirmation gate because `check` does its own strict config
    // load and never touches the system.
    if dry_run {
        let check_args = crate::cli::args::CheckArgs {
            overlay_only,
            nixos_flake: nixos_flake.clone(),
            accept_persistent_decoy,
        };
        return super::check::execute(settings, env, &check_args, config_override);
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

    // Confirmation gate: -y proceeds unattended; otherwise a terminal confirms
    // (the session-kill prompt below) and a non-terminal is refused here, before
    // anything is staged, mounted or switched, so activation never ends a session
    // with no one watching. A detached worker re-runs this command inside a
    // transient service with no terminal; its parent already confirmed, so it
    // must neither prompt nor refuse.
    let already_detached = env.nails_detached.is_some();
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
    let mut manager = super::build_nixos_manager(config, state_path, overlay_only, env);

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

    // Short-circuit a verifiably active system to the same no-op outcome and exit
    // code on every flag path, before the session-kill pre-flight below (whose
    // StateCheck would otherwise refuse an already-active system with a different
    // exit code). The in-core reconcile gate still makes the authoritative
    // decision once activation proceeds; this only keeps the default,
    // session-killing path consistent with the keep-session and --no-preflight
    // paths, all of which report "already active" and exit 0.
    if manager.is_verified_active() {
        let already_active =
            Ok::<_, nails_core::NailsError>(nails_core::ActivationOutcome::AlreadyActive);
        if json {
            output::print_activate_json_result(&already_active, 0.0, &manager, None);
        } else {
            output::print_activate_human(&already_active, 0.0, &manager, None, settings);
        }
        return ExitStatus::Ok;
    }

    // Detect a graphical session up front: it decides both whether we detach
    // and whether we must confirm the session kill, and that confirmation has
    // to come before any pre-flight staging writes to the hidden volume.
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let mut session_ctx = None;
    if options.kill_session
        && let Ok(ctx) =
            nails_core::detect_session_context(&nails_core::RealSessionCommandExecutor, env)
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
                Ok(nails_core::CheckResult::Pass(_))
                | Ok(nails_core::CheckResult::Warn(_))
                | Ok(nails_core::CheckResult::Skipped(_)) => {}
                Ok(nails_core::CheckResult::Fail {
                    message,
                    remediation,
                }) => {
                    return report_error(
                        json,
                        "activate",
                        ExitStatus::PreflightRefused,
                        ErrorBody::new(
                            "preflight",
                            nails_core::NailsError::PreFlightCheckFailed(vec![(
                                suspicious_check_name(),
                                message,
                                remediation,
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
            // Route staging through the platform config layer so a host without one
            // (FHS / Debian) and an overlay-only run stage nothing: the hidden
            // `/etc/nixos` tree is only touched on a host that has a config layer.
            if let Err(e) = mgr.stage_hidden_config(overlay_only) {
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
            if let Err(e) = mgr.run_preflight_checks(overlay_only, options.accept_persistent_decoy)
            {
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
        maybe_detach_for_session_kill(env, options.kill_session, &argv, session_ctx.as_ref(), json)
    {
        return report_error(
            json,
            "activate",
            ExitStatus::Failed,
            ErrorBody::new("detach", e.to_string()),
        );
    }

    // Refuse before taking the state lock or writing the residue baseline when the
    // hidden root is not actually mounted. An overlay-only / `--session keep` run
    // skips the pre-detach preflight above, and the core preflight inside
    // `activate_with_options` runs only after the lock and the baseline are
    // written — so without this gate a `.lock` and a `reports/` tree would land on
    // what is really the decoy disk before the attach check ever refused. This is
    // the same attach gate every write path consults; fail closed here.
    {
        let mgr = &manager;
        match nails_core::HiddenRoot::verify_attached(
            mgr.filesystem(),
            &mgr.config().hidden_volume_root,
            false,
        ) {
            Ok(nails_core::AttachState::Attached) => {}
            Ok(nails_core::AttachState::Unattached(reason)) => {
                return report_error(
                    json,
                    "activate",
                    ExitStatus::PreflightRefused,
                    ErrorBody::new("preflight", format!("hidden-root: {reason}")),
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

    // Record a pre-mount decoy residue baseline. The scan is read-only and runs
    // before any overlay is mounted, so it describes the decoy as it was when the
    // session began; the report is written to the hidden volume, which is torn
    // down with the session. It is a convenience snapshot, not a gate: a scan or
    // write failure is logged and activation proceeds.
    write_activation_residue_baseline(&manager, json, settings);

    // Run activation with options and measure duration. Under --json the stream
    // is NDJSON: a progress line now, the result line below.
    if json {
        output::print_activate_progress("activating");
    }
    // Present the activation's progress for this surface: a spinner on an
    // interactive terminal, plain lines on a pipe, typed events under --json,
    // and nothing at all from a detached worker (whose progress `nails status`
    // reads from the hidden volume).
    manager.set_reporter(
        output::ProgressSurface::select(settings, already_detached).reporter(settings),
    );
    let start = Instant::now();
    let result = manager.activate_with_options(options, skip_preflight);
    let duration = start.elapsed().as_secs_f64();

    // Run the shell integration only on a genuine activation, never on an
    // already-active no-op: the overlays are freshly mounted, so the rc block,
    // autostart entry and colour scheme land in the hidden home. The core
    // `shell_setup` additionally refuses to write when the target home is not on
    // a NAILS overlay, so a lost race still cannot touch the decoy disk.
    let shell_setup_result =
        if matches!(result, Ok(nails_core::ActivationOutcome::Activated { .. })) {
            use nails_core::ShellInstrumentation;
            let mut shell =
                ShellInstrumentation::new(nails_core::RealFilesystem, manager.config().clone())
                    .with_shell_env(manager.runtime_env().shell.clone());
            // Attach the operator so rc and autostart files land symlink-safe and
            // owned by them; fall back to a best-effort root-owned write otherwise.
            match nails_core::TargetUser::resolve_with(manager.runtime_env()) {
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

    // Return the appropriate exit status: an activation that mounted the overlays
    // but could not apply the hidden NixOS configuration reports a distinct
    // success-with-warnings code, and a pre-flight refusal and an unsupported host
    // are each distinguished from an ordinary activation failure.
    match &result {
        Ok(outcome) if !outcome.warnings().is_empty() => ExitStatus::SuccessWithWarnings,
        Ok(_) => ExitStatus::Ok,
        Err(nails_core::NailsError::PreFlightCheckFailed(_)) => ExitStatus::PreflightRefused,
        Err(nails_core::NailsError::UnsupportedPlatform { .. }) => ExitStatus::Unsupported,
        // A signal rolled the activation back cleanly; report the conventional
        // cancellation code rather than a generic failure.
        Err(nails_core::NailsError::Cancelled) => ExitStatus::Cancelled,
        Err(_) => ExitStatus::Failed,
    }
}

#[cfg(test)]
mod tests;
