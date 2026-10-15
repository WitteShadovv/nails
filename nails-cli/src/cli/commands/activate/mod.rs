// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Activate command handler
//!
//! Activation runs on the decoy and prepares the whole-root session: the
//! pre-flight checks, the hidden NixOS configuration (built into the next
//! root's store), the overlay at `/run/nextroot` and the armed plan. It prints
//! its result and then enqueues the soft-reboot, which stops every program of
//! the decoy and starts the hidden userspace inside the overlay: the operator
//! is logged out and logs in again at the hidden session's login screen. As its
//! last step it SIGKILLs the decoy's interactive shells, so none of them writes
//! the activation command to its history file on the decoy disk.

use crate::cli::args::ActivateArgs;
use crate::cli::output::envelope::{ErrorBody, report_error};
use crate::cli::output::refusal::report_refusal;
use crate::cli::output::{self, ActivateResult, ExitStatus, OutputSettings};

use nails_core::hidden_root::{Assessment, Refusal};
use nails_core::manager::{EnterOptions, EnterOutcome};
use nails_core::session::{RealEntryHost, RealTargetHost};
use nails_core::{CliOverrides, NailsError, Verbosity};
use std::io::IsTerminal;
use std::time::Instant;

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
    use nails_core::{RealFilesystem, StateFileStatus, Verifier};

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
            if json {
                tracing::debug!(
                    path = %summary.path.display(),
                    "wrote pre-activation decoy residue report"
                );
            } else if settings.verbosity >= Verbosity::Normal {
                println!(
                    "Pre-activation decoy residue baseline: {} -> {}",
                    baseline_summary(&result),
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

/// The progress line before the entry, naming only the steps it runs, in
/// their order: the pre-flight checks (not under `--no-preflight`), the next
/// root, and the hidden NixOS system built into it (NixOS with a build target
/// only, never with `--overlay-only` or on Debian and Ubuntu).
fn preparing_line(preflight: bool, builds_system: bool) -> String {
    let mut steps = Vec::new();
    if preflight {
        steps.push("pre-flight");
    }
    steps.push("next root");
    if builds_system {
        steps.push("hidden NixOS system");
    }
    format!("Preparing the hidden session ({})...", steps.join(", "))
}

/// What the residue baseline line says about the decoy: no count when it shows
/// no known residue, otherwise the warnings and critical findings. The
/// informational notes every scan adds (the RAM caveat, the scope of the
/// baseline, catalogue notes such as `timesync-clock`) are not findings and
/// stay in the report.
fn baseline_summary(result: &nails_core::VerifyResult) -> String {
    use crate::cli::output::count_noun;
    use nails_core::{Severity, VerifyStatus};

    let of = |severity: Severity| {
        result
            .findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .count()
    };
    let warnings = of(Severity::Warn);
    match result.status {
        VerifyStatus::Secure => "no known residue".to_string(),
        VerifyStatus::Warning => count_noun(warnings, "warning", "warnings"),
        VerifyStatus::Critical => {
            let critical = of(Severity::Critical);
            let mut text = count_noun(critical, "critical finding", "critical findings");
            if warnings > 0 {
                text.push_str(&format!(
                    ", {}",
                    count_noun(warnings, "warning", "warnings")
                ));
            }
            text
        }
    }
}

/// The line activation prints before it asks for confirmation when no
/// configuration file was found: every opt-in protection then keeps its
/// built-in default, which the operator should know before the switch.
fn defaults_notice(loaded: &nails_core::LoadedConfig) -> Option<String> {
    (!loaded.file_found).then(|| {
        format!(
            "No config file at {}: activation uses the built-in defaults.",
            loaded.path.display()
        )
    })
}

/// The `check` arguments `activate --dry-run` runs with.
fn dry_run_check_args(args: &ActivateArgs) -> crate::cli::args::CheckArgs {
    crate::cli::args::CheckArgs {
        overlay_only: args.overlay_only,
        nixos_flake: args.nixos_flake.clone(),
        accept_persistent_decoy: args.accept_persistent_decoy,
        allow_decoy_storage: args.allow_decoy_storage,
    }
}

/// What the activation asks of the session entry.
fn enter_options(args: &ActivateArgs) -> EnterOptions {
    EnterOptions {
        skip_preflight: args.no_preflight,
        overlay_only: args.overlay_only,
        accept_persistent_decoy: args.accept_persistent_decoy,
        binary: std::env::current_exe().unwrap_or_default(),
        allow_decoy_storage: args.allow_decoy_storage,
    }
}

/// Execute the activate command.
///
/// # Returns
///
/// [`ExitStatus::Ok`] once the soft-reboot is enqueued (or the session was
/// already active), [`ExitStatus::SuccessWithWarnings`] when it is enqueued
/// with warnings, [`ExitStatus::PreflightRefused`] when the attach gate or a
/// pre-flight check refuses, [`ExitStatus::Unsupported`] on an unsupported host,
/// [`ExitStatus::Usage`] without confirmation off a terminal,
/// [`ExitStatus::InvalidState`] when the state file cannot be trusted,
/// [`ExitStatus::Config`] for a bad configuration and [`ExitStatus::Failed`]
/// otherwise.
pub fn execute(
    settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    args: &ActivateArgs,
    config_override: Option<&std::path::Path>,
) -> ExitStatus {
    let json = settings.is_json();
    if args.dry_run {
        return super::check::execute(settings, env, &dry_run_check_args(args), config_override);
    }

    let mut loaded = match super::load_config_or_report(config_override, "activate", json) {
        Ok(loaded) => loaded,
        Err(status) => return status,
    };
    let defaults_notice = defaults_notice(&loaded);
    loaded.apply_cli_overrides(&CliOverrides {
        nixos_flake: args.nixos_flake.clone(),
    });
    let config = loaded.into_config();

    if !args.yes && !std::io::stdin().is_terminal() {
        return report_error(
            json,
            "activate",
            ExitStatus::Usage,
            ErrorBody::new(
                "needs_confirmation",
                "activate logs you out and needs confirmation, but stdin is not a terminal; pass -y/--yes to run non-interactively",
            ),
        );
    }

    let state_path = config.state_file_path.clone();
    let mut manager =
        super::build_nixos_manager(config, state_path.clone(), args.overlay_only, env);
    manager.set_verbosity(settings.verbosity);

    if manager.session_view().is_hidden() {
        print_result(settings, &ActivateResult::AlreadyActive, 0.0);
        return ExitStatus::Ok;
    }

    // The attach gate decides before anything is written: the state lock, the
    // residue baseline and the staged configuration all land on the root.
    // --no-preflight does not skip it.
    let options = enter_options(args);
    let accepted = match nails_core::HiddenRoot::assess_allowing(
        manager.filesystem(),
        &manager.config().hidden_volume_root,
        options.allow(),
    ) {
        Ok(Assessment::Attached) => None,
        Ok(Assessment::Warned(refusal)) => {
            crate::cli::output::eprintln_tolerating_broken_pipe(&format!(
                "warning: {}",
                refusal.warning()
            ));
            refusal.overridden().then_some(refusal)
        }
        Ok(Assessment::Refused(refusal)) => {
            return report_refusal(json, "activate", &refusal);
        }
        Err(e) => {
            return report_error(
                json,
                "activate",
                ExitStatus::PreflightRefused,
                ErrorBody::new("preflight", e.to_string()),
            );
        }
    };

    let _state_lock = match super::acquire_state_lock_or_report(
        &manager.config().hidden_volume_root,
        options.allow(),
        &state_path,
        "activate",
        json,
    ) {
        Ok(lock) => lock,
        Err(status) => return status,
    };
    if let Ok((_, outcome)) = manager.current_state_with_outcome()
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

    if let Some(notice) = defaults_notice.filter(|_| !settings.is_quiet()) {
        crate::cli::output::eprintln_tolerating_broken_pipe(&notice);
    }
    if !args.yes && !confirm_logout(settings, accepted.as_ref()) {
        return report_error(
            json,
            "activate",
            ExitStatus::Failed,
            ErrorBody::new("cancelled", "activation cancelled; nothing changed"),
        );
    }
    // Ctrl+C sets a flag that every step from here on reads (see
    // nails_core::cancel). At the prompt, whose read goes on until Enter, and
    // during the residue baseline, it ends the activation before the entry
    // begins.
    if nails_core::cancel::is_cancelled() {
        return report_cancelled(settings);
    }
    write_activation_residue_baseline(&manager, json, settings);
    if nails_core::cancel::is_cancelled() {
        return report_cancelled(settings);
    }

    if json {
        output::print_activate_progress("preparing");
    } else if settings.verbosity >= Verbosity::Normal {
        crate::cli::output::eprintln_tolerating_broken_pipe(&preparing_line(
            !options.skip_preflight,
            manager.builds_hidden_system(&options),
        ));
    }
    let start = Instant::now();
    let result = manager.enter_session(&options, &RealEntryHost);
    let duration = start.elapsed().as_secs_f64();

    let entry = match result {
        Ok(EnterOutcome::AlreadyActive) => {
            print_result(settings, &ActivateResult::AlreadyActive, duration);
            return ExitStatus::Ok;
        }
        Ok(EnterOutcome::Prepared(entry)) => entry,
        Err(error) => {
            print_result(settings, &ActivateResult::Failed(&error), duration);
            return match error {
                NailsError::PreFlightCheckFailed(_) => ExitStatus::PreflightRefused,
                NailsError::UnsupportedPlatform { .. } => ExitStatus::Unsupported,
                NailsError::Cancelled => ExitStatus::Cancelled,
                _ => ExitStatus::Failed,
            };
        }
    };
    print_result(settings, &ActivateResult::Entering(&entry), duration);
    crate::cli::output::flush_stdio();

    // The decoy's shells write their history when they exit, bash on the
    // SIGHUP that stopping their login session sends: the soft-reboot would
    // do that the moment it is enqueued. SIGKILL them first, ours last, so
    // the activation command never reaches a history file on the decoy disk.
    // Everything above is already on the terminal; a failure below still
    // reaches the log.
    nails_teardown::shells::kill_all_interactive_shells(&[]);
    let host = RealTargetHost::for_plan(Some(&entry.plan));
    if let Err(error) = manager.trigger_entry(&host, &RealEntryHost) {
        return report_error(
            json,
            "activate",
            ExitStatus::Failed,
            ErrorBody::new("soft_reboot", error.to_string())
                .with_hint("the next root was removed again; nothing changed"),
        );
    }
    drop(_state_lock);
    if entry.warnings.is_empty() {
        ExitStatus::Ok
    } else {
        ExitStatus::SuccessWithWarnings
    }
}

/// Report an activation that a signal cancelled before it changed anything.
fn report_cancelled(settings: &OutputSettings) -> ExitStatus {
    print_result(
        settings,
        &ActivateResult::Failed(&NailsError::Cancelled),
        0.0,
    );
    ExitStatus::Cancelled
}

fn print_result(settings: &OutputSettings, result: &ActivateResult<'_>, duration: f64) {
    if settings.is_json() {
        output::print_activate_json_result(result, duration);
    } else {
        output::print_activate_human(result, duration, settings);
    }
}

/// Ask on the terminal before logging the operator out. `accepted` is the
/// refusal the operator overrode with `--allow-decoy-storage`, repeated here.
fn confirm_logout(settings: &OutputSettings, accepted: Option<&Refusal>) -> bool {
    use nails_core::output::Mark;
    use std::io::{BufRead, Write};
    let style = settings.stderr_style();
    let mut stderr = std::io::stderr();
    let _ = writeln!(
        stderr,
        "{}",
        style.marked(
            Mark::Warn,
            "Activation soft-reboots into the hidden session."
        )
    );
    let _ = writeln!(
        stderr,
        "    Every program closes and you are logged out; unsaved work is lost."
    );
    if let Some(refusal) = accepted {
        let _ = writeln!(stderr, "    {}.", refusal.warning());
    }
    let _ = write!(stderr, "    Continue? [y/N]: ");
    let _ = stderr.flush();
    let mut input = String::new();
    if std::io::stdin().lock().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests;
