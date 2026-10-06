// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Emergency command handler
//!
//! Emergency is a fast, best-effort teardown, not a switch back to the decoy
//! configuration. It detaches the NAILS overlays first — the one step that
//! matters — then runs best-effort cleanup and drops the page cache, so a stalled
//! backend can never delay the unmount. It ends the hidden graphical session and
//! the services the hidden configuration added, and restarts the display manager
//! so the decoy greeter reappears. It does not run `switch-to-configuration` and
//! does not claim an immediate, complete return to the decoy: the operator still
//! closes the encrypted backend (and powers off or reboots to clear RAM) as the
//! recovery guidance explains. The teardown starts immediately unless
//! `--countdown <SECS>` is given, and `--poweroff`/`--reboot` run only after it
//! finishes.

use std::path::Path;

use nails_core::output::Mark;
use nails_core::{DeactivationReport, Filesystem, NailsManager, PostTeardownPower};
use serde::Serialize;

use crate::cli::args::EmergencyArgs;
use crate::cli::output::deactivate::deactivate_error_body;
use crate::cli::output::envelope::{Envelope, ErrorBody, report_error};
use crate::cli::output::{ExitStatus, OutputSettings};

/// Execute the emergency command.
///
/// A missing or invalid config is logged as a warning and defaults are used. The
/// teardown is immediate by default; `--countdown <SECS>` adds an abortable wait
/// that output flags never change.
///
/// # Returns
///
/// - [`ExitStatus::Ok`] once the teardown completed
/// - [`ExitStatus::DegradedReboot`] when some NAILS mount could not be removed
/// - [`ExitStatus::Failed`] on any other failure
pub fn execute(
    settings: &OutputSettings,
    args: &EmergencyArgs,
    config_override: Option<&Path>,
) -> ExitStatus {
    use nails_core::RealFilesystem;

    let json = settings.is_json();
    let verbosity = settings.verbosity;

    // A broken or missing config must never block an emergency teardown. When the
    // hidden volume that holds the config has failed, fall back to the RAM-backed
    // copy under /run and tell the operator which source was used.
    let (config, config_source) = super::load_config_for_teardown(config_override);
    if !json {
        tracing::info!("Emergency teardown using the {}", config_source.describe());
    }

    let state_path = config.state_file_path.clone();
    // Retained for the state lock, since `config` and the clone above are moved
    // into the manager below.
    let lock_state_path = state_path.clone();

    // Create manager
    let filesystem = RealFilesystem;
    let mut manager = NailsManager::new(filesystem, config, state_path);
    manager.set_verbosity(verbosity);

    // Try to take the state lock, but never let a crashed or unresponsive holder
    // block an emergency teardown: proceed without it after a short timeout.
    let _state_lock = super::acquire_state_lock_for_emergency(&lock_state_path);

    // Opt-in countdown before teardown. Immediate by default. The wait is never
    // skipped or shortened by --quiet or --json: output flags must never change
    // the timing of a panic button.
    if let Some(secs) = args.countdown {
        run_countdown(secs);
    }

    let power_action = requested_power_action(args);

    // The `--lock-backend` flag forces the backend close for this run; otherwise
    // the opt-in comes from the `[emergency] lock_backend` config key.
    let lock_requested = args.lock_backend || manager.config().emergency.lock_backend;

    match manager.emergency_deactivate() {
        Ok(report) => {
            // Opt-in: close the encrypted backend (lazy unmount + deferred
            // device-mapper removal), wiping the key from RAM when the last
            // reference drops. Off by default, so the hidden filesystem stays
            // mounted until the operator closes it by hand.
            let lock_outcome = lock_requested.then(|| perform_backend_lock(&manager));

            let backend_commands = backend_close_commands(&manager);
            let hidden_root = manager.config().hidden_volume_root.clone();
            let still_mounted = manager
                .filesystem()
                .is_mounted(&hidden_root)
                .unwrap_or(false);

            // Dispatch the requested power action after the teardown completes.
            // Powering off or rebooting is the only way to clear RAM, so it is
            // offered only once the overlays are gone.
            let power_note = dispatch_power_action(&manager, power_action);

            let view = EmergencyView {
                report: &report,
                backend_commands: &backend_commands,
                lock_outcome: lock_outcome.as_ref(),
                hidden_root: &hidden_root,
                hidden_root_still_mounted: still_mounted,
                power_action,
                power_note: &power_note,
            };

            if json {
                print_emergency_json(&view);
            } else {
                render_emergency_success(settings, &view);
            }
            ExitStatus::Ok
        }
        Err(nails_core::NailsError::DeactivationIncomplete { remaining_mounts }) => {
            let remaining = remaining_mounts
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            report_error(
                json,
                "emergency",
                ExitStatus::DegradedReboot,
                ErrorBody::new(
                    "teardown_incomplete",
                    format!("REBOOT REQUIRED: could not remove every NAILS mount: {remaining}"),
                )
                .with_hint(
                    "processes still hold the mounts; reboot to clear them and the key from RAM",
                ),
            )
        }
        Err(e) => report_error(
            json,
            "emergency",
            ExitStatus::Failed,
            deactivate_error_body(&e),
        ),
    }
}

/// Which post-teardown power action the operator requested, if any.
fn requested_power_action(args: &EmergencyArgs) -> Option<PostTeardownPower> {
    if args.poweroff {
        Some(PostTeardownPower::Poweroff)
    } else if args.reboot {
        Some(PostTeardownPower::Reboot)
    } else {
        None
    }
}

/// Dispatch the requested power action after a successful teardown.
///
/// Returns a short human note describing what happened (dispatched, skipped in a
/// safe runtime, or failed), or `None` when no action was requested.
fn dispatch_power_action<F: Filesystem>(
    manager: &NailsManager<F>,
    action: Option<PostTeardownPower>,
) -> Option<String> {
    let action = action?;
    let label = match action {
        PostTeardownPower::Poweroff => "power off",
        PostTeardownPower::Reboot => "reboot",
    };
    match manager.run_post_teardown_power(action) {
        Ok(true) => Some(format!("{label} dispatched")),
        Ok(false) => Some(format!("{label} skipped (safe runtime)")),
        Err(e) => Some(format!("{label} failed: {e}")),
    }
}

/// Print an abortable countdown to stderr, one line per second, always ending
/// with a Ctrl+C hint. Never gated by `--quiet`/`--json`.
fn run_countdown(secs: u64) {
    for remaining in (1..=secs).rev() {
        crate::cli::output::eprint_tolerating_broken_pipe(&format!(
            "\r  Emergency deactivation in {remaining}... (Ctrl+C to abort) "
        ));
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    if secs > 0 {
        crate::cli::output::eprintln_tolerating_broken_pipe(
            "\r  Emergency deactivation starting now!            ",
        );
    }
}

/// The exact commands to close the encrypted backend by hand, derived from the
/// hidden volume's device-mapper / loop chain.
///
/// The overlays come down during the teardown, but without the `lock_backend`
/// opt-in the encrypted backend stays open so its key remains in RAM until the
/// operator closes it. Best-effort: an unreadable or already-unmounted root
/// yields no command lines and the generic dismount guidance still applies.
fn backend_close_commands<F: Filesystem>(manager: &NailsManager<F>) -> Vec<String> {
    let root = manager.config().hidden_volume_root.clone();
    match nails_core::backend_lock::resolve_backend_chain(manager.filesystem(), &root) {
        Ok(Some(chain)) => nails_core::backend_lock::manual_close_sequence(&chain),
        _ => Vec::new(),
    }
}

/// Perform the opt-in backend close: lazy-unmount the hidden root and mark its
/// device-mapper stack for deferred removal, plus any explicit `close_command`.
///
/// Returns the core [`BackendLockReport`](nails_core::backend_lock::BackendLockReport),
/// with a failed or dispatched `close_command` folded into it. Nothing is
/// suppressed: every failure is reported.
fn perform_backend_lock<F: Filesystem>(
    manager: &NailsManager<F>,
) -> nails_core::backend_lock::BackendLockReport {
    let hidden_root = manager.config().hidden_volume_root.clone();
    let mut report = nails_core::backend_lock::lock_backend(manager.filesystem(), &hidden_root);

    if let Some(argv) = manager.config().emergency.close_command.clone() {
        match crate::cli::detach::run_detached_close_command(&argv) {
            Ok(()) => report.close_command_dispatched = true,
            Err(e) => report.errors.push(format!("close_command failed: {e}")),
        }
    }

    report
}

/// Everything the emergency success output renders, gathered once so the human
/// and JSON renderers stay in step.
struct EmergencyView<'a> {
    report: &'a DeactivationReport,
    backend_commands: &'a [String],
    lock_outcome: Option<&'a nails_core::backend_lock::BackendLockReport>,
    hidden_root: &'a Path,
    hidden_root_still_mounted: bool,
    power_action: Option<PostTeardownPower>,
    power_note: &'a Option<String>,
}

/// The `data` payload for a successful `emergency --json`.
#[derive(Debug, Serialize)]
struct EmergencyData {
    /// What happened (`complete`).
    status: &'static str,
    /// Overlays detached during the teardown.
    detached_overlays: Vec<String>,
    /// Overlays that only came down after the forced (lazy) detach, because
    /// processes still held the mount.
    force_detached_overlays: Vec<String>,
    /// Best-effort cleanup errors (non-fatal).
    cleanup_errors: Vec<String>,
    /// Whether the page cache was dropped after unmount.
    page_cache_dropped: bool,
    /// Whether the volatile runtime journal under `/run/log/journal` was scrubbed.
    runtime_journal_scrubbed: bool,
    /// Result of the opt-in post-unmount history-truncation check, if it ran.
    history_truncation_verified: Option<bool>,
    /// Whether the hidden root is still mounted after the teardown. `true` means
    /// the hidden filesystem is still browsable and the key is still in RAM.
    hidden_root_still_mounted: bool,
    /// The hidden-root path, so a still-mounted warning names it.
    hidden_root: String,
    /// The outcome of the opt-in backend close, when it was requested.
    backend_lock: Option<BackendLockData>,
    /// The exact commands to close the encrypted backend by hand.
    backend_close_commands: Vec<String>,
    /// The requested post-teardown power action, if any.
    power_action: Option<&'static str>,
    /// What the power action did (dispatched / skipped / failed), if requested.
    power_result: Option<String>,
    /// The recovery steps the operator should still take.
    recovery_guidance: Vec<&'static str>,
}

/// The JSON view of an opt-in backend-close attempt.
#[derive(Debug, Serialize)]
struct BackendLockData {
    /// Whether the lazy unmount of the hidden root succeeded.
    unmounted: bool,
    /// Device-mapper devices marked for deferred removal.
    dm_deferred: Vec<String>,
    /// Whether an explicit `close_command` was dispatched.
    close_command_dispatched: bool,
    /// Every failure encountered during the close.
    errors: Vec<String>,
}

impl BackendLockData {
    fn from_report(report: &nails_core::backend_lock::BackendLockReport) -> Self {
        Self {
            unmounted: report.unmounted,
            dm_deferred: report.dm_deferred.clone(),
            close_command_dispatched: report.close_command_dispatched,
            errors: report.errors.clone(),
        }
    }
}

fn power_action_name(action: Option<PostTeardownPower>) -> Option<&'static str> {
    action.map(|action| match action {
        PostTeardownPower::Poweroff => "poweroff",
        PostTeardownPower::Reboot => "reboot",
    })
}

/// Print the success envelope for a completed emergency teardown.
fn print_emergency_json(view: &EmergencyView) {
    let report = view.report;
    let data = EmergencyData {
        status: "complete",
        detached_overlays: report.unmounted_overlays.clone(),
        force_detached_overlays: report.force_detached_overlays.clone(),
        cleanup_errors: report.cleanup_report.errors.clone(),
        page_cache_dropped: report.page_cache_dropped,
        runtime_journal_scrubbed: report.runtime_journal_scrubbed,
        history_truncation_verified: report.history_truncation_verified,
        hidden_root_still_mounted: view.hidden_root_still_mounted,
        hidden_root: view.hidden_root.display().to_string(),
        backend_lock: view.lock_outcome.map(BackendLockData::from_report),
        backend_close_commands: view.backend_commands.to_vec(),
        power_action: power_action_name(view.power_action),
        power_result: view.power_note.clone(),
        recovery_guidance: EMERGENCY_RECOVERY_GUIDANCE.to_vec(),
    };
    Envelope::success("emergency", data).print();
}

/// Render the human-readable success output for a completed emergency teardown.
///
/// The stdout lines are gathered into a buffer and flushed through the pipe-safe
/// writer: an emergency can sever the session reading its own stdout, so the
/// final result must never abort fatally on a broken pipe once the teardown has
/// completed.
fn render_emergency_success(settings: &OutputSettings, view: &EmergencyView) {
    let report = view.report;
    let style = settings.stdout_style();
    let mut out: Vec<String> = Vec::new();
    out.push(style.marked(Mark::Pass, "Emergency teardown complete"));

    if report.unmounted_overlays.is_empty() {
        out.push("  No NAILS overlays were mounted".to_string());
    } else {
        out.push(format!(
            "  Detached {} overlay(s):",
            report.unmounted_overlays.len()
        ));
        for overlay in &report.unmounted_overlays {
            out.push(format!("    - {overlay}"));
        }
    }

    if !report.force_detached_overlays.is_empty() {
        out.push(format!(
            "  {} overlay(s) needed a forced detach (processes still held them);",
            report.force_detached_overlays.len()
        ));
        out.push(
            "  the backend cannot be closed until those processes exit or you reboot:".to_string(),
        );
        for overlay in &report.force_detached_overlays {
            out.push(format!("    ! {overlay}"));
        }
    }

    if report.page_cache_dropped {
        out.push("  Page cache dropped".to_string());
    }

    if report.runtime_journal_scrubbed {
        out.push("  Runtime journal scrubbed (/run/log/journal)".to_string());
    }

    if !report.cleanup_report.errors.is_empty() {
        out.push(format!(
            "  Cleanup reported {} error(s):",
            report.cleanup_report.errors.len()
        ));
        for error in &report.cleanup_report.errors {
            out.push(format!("    - {error}"));
        }
    }

    match report.history_truncation_verified {
        Some(true) => out.push("  History truncation verified".to_string()),
        Some(false) => out.push("  History truncation incomplete: some files remain".to_string()),
        None => {}
    }

    push_backend_lock_outcome(&mut out, view);

    if let Some(note) = view.power_note {
        out.push(format!("  Power action: {note}"));
    } else if view.power_action.is_none() && !view.hidden_root_still_mounted {
        out.push("  The decoy greeter will reappear".to_string());
    }

    push_hidden_root_status(&mut out, settings, view);

    for line in &out {
        crate::cli::output::println_tolerating_broken_pipe(line);
    }

    // Pipe-safe: the teardown restarts journald while scrubbing the runtime
    // journal, which severs the unit's `journal+console` stderr, so a plain
    // `eprintln!` here would panic on the broken pipe and abort after the work is
    // already done.
    crate::cli::output::eprintln_tolerating_broken_pipe("");
    for line in emergency_recovery_guidance(settings) {
        crate::cli::output::eprintln_tolerating_broken_pipe(&line);
    }
}

/// Append the outcome of the opt-in backend close, loudly on any failure.
fn push_backend_lock_outcome(out: &mut Vec<String>, view: &EmergencyView) {
    let Some(outcome) = view.lock_outcome else {
        return;
    };

    if outcome.unmounted {
        out.push("  Hidden root lazy-unmounted".to_string());
    }
    if !outcome.dm_deferred.is_empty() {
        out.push(format!(
            "  Backend marked for deferred removal: {}",
            outcome.dm_deferred.join(", ")
        ));
    }
    if outcome.close_command_dispatched {
        out.push("  Backend close command dispatched".to_string());
    }
    for error in &outcome.errors {
        out.push(format!("  ! Backend close error: {error}"));
    }
}

/// Append whether the hidden root is still mounted, and how to close it.
///
/// A still-mounted hidden root after an emergency is a Critical condition: the
/// hidden filesystem is browsable and the key is still in RAM. The exact manual
/// close sequence is printed so the operator can finish the job.
fn push_hidden_root_status(out: &mut Vec<String>, settings: &OutputSettings, view: &EmergencyView) {
    let style = settings.stdout_style();
    if view.hidden_root_still_mounted {
        out.push(String::new());
        out.push(style.marked(
            Mark::Fail,
            format!(
                "Critical: hidden root still mounted at {}",
                view.hidden_root.display()
            ),
        ));
        out.push(
            "  The hidden filesystem is still readable and its key is still in RAM.".to_string(),
        );
        if !view.backend_commands.is_empty() {
            out.push("  Close the encrypted backend when it is safe to do so:".to_string());
            for command in view.backend_commands {
                out.push(format!("    {command}"));
            }
        }
    } else if view.lock_outcome.is_some() {
        out.push("  Hidden root closed; the key is wiped as the last reference drops".to_string());
    }
}

/// Recovery guidance printed to stderr after an emergency teardown; the first
/// line carries the shared warning mark in the stderr style.
const EMERGENCY_RECOVERY_GUIDANCE: &[&str] = &[
    "Critical: For maximum safety:",
    "  1. Close the encrypted backend when it is safe to do so",
    "  2. Power off or reboot to clear the key and any residue from RAM",
];

fn emergency_recovery_guidance(settings: &OutputSettings) -> Vec<String> {
    let mut lines: Vec<String> = EMERGENCY_RECOVERY_GUIDANCE
        .iter()
        .map(|line| line.to_string())
        .collect();
    lines[0] = settings.stderr_style().marked(Mark::Warn, &lines[0]);
    lines
}

#[cfg(test)]
mod tests {
    use super::{EMERGENCY_RECOVERY_GUIDANCE, emergency_recovery_guidance, execute, run_countdown};
    use crate::cli::args::EmergencyArgs;
    use crate::cli::output::{OutputMode, OutputSettings};
    use nails_core::test_support::EnvGuard;
    use std::path::PathBuf;
    use std::time::Instant;

    const SUBPROCESS_TEST_NAME: &str =
        "cli::commands::emergency::tests::subprocess_emergency_entrypoint";

    fn run_subprocess(case: &str, config_path: Option<&std::path::Path>) -> std::process::Output {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
            // Keep the subprocess in runtime-safety mode so the emergency teardown
            // never touches the host (no confirmation gate stands between the CLI
            // and the real teardown).
            .env("NAILS_TEST_RUNTIME", "1")
            .env("NAILS_EMERGENCY_SUBPROCESS_CASE", case);

        if let Some(path) = config_path {
            command.env("NAILS_EMERGENCY_SUBPROCESS_CONFIG", path);
        }

        let _env = EnvGuard::lock();
        command
            .output()
            .expect("failed to run emergency subprocess test")
    }

    #[test]
    fn subprocess_emergency_entrypoint() {
        let Ok(case) = std::env::var("NAILS_EMERGENCY_SUBPROCESS_CASE") else {
            return;
        };

        let config_override =
            std::env::var_os("NAILS_EMERGENCY_SUBPROCESS_CONFIG").map(PathBuf::from);

        // Make the config warning visible on stderr, as the binary's subscriber does.
        let _ = tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .without_time()
            .try_init();

        let base = EmergencyArgs::default();
        let status = match case.as_str() {
            "invalid-config" => execute(
                &OutputSettings::default(),
                &base,
                config_override.as_deref(),
            ),
            "invalid-config-json" => {
                let settings = OutputSettings {
                    verbosity: nails_core::Verbosity::Verbose,
                    mode: OutputMode::Json,
                    ascii: true,
                    ..OutputSettings::default()
                };
                execute(&settings, &base, config_override.as_deref())
            }
            "poweroff" => execute(
                &OutputSettings::default(),
                &EmergencyArgs {
                    poweroff: true,
                    ..EmergencyArgs::default()
                },
                config_override.as_deref(),
            ),
            other => panic!("unknown emergency subprocess case: {other}"),
        };
        crate::cli::detach::exit_process(status.code());
    }

    #[test]
    fn execute_emergency_warns_and_proceeds_with_defaults_for_invalid_config() {
        use std::io::Write;

        let mut config = tempfile::NamedTempFile::new().unwrap();
        writeln!(config, "[color_scheme]\nenable = false").unwrap();

        let output = run_subprocess("invalid-config", Some(config.path()));
        let stderr = String::from_utf8_lossy(&output.stderr);

        // A broken config never blocks an emergency teardown: it falls back to
        // defaults with a warning and proceeds. The panic button runs from any
        // state, so against a clean Inactive default (no NAILS mounts) it is a
        // successful no-op (exit 0) rather than a refusal.
        assert_eq!(output.status.code(), Some(0), "stderr={stderr}");
        assert!(stderr.contains("did you mean `enabled`?"), "{stderr}");
        assert!(stderr.contains("continuing with defaults"), "{stderr}");
    }

    #[test]
    fn execute_emergency_warns_and_proceeds_when_explicit_config_is_missing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let missing = temp_dir.path().join("missing.toml");

        let output = run_subprocess("invalid-config", Some(&missing));
        let stderr = String::from_utf8_lossy(&output.stderr);

        // A missing config falls back to defaults with a warning; with nothing to
        // tear down the teardown is a clean no-op (exit 0).
        assert_eq!(output.status.code(), Some(0), "stderr={stderr}");
        assert!(stderr.contains("config file not found"), "{stderr}");
    }

    #[test]
    fn execute_emergency_succeeds_from_inactive_as_json() {
        let temp_dir = tempfile::tempdir().unwrap();
        let missing = temp_dir.path().join("missing.toml");

        let output = run_subprocess("invalid-config-json", Some(&missing));
        let stdout = String::from_utf8_lossy(&output.stdout);

        // The panic button runs from any state; against a clean Inactive default
        // it reports a successful no-op through one envelope on stdout.
        assert_eq!(output.status.code(), Some(0), "stdout={stdout}");
        assert!(stdout.contains("\"ok\":true"), "stdout={stdout}");
    }

    #[test]
    fn execute_emergency_poweroff_dispatches_after_teardown() {
        let temp_dir = tempfile::tempdir().unwrap();
        let missing = temp_dir.path().join("missing.toml");

        let output = run_subprocess("poweroff", Some(&missing));
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // In the safe runtime the real poweroff is skipped, but the CLI still runs
        // the power action after the teardown and reports it, so the dispatch path
        // is exercised without touching the host.
        assert_eq!(output.status.code(), Some(0), "stderr={stderr}");
        assert!(
            stdout.contains("Power action") && stdout.contains("power off"),
            "stdout={stdout}"
        );
    }

    #[test]
    fn countdown_waits_the_requested_seconds_and_prints_abort_hint() {
        // A 1s countdown should take at least ~1s and emit the abort hint.
        let shared = std::sync::Arc::new(std::sync::Mutex::new(()));
        let _guard = shared.lock().unwrap();
        let start = Instant::now();
        run_countdown(1);
        assert!(start.elapsed() >= std::time::Duration::from_millis(900));
    }

    #[test]
    fn zero_countdown_is_immediate() {
        let start = Instant::now();
        run_countdown(0);
        assert!(start.elapsed() < std::time::Duration::from_millis(200));
    }

    #[test]
    fn lock_backend_flag_is_accepted_by_clap() {
        use crate::cli::args::{Cli, Commands};
        use clap::Parser;

        let cli = Cli::try_parse_from(["nails", "emergency", "--lock-backend"])
            .expect("clap should accept --lock-backend");
        match cli.command {
            Commands::Emergency(args) => assert!(args.lock_backend),
            _ => panic!("expected the emergency command"),
        }
    }

    #[test]
    fn no_countdown_flag_is_rejected_by_clap() {
        use crate::cli::args::Cli;
        use clap::Parser;

        let result = Cli::try_parse_from(["nails", "emergency", "--no-countdown"]);
        assert!(result.is_err(), "clap should reject the removed flag");
    }

    #[test]
    fn emergency_ascii_recovery_guidance_is_ascii_only() {
        let settings = OutputSettings {
            color_stderr: true,
            ascii: true,
            ..OutputSettings::default()
        };
        let combined = emergency_recovery_guidance(&settings).join("\n");

        assert!(combined.contains("[WARN]"), "guidance={combined}");
        let without_escapes = combined.replace("\x1b[1;33m", "").replace("\x1b[0m", "");
        assert!(without_escapes.is_ascii(), "guidance={combined}");
    }

    #[test]
    fn emergency_recovery_guidance_follows_stderr_colour() {
        let plain = emergency_recovery_guidance(&OutputSettings::default()).join("\n");
        assert!(plain.starts_with("⚠ Critical"), "{plain}");
        assert!(!plain.contains('\x1b'), "{plain}");

        let coloured = OutputSettings {
            color_stderr: true,
            ..OutputSettings::default()
        };
        assert!(emergency_recovery_guidance(&coloured)[0].contains('\x1b'));
    }

    #[test]
    fn emergency_recovery_guidance_contains_expected_text() {
        let combined: String = EMERGENCY_RECOVERY_GUIDANCE.join("\n");
        assert!(combined.contains("Close the encrypted backend"));
        assert!(combined.contains("clear the key"));
    }
}
