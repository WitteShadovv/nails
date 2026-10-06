// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Output formatting for the activate command

use nails_core::output::{Mark, Tone};
use serde::Serialize;

use super::OutputSettings;
use crate::cli::output::dto::{DecoyWriterJson, StateJson, decoy_writers_json};
use crate::cli::output::envelope::SCHEMA_VERSION;

/// A streamed progress line for `activate --json`.
#[derive(Debug, Serialize)]
struct ActivateProgressEvent {
    schema_version: u32,
    command: &'static str,
    #[serde(rename = "type")]
    event_type: &'static str,
    phase: &'static str,
}

/// The final NDJSON line for `activate --json`.
#[derive(Debug, Serialize)]
struct ActivateResultEvent {
    schema_version: u32,
    command: &'static str,
    #[serde(rename = "type")]
    event_type: &'static str,
    ok: bool,
    status: &'static str,
    duration: f64,
    state: StateJson,
    /// Processes that kept writing to the decoy after the overlays came up.
    /// Empty when activation left none behind (or did not complete).
    decoy_writers: Vec<DecoyWriterJson>,
    /// Non-fatal warnings the activation carried — currently a hidden NixOS
    /// configuration that was not applied. Omitted when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_checks: Option<Vec<FailedCheckJson>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shell_instructions: Option<ShellInstructionsJson>,
}

#[derive(Debug, Serialize)]
pub struct ShellInstructionsJson {
    pub shell_type: String,
    pub prompt_script: String,
    pub alias_script: String,
    pub instructions: Vec<String>,
}

#[derive(Debug, Serialize)]
struct FailedCheckJson {
    name: String,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<String>,
}

fn manager_state_label<F: nails_core::Filesystem>(
    manager: &nails_core::NailsManager<F>,
) -> Option<&'static str> {
    manager
        .current_state()
        .ok()
        .map(|state| crate::cli::output::dto::system_state_label(&state))
}

fn manager_state_json<F: nails_core::Filesystem>(
    manager: &nails_core::NailsManager<F>,
) -> StateJson {
    match manager.current_state() {
        Ok(state) => StateJson::from_state(&state),
        Err(_) => StateJson::Unknown {
            reason: "state could not be read after activation".to_string(),
        },
    }
}

/// The writers activation recorded as still on the decoy (empty unless the
/// state is Active).
fn manager_decoy_writers<F: nails_core::Filesystem>(
    manager: &nails_core::NailsManager<F>,
) -> Vec<nails_core::DecoyWriter> {
    match manager.current_state() {
        Ok(nails_core::SystemState::Active { decoy_writers, .. }) => decoy_writers,
        _ => Vec::new(),
    }
}

/// The lines naming the writers left on the decoy, or none when there are none:
/// a `NOT OPTIMAL` headline, then one bulleted line per writer.
fn decoy_writer_lines(
    writers: &[nails_core::DecoyWriter],
    style: nails_core::output::Style,
) -> Vec<String> {
    if writers.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![style.paint_bold(
        format_args!(
            "{} NOT OPTIMAL: {}:",
            style.glyph(Mark::Warn),
            nails_core::decoy_writers_headline(writers.len())
        ),
        Tone::Yellow,
    )];
    lines.extend(
        writers
            .iter()
            .map(|writer| format!("  {} {}", style.glyph(Mark::Bullet), writer)),
    );
    lines
}

/// How activation progress is presented on this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressSurface {
    /// A redrawn spinner line with the step and its elapsed time (stderr is an
    /// interactive terminal).
    Spinner,
    /// One plain line per step, detail and heartbeat on stderr.
    Plain,
    /// Typed `progress` events in the `activate --json` stream on stdout.
    Json,
    /// Nothing on stdout or stderr: a detached worker, whose progress is read
    /// from the hidden-volume progress record by `nails status`.
    Silent,
}

impl ProgressSurface {
    /// Choose the surface for a run. A detached worker is always silent, even
    /// when it inherited `--json`: its output streams are discarded. Quiet runs
    /// report no progress, so they never start a spinner.
    pub fn select(settings: &OutputSettings, detached: bool) -> Self {
        if detached {
            ProgressSurface::Silent
        } else if settings.is_json() {
            ProgressSurface::Json
        } else if settings.progress_animation && !settings.is_quiet() {
            ProgressSurface::Spinner
        } else {
            ProgressSurface::Plain
        }
    }

    /// Build the reporter for this surface.
    pub fn reporter(
        self,
        settings: &OutputSettings,
    ) -> nails_core::reporter::progress::SharedReporter {
        use nails_core::reporter::progress::{
            JsonReporter, PlainReporter, SilentReporter, TtyReporter, shared,
        };
        match self {
            ProgressSurface::Spinner => shared(TtyReporter::new(
                Box::new(std::io::stderr()),
                settings.stderr_style(),
            )),
            ProgressSurface::Plain => shared(PlainReporter::new(Box::new(std::io::stderr()))),
            ProgressSurface::Json => shared(JsonReporter::new(
                Box::new(std::io::stdout()),
                SCHEMA_VERSION,
                "activate",
            )),
            ProgressSurface::Silent => shared(SilentReporter),
        }
    }
}

/// Emit a progress event on stdout, ahead of the final result line.
pub fn print_activate_progress(phase: &'static str) {
    let event = ActivateProgressEvent {
        schema_version: SCHEMA_VERSION,
        command: "activate",
        event_type: "progress",
        phase,
    };
    println!(
        "{}",
        serde_json::to_string(&event).expect("activate progress serialization cannot fail")
    );
}

/// Print the final activation result line in NDJSON.
pub fn print_activate_json_result<F: nails_core::Filesystem>(
    result: &Result<nails_core::ActivationOutcome, nails_core::NailsError>,
    duration: f64,
    manager: &nails_core::NailsManager<F>,
    shell_setup: Option<&nails_core::ShellSetupResult>,
) {
    let output = build_activate_json_output(result, duration, manager, shell_setup);

    println!(
        "{}",
        serde_json::to_string(&output).expect("Failed to serialize JSON")
    );
}

fn build_activate_json_output<F: nails_core::Filesystem>(
    result: &Result<nails_core::ActivationOutcome, nails_core::NailsError>,
    duration: f64,
    manager: &nails_core::NailsManager<F>,
    shell_setup: Option<&nails_core::ShellSetupResult>,
) -> ActivateResultEvent {
    use nails_core::{ActivationOutcome, NailsError};

    let state = manager_state_json(manager);
    let decoy_writers = match manager.current_state() {
        Ok(state) => decoy_writers_json(&state),
        Err(_) => Vec::new(),
    };

    // Convert shell setup result to JSON structure
    let shell_instructions_json = shell_setup.map(|setup| ShellInstructionsJson {
        shell_type: format!("{:?}", setup.shell_type).to_lowercase(),
        prompt_script: setup.prompt_script_path.display().to_string(),
        alias_script: setup.alias_script_path.display().to_string(),
        instructions: setup.instructions.clone(),
    });

    match result {
        Ok(ActivationOutcome::AlreadyActive) => ActivateResultEvent {
            schema_version: SCHEMA_VERSION,
            command: "activate",
            event_type: "result",
            ok: true,
            status: "already_active",
            duration,
            state,
            decoy_writers,
            warnings: Vec::new(),
            message: "System is already active; nothing to do".to_string(),
            failed_checks: None,
            // No activation ran, so no shell integration was applied.
            shell_instructions: None,
        },
        Ok(outcome @ ActivationOutcome::Activated { .. }) => {
            let warnings = outcome.warnings();
            // A failed hidden switch is reported truthfully: a distinct status and
            // a warnings array, not a clean "success".
            let (status, message) = if warnings.is_empty() {
                (
                    "success",
                    format!("Activation complete in {:.1}s", duration),
                )
            } else {
                (
                    "success_with_warnings",
                    format!("Activated with warnings: {}", warnings.join("; ")),
                )
            };
            ActivateResultEvent {
                schema_version: SCHEMA_VERSION,
                command: "activate",
                event_type: "result",
                ok: true,
                status,
                duration,
                state,
                decoy_writers,
                warnings,
                message,
                failed_checks: None,
                shell_instructions: shell_instructions_json,
            }
        }
        Err(e) => match e {
            NailsError::PreFlightCheckFailed(failures) => ActivateResultEvent {
                schema_version: SCHEMA_VERSION,
                command: "activate",
                event_type: "result",
                ok: false,
                status: "error",
                duration,
                state,
                decoy_writers,
                warnings: Vec::new(),
                message: "Pre-flight checks failed".to_string(),
                failed_checks: Some(
                    failures
                        .iter()
                        .map(|(name, reason, remediation)| FailedCheckJson {
                            name: name.clone(),
                            reason: reason.clone(),
                            // Prefer the check's own remediation; fall back to the
                            // neutral generic action rather than assuming every
                            // failure is an unmounted hidden volume.
                            fix: Some(remediation.clone().unwrap_or_else(|| {
                                "Resolve the reported check and retry activation".to_string()
                            })),
                        })
                        .collect(),
                ),
                shell_instructions: None,
            },
            _ => ActivateResultEvent {
                schema_version: SCHEMA_VERSION,
                command: "activate",
                event_type: "result",
                ok: false,
                status: "error",
                duration,
                state,
                decoy_writers,
                warnings: Vec::new(),
                message: format!("Activation failed: {}", e),
                failed_checks: None,
                shell_instructions: None,
            },
        },
    }
}

/// Print activation result in human-readable format
///
/// Results go to stdout and failures to stderr, each painted with that
/// stream's style; under `--quiet` only the result line and any writers left on
/// the decoy (a security finding, never suppressed) are printed.
pub fn print_activate_human<F: nails_core::Filesystem>(
    result: &Result<nails_core::ActivationOutcome, nails_core::NailsError>,
    duration: f64,
    manager: &nails_core::NailsManager<F>,
    shell_setup: Option<&nails_core::ShellSetupResult>,
    settings: &OutputSettings,
) {
    use nails_core::{ActivationOutcome, NailsError};

    let err = settings.stderr_style();

    match result {
        Ok(ActivationOutcome::AlreadyActive) => {
            // A verified-active no-op: report it plainly and never claim a fresh
            // activation. Nothing was mounted and no shell integration ran.
            let out = settings.stdout_style();
            println!(
                "{}",
                out.paint_bold(
                    format_args!(
                        "{} System already active; nothing to do",
                        out.glyph(Mark::Pass)
                    ),
                    Tone::Green
                )
            );
        }
        Ok(outcome @ ActivationOutcome::Activated { .. }) => {
            let out = settings.stdout_style();
            // The success summary (stdout) is built as a string so it can be
            // snapshotted at each verbosity without capturing the process stdout.
            print!(
                "{}",
                render_activate_success(duration, shell_setup, settings)
            );
            // A hidden NixOS configuration that did not apply is a warning, not a
            // clean success: name it after the completion summary, in warning style
            // and even under --quiet, so an activation that only mounted the
            // overlays is never reported as fully done.
            for warning in outcome.warnings() {
                println!(
                    "{}",
                    out.paint(
                        format_args!(
                            "{} Activated with warnings: {}",
                            out.glyph(Mark::Warn),
                            warning
                        ),
                        Tone::Yellow
                    )
                );
            }
            // Writers left on the decoy are a security warning, so report them
            // even in quiet mode, after the completion summary.
            for line in decoy_writer_lines(&manager_decoy_writers(manager), out) {
                println!("{line}");
            }
        }
        Err(NailsError::PreFlightCheckFailed(failures)) => {
            eprintln!(
                "{}",
                err.paint_bold(
                    format_args!("{} Pre-flight checks failed:", err.glyph(Mark::Fail)),
                    Tone::Red
                )
            );
            for (name, reason, _remediation) in failures {
                eprintln!(
                    "  {} {}: {}",
                    err.glyph(Mark::Bullet),
                    err.paint(name, Tone::Yellow),
                    reason
                );
            }
            // One ordered, deduplicated remediation list drawn from the checks
            // that named a concrete fix; a missing hidden volume that cascades
            // into several failures therefore shows a single step. When no check
            // named a fix, fall back to the neutral generic action.
            let steps = nails_core::remediation_steps(failures);
            if steps.is_empty() {
                eprintln!(
                    "\n  {}",
                    err.paint(
                        format_args!("Fix: {}", nails_core::reporter::GENERIC_REMEDIATION),
                        Tone::Yellow
                    )
                );
            } else {
                eprintln!("\n  {}", err.paint("To fix:", Tone::Yellow));
                for step in steps {
                    eprintln!(
                        "    {} {}",
                        err.glyph(Mark::Bullet),
                        err.paint(step, Tone::Yellow)
                    );
                }
            }
        }
        Err(e) => {
            let diagnostic = nails_core::Diagnostic::from_error(e);
            eprintln!(
                "{}",
                err.paint_bold(
                    format_args!("{} Activation failed: {}", err.glyph(Mark::Fail), e),
                    Tone::Red
                )
            );
            // Report the rollback only as it actually happened: nothing for a
            // failure raised before any overlay was mounted (option validation,
            // lock acquisition, the session kill), a plain confirmation when the
            // overlays came down cleanly, and the mounts it could not undo when
            // the rollback itself failed.
            match manager.last_rollback() {
                nails_core::RollbackOutcome::NotNeeded => {}
                nails_core::RollbackOutcome::Completed => {
                    eprintln!(
                        "  {}",
                        err.paint("Automatic rollback completed.", Tone::Dim)
                    );
                }
                nails_core::RollbackOutcome::Failed(errors) => {
                    eprintln!(
                        "  {}",
                        err.paint_bold("Automatic rollback FAILED:", Tone::Red)
                    );
                    for item in errors {
                        eprintln!(
                            "    {} {}",
                            err.glyph(Mark::Bullet),
                            err.paint(format_args!("still mounted: {item}"), Tone::Red)
                        );
                    }
                }
            }
            // Surface the error's single concrete next step when it has one, so
            // the failure names not just what went wrong but what to do about it.
            if let Some(hint) = diagnostic.hint {
                eprintln!("  {}", err.paint(format_args!("Fix: {hint}"), Tone::Yellow));
            }
            if let Some(state) = manager_state_label(manager) {
                eprintln!("  {}: {}", err.paint("Current state", Tone::Dim), state);
            }
        }
    }
}

/// Build the human-readable success summary for `activate` (stdout).
///
/// Only `--quiet` changes what is shown: it prints just the completion line,
/// while every other level adds the shell-integration guidance. Verbosity above
/// Normal affects tracing, not this summary, so Normal, Verbose and Debug render
/// identically here.
fn render_activate_success(
    duration: f64,
    shell_setup: Option<&nails_core::ShellSetupResult>,
    settings: &OutputSettings,
) -> String {
    use std::fmt::Write as _;

    let out = settings.stdout_style();
    let manual_hint = "You can manually source scripts from the hidden volume if needed";
    let mut buf = String::new();

    let _ = writeln!(
        buf,
        "{}",
        out.paint_bold(
            format_args!(
                "{} Activation complete in {:.1}s",
                out.glyph(Mark::Pass),
                duration
            ),
            Tone::Green
        )
    );

    if settings.is_quiet() {
        return buf;
    }

    let _ = writeln!(buf);
    match shell_setup {
        Some(setup) if setup.warning.is_some() => {
            // Script generation failed, show warning with reason
            let reason = setup.warning.as_deref().unwrap_or_default();
            let _ = writeln!(
                buf,
                "{}",
                out.paint(
                    format_args!("Shell prompt not updated: {reason}"),
                    Tone::Yellow
                )
            );
            let _ = writeln!(buf, "{}", out.paint(manual_hint, Tone::Dim));
        }
        Some(setup) => {
            let _ = writeln!(buf, "{}", out.paint_bold("Shell Integration:", Tone::Cyan));
            if setup.rc_modified {
                // RC file was modified - new terminals auto-configured
                let _ = writeln!(
                    buf,
                    "{}",
                    out.paint(
                        format_args!(
                            "{} New terminals will automatically have prompt, alias, and color scheme.",
                            out.glyph(Mark::Pass)
                        ),
                        Tone::Green
                    )
                );
                let _ = writeln!(buf);
                let _ = writeln!(
                    buf,
                    "{}",
                    out.paint("To apply to this terminal now, run:", Tone::Dim)
                );
            } else {
                let _ = writeln!(
                    buf,
                    "{}",
                    out.paint(
                        "To update your prompt and add the 'nails' alias, run:",
                        Tone::Dim
                    )
                );
            }
            for cmd in &setup.instructions {
                let _ = writeln!(buf, "  {}", out.paint(cmd, Tone::Bold));
            }
        }
        None => {
            // No shell detected or unsupported shell
            let _ = writeln!(
                buf,
                "{}",
                out.paint(
                    "Shell prompt not updated - no supported shell detected",
                    Tone::Yellow
                )
            );
            let _ = writeln!(buf, "{}", out.paint(manual_hint, Tone::Dim));
        }
    }

    // The RAM-backed control copy survives the loss of the hidden volume, so the
    // panic button is still reachable if the backend disappears mid-session.
    // Surfaced here (and in the activation notification) so the operator has it
    // recorded before anything goes wrong.
    let emergency_cmd = format!(
        "sudo {} emergency",
        nails_core::runtime_copy::binary_copy_path().display()
    );
    let _ = writeln!(buf);
    let _ = writeln!(
        buf,
        "{}",
        out.paint(
            "If the hidden volume fails, tear everything down with:",
            Tone::Dim
        )
    );
    let _ = writeln!(buf, "  {}", out.paint(emergency_cmd, Tone::Bold));

    buf
}

#[cfg(test)]
#[path = "activate_tests.rs"]
mod tests;
