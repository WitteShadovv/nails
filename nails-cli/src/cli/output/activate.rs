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
            message: "System is already active; nothing to do".to_string(),
            failed_checks: None,
            // No activation ran, so no shell integration was applied.
            shell_instructions: None,
        },
        Ok(ActivationOutcome::Activated) => ActivateResultEvent {
            schema_version: SCHEMA_VERSION,
            command: "activate",
            event_type: "result",
            ok: true,
            status: "success",
            duration,
            state,
            decoy_writers,
            message: format!("Activation complete in {:.1}s", duration),
            failed_checks: None,
            shell_instructions: shell_instructions_json,
        },
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
                message: "Pre-flight checks failed".to_string(),
                failed_checks: Some(
                    failures
                        .iter()
                        .map(|(name, reason)| FailedCheckJson {
                            name: name.clone(),
                            reason: reason.clone(),
                            // The per-check `reason` already carries the specific
                            // remediation (for example "commit a flake.lock"), so
                            // the generic hint must stay neutral rather than
                            // assuming every failure is an unmounted hidden volume.
                            fix: Some(
                                "Resolve the reported check and retry activation".to_string(),
                            ),
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
        Ok(ActivationOutcome::Activated) => {
            let out = settings.stdout_style();
            // The success summary (stdout) is built as a string so it can be
            // snapshotted at each verbosity without capturing the process stdout.
            print!(
                "{}",
                render_activate_success(duration, shell_setup, settings)
            );
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
            for (name, reason) in failures {
                eprintln!(
                    "  {} {}: {}",
                    err.glyph(Mark::Bullet),
                    err.paint(name, Tone::Yellow),
                    reason
                );
            }
            eprintln!(
                "\n  {}",
                err.paint(
                    "Fix: Resolve the checks listed above and retry activation",
                    Tone::Yellow
                )
            );
        }
        Err(e) => {
            eprintln!(
                "{}",
                err.paint_bold(
                    format_args!("{} Activation failed: {}", err.glyph(Mark::Fail), e),
                    Tone::Red
                )
            );
            eprintln!(
                "  {}",
                err.paint("Automatic rollback completed.", Tone::Dim)
            );
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
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_core::{MockFilesystem, NailsError, NailsManager, ShellSetupResult, TestWorld};
    use std::path::PathBuf;

    fn quiet_settings() -> OutputSettings {
        OutputSettings {
            verbosity: nails_core::Verbosity::Quiet,
            ..OutputSettings::default()
        }
    }

    /// Settings fixed at one verbosity with colour off and ASCII markers, so a
    /// rendering snapshot is deterministic and isolates the verbosity dimension.
    fn settings_at(verbosity: nails_core::Verbosity) -> OutputSettings {
        OutputSettings {
            verbosity,
            ascii: true,
            ..OutputSettings::default()
        }
    }

    fn make_shell_setup_rc_modified() -> ShellSetupResult {
        use nails_core::shell::ShellType;
        ShellSetupResult {
            shell_type: ShellType::Bash,
            prompt_script_path: PathBuf::from("/mnt/hidden/scripts/nails_prompt.bash"),
            alias_script_path: PathBuf::from("/mnt/hidden/scripts/nails_alias.sh"),
            instructions: vec!["source /mnt/hidden/scripts/nails_prompt.bash".to_string()],
            warning: None,
            rc_modified: true,
        }
    }

    fn make_shell_setup_no_rc() -> ShellSetupResult {
        use nails_core::shell::ShellType;
        ShellSetupResult {
            shell_type: ShellType::Bash,
            prompt_script_path: PathBuf::from("/mnt/hidden/scripts/nails_prompt.bash"),
            alias_script_path: PathBuf::from("/mnt/hidden/scripts/nails_alias.sh"),
            instructions: vec!["source /mnt/hidden/scripts/nails_prompt.bash".to_string()],
            warning: None,
            rc_modified: false,
        }
    }

    fn make_shell_setup_with_warning() -> ShellSetupResult {
        use nails_core::shell::ShellType;
        ShellSetupResult {
            shell_type: ShellType::Bash,
            prompt_script_path: PathBuf::from("/mnt/hidden/scripts/nails_prompt.bash"),
            alias_script_path: PathBuf::from("/mnt/hidden/scripts/nails_alias.sh"),
            instructions: vec![],
            warning: Some("Could not detect shell config".to_string()),
            rc_modified: false,
        }
    }

    /// A manager whose state is Active with one writer left on the decoy. The
    /// temporary directory doubles as the hidden volume so the state can be saved.
    fn make_active_manager_with_writer() -> (tempfile::TempDir, NailsManager<MockFilesystem>) {
        let (mut manager, dir) = TestWorld::new().manager();
        manager
            .force_state(nails_core::SystemState::Active {
                activated_at: chrono::Utc::now(),
                overlays: vec![PathBuf::from("/var")],
                decoy_writers: vec![tail_writer()],
            })
            .unwrap();
        (dir, manager)
    }

    fn tail_writer() -> nails_core::DecoyWriter {
        nails_core::DecoyWriter {
            pid: 812,
            name: "tail".to_string(),
            service: None,
            targets: vec![PathBuf::from("/var")],
        }
    }

    // ── decoy writers ──────────────────────────────────────────────────────────

    #[test]
    fn test_json_success_lists_writers_left_on_the_decoy() {
        let (_dir, manager) = make_active_manager_with_writer();
        let output = build_activate_json_output(
            &Ok(nails_core::ActivationOutcome::Activated),
            1.0,
            &manager,
            None,
        );
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["state"]["kind"], "active");
        assert_eq!(
            json["decoy_writers"],
            serde_json::json!([{"pid": 812, "name": "tail", "targets": ["/var"]}])
        );
    }

    #[test]
    fn test_json_result_always_carries_decoy_writers() {
        let (manager, _tempdir) = TestWorld::new().manager();
        let output = build_activate_json_output(
            &Ok(nails_core::ActivationOutcome::Activated),
            1.0,
            &manager,
            None,
        );
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["decoy_writers"], serde_json::json!([]));
    }

    #[test]
    fn test_decoy_writer_lines_name_each_writer() {
        let style = nails_core::output::Style {
            color: false,
            ascii: true,
        };
        let lines = decoy_writer_lines(&[tail_writer()], style);
        assert_eq!(
            lines,
            vec![
                "[WARN] NOT OPTIMAL: 1 writer still on the decoy:".to_string(),
                "  - tail (PID 812) on /var".to_string(),
            ]
        );
        assert!(decoy_writer_lines(&[], style).is_empty());
    }

    #[test]
    fn test_human_success_with_writers_quiet() {
        let (_dir, manager) = make_active_manager_with_writer();
        assert_eq!(manager_decoy_writers(&manager), vec![tail_writer()]);
        print_activate_human(
            &Ok(nails_core::ActivationOutcome::Activated),
            1.0,
            &manager,
            None,
            &quiet_settings(),
        );
    }

    // ── print_activate_json ────────────────────────────────────────────────────

    #[test]
    fn test_json_success_no_shell() {
        let (manager, _tempdir) = TestWorld::new().manager();
        let output = build_activate_json_output(
            &Ok(nails_core::ActivationOutcome::Activated),
            1.5,
            &manager,
            None,
        );
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(output.event_type, "result");
        assert_eq!(output.status, "success");
        assert!(output.ok);
        assert_eq!(output.message, "Activation complete in 1.5s");
        assert_eq!(json["type"].as_str(), Some("result"));
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["command"], "activate");
        // State is a tagged object, never a Debug string.
        assert!(json["state"]["kind"].is_string());
    }

    #[test]
    fn test_json_success_with_shell() {
        let (manager, _tempdir) = TestWorld::new().manager();
        let setup = make_shell_setup_rc_modified();
        let output = build_activate_json_output(
            &Ok(nails_core::ActivationOutcome::Activated),
            2.3,
            &manager,
            Some(&setup),
        );
        assert_eq!(output.event_type, "result");
        assert_eq!(output.status, "success");
        assert!(output.shell_instructions.is_some());
    }

    #[test]
    fn test_json_already_active_distinct_from_success() {
        // An already-active no-op reports a success exit (ok=true) but with its
        // own status and message — never "Activation complete" — and never any
        // shell instructions, since no activation ran.
        let (manager, _tempdir) = TestWorld::new().manager();
        let setup = make_shell_setup_rc_modified();
        let output = build_activate_json_output(
            &Ok(nails_core::ActivationOutcome::AlreadyActive),
            0.0,
            &manager,
            Some(&setup),
        );
        assert!(output.ok);
        assert_eq!(output.status, "already_active");
        assert!(
            !output.message.contains("Activation complete"),
            "already-active message must differ from a fresh activation: {}",
            output.message
        );
        assert!(output.shell_instructions.is_none());
    }

    #[test]
    fn test_human_already_active_message_is_distinct() {
        // The human already-active line goes to stdout and must not claim a fresh
        // activation completed.
        let (manager, _tempdir) = TestWorld::new().manager();
        print_activate_human(
            &Ok(nails_core::ActivationOutcome::AlreadyActive),
            0.0,
            &manager,
            None,
            &settings_at(nails_core::Verbosity::Normal),
        );
    }

    #[test]
    fn test_json_preflight_failure() {
        let (manager, _tempdir) = TestWorld::new().manager();
        let err = NailsError::PreFlightCheckFailed(vec![
            ("hidden_volume".to_string(), "not mounted".to_string()),
            ("swap".to_string(), "swap enabled".to_string()),
        ]);
        let output = build_activate_json_output(&Err(err), 0.1, &manager, None);
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(output.event_type, "result");
        assert_eq!(output.status, "error");
        assert!(!output.ok);
        assert_eq!(output.message, "Pre-flight checks failed");
        assert_eq!(output.failed_checks.as_ref().map(Vec::len), Some(2));
        assert_eq!(json["type"].as_str(), Some("result"));
    }

    #[test]
    fn test_json_preflight_failure_fix_is_not_mount_specific() {
        // A flake.lock problem is a pre-flight failure that has nothing to do
        // with mounting the hidden volume, so the remediation hint must not
        // claim it does; the specific guidance lives in the per-check reason.
        let (manager, _tempdir) = TestWorld::new().manager();
        let err = NailsError::PreFlightCheckFailed(vec![(
            "nixos-build-target".to_string(),
            "flake.lock not found in '/tmp/flake-target'. Activation does not run \
             'nix flake update' automatically; commit a flake.lock and retry activation."
                .to_string(),
        )]);
        let output = build_activate_json_output(&Err(err), 0.1, &manager, None);
        let checks = output.failed_checks.expect("failed checks present");
        let fix = checks[0].fix.as_deref().unwrap_or_default();
        assert!(
            !fix.contains("hidden volume is mounted"),
            "remediation hint must not assume a mount problem: {fix:?}"
        );
        assert!(
            fix.contains("retry activation"),
            "remediation hint should direct the operator to retry: {fix:?}"
        );
    }

    #[test]
    fn test_json_other_error() {
        let (manager, _tempdir) = TestWorld::new().manager();
        let err = NailsError::InvalidState("unexpected state".to_string());
        let output = build_activate_json_output(&Err(err), 0.5, &manager, None);
        assert_eq!(output.event_type, "result");
        assert_eq!(output.status, "error");
        assert_eq!(
            output.message,
            "Activation failed: Invalid state: unexpected state"
        );
    }

    #[test]
    fn test_progress_event_is_typed_ndjson() {
        // Smoke: the progress line serializes without panicking.
        print_activate_progress("activating");
    }

    // ── renderer verbosity matrix ───────────────────────────────────────────────

    #[test]
    fn snapshot_activate_success_render_across_verbosity() {
        // The success summary only branches on `--quiet`: Normal, Verbose and
        // Debug add the same shell-integration guidance (verbosity above Normal
        // changes tracing, not this summary), and Quiet prints just the result
        // line. `-vv` and `-vvv` both resolve to Debug, so the four distinct
        // states are Quiet / Normal / Verbose / Debug.
        use nails_core::Verbosity;
        let setup = make_shell_setup_rc_modified();
        for (label, verbosity) in [
            ("quiet", Verbosity::Quiet),
            ("normal", Verbosity::Normal),
            ("verbose", Verbosity::Verbose),
            ("debug", Verbosity::Debug),
        ] {
            insta::assert_snapshot!(
                format!("activate_success_{label}"),
                render_activate_success(1.5, Some(&setup), &settings_at(verbosity))
            );
        }
    }

    // ── print_activate_human ───────────────────────────────────────────────────

    #[test]
    fn test_human_success_no_shell() {
        let (manager, _tempdir) = TestWorld::new().manager();
        print_activate_human(
            &Ok(nails_core::ActivationOutcome::Activated),
            1.5,
            &manager,
            None,
            &OutputSettings::default(),
        );
    }

    #[test]
    fn test_human_success_quiet() {
        let (manager, _tempdir) = TestWorld::new().manager();
        print_activate_human(
            &Ok(nails_core::ActivationOutcome::Activated),
            1.5,
            &manager,
            None,
            &quiet_settings(),
        );
    }

    #[test]
    fn test_human_success_shell_rc_modified() {
        let (manager, _tempdir) = TestWorld::new().manager();
        let setup = make_shell_setup_rc_modified();
        print_activate_human(
            &Ok(nails_core::ActivationOutcome::Activated),
            1.0,
            &manager,
            Some(&setup),
            &OutputSettings::default(),
        );
    }

    #[test]
    fn test_human_success_shell_no_rc() {
        let (manager, _tempdir) = TestWorld::new().manager();
        let setup = make_shell_setup_no_rc();
        print_activate_human(
            &Ok(nails_core::ActivationOutcome::Activated),
            1.0,
            &manager,
            Some(&setup),
            &OutputSettings::default(),
        );
    }

    #[test]
    fn test_human_success_shell_with_warning() {
        let (manager, _tempdir) = TestWorld::new().manager();
        let setup = make_shell_setup_with_warning();
        print_activate_human(
            &Ok(nails_core::ActivationOutcome::Activated),
            1.0,
            &manager,
            Some(&setup),
            &OutputSettings::default(),
        );
    }

    #[test]
    fn test_human_success_shell_quiet_suppresses_instructions() {
        let (manager, _tempdir) = TestWorld::new().manager();
        let setup = make_shell_setup_rc_modified();
        print_activate_human(
            &Ok(nails_core::ActivationOutcome::Activated),
            1.0,
            &manager,
            Some(&setup),
            &quiet_settings(),
        );
    }

    #[test]
    fn test_human_preflight_failure() {
        let (manager, _tempdir) = TestWorld::new().manager();
        let err = NailsError::PreFlightCheckFailed(vec![(
            "hidden_volume".to_string(),
            "not mounted".to_string(),
        )]);
        print_activate_human(&Err(err), 0.1, &manager, None, &OutputSettings::default());
    }

    #[test]
    fn test_human_other_error() {
        let (manager, _tempdir) = TestWorld::new().manager();
        let err = NailsError::InvalidState("bad state".to_string());
        print_activate_human(&Err(err), 0.3, &manager, None, &OutputSettings::default());
    }
}
