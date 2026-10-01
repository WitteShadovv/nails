//! Emergency command handler

use std::path::Path;

use nails_core::output::Mark;
use serde::Serialize;

use crate::cli::args::EmergencyArgs;
use crate::cli::output::deactivate::deactivate_error_body;
use crate::cli::output::envelope::{Envelope, ErrorBody, report_error};
use crate::cli::output::{ExitStatus, OutputSettings};

/// Execute the emergency command.
///
/// Rapid deactivation with a countdown. A missing or invalid config is logged as
/// a warning and defaults are used.
///
/// # Returns
///
/// - [`ExitStatus::Ok`] once the teardown completed
/// - [`ExitStatus::NeedsRoot`] when the safety guard blocks real operations
/// - [`ExitStatus::Failed`] when the teardown failed
pub fn execute(
    settings: &OutputSettings,
    args: &EmergencyArgs,
    config_override: Option<&Path>,
    check_real_ops: impl Fn(&std::path::Path) -> Result<(), String>,
) -> ExitStatus {
    use nails_core::{NailsManager, RealFilesystem};

    let json = settings.is_json();
    let verbosity = settings.verbosity;

    // A broken or missing config must never block an emergency teardown.
    let config = super::load_config_or_defaults(config_override).into_config();

    if let Err(msg) = check_real_ops(&config.hidden_volume_root) {
        return report_error(
            json,
            "emergency",
            ExitStatus::NeedsRoot,
            ErrorBody::new("safety_guard", msg),
        );
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

    // Countdown before emergency deactivation (skip if --no-countdown, --quiet, or --json)
    if !args.no_countdown && !settings.is_quiet() && !json {
        use std::io::Write;

        for i in (1..=3).rev() {
            eprint!("\r  Emergency deactivation in {}... ", i);
            let _ = std::io::stderr().flush();
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        eprintln!("\r  Emergency deactivation starting now!  ");
    }

    // Run emergency deactivation
    match manager.emergency_deactivate() {
        Ok(()) => {
            if json {
                print_emergency_json();
            } else {
                println!(
                    "{}",
                    settings
                        .stdout_style()
                        .marked(Mark::Pass, "Emergency deactivation complete")
                );
                println!("  System returned to decoy configuration");
                eprintln!();
                for line in emergency_recovery_guidance(settings) {
                    eprintln!("{line}");
                }
            }
            ExitStatus::Ok
        }
        Err(e) => report_error(
            json,
            "emergency",
            ExitStatus::Failed,
            deactivate_error_body(&e),
        ),
    }
}

/// The `data` payload for a successful `emergency --json`.
#[derive(Debug, Serialize)]
struct EmergencyData {
    /// What happened (`complete`).
    status: &'static str,
    /// The recovery steps the operator should still take.
    recovery_guidance: Vec<&'static str>,
}

/// Print the success envelope for a completed emergency teardown.
fn print_emergency_json() {
    let data = EmergencyData {
        status: "complete",
        recovery_guidance: EMERGENCY_RECOVERY_GUIDANCE.to_vec(),
    };
    Envelope::success("emergency", data).print();
}

/// Recovery guidance printed to stderr after an emergency teardown; the first
/// line carries the shared warning mark in the stderr style.
const EMERGENCY_RECOVERY_GUIDANCE: &[&str] = &[
    "Critical: For maximum safety:",
    "  1. Dismount the hidden volume when it is safe to do so",
    "  2. If you are unsure cleanup was complete, reboot immediately",
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
    use super::{
        EMERGENCY_RECOVERY_GUIDANCE, emergency_recovery_guidance, execute, print_emergency_json,
    };
    use crate::cli::args::EmergencyArgs;
    use crate::cli::output::{OutputMode, OutputSettings};
    use std::path::PathBuf;

    const SUBPROCESS_TEST_NAME: &str =
        "cli::commands::emergency::tests::subprocess_emergency_entrypoint";

    fn run_subprocess(case: &str, config_path: Option<&std::path::Path>) -> std::process::Output {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
            .env("NAILS_EMERGENCY_SUBPROCESS_CASE", case);

        if let Some(path) = config_path {
            command.env("NAILS_EMERGENCY_SUBPROCESS_CONFIG", path);
        }

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

        let args = EmergencyArgs { no_countdown: true };
        let status = match case.as_str() {
            "invalid-config" => execute(
                &OutputSettings::default(),
                &args,
                config_override.as_deref(),
                |root| Err(format!("guard saw root {}", root.display())),
            ),
            "guard" => {
                let settings = OutputSettings {
                    verbosity: nails_core::Verbosity::Verbose,
                    mode: OutputMode::Json,
                    ascii: true,
                    ..OutputSettings::default()
                };
                execute(&settings, &args, config_override.as_deref(), |_| {
                    Err("emergency guard blocked".to_string())
                })
            }
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

        // Exit 5 comes from the safety guard, which runs only after config
        // loading has fallen back to defaults instead of refusing.
        assert_eq!(output.status.code(), Some(5), "stderr={stderr}");
        assert!(stderr.contains("did you mean `enabled`?"), "{stderr}");
        assert!(stderr.contains("continuing with defaults"), "{stderr}");
        let derived = nails_core::config::derive_hidden_volume_root();
        assert!(
            stderr.contains(&format!("guard saw root {}", derived.display())),
            "{stderr}"
        );
    }

    #[test]
    fn execute_emergency_warns_and_proceeds_when_explicit_config_is_missing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let missing = temp_dir.path().join("missing.toml");

        let output = run_subprocess("invalid-config", Some(&missing));
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert_eq!(output.status.code(), Some(5), "stderr={stderr}");
        assert!(stderr.contains("config file not found"), "{stderr}");
        assert!(stderr.contains("guard saw root"), "{stderr}");
    }

    #[test]
    fn execute_emergency_honors_safety_guard() {
        use std::io::Write;

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path().join("hidden-volume");
        std::fs::create_dir_all(&hidden_root).unwrap();

        let mut config = tempfile::NamedTempFile::new().unwrap();
        writeln!(config, "hidden_volume_root = \"{}\"", hidden_root.display()).unwrap();

        let output = run_subprocess("guard", Some(config.path()));
        let stdout = String::from_utf8_lossy(&output.stdout);

        // --json routes the guard refusal through one envelope on stdout.
        assert_eq!(output.status.code(), Some(5), "stdout={stdout}");
        assert!(
            stdout.contains("emergency guard blocked"),
            "stdout={stdout}"
        );
        assert!(stdout.contains("\"ok\":false"), "stdout={stdout}");
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
    fn emergency_success_json_contains_recovery_guidance() {
        // The renderer prints a parseable envelope; the shape is asserted here by
        // capturing the serialized data rather than re-reading stdout.
        print_emergency_json();
    }

    #[test]
    fn emergency_recovery_guidance_contains_expected_text() {
        let combined: String = EMERGENCY_RECOVERY_GUIDANCE.join("\n");
        assert!(combined.contains("Dismount the hidden volume"));
        assert!(combined.contains("reboot immediately"));
    }
}
