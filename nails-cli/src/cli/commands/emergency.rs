//! Emergency command handler

use std::path::PathBuf;

/// Execute the emergency command
///
/// Rapid deactivation with countdown.
///
/// # Arguments
///
/// * `config_override` - Optional config file path override
/// * `no_countdown` - Skip the 3-second countdown (proceed immediately)
/// * `quiet` - Suppress output except final result
/// * `verbose` - Verbosity level (0 = normal, 1 = verbose, 2+ = debug)
/// * `json` - Output results in JSON format
/// * `no_color` - Disable colored output
/// * `plain` - ASCII-only output (no Unicode symbols)
///
/// # Returns
///
/// Never returns - exits with code 0 on success, 1 on failure, 2 on config or safety guard failures
#[allow(clippy::too_many_arguments)]
pub fn execute(
    config_override: Option<PathBuf>,
    no_countdown: bool,
    quiet: bool,
    verbose: u8,
    json: bool,
    no_color: bool,
    plain: bool,
    check_real_ops: impl Fn(&std::path::Path) -> Result<(), String>,
) -> ! {
    use nails_core::{NailsManager, RealFilesystem, Verbosity, emergency_deactivate};
    use std::sync::{Arc, Mutex};

    // Configure color output
    nails_core::set_plain_mode(plain);
    nails_core::set_color_enabled(
        !(plain
            || no_color
            || std::env::var("NO_COLOR").is_ok()
            || std::env::var(nails_core::obfuscate::env_no_color()).is_ok()),
    );

    // Convert CLI flags to Verbosity enum
    let verbosity = if quiet {
        Verbosity::Quiet
    } else {
        match verbose {
            0 => Verbosity::Normal,
            1 => Verbosity::Verbose,
            _ => Verbosity::Debug,
        }
    };

    // Load config
    let config_path = nails_core::config::discover_config_path(config_override.as_deref());
    let mut config = super::load_config_or_exit(&config_path, config_override.as_deref());
    config.loaded_config_path = config_override
        .clone()
        .or_else(|| Some(config_path.clone()));

    // TEST SAFETY GUARD
    if let Err(msg) = check_real_ops(&config.hidden_volume_root) {
        eprintln!("{}", msg);
        std::process::exit(2);
    }

    let state_path = config.state_file_path.clone();

    // Create manager
    let filesystem = RealFilesystem;
    let manager = Arc::new(Mutex::new(NailsManager::new(
        filesystem, config, state_path,
    )));
    super::lock_manager_or_exit(&manager, "setting emergency deactivation verbosity")
        .set_verbosity(verbosity);

    // Countdown before emergency deactivation (skip if --no-countdown, --quiet, or --json)
    if !no_countdown && !quiet && !json {
        use std::io::Write;

        for i in (1..=3).rev() {
            eprint!("\r  Emergency deactivation in {}... ", i);
            let _ = std::io::stderr().flush();
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        eprintln!("\r  Emergency deactivation starting now!  ");
    }

    // Run emergency deactivation
    match emergency_deactivate(Arc::clone(&manager)) {
        Ok(()) => {
            if !json {
                let success_prefix = if plain { "[PASS]" } else { "✓" };
                println!("{success_prefix} Emergency deactivation complete");
                println!("  System returned to decoy configuration");
                eprintln!();
                for line in emergency_recovery_guidance(plain) {
                    eprintln!("{line}");
                }
            } else {
                println!("{}", emergency_success_json());
            }
            std::process::exit(0);
        }
        Err(e) => {
            if !json {
                let error_prefix = if plain { "[FAIL]" } else { "✗" };
                eprintln!("{error_prefix} Emergency deactivation failed: {}", e);
            } else {
                eprintln!("{{\"status\":\"error\",\"message\":\"{}\"}}", e);
            }
            std::process::exit(1);
        }
    }
}

/// Build the JSON success response for emergency deactivation
fn emergency_success_json() -> String {
    r#"{"status":"success","message":"Emergency deactivation complete","recovery_guidance":["Dismount the hidden volume when it is safe to do so","If you are unsure cleanup was complete, reboot immediately"]}"#.to_string()
}

/// Recovery guidance lines for human-readable emergency output
const EMERGENCY_RECOVERY_GUIDANCE: &[&str] = &[
    "⚠ Critical: For maximum safety:",
    "  1. Dismount the hidden volume when it is safe to do so",
    "  2. If you are unsure cleanup was complete, reboot immediately",
];

const EMERGENCY_RECOVERY_GUIDANCE_PLAIN: &[&str] = &[
    "[WARN] Critical: For maximum safety:",
    "  1. Dismount the hidden volume when it is safe to do so",
    "  2. If you are unsure cleanup was complete, reboot immediately",
];

fn emergency_recovery_guidance(plain: bool) -> &'static [&'static str] {
    if plain {
        EMERGENCY_RECOVERY_GUIDANCE_PLAIN
    } else {
        EMERGENCY_RECOVERY_GUIDANCE
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EMERGENCY_RECOVERY_GUIDANCE, emergency_recovery_guidance, emergency_success_json, execute,
    };
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

        match case.as_str() {
            "invalid-config" => {
                execute(config_override, true, false, 0, false, false, false, |_| {
                    Ok(())
                })
            }
            "guard" => execute(config_override, true, false, 1, true, true, true, |_| {
                Err("emergency guard blocked".to_string())
            }),
            other => panic!("unknown emergency subprocess case: {other}"),
        }
    }

    #[test]
    fn execute_emergency_fails_closed_for_invalid_config() {
        use std::io::Write;

        let mut config = tempfile::NamedTempFile::new().unwrap();
        writeln!(config, "hidden_volume_path: [broken").unwrap();

        let output = run_subprocess("invalid-config", Some(config.path()));
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
        assert!(stderr.contains("Error loading config"));
        assert!(stderr.contains("Invalid YAML"));
    }

    #[test]
    fn execute_emergency_honors_safety_guard() {
        use std::io::Write;

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path().join("hidden-volume");
        std::fs::create_dir_all(&hidden_root).unwrap();

        let mut config = tempfile::NamedTempFile::new().unwrap();
        writeln!(config, "hidden_volume_path: {}", hidden_root.display()).unwrap();

        let output = run_subprocess("guard", Some(config.path()));
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
        assert!(stderr.contains("emergency guard blocked"));
    }

    #[test]
    fn emergency_plain_recovery_guidance_is_ascii_only() {
        let combined = emergency_recovery_guidance(true).join("\n");

        assert!(combined.is_ascii(), "guidance={combined}");
        assert!(combined.contains("[WARN]"));
    }

    #[test]
    fn emergency_success_json_contains_recovery_guidance() {
        let json_str = emergency_success_json();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["status"], "success");
        let guidance = parsed["recovery_guidance"].as_array().unwrap();
        assert_eq!(guidance.len(), 2);
        assert!(guidance[0].as_str().unwrap().contains("Dismount"));
        assert!(guidance[1].as_str().unwrap().contains("reboot"));
    }

    #[test]
    fn emergency_recovery_guidance_contains_expected_text() {
        let combined: String = EMERGENCY_RECOVERY_GUIDANCE.join("\n");
        assert!(combined.contains("Dismount the hidden volume"));
        assert!(combined.contains("reboot immediately"));
    }
}
