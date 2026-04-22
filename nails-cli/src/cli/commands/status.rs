//! Status command handler

use crate::cli::output;
use std::io::Write;
use std::path::PathBuf;

/// Execute the status command
///
/// Shows current system status and uptime.
///
/// # Arguments
///
/// * `config_override` - Optional config file path override
/// * `json` - Output results in JSON format
/// * `no_color` - Disable colored output
/// * `plain` - ASCII-only output (no Unicode symbols)
/// * `verbose` - Display detailed overlay mount information
///
/// # Returns
///
/// Never returns - exits with code 0 for status results, 2 for config load failures
pub fn execute(
    config_override: Option<PathBuf>,
    json: bool,
    no_color: bool,
    plain: bool,
    verbose: bool,
) -> ! {
    use nails_core::{NailsError, RealFilesystem, StatusCommand, status::SecurityPosture};

    // Configure color output (must be done before any colored output)
    // Story 14.7: Integrate output module with NO_COLOR/--no-color/--plain support
    // Note: set_plain_mode() already handles colored::control::set_override()
    nails_core::set_plain_mode(plain);
    nails_core::set_color_enabled(
        !(plain
            || no_color
            || std::env::var("NO_COLOR").is_ok()
            || std::env::var(nails_core::obfuscate::env_no_color()).is_ok()),
    );

    // Load configuration (Story 14.1)
    let config_path = nails_core::config::discover_config_path(config_override.as_deref());

    let mut config = super::load_config_or_exit(&config_path, config_override.as_deref());
    config.loaded_config_path = config_override
        .clone()
        .or_else(|| Some(config_path.clone()));

    let state_path = config.state_file_path.clone();
    let hidden_volume_root = config.hidden_volume_root.clone();
    let log_path = config.log_path.clone();

    // Create StatusCommand and run
    let filesystem = RealFilesystem;
    let command = StatusCommand::new(filesystem, config, state_path.clone());

    // Preserve FR63 for status collection/runtime failures after config is loaded.
    let report = match command.run() {
        Ok(report) => report,
        // FIX #4 & #7: Better error context with specific messages
        Err(e) => {
            // State file error - show INACTIVE status with error details
            // FR63: Status always succeeds (exit code 0)
            let error_msg = match e {
                NailsError::IoError(ref io_err) => {
                    if io_err.kind() == std::io::ErrorKind::NotFound {
                        format!("State file not found: {}", state_path.display())
                    } else {
                        format!(
                            "I/O error reading state file {}: {}",
                            state_path.display(),
                            io_err
                        )
                    }
                }
                NailsError::PermissionDenied(ref msg) => {
                    format!(
                        "Permission denied accessing state file {}: {}",
                        state_path.display(),
                        msg
                    )
                }
                NailsError::ConfigError(ref msg) => {
                    format!(
                        "State file corrupted or invalid at {}: {}",
                        state_path.display(),
                        msg
                    )
                }
                _ => {
                    format!("Error reading state file {}: {}", state_path.display(), e)
                }
            };

            // FIX #5: Use SecurityPosture constant instead of duplicated strings
            let posture = SecurityPosture::Decoy;

            if json {
                println!(
                    "{{\"state\":\"INACTIVE\",\"security_posture\":\"decoy\",\"error\":\"{}\"}}",
                    error_msg.replace('"', "\\\"")
                );
            } else if plain {
                println!("=== NAILS Status Report ===");
                println!();
                println!("State:              INACTIVE");
                println!("Security Posture:   {}", posture.to_plain());
                println!();
                println!("Error: {}", error_msg);
                println!();
                println!("Run 'nails activate' to mount hidden environment");
            } else {
                println!("╭─────────────────────────────────────╮");
                println!("│  NAILS Status Report                │");
                println!("╰─────────────────────────────────────╯");
                println!();
                println!("State:              INACTIVE");
                println!("Security Posture:   {}", posture);
                println!();
                println!("Error: {}", error_msg);
                println!();
                println!("Run 'nails activate' to mount hidden environment");
            }
            let _ = std::io::stdout().flush();
            std::process::exit(0); // FR63: Always exit 0
        }
    };

    // Format output based on flags
    if json {
        output::print_status_json(&report);
    } else if plain {
        output::print_status_ascii(
            &report,
            verbose,
            &config_path,
            &state_path,
            &hidden_volume_root,
            &log_path,
        );
    } else {
        output::print_status_human(
            &report,
            verbose,
            &config_path,
            &state_path,
            &hidden_volume_root,
            &log_path,
        );
    }

    // FR63: Status always succeeds (exit code 0)
    let _ = std::io::stdout().flush();
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::execute;
    use std::path::PathBuf;

    const SUBPROCESS_TEST_NAME: &str = "cli::commands::status::tests::subprocess_status_entrypoint";

    fn run_subprocess(case: &str, config_path: Option<&std::path::Path>) -> std::process::Output {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
            .env("NAILS_STATUS_SUBPROCESS_CASE", case);

        if let Some(path) = config_path {
            command.env("NAILS_STATUS_SUBPROCESS_CONFIG", path);
        }

        command
            .output()
            .expect("failed to run status subprocess test")
    }

    fn run_subprocess_with_env(
        case: &str,
        config_path: Option<&std::path::Path>,
        envs: &[(&str, &str)],
    ) -> std::process::Output {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
            .env("NAILS_STATUS_SUBPROCESS_CASE", case);

        if let Some(path) = config_path {
            command.env("NAILS_STATUS_SUBPROCESS_CONFIG", path);
        }

        for (key, value) in envs {
            command.env(key, value);
        }

        command
            .output()
            .expect("failed to run status subprocess test")
    }

    #[test]
    fn subprocess_status_entrypoint() {
        let Ok(case) = std::env::var("NAILS_STATUS_SUBPROCESS_CASE") else {
            return;
        };

        let config_override = std::env::var_os("NAILS_STATUS_SUBPROCESS_CONFIG").map(PathBuf::from);

        match case.as_str() {
            "plain" => execute(config_override, false, false, true, true),
            "json" => execute(config_override, true, false, false, false),
            "no-color" => execute(config_override, false, true, false, true),
            "invalid-config" => execute(config_override, false, false, false, false),
            other => panic!("unknown status subprocess case: {other}"),
        }
    }

    #[test]
    fn execute_status_plain_mode_succeeds_with_missing_state_file() {
        use std::io::Write;

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path().join("hidden-volume");
        std::fs::create_dir_all(&hidden_root).unwrap();
        let state_path = hidden_root.join("state.json");

        let mut config = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            config,
            "hidden_volume_path: {}\nstate_file_path: {}\noverlays: []",
            hidden_root.display(),
            state_path.display()
        )
        .unwrap();

        let output = run_subprocess("plain", Some(config.path()));
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "stdout={stdout}");
        assert!(stdout.contains("State:"));
        assert!(
            stdout.contains("Security Posture:") || stdout.contains("security_posture"),
            "stdout={stdout}"
        );
    }

    #[test]
    fn execute_status_json_mode_succeeds() {
        use std::io::Write;

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path().join("hidden-volume");
        std::fs::create_dir_all(&hidden_root).unwrap();

        let mut config = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            config,
            "hidden_volume_path: {}\noverlays: []",
            hidden_root.display()
        )
        .unwrap();

        let output = run_subprocess("json", Some(config.path()));
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "stdout={stdout}");
        assert!(stdout.contains("\"state\""));
        assert!(stdout.contains("\"security_posture\""));
    }

    #[test]
    fn execute_status_no_color_keeps_unicode_without_ansi() {
        use std::io::Write;

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path().join("hidden-volume");
        std::fs::create_dir_all(&hidden_root).unwrap();
        let state_path = hidden_root.join("state.json");

        let mut config = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            config,
            "hidden_volume_path: {}\nstate_file_path: {}\noverlays: []",
            hidden_root.display(),
            state_path.display()
        )
        .unwrap();

        let output = run_subprocess("no-color", Some(config.path()));
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "stdout={stdout}");
        assert!(stdout.contains("🟢") || stdout.contains("🟡") || stdout.contains("🔴"));
        assert!(!stdout.contains("\u{001b}"), "stdout={stdout}");
    }

    #[test]
    fn execute_status_no_color_env_keeps_unicode_without_ansi() {
        use std::io::Write;

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path().join("hidden-volume");
        std::fs::create_dir_all(&hidden_root).unwrap();
        let state_path = hidden_root.join("state.json");

        let mut config = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            config,
            "hidden_volume_path: {}\nstate_file_path: {}\noverlays: []",
            hidden_root.display(),
            state_path.display()
        )
        .unwrap();

        let output = run_subprocess_with_env("no-color", Some(config.path()), &[("NO_COLOR", "1")]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "stdout={stdout}");
        assert!(!stdout.is_ascii(), "stdout={stdout}");
        assert!(!stdout.contains("\u{001b}"), "stdout={stdout}");
    }

    #[test]
    fn execute_status_fails_closed_for_invalid_config() {
        use std::io::Write;

        let mut config = tempfile::NamedTempFile::new().unwrap();
        writeln!(config, "hidden_volume_path: [broken").unwrap();

        let output = run_subprocess("invalid-config", Some(config.path()));
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
        assert!(stderr.contains("Error loading config"));
        assert!(stderr.contains("Invalid YAML"));
    }
}
