//! Deactivate command handler

use std::path::PathBuf;

use crate::cli::detach::maybe_detach_for_deactivation;

/// Execute the deactivate command
///
/// Deactivate and return to decoy state (unmount + cleanup).
///
/// # Arguments
///
/// * `config_override` - Optional config file path override
/// * `no_clear_history` - Skip shell history cleanup
/// * `quiet` - Suppress output except errors
/// * `verbose` - Verbosity level (0 = normal, 1 = verbose, 2+ = debug)
/// * `json` - Output results in JSON format
/// * `no_color` - Disable colored output
/// * `plain` - ASCII-only output (no Unicode symbols)
///
/// # Returns
///
/// Never returns - exits with code 0 on success, 1 on deactivation failure, 2 on config failure
#[allow(clippy::too_many_arguments)]
pub fn execute(
    config_override: Option<PathBuf>,
    no_clear_history: bool,
    quiet: bool,
    verbose: u8,
    json: bool,
    no_color: bool,
    plain: bool,
    check_real_ops: impl Fn(&std::path::Path) -> Result<(), String>,
) -> ! {
    use nails_core::{NailsManager, RealFilesystem, Verbosity};
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

    // Load configuration
    let config_path = nails_core::config::discover_config_path(config_override.as_deref());
    let mut config = super::load_config_or_exit(&config_path, config_override.as_deref());
    config.loaded_config_path = config_override
        .clone()
        .or_else(|| Some(config_path.clone()));

    // Apply --no-clear-history CLI override
    if no_clear_history {
        config.clear_history = false;
    }

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
    super::lock_manager_or_exit(&manager, "setting deactivation verbosity")
        .set_verbosity(verbosity);

    if let Err(e) = maybe_detach_for_deactivation() {
        if !json {
            eprintln!("Error: {}", e);
        } else {
            eprintln!("{{\"status\":\"error\",\"message\":\"{}\"}}", e);
        }
        std::process::exit(2);
    }

    // Run quick deactivation (restore symlink + reboot)
    match NailsManager::deactivate(Arc::clone(&manager)) {
        Ok(()) => {
            // Success - system will reboot
            if !json {
                let success_prefix = if plain { "[PASS]" } else { "✓" };
                println!("{success_prefix} System configuration restored");
                println!("  Rebooting to decoy environment...");
                eprintln!();
                for line in deactivate_recovery_guidance(plain) {
                    eprintln!("{line}");
                }
            } else {
                println!("{}", deactivate_success_json());
            }
            // Note: Reboot command was already issued, this code may not execute
            std::process::exit(0);
        }
        Err(e) => {
            if !json {
                let error_prefix = if plain { "[FAIL]" } else { "✗" };
                eprintln!("{error_prefix} Deactivation failed: {}", e);
            } else {
                eprintln!("{{\"status\":\"error\",\"message\":\"{}\"}}", e);
            }
            std::process::exit(1);
        }
    }
}

/// Build the JSON success response for deactivation
fn deactivate_success_json() -> String {
    r#"{"status":"success","message":"Rebooting to decoy configuration","recovery_guidance":["Dismount hidden volume","Reboot to ensure clean state"]}"#.to_string()
}

/// Recovery guidance lines for human-readable deactivation output
const DEACTIVATE_RECOVERY_GUIDANCE: &[&str] = &[
    "⚠ Important: Hidden storage may still be mounted. Your system is not in a fully safe state until:",
    "  1. The hidden volume is dismounted",
    "  2. The system is rebooted",
];

const DEACTIVATE_RECOVERY_GUIDANCE_PLAIN: &[&str] = &[
    "[WARN] Important: Hidden storage may still be mounted. Your system is not in a fully safe state until:",
    "  1. The hidden volume is dismounted",
    "  2. The system is rebooted",
];

fn deactivate_recovery_guidance(plain: bool) -> &'static [&'static str] {
    if plain {
        DEACTIVATE_RECOVERY_GUIDANCE_PLAIN
    } else {
        DEACTIVATE_RECOVERY_GUIDANCE
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEACTIVATE_RECOVERY_GUIDANCE, deactivate_recovery_guidance, deactivate_success_json,
        execute,
    };
    use nails_core::obfuscate;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    const SUBPROCESS_TEST_NAME: &str =
        "cli::commands::deactivate::tests::subprocess_deactivate_entrypoint";

    fn copy_current_exe_outside_deps(temp_dir: &std::path::Path) -> PathBuf {
        let copied = temp_dir.join("deactivate-runtime-helper");
        std::fs::copy(std::env::current_exe().unwrap(), &copied).unwrap();

        let mut permissions = std::fs::metadata(&copied).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&copied, permissions).unwrap();

        copied
    }

    fn run_subprocess(case: &str, config_path: Option<&std::path::Path>) -> std::process::Output {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
            .env("NAILS_DEACTIVATE_SUBPROCESS_CASE", case)
            .env(obfuscate::env_skip_detach(), "1");

        if let Some(path) = config_path {
            command.env("NAILS_DEACTIVATE_SUBPROCESS_CONFIG", path);
        }

        command
            .output()
            .expect("failed to run deactivate subprocess test")
    }

    fn run_runtime_subprocess(
        case: &str,
        config_path: Option<&std::path::Path>,
    ) -> std::process::Output {
        let temp_dir = tempfile::tempdir().unwrap();
        let helper = copy_current_exe_outside_deps(temp_dir.path());

        let mut command = std::process::Command::new(helper);
        command
            .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
            .env("NAILS_DEACTIVATE_SUBPROCESS_CASE", case)
            .env("NAILS_TEST_RUNTIME", "1")
            .env(obfuscate::env_skip_detach(), "1")
            .env_remove("NAILS_DETACHED");

        if let Some(path) = config_path {
            command.env("NAILS_DEACTIVATE_SUBPROCESS_CONFIG", path);
        }

        command
            .output()
            .expect("failed to run deactivate runtime subprocess test")
    }

    #[test]
    fn subprocess_deactivate_entrypoint() {
        let Ok(case) = std::env::var("NAILS_DEACTIVATE_SUBPROCESS_CASE") else {
            return;
        };

        let config_override =
            std::env::var_os("NAILS_DEACTIVATE_SUBPROCESS_CONFIG").map(PathBuf::from);

        fn allow_real_ops(_: &std::path::Path) -> Result<(), String> {
            Ok(())
        }

        match case.as_str() {
            "invalid-config" => execute(
                config_override,
                false,
                false,
                0,
                false,
                false,
                false,
                allow_real_ops,
            ),
            "inactive-error" => execute(
                config_override,
                true,
                false,
                2,
                true,
                true,
                true,
                allow_real_ops,
            ),
            "runtime-inactive-error" => execute(
                config_override,
                true,
                false,
                2,
                true,
                true,
                true,
                allow_real_ops,
            ),
            other => panic!("unknown deactivate subprocess case: {other}"),
        }
    }

    #[test]
    fn execute_deactivate_fails_closed_for_invalid_config() {
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
    fn execute_deactivate_reports_inactive_error_path() {
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

        let output = run_subprocess("inactive-error", Some(config.path()));
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert_eq!(output.status.code(), Some(1), "stderr={stderr}");
        assert!(stderr.contains("status") || stderr.contains("error") || stderr.contains("failed"));
    }

    #[test]
    fn execute_deactivate_runtime_safety_skips_transient_unit_handoff() {
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

        let output = run_runtime_subprocess("runtime-inactive-error", Some(config.path()));
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert_eq!(output.status.code(), Some(1), "stderr={stderr}");
        assert!(
            !stderr.contains("Failed to execute systemd-run")
                && !stderr.contains("systemd-run failed"),
            "runtime-safe deactivate path must not attempt transient-unit detach: {stderr}"
        );
    }

    #[test]
    fn deactivate_plain_recovery_guidance_is_ascii_only() {
        let combined = deactivate_recovery_guidance(true).join("\n");

        assert!(combined.is_ascii(), "guidance={combined}");
        assert!(combined.contains("[WARN]"));
    }

    #[test]
    fn deactivate_success_json_contains_recovery_guidance() {
        let json_str = deactivate_success_json();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["status"], "success");
        let guidance = parsed["recovery_guidance"].as_array().unwrap();
        assert_eq!(guidance.len(), 2);
        assert!(guidance[0].as_str().unwrap().contains("Dismount"));
        assert!(guidance[1].as_str().unwrap().contains("Reboot"));
    }

    #[test]
    fn deactivate_recovery_guidance_contains_expected_text() {
        let combined: String = DEACTIVATE_RECOVERY_GUIDANCE.join("\n");
        assert!(combined.contains("hidden volume is dismounted"));
        assert!(combined.contains("system is rebooted"));
    }
}
