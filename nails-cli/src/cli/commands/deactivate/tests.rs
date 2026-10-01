use super::{
    DEACTIVATE_RECOVERY_GUIDANCE, deactivate_recovery_guidance, deactivate_success_json, execute,
};
use crate::cli::args::DeactivateArgs;
use crate::cli::output::{OutputMode, OutputSettings};
use nails_core::Verbosity;
use nails_core::constants::{ENV_FORCE_DETACH, ENV_SKIP_DETACH};
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
        .env(ENV_SKIP_DETACH, "1");

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
        .env(ENV_SKIP_DETACH, "1")
        .env_remove("NAILS_DETACHED");

    if let Some(path) = config_path {
        command.env("NAILS_DEACTIVATE_SUBPROCESS_CONFIG", path);
    }

    for attempt in 0..5 {
        match command.output() {
            Ok(output) => return output,
            Err(err) if err.kind() == std::io::ErrorKind::ExecutableFileBusy && attempt < 4 => {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(err) => panic!("failed to run deactivate runtime subprocess test: {err}"),
        }
    }

    unreachable!("exhausted executable-file-busy retry loop")
}

#[test]
fn subprocess_deactivate_entrypoint() {
    let Ok(case) = std::env::var("NAILS_DEACTIVATE_SUBPROCESS_CASE") else {
        return;
    };

    let config_override = std::env::var_os("NAILS_DEACTIVATE_SUBPROCESS_CONFIG").map(PathBuf::from);

    fn allow_real_ops(_: &std::path::Path) -> Result<(), String> {
        Ok(())
    }

    fn reject_real_ops(_: &std::path::Path) -> Result<(), String> {
        Err("real operations blocked for test".to_string())
    }

    fn report_root(root: &std::path::Path) -> Result<(), String> {
        Err(format!("guard saw root {}", root.display()))
    }

    // Make the config warning visible on stderr, as the binary's subscriber does.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .without_time()
        .try_init();

    let keep_history = DeactivateArgs {
        no_clear_history: true,
    };
    let json_debug = OutputSettings {
        verbosity: Verbosity::Debug,
        mode: OutputMode::Json,
        ascii: true,
        ..OutputSettings::default()
    };
    let with_verbosity = |verbosity| OutputSettings {
        verbosity,
        ..OutputSettings::default()
    };
    let config = config_override.as_deref();

    match case.as_str() {
        "invalid-config" => execute(
            &OutputSettings::default(),
            &DeactivateArgs::default(),
            config,
            report_root,
        ),
        "inactive-error" | "runtime-inactive-error" | "detach-error-json" => {
            execute(&json_debug, &keep_history, config, allow_real_ops)
        }
        "detach-error-human" => execute(
            &OutputSettings::default(),
            &DeactivateArgs::default(),
            config,
            allow_real_ops,
        ),
        "real-ops-blocked" => execute(
            &OutputSettings::default(),
            &DeactivateArgs::default(),
            config,
            reject_real_ops,
        ),
        "real-ops-blocked-quiet" => execute(
            &with_verbosity(Verbosity::Quiet),
            &DeactivateArgs::default(),
            config,
            reject_real_ops,
        ),
        "real-ops-blocked-verbose" => execute(
            &with_verbosity(Verbosity::Verbose),
            &DeactivateArgs::default(),
            config,
            reject_real_ops,
        ),
        other => panic!("unknown deactivate subprocess case: {other}"),
    }
}

#[test]
fn execute_deactivate_warns_and_proceeds_with_defaults_for_invalid_config() {
    use std::io::Write;

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config,
        "hidden_volume_root = \"/elsewhere\"\nnixos_flak = \"x\""
    )
    .unwrap();

    let output = run_subprocess("invalid-config", Some(config.path()));
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Exit 2 comes from the safety guard, which runs only after config loading
    // has fallen back to defaults instead of refusing.
    assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
    assert!(stderr.contains("did you mean `nixos_flake`?"), "{stderr}");
    assert!(stderr.contains("continuing with defaults"), "{stderr}");
    let derived = nails_core::config::derive_hidden_volume_root();
    assert!(
        stderr.contains(&format!("guard saw root {}", derived.display())),
        "{stderr}"
    );
    assert_eq!(
        stderr.matches("continuing with defaults").count(),
        1,
        "exactly one warning line: {stderr}"
    );
}

#[test]
fn execute_deactivate_warns_and_proceeds_when_explicit_config_is_missing() {
    let temp_dir = tempfile::tempdir().unwrap();
    let missing = temp_dir.path().join("missing.toml");

    let output = run_subprocess("invalid-config", Some(&missing));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
    assert!(stderr.contains("config file not found"), "{stderr}");
    assert!(stderr.contains("guard saw root"), "{stderr}");
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
        "hidden_volume_root = \"{}\"\noverlays = []",
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
        "hidden_volume_root = \"{}\"\noverlays = []",
        hidden_root.display()
    )
    .unwrap();

    let output = run_runtime_subprocess("runtime-inactive-error", Some(config.path()));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(1), "stderr={stderr}");
    assert!(
        !stderr.contains("Failed to execute systemd-run") && !stderr.contains("systemd-run failed"),
        "runtime-safe deactivate path must not attempt transient-unit detach: {stderr}"
    );
}

#[test]
fn execute_deactivate_reports_detach_error_as_json() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config,
        "hidden_volume_root = \"{}\"\noverlays = []",
        hidden_root.display()
    )
    .unwrap();

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
        .env("NAILS_DEACTIVATE_SUBPROCESS_CASE", "detach-error-json")
        .env(ENV_FORCE_DETACH, "1")
        .env("NAILS_DEACTIVATE_SUBPROCESS_CONFIG", config.path())
        .env_remove(ENV_SKIP_DETACH)
        .output()
        .expect("failed to run deactivate subprocess test");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
    assert!(stderr.contains("\"status\":\"error\""));
    assert!(stderr.contains("Refusing to start transient systemd units"));
}

#[test]
fn execute_deactivate_reports_detach_error_in_human_output() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config,
        "hidden_volume_root = \"{}\"\noverlays = []",
        hidden_root.display()
    )
    .unwrap();

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
        .env("NAILS_DEACTIVATE_SUBPROCESS_CASE", "detach-error-human")
        .env(ENV_FORCE_DETACH, "1")
        .env("NAILS_DEACTIVATE_SUBPROCESS_CONFIG", config.path())
        .env_remove(ENV_SKIP_DETACH)
        .output()
        .expect("failed to run deactivate subprocess test");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
    assert!(stderr.contains("Error: Invalid state: Refusing to start transient systemd units"));
}

#[test]
fn execute_deactivate_blocks_disallowed_real_operations_before_manager_creation() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config,
        "hidden_volume_root = \"{}\"\noverlays = []",
        hidden_root.display()
    )
    .unwrap();

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
        .env("NAILS_DEACTIVATE_SUBPROCESS_CASE", "real-ops-blocked")
        .env("NAILS_DEACTIVATE_SUBPROCESS_CONFIG", config.path())
        .env(ENV_SKIP_DETACH, "1")
        .output()
        .expect("failed to run deactivate subprocess test");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
    assert!(stderr.contains("real operations blocked for test"));
}

#[test]
fn execute_deactivate_blocks_disallowed_real_operations_in_quiet_mode() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config,
        "hidden_volume_root = \"{}\"\noverlays = []",
        hidden_root.display()
    )
    .unwrap();

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
        .env("NAILS_DEACTIVATE_SUBPROCESS_CASE", "real-ops-blocked-quiet")
        .env("NAILS_DEACTIVATE_SUBPROCESS_CONFIG", config.path())
        .env(ENV_SKIP_DETACH, "1")
        .output()
        .expect("failed to run deactivate subprocess test");

    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn execute_deactivate_blocks_disallowed_real_operations_with_verbose_mode() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config,
        "hidden_volume_root = \"{}\"\noverlays = []",
        hidden_root.display()
    )
    .unwrap();

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
        .env(
            "NAILS_DEACTIVATE_SUBPROCESS_CASE",
            "real-ops-blocked-verbose",
        )
        .env("NAILS_DEACTIVATE_SUBPROCESS_CONFIG", config.path())
        .env(ENV_SKIP_DETACH, "1")
        .output()
        .expect("failed to run deactivate subprocess test");

    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn deactivate_ascii_recovery_guidance_is_ascii_only() {
    let settings = OutputSettings {
        ascii: true,
        ..OutputSettings::default()
    };
    let combined = deactivate_recovery_guidance(&settings).join("\n");

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

#[test]
fn deactivate_recovery_guidance_default_mode_uses_unicode_warning_text() {
    let combined = deactivate_recovery_guidance(&OutputSettings::default()).join("\n");

    assert!(combined.contains("⚠ Important"));
    assert!(combined.contains("hidden volume is dismounted"));
}
