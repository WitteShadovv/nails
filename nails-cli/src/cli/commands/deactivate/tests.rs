// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::{deactivate_recovery_guidance, execute};
use crate::cli::args::DeactivateArgs;
use crate::cli::output::deactivate::DEACTIVATE_RECOVERY_GUIDANCE;
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
        .env(ENV_SKIP_DETACH, "1")
        // The temp hidden roots share `/`'s device; declare them attached so the
        // state lock (which refuses an unmounted hidden root) admits them.
        .env("NAILS_TEST_FORCE_ATTACHED", "1");

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

    // The child stands in for the CLI entry point: it reads the environment the
    // parent prepared on the `Command` exactly once and installs it, as `main`
    // does.
    let env = nails_core::RuntimeEnv::from_process_env();
    nails_core::runtime_env::install(env.clone());

    let execute =
        |settings: &OutputSettings, args: &DeactivateArgs, config: Option<&std::path::Path>| {
            execute(settings, &env, args, config)
        };

    let config_override = std::env::var_os("NAILS_DEACTIVATE_SUBPROCESS_CONFIG").map(PathBuf::from);

    // Make the config warning visible on stderr, as the binary's subscriber does.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .without_time()
        .try_init();

    let keep_history = DeactivateArgs {
        no_clear_history: true,
        yes: true,
    };
    let confirmed = DeactivateArgs {
        yes: true,
        ..DeactivateArgs::default()
    };
    let json_debug = OutputSettings {
        verbosity: Verbosity::Debug,
        mode: OutputMode::Json,
        ascii: true,
        ..OutputSettings::default()
    };
    let config = config_override.as_deref();

    let status = match case.as_str() {
        "invalid-config" => execute(
            &OutputSettings::default(),
            &DeactivateArgs::default(),
            config,
        ),
        "inactive-error" | "runtime-inactive-error" | "detach-error-json" => {
            execute(&json_debug, &keep_history, config)
        }
        "detach-error-human" => execute(&OutputSettings::default(), &confirmed, config),
        "reboot-guidance-order" => execute(&OutputSettings::default(), &confirmed, config),
        "needs-confirmation-off-tty" => execute(
            &OutputSettings::default(),
            &DeactivateArgs::default(),
            config,
        ),
        other => panic!("unknown deactivate subprocess case: {other}"),
    };
    crate::cli::detach::exit_process(status.code());
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

    // A broken config never blocks returning to the decoy: it falls back to
    // defaults with a warning and proceeds to the confirmation gate, which off a
    // terminal refuses with exit 2 before any teardown.
    assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
    assert!(stderr.contains("did you mean `nixos_flake`?"), "{stderr}");
    assert!(stderr.contains("continuing with defaults"), "{stderr}");
    assert!(stderr.contains("stdin is not a terminal"), "{stderr}");
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

    // Missing config also falls back to defaults and proceeds to the confirmation
    // gate, which refuses off a terminal with exit 2.
    assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
    assert!(stderr.contains("config file not found"), "{stderr}");
    assert!(stderr.contains("stdin is not a terminal"), "{stderr}");
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
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout={stdout} stderr={stderr}"
    );
    assert!(stdout.contains("\"ok\":false"), "stdout={stdout}");
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

    let stdout = String::from_utf8_lossy(&output.stdout);

    // The envelope for a --json failure is one document on stdout.
    assert_eq!(output.status.code(), Some(1), "stdout={stdout}");
    assert!(stdout.contains("\"ok\":false"), "stdout={stdout}");
    assert!(stdout.contains("\"code\":\"detach\""), "stdout={stdout}");
    assert!(
        stdout.contains("Refusing to start transient systemd units"),
        "stdout={stdout}"
    );
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

    assert_eq!(output.status.code(), Some(1), "stderr={stderr}");
    assert!(stderr.contains("error: Invalid state: Refusing to start transient systemd units"));
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

#[test]
fn execute_deactivate_refuses_off_tty_without_yes_before_any_teardown() {
    use std::io::Write;

    // The confirmation gate is what must stop the reboot: without -y and without
    // a terminal it refuses before unmounting, restoring or rebooting anything.
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

    let output = run_subprocess("needs-confirmation-off-tty", Some(config.path()));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
    assert!(
        stderr.contains("stdin is not a terminal"),
        "stderr={stderr}"
    );
}

#[test]
fn execute_deactivate_emits_recovery_guidance_before_the_reboot_handoff() {
    use std::io::Write;

    // The core deactivation reboots as its last step, so the CLI must print the
    // recovery guidance before handing off to it. With an inactive hidden root
    // the handoff fails instead of rebooting, which lets this test observe that
    // the guidance was already on stderr before that outcome.
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

    let output = run_subprocess("reboot-guidance-order", Some(config.path()));
    let stderr = String::from_utf8_lossy(&output.stderr);

    let guidance_at = stderr
        .find("Important")
        .unwrap_or_else(|| panic!("recovery guidance missing from stderr: {stderr}"));
    let outcome_at = stderr
        .find("error:")
        .unwrap_or_else(|| panic!("deactivation outcome missing from stderr: {stderr}"));
    assert!(
        guidance_at < outcome_at,
        "guidance must precede the deactivation handoff: {stderr}"
    );
    assert!(
        stderr.contains("hidden volume is dismounted"),
        "stderr={stderr}"
    );
}
