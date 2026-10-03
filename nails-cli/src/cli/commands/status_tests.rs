use super::{execute, status_exit_code};
use crate::cli::args::StatusArgs;
use crate::cli::output::{ExitStatus, OutputMode, OutputSettings};
use nails_core::status::Posture;
use nails_core::test_support::EnvGuard;
use std::path::PathBuf;

#[test]
fn status_exit_code_is_driven_by_the_posture() {
    // Safe postures exit 0; the dangerous ones fail closed.
    assert_eq!(status_exit_code(Posture::Decoy), ExitStatus::Ok);
    assert_eq!(status_exit_code(Posture::Active), ExitStatus::Ok);
    // An in-progress transition is a safe, transient posture: exit 0, so a
    // concurrent `nails status` during activation does not report failure.
    assert_eq!(status_exit_code(Posture::Transitioning), ExitStatus::Ok);
    assert_eq!(
        status_exit_code(Posture::Degraded),
        ExitStatus::DegradedReboot
    );
    assert_eq!(
        status_exit_code(Posture::Inconsistent),
        ExitStatus::DegradedReboot
    );
    assert_eq!(status_exit_code(Posture::Unknown), ExitStatus::InvalidState);
}

const SUBPROCESS_TEST_NAME: &str = "cli::commands::status::tests::subprocess_status_entrypoint";

fn run_subprocess(case: &str, config_path: Option<&std::path::Path>) -> std::process::Output {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
        .env("NAILS_STATUS_SUBPROCESS_CASE", case);

    if let Some(path) = config_path {
        command.env("NAILS_STATUS_SUBPROCESS_CONFIG", path);
    }

    let _env = EnvGuard::lock();
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

    let config = config_override.as_deref();
    let details = StatusArgs { details: true };
    let status = match case.as_str() {
        "ascii" => execute(
            &OutputSettings {
                ascii: true,
                ..OutputSettings::default()
            },
            &details,
            config,
        ),
        "json" => execute(
            &OutputSettings {
                mode: OutputMode::Json,
                ..OutputSettings::default()
            },
            &StatusArgs::default(),
            config,
        ),
        "no-color" => execute(&OutputSettings::default(), &details, config),
        "invalid-config" => execute(&OutputSettings::default(), &StatusArgs::default(), config),
        other => panic!("unknown status subprocess case: {other}"),
    };
    crate::cli::detach::exit_process(status.code());
}

#[test]
fn execute_status_ascii_mode_succeeds_with_missing_state_file() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();
    let state_path = hidden_root.join("state.json");

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config,
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\noverlays = []",
        hidden_root.display(),
        state_path.display()
    )
    .unwrap();

    let output = run_subprocess("ascii", Some(config.path()));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout={stdout}");
    assert!(stdout.contains("State:"));
    assert!(stdout.contains("Security Posture:"), "stdout={stdout}");
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
        "hidden_volume_root = \"{}\"\noverlays = []",
        hidden_root.display()
    )
    .unwrap();

    let output = run_subprocess("json", Some(config.path()));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout={stdout}");
    assert!(stdout.contains("\"state\""));
    assert!(stdout.contains("\"posture\""));
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
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\noverlays = []",
        hidden_root.display(),
        state_path.display()
    )
    .unwrap();

    let output = run_subprocess("no-color", Some(config.path()));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout={stdout}");
    // A missing state file means the decoy is in use: neutral mark, not failure.
    assert!(stdout.contains("○ DECOY"), "stdout={stdout}");
    assert!(!stdout.contains("✗ DECOY"), "stdout={stdout}");
    assert!(!stdout.contains("\u{001b}"), "stdout={stdout}");
}

#[test]
fn execute_status_ascii_mode_is_ascii_only() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();
    let state_path = hidden_root.join("state.json");

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config,
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\noverlays = []",
        hidden_root.display(),
        state_path.display()
    )
    .unwrap();

    let output = run_subprocess("ascii", Some(config.path()));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout={stdout}");
    assert!(stdout.is_ascii(), "stdout={stdout}");
    assert!(stdout.contains("[DECOY]"), "stdout={stdout}");
    assert!(!stdout.contains('\u{001b}'), "stdout={stdout}");
}

#[test]
fn execute_status_fails_closed_for_invalid_config() {
    use std::io::Write;

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(config, "hidden_volume_root = [broken").unwrap();

    let output = run_subprocess("invalid-config", Some(config.path()));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(3), "stderr={stderr}");
    assert!(stderr.contains("invalid config"), "{stderr}");
    assert!(!stderr.contains("Example"), "no example dump: {stderr}");
}

#[test]
fn execute_status_permission_denied_reports_unknown_not_inactive() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let state_path = hidden_root.join("state.json");
    std::fs::create_dir_all(&hidden_root).unwrap();
    std::fs::write(&state_path, "{}\n").unwrap();

    let mut perms = std::fs::metadata(&state_path).unwrap().permissions();
    perms.set_mode(0o000);
    std::fs::set_permissions(&state_path, perms).unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config,
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\noverlays = []",
        hidden_root.display(),
        state_path.display()
    )
    .unwrap();

    let output = run_subprocess("ascii", Some(config.path()));

    let mut restore = std::fs::metadata(&state_path).unwrap().permissions();
    restore.set_mode(0o600);
    std::fs::set_permissions(&state_path, restore).unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    // An unreadable state file is an unknown posture: fail closed with code 6.
    assert_eq!(output.status.code(), Some(6), "stdout={stdout}");
    assert!(
        stdout.contains("State:              UNKNOWN"),
        "stdout={stdout}"
    );
    assert!(stdout.contains("Permission denied"), "stdout={stdout}");
    assert!(
        !stdout.contains("State:              INACTIVE"),
        "stdout={stdout}"
    );
}

#[test]
fn execute_status_no_color_verbose_reports_loaded_outcome() {
    use nails_core::{StateFile, SystemState};
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let state_path = hidden_root.join("state.json");
    std::fs::create_dir_all(&hidden_root).unwrap();

    // Write a sealed state file (valid integrity digest) so it loads cleanly.
    let state = StateFile {
        version: "0.0.5".to_string(),
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    state
        .save_with_custom_root(&state_path, &hidden_root)
        .unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config,
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\noverlays = []",
        hidden_root.display(),
        state_path.display()
    )
    .unwrap();

    let output = run_subprocess("no-color", Some(config.path()));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout={stdout}");
    assert!(stdout.contains("Details:"), "stdout={stdout}");
    assert!(
        stdout.contains("State loaded:       normal"),
        "stdout={stdout}"
    );
    assert!(!stdout.contains("\u{001b}"), "stdout={stdout}");
}

#[test]
fn execute_status_no_color_verbose_reports_corrupt_state() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let state_path = hidden_root.join("state.json");
    std::fs::create_dir_all(&hidden_root).unwrap();
    std::fs::write(&state_path, "{ definitely-not-json").unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config,
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\noverlays = []",
        hidden_root.display(),
        state_path.display()
    )
    .unwrap();

    let output = run_subprocess("no-color", Some(config.path()));
    let stdout = String::from_utf8_lossy(&output.stdout);

    // A corrupt state file is an unknown posture: fail closed with code 6.
    assert_eq!(output.status.code(), Some(6), "stdout={stdout}");
    assert!(stdout.contains("Details:"), "stdout={stdout}");
    assert!(
        stdout.contains("State loaded:       corrupt (state unknown, using defaults)"),
        "stdout={stdout}"
    );
    assert!(!stdout.contains("\u{001b}"), "stdout={stdout}");
}

#[test]
fn execute_status_no_color_verbose_active_shows_overlay_details_and_logs() {
    use nails_core::{OverlayInfo, StateFile, SystemState};
    use std::collections::HashMap;
    use std::io::Write;
    use std::path::PathBuf;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let log_dir = hidden_root.join("logs");
    let state_path = hidden_root.join("state.json");
    let mounted_at = chrono::Utc::now() - chrono::Duration::minutes(3);
    let activated_at = mounted_at - chrono::Duration::minutes(7);
    std::fs::create_dir_all(&log_dir).unwrap();

    let mut overlay_status = HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_method: Default::default(),
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/home"),
            upper_dir: hidden_root.join("overlays/home/upper"),
            work_dir: hidden_root.join("overlays/home/work"),
            mounted_at,
        },
    );
    let state = StateFile {
        state: SystemState::Active {
            activated_at,
            overlays: vec![PathBuf::from("/home")],
            decoy_writers: Vec::new(),
        },
        hidden_toplevel: Some("nails-gen-77".to_string()),
        overlay_status,
        ..StateFile::default()
    };
    state
        .save_with_custom_root(&state_path, &hidden_root)
        .unwrap();

    let mut log_file = std::fs::File::create(log_dir.join("nails.log")).unwrap();
    writeln!(
        log_file,
        r#"{{"timestamp":"{}","level":"DEBUG","fields":{{"message":"debug log visible"}}}}"#,
        chrono::Utc::now().to_rfc3339()
    )
    .unwrap();
    writeln!(
        log_file,
        r#"{{"timestamp":"{}","level":"INFO","fields":{{"message":"info log visible"}}}}"#,
        chrono::Utc::now().to_rfc3339()
    )
    .unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config,
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\nlog_path = \"{}\"\n[[overlays]]\nname = \"home\"\nlower = \"/home\"\nupper = \"{}/overlays/home/upper\"\nwork = \"{}/overlays/home/work\"\ntarget = \"/home\"",
        hidden_root.display(),
        state_path.display(),
        log_dir.display(),
        hidden_root.display(),
        hidden_root.display(),
    )
    .unwrap();

    let output = run_subprocess("no-color", Some(config.path()));
    let stdout = String::from_utf8_lossy(&output.stdout);

    // The recorded overlay is not a live NAILS overlay in this sandbox, so the
    // posture is degraded (exit 7); the details and logs are still shown.
    assert_eq!(output.status.code(), Some(7), "stdout={stdout}");
    assert!(
        stdout.contains("Hidden system:      nails-gen-77"),
        "stdout={stdout}"
    );
    assert!(stdout.contains("Overlay Mount Details:"), "stdout={stdout}");
    assert!(stdout.contains("Mount:     /home"), "stdout={stdout}");
    assert!(stdout.contains("Recent Logs:"), "stdout={stdout}");
    assert!(
        stdout.contains("DEBUG debug log visible"),
        "stdout={stdout}"
    );
    assert!(stdout.contains("INFO info log visible"), "stdout={stdout}");
    assert!(!stdout.contains("\u{001b}"), "stdout={stdout}");
}
