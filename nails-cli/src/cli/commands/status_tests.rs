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
        "hidden_volume_path: {}\nstate_file_path: {}\noverlays: []",
        hidden_root.display(),
        state_path.display()
    )
    .unwrap();

    let output = run_subprocess("plain", Some(config.path()));

    let mut restore = std::fs::metadata(&state_path).unwrap().permissions();
    restore.set_mode(0o600);
    std::fs::set_permissions(&state_path, restore).unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stdout={stdout}");
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
fn execute_status_no_color_verbose_reports_migrated_load_outcome() {
    use nails_core::{StateFile, SystemState};
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let state_path = hidden_root.join("state.json");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let state = StateFile {
        version: "0.0.5".to_string(),
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    std::fs::write(&state_path, serde_json::to_string(&state).unwrap()).unwrap();

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
    assert!(stdout.contains("Verbose Details:"), "stdout={stdout}");
    assert!(
        stdout.contains("State loaded:       migrated from v0.0.5"),
        "stdout={stdout}"
    );
    assert!(!stdout.contains("\u{001b}"), "stdout={stdout}");
}

#[test]
fn execute_status_no_color_verbose_reports_recovered_from_corruption() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let state_path = hidden_root.join("state.json");
    std::fs::create_dir_all(&hidden_root).unwrap();
    std::fs::write(&state_path, "{ definitely-not-json").unwrap();

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
    assert!(stdout.contains("Verbose Details:"), "stdout={stdout}");
    assert!(
        stdout.contains("State loaded:       recovered from corruption (using defaults)"),
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
        },
        nixos_generation: Some("nails-gen-77".to_string()),
        overlay_status,
        ..StateFile::default()
    };
    std::fs::write(&state_path, serde_json::to_string(&state).unwrap()).unwrap();

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
        "hidden_volume_path: {}\nstate_file_path: {}\nlog_path: {}\noverlays:\n  - name: home\n    lower: /home\n    upper: {}/overlays/home/upper\n    work: {}/overlays/home/work\n    target: /home",
        hidden_root.display(),
        state_path.display(),
        log_dir.display(),
        hidden_root.display(),
        hidden_root.display(),
    )
    .unwrap();

    let output = run_subprocess("no-color", Some(config.path()));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout={stdout}");
    assert!(
        stdout.contains("NixOS Generation:   nails-gen-77"),
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
