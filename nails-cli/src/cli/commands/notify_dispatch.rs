//! Notify-dispatch command handler
//!
//! Reads pending notification signal files from the hidden volume and
//! dispatches them as desktop notifications via `notify-send`.
//! Called by the XDG autostart entry after user login.

use std::path::PathBuf;

/// Execute the notify-dispatch command
///
/// Reads all pending notification files, sends them via `notify-send`,
/// and deletes successfully dispatched files.
///
/// # Arguments
///
/// * `config_override` - Optional config file path override
/// * `json` - Output results in JSON format
pub fn execute(config_override: Option<PathBuf>, json: bool) -> ! {
    let config_path = nails_core::config::discover_config_path(config_override.as_deref());
    let mut config = super::load_config_or_exit(&config_path, config_override.as_deref());
    config.loaded_config_path = config_override
        .clone()
        .or_else(|| Some(config_path.clone()));

    match nails_core::notification::dispatch_all(&config.hidden_volume_root) {
        Ok(initial_count) => {
            let mut total = initial_count;
            // If we dispatched any notifications, the system is activating.
            // Poll briefly for late-arriving notifications (e.g., NixOS rebuild result).
            // We use an idle-timeout strategy instead of breaking on the first late hit:
            // after dispatching a late notification, continue polling for 3 more empty
            // cycles (15s) in case more arrive. If nothing ever arrives after the initial
            // batch, give up after 6 empty cycles (30s).
            if initial_count > 0 {
                let mut idle_streak = 0u32;
                for _ in 0..60 {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    match nails_core::notification::dispatch_all(&config.hidden_volume_root) {
                        Ok(0) => {
                            idle_streak += 1;
                            // Exit after 3 consecutive empty polls following a late dispatch,
                            // or after 6 empty polls if we never got a late one.
                            if (total > initial_count && idle_streak >= 3) || idle_streak >= 6 {
                                break;
                            }
                        }
                        Ok(n) => {
                            total += n;
                            idle_streak = 0;
                        }
                        Err(_) => break,
                    }
                }
            }
            if json {
                println!(
                    "{}",
                    serde_json::json!({"dispatched": total, "status": "ok"})
                );
            } else if total > 0 {
                tracing::debug!(count = total, "Dispatched desktop notifications");
            }
            std::process::exit(0);
        }
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"dispatched": 0, "status": "error", "error": e.to_string()})
                );
            } else {
                tracing::warn!(error = %e, "Failed to dispatch notifications");
            }
            // Exit 0 even on error — this runs from autostart; we don't want
            // error dialogs bothering the user for a non-critical feature.
            std::process::exit(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::execute;
    use std::path::PathBuf;

    const SUBPROCESS_TEST_NAME: &str =
        "cli::commands::notify_dispatch::tests::subprocess_notify_dispatch_entrypoint";

    fn run_subprocess(case: &str, config_path: Option<&std::path::Path>) -> std::process::Output {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
            .env("NAILS_NOTIFY_DISPATCH_SUBPROCESS_CASE", case);

        if let Some(path) = config_path {
            command.env("NAILS_NOTIFY_DISPATCH_SUBPROCESS_CONFIG", path);
        }

        command
            .output()
            .expect("failed to run notify-dispatch subprocess test")
    }

    #[test]
    fn subprocess_notify_dispatch_entrypoint() {
        let Ok(case) = std::env::var("NAILS_NOTIFY_DISPATCH_SUBPROCESS_CASE") else {
            return;
        };

        let config_override =
            std::env::var_os("NAILS_NOTIFY_DISPATCH_SUBPROCESS_CONFIG").map(PathBuf::from);

        match case.as_str() {
            "json" => execute(config_override, true),
            "invalid-config" => execute(config_override, false),
            other => panic!("unknown notify-dispatch subprocess case: {other}"),
        }
    }

    #[test]
    fn execute_notify_dispatch_json_reports_ok() {
        use std::io::Write;

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path().join("hidden-volume");
        std::fs::create_dir_all(&hidden_root).unwrap();

        let mut config = tempfile::NamedTempFile::new().unwrap();
        writeln!(config, "hidden_volume_path: {}", hidden_root.display()).unwrap();

        let output = run_subprocess("json", Some(config.path()));
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "stdout={stdout}");
        assert!(stdout.contains("\"status\":\"ok\""));
        assert!(stdout.contains("\"dispatched\":0"));
    }

    #[test]
    fn execute_notify_dispatch_json_skips_queued_notifications_in_test_runtime() {
        use std::io::Write;

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path().join("hidden-volume");
        std::fs::create_dir_all(&hidden_root).unwrap();

        nails_core::notification::write_notification(
            &hidden_root,
            &nails_core::Notification {
                title: "Queued".to_string(),
                body: "Body".to_string(),
                urgency: "critical".to_string(),
                icon: Some("dialog-error".to_string()),
                created_at: "2026-01-01T00:00:00Z".to_string(),
            },
        )
        .unwrap();

        let mut config = tempfile::NamedTempFile::new().unwrap();
        writeln!(config, "hidden_volume_path: {}", hidden_root.display()).unwrap();

        let output = run_subprocess("json", Some(config.path()));
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "stdout={stdout}");
        assert!(stdout.contains("\"status\":\"ok\""));
        assert!(stdout.contains("\"dispatched\":0"));
        assert_eq!(
            nails_core::notification::read_pending(&hidden_root)
                .unwrap()
                .len(),
            1,
            "test-harness subprocess must preserve queued notification"
        );
    }

    #[test]
    fn execute_notify_dispatch_fails_closed_for_invalid_config() {
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
