// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Notify-dispatch command handler
//!
//! Reads pending notification signal files from the hidden volume and
//! dispatches them as desktop notifications via `notify-send`.
//! Called by the XDG autostart entry after user login.

use std::path::Path;

use crate::cli::output::envelope::Envelope;
use crate::cli::output::{ExitStatus, OutputSettings};

/// The real surroundings of the login dispatch loop: the hidden-volume queue,
/// the activation-in-progress marker, the wall clock and a real sleep.
struct LoginDispatch<'a> {
    hidden_volume_root: &'a Path,
    started: std::time::Instant,
}

impl<'a> LoginDispatch<'a> {
    fn new(hidden_volume_root: &'a Path) -> Self {
        Self {
            hidden_volume_root,
            started: std::time::Instant::now(),
        }
    }
}

impl nails_core::notification::deliver::DispatchEnv for LoginDispatch<'_> {
    fn dispatch(&mut self) -> nails_core::Result<usize> {
        nails_core::notification::dispatch_all(self.hidden_volume_root)
    }

    fn activation_in_progress(&mut self) -> bool {
        nails_core::notification::deliver::result_pending(
            self.hidden_volume_root,
            std::time::SystemTime::now(),
        )
    }

    fn elapsed(&self) -> std::time::Duration {
        self.started.elapsed()
    }

    fn sleep(&mut self, duration: std::time::Duration) {
        std::thread::sleep(duration);
    }
}

/// Execute the notify-dispatch command.
///
/// Dispatches the pending notification files via `notify-send` (deleting each
/// one delivered) and, while an activation is still in progress, keeps
/// dispatching until it settles — at most fifteen minutes — so a result raised
/// after the session restart reaches the operator. Runs from XDG autostart, so
/// a dispatch failure is reported but still exits [`ExitStatus::Ok`]; only a
/// config load failure exits [`ExitStatus::Config`].
///
/// # Arguments
///
/// * `settings` - Output settings resolved once from the global flags
/// * `config_override` - Optional config file path override
pub fn execute(settings: &OutputSettings, config_override: Option<&Path>) -> ExitStatus {
    let json = settings.is_json();
    let config = match super::load_config_or_report(config_override, "notify-dispatch", json) {
        Ok(loaded) => loaded.into_config(),
        Err(status) => return status,
    };

    let mut env = LoginDispatch::new(&config.hidden_volume_root);
    match nails_core::notification::deliver::dispatch_until_settled(
        &mut env,
        nails_core::notification::deliver::DISPATCH_POLL_INTERVAL,
        nails_core::notification::deliver::DISPATCH_POLL_CAP,
    ) {
        Ok(total) => {
            if json {
                Envelope::success(
                    "notify-dispatch",
                    serde_json::json!({"dispatched": total, "status": "ok"}),
                )
                .print();
            } else if total > 0 {
                tracing::debug!(count = total, "Dispatched desktop notifications");
            }
            ExitStatus::Ok
        }
        Err(e) => {
            if json {
                Envelope::success(
                    "notify-dispatch",
                    serde_json::json!({"dispatched": 0, "status": "error", "error": e.to_string()}),
                )
                .print();
            } else {
                tracing::warn!(error = %e, "Failed to dispatch notifications");
            }
            // Exit 0 even on error — this runs from autostart; we don't want
            // error dialogs bothering the user for a non-critical feature.
            ExitStatus::Ok
        }
    }
}

#[cfg(test)]
mod tests {
    use super::execute;
    use crate::cli::output::{OutputMode, OutputSettings};
    use nails_core::test_support::EnvGuard;
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

        let _env = EnvGuard::lock();
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

        let status = match case.as_str() {
            "json" => execute(
                &OutputSettings {
                    mode: OutputMode::Json,
                    ..OutputSettings::default()
                },
                config_override.as_deref(),
            ),
            "invalid-config" => execute(&OutputSettings::default(), config_override.as_deref()),
            other => panic!("unknown notify-dispatch subprocess case: {other}"),
        };
        crate::cli::detach::exit_process(status.code());
    }

    #[test]
    fn execute_notify_dispatch_json_reports_ok() {
        use std::io::Write;

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path().join("hidden-volume");
        std::fs::create_dir_all(&hidden_root).unwrap();

        let mut config = tempfile::NamedTempFile::new().unwrap();
        writeln!(config, "hidden_volume_root = \"{}\"", hidden_root.display()).unwrap();

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
        writeln!(config, "hidden_volume_root = \"{}\"", hidden_root.display()).unwrap();

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
        writeln!(config, "hidden_volume_root = [broken").unwrap();

        let output = run_subprocess("invalid-config", Some(config.path()));
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert_eq!(output.status.code(), Some(3), "stderr={stderr}");
        assert!(stderr.contains("invalid config"), "{stderr}");
    }
}
