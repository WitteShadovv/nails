//! Logging configuration and subscriber installation
//!
//! Provides validated configuration for structured JSON logging with
//! tracing subscriber setup.

use crate::{NailsError, Result, Verbosity};
use std::path::PathBuf;

/// Validated logging configuration returned by `LoggingManager::init()`
///
/// Contains the validated log file path. Use `build_and_install_subscriber()` to
/// create a tracing subscriber from this configuration.
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Path to the log file (validated to be within hidden volume)
    pub log_file_path: PathBuf,
}

impl LoggingConfig {
    /// Build and install a tracing subscriber with JSON formatting
    ///
    /// Opens the log file for appending, configures a JSON-formatted
    /// tracing subscriber, and sets it as the global default.
    ///
    /// # Arguments
    ///
    /// * `max_level` - Maximum tracing level to capture (use `Verbosity::to_tracing_level()`)
    ///
    /// # Returns
    ///
    /// `Ok(())` on success. The subscriber is installed globally and will
    /// remain active for the program duration.
    ///
    /// # Errors
    ///
    /// Returns `NailsError::IoError` if the log file cannot be opened.
    /// Returns `NailsError::InvalidState` if the global subscriber is already set.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nails_core::logging::LoggingConfig;
    /// use nails_core::Verbosity;
    /// use std::path::PathBuf;
    ///
    /// // Typically obtained from LoggingManager::init()
    /// let config = LoggingConfig {
    ///     log_file_path: PathBuf::from("/mnt/hidden-volume/logs/nails.log"),
    /// };
    ///
    /// // Install the subscriber
    /// config.build_and_install_subscriber(Verbosity::Normal.to_tracing_level())
    ///     .expect("Failed to install logging");
    ///
    /// // Now all tracing events will be written to the log file
    /// ```
    pub fn build_and_install_subscriber(&self, max_level: tracing::Level) -> Result<()> {
        use std::fs::OpenOptions;
        #[cfg(unix)]
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let mut options = OpenOptions::new();
        options.create(true).append(true);

        #[cfg(unix)]
        options.mode(0o600);

        let file = options.open(&self.log_file_path)?;

        #[cfg(unix)]
        {
            let mut permissions = file.metadata()?.permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(&self.log_file_path, permissions)?;
        }

        let writer = std::sync::Mutex::new(file);

        let json_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(writer)
            .with_target(true)
            .with_level(true)
            .with_thread_ids(false)
            .with_thread_names(false);

        tracing_subscriber::registry()
            .with(tracing_subscriber::filter::LevelFilter::from_level(
                max_level,
            ))
            .with(json_layer)
            .try_init()
            .map_err(|e| {
                NailsError::InvalidState(format!("Failed to initialize tracing subscriber: {}", e))
            })?;

        Ok(())
    }

    /// Build and install a tracing subscriber with Verbosity level
    ///
    /// Convenience method that converts `Verbosity` to `tracing::Level`.
    ///
    /// # Arguments
    ///
    /// * `verbosity` - Verbosity level (Quiet, Normal, Verbose, Debug)
    ///
    /// # Errors
    ///
    /// Returns `NailsError::IoError` if the log file cannot be opened.
    /// Returns `NailsError::InvalidState` if the global subscriber is already set.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nails_core::logging::LoggingConfig;
    /// use nails_core::Verbosity;
    /// use std::path::PathBuf;
    ///
    /// // Typically obtained from LoggingManager::init()
    /// let config = LoggingConfig {
    ///     log_file_path: PathBuf::from("/mnt/hidden-volume/logs/nails.log"),
    /// };
    ///
    /// let result = config.build_and_install_with_verbosity(Verbosity::Normal)
    ///     .expect("Failed to install logging");
    /// ```
    pub fn build_and_install_with_verbosity(&self, verbosity: Verbosity) -> Result<()> {
        self.build_and_install_subscriber(verbosity.to_tracing_level())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    const SUBPROCESS_TEST_NAME: &str =
        "logging::config::tests::subprocess_logging_config_entrypoint";

    fn run_subprocess(case: &str, log_path: &std::path::Path) -> std::process::Output {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
            .env("NAILS_LOGGING_CONFIG_SUBPROCESS_CASE", case)
            .env("NAILS_LOGGING_CONFIG_LOG_PATH", log_path)
            .output()
            .expect("failed to run logging config subprocess")
    }

    #[test]
    fn subprocess_logging_config_entrypoint() {
        let Ok(case) = std::env::var("NAILS_LOGGING_CONFIG_SUBPROCESS_CASE") else {
            return;
        };
        let log_file_path = PathBuf::from(std::env::var("NAILS_LOGGING_CONFIG_LOG_PATH").unwrap());
        let config = LoggingConfig { log_file_path };

        match case.as_str() {
            "install-info" => {
                config
                    .build_and_install_subscriber(tracing::Level::INFO)
                    .unwrap();
                tracing::info!(event = "logging-config", "installed info subscriber");
            }
            "install-verbose" => {
                config
                    .build_and_install_with_verbosity(Verbosity::Verbose)
                    .unwrap();
                tracing::debug!(event = "logging-config", "installed verbose subscriber");
            }
            "double-init" => {
                config
                    .build_and_install_subscriber(tracing::Level::INFO)
                    .unwrap();
                let err = config
                    .build_and_install_subscriber(tracing::Level::INFO)
                    .unwrap_err();
                assert!(
                    err.to_string()
                        .contains("Failed to initialize tracing subscriber"),
                    "err={err}"
                );
            }
            other => panic!("unknown logging config subprocess case: {other}"),
        }
    }

    #[test]
    fn test_logging_config_is_cloneable() {
        let config = LoggingConfig {
            log_file_path: PathBuf::from("/mnt/hidden-volume/logs/nails.log"),
        };
        let cloned = config.clone();
        assert_eq!(cloned.log_file_path, config.log_file_path);
    }

    #[test]
    fn test_logging_config_is_debuggable() {
        let config = LoggingConfig {
            log_file_path: PathBuf::from("/mnt/hidden-volume/logs/nails.log"),
        };
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("LoggingConfig"));
        assert!(debug_str.contains("nails.log"));
    }

    #[test]
    fn test_build_and_install_subscriber_returns_io_error_when_parent_missing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = LoggingConfig {
            log_file_path: temp_dir.path().join("missing/logs/nails.log"),
        };

        let err = config
            .build_and_install_subscriber(tracing::Level::INFO)
            .unwrap_err();

        match err {
            NailsError::IoError(io) => assert_eq!(io.kind(), ErrorKind::NotFound),
            other => panic!("expected IoError(NotFound), got {other:?}"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_build_and_install_subscriber_creates_log_file_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let log_path = temp_dir.path().join("nails.log");
        let output = run_subprocess("install-info", &log_path);
        assert!(
            output.status.success(),
            "stdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let mode = std::fs::metadata(&log_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "log file mode should be 0o600");
    }

    #[test]
    fn test_build_and_install_with_verbosity_propagates_open_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = LoggingConfig {
            log_file_path: temp_dir.path().join("missing/logs/nails.log"),
        };

        let err = config
            .build_and_install_with_verbosity(Verbosity::Normal)
            .unwrap_err();

        match err {
            NailsError::IoError(io) => assert_eq!(io.kind(), ErrorKind::NotFound),
            other => panic!("expected IoError(NotFound), got {other:?}"),
        }
    }

    #[test]
    fn test_build_and_install_subscriber_writes_json_log_in_subprocess() {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_path = temp_dir.path().join("nails.log");

        let output = run_subprocess("install-info", &log_path);
        assert!(
            output.status.success(),
            "stdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let contents = std::fs::read_to_string(&log_path).unwrap();
        assert!(
            contents.contains("installed info subscriber"),
            "contents={contents}"
        );
        assert!(
            contents.contains("\"level\":\"INFO\""),
            "contents={contents}"
        );
    }

    #[test]
    fn test_build_and_install_with_verbosity_writes_debug_log_in_subprocess() {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_path = temp_dir.path().join("nails.log");

        let output = run_subprocess("install-verbose", &log_path);
        assert!(
            output.status.success(),
            "stdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let contents = std::fs::read_to_string(&log_path).unwrap();
        assert!(
            contents.contains("installed verbose subscriber"),
            "contents={contents}"
        );
        assert!(
            contents.contains("\"level\":\"DEBUG\""),
            "contents={contents}"
        );
    }

    #[test]
    fn test_build_and_install_subscriber_reports_global_init_conflict_in_subprocess() {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_path = temp_dir.path().join("nails.log");

        let output = run_subprocess("double-init", &log_path);
        assert!(
            output.status.success(),
            "stdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
