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
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file_path)?;

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
}
