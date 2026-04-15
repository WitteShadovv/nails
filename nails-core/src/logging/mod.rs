//! Logging infrastructure with hidden volume validation
//!
//! Provides structured JSON logging that only writes to the hidden volume,
//! ensuring operational logs never contaminate the decoy system.
//!
//! # Security Constraints
//!
//! - **FR35**: Logs to hidden volume ONLY
//! - **FR36**: Refuse to log if hidden volume not mounted (fail-safe)
//! - **FR38**: Structured JSON logs (newline-delimited)
//! - **AR26**: Pre-flight validation of hidden volume path before any write
//!
//! # Usage Workflow
//!
//! ## 1. Initialize LoggingManager
//!
//! ```no_run
//! use nails_core::logging::LoggingManager;
//! use nails_core::{RealFilesystem, Verbosity};
//! use std::path::PathBuf;
//!
//! // Create manager with log path and hidden volume path
//! let log_path = PathBuf::from("/mnt/hidden-volume/logs");
//! let hidden_volume_root = PathBuf::from("/mnt/hidden-volume");
//! let manager = LoggingManager::new(log_path, hidden_volume_root);
//!
//! // Validate and initialize (fail-safe: refuses if outside hidden volume)
//! let fs = RealFilesystem;
//! let config = manager.init(&fs).expect("Failed to initialize logging")
//!     .expect("Hidden volume not available");
//! ```
//!
//! ## 2. Install Subscriber
//!
//! ```no_run
//! # use nails_core::logging::LoggingConfig;
//! # use nails_core::Verbosity;
//! # use std::path::PathBuf;
//! # let config = LoggingConfig {
//! #     log_file_path: PathBuf::from("/mnt/hidden-volume/logs/nails.log"),
//! # };
//! // Install with verbosity level
//! config.build_and_install_with_verbosity(Verbosity::Normal)
//!     .expect("Failed to install subscriber");
//! ```
//!
//! ## 3. Use Tracing Events
//!
//! ```no_run
//! // Now all tracing events are captured to the log file
//! tracing::info!(user = "alice", state = "active", "System activated");
//! tracing::error!(path = "/home", error = "busy", "Mount failed");
//! ```
//!
//! ## JSON Output Format
//!
//! Logs are written as newline-delimited JSON:
//!
//! ```json
//! {"timestamp":"2026-02-12T10:30:45.123Z","level":"INFO","message":"System activated","fields":{"user":"alice","state":"active"}}
//! {"timestamp":"2026-02-12T10:30:46.456Z","level":"ERROR","message":"Mount failed","fields":{"path":"/home","error":"busy"}}
//! ```

use crate::obfuscate;
use colored::Colorize;
use std::env;

// Module declarations
mod config;
mod manager;
mod path;
mod rotation;

// Public re-exports
pub use config::LoggingConfig;
pub use manager::LoggingManager;
pub use rotation::{DEFAULT_MAX_LOG_SIZE_MB, DEFAULT_RETENTION_DAYS, LOG_FILE_NAME};

/// Check if color output should be disabled
///
/// Returns true if `NO_COLOR` or `NAILS_NO_COLOR` environment variables are set.
/// Follows the NO_COLOR convention (<https://no-color.org/>).
fn should_disable_color() -> bool {
    env::var("NO_COLOR").is_ok() || env::var(obfuscate::env_no_color()).is_ok()
}

/// Format an early error message for pre-logging output
///
/// Used for critical errors that occur before the tracing subscriber is initialized
/// (e.g., during logging path validation). Matches the preflight check output format.
///
/// - With color: `✗ {msg}` (red)
/// - Without color (NO_COLOR set): `[FAIL] {msg}`
pub fn format_early_error(msg: &str) -> String {
    if should_disable_color() {
        format!("[FAIL] {}", msg)
    } else {
        format!("{} {}", "✗".red().bold(), msg.red())
    }
}

/// Format an early warning message for pre-logging output
///
/// Used for non-critical warnings that occur before the tracing subscriber is initialized
/// (e.g., graceful degradation when hidden volume is unavailable). Matches the preflight
/// check output format.
///
/// - With color: `⚠ {msg}` (yellow)
/// - Without color (NO_COLOR set): `[WARN] {msg}`
pub fn format_early_warning(msg: &str) -> String {
    if should_disable_color() {
        format!("[WARN] {}", msg)
    } else {
        format!("{} {}", "⚠".yellow().bold(), msg.yellow())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    // ========================================================================
    // Early output formatting helpers
    // ========================================================================

    #[test]
    #[serial]
    fn test_format_early_error_with_color() {
        unsafe {
            std::env::remove_var("NO_COLOR");
            std::env::remove_var("NAILS_NO_COLOR");
        }
        let result = format_early_error("Something went wrong");
        assert!(result.contains("Something went wrong"));
        assert!(result.contains("✗"));
    }

    #[test]
    #[serial]
    fn test_format_early_error_without_color() {
        unsafe {
            std::env::set_var("NO_COLOR", "1");
        }
        let result = format_early_error("Something went wrong");
        assert_eq!(result, "[FAIL] Something went wrong");
        unsafe {
            std::env::remove_var("NO_COLOR");
        }
    }

    #[test]
    #[serial]
    fn test_format_early_warning_with_color() {
        unsafe {
            std::env::remove_var("NO_COLOR");
            std::env::remove_var("NAILS_NO_COLOR");
        }
        let result = format_early_warning("Volume not available");
        assert!(result.contains("Volume not available"));
        assert!(result.contains("⚠"));
    }

    #[test]
    #[serial]
    fn test_format_early_warning_without_color() {
        unsafe {
            std::env::set_var("NO_COLOR", "1");
        }
        let result = format_early_warning("Volume not available");
        assert_eq!(result, "[WARN] Volume not available");
        unsafe {
            std::env::remove_var("NO_COLOR");
        }
    }

    #[test]
    #[serial]
    fn test_format_early_error_respects_nails_no_color() {
        unsafe {
            std::env::remove_var("NO_COLOR");
            std::env::set_var("NAILS_NO_COLOR", "1");
        }
        let result = format_early_error("Test error");
        assert_eq!(result, "[FAIL] Test error");
        unsafe {
            std::env::remove_var("NAILS_NO_COLOR");
        }
    }

    #[test]
    #[serial]
    fn test_format_early_warning_respects_nails_no_color() {
        unsafe {
            std::env::remove_var("NO_COLOR");
            std::env::set_var("NAILS_NO_COLOR", "1");
        }
        let result = format_early_warning("Test warning");
        assert_eq!(result, "[WARN] Test warning");
        unsafe {
            std::env::remove_var("NAILS_NO_COLOR");
        }
    }
}
