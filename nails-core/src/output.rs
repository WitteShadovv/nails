//! Structured CLI output formatting module
//!
//! Provides consistent formatting for CLI messages with support for:
//! - Color output using Unicode symbols (✗ ⚠ ✓)
//! - Plain mode with ASCII symbols ([FAIL] [WARN] [PASS])
//! - NO_COLOR environment variable support
//! - stderr for errors/warnings, stdout for info
//!
//! # Examples
//!
//! ```no_run
//! use nails_core::output;
//!
//! // Print formatted messages
//! output::error("Operation failed");
//! output::warn("Configuration not found, using defaults");
//! output::info("Successfully completed");
//!
//! // Format without printing
//! let msg = output::format_error("Something went wrong");
//! ```

use colored::{Color, Colorize, control};
use std::io::{Write, stderr, stdout};
use std::sync::atomic::{AtomicBool, Ordering};

/// Global plain mode flag (thread-safe)
static PLAIN_MODE: AtomicBool = AtomicBool::new(false);

/// Set plain mode globally (ASCII symbols instead of Unicode)
///
/// This should be called early in CLI initialization if --plain flag is set.
/// Plain mode also activates automatically if NO_COLOR environment variable is set.
///
/// # Examples
///
/// ```
/// use nails_core::output;
///
/// output::set_plain_mode(true);
/// assert_eq!(output::format_error("test"), "[FAIL] test");
/// ```
pub fn set_plain_mode(plain: bool) {
    PLAIN_MODE.store(plain, Ordering::Relaxed);
    // Update colored crate's override when plain mode changes
    if plain {
        control::set_override(false);
    } else {
        control::unset_override();
    }
}

/// Check if plain mode is active
///
/// Returns true if:
/// - Plain mode was explicitly set via `set_plain_mode(true)`
/// - NO_COLOR environment variable is set
fn is_plain_mode() -> bool {
    PLAIN_MODE.load(Ordering::Relaxed) || std::env::var("NO_COLOR").is_ok()
}

/// Format error message with red ✗ symbol (or [FAIL] in plain mode)
///
/// Returns formatted string without printing.
///
/// # Examples
///
/// ```
/// use nails_core::output;
///
/// let msg = output::format_error("Database connection failed");
/// // With color: "\u{001b}[31m✗ Database connection failed\u{001b}[0m"
/// // Plain mode: "[FAIL] Database connection failed"
/// ```
pub fn format_error(msg: &str) -> String {
    if is_plain_mode() {
        format!("[FAIL] {}", msg)
    } else {
        format!("{} {}", "✗".color(Color::Red), msg)
    }
}

/// Format warning message with yellow ⚠ symbol (or [WARN] in plain mode)
///
/// Returns formatted string without printing.
///
/// # Examples
///
/// ```
/// use nails_core::output;
///
/// let msg = output::format_warn("Disk space low");
/// // With color: "\u{001b}[33m⚠ Disk space low\u{001b}[0m"
/// // Plain mode: "[WARN] Disk space low"
/// ```
pub fn format_warn(msg: &str) -> String {
    if is_plain_mode() {
        format!("[WARN] {}", msg)
    } else {
        format!("{} {}", "⚠".color(Color::Yellow), msg)
    }
}

/// Format info message with green ✓ symbol (or [PASS] in plain mode)
///
/// Returns formatted string without printing.
///
/// # Examples
///
/// ```
/// use nails_core::output;
///
/// let msg = output::format_info("All checks passed");
/// // With color: "\u{001b}[32m✓ All checks passed\u{001b}[0m"
/// // Plain mode: "[PASS] All checks passed"
/// ```
pub fn format_info(msg: &str) -> String {
    if is_plain_mode() {
        format!("[PASS] {}", msg)
    } else {
        format!("{} {}", "✓".color(Color::Green), msg)
    }
}

/// Print error message to stderr with red ✗ symbol
///
/// # Examples
///
/// ```no_run
/// use nails_core::output;
///
/// output::error("Failed to mount overlay");
/// // Prints to stderr: "✗ Failed to mount overlay"
/// ```
pub fn error(msg: &str) {
    let formatted = format_error(msg);
    let _ = writeln!(stderr(), "{}", formatted);
}

/// Print warning message to stderr with yellow ⚠ symbol
///
/// # Examples
///
/// ```no_run
/// use nails_core::output;
///
/// output::warn("Configuration file not found, using defaults");
/// // Prints to stderr: "⚠ Configuration file not found, using defaults"
/// ```
pub fn warn(msg: &str) {
    let formatted = format_warn(msg);
    let _ = writeln!(stderr(), "{}", formatted);
}

/// Print info message to stdout with green ✓ symbol
///
/// # Examples
///
/// ```no_run
/// use nails_core::output;
///
/// output::info("System activated successfully");
/// // Prints to stdout: "✓ System activated successfully"
/// ```
pub fn info(msg: &str) {
    let formatted = format_info(msg);
    let _ = writeln!(stdout(), "{}", formatted);
}

/// Print a preflight check result to stderr with check name label
///
/// Displays the check name in brackets followed by the result using the
/// existing `CheckResult` Display formatting (colored ✓/⚠/✗).
///
/// # Examples
///
/// ```no_run
/// use nails_core::output;
/// use nails_core::preflight::CheckResult;
///
/// let result = CheckResult::Pass("Hidden volume mounted".to_string());
/// output::check_result("hidden-volume", &result);
/// // Prints to stderr: "  [hidden-volume] ✓ Hidden volume mounted"
/// ```
pub fn check_result(name: &str, result: &crate::preflight::CheckResult) {
    let _ = writeln!(stderr(), "  [{}] {}", name, result);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    // Helper to reset plain mode between tests
    fn reset_plain_mode() {
        set_plain_mode(false);
        unsafe {
            std::env::remove_var("NO_COLOR");
        }
        // Force colored crate to always output colors in tests
        control::set_override(true);
    }

    #[test]
    #[serial]
    fn test_format_error_with_color() {
        reset_plain_mode();
        let result = format_error("test message");
        // Should contain the ✗ symbol and ANSI color codes
        assert!(result.contains("✗"));
        assert!(result.contains("test message"));
        // Verify ANSI color code for red (31m)
        assert!(result.contains("\u{001b}[31m"));
    }

    #[test]
    #[serial]
    fn test_format_warn_with_color() {
        reset_plain_mode();
        let result = format_warn("warning text");
        // Should contain the ⚠ symbol and ANSI color codes
        assert!(result.contains("⚠"));
        assert!(result.contains("warning text"));
        // Verify ANSI color code for yellow (33m)
        assert!(result.contains("\u{001b}[33m"));
    }

    #[test]
    #[serial]
    fn test_format_info_with_color() {
        reset_plain_mode();
        let result = format_info("info text");
        // Should contain the ✓ symbol and ANSI color codes
        assert!(result.contains("✓"));
        assert!(result.contains("info text"));
        // Verify ANSI color code for green (32m)
        assert!(result.contains("\u{001b}[32m"));
    }

    #[test]
    #[serial]
    fn test_format_error_plain_mode() {
        reset_plain_mode();
        set_plain_mode(true);
        let result = format_error("test message");
        assert_eq!(result, "[FAIL] test message");
        // Should NOT contain ANSI codes
        assert!(!result.contains("\u{001b}"));
    }

    #[test]
    #[serial]
    fn test_format_warn_plain_mode() {
        reset_plain_mode();
        set_plain_mode(true);
        let result = format_warn("warning text");
        assert_eq!(result, "[WARN] warning text");
        // Should NOT contain ANSI codes
        assert!(!result.contains("\u{001b}"));
    }

    #[test]
    #[serial]
    fn test_format_info_plain_mode() {
        reset_plain_mode();
        set_plain_mode(true);
        let result = format_info("info text");
        assert_eq!(result, "[PASS] info text");
        // Should NOT contain ANSI codes
        assert!(!result.contains("\u{001b}"));
    }

    #[test]
    #[serial]
    fn test_no_color_env_var() {
        reset_plain_mode();
        unsafe {
            std::env::set_var("NO_COLOR", "1");
        }

        // NO_COLOR should trigger plain mode
        let result = format_error("test");
        assert_eq!(result, "[FAIL] test");

        unsafe {
            std::env::remove_var("NO_COLOR");
        }
    }

    #[test]
    #[serial]
    fn test_is_plain_mode_explicit() {
        reset_plain_mode();
        assert!(!is_plain_mode());

        set_plain_mode(true);
        assert!(is_plain_mode());

        set_plain_mode(false);
        control::set_override(true); // Re-enable for other tests
        assert!(!is_plain_mode());
    }

    #[test]
    #[serial]
    fn test_is_plain_mode_no_color_env() {
        reset_plain_mode();
        assert!(!is_plain_mode());

        unsafe {
            std::env::set_var("NO_COLOR", "1");
        }
        assert!(is_plain_mode());

        unsafe {
            std::env::remove_var("NO_COLOR");
        }
        assert!(!is_plain_mode());
    }

    // Integration test: verify that error/warn/info functions don't panic
    #[test]
    #[serial]
    fn test_print_functions_dont_panic() {
        reset_plain_mode();
        error("test error");
        warn("test warning");
        info("test info");

        set_plain_mode(true);
        error("test error plain");
        warn("test warning plain");
        info("test info plain");
    }
}
