//! Pre-flight validation system for NAILS
//!
//! This module provides a trait-based pre-flight check system with an extensible registry.
//! Each validation is isolated, testable, and new checks can be added easily.
//!
//! # Architecture
//!
//! - **CheckResult**: Enum representing check outcomes (Pass/Warn/Fail)
//! - **PreFlightCheck**: Trait defining the check interface
//! - **PreFlightRegistry**: Registry for managing and executing multiple checks
//!
//! # Example
//!
//! ```rust
//! use nails_core::preflight::{CheckResult, PreFlightCheck, PreFlightRegistry};
//! use nails_core::filesystem::MockFilesystem;
//! use nails_core::Result;
//!
//! // Define a custom check
//! struct MyCheck;
//!
//! impl<F: nails_core::Filesystem> PreFlightCheck<F> for MyCheck {
//!     fn name(&self) -> &'static str { "my-check" }
//!     fn description(&self) -> &'static str { "My custom validation" }
//!     fn run(&self, _fs: &F) -> Result<CheckResult> {
//!         Ok(CheckResult::Pass("All good!".to_string()))
//!     }
//! }
//!
//! // Use the registry
//! let fs = MockFilesystem::new();
//! let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
//! registry.add_check(Box::new(MyCheck));
//!
//! let results = registry.run_all(&fs);
//! ```

use crate::{Filesystem, NailsError, Result};
use colored::Colorize;
use std::env;
use std::fmt;
use std::path::PathBuf;

// ============================================================================
// CheckResult Enum
// ============================================================================

/// Result of a pre-flight check execution
///
/// Each check returns one of three outcomes:
/// - **Pass**: Check succeeded with a success message
/// - **Warn**: Check passed but with warnings (non-blocking)
/// - **Fail**: Check failed and blocks activation
///
/// # Display Formatting
///
/// When displayed, CheckResult uses colored output:
/// - Pass: Green checkmark (✓)
/// - Warn: Yellow warning (⚠)
/// - Fail: Red X (✗)
///
/// Color output can be disabled via `NO_COLOR` or `NAILS_NO_COLOR` environment variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResult {
    /// Check succeeded - activation can proceed
    Pass(String),
    /// Check passed with warning - activation can proceed but user should be aware
    Warn(String),
    /// Check failed - activation is blocked
    Fail(String),
}

impl CheckResult {
    /// Returns true if the check result is a Pass
    pub fn is_pass(&self) -> bool {
        matches!(self, CheckResult::Pass(_))
    }

    /// Returns true if the check result is a Warning
    pub fn is_warn(&self) -> bool {
        matches!(self, CheckResult::Warn(_))
    }

    /// Returns true if the check result is a Failure
    pub fn is_fail(&self) -> bool {
        matches!(self, CheckResult::Fail(_))
    }

    /// Returns the message contained in the result
    pub fn message(&self) -> &str {
        match self {
            CheckResult::Pass(msg) => msg,
            CheckResult::Warn(msg) => msg,
            CheckResult::Fail(msg) => msg,
        }
    }
}

/// Check if color output should be disabled
///
/// Returns true if `NO_COLOR` or `NAILS_NO_COLOR` environment variables are set.
/// This follows the standard NO_COLOR convention (https://no-color.org/).
fn should_disable_color() -> bool {
    env::var("NO_COLOR").is_ok() || env::var("NAILS_NO_COLOR").is_ok()
}

impl fmt::Display for CheckResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let no_color = should_disable_color();

        match self {
            CheckResult::Pass(msg) => {
                if no_color {
                    write!(f, "[PASS] {}", msg)
                } else {
                    write!(f, "{} {}", "✓".green().bold(), msg.green())
                }
            }
            CheckResult::Warn(msg) => {
                if no_color {
                    write!(f, "[WARN] {}", msg)
                } else {
                    write!(f, "{} {}", "⚠".yellow().bold(), msg.yellow())
                }
            }
            CheckResult::Fail(msg) => {
                if no_color {
                    write!(f, "[FAIL] {}", msg)
                } else {
                    write!(f, "{} {}", "✗".red().bold(), msg.red())
                }
            }
        }
    }
}

// ============================================================================
// PreFlightCheck Trait
// ============================================================================

/// Trait for pre-flight validation checks
///
/// Each check implementation performs a specific validation before activation.
/// Checks are generic over the `Filesystem` trait to enable testing with `MockFilesystem`.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to allow concurrent execution and
/// sharing across threads.
///
/// # Example
///
/// ```rust
/// use nails_core::preflight::{CheckResult, PreFlightCheck};
/// use nails_core::{Filesystem, Result};
///
/// struct SwapDisabledCheck;
///
/// impl<F: Filesystem> PreFlightCheck<F> for SwapDisabledCheck {
///     fn name(&self) -> &'static str {
///         "swap-disabled"
///     }
///
///     fn description(&self) -> &'static str {
///         "Verify swap is disabled to prevent sensitive data leakage"
///     }
///
///     fn run(&self, fs: &F) -> Result<CheckResult> {
///         match fs.swap_is_enabled() {
///             Ok(true) => Ok(CheckResult::Fail("Swap is enabled - disable before activation".to_string())),
///             Ok(false) => Ok(CheckResult::Pass("Swap is disabled".to_string())),
///             Err(e) => Err(e),
///         }
///     }
/// }
/// ```
pub trait PreFlightCheck<F: Filesystem>: Send + Sync {
    /// Returns the unique identifier for this check
    ///
    /// Should be a short, kebab-case string (e.g., "swap-disabled", "hidden-volume-mounted").
    fn name(&self) -> &'static str;

    /// Returns a user-facing description of what this check validates
    ///
    /// Should be a complete sentence explaining the purpose of the check.
    fn description(&self) -> &'static str;

    /// Execute the validation check
    ///
    /// # Arguments
    ///
    /// * `fs` - Filesystem implementation to use for validation
    ///
    /// # Returns
    ///
    /// * `Ok(CheckResult::Pass(_))` - Check succeeded
    /// * `Ok(CheckResult::Warn(_))` - Check passed with warnings
    /// * `Ok(CheckResult::Fail(_))` - Check failed (blocks activation)
    /// * `Err(_)` - Check encountered an error during execution
    fn run(&self, fs: &F) -> Result<CheckResult>;
}

// ============================================================================
// PreFlightRegistry
// ============================================================================

/// Registry for managing and executing pre-flight checks
///
/// The registry stores checks and executes them in registration order.
/// All checks are executed even if some fail, providing a complete report.
///
/// # Type Parameters
///
/// * `F` - Filesystem implementation (use `MockFilesystem` for testing)
///
/// # Example
///
/// ```rust
/// use nails_core::preflight::{PreFlightRegistry, CheckResult, PreFlightCheck};
/// use nails_core::filesystem::MockFilesystem;
/// use nails_core::Result;
///
/// struct AlwaysPassCheck;
/// impl<F: nails_core::Filesystem> PreFlightCheck<F> for AlwaysPassCheck {
///     fn name(&self) -> &'static str { "always-pass" }
///     fn description(&self) -> &'static str { "A check that always passes" }
///     fn run(&self, _fs: &F) -> Result<CheckResult> {
///         Ok(CheckResult::Pass("Passed!".to_string()))
///     }
/// }
///
/// let fs = MockFilesystem::new();
/// let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
/// registry.add_check(Box::new(AlwaysPassCheck));
///
/// let result = registry.run_all(&fs);
/// assert!(result.is_ok());
/// ```
pub struct PreFlightRegistry<F: Filesystem> {
    checks: Vec<Box<dyn PreFlightCheck<F>>>,
}

impl<F: Filesystem> PreFlightRegistry<F> {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self { checks: Vec::new() }
    }

    /// Add a check to the registry
    ///
    /// Checks are executed in the order they are added.
    ///
    /// # Arguments
    ///
    /// * `check` - Boxed check implementation
    pub fn add_check(&mut self, check: Box<dyn PreFlightCheck<F>>) {
        self.checks.push(check);
    }

    /// Returns the number of registered checks
    pub fn len(&self) -> usize {
        self.checks.len()
    }

    /// Returns true if no checks are registered
    pub fn is_empty(&self) -> bool {
        self.checks.is_empty()
    }

    /// Execute all registered checks and return results
    ///
    /// All checks are executed regardless of individual failures.
    /// This provides a complete report of all check results.
    ///
    /// # Arguments
    ///
    /// * `fs` - Filesystem implementation to pass to each check
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<(String, CheckResult)>)` - All checks completed, none failed
    /// * `Err(NailsError::PreFlightCheckFailed)` - One or more checks failed
    ///
    /// The returned Vec contains tuples of (check_name, result) in execution order.
    /// Even when Err is returned, all results are included in the error message.
    pub fn run_all(&self, fs: &F) -> Result<Vec<(String, CheckResult)>> {
        let mut results: Vec<(String, CheckResult)> = Vec::new();
        let mut has_failure = false;
        let mut failed_checks: Vec<String> = Vec::new();

        for check in &self.checks {
            let name = check.name().to_string();
            match check.run(fs) {
                Ok(result) => {
                    if result.is_fail() {
                        has_failure = true;
                        failed_checks.push(format!("{}: {}", name, result.message()));
                    }
                    results.push((name, result));
                }
                Err(e) => {
                    // Convert execution error to Fail result
                    has_failure = true;
                    let fail_msg = format!("Check execution error: {}", e);
                    failed_checks.push(format!("{}: {}", name, fail_msg));
                    results.push((name, CheckResult::Fail(fail_msg)));
                }
            }
        }

        if has_failure {
            Err(NailsError::PreFlightCheckFailed(format!(
                "Pre-flight checks failed:\n  - {}",
                failed_checks.join("\n  - ")
            )))
        } else {
            Ok(results)
        }
    }

    /// Execute all checks and return detailed results regardless of failures
    ///
    /// Unlike `run_all()`, this method always returns Ok with all results,
    /// even if some checks failed. Useful for reporting/diagnostic purposes.
    ///
    /// # Arguments
    ///
    /// * `fs` - Filesystem implementation to pass to each check
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * `Vec<(String, CheckResult)>` - All check results in execution order
    /// * `bool` - True if all checks passed (no Fail results)
    pub fn run_all_detailed(&self, fs: &F) -> (Vec<(String, CheckResult)>, bool) {
        let mut results: Vec<(String, CheckResult)> = Vec::new();
        let mut all_passed = true;

        for check in &self.checks {
            let name = check.name().to_string();
            match check.run(fs) {
                Ok(result) => {
                    if result.is_fail() {
                        all_passed = false;
                    }
                    results.push((name, result));
                }
                Err(e) => {
                    all_passed = false;
                    results.push((
                        name,
                        CheckResult::Fail(format!("Check execution error: {}", e)),
                    ));
                }
            }
        }

        (results, all_passed)
    }
}

impl<F: Filesystem> Default for PreFlightRegistry<F> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// HiddenVolumeCheck - Validates hidden volume is mounted and writable
// ============================================================================

/// Pre-flight check that validates the hidden volume is mounted and accessible
///
/// This check performs three-step validation:
/// 1. **Path Existence**: Hidden volume path must exist
/// 2. **Mount Status**: Path must be mounted (not just exist as an empty directory)
/// 3. **Write Permission**: Path must be writable to store overlay directories
///
/// # Failure Guidance
///
/// Each failure mode provides actionable guidance following UXR19 requirements:
/// - **Path not found**: Suggests mounting the hidden volume
/// - **Not mounted**: Provides cryptsetup command example
/// - **Not writable**: Suggests checking permissions
///
/// # Example
///
/// ```rust
/// use nails_core::preflight::{HiddenVolumeCheck, PreFlightCheck};
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// let check = HiddenVolumeCheck::new(PathBuf::from("/mnt/hidden-volume"));
///
/// // Set up mock state
/// fs.mock_set_path_exists("/mnt/hidden-volume", true);
/// fs.mock_set_mounted(std::path::Path::new("/mnt/hidden-volume"), true);
/// fs.mock_set_writable("/mnt/hidden-volume", true);
///
/// let result = check.run(&fs).unwrap();
/// assert!(result.is_pass());
/// ```
#[derive(Debug, Clone)]
pub struct HiddenVolumeCheck {
    hidden_volume_path: PathBuf,
}

impl HiddenVolumeCheck {
    /// Create a new HiddenVolumeCheck with a custom path
    ///
    /// # Arguments
    ///
    /// * `hidden_volume_path` - Path to the hidden volume mount point
    pub fn new(hidden_volume_path: PathBuf) -> Self {
        Self { hidden_volume_path }
    }
}

impl Default for HiddenVolumeCheck {
    /// Create check with default hidden volume path (/mnt/hidden-volume)
    fn default() -> Self {
        Self {
            hidden_volume_path: PathBuf::from("/mnt/hidden-volume"),
        }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for HiddenVolumeCheck {
    fn name(&self) -> &'static str {
        "hidden-volume"
    }

    fn description(&self) -> &'static str {
        "Validates hidden volume is mounted and writable"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // Step 1: Check path exists
        if !fs.path_exists(&self.hidden_volume_path)? {
            return Ok(CheckResult::Fail(format!(
                "Hidden volume not found at {}. Mount volume before activation.",
                self.hidden_volume_path.display()
            )));
        }

        // Step 2: Check path is mounted
        if !fs.is_mounted(&self.hidden_volume_path)? {
            return Ok(CheckResult::Fail(format!(
                "Hidden volume at {} is not mounted. Mount with: cryptsetup open ...",
                self.hidden_volume_path.display()
            )));
        }

        // Step 3: Check path is writable
        if !fs.is_writable(&self.hidden_volume_path)? {
            return Ok(CheckResult::Fail(format!(
                "Hidden volume at {} is not writable. Check permissions.",
                self.hidden_volume_path.display()
            )));
        }

        Ok(CheckResult::Pass(format!(
            "Hidden volume mounted at {}",
            self.hidden_volume_path.display()
        )))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    // ========================================================================
    // Test Doubles
    // ========================================================================

    /// DummyCheck - always passes (AC 5)
    struct DummyCheck;

    impl<F: Filesystem> PreFlightCheck<F> for DummyCheck {
        fn name(&self) -> &'static str {
            "dummy-check"
        }

        fn description(&self) -> &'static str {
            "A dummy check for testing purposes"
        }

        fn run(&self, _fs: &F) -> Result<CheckResult> {
            Ok(CheckResult::Pass("Dummy check passed".to_string()))
        }
    }

    /// FailingCheck - always fails
    struct FailingCheck;

    impl<F: Filesystem> PreFlightCheck<F> for FailingCheck {
        fn name(&self) -> &'static str {
            "failing-check"
        }

        fn description(&self) -> &'static str {
            "A check that always fails"
        }

        fn run(&self, _fs: &F) -> Result<CheckResult> {
            Ok(CheckResult::Fail("This check always fails".to_string()))
        }
    }

    /// WarningCheck - always warns
    struct WarningCheck;

    impl<F: Filesystem> PreFlightCheck<F> for WarningCheck {
        fn name(&self) -> &'static str {
            "warning-check"
        }

        fn description(&self) -> &'static str {
            "A check that always warns"
        }

        fn run(&self, _fs: &F) -> Result<CheckResult> {
            Ok(CheckResult::Warn("This check has a warning".to_string()))
        }
    }

    /// ErrorCheck - always returns an error
    struct ErrorCheck;

    impl<F: Filesystem> PreFlightCheck<F> for ErrorCheck {
        fn name(&self) -> &'static str {
            "error-check"
        }

        fn description(&self) -> &'static str {
            "A check that always errors"
        }

        fn run(&self, _fs: &F) -> Result<CheckResult> {
            Err(NailsError::PreFlightCheckFailed(
                "Simulated error".to_string(),
            ))
        }
    }

    /// OrderTrackingCheck - tracks execution order
    struct OrderTrackingCheck {
        id: &'static str,
        order: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl<F: Filesystem> PreFlightCheck<F> for OrderTrackingCheck {
        fn name(&self) -> &'static str {
            self.id
        }

        fn description(&self) -> &'static str {
            "Tracks execution order"
        }

        fn run(&self, _fs: &F) -> Result<CheckResult> {
            self.order.lock().unwrap().push(self.id.to_string());
            Ok(CheckResult::Pass(format!("Check {} executed", self.id)))
        }
    }

    // ========================================================================
    // CheckResult Tests
    // ========================================================================

    #[test]
    fn test_check_result_pass_is_pass() {
        let result = CheckResult::Pass("test".to_string());
        assert!(result.is_pass());
        assert!(!result.is_warn());
        assert!(!result.is_fail());
    }

    #[test]
    fn test_check_result_warn_is_warn() {
        let result = CheckResult::Warn("test".to_string());
        assert!(!result.is_pass());
        assert!(result.is_warn());
        assert!(!result.is_fail());
    }

    #[test]
    fn test_check_result_fail_is_fail() {
        let result = CheckResult::Fail("test".to_string());
        assert!(!result.is_pass());
        assert!(!result.is_warn());
        assert!(result.is_fail());
    }

    #[test]
    fn test_check_result_message_extraction() {
        assert_eq!(
            CheckResult::Pass("pass msg".to_string()).message(),
            "pass msg"
        );
        assert_eq!(
            CheckResult::Warn("warn msg".to_string()).message(),
            "warn msg"
        );
        assert_eq!(
            CheckResult::Fail("fail msg".to_string()).message(),
            "fail msg"
        );
    }

    #[test]
    fn test_check_result_display_contains_message() {
        // Test that display output contains the message regardless of color mode
        let pass = CheckResult::Pass("All good".to_string());
        let warn = CheckResult::Warn("Be careful".to_string());
        let fail = CheckResult::Fail("Something wrong".to_string());

        let pass_display = format!("{}", pass);
        let warn_display = format!("{}", warn);
        let fail_display = format!("{}", fail);

        // Messages must be present in output
        assert!(pass_display.contains("All good"));
        assert!(warn_display.contains("Be careful"));
        assert!(fail_display.contains("Something wrong"));
    }

    #[test]
    fn test_check_result_display_pass_has_indicator() {
        let pass = CheckResult::Pass("test".to_string());
        let display = format!("{}", pass);
        // Should contain either checkmark (colored) or [PASS] (no color)
        assert!(display.contains("✓") || display.contains("[PASS]"));
    }

    #[test]
    fn test_check_result_display_warn_has_indicator() {
        let warn = CheckResult::Warn("test".to_string());
        let display = format!("{}", warn);
        // Should contain either warning symbol (colored) or [WARN] (no color)
        assert!(display.contains("⚠") || display.contains("[WARN]"));
    }

    #[test]
    fn test_check_result_display_fail_has_indicator() {
        let fail = CheckResult::Fail("test".to_string());
        let display = format!("{}", fail);
        // Should contain either X (colored) or [FAIL] (no color)
        assert!(display.contains("✗") || display.contains("[FAIL]"));
    }

    #[test]
    fn test_should_disable_color_function() {
        // Test that the function exists and returns a boolean
        // We can't reliably test env var behavior in parallel tests
        let _result = should_disable_color();
        // The function should compile and return without panicking
    }

    #[test]
    fn test_check_result_equality() {
        let result1 = CheckResult::Pass("test".to_string());
        let result2 = CheckResult::Pass("test".to_string());
        let result3 = CheckResult::Pass("different".to_string());
        let result4 = CheckResult::Fail("test".to_string());

        assert_eq!(result1, result2);
        assert_ne!(result1, result3);
        assert_ne!(result1, result4);
    }

    #[test]
    fn test_check_result_debug() {
        let result = CheckResult::Pass("test message".to_string());
        let debug = format!("{:?}", result);
        assert!(debug.contains("Pass"));
        assert!(debug.contains("test message"));
    }

    #[test]
    fn test_check_result_clone() {
        let result = CheckResult::Pass("test".to_string());
        let cloned = result.clone();
        assert_eq!(result, cloned);
    }

    // ========================================================================
    // PreFlightCheck Trait Tests
    // ========================================================================

    #[test]
    fn test_dummy_check_passes() {
        let fs = MockFilesystem::new();
        let check = DummyCheck;

        assert_eq!(
            <DummyCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "dummy-check"
        );
        assert_eq!(
            <DummyCheck as PreFlightCheck<MockFilesystem>>::description(&check),
            "A dummy check for testing purposes"
        );

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert_eq!(result.message(), "Dummy check passed");
    }

    #[test]
    fn test_failing_check_fails() {
        let fs = MockFilesystem::new();
        let check = FailingCheck;

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
    }

    #[test]
    fn test_warning_check_warns() {
        let fs = MockFilesystem::new();
        let check = WarningCheck;

        let result = check.run(&fs).unwrap();
        assert!(result.is_warn());
    }

    // ========================================================================
    // PreFlightRegistry Tests
    // ========================================================================

    #[test]
    fn test_registry_new_is_empty() {
        let registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_registry_add_check_increases_count() {
        let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        assert_eq!(registry.len(), 0);

        registry.add_check(Box::new(DummyCheck));
        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());

        registry.add_check(Box::new(DummyCheck));
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn test_registry_run_all_empty_registry_succeeds() {
        let fs = MockFilesystem::new();
        let registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();

        let result = registry.run_all(&fs);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_registry_run_all_single_passing_check() {
        let fs = MockFilesystem::new();
        let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        registry.add_check(Box::new(DummyCheck));

        let result = registry.run_all(&fs);
        assert!(result.is_ok());

        let results = result.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "dummy-check");
        assert!(results[0].1.is_pass());
    }

    #[test]
    fn test_registry_run_all_multiple_passing_checks() {
        let fs = MockFilesystem::new();
        let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        registry.add_check(Box::new(DummyCheck));
        registry.add_check(Box::new(WarningCheck)); // Warnings don't fail

        let result = registry.run_all(&fs);
        assert!(result.is_ok());

        let results = result.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_registry_run_all_single_failing_check() {
        let fs = MockFilesystem::new();
        let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        registry.add_check(Box::new(FailingCheck));

        let result = registry.run_all(&fs);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(err, NailsError::PreFlightCheckFailed(_)));
    }

    #[test]
    fn test_registry_run_all_continues_after_failure() {
        let fs = MockFilesystem::new();
        let order = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        registry.add_check(Box::new(OrderTrackingCheck {
            id: "first",
            order: order.clone(),
        }));
        registry.add_check(Box::new(FailingCheck));
        registry.add_check(Box::new(OrderTrackingCheck {
            id: "third",
            order: order.clone(),
        }));

        // run_all should return error but execute all checks
        let result = registry.run_all(&fs);
        assert!(result.is_err());

        // Verify all checks executed
        let executed = order.lock().unwrap();
        assert_eq!(executed.len(), 2);
        assert_eq!(executed[0], "first");
        assert_eq!(executed[1], "third");
    }

    #[test]
    fn test_registry_run_all_execution_order() {
        let fs = MockFilesystem::new();
        let order = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        registry.add_check(Box::new(OrderTrackingCheck {
            id: "first",
            order: order.clone(),
        }));
        registry.add_check(Box::new(OrderTrackingCheck {
            id: "second",
            order: order.clone(),
        }));
        registry.add_check(Box::new(OrderTrackingCheck {
            id: "third",
            order: order.clone(),
        }));

        let _ = registry.run_all(&fs);

        let executed = order.lock().unwrap();
        assert_eq!(executed.as_slice(), &["first", "second", "third"]);
    }

    #[test]
    fn test_registry_run_all_handles_check_errors() {
        let fs = MockFilesystem::new();
        let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        registry.add_check(Box::new(ErrorCheck));

        let result = registry.run_all(&fs);
        assert!(result.is_err());

        // Error should be converted to Fail
        let err = result.unwrap_err();
        if let NailsError::PreFlightCheckFailed(msg) = err {
            assert!(msg.contains("Check execution error"));
        } else {
            panic!("Expected PreFlightCheckFailed error");
        }
    }

    #[test]
    fn test_registry_run_all_mixed_results() {
        let fs = MockFilesystem::new();
        let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        registry.add_check(Box::new(DummyCheck));
        registry.add_check(Box::new(WarningCheck));
        registry.add_check(Box::new(FailingCheck));

        let result = registry.run_all(&fs);
        assert!(result.is_err()); // Has failure

        // Detailed should show all results
        let (results, all_passed) = registry.run_all_detailed(&fs);
        assert!(!all_passed);
        assert_eq!(results.len(), 3);
        assert!(results[0].1.is_pass());
        assert!(results[1].1.is_warn());
        assert!(results[2].1.is_fail());
    }

    #[test]
    fn test_registry_run_all_detailed_all_pass() {
        let fs = MockFilesystem::new();
        let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        registry.add_check(Box::new(DummyCheck));
        registry.add_check(Box::new(WarningCheck)); // Warn is not Fail

        let (results, all_passed) = registry.run_all_detailed(&fs);
        assert!(all_passed);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_registry_run_all_detailed_with_failure() {
        let fs = MockFilesystem::new();
        let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        registry.add_check(Box::new(DummyCheck));
        registry.add_check(Box::new(FailingCheck));

        let (results, all_passed) = registry.run_all_detailed(&fs);
        assert!(!all_passed);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_registry_default() {
        let registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::default();
        assert!(registry.is_empty());
    }

    #[test]
    fn test_registry_aggregate_result_pass_only() {
        let fs = MockFilesystem::new();
        let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        registry.add_check(Box::new(DummyCheck));
        registry.add_check(Box::new(DummyCheck));

        let result = registry.run_all(&fs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_registry_aggregate_result_pass_and_warn() {
        let fs = MockFilesystem::new();
        let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        registry.add_check(Box::new(DummyCheck));
        registry.add_check(Box::new(WarningCheck));

        let result = registry.run_all(&fs);
        assert!(result.is_ok()); // Warn doesn't cause failure
    }

    #[test]
    fn test_registry_aggregate_result_fail() {
        let fs = MockFilesystem::new();
        let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        registry.add_check(Box::new(FailingCheck));

        let result = registry.run_all(&fs);
        assert!(result.is_err());
    }

    #[test]
    fn test_registry_error_message_lists_all_failures() {
        let fs = MockFilesystem::new();
        let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        registry.add_check(Box::new(FailingCheck));
        registry.add_check(Box::new(DummyCheck));
        registry.add_check(Box::new(FailingCheck));

        let result = registry.run_all(&fs);
        let err = result.unwrap_err();

        if let NailsError::PreFlightCheckFailed(msg) = err {
            // Should list both failures
            assert!(msg.contains("failing-check"));
            // Message format: "Pre-flight checks failed:\n  - ..."
            assert!(msg.contains("Pre-flight checks failed"));
        } else {
            panic!("Expected PreFlightCheckFailed error");
        }
    }

    // ========================================================================
    // HiddenVolumeCheck Tests
    // ========================================================================

    #[test]
    fn test_hidden_volume_check_default_path() {
        let check = HiddenVolumeCheck::default();
        assert_eq!(
            check.hidden_volume_path,
            PathBuf::from("/mnt/hidden-volume")
        );
    }

    #[test]
    fn test_hidden_volume_check_custom_path() {
        let custom_path = PathBuf::from("/custom/path");
        let check = HiddenVolumeCheck::new(custom_path.clone());
        assert_eq!(check.hidden_volume_path, custom_path);
    }

    #[test]
    fn test_hidden_volume_check_trait_metadata() {
        let check = HiddenVolumeCheck::default();

        assert_eq!(
            <HiddenVolumeCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "hidden-volume"
        );
        assert_eq!(
            <HiddenVolumeCheck as PreFlightCheck<MockFilesystem>>::description(&check),
            "Validates hidden volume is mounted and writable"
        );
    }

    #[test]
    fn test_hidden_volume_check_pass_when_mounted_and_writable() {
        let fs = MockFilesystem::new();
        let check = HiddenVolumeCheck::default();

        // Set up: volume exists, is mounted, and writable
        fs.mock_set_path_exists("/mnt/hidden-volume", true);
        fs.mock_set_mounted(Path::new("/mnt/hidden-volume"), true);
        fs.mock_set_writable("/mnt/hidden-volume", true);

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert_eq!(
            result.message(),
            "Hidden volume mounted at /mnt/hidden-volume"
        );
    }

    #[test]
    fn test_hidden_volume_check_fail_when_path_does_not_exist() {
        let fs = MockFilesystem::new();
        let check = HiddenVolumeCheck::default();

        // Volume path does not exist
        fs.mock_set_path_exists("/mnt/hidden-volume", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(
            result
                .message()
                .contains("Hidden volume not found at /mnt/hidden-volume")
        );
        assert!(result.message().contains("Mount volume before activation"));
    }

    #[test]
    fn test_hidden_volume_check_fail_when_not_mounted() {
        let fs = MockFilesystem::new();
        let check = HiddenVolumeCheck::default();

        // Volume exists but is NOT mounted
        fs.mock_set_path_exists("/mnt/hidden-volume", true);
        fs.mock_set_mounted(Path::new("/mnt/hidden-volume"), false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("is not mounted"));
        assert!(result.message().contains("cryptsetup open"));
    }

    #[test]
    fn test_hidden_volume_check_fail_when_not_writable() {
        let fs = MockFilesystem::new();
        let check = HiddenVolumeCheck::default();

        // Volume exists and is mounted but NOT writable
        fs.mock_set_path_exists("/mnt/hidden-volume", true);
        fs.mock_set_mounted(Path::new("/mnt/hidden-volume"), true);
        fs.mock_set_writable("/mnt/hidden-volume", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("is not writable"));
        assert!(result.message().contains("Check permissions"));
    }

    #[test]
    fn test_hidden_volume_check_custom_path_works() {
        let fs = MockFilesystem::new();
        let custom_path = PathBuf::from("/custom/volume");
        let check = HiddenVolumeCheck::new(custom_path.clone());

        // Set up custom path
        fs.mock_set_path_exists("/custom/volume", true);
        fs.mock_set_mounted(Path::new("/custom/volume"), true);
        fs.mock_set_writable("/custom/volume", true);

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert!(result.message().contains("/custom/volume"));
    }

    #[test]
    fn test_hidden_volume_check_clone() {
        let check = HiddenVolumeCheck::default();
        let cloned = check.clone();
        assert_eq!(check.hidden_volume_path, cloned.hidden_volume_path);
    }
}
