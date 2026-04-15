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

use crate::{Filesystem, NailsError, Result, obfuscate};
use colored::Colorize;
use std::env;
use std::fmt;

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
    env::var("NO_COLOR").is_ok() || env::var(obfuscate::env_no_color()).is_ok()
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
        let mut failed_checks: Vec<(String, String)> = Vec::new();

        for check in &self.checks {
            let name = check.name().to_string();
            match check.run(fs) {
                Ok(result) => {
                    if result.is_fail() {
                        failed_checks.push((name.clone(), result.message().to_string()));
                    }
                    results.push((name, result));
                }
                Err(e) => {
                    // Convert execution error to Fail result
                    let fail_msg = format!("Check execution error: {}", e);
                    failed_checks.push((name.clone(), fail_msg.clone()));
                    results.push((name, CheckResult::Fail(fail_msg)));
                }
            }
        }

        if !failed_checks.is_empty() {
            Err(NailsError::PreFlightCheckFailed(failed_checks))
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
// Submodules
// ============================================================================

pub mod checks;

// ============================================================================
// Re-exports
// ============================================================================

// Re-export all checks for convenience
pub use checks::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_result_is_pass() {
        assert!(CheckResult::Pass("ok".to_string()).is_pass());
        assert!(!CheckResult::Warn("w".to_string()).is_pass());
        assert!(!CheckResult::Fail("f".to_string()).is_pass());
    }

    #[test]
    fn test_check_result_is_warn() {
        assert!(CheckResult::Warn("w".to_string()).is_warn());
        assert!(!CheckResult::Pass("ok".to_string()).is_warn());
        assert!(!CheckResult::Fail("f".to_string()).is_warn());
    }

    #[test]
    fn test_check_result_is_fail() {
        assert!(CheckResult::Fail("f".to_string()).is_fail());
        assert!(!CheckResult::Pass("ok".to_string()).is_fail());
        assert!(!CheckResult::Warn("w".to_string()).is_fail());
    }

    #[test]
    fn test_check_result_message() {
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
    fn test_check_result_display_pass() {
        let result = CheckResult::Pass("All good".to_string());
        let s = format!("{}", result);
        assert!(s.contains("All good") || s.contains("PASS"));
    }

    #[test]
    fn test_check_result_display_warn() {
        let result = CheckResult::Warn("Minor issue".to_string());
        let s = format!("{}", result);
        assert!(s.contains("Minor issue") || s.contains("WARN"));
    }

    #[test]
    fn test_check_result_display_fail() {
        let result = CheckResult::Fail("Critical issue".to_string());
        let s = format!("{}", result);
        assert!(s.contains("Critical issue") || s.contains("FAIL"));
    }

    #[test]
    fn test_preflight_registry_new_and_len() {
        use crate::filesystem::MockFilesystem;
        let registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        assert_eq!(registry.len(), 0);
        assert!(registry.is_empty());
    }

    #[test]
    fn test_preflight_registry_default() {
        use crate::filesystem::MockFilesystem;
        let registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::default();
        assert!(registry.is_empty());
    }
}
