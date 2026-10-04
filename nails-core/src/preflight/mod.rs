// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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
use std::fmt;

/// The reason reported for every check short-circuited because the hidden volume
/// is not mounted.
pub const SKIPPED_NO_HIDDEN_VOLUME: &str = "requires mounted hidden volume";

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
/// Displayed as the shared pass/warn/fail mark followed by the message. Marks
/// and colour follow the stderr style configured in [`crate::output`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResult {
    /// Check succeeded - activation can proceed
    Pass(String),
    /// Check passed with warning - activation can proceed but user should be aware
    Warn(String),
    /// Check failed - activation is blocked.
    ///
    /// `message` states the problem; `remediation`, when present, is the single
    /// concrete action that clears it (a command to run, a volume to mount).
    /// Keeping the two apart lets the diagnostics layer state every problem once
    /// and then gather one deduplicated, ordered list of actions, instead of
    /// burying `Run: ...` fragments inside each failure line.
    Fail {
        /// What is wrong.
        message: String,
        /// The one action that fixes it, if there is a specific one.
        remediation: Option<String>,
    },
    /// Check was not run because a prerequisite failed.
    ///
    /// When the hidden volume is not mounted, the checks that inspect it (storage
    /// readiness, overlay compatibility, the NixOS config layer, free space)
    /// would all fail with cascaded, misleading errors. Instead they are reported
    /// as `Skipped` with the reason, so the operator sees one real root failure
    /// and a list of what it short-circuited. A skip is neither a pass nor a
    /// failure: it never blocks activation on its own, never contributes a
    /// remediation step, and never counts toward the exit code.
    Skipped(String),
}

impl CheckResult {
    /// Construct a failure with no specific remediation.
    ///
    /// The diagnostics layer shows the generic guidance for such a failure.
    pub fn fail(message: impl Into<String>) -> Self {
        CheckResult::Fail {
            message: message.into(),
            remediation: None,
        }
    }

    /// Construct a failure with a concrete remediation action.
    pub fn fail_with(message: impl Into<String>, remediation: impl Into<String>) -> Self {
        CheckResult::Fail {
            message: message.into(),
            remediation: Some(remediation.into()),
        }
    }

    /// Construct a skip with the reason the check could not run.
    pub fn skipped(reason: impl Into<String>) -> Self {
        CheckResult::Skipped(reason.into())
    }

    /// Returns true if the check result is a Pass
    pub fn is_pass(&self) -> bool {
        matches!(self, CheckResult::Pass(_))
    }

    /// Returns true if the check was skipped because a prerequisite failed
    pub fn is_skipped(&self) -> bool {
        matches!(self, CheckResult::Skipped(_))
    }

    /// Returns true if the check result is a Warning
    pub fn is_warn(&self) -> bool {
        matches!(self, CheckResult::Warn(_))
    }

    /// Returns true if the check result is a Failure
    pub fn is_fail(&self) -> bool {
        matches!(self, CheckResult::Fail { .. })
    }

    /// Returns the message contained in the result
    pub fn message(&self) -> &str {
        match self {
            CheckResult::Pass(msg) => msg,
            CheckResult::Warn(msg) => msg,
            CheckResult::Fail { message, .. } => message,
            CheckResult::Skipped(reason) => reason,
        }
    }

    /// Returns the remediation action for a failure, if one was attached.
    pub fn remediation(&self) -> Option<&str> {
        match self {
            CheckResult::Fail { remediation, .. } => remediation.as_deref(),
            _ => None,
        }
    }
}

impl fmt::Display for CheckResult {
    /// Check results are diagnostics written to stderr, so they follow the
    /// stderr style.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::output::{Mark, Stream};

        let mark = match self {
            CheckResult::Pass(_) => Mark::Pass,
            CheckResult::Warn(_) => Mark::Warn,
            CheckResult::Fail { .. } => Mark::Fail,
            CheckResult::Skipped(_) => Mark::Neutral,
        };
        f.write_str(&crate::output::style(Stream::Stderr).marked(mark, self.message()))
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
///         match fs.read_file_content(std::path::Path::new("/proc/swaps")) {
///             Ok(table) if table.lines().count() > 1 => {
///                 Ok(CheckResult::fail("Swap is enabled - disable before activation".to_string()))
///             }
///             _ => Ok(CheckResult::Pass("Swap is disabled".to_string())),
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
    /// * `Ok(CheckResult::fail(_))` - Check failed (blocks activation)
    /// * `Err(_)` - Check encountered an error during execution
    fn run(&self, fs: &F) -> Result<CheckResult>;

    /// Whether this is the hidden-volume gate check.
    ///
    /// The registry runs this check first; when it fails, every check that
    /// [`requires_hidden_volume`](Self::requires_hidden_volume) is reported as
    /// [`CheckResult::Skipped`] rather than run, so a missing hidden volume shows
    /// one root failure instead of a cascade of dependent errors.
    fn is_hidden_volume_gate(&self) -> bool {
        false
    }

    /// Whether this check can only produce a meaningful result once the hidden
    /// volume is mounted.
    ///
    /// Checks that inspect the hidden volume (storage readiness, overlay
    /// compatibility, the NixOS config layer, free space) override this to
    /// `true`, so the registry short-circuits them to [`CheckResult::Skipped`]
    /// when the hidden-volume gate fails.
    fn requires_hidden_volume(&self) -> bool {
        false
    }
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
        let mut failed_checks: crate::error::PreFlightFailures = Vec::new();
        let mut hidden_volume_failed = false;

        for check in &self.checks {
            let name = check.name().to_string();

            // Short-circuit the hidden-volume-dependent checks once the gate has
            // failed: running them would only cascade misleading errors, and a
            // skip never fails or contributes a remediation step.
            if hidden_volume_failed && check.requires_hidden_volume() {
                results.push((name, CheckResult::skipped(SKIPPED_NO_HIDDEN_VOLUME)));
                continue;
            }

            match check.run(fs) {
                Ok(result) => {
                    if result.is_fail() {
                        if check.is_hidden_volume_gate() {
                            hidden_volume_failed = true;
                        }
                        failed_checks.push((
                            name.clone(),
                            result.message().to_string(),
                            result.remediation().map(str::to_string),
                        ));
                    }
                    results.push((name, result));
                }
                Err(e) => {
                    // Convert execution error to Fail result
                    let fail_msg = format!("Check execution error: {}", e);
                    if check.is_hidden_volume_gate() {
                        hidden_volume_failed = true;
                    }
                    failed_checks.push((name.clone(), fail_msg.clone(), None));
                    results.push((name, CheckResult::fail(fail_msg)));
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
        let mut hidden_volume_failed = false;

        for check in &self.checks {
            let name = check.name().to_string();

            // Once the hidden-volume gate has failed, report its dependents as
            // skipped instead of running them: a skip is not a failure, so it
            // does not flip `all_passed` and keeps the cascade out of the report.
            if hidden_volume_failed && check.requires_hidden_volume() {
                results.push((name, CheckResult::skipped(SKIPPED_NO_HIDDEN_VOLUME)));
                continue;
            }

            match check.run(fs) {
                Ok(result) => {
                    if result.is_fail() {
                        all_passed = false;
                        if check.is_hidden_volume_gate() {
                            hidden_volume_failed = true;
                        }
                    }
                    results.push((name, result));
                }
                Err(e) => {
                    all_passed = false;
                    if check.is_hidden_volume_gate() {
                        hidden_volume_failed = true;
                    }
                    results.push((
                        name,
                        CheckResult::fail(format!("Check execution error: {}", e)),
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
    use crate::filesystem::MockFilesystem;
    use serial_test::serial;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Stands in for the hidden-volume gate in the short-circuit tests.
    struct FailingGate;
    impl<F: Filesystem> PreFlightCheck<F> for FailingGate {
        fn name(&self) -> &'static str {
            "hidden-volume"
        }
        fn description(&self) -> &'static str {
            "gate"
        }
        fn is_hidden_volume_gate(&self) -> bool {
            true
        }
        fn run(&self, _fs: &F) -> Result<CheckResult> {
            Ok(CheckResult::fail_with(
                "not mounted",
                "mount the hidden storage",
            ))
        }
    }

    /// A hidden-volume-dependent check that records whether it was ever run and
    /// would write if it were.
    struct Dependent(Arc<AtomicBool>);
    impl<F: Filesystem> PreFlightCheck<F> for Dependent {
        fn name(&self) -> &'static str {
            "storage"
        }
        fn description(&self) -> &'static str {
            "dependent"
        }
        fn requires_hidden_volume(&self) -> bool {
            true
        }
        fn run(&self, fs: &F) -> Result<CheckResult> {
            self.0.store(true, Ordering::SeqCst);
            // A real dependent writes here; proving run() is never reached proves
            // staging/cleanup writes nothing on the short-circuited path.
            let _ = fs.create_directory(std::path::Path::new("/mnt/hidden/should-not-happen"));
            Ok(CheckResult::Pass("ran".into()))
        }
    }

    /// An independent check that still runs after the gate fails.
    struct Independent;
    impl<F: Filesystem> PreFlightCheck<F> for Independent {
        fn name(&self) -> &'static str {
            "swap"
        }
        fn description(&self) -> &'static str {
            "independent"
        }
        fn run(&self, _fs: &F) -> Result<CheckResult> {
            Ok(CheckResult::Pass("ok".into()))
        }
    }

    #[test]
    fn hidden_volume_failure_skips_dependents_without_running_them() {
        let ran = Arc::new(AtomicBool::new(false));
        let fs = MockFilesystem::new();
        let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        registry.add_check(Box::new(FailingGate));
        registry.add_check(Box::new(Dependent(ran.clone())));
        registry.add_check(Box::new(Independent));

        let (results, all_passed) = registry.run_all_detailed(&fs);

        assert!(!all_passed, "the gate failed");
        assert!(
            !ran.load(Ordering::SeqCst),
            "a skipped dependent must never run (so it writes nothing)"
        );
        assert!(
            fs.mock_ops().is_empty(),
            "no filesystem writes on the short-circuit path: {:?}",
            fs.mock_ops()
        );

        let storage = results.iter().find(|(n, _)| n == "storage").unwrap();
        assert!(storage.1.is_skipped(), "{:?}", storage.1);
        assert_eq!(storage.1.message(), SKIPPED_NO_HIDDEN_VOLUME);

        // An independent check still runs after the gate fails.
        let swap = results.iter().find(|(n, _)| n == "swap").unwrap();
        assert!(swap.1.is_pass(), "{:?}", swap.1);
    }

    #[test]
    fn skipped_dependents_do_not_contribute_remediation() {
        let ran = Arc::new(AtomicBool::new(false));
        let fs = MockFilesystem::new();
        let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        registry.add_check(Box::new(FailingGate));
        registry.add_check(Box::new(Dependent(ran.clone())));

        let err = registry.run_all(&fs).expect_err("the gate failed");
        let NailsError::PreFlightCheckFailed(failures) = err else {
            panic!("expected PreFlightCheckFailed, got {err:?}");
        };
        // Only the gate is a failure; the skipped dependent contributes nothing.
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, "hidden-volume");
        let steps = crate::reporter::remediation_steps(&failures);
        assert_eq!(steps, vec!["mount the hidden storage".to_string()]);
    }

    #[test]
    fn test_check_result_is_pass() {
        assert!(CheckResult::Pass("ok".to_string()).is_pass());
        assert!(!CheckResult::Warn("w".to_string()).is_pass());
        assert!(!CheckResult::fail("f".to_string()).is_pass());
    }

    #[test]
    fn test_check_result_is_warn() {
        assert!(CheckResult::Warn("w".to_string()).is_warn());
        assert!(!CheckResult::Pass("ok".to_string()).is_warn());
        assert!(!CheckResult::fail("f".to_string()).is_warn());
    }

    #[test]
    fn test_check_result_is_fail() {
        assert!(CheckResult::fail("f".to_string()).is_fail());
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
            CheckResult::fail("fail msg".to_string()).message(),
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
        let result = CheckResult::fail("Critical issue".to_string());
        let s = format!("{}", result);
        assert!(s.contains("Critical issue") || s.contains("FAIL"));
    }

    #[test]
    #[serial(render_state)]
    fn test_check_result_display_without_colour_keeps_unicode_without_ansi() {
        let _guard = crate::output::RenderStateTestGuard::new();

        let rendered = format!("{}", CheckResult::Warn("Minor issue".to_string()));

        assert_eq!(rendered, "⚠ Minor issue");
        assert!(!rendered.contains('\u{001b}'));
    }

    #[test]
    #[serial(render_state)]
    fn test_check_result_display_ascii_uses_bracket_markers() {
        let _guard = crate::output::RenderStateTestGuard::new();
        crate::output::configure(true, true, true);

        let rendered = format!("{}", CheckResult::Warn("Minor issue".to_string()));

        assert!(rendered.contains("[WARN]"), "{rendered}");
        assert!(rendered.ends_with(" Minor issue"), "{rendered}");
    }

    #[test]
    #[serial(render_state)]
    fn test_check_result_display_follows_stderr_colour_only() {
        let _guard = crate::output::RenderStateTestGuard::new();
        crate::output::configure(true, false, false);
        assert!(!format!("{}", CheckResult::fail("x".to_string())).contains('\u{001b}'));

        crate::output::configure(false, true, false);
        assert!(format!("{}", CheckResult::fail("x".to_string())).contains('\u{001b}'));
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
