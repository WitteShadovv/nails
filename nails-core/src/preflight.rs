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
                "Hidden volume at {} is not mounted. Mount the hidden LUKS volume to this path before activation.",
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
// HiddenStorageStructureCheck - Validates hidden storage directory structure
// ============================================================================

/// Required directories in hidden storage (design.tex Section 4.3.5)
const REQUIRED_DIRS: &[&str] = &[
    "etc",        // Upper layer for /etc overlay
    "home",       // Upper layer for /home overlay
    "config",     // NAILS configuration (nails.toml)
    "nixos",      // Hidden environment NixOS configuration
    ".work/etc",  // OverlayFS work directory for /etc
    ".work/home", // OverlayFS work directory for /home
];

// Note: nix/ directory is optional - not enforced by this check

/// Pre-flight check that validates hidden storage has expected directory structure
///
/// This check validates that the hidden volume contains all required directories
/// for NAILS overlay operations as documented in thesis design.tex Section 4.3.5.
///
/// # Required Directory Structure
///
/// ```text
/// /mnt/hidden-volume/
/// ├── etc/           # Upper layer for /etc overlay
/// ├── home/          # Upper layer for /home overlay
/// ├── nix/           # Upper layer for /nix overlay (OPTIONAL)
/// ├── config/        # NAILS configuration (nails.toml)
/// ├── nixos/         # Hidden environment NixOS configuration
/// └── .work/         # OverlayFS work directories
///     ├── etc/
///     └── home/
/// ```
///
/// # Failure Guidance
///
/// When directories are missing, the check provides actionable guidance:
/// - Lists ALL missing directories (not just the first one)
/// - Suggests running `nails init-structure` to create required directories
/// - References thesis documentation for context
///
/// # Example
///
/// ```rust,no_run
/// use nails_core::preflight::{HiddenStorageStructureCheck, PreFlightCheck};
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// let check = HiddenStorageStructureCheck::new(PathBuf::from("/mnt/hidden-volume"));
///
/// // Set up mock directory structure - all required directories
/// fs.mock_set_path_exists("/mnt/hidden-volume/etc", true);
/// fs.mock_set_path_type("/mnt/hidden-volume/etc", "directory");
///
/// fs.mock_set_path_exists("/mnt/hidden-volume/home", true);
/// fs.mock_set_path_type("/mnt/hidden-volume/home", "directory");
///
/// fs.mock_set_path_exists("/mnt/hidden-volume/config", true);
/// fs.mock_set_path_type("/mnt/hidden-volume/config", "directory");
///
/// fs.mock_set_path_exists("/mnt/hidden-volume/nixos", true);
/// fs.mock_set_path_type("/mnt/hidden-volume/nixos", "directory");
///
/// fs.mock_set_path_exists("/mnt/hidden-volume/.work/etc", true);
/// fs.mock_set_path_type("/mnt/hidden-volume/.work/etc", "directory");
///
/// fs.mock_set_path_exists("/mnt/hidden-volume/.work/home", true);
/// fs.mock_set_path_type("/mnt/hidden-volume/.work/home", "directory");
///
/// let result = check.run(&fs).unwrap();
/// assert!(result.is_pass());
/// ```
#[derive(Debug, Clone)]
pub struct HiddenStorageStructureCheck {
    hidden_volume_path: PathBuf,
}

impl HiddenStorageStructureCheck {
    /// Create a new HiddenStorageStructureCheck with a custom path
    ///
    /// # Arguments
    ///
    /// * `hidden_volume_path` - Path to the hidden volume mount point
    pub fn new(hidden_volume_path: PathBuf) -> Self {
        Self { hidden_volume_path }
    }
}

impl Default for HiddenStorageStructureCheck {
    /// Create check with default hidden volume path (/mnt/hidden-volume)
    fn default() -> Self {
        Self {
            hidden_volume_path: PathBuf::from("/mnt/hidden-volume"),
        }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for HiddenStorageStructureCheck {
    fn name(&self) -> &'static str {
        "hidden-storage-structure"
    }

    fn description(&self) -> &'static str {
        "Validates hidden storage has expected directory structure"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let mut missing = Vec::new();

        // Check all required directories
        for dir in REQUIRED_DIRS {
            let path = self.hidden_volume_path.join(dir);
            if !fs.path_exists(&path)? || !fs.is_directory(&path)? {
                missing.push(format!("{}/", dir));
            }
        }

        if missing.is_empty() {
            Ok(CheckResult::Pass(
                "Hidden storage structure valid: etc/, home/, config/, nixos/, .work/etc/, .work/home/".to_string()
            ))
        } else {
            Ok(CheckResult::Fail(format!(
                "Hidden storage structure invalid. Missing directories: {}. Run 'nails init-structure' to create required directories.",
                missing.join(", ")
            )))
        }
    }
}

// ============================================================================
// SwapCheck - Validates swap is disabled for memory security
// ============================================================================

/// Pre-flight check to validate swap is disabled
///
/// # Security
///
/// Swap must be disabled before activation because sensitive data
/// (including encryption keys) could be written to persistent storage,
/// defeating the plausible deniability guarantee.
///
/// # Rationale
///
/// - **Memory forensics**: Sensitive data in RAM could be written to swap partition
/// - **Persistence**: Swap contents persist after shutdown (unlike RAM)
/// - **Decryption keys**: Encryption keys in memory could leak to swap
/// - **Plausible deniability**: Swap could contain evidence of hidden environment usage
///
/// # Failure Guidance
///
/// When swap is enabled, the check provides actionable guidance:
/// - Clear explanation of the problem ("Swap is enabled")
/// - Exact command to fix it (`sudo swapoff -a`)
///
/// This follows UXR19 requirements for error messages with fix guidance.
///
/// # Example
///
/// ```rust
/// use nails_core::preflight::{SwapCheck, PreFlightCheck};
/// use nails_core::filesystem::MockFilesystem;
///
/// let fs = MockFilesystem::new();
/// let check = SwapCheck::new();
///
/// // Simulate swap disabled
/// fs.mock_set_swap_enabled(false);
/// let result = check.run(&fs).unwrap();
/// assert!(result.is_pass());
/// ```
#[derive(Debug, Default)]
pub struct SwapCheck;

impl SwapCheck {
    /// Create a new SwapCheck
    pub fn new() -> Self {
        Self
    }
}

impl<F: Filesystem> PreFlightCheck<F> for SwapCheck {
    fn name(&self) -> &'static str {
        "swap"
    }

    fn description(&self) -> &'static str {
        "Validates swap is disabled for memory security"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        if fs.swap_is_enabled()? {
            Ok(CheckResult::Fail(
                "Swap is enabled. Disable swap: sudo swapoff -a".into(),
            ))
        } else {
            Ok(CheckResult::Pass(
                "Swap is disabled - memory is secure".into(),
            ))
        }
    }
}

// ============================================================================
// SpaceCheck - Validates sufficient disk space is available
// ============================================================================

/// Pre-flight check to validate sufficient disk space is available
///
/// # Security & Reliability
///
/// Activation requires disk space for:
/// - OverlayFS upper layers (modifications persist here)
/// - Temporary files during activation
/// - NixOS profile builds (lazy build pattern)
///
/// # Graduated Response System
///
/// Uses three-tier threshold system for nuanced feedback:
/// - **Pass** (>= minimum): Safe to proceed
/// - **Warn** (50-100% of minimum): Proceed with caution, monitor space
/// - **Fail** (< 50% of minimum): Blocked, insufficient space
///
/// # Default Thresholds
///
/// Default minimum: 1024 MB (1 GB)
/// - Pass: >= 1024 MB
/// - Warn: 512-1023 MB
/// - Fail: < 512 MB
///
/// # Example
///
/// ```rust
/// use nails_core::preflight::{SpaceCheck, PreFlightCheck};
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// let check = SpaceCheck::new(PathBuf::from("/mnt/hidden-volume"), 1024);
///
/// // Simulate 2GB available
/// fs.mock_set_free_space(std::path::Path::new("/mnt/hidden-volume"), 2 * 1024 * 1024 * 1024);
///
/// let result = check.run(&fs).unwrap();
/// assert!(result.is_pass());
/// ```
#[derive(Debug, Clone)]
pub struct SpaceCheck {
    hidden_volume_path: PathBuf,
    minimum_space_mb: u64,
}

impl SpaceCheck {
    /// Create a new SpaceCheck with custom minimum space requirement
    ///
    /// # Arguments
    ///
    /// * `hidden_volume_path` - Path to check for free space
    /// * `minimum_space_mb` - Minimum space required in megabytes
    pub fn new(hidden_volume_path: PathBuf, minimum_space_mb: u64) -> Self {
        Self {
            hidden_volume_path,
            minimum_space_mb,
        }
    }

    /// Convert bytes to megabytes
    ///
    /// Performs integer division, converting raw byte values to megabytes
    /// for threshold comparison and display.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Space in bytes
    ///
    /// # Returns
    ///
    /// Space value in megabytes (integer division)
    fn bytes_to_mb(bytes: u64) -> u64 {
        bytes / (1024 * 1024)
    }

    /// Format space value with appropriate unit (MB or GB)
    ///
    /// Converts raw megabyte values to human-readable format:
    /// - Values < 1024 MB → displayed as MB (e.g., "800 MB")
    /// - Values >= 1024 MB → displayed as GB with 1 decimal place (e.g., "1.5 GB")
    ///
    /// # Arguments
    ///
    /// * `mb` - Space in megabytes
    ///
    /// # Returns
    ///
    /// Formatted string with appropriate unit
    fn format_space(mb: u64) -> String {
        if mb >= 1024 {
            format!("{:.1} GB", mb as f64 / 1024.0)
        } else {
            format!("{} MB", mb)
        }
    }
}

impl Default for SpaceCheck {
    /// Create check with default hidden volume path and 1024 MB minimum
    fn default() -> Self {
        Self {
            hidden_volume_path: PathBuf::from("/mnt/hidden-volume"),
            minimum_space_mb: 1024, // 1 GB default
        }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for SpaceCheck {
    fn name(&self) -> &'static str {
        "space"
    }

    fn description(&self) -> &'static str {
        "Validates sufficient disk space is available for activation"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // Get available space in bytes
        let available_bytes = fs.get_free_space(&self.hidden_volume_path)?;
        let available_mb = Self::bytes_to_mb(available_bytes);
        let minimum_mb = self.minimum_space_mb;
        let warn_threshold = minimum_mb / 2; // 50% of minimum

        // Three-tier graduated response
        if available_mb >= minimum_mb {
            // PASS: >= minimum (safe to proceed)
            let ratio = available_mb / minimum_mb;
            Ok(CheckResult::Pass(format!(
                "{} available ({}x minimum required)",
                Self::format_space(available_mb),
                ratio
            )))
        } else if available_mb >= warn_threshold {
            // WARN: 50-100% of minimum (proceed with caution)
            Ok(CheckResult::Warn(format!(
                "{} available (below {} recommended). Activation may succeed but monitor space.",
                Self::format_space(available_mb),
                Self::format_space(minimum_mb)
            )))
        } else {
            // FAIL: < 50% of minimum (blocked)
            Ok(CheckResult::Fail(format!(
                "Only {} available. Free up at least {} before activation.",
                Self::format_space(available_mb),
                Self::format_space(minimum_mb)
            )))
        }
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
        assert!(result.message().contains("Mount the hidden LUKS volume"));
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

    // ========================================================================
    // HiddenStorageStructureCheck Tests (Story 3.3)
    // ========================================================================

    #[test]
    fn test_hidden_storage_structure_check_all_directories_exist_pass() {
        // AC 3, 7: All required directories exist -> Pass
        let fs = MockFilesystem::new();
        let check = HiddenStorageStructureCheck::new(PathBuf::from("/mnt/hidden-volume"));

        // Set up all required directories
        fs.mock_set_path_exists("/mnt/hidden-volume/etc", true);
        fs.mock_set_path_type("/mnt/hidden-volume/etc", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/home", true);
        fs.mock_set_path_type("/mnt/hidden-volume/home", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/config", true);
        fs.mock_set_path_type("/mnt/hidden-volume/config", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/nixos", true);
        fs.mock_set_path_type("/mnt/hidden-volume/nixos", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/.work/etc", true);
        fs.mock_set_path_type("/mnt/hidden-volume/.work/etc", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/.work/home", true);
        fs.mock_set_path_type("/mnt/hidden-volume/.work/home", "directory");

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert!(result.message().contains("Hidden storage structure valid"));
    }

    #[test]
    fn test_hidden_storage_structure_check_single_directory_missing_fail() {
        // AC 4, 8: Single directory missing -> Fail with that directory
        let fs = MockFilesystem::new();
        let check = HiddenStorageStructureCheck::new(PathBuf::from("/mnt/hidden-volume"));

        // Set up all directories except etc/
        fs.mock_set_path_exists("/mnt/hidden-volume/etc", false);

        fs.mock_set_path_exists("/mnt/hidden-volume/home", true);
        fs.mock_set_path_type("/mnt/hidden-volume/home", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/config", true);
        fs.mock_set_path_type("/mnt/hidden-volume/config", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/nixos", true);
        fs.mock_set_path_type("/mnt/hidden-volume/nixos", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/.work/etc", true);
        fs.mock_set_path_type("/mnt/hidden-volume/.work/etc", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/.work/home", true);
        fs.mock_set_path_type("/mnt/hidden-volume/.work/home", "directory");

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("Missing directories: etc/"));
        assert!(
            result
                .message()
                .contains("Hidden storage structure invalid")
        );
    }

    #[test]
    fn test_hidden_storage_structure_check_multiple_directories_missing_fail() {
        // AC 5, 8: Multiple directories missing -> Fail listing all
        let fs = MockFilesystem::new();
        let check = HiddenStorageStructureCheck::new(PathBuf::from("/mnt/hidden-volume"));

        // Only set up some directories, missing config/ and nixos/
        fs.mock_set_path_exists("/mnt/hidden-volume/etc", true);
        fs.mock_set_path_type("/mnt/hidden-volume/etc", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/home", true);
        fs.mock_set_path_type("/mnt/hidden-volume/home", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/config", false);
        fs.mock_set_path_exists("/mnt/hidden-volume/nixos", false);

        fs.mock_set_path_exists("/mnt/hidden-volume/.work/etc", true);
        fs.mock_set_path_type("/mnt/hidden-volume/.work/etc", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/.work/home", true);
        fs.mock_set_path_type("/mnt/hidden-volume/.work/home", "directory");

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("config/"));
        assert!(result.message().contains("nixos/"));
        assert!(result.message().contains("'nails init-structure'"));
    }

    #[test]
    fn test_hidden_storage_structure_check_directory_is_file_fail() {
        // AC 8: Directory exists but is a file -> Fail
        let fs = MockFilesystem::new();
        let check = HiddenStorageStructureCheck::new(PathBuf::from("/mnt/hidden-volume"));

        // etc/ exists but is a file, not a directory
        fs.mock_set_path_exists("/mnt/hidden-volume/etc", true);
        fs.mock_set_path_type("/mnt/hidden-volume/etc", "file");

        fs.mock_set_path_exists("/mnt/hidden-volume/home", true);
        fs.mock_set_path_type("/mnt/hidden-volume/home", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/config", true);
        fs.mock_set_path_type("/mnt/hidden-volume/config", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/nixos", true);
        fs.mock_set_path_type("/mnt/hidden-volume/nixos", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/.work/etc", true);
        fs.mock_set_path_type("/mnt/hidden-volume/.work/etc", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/.work/home", true);
        fs.mock_set_path_type("/mnt/hidden-volume/.work/home", "directory");

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("etc/"));
    }

    #[test]
    fn test_hidden_storage_structure_check_optional_nix_missing_pass() {
        // AC 8: Optional nix/ missing -> Pass (it's optional)
        let fs = MockFilesystem::new();
        let check = HiddenStorageStructureCheck::new(PathBuf::from("/mnt/hidden-volume"));

        // Set up all required directories (nix/ is optional, can be missing)
        fs.mock_set_path_exists("/mnt/hidden-volume/etc", true);
        fs.mock_set_path_type("/mnt/hidden-volume/etc", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/home", true);
        fs.mock_set_path_type("/mnt/hidden-volume/home", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/config", true);
        fs.mock_set_path_type("/mnt/hidden-volume/config", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/nixos", true);
        fs.mock_set_path_type("/mnt/hidden-volume/nixos", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/.work/etc", true);
        fs.mock_set_path_type("/mnt/hidden-volume/.work/etc", "directory");

        fs.mock_set_path_exists("/mnt/hidden-volume/.work/home", true);
        fs.mock_set_path_type("/mnt/hidden-volume/.work/home", "directory");

        // nix/ is not set up - optional
        fs.mock_set_path_exists("/mnt/hidden-volume/nix", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
    }

    #[test]
    fn test_hidden_storage_structure_check_trait_metadata() {
        // AC 1: Verify trait implementation
        let check = HiddenStorageStructureCheck::new(PathBuf::from("/mnt/hidden-volume"));

        assert_eq!(
            <HiddenStorageStructureCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "hidden-storage-structure"
        );
        assert!(
            <HiddenStorageStructureCheck as PreFlightCheck<MockFilesystem>>::description(&check)
                .contains("directory structure")
        );
    }

    // ========================================================================
    // SwapCheck Tests (Story 3.4)
    // ========================================================================

    #[test]
    fn test_swap_check_new_constructor() {
        // AC 1: SwapCheck::new() constructor works
        let _check = SwapCheck::new();
    }

    #[test]
    fn test_swap_check_default_trait() {
        // AC 1: SwapCheck implements Default
        let _check = SwapCheck;
    }

    #[test]
    fn test_swap_check_trait_metadata() {
        // AC 1: Verifies SwapCheck implements PreFlightCheck trait
        // AC 2: Verifies name() returns "swap" and description() is correct
        let check = SwapCheck::new();

        assert_eq!(
            <SwapCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "swap"
        );
        assert_eq!(
            <SwapCheck as PreFlightCheck<MockFilesystem>>::description(&check),
            "Validates swap is disabled for memory security"
        );
    }

    #[test]
    fn test_swap_check_pass_when_swap_disabled() {
        // AC 3: Given swap is disabled, When SwapCheck runs, Then returns Pass
        // AC 5: Given MockFilesystem simulates swap disabled, Then test verifies Pass
        let fs = MockFilesystem::new();
        fs.mock_set_swap_enabled(false);

        let check = SwapCheck::new();
        let result = check.run(&fs).unwrap();

        assert!(result.is_pass());
        assert_eq!(result.message(), "Swap is disabled - memory is secure");
    }

    #[test]
    fn test_swap_check_fail_when_swap_enabled() {
        // AC 4: Given swap is enabled, When SwapCheck runs, Then returns Fail with fix guidance
        // AC 6: Given MockFilesystem simulates swap enabled, Then test verifies Fail with command
        let fs = MockFilesystem::new();
        fs.mock_set_swap_enabled(true);

        let check = SwapCheck::new();
        let result = check.run(&fs).unwrap();

        assert!(result.is_fail());
        assert_eq!(
            result.message(),
            "Swap is enabled. Disable swap: sudo swapoff -a"
        );
    }

    // ========================================================================
    // SpaceCheck Tests (Story 3.5)
    // ========================================================================

    #[test]
    fn test_space_check_struct_with_fields() {
        // AC 1: Create SpaceCheck struct with minimum_space_mb and hidden_volume_path fields
        let check = SpaceCheck::new(PathBuf::from("/mnt/hidden-volume"), 2048);
        assert_eq!(
            check.hidden_volume_path,
            PathBuf::from("/mnt/hidden-volume")
        );
        assert_eq!(check.minimum_space_mb, 2048);
    }

    #[test]
    fn test_space_check_default_values() {
        // AC 1: Default trait provides 1024 MB minimum and default path
        let check = SpaceCheck::default();
        assert_eq!(
            check.hidden_volume_path,
            PathBuf::from("/mnt/hidden-volume")
        );
        assert_eq!(check.minimum_space_mb, 1024);
    }

    #[test]
    fn test_space_check_trait_metadata() {
        // AC 2: Implements PreFlightCheck trait with name() and description()
        let check = SpaceCheck::default();

        assert_eq!(
            <SpaceCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "space"
        );
        assert_eq!(
            <SpaceCheck as PreFlightCheck<MockFilesystem>>::description(&check),
            "Validates sufficient disk space is available for activation"
        );
    }

    #[test]
    fn test_space_check_pass_plenty_of_space() {
        // AC 3, 6: Given 2GB available with 1GB minimum, returns Pass with 2x multiplier
        let fs = MockFilesystem::new();
        let check = SpaceCheck::default(); // 1024 MB minimum

        // Set up 2GB available (2048 MB)
        fs.mock_set_free_space(Path::new("/mnt/hidden-volume"), 2 * 1024 * 1024 * 1024);

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert!(result.message().contains("2.0 GB available"));
        assert!(result.message().contains("2x minimum required"));
    }

    #[test]
    fn test_space_check_pass_exactly_at_minimum() {
        // AC 6: Exactly at minimum (1024 MB) -> Pass
        let fs = MockFilesystem::new();
        let check = SpaceCheck::default(); // 1024 MB minimum

        // Set up exactly 1GB available (1024 MB)
        fs.mock_set_free_space(Path::new("/mnt/hidden-volume"), 1024 * 1024 * 1024);

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert!(result.message().contains("1.0 GB available"));
        assert!(result.message().contains("1x minimum required"));
    }

    #[test]
    fn test_space_check_warn_low_space() {
        // AC 4, 6: Given 800MB available with 1GB minimum, returns Warn
        let fs = MockFilesystem::new();
        let check = SpaceCheck::default(); // 1024 MB minimum

        // Set up 800MB available (between 512-1024 MB = warn range)
        fs.mock_set_free_space(Path::new("/mnt/hidden-volume"), 800 * 1024 * 1024);

        let result = check.run(&fs).unwrap();
        assert!(result.is_warn());
        assert!(result.message().contains("800 MB available"));
        assert!(result.message().contains("below 1.0 GB recommended"));
        assert!(
            result
                .message()
                .contains("Activation may succeed but monitor space")
        );
    }

    #[test]
    fn test_space_check_warn_at_50_percent_boundary() {
        // AC 6: At 50% boundary (512 MB with 1024 minimum) -> Warn
        let fs = MockFilesystem::new();
        let check = SpaceCheck::default(); // 1024 MB minimum

        // Set up exactly 512MB available (50% of 1024 MB)
        fs.mock_set_free_space(Path::new("/mnt/hidden-volume"), 512 * 1024 * 1024);

        let result = check.run(&fs).unwrap();
        assert!(result.is_warn());
        assert!(result.message().contains("512 MB available"));
    }

    #[test]
    fn test_space_check_fail_below_50_percent() {
        // AC 5, 6: Given 300MB available with 1GB minimum, returns Fail
        let fs = MockFilesystem::new();
        let check = SpaceCheck::default(); // 1024 MB minimum

        // Set up 300MB available (< 512 MB = fail)
        fs.mock_set_free_space(Path::new("/mnt/hidden-volume"), 300 * 1024 * 1024);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("Only 300 MB available"));
        assert!(
            result
                .message()
                .contains("Free up at least 1.0 GB before activation")
        );
    }

    #[test]
    fn test_space_check_fail_just_below_50_percent_boundary() {
        // AC 6: Just below 50% (511 MB with 1024 minimum) -> Fail
        let fs = MockFilesystem::new();
        let check = SpaceCheck::default(); // 1024 MB minimum

        // Set up 511MB available (just below 512 MB threshold)
        fs.mock_set_free_space(Path::new("/mnt/hidden-volume"), 511 * 1024 * 1024);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("Only 511 MB available"));
    }

    #[test]
    fn test_space_check_fail_critically_low() {
        // AC 6: Critically low space (10% of minimum) -> Fail
        let fs = MockFilesystem::new();
        let check = SpaceCheck::default(); // 1024 MB minimum

        // Set up 100MB available (10% of 1024 MB)
        fs.mock_set_free_space(Path::new("/mnt/hidden-volume"), 100 * 1024 * 1024);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("Only 100 MB available"));
    }

    #[test]
    fn test_space_check_fail_zero_space() {
        // AC 6: Zero space -> Fail
        let fs = MockFilesystem::new();
        let check = SpaceCheck::default(); // 1024 MB minimum

        // Set up 0 bytes available
        fs.mock_set_free_space(Path::new("/mnt/hidden-volume"), 0);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("Only 0 MB available"));
    }

    #[test]
    fn test_space_check_custom_minimum() {
        // AC 6: Custom minimum value works
        let fs = MockFilesystem::new();
        let check = SpaceCheck::new(PathBuf::from("/mnt/hidden-volume"), 2048); // 2GB minimum

        // Set up 3GB available
        fs.mock_set_free_space(Path::new("/mnt/hidden-volume"), 3 * 1024 * 1024 * 1024);

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert!(result.message().contains("3.0 GB available"));
    }

    #[test]
    fn test_space_check_custom_minimum_warn_threshold() {
        // AC 6: Custom minimum affects warn threshold (50% rule)
        let fs = MockFilesystem::new();
        let check = SpaceCheck::new(PathBuf::from("/mnt/hidden-volume"), 2048); // 2GB minimum

        // Set up 1.5GB available (between 1GB and 2GB = warn range)
        fs.mock_set_free_space(Path::new("/mnt/hidden-volume"), 1536 * 1024 * 1024);

        let result = check.run(&fs).unwrap();
        assert!(result.is_warn());
        assert!(result.message().contains("1.5 GB available"));
    }

    #[test]
    fn test_space_check_bytes_to_mb_conversion() {
        // Helper function test
        assert_eq!(SpaceCheck::bytes_to_mb(1024 * 1024), 1);
        assert_eq!(SpaceCheck::bytes_to_mb(2 * 1024 * 1024 * 1024), 2048);
        assert_eq!(SpaceCheck::bytes_to_mb(512 * 1024 * 1024), 512);
    }

    #[test]
    fn test_space_check_format_space_mb() {
        // Helper function test: values < 1024 MB show as MB
        assert_eq!(SpaceCheck::format_space(512), "512 MB");
        assert_eq!(SpaceCheck::format_space(800), "800 MB");
        assert_eq!(SpaceCheck::format_space(1023), "1023 MB");
    }

    #[test]
    fn test_space_check_format_space_gb() {
        // Helper function test: values >= 1024 MB show as GB
        assert_eq!(SpaceCheck::format_space(1024), "1.0 GB");
        assert_eq!(SpaceCheck::format_space(2048), "2.0 GB");
        assert_eq!(SpaceCheck::format_space(1536), "1.5 GB");
    }

    #[test]
    fn test_space_check_format_space_gb_rounding() {
        // Edge case: verify rounding behavior for precision
        assert_eq!(SpaceCheck::format_space(1025), "1.0 GB"); // Rounds to 1 decimal
        assert_eq!(SpaceCheck::format_space(1792), "1.8 GB"); // 1.75 rounded to 1.8
    }

    #[test]
    fn test_space_check_format_space_large_values() {
        // Edge case: very large values (terabyte range)
        assert_eq!(SpaceCheck::format_space(1048576), "1024.0 GB"); // 1 TB
        assert_eq!(SpaceCheck::format_space(2097152), "2048.0 GB"); // 2 TB
    }

    #[test]
    fn test_space_check_clone() {
        // Verify SpaceCheck is Clone
        let check = SpaceCheck::default();
        let cloned = check.clone();
        assert_eq!(check.hidden_volume_path, cloned.hidden_volume_path);
        assert_eq!(check.minimum_space_mb, cloned.minimum_space_mb);
    }

    #[test]
    fn test_space_check_debug() {
        // Verify SpaceCheck is Debug
        let check = SpaceCheck::default();
        let debug = format!("{:?}", check);
        assert!(debug.contains("SpaceCheck"));
    }
}
