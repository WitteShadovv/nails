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

use crate::{Filesystem, NailsError, Result, SystemState, config::DEFAULT_HIDDEN_VOLUME_ROOT};
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
/// use nails_core::config::DEFAULT_HIDDEN_VOLUME_ROOT;
/// use nails_core::preflight::{HiddenVolumeCheck, PreFlightCheck};
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// let check = HiddenVolumeCheck::new(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT));
///
/// // Set up mock state
/// fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
/// fs.mock_set_mounted(std::path::Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), true);
/// fs.mock_set_writable(DEFAULT_HIDDEN_VOLUME_ROOT, true);
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
    /// Create check with default hidden volume path
    fn default() -> Self {
        Self {
            hidden_volume_path: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
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
// StorageReadinessCheck - Unified storage validation (Story 14.5)
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

/// Unified pre-flight check that validates hidden storage directory structure
/// AND overlay directory accessibility in a single pass.
///
/// Replaces both `HiddenStorageStructureCheck` and `OverlayDirectoriesCheck`
/// with one comprehensive validation that provides a single coherent result.
///
/// # Validation Phases
///
/// 1. **Structure**: Required base directories exist on hidden volume
/// 2. **Auto-create**: Missing directories are created with 0o700 permissions
/// 3. **Overlay access**: Overlay lower/upper/work directories are accessible
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
/// # Example
///
/// ```rust,no_run
/// use nails_core::config::DEFAULT_HIDDEN_VOLUME_ROOT;
/// use nails_core::preflight::{StorageReadinessCheck, OverlayDirs, PreFlightCheck};
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// let check = StorageReadinessCheck::new(
///     PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
///     vec![OverlayDirs::new(
///         "home".to_string(),
///         PathBuf::from("/home"),
///         PathBuf::from("/mnt/hidden-volume/home"),
///         PathBuf::from("/mnt/hidden-volume/.work/home"),
///     )],
/// );
/// ```
#[derive(Debug, Clone)]
pub struct StorageReadinessCheck {
    hidden_volume_path: PathBuf,
    overlays: Vec<OverlayDirs>,
}

impl StorageReadinessCheck {
    /// Create a new StorageReadinessCheck
    ///
    /// # Arguments
    ///
    /// * `hidden_volume_path` - Path to the hidden volume mount point
    /// * `overlays` - Overlay directory configurations to validate
    pub fn new(hidden_volume_path: PathBuf, overlays: Vec<OverlayDirs>) -> Self {
        Self {
            hidden_volume_path,
            overlays,
        }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for StorageReadinessCheck {
    fn name(&self) -> &'static str {
        "storage-readiness"
    }

    fn description(&self) -> &'static str {
        "Validates hidden storage directories exist and are accessible"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let mut issues = Vec::new();

        // Phase 1: Check required directories exist on hidden volume
        let mut missing = Vec::new();
        for dir in REQUIRED_DIRS {
            let path = self.hidden_volume_path.join(dir);
            if !fs.path_exists(&path)? || !fs.is_directory(&path)? {
                missing.push(*dir);
            }
        }

        // Phase 2: Auto-create missing directories (Story 14.4)
        if !missing.is_empty() {
            let mut created = Vec::new();

            for dir in &missing {
                let path = self.hidden_volume_path.join(dir);
                match fs.create_directory(&path) {
                    Ok(()) => {
                        if let Err(e) = fs.set_permissions(&path, 0o700) {
                            issues.push(format!(
                                "Missing: {}/: failed to set permissions: {}",
                                dir, e
                            ));
                            continue;
                        }
                        tracing::info!(directory = %dir, "Created missing hidden storage directory");
                        created.push(format!("{}/", dir));
                    }
                    Err(e) => {
                        issues.push(format!("Missing: {}/: {}", dir, e));
                    }
                }
            }

            if !created.is_empty() {
                tracing::info!(directories = %created.join(", "), "Auto-created directories");
            }
        }

        // Phase 3: Validate overlay directories are accessible
        for overlay in &self.overlays {
            // Lower must exist and be readable
            if !fs.path_exists(&overlay.lower)? {
                issues.push(format!(
                    "{} lower directory not found: {}",
                    overlay.name,
                    overlay.lower.display()
                ));
            } else if !fs.is_readable(&overlay.lower)? {
                issues.push(format!(
                    "{} lower directory not readable: {}",
                    overlay.name,
                    overlay.lower.display()
                ));
            }

            // Upper must exist and be writable
            if !fs.path_exists(&overlay.upper)? {
                issues.push(format!(
                    "{} upper directory not found: {}",
                    overlay.name,
                    overlay.upper.display()
                ));
            } else if !fs.is_writable(&overlay.upper)? {
                issues.push(format!(
                    "Not writable: {} upper ({})",
                    overlay.name,
                    overlay.upper.display()
                ));
            }

            // Work must exist and be writable
            if !fs.path_exists(&overlay.work)? {
                issues.push(format!(
                    "{} work directory not found: {}",
                    overlay.name,
                    overlay.work.display()
                ));
            } else if !fs.is_writable(&overlay.work)? {
                issues.push(format!(
                    "Not writable: {} work ({})",
                    overlay.name,
                    overlay.work.display()
                ));
            }
        }

        if issues.is_empty() {
            Ok(CheckResult::Pass(
                "Hidden storage ready: all directories accessible".to_string(),
            ))
        } else {
            Ok(CheckResult::Fail(format!(
                "Storage not ready: {}",
                issues.join(". ")
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
/// use nails_core::config::DEFAULT_HIDDEN_VOLUME_ROOT;
/// use nails_core::preflight::{SpaceCheck, PreFlightCheck};
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// let check = SpaceCheck::new(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT), 1024);
///
/// // Simulate 2GB available
/// fs.mock_set_free_space(std::path::Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 2 * 1024 * 1024 * 1024);
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
            hidden_volume_path: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
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
// OverlayDirs - Configuration for a single overlay mount
// ============================================================================

/// Configuration for a single overlay mount (lower, upper, work directories)
///
/// # OverlayFS Structure
///
/// OverlayFS requires three directory types:
/// - **Lower**: Read-only base layer (e.g., /home, /etc)
/// - **Upper**: Writable layer for changes (on hidden volume)
/// - **Work**: OverlayFS internal working directory (on hidden volume)
///
/// # Example
///
/// ```rust
/// use nails_core::preflight::OverlayDirs;
/// use std::path::PathBuf;
///
/// let home_overlay = OverlayDirs::new(
///     "home".to_string(),
///     PathBuf::from("/home"),
///     PathBuf::from("/mnt/hidden-volume/home"),
///     PathBuf::from("/mnt/hidden-volume/.work/home"),
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayDirs {
    /// Name/identifier for this overlay (e.g., "home", "etc")
    pub name: String,
    /// Lower (read-only) directory - base layer
    pub lower: PathBuf,
    /// Upper (writable) directory - changes persist here
    pub upper: PathBuf,
    /// Work directory - OverlayFS metadata
    pub work: PathBuf,
}

impl OverlayDirs {
    /// Create a new OverlayDirs configuration
    ///
    /// # Arguments
    ///
    /// * `name` - Identifier for this overlay (e.g., "home", "etc")
    /// * `lower` - Read-only base layer path
    /// * `upper` - Writable overlay layer path
    /// * `work` - OverlayFS work directory path
    pub fn new(name: String, lower: PathBuf, upper: PathBuf, work: PathBuf) -> Self {
        Self {
            name,
            lower,
            upper,
            work,
        }
    }
}

// ============================================================================
// StateCheck - Validates Current State Allows Activation
// ============================================================================

/// Pre-flight check that validates the current system state
///
/// This check ensures activation doesn't run when the system is already active
/// or in a transitional state (activating, deactivating, emergency).
///
/// # Valid State for Activation
///
/// Activation is only allowed when the system state is **Inactive**.
///
/// # Blocked States
///
/// The following states block activation with specific guidance:
/// - **Active**: System already active - user should run `nails deactivate` first
/// - **Activating**: Activation in progress - user should wait or reboot if stuck
/// - **Deactivating**: Deactivation in progress - user should wait for completion
/// - **Emergency**: System in emergency state - user must reboot to reset
///
/// # State Machine Integration
///
/// This check enforces the state transition rules defined in `SystemState`:
/// - Valid: `Inactive → Activating → Active → Deactivating → Inactive`
/// - Valid: `Any State → Emergency`
/// - Invalid: Activation from any state except `Inactive`
///
/// See [`SystemState`](crate::state::SystemState) for complete state machine documentation.
///
/// # Idempotent Activation (FR61)
///
/// Per requirement FR61, attempting to activate when already active returns
/// a friendly message ("already active") rather than an error, supporting
/// idempotent behavior.
///
/// # Example
///
/// ```rust
/// use nails_core::preflight::{StateCheck, PreFlightCheck};
/// use nails_core::{SystemState, MockFilesystem};
///
/// let fs = MockFilesystem::new();
/// let check = StateCheck::new(SystemState::Inactive);
///
/// let result = check.run(&fs).unwrap();
/// assert!(result.is_pass());
/// ```
#[derive(Debug, Clone)]
pub struct StateCheck {
    current_state: SystemState,
}

impl StateCheck {
    /// Create a new StateCheck with the current system state
    ///
    /// # Arguments
    ///
    /// * `current_state` - The current system state to validate
    pub fn new(current_state: SystemState) -> Self {
        Self { current_state }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for StateCheck {
    fn name(&self) -> &'static str {
        "state"
    }

    fn description(&self) -> &'static str {
        "Validates system state allows activation"
    }

    fn run(&self, _fs: &F) -> Result<CheckResult> {
        match &self.current_state {
            SystemState::Inactive => Ok(CheckResult::Pass(
                "System is inactive - ready for activation".into(),
            )),
            SystemState::Active { .. } => Ok(CheckResult::Fail(
                "System is already active. Run 'nails deactivate' first or use 'nails status' to check state.".into(),
            )),
            SystemState::Activating { .. } => Ok(CheckResult::Fail(
                "System is currently activating. Wait for completion or reboot if stuck.".into(),
            )),
            SystemState::Deactivating { .. } => Ok(CheckResult::Fail(
                "System is currently deactivating. Wait for completion or reboot if stuck.".into(),
            )),
            SystemState::Emergency { .. } => Ok(CheckResult::Fail(
                "System is in emergency state. Reboot to reset state.".into(),
            )),
        }
    }
}

// ============================================================================
// NixOSConfigCheck - Validates NixOS Configuration Overlay Structure (Story 4.12)
// ============================================================================

/// Validates NixOS configuration overlay structure in hidden storage
///
/// Ensures the hidden storage contains all required NixOS configuration files
/// for the overlay mechanism:
/// - `{hidden}/etc/nixos/` directory exists
/// - `{hidden}/etc/nixos/hardware-configuration.nix` exists (modified with import)
/// - `{hidden}/nixos/configuration.nix` exists (hidden environment config)
/// - Modified hardware-configuration.nix contains import to hidden config
///
/// # Example
///
/// ```rust
/// use nails_core::preflight::{NixOSConfigCheck, PreFlightCheck, CheckResult};
/// use nails_core::MockFilesystem;
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
/// fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
/// fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
/// fs.mock_set_path_exists("/mnt/hidden/nixos/configuration.nix", true);
/// fs.mock_set_file_content(
///     "/mnt/hidden/etc/nixos/hardware-configuration.nix",
///     "{ imports = [ /mnt/hidden/nixos/configuration.nix ]; }"
/// );
///
/// let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
/// let result = check.run(&fs).unwrap();
/// assert!(result.is_pass());
/// ```
#[derive(Debug, Clone)]
pub struct NixOSConfigCheck {
    hidden_storage_path: PathBuf,
}

impl NixOSConfigCheck {
    /// Create a new NixOSConfigCheck
    ///
    /// # Arguments
    ///
    /// * `hidden_storage_path` - Path to hidden storage root
    pub fn new(hidden_storage_path: PathBuf) -> Self {
        Self {
            hidden_storage_path,
        }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for NixOSConfigCheck {
    fn name(&self) -> &'static str {
        "nixos-config"
    }

    fn description(&self) -> &'static str {
        "Validates NixOS configuration overlay structure"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // Check 1: Base hardware-configuration.nix exists
        let base_config = PathBuf::from("/etc/nixos/hardware-configuration.nix");
        if !fs.path_exists(&base_config)? {
            return Ok(CheckResult::Fail(
                "Base /etc/nixos/hardware-configuration.nix not found. Ensure NixOS is properly installed.".into()
            ));
        }

        // Check 2: Hidden etc/nixos directory exists
        let hidden_etc_nixos = self.hidden_storage_path.join("etc/nixos");
        if !fs.path_exists(&hidden_etc_nixos)? {
            return Ok(CheckResult::Fail(format!(
                "Hidden storage missing etc/nixos/ directory at {}. Create this directory with modified hardware-configuration.nix.",
                hidden_etc_nixos.display()
            )));
        }

        // Check 3: Modified hardware-configuration.nix exists
        let modified_config = hidden_etc_nixos.join("hardware-configuration.nix");
        if !fs.path_exists(&modified_config)? {
            return Ok(CheckResult::Fail(format!(
                "Modified hardware-configuration.nix not found at {}. Copy base config and add hidden import.",
                modified_config.display()
            )));
        }

        // Check 4: Modified hardware-configuration.nix has hidden import
        let content = fs.read_file_content(&modified_config)?;
        let expected_import = format!(
            "{}/nixos/configuration.nix",
            self.hidden_storage_path.display()
        );
        if !content.contains(&expected_import) {
            return Ok(CheckResult::Fail(format!(
                "Modified hardware-configuration.nix missing hidden import. Add: imports = [ ... {} ];",
                expected_import
            )));
        }

        // Check 5: Hidden configuration.nix exists
        let hidden_config = self.hidden_storage_path.join("nixos/configuration.nix");
        if !fs.path_exists(&hidden_config)? {
            return Ok(CheckResult::Fail(format!(
                "Hidden configuration.nix not found at {}. Create this file with hidden environment settings.",
                hidden_config.display()
            )));
        }

        Ok(CheckResult::Pass(
            "NixOS configuration overlay structure is valid".into(),
        ))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
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
            Err(NailsError::PreFlightCheckFailed(vec![(
                "error-check".to_string(),
                "Simulated error".to_string(),
            )]))
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
        if let NailsError::PreFlightCheckFailed(failures) = err {
            assert_eq!(failures.len(), 1);
            assert_eq!(failures[0].0, "error-check");
            assert!(
                failures[0].1.contains("Check execution error")
                    || failures[0].1.contains("Simulated error")
            );
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

        if let NailsError::PreFlightCheckFailed(failures) = err {
            // Should have 2 failures (both FailingCheck instances)
            assert_eq!(failures.len(), 2);
            // Both should be from failing-check
            assert_eq!(failures[0].0, "failing-check");
            assert_eq!(failures[1].0, "failing-check");
            // Both should contain the failure message
            assert!(failures[0].1.contains("This check always fails"));
            assert!(failures[1].1.contains("This check always fails"));
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
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
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
        fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
        fs.mock_set_mounted(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), true);
        fs.mock_set_writable(DEFAULT_HIDDEN_VOLUME_ROOT, true);

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
        fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, false);

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
        fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
        fs.mock_set_mounted(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), false);

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
        fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
        fs.mock_set_mounted(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), true);
        fs.mock_set_writable(DEFAULT_HIDDEN_VOLUME_ROOT, false);

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
    // StorageReadinessCheck Tests (Story 14.5, merged from 3.3 + 3.6 + 14.4)
    // ========================================================================

    /// Helper: create StorageReadinessCheck with no overlays for base directory tests
    fn make_check_no_overlays() -> StorageReadinessCheck {
        StorageReadinessCheck::new(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT), vec![])
    }

    /// Helper: create StorageReadinessCheck with home+etc overlays
    fn make_check_with_overlays() -> StorageReadinessCheck {
        StorageReadinessCheck::new(
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
            vec![
                OverlayDirs::new(
                    "home".to_string(),
                    PathBuf::from("/home"),
                    PathBuf::from("/mnt/hidden-volume/home"),
                    PathBuf::from("/mnt/hidden-volume/.work/home"),
                ),
                OverlayDirs::new(
                    "etc".to_string(),
                    PathBuf::from("/etc"),
                    PathBuf::from("/mnt/hidden-volume/etc"),
                    PathBuf::from("/mnt/hidden-volume/.work/etc"),
                ),
            ],
        )
    }

    /// Helper: set up all required hidden volume dirs as existing
    fn setup_all_required_dirs(fs: &MockFilesystem) {
        for dir in &["etc", "home", "config", "nixos", ".work/etc", ".work/home"] {
            let path = format!("/mnt/hidden-volume/{}", dir);
            fs.mock_set_path_exists(&path, true);
            fs.mock_set_path_type(&path, "directory");
            fs.mock_set_writable(&path, true);
        }
    }

    /// Helper: set up overlay lower dirs as existing and readable
    fn setup_overlay_lower_dirs(fs: &MockFilesystem) {
        fs.mock_set_path_exists("/home", true);
        fs.mock_set_readable("/home", true);
        fs.mock_set_path_exists("/etc", true);
        fs.mock_set_readable("/etc", true);
    }

    #[test]
    fn test_storage_readiness_trait_metadata() {
        let check = make_check_no_overlays();
        assert_eq!(
            <StorageReadinessCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "storage-readiness"
        );
        assert!(
            <StorageReadinessCheck as PreFlightCheck<MockFilesystem>>::description(&check)
                .contains("directories exist and are accessible")
        );
    }

    #[test]
    fn test_storage_readiness_all_dirs_exist_no_overlays_pass() {
        // AC4: All dirs exist → Pass
        let fs = MockFilesystem::new();
        let check = make_check_no_overlays();
        setup_all_required_dirs(&fs);

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert!(result.message().contains("Hidden storage ready"));
    }

    #[test]
    fn test_storage_readiness_all_dirs_and_overlays_pass() {
        // AC1+AC4: All dirs exist + overlays accessible → single Pass
        let fs = MockFilesystem::new();
        let check = make_check_with_overlays();
        setup_all_required_dirs(&fs);
        setup_overlay_lower_dirs(&fs);

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert!(
            result
                .message()
                .contains("Hidden storage ready: all directories accessible")
        );
    }

    #[test]
    fn test_storage_readiness_missing_dir_autocreate_success() {
        // AC6: Auto-create missing dirs (integration from 14.4)
        let fs = MockFilesystem::new();
        let check = make_check_no_overlays();

        // Most dirs exist
        for dir in &["home", "config", "nixos", ".work/etc", ".work/home"] {
            let path = format!("/mnt/hidden-volume/{}", dir);
            fs.mock_set_path_exists(&path, true);
            fs.mock_set_path_type(&path, "directory");
        }

        // etc/ is missing but creatable
        fs.mock_set_path_exists("/mnt/hidden-volume/etc", false);
        fs.mock_set_directory_creatable("/mnt/hidden-volume/etc", true);

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());

        // Verify permissions set
        let perms = fs.mock_get_permissions(Path::new("/mnt/hidden-volume/etc"));
        assert_eq!(perms, Some(0o700));
    }

    #[test]
    fn test_storage_readiness_missing_dir_autocreate_fails() {
        // AC3: Creation failure → single Fail message
        let fs = MockFilesystem::new();
        let check = make_check_no_overlays();

        for dir in &["home", "config", "nixos", ".work/etc", ".work/home"] {
            let path = format!("/mnt/hidden-volume/{}", dir);
            fs.mock_set_path_exists(&path, true);
            fs.mock_set_path_type(&path, "directory");
        }

        fs.mock_set_path_exists("/mnt/hidden-volume/etc", false);
        fs.mock_set_directory_creatable("/mnt/hidden-volume/etc", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("Storage not ready"));
        assert!(result.message().contains("etc/"));
    }

    #[test]
    fn test_storage_readiness_overlay_lower_missing_fail() {
        // AC3: Overlay lower missing → Fail
        let fs = MockFilesystem::new();
        let check = make_check_with_overlays();
        setup_all_required_dirs(&fs);

        // /home exists, /etc does NOT
        fs.mock_set_path_exists("/home", true);
        fs.mock_set_readable("/home", true);
        fs.mock_set_path_exists("/etc", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("etc lower directory not found"));
    }

    #[test]
    fn test_storage_readiness_overlay_upper_not_writable_fail() {
        // AC3: Upper not writable → single Fail
        let fs = MockFilesystem::new();
        let check = make_check_with_overlays();
        setup_all_required_dirs(&fs);
        setup_overlay_lower_dirs(&fs);

        // Override: home upper is not writable
        fs.mock_set_writable("/mnt/hidden-volume/home", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("Not writable: home upper"));
    }

    #[test]
    fn test_storage_readiness_overlay_work_not_writable_fail() {
        // AC3: Work not writable → Fail
        let fs = MockFilesystem::new();
        let check = make_check_with_overlays();
        setup_all_required_dirs(&fs);
        setup_overlay_lower_dirs(&fs);

        // Override: etc work is not writable
        fs.mock_set_writable("/mnt/hidden-volume/.work/etc", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("Not writable: etc work"));
    }

    #[test]
    fn test_storage_readiness_mixed_issues_single_fail() {
        // AC3: Mixed issues → single Fail message listing ALL problems
        let fs = MockFilesystem::new();
        let check = make_check_with_overlays();

        // config/ and nixos/ missing and not creatable
        for dir in &["etc", "home", ".work/etc", ".work/home"] {
            let path = format!("/mnt/hidden-volume/{}", dir);
            fs.mock_set_path_exists(&path, true);
            fs.mock_set_path_type(&path, "directory");
            fs.mock_set_writable(&path, true);
        }
        fs.mock_set_path_exists("/mnt/hidden-volume/config", false);
        fs.mock_set_directory_creatable("/mnt/hidden-volume/config", false);
        fs.mock_set_path_exists("/mnt/hidden-volume/nixos", false);
        fs.mock_set_directory_creatable("/mnt/hidden-volume/nixos", false);

        // Lower dirs: /etc not readable
        fs.mock_set_path_exists("/home", true);
        fs.mock_set_readable("/home", true);
        fs.mock_set_path_exists("/etc", true);
        fs.mock_set_readable("/etc", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        let msg = result.message();
        assert!(msg.contains("Storage not ready"), "msg: {}", msg);
        assert!(msg.contains("config/"), "missing config/: {}", msg);
        assert!(msg.contains("nixos/"), "missing nixos/: {}", msg);
        assert!(
            msg.contains("etc lower directory not readable"),
            "etc not readable: {}",
            msg
        );
    }

    #[test]
    fn test_storage_readiness_directory_is_file_triggers_autocreate() {
        // Directory exists but is a file → treated as missing, auto-create attempted
        let fs = MockFilesystem::new();
        let check = make_check_no_overlays();

        for dir in &["home", "config", "nixos", ".work/etc", ".work/home"] {
            let path = format!("/mnt/hidden-volume/{}", dir);
            fs.mock_set_path_exists(&path, true);
            fs.mock_set_path_type(&path, "directory");
        }

        // etc/ exists but is a file, not a directory
        fs.mock_set_path_exists("/mnt/hidden-volume/etc", true);
        fs.mock_set_path_type("/mnt/hidden-volume/etc", "file");
        fs.mock_set_directory_creatable("/mnt/hidden-volume/etc", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("etc/"));
    }

    // ========================================================================
    // NixOSConfigCheck Tests
    // ========================================================================

    #[test]
    fn test_nixos_config_check_success() {
        // AC5: Pre-flight validation - all conditions pass
        let fs = MockFilesystem::new();

        // Setup: All required files exist with correct content
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");

        fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");

        fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/mnt/hidden/etc/nixos/hardware-configuration.nix",
            "{ config, lib, pkgs, ... }:\n{ imports = [ /mnt/hidden/nixos/configuration.nix ]; }",
        );

        fs.mock_set_path_exists("/mnt/hidden/nixos/configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/nixos/configuration.nix", "file");

        let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
        let result = check.run(&fs).expect("Check should not error");

        assert!(
            result.is_pass(),
            "Check should pass when all conditions met"
        );
        assert_eq!(
            result.message(),
            "NixOS configuration overlay structure is valid"
        );
    }

    #[test]
    fn test_nixos_config_check_missing_base_config() {
        // AC5: Check 1 - Base hardware-configuration.nix missing
        let fs = MockFilesystem::new();

        // Base config does NOT exist
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", false);

        let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
        let result = check.run(&fs).expect("Check should not error");

        assert!(
            result.is_fail(),
            "Check should fail when base config missing"
        );
        assert!(
            result
                .message()
                .contains("Base /etc/nixos/hardware-configuration.nix not found")
        );
        assert!(
            result
                .message()
                .contains("Ensure NixOS is properly installed")
        );
    }

    #[test]
    fn test_nixos_config_check_missing_hidden_etc_nixos() {
        // AC5: Check 2 - Hidden etc/nixos directory missing
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");

        // Hidden etc/nixos directory does NOT exist
        fs.mock_set_path_exists("/mnt/hidden/etc/nixos", false);

        let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
        let result = check.run(&fs).expect("Check should not error");

        assert!(
            result.is_fail(),
            "Check should fail when hidden etc/nixos missing"
        );
        assert!(
            result
                .message()
                .contains("Hidden storage missing etc/nixos/ directory")
        );
        assert!(result.message().contains("/mnt/hidden/etc/nixos"));
        assert!(result.message().contains("Create this directory"));
    }

    #[test]
    fn test_nixos_config_check_missing_modified_hardware_config() {
        // AC5: Check 3 - Modified hardware-configuration.nix missing
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");

        fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");

        // Modified hardware-configuration.nix does NOT exist
        fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", false);

        let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
        let result = check.run(&fs).expect("Check should not error");

        assert!(
            result.is_fail(),
            "Check should fail when modified hardware config missing"
        );
        assert!(
            result
                .message()
                .contains("Modified hardware-configuration.nix not found")
        );
        assert!(
            result
                .message()
                .contains("/mnt/hidden/etc/nixos/hardware-configuration.nix")
        );
        assert!(
            result
                .message()
                .contains("Copy base config and add hidden import")
        );
    }

    #[test]
    fn test_nixos_config_check_missing_hidden_import() {
        // AC5: Check 4 - Modified hardware-configuration.nix missing hidden import
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");

        fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");

        fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos/hardware-configuration.nix", "file");
        // Content does NOT contain the hidden import
        fs.mock_set_file_content(
            "/mnt/hidden/etc/nixos/hardware-configuration.nix",
            "{ config, lib, pkgs, ... }:\n{ imports = [ ]; }",
        );

        let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
        let result = check.run(&fs).expect("Check should not error");

        assert!(
            result.is_fail(),
            "Check should fail when hidden import missing"
        );
        assert!(
            result
                .message()
                .contains("Modified hardware-configuration.nix missing hidden import")
        );
        assert!(
            result
                .message()
                .contains("/mnt/hidden/nixos/configuration.nix")
        );
        assert!(result.message().contains("imports = [ ..."));
    }

    #[test]
    fn test_nixos_config_check_missing_hidden_configuration() {
        // AC5: Check 5 - Hidden configuration.nix missing
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");

        fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");

        fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/mnt/hidden/etc/nixos/hardware-configuration.nix",
            "{ config, lib, pkgs, ... }:\n{ imports = [ /mnt/hidden/nixos/configuration.nix ]; }",
        );

        // Hidden configuration.nix does NOT exist
        fs.mock_set_path_exists("/mnt/hidden/nixos/configuration.nix", false);

        let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
        let result = check.run(&fs).expect("Check should not error");

        assert!(
            result.is_fail(),
            "Check should fail when hidden configuration.nix missing"
        );
        assert!(
            result
                .message()
                .contains("Hidden configuration.nix not found")
        );
        assert!(
            result
                .message()
                .contains("/mnt/hidden/nixos/configuration.nix")
        );
        assert!(
            result
                .message()
                .contains("Create this file with hidden environment settings")
        );
    }

    #[test]
    fn test_nixos_config_check_different_hidden_path() {
        // AC5: Test with non-standard hidden storage path
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");

        fs.mock_set_path_exists("/media/secret/etc/nixos", true);
        fs.mock_set_path_type("/media/secret/etc/nixos", "directory");

        fs.mock_set_path_exists("/media/secret/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/media/secret/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/media/secret/etc/nixos/hardware-configuration.nix",
            "{ imports = [ /media/secret/nixos/configuration.nix ]; }",
        );

        fs.mock_set_path_exists("/media/secret/nixos/configuration.nix", true);
        fs.mock_set_path_type("/media/secret/nixos/configuration.nix", "file");

        let check = NixOSConfigCheck::new(PathBuf::from("/media/secret"));
        let result = check.run(&fs).expect("Check should not error");

        assert!(
            result.is_pass(),
            "Check should work with custom hidden paths"
        );
    }

    #[test]
    fn test_nixos_config_check_integration_with_registry() {
        // AC5: Integration test - NixOSConfigCheck works with PreFlightRegistry
        let fs = MockFilesystem::new();

        // Setup valid configuration
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");

        fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");

        fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/mnt/hidden/etc/nixos/hardware-configuration.nix",
            "{ imports = [ /mnt/hidden/nixos/configuration.nix ]; }",
        );

        fs.mock_set_path_exists("/mnt/hidden/nixos/configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/nixos/configuration.nix", "file");

        let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        registry.add_check(Box::new(NixOSConfigCheck::new(PathBuf::from(
            "/mnt/hidden",
        ))));

        let result = registry.run_all(&fs);
        assert!(
            result.is_ok(),
            "Registry should succeed with valid NixOS config"
        );

        let results = result.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "nixos-config");
        assert!(results[0].1.is_pass());

        // Test failure case
        let fs_fail = MockFilesystem::new();
        fs_fail.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", false);

        let mut registry_fail: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        registry_fail.add_check(Box::new(NixOSConfigCheck::new(PathBuf::from(
            "/mnt/hidden",
        ))));

        let result_fail = registry_fail.run_all(&fs_fail);
        assert!(
            result_fail.is_err(),
            "Registry should fail with invalid NixOS config"
        );
        assert!(matches!(
            result_fail.unwrap_err(),
            NailsError::PreFlightCheckFailed(_)
        ));
    }

    // ========================================================================
    // SwapCheck Tests (Story 3.4)
    // ========================================================================

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
        let check = SpaceCheck::new(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT), 2048);
        assert_eq!(
            check.hidden_volume_path,
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
        );
        assert_eq!(check.minimum_space_mb, 2048);
    }

    #[test]
    fn test_space_check_default_values() {
        // AC 1: Default trait provides 1024 MB minimum and default path
        let check = SpaceCheck::default();
        assert_eq!(
            check.hidden_volume_path,
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
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
        fs.mock_set_free_space(
            Path::new(DEFAULT_HIDDEN_VOLUME_ROOT),
            2 * 1024 * 1024 * 1024,
        );

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
        fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 1024 * 1024 * 1024);

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
        fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 800 * 1024 * 1024);

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
        fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 512 * 1024 * 1024);

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
        fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 300 * 1024 * 1024);

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
        fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 511 * 1024 * 1024);

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
        fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 100 * 1024 * 1024);

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
        fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 0);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("Only 0 MB available"));
    }

    #[test]
    fn test_space_check_custom_minimum() {
        // AC 6: Custom minimum value works
        let fs = MockFilesystem::new();
        let check = SpaceCheck::new(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT), 2048); // 2GB minimum

        // Set up 3GB available
        fs.mock_set_free_space(
            Path::new(DEFAULT_HIDDEN_VOLUME_ROOT),
            3 * 1024 * 1024 * 1024,
        );

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert!(result.message().contains("3.0 GB available"));
    }

    #[test]
    fn test_space_check_custom_minimum_warn_threshold() {
        // AC 6: Custom minimum affects warn threshold (50% rule)
        let fs = MockFilesystem::new();
        let check = SpaceCheck::new(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT), 2048); // 2GB minimum

        // Set up 1.5GB available (between 1GB and 2GB = warn range)
        fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 1536 * 1024 * 1024);

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

    // ========================================================================
    // OverlayDirs Tests
    // ========================================================================

    #[test]
    fn test_overlay_dirs_new_constructor() {
        // AC 1: OverlayDirs struct with new() constructor
        let overlay = OverlayDirs::new(
            "home".to_string(),
            PathBuf::from("/home"),
            PathBuf::from("/mnt/hidden-volume/home"),
            PathBuf::from("/mnt/hidden-volume/.work/home"),
        );

        assert_eq!(overlay.name, "home");
        assert_eq!(overlay.lower, PathBuf::from("/home"));
        assert_eq!(overlay.upper, PathBuf::from("/mnt/hidden-volume/home"));
        assert_eq!(overlay.work, PathBuf::from("/mnt/hidden-volume/.work/home"));
    }

    #[test]
    fn test_overlay_dirs_struct_fields() {
        // AC 1: OverlayDirs has correct fields
        let overlay = OverlayDirs {
            name: "test".to_string(),
            lower: PathBuf::from("/test"),
            upper: PathBuf::from("/upper"),
            work: PathBuf::from("/work"),
        };

        assert_eq!(overlay.name, "test");
        assert_eq!(overlay.lower, PathBuf::from("/test"));
        assert_eq!(overlay.upper, PathBuf::from("/upper"));
        assert_eq!(overlay.work, PathBuf::from("/work"));
    }

    #[test]
    fn test_overlay_dirs_clone() {
        // Verify OverlayDirs is Clone
        let overlay = OverlayDirs::new(
            "home".to_string(),
            PathBuf::from("/home"),
            PathBuf::from("/upper"),
            PathBuf::from("/work"),
        );
        let cloned = overlay.clone();
        assert_eq!(overlay, cloned);
    }

    #[test]
    fn test_overlay_dirs_debug() {
        // Verify OverlayDirs is Debug
        let overlay = OverlayDirs::new(
            "home".to_string(),
            PathBuf::from("/home"),
            PathBuf::from("/upper"),
            PathBuf::from("/work"),
        );
        let debug = format!("{:?}", overlay);
        assert!(debug.contains("OverlayDirs"));
        assert!(debug.contains("home"));
    }

    #[test]
    fn test_storage_readiness_overlay_lower_not_readable_fail() {
        // Lower exists but not readable → Fail
        let fs = MockFilesystem::new();
        let check = make_check_with_overlays();
        setup_all_required_dirs(&fs);

        fs.mock_set_path_exists("/home", true);
        fs.mock_set_readable("/home", true);
        fs.mock_set_path_exists("/etc", true);
        fs.mock_set_readable("/etc", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(
            result
                .message()
                .contains("etc lower directory not readable")
        );
    }

    #[test]
    fn test_storage_readiness_overlay_upper_missing_fail() {
        // Upper directory missing → Fail
        let fs = MockFilesystem::new();
        let check = make_check_with_overlays();
        setup_all_required_dirs(&fs);
        setup_overlay_lower_dirs(&fs);

        // Override: home upper does not exist
        fs.mock_set_path_exists("/mnt/hidden-volume/home", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("home upper directory not found"));
    }

    #[test]
    fn test_storage_readiness_overlay_work_missing_fail() {
        // Work directory missing → Fail
        let fs = MockFilesystem::new();
        let check = make_check_with_overlays();
        setup_all_required_dirs(&fs);
        setup_overlay_lower_dirs(&fs);

        // Override: etc work does not exist
        fs.mock_set_path_exists("/mnt/hidden-volume/.work/etc", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("etc work directory not found"));
    }

    #[test]
    fn test_storage_readiness_collect_all_overlay_errors() {
        // All overlay dirs missing → single Fail with all issues listed
        let fs = MockFilesystem::new();
        let check = StorageReadinessCheck::new(
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
            vec![OverlayDirs::new(
                "home".to_string(),
                PathBuf::from("/home"),
                PathBuf::from("/mnt/hidden-volume/home"),
                PathBuf::from("/mnt/hidden-volume/.work/home"),
            )],
        );
        setup_all_required_dirs(&fs);

        // All overlay dirs missing
        fs.mock_set_path_exists("/home", false);
        fs.mock_set_path_exists("/mnt/hidden-volume/home", false);
        fs.mock_set_path_exists("/mnt/hidden-volume/.work/home", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("lower directory not found"));
        assert!(result.message().contains("upper directory not found"));
        assert!(result.message().contains("work directory not found"));
    }

    #[test]
    fn test_storage_readiness_multiple_missing_dirs_autocreate_partial() {
        // Multiple dirs missing: one creatable, one not → Fail with only the uncreatable
        let fs = MockFilesystem::new();
        let check = make_check_no_overlays();

        for dir in &["home", ".work/etc", ".work/home"] {
            let path = format!("/mnt/hidden-volume/{}", dir);
            fs.mock_set_path_exists(&path, true);
            fs.mock_set_path_type(&path, "directory");
        }

        // config/ missing but creatable
        fs.mock_set_path_exists("/mnt/hidden-volume/config", false);
        fs.mock_set_directory_creatable("/mnt/hidden-volume/config", true);
        // nixos/ missing and NOT creatable
        fs.mock_set_path_exists("/mnt/hidden-volume/nixos", false);
        fs.mock_set_directory_creatable("/mnt/hidden-volume/nixos", false);
        // etc/ exists
        fs.mock_set_path_exists("/mnt/hidden-volume/etc", true);
        fs.mock_set_path_type("/mnt/hidden-volume/etc", "directory");

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("nixos/"));
        // config/ was auto-created, so should NOT be in the error
    }

    #[test]
    fn test_storage_readiness_clone() {
        let check = make_check_with_overlays();
        let cloned = check.clone();
        assert_eq!(format!("{:?}", check), format!("{:?}", cloned));
    }

    #[test]
    fn test_storage_readiness_debug() {
        let check = make_check_no_overlays();
        let debug = format!("{:?}", check);
        assert!(debug.contains("StorageReadinessCheck"));
    }

    // ========================================================================
    // StateCheck Tests (Story 3.7)
    // ========================================================================

    #[test]
    fn test_state_check_new_constructor() {
        // AC 1: StateCheck::new() constructor accepting current state
        use crate::SystemState;
        let _check = StateCheck::new(SystemState::Inactive);
    }

    #[test]
    fn test_state_check_trait_metadata() {
        // AC 1, 2: StateCheck implements PreFlightCheck trait with correct name and description
        use crate::SystemState;
        let check = StateCheck::new(SystemState::Inactive);

        assert_eq!(
            <StateCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "state"
        );
        assert_eq!(
            <StateCheck as PreFlightCheck<MockFilesystem>>::description(&check),
            "Validates system state allows activation"
        );
    }

    #[test]
    fn test_state_check_inactive_state_pass() {
        // AC 3: Given current state is Inactive, When StateCheck runs, Then returns Pass
        use crate::SystemState;
        let fs = MockFilesystem::new();
        let check = StateCheck::new(SystemState::Inactive);

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert_eq!(
            result.message(),
            "System is inactive - ready for activation"
        );
    }

    #[test]
    fn test_state_check_active_state_fail() {
        // AC 4: Given current state is Active, When StateCheck runs, Then returns Fail with deactivate guidance
        use crate::SystemState;
        use chrono::Utc;
        let fs = MockFilesystem::new();
        let check = StateCheck::new(SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![],
        });

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert_eq!(
            result.message(),
            "System is already active. Run 'nails deactivate' first or use 'nails status' to check state."
        );
    }

    #[test]
    fn test_state_check_activating_state_fail() {
        // AC 5: Given current state is Activating, When StateCheck runs, Then returns Fail with wait/reboot guidance
        use crate::SystemState;
        use chrono::Utc;
        let fs = MockFilesystem::new();
        let check = StateCheck::new(SystemState::Activating {
            started_at: Utc::now(),
        });

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert_eq!(
            result.message(),
            "System is currently activating. Wait for completion or reboot if stuck."
        );
    }

    #[test]
    fn test_state_check_deactivating_state_fail() {
        // AC 2: Deactivating state should also fail (not in story AC but in implementation requirements)
        use crate::SystemState;
        use chrono::Utc;
        let fs = MockFilesystem::new();
        let check = StateCheck::new(SystemState::Deactivating {
            started_at: Utc::now(),
        });

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("deactivating"));
        assert!(
            result
                .message()
                .contains("Wait for completion or reboot if stuck")
        );
    }

    #[test]
    fn test_state_check_emergency_state_fail() {
        // AC 6: Given current state is Emergency, When StateCheck runs, Then returns Fail with reboot guidance
        use crate::SystemState;
        use chrono::Utc;
        let fs = MockFilesystem::new();
        let check = StateCheck::new(SystemState::Emergency {
            triggered_at: Utc::now(),
        });

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert_eq!(
            result.message(),
            "System is in emergency state. Reboot to reset state."
        );
    }

    #[test]
    fn test_state_check_all_states_coverage() {
        // AC 7: Write unit tests for all 5 state variants
        use crate::SystemState;
        use chrono::Utc;
        let fs = MockFilesystem::new();

        // Inactive -> Pass
        let check_inactive = StateCheck::new(SystemState::Inactive);
        assert!(check_inactive.run(&fs).unwrap().is_pass());

        // Active -> Fail
        let check_active = StateCheck::new(SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![],
        });
        assert!(check_active.run(&fs).unwrap().is_fail());

        // Activating -> Fail
        let check_activating = StateCheck::new(SystemState::Activating {
            started_at: Utc::now(),
        });
        assert!(check_activating.run(&fs).unwrap().is_fail());

        // Deactivating -> Fail
        let check_deactivating = StateCheck::new(SystemState::Deactivating {
            started_at: Utc::now(),
        });
        assert!(check_deactivating.run(&fs).unwrap().is_fail());

        // Emergency -> Fail
        let check_emergency = StateCheck::new(SystemState::Emergency {
            triggered_at: Utc::now(),
        });
        assert!(check_emergency.run(&fs).unwrap().is_fail());
    }

    #[test]
    fn test_state_check_integration_with_registry() {
        // Integration test: StateCheck works correctly with PreFlightRegistry
        use crate::SystemState;
        use chrono::Utc;
        let fs = MockFilesystem::new();
        let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();

        // Test with Inactive state (should pass)
        registry.add_check(Box::new(StateCheck::new(SystemState::Inactive)));
        let result = registry.run_all(&fs);
        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "state");
        assert!(results[0].1.is_pass());

        // Test with Active state (should fail)
        let mut registry_fail: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        registry_fail.add_check(Box::new(StateCheck::new(SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![],
        })));
        let result_fail = registry_fail.run_all(&fs);
        assert!(result_fail.is_err());
        assert!(matches!(
            result_fail.unwrap_err(),
            NailsError::PreFlightCheckFailed(_)
        ));
    }
}
