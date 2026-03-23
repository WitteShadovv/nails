//! Types for cleanup operations
//!
//! Provides the configuration, mode, and reporting types used by the cleanup system.

use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

/// Cleanup execution mode
///
/// Determines the thoroughness of cleanup operations:
/// - **Thorough**: Full cleanup with optional verification (deactivation)
/// - **Fast**: Speed-priority cleanup without verification (emergency)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupMode {
    /// Thorough cleanup mode for normal deactivation
    ///
    /// Performs complete cleanup with optional verification step.
    /// Use when time permits and verification is valuable.
    Thorough {
        /// If true, verify artifacts are removed after each cleanup step
        verify_cleanup: bool,
    },

    /// Fast cleanup mode for emergency deactivation
    ///
    /// Prioritizes speed over thoroughness. Skips verification.
    /// Use when under time pressure (emergency scenarios).
    Fast,
}

impl Default for CleanupMode {
    fn default() -> Self {
        CleanupMode::Thorough {
            verify_cleanup: true,
        }
    }
}

/// Configuration for cleanup operations
///
/// Controls which cleanup operations are performed and their parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupConfig {
    /// Whether to clear shell history (default: true)
    pub clear_history: bool,

    /// Whether to clear temporary files (default: true)
    pub clear_temp_files: bool,

    /// Whether to clear log files (default: true)
    pub clear_logs: bool,

    /// Patterns to match in history for removal (case-insensitive)
    /// Default: ["nails", "NAILS"]
    pub history_patterns: Vec<String>,

    /// Directories to scan for temporary files
    /// Default: ["/tmp"]
    pub temp_dirs: Vec<PathBuf>,

    /// Path to NAILS log directory (must be on hidden volume)
    /// Default: {HIDDEN_VOLUME_ROOT}/logs
    pub log_path: PathBuf,

    /// Path to hidden volume root (for security validation)
    /// Default: HIDDEN_VOLUME_ROOT
    pub hidden_volume_path: PathBuf,

    /// Whether to sanitize memory after cleanup (default: false)
    ///
    /// When enabled, attempts to clear page cache by writing "3" to
    /// /proc/sys/vm/drop_caches. Requires root privileges.
    /// This helps prevent forensic recovery of cleanup artifacts from RAM.
    #[serde(default)]
    pub sanitize_memory: bool,

    /// Use secure deletion (overwrite before delete) (default: false)
    ///
    /// When enabled, files are overwritten with zeros, random data, and zeros
    /// again before being deleted. This makes forensic recovery more difficult.
    #[serde(default)]
    pub secure_delete: bool,

    /// Whether to perform post-unmount cleanup on the real disk (default: true)
    ///
    /// When enabled, a second cleanup phase runs AFTER overlay unmount to clean
    /// history files on the actual disk. This is critical for forensic safety
    /// because the first cleanup phase only cleans the overlay layer, not the
    /// real underlying filesystem.
    ///
    /// The post-unmount cleanup:
    /// - Uses secure_delete=true for better forensic resistance
    /// - Cleans an extended list of history file locations (not just shells)
    /// - Is best-effort (failures don't abort deactivation)
    #[serde(default = "default_post_unmount_cleanup")]
    pub post_unmount_cleanup: bool,
}

fn default_post_unmount_cleanup() -> bool {
    true
}

impl Default for CleanupConfig {
    fn default() -> Self {
        let hidden_volume = PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT);
        Self {
            clear_history: true,
            clear_temp_files: true,
            clear_logs: true,
            history_patterns: vec!["nails".to_string(), "NAILS".to_string()],
            temp_dirs: vec![PathBuf::from("/tmp")],
            log_path: hidden_volume.join("logs"),
            hidden_volume_path: hidden_volume,
            sanitize_memory: false,
            secure_delete: false,
            post_unmount_cleanup: true,
        }
    }
}

/// Report of cleanup operations
///
/// Provides detailed accounting of what was cleaned, any errors, and timing.
#[derive(Debug, Clone)]
pub struct CleanupReport {
    /// Items that were successfully cleaned
    pub cleaned_items: Vec<String>,

    /// Errors encountered during cleanup (best-effort continues)
    pub errors: Vec<String>,

    /// Total time taken for cleanup
    pub duration: Duration,

    /// The cleanup mode that was used
    pub mode: CleanupMode,

    /// Result of verification (None if verification was skipped)
    /// - Some(true): All verifications passed
    /// - Some(false): At least one verification failed
    /// - None: Verification was not performed (Fast mode or verify_cleanup=false)
    pub verification_passed: Option<bool>,

    /// Whether memory sanitization was performed
    pub memory_sanitized: bool,

    /// Number of canary pattern findings during verification
    pub canary_findings_count: usize,
}

impl CleanupReport {
    /// Create a new empty report with the specified mode
    pub fn new(mode: CleanupMode) -> Self {
        Self {
            cleaned_items: Vec::new(),
            errors: Vec::new(),
            duration: Duration::ZERO,
            mode,
            verification_passed: None,
            memory_sanitized: false,
            canary_findings_count: 0,
        }
    }

    /// Check if cleanup was fully successful (no errors)
    pub fn is_successful(&self) -> bool {
        self.errors.is_empty()
    }

    /// Get total number of items cleaned
    pub fn total_cleaned(&self) -> usize {
        self.cleaned_items.len()
    }

    /// Add a cleaned item to the report
    pub fn add_cleaned(&mut self, item: impl Into<String>) {
        self.cleaned_items.push(item.into());
    }

    /// Add an error to the report
    pub fn add_error(&mut self, error: impl Into<String>) {
        self.errors.push(error.into());
    }

    /// Extend cleaned items with a vector of items
    pub fn extend_cleaned(&mut self, items: Vec<String>) {
        self.cleaned_items.extend(items);
    }
}

impl Default for CleanupReport {
    fn default() -> Self {
        Self::new(CleanupMode::default())
    }
}

impl fmt::Display for CleanupReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Cleanup Report")?;
        writeln!(f, "==============")?;
        writeln!(f, "Mode: {:?}", self.mode)?;
        writeln!(f, "Duration: {:?}", self.duration)?;

        if let CleanupMode::Fast = self.mode {
            writeln!(f, "Note: Fast mode - verification skipped")?;
        }

        writeln!(f)?;

        if self.cleaned_items.is_empty() {
            writeln!(f, "No items cleaned.")?;
        } else {
            writeln!(f, "Cleaned ({}):", self.cleaned_items.len())?;
            for item in &self.cleaned_items {
                writeln!(f, "  ✓ {}", item)?;
            }
        }

        if !self.errors.is_empty() {
            writeln!(f)?;
            writeln!(f, "Errors ({}):", self.errors.len())?;
            for error in &self.errors {
                writeln!(f, "  ✗ {}", error)?;
            }
        }

        if let Some(passed) = self.verification_passed {
            writeln!(f)?;
            if passed {
                writeln!(f, "✓ Verification passed - no artifacts remain")?;
            } else {
                writeln!(f, "⚠ Verification failed - some artifacts may remain")?;
                if self.canary_findings_count > 0 {
                    writeln!(
                        f,
                        "  Found {} canary pattern(s) in scanned files",
                        self.canary_findings_count
                    )?;
                }
            }
        }

        if self.memory_sanitized {
            writeln!(f)?;
            writeln!(f, "✓ Memory sanitization completed (page cache cleared)")?;
        }

        Ok(())
    }
}
