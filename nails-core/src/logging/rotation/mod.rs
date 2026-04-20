//! Log file rotation and retention management
//!
//! Provides automatic log rotation based on file size limits and
//! enforcement of retention policies based on file age.

use crate::obfuscate;
use crate::{Filesystem, Result};
use std::path::Path;

use super::path::is_permission_denied;

/// Default maximum log file size in megabytes
pub const DEFAULT_MAX_LOG_SIZE_MB: u64 = 10;

/// Default log retention period in days
pub const DEFAULT_RETENTION_DAYS: u64 = 7;

/// Log file name within the log directory
///
/// # Note
///
/// This constant is kept for backwards compatibility with tests.
/// The actual value is deobfuscated at runtime via `log_file_name()`.
pub const LOG_FILE_NAME: &str = "nails.log";

/// Get the log file name (deobfuscated at runtime)
#[inline]
#[allow(dead_code)]
pub fn log_file_name() -> String {
    obfuscate::log_file_name()
}

/// Check if log rotation should be triggered
///
/// Compares current log file size against `max_log_size_mb` threshold.
/// Uses overflow-safe arithmetic per architecture requirements.
///
/// # Arguments
///
/// * `log_path` - Directory containing log files
/// * `max_log_size_mb` - Maximum log file size in megabytes
/// * `fs` - Filesystem implementation
///
/// # Returns
///
/// `Ok(true)` if file size exceeds threshold (rotation needed),
/// `Ok(false)` if file size is within limit.
///
/// # Errors
///
/// Returns `NailsError::IoError` if log file doesn't exist or cannot be accessed.
///
/// # Overflow Safety
///
/// Uses `checked_mul()` for size calculation. If multiplication overflows,
/// treats threshold as `u64::MAX` (effectively infinite - no rotation).
pub fn should_rotate<F: Filesystem>(log_path: &Path, max_log_size_mb: u64, fs: &F) -> Result<bool> {
    let log_file = log_path.join(LOG_FILE_NAME);
    let file_size = fs.file_size(&log_file)?;

    // Overflow-safe size calculation: MB to bytes
    let threshold = max_log_size_mb
        .checked_mul(1024)
        .and_then(|kb| kb.checked_mul(1024))
        .unwrap_or(u64::MAX);

    Ok(file_size > threshold)
}

/// Rotate log files when size limit is exceeded
///
/// Renames logs in sequence (reverse order to avoid overwriting):
/// - `nails.log.6` → `nails.log.7`
/// - `nails.log.5` → `nails.log.6`
/// - ...
/// - `nails.log.1` → `nails.log.2`
/// - `nails.log` → `nails.log.1`
///
/// Creates a new empty `nails.log` file after rotation.
/// Enforces retention policy after rotation completes.
///
/// # Arguments
///
/// * `log_path` - Directory containing log files
/// * `max_log_size_mb` - Maximum log file size in megabytes
/// * `retention_days` - Number of days to retain log files
/// * `fs` - Filesystem implementation
///
/// # Returns
///
/// `Ok(())` if rotation completed successfully or was not needed.
/// Continues on individual file errors (degraded but functional).
///
/// # Errors
///
/// Returns `NailsError::IoError` only if critical operations fail.
/// Individual rename/remove failures are logged but don't abort rotation.
///
/// # AC Compliance
///
/// - AC #1: No-op if size <= max_log_size_mb
/// - AC #2: Rotates in sequence, logs rotation event
/// - AC #3: Calls `enforce_retention()` after rotation
/// - AC #4: Logs warning on permission denied, continues with degraded functionality
pub fn rotate_logs<F: Filesystem>(
    log_path: &Path,
    max_log_size_mb: u64,
    retention_days: u64,
    fs: &F,
) -> Result<()> {
    // Check if rotation is needed (AC #1)
    match should_rotate(log_path, max_log_size_mb, fs) {
        Ok(false) => return Ok(()), // No-op
        Err(e) => {
            // Log warning but continue - logging still works to current file
            tracing::warn!("Failed to check log file size: {}", e);
            return Err(e);
        }
        Ok(true) => {} // Proceed with rotation
    }

    let log_file = log_path.join(LOG_FILE_NAME);
    #[allow(unused_assignments)]
    let mut rotation_completed = false;
    #[allow(unused_assignments)]
    let mut new_log_created = false;

    // Rotate numbered logs in REVERSE order (highest to lowest)
    // This prevents overwriting: .6 -> .7, .5 -> .6, etc.
    for i in (1..retention_days).rev() {
        let from = log_path.join(format!("{}.{}", LOG_FILE_NAME, i));
        let to = log_path.join(format!("{}.{}", LOG_FILE_NAME, i + 1));

        if fs.path_exists(&from).unwrap_or(false) {
            match fs.rename_file(&from, &to) {
                Ok(_) => {}
                Err(e) => {
                    // Check if this is a permission denied error
                    if is_permission_denied(&e) {
                        tracing::warn!(
                            "Log rotation failed: permission denied renaming {}",
                            from.display()
                        );
                    } else {
                        tracing::warn!(
                            "Failed to rename {} to {}: {}",
                            from.display(),
                            to.display(),
                            e
                        );
                    }
                    // Continue with other files (degraded but functional)
                }
            }
        }
    }

    // Rotate current log to .1
    let log_1 = log_path.join(format!("{}.1", LOG_FILE_NAME));
    match fs.rename_file(&log_file, &log_1) {
        Ok(_) => {
            rotation_completed = true;
        }
        Err(e) => {
            // Log specific permission denied message per AC #4
            if is_permission_denied(&e) {
                tracing::warn!(
                    "Log rotation failed: permission denied renaming {}",
                    log_file.display()
                );
            } else {
                tracing::warn!(
                    "Failed to rename {} to {}: {}",
                    log_file.display(),
                    log_1.display(),
                    e
                );
            }
            // Can't continue without moving current log
            return Err(e);
        }
    }

    // Create new empty log file
    match fs.write_file_content(&log_file, "") {
        Ok(_) => {
            new_log_created = true;
        }
        Err(e) => {
            if is_permission_denied(&e) {
                tracing::warn!("Log rotation failed: permission denied creating new log file",);
            } else {
                tracing::warn!(
                    "Failed to create new log file {}: {}",
                    log_file.display(),
                    e
                );
            }
            // Try to restore rotated log if new file creation failed
            let _ = fs.rename_file(&log_1, &log_file);
            return Err(e);
        }
    }

    // Only log rotation event if it actually completed (AC #2)
    if rotation_completed && new_log_created {
        tracing::info!("Rotated logs: nails.log -> nails.log.1");

        // Enforce retention policy (AC #3)
        let _ = enforce_retention(log_path, retention_days, fs);
    }

    Ok(())
}

/// Enforce log retention policy
///
/// Deletes numbered log files older than the retention period based on
/// file modification timestamps.
///
/// # Arguments
///
/// * `log_path` - Directory containing log files
/// * `retention_days` - Number of days to retain log files
/// * `fs` - Filesystem implementation
///
/// # Returns
///
/// `Ok(())` if retention enforcement succeeded.
///
/// # Errors
///
/// Returns `NailsError::IoError` if file metadata access or deletion fails.
///
/// # AC Compliance
///
/// - AC #3: Checks file modification timestamps
/// - AC #3: Deletes logs older than retention_days (default 7)
/// - AC #3: Logs each deletion with age information
pub fn enforce_retention<F: Filesystem>(
    log_path: &Path,
    retention_days: u64,
    fs: &F,
) -> Result<()> {
    // List all files in log directory
    let entries = fs.list_directory(log_path)?;

    let now = chrono::Utc::now();

    for entry in entries {
        // Check if filename matches pattern: nails.log.N
        if let Some(filename) = entry.file_name().and_then(|n| n.to_str())
            && filename.starts_with(&format!("{}.", LOG_FILE_NAME))
        {
            // Get file modification time
            match fs.modified_time(&entry) {
                Ok(modified) => {
                    // Calculate age in days
                    let duration = now.signed_duration_since(modified);
                    let age_days = duration.num_days();

                    // Delete if older than retention window
                    if age_days > retention_days as i64 {
                        match fs.remove_file(&entry) {
                            Ok(_) => {
                                tracing::info!(
                                    "Deleted old log: {} ({} days old)",
                                    filename,
                                    age_days
                                );
                            }
                            Err(e) => {
                                // Log deletion failure but continue with other files
                                tracing::warn!("Failed to delete old log {}: {}", filename, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    // Log error accessing metadata but continue with other files
                    tracing::warn!("Failed to get modification time for {}: {}", filename, e);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;
