//! Ephemeral overlay directory configuration
//!
//! This module provides configuration for ephemeral overlays with tmpfs-backed
//! upper layers. These overlays store data in RAM and destroy it on unmount,
//! providing defense-in-depth against forensic analysis.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Ephemeral overlay directory configuration
///
/// Defines a single ephemeral overlay with tmpfs-backed upper and work layers.
///
/// # Example
///
/// ```rust
/// use nails_core::config::EphemeralOverlayDir;
/// use std::path::PathBuf;
///
/// let dir = EphemeralOverlayDir {
///     path: PathBuf::from("/var"),
///     tmpfs_upper_size: "1G".to_string(),
///     tmpfs_work_size: "512M".to_string(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EphemeralOverlayDir {
    /// Target directory path to overlay (e.g., "/var", "/tmp")
    pub path: PathBuf,

    /// Tmpfs size for upper layer (e.g., "1G", "512M")
    pub tmpfs_upper_size: String,

    /// Tmpfs size for work layer (e.g., "512M", "256M")
    pub tmpfs_work_size: String,
}

impl EphemeralOverlayDir {
    /// Parse tmpfs size string to bytes
    ///
    /// Supports standard size suffixes:
    /// - "M" or "MB" for megabytes
    /// - "G" or "GB" for gigabytes
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::config::EphemeralOverlayDir;
    /// use std::path::PathBuf;
    ///
    /// let dir = EphemeralOverlayDir {
    ///     path: PathBuf::from("/var"),
    ///     tmpfs_upper_size: "1G".to_string(),
    ///     tmpfs_work_size: "512M".to_string(),
    /// };
    ///
    /// assert_eq!(dir.parse_upper_size().unwrap(), 1024 * 1024 * 1024);
    /// assert_eq!(dir.parse_work_size().unwrap(), 512 * 1024 * 1024);
    /// ```
    pub fn parse_upper_size(&self) -> Result<u64, String> {
        parse_size(&self.tmpfs_upper_size)
    }

    /// Parse work directory tmpfs size to bytes
    pub fn parse_work_size(&self) -> Result<u64, String> {
        parse_size(&self.tmpfs_work_size)
    }
}

/// Parse size string to bytes
///
/// Internal helper for parsing tmpfs size specifications.
///
/// # Supported Formats
///
/// - "512M", "512MB" → 512 megabytes
/// - "1G", "1GB" → 1 gigabyte
/// - Numbers only → bytes
///
/// # Errors
///
/// Returns error string if format is invalid.
fn parse_size(size_str: &str) -> Result<u64, String> {
    let trimmed = size_str.trim().to_uppercase();

    // Check for gigabyte suffix
    if let Some(num_str) = trimmed.strip_suffix("GB") {
        let num: u64 = num_str
            .trim()
            .parse()
            .map_err(|_| format!("Invalid number in size: {}", size_str))?;
        return Ok(num * 1024 * 1024 * 1024);
    }

    if let Some(num_str) = trimmed.strip_suffix('G') {
        let num: u64 = num_str
            .trim()
            .parse()
            .map_err(|_| format!("Invalid number in size: {}", size_str))?;
        return Ok(num * 1024 * 1024 * 1024);
    }

    // Check for megabyte suffix
    if let Some(num_str) = trimmed.strip_suffix("MB") {
        let num: u64 = num_str
            .trim()
            .parse()
            .map_err(|_| format!("Invalid number in size: {}", size_str))?;
        return Ok(num * 1024 * 1024);
    }

    if let Some(num_str) = trimmed.strip_suffix('M') {
        let num: u64 = num_str
            .trim()
            .parse()
            .map_err(|_| format!("Invalid number in size: {}", size_str))?;
        return Ok(num * 1024 * 1024);
    }

    // No suffix, parse as bytes
    trimmed
        .parse::<u64>()
        .map_err(|_| format!("Invalid size format: {}", size_str))
}
