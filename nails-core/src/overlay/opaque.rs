//! Overlayfs opaque directory detection and cleanup
//!
//! When a directory is deleted and recreated through an active overlayfs mount,
//! the kernel sets `trusted.overlay.opaque=y` on the upper-layer directory.
//! This makes the upper directory completely **replace** (instead of merge with)
//! the lower-layer directory — hiding all lower-layer contents.
//!
//! This is a problem for NAILS because the upper layer (hidden volume) typically
//! contains only a few files (e.g., `hardware-configuration.nix`), while the
//! lower layer (base system) contains many more. An opaque upper directory hides
//! the base system contents, breaking things like `nixos-rebuild` which expects
//! to find `flake.nix` from the lower layer.
//!
//! This module provides functions to detect and strip opaque xattrs from upper
//! layer directories before mounting overlays.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Strip `trusted.overlay.opaque` xattr from all directories under `upper`.
///
/// This is idempotent — directories without the xattr are silently skipped.
/// Requires root privileges (trusted.* xattrs are root-only).
///
/// # Arguments
///
/// * `upper` - Root of the overlay upper layer directory
///
/// # Returns
///
/// Number of directories that had the opaque xattr stripped.
pub fn strip_opaque_xattrs(upper: &Path) -> usize {
    let opaque = find_opaque_dirs(upper);
    let count = opaque.len();

    for dir in &opaque {
        let _ = Command::new("setfattr")
            .args(["-x", "trusted.overlay.opaque"])
            .arg(dir)
            .stderr(std::process::Stdio::null())
            .status();
    }

    count
}

/// Find directories in the upper layer that have `trusted.overlay.opaque` set.
///
/// Returns an empty Vec if `getfattr` is not available or `upper` doesn't exist.
///
/// # Arguments
///
/// * `upper` - Root of the overlay upper layer directory
pub fn find_opaque_dirs(upper: &Path) -> Vec<PathBuf> {
    if !upper.exists() {
        return vec![];
    }

    // List all directories under upper
    let find_output = Command::new("find")
        .arg(upper)
        .args(["-type", "d"])
        .output();

    let dirs: Vec<PathBuf> = match find_output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter(|l| !l.is_empty())
            .map(PathBuf::from)
            .collect(),
        _ => return vec![],
    };

    // Check each directory for the opaque xattr
    let mut opaque = Vec::new();
    for dir in dirs {
        let result = Command::new("getfattr")
            .args(["-n", "trusted.overlay.opaque"])
            .arg(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        if let Ok(status) = result
            && status.success()
        {
            opaque.push(dir);
        }
    }

    opaque
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_opaque_dirs_nonexistent_path() {
        let result = find_opaque_dirs(Path::new("/nonexistent/path/that/doesnt/exist"));
        assert!(result.is_empty());
    }

    #[test]
    fn test_strip_opaque_xattrs_nonexistent_path() {
        let count = strip_opaque_xattrs(Path::new("/nonexistent/path/that/doesnt/exist"));
        assert_eq!(count, 0);
    }
}
