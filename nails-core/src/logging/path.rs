//! Path validation and manipulation utilities for logging
//!
//! Provides secure path handling to prevent directory traversal attacks
//! and ensure logs are written only to the hidden volume.

use crate::NailsError;
use std::path::{Path, PathBuf};

/// Check if an error indicates permission was denied
///
/// Helper for detecting permission-related failures to log
/// appropriate warning messages per AC #4.
pub(crate) fn is_permission_denied(err: &NailsError) -> bool {
    match err {
        NailsError::IoError(io) => {
            matches!(io.kind(), std::io::ErrorKind::PermissionDenied)
        }
        _ => false,
    }
}

/// Clean a path by resolving `..` components without filesystem access
///
/// This prevents path traversal attacks like `/mnt/hidden-volume/../var/log`
/// by manually resolving parent directory references.
///
/// # Security
///
/// This function is a critical component of path validation. It ensures that
/// path traversal attempts using `..` components are neutralized before
/// checking if a path is within the hidden volume. Combined with
/// symlink checking in `init()`, this defense-in-depth prevents attackers
/// from bypassing hidden volume validation.
///
/// # Limitations
///
/// **Does not follow symlinks** - Symlink detection is handled separately
/// via `Filesystem::is_symlink()` to prevent symlink-based bypasses.
pub(crate) fn clean_path(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                // Pop the last component when encountering ".."
                if !components.is_empty() {
                    components.pop();
                }
            }
            std::path::Component::Normal(c) => {
                components.push(c);
            }
            std::path::Component::RootDir => {
                // Start fresh from root
                components.clear();
            }
            std::path::Component::CurDir => {
                // Ignore current directory component
            }
            std::path::Component::Prefix(_) => {
                // Ignore path prefix (Windows-only)
            }
        }
    }

    // Build cleaned path from collected components
    // Start with root if the original path was absolute
    let mut cleaned = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        PathBuf::new()
    };

    for component in components {
        cleaned.push(component);
    }
    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    #[test]
    fn test_clean_path_no_traversal() {
        assert_eq!(
            clean_path(Path::new("/mnt/hidden-volume/logs")),
            PathBuf::from("/mnt/hidden-volume/logs")
        );
    }

    #[test]
    fn test_clean_path_with_single_traversal() {
        // /mnt/hidden-volume/../var/log resolves to /mnt/var/log (one level up from hidden-volume)
        assert_eq!(
            clean_path(Path::new("/mnt/hidden-volume/../var/log")),
            PathBuf::from("/mnt/var/log")
        );
    }

    #[test]
    fn test_clean_path_with_double_traversal() {
        assert_eq!(
            clean_path(Path::new("/mnt/hidden-volume/../../etc")),
            PathBuf::from("/etc")
        );
    }

    #[test]
    fn test_clean_path_root() {
        assert_eq!(clean_path(Path::new("/")), PathBuf::from("/"));
    }

    #[test]
    fn test_clean_path_with_dot() {
        // CurDir (.) is ignored by our cleaner
        assert_eq!(
            clean_path(Path::new("/mnt/./hidden-volume/logs")),
            PathBuf::from("/mnt/hidden-volume/logs")
        );
    }

    #[test]
    fn test_clean_path_trailing_slash() {
        use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
        assert_eq!(
            clean_path(Path::new("/mnt/hidden-volume/")),
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
        );
    }

    #[test]
    fn test_is_permission_denied_matches_permission_denied_io_error() {
        let err = NailsError::IoError(std::io::Error::new(
            ErrorKind::PermissionDenied,
            "access denied",
        ));

        assert!(is_permission_denied(&err));
    }

    #[test]
    fn test_is_permission_denied_rejects_other_io_error_kinds() {
        let err = NailsError::IoError(std::io::Error::new(ErrorKind::NotFound, "missing"));

        assert!(!is_permission_denied(&err));
    }

    #[test]
    fn test_is_permission_denied_rejects_non_io_errors() {
        let err = NailsError::ConfigError("bad config".to_string());

        assert!(!is_permission_denied(&err));
    }

    #[test]
    fn test_clean_path_relative_parent_components() {
        assert_eq!(
            clean_path(Path::new("logs/../audit/app.log")),
            PathBuf::from("audit/app.log")
        );
    }

    #[test]
    fn test_clean_path_relative_leading_parent_is_dropped() {
        assert_eq!(
            clean_path(Path::new("../logs/app.log")),
            PathBuf::from("logs/app.log")
        );
    }

    #[test]
    fn test_clean_path_absolute_cannot_escape_root() {
        assert_eq!(
            clean_path(Path::new("/../../etc/passwd")),
            PathBuf::from("/etc/passwd")
        );
    }

    #[test]
    fn test_clean_path_mixed_dot_and_parent_components() {
        assert_eq!(
            clean_path(Path::new("/mnt/hidden-volume/logs/./../audit")),
            PathBuf::from("/mnt/hidden-volume/audit")
        );
    }
}
