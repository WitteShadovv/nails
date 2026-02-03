use thiserror::Error;

/// Format pre-flight check failures for display
///
/// Converts a list of (check_name, error_message) tuples into a formatted
/// multi-line string for error output.
fn format_preflight_errors(errors: &[(String, String)]) -> String {
    errors
        .iter()
        .map(|(name, msg)| format!("  - [{}] {}", name, msg))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Comprehensive error types for NAILS operations
///
/// All NAILS operations return Result<T, NailsError> for explicit error handling.
/// This enum covers all error conditions across the system with rich context.
#[derive(Error, Debug)]
pub enum NailsError {
    /// Permission denied - operation requires root privileges or filesystem access
    ///
    /// # Example
    /// ```
    /// # use nails_core::{NailsError, Result};
    /// fn check_permission() -> Result<()> {
    ///     return Err(NailsError::PermissionDenied(
    ///         "Mounting overlays requires root privileges".into()
    ///     ));
    /// }
    /// ```
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Invalid state transition or operation
    ///
    /// Used when state machine validation fails or an operation is invalid
    /// for the current system state.
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Overlay filesystem operation failed
    ///
    /// Covers mount, unmount, and overlay configuration errors.
    #[error("Overlay operation failed: {0}")]
    OverlayError(String),

    /// NixOS-specific operation failed
    ///
    /// Covers profile switching, NixOS rebuild, and configuration errors.
    #[error("NixOS operation failed: {0}")]
    NixOSError(String),

    /// Pre-flight validation check failed
    ///
    /// Contains a list of (check_name, error_message) tuples for all failed checks.
    /// This allows comprehensive reporting of multiple validation failures.
    ///
    /// # Example
    /// ```
    /// # use nails_core::NailsError;
    /// let failures = vec![
    ///     ("swap-check".to_string(), "Swap is enabled - disable before activation".to_string()),
    ///     ("space-check".to_string(), "Insufficient disk space: 100 MB available, 500 MB required".to_string()),
    /// ];
    /// let err = NailsError::PreFlightCheckFailed(failures);
    /// ```
    #[error("Pre-flight checks failed:\n{}", format_preflight_errors(.0))]
    PreFlightCheckFailed(Vec<(String, String)>),

    /// Configuration error (missing file, invalid format, etc.)
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Invalid command-line argument or option
    ///
    /// Used when CLI flags or options are invalid or conflicting.
    /// Story 4.15: User Prompts and CLI Flags for Overlay Strategy
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// Target is already mounted
    #[error("Already mounted: {path}")]
    AlreadyMounted { path: std::path::PathBuf },

    /// Mount point is busy (open files)
    #[error("Mount busy: {path}\nSuggestion: {suggestion}")]
    MountBusy {
        path: std::path::PathBuf,
        suggestion: String,
    },

    /// Unmount operation failed
    #[error("Unmount failed: {path}\nReason: {reason}")]
    UnmountError {
        path: std::path::PathBuf,
        reason: String,
    },

    /// Swap disable failed
    #[error("Swap disable failed")]
    SwapDisableFailed,

    /// NixOS profile not found
    #[error("NixOS profile not found: {profile}")]
    NixOSProfileNotFound { profile: String },

    /// NixOS build failed
    #[error("NixOS build failed for profile: {profile}")]
    NixOSBuildFailed { profile: String },

    /// NixOS switch failed
    #[error("NixOS switch failed for profile: {profile}")]
    NixOSSwitchFailed { profile: String },

    /// Cleanup operation failed
    ///
    /// Used when artifact cleanup fails during deactivation.
    /// Per AC4: cleanup failures trigger rollback to ACTIVE state.
    ///
    /// # Example
    /// ```
    /// # use nails_core::NailsError;
    /// let err = NailsError::CleanupError(
    ///     "Failed to remove history files: permission denied".to_string()
    /// );
    /// ```
    #[error("Cleanup failed: {0}")]
    CleanupError(String),

    /// I/O error (transparently converted from std::io::Error)
    ///
    /// This variant has #[from] attribute, enabling automatic conversion
    /// from std::io::Error via the ? operator.
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

/// Result type alias for NAILS operations
///
/// All public functions return Result<T, NailsError> for explicit error handling.
/// This enables the ? operator for error propagation throughout the codebase.
///
/// # Example
/// ```
/// use nails_core::{Result, NailsError};
///
/// fn read_config() -> Result<String> {
///     let content = std::fs::read_to_string("/path/to/config")?;
///     Ok(content)
/// }
/// ```
pub type Result<T> = std::result::Result<T, NailsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_error_automatic_conversion() {
        // std::io::Error should automatically convert to NailsError::IoError
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let nails_err: NailsError = io_err.into();

        match nails_err {
            NailsError::IoError(_) => {} // Expected
            _ => panic!("Expected IoError variant"),
        }
    }

    #[test]
    fn test_error_display_messages() {
        let err = NailsError::PermissionDenied("Root required".into());
        assert_eq!(err.to_string(), "Permission denied: Root required");

        let err = NailsError::InvalidState("Cannot activate when already active".into());
        assert_eq!(
            err.to_string(),
            "Invalid state: Cannot activate when already active"
        );

        let err = NailsError::OverlayError("Mount failed".into());
        assert_eq!(err.to_string(), "Overlay operation failed: Mount failed");

        let err = NailsError::NixOSError("Profile switch failed".into());
        assert_eq!(
            err.to_string(),
            "NixOS operation failed: Profile switch failed"
        );

        let err = NailsError::PreFlightCheckFailed(vec![(
            "hidden-volume".to_string(),
            "Hidden volume not mounted".to_string(),
        )]);
        assert!(err.to_string().contains("Pre-flight checks failed"));
        assert!(err.to_string().contains("hidden-volume"));
        assert!(err.to_string().contains("Hidden volume not mounted"));

        let err = NailsError::ConfigError("Missing config key".into());
        assert_eq!(err.to_string(), "Configuration error: Missing config key");
    }

    #[test]
    fn test_error_debug_output() {
        let err = NailsError::OverlayError("Mount failed".into());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("OverlayError"));
        assert!(debug_str.contains("Mount failed"));
    }

    #[test]
    fn test_result_type_alias() {
        // Result<T> should work as expected
        fn returns_ok() -> Result<String> {
            Ok("success".to_string())
        }

        fn returns_err() -> Result<String> {
            Err(NailsError::ConfigError("Missing config".into()))
        }

        assert!(returns_ok().is_ok());
        assert!(returns_err().is_err());
    }

    #[test]
    fn test_error_propagation_with_question_mark() {
        // Test that ? operator works with std::io::Error
        fn read_file() -> Result<String> {
            let content = std::fs::read_to_string("/nonexistent/path/that/does/not/exist")?;
            Ok(content)
        }

        let result = read_file();
        assert!(result.is_err());

        // Verify it's an IoError variant
        match result.unwrap_err() {
            NailsError::IoError(_) => {} // Expected
            _ => panic!("Expected IoError variant from automatic conversion"),
        }
    }

    #[test]
    fn test_all_error_variants_constructible() {
        // Verify all error variants can be constructed
        let _err1 = NailsError::PermissionDenied("test".into());
        let _err2 = NailsError::InvalidState("test".into());
        let _err3 = NailsError::OverlayError("test".into());
        let _err4 = NailsError::NixOSError("test".into());
        let _err5 =
            NailsError::PreFlightCheckFailed(vec![("test-check".to_string(), "test".to_string())]);
        let _err6 = NailsError::ConfigError("test".into());
        let _err7 = NailsError::InvalidArgument("test".into());
        let _err8 = NailsError::IoError(std::io::Error::other("test"));

        // Filesystem-specific error variants
        use std::path::PathBuf;
        let _err9 = NailsError::AlreadyMounted {
            path: PathBuf::from("/test"),
        };
        let _err10 = NailsError::MountBusy {
            path: PathBuf::from("/test"),
            suggestion: "Close open files".into(),
        };
        let _err11 = NailsError::UnmountError {
            path: PathBuf::from("/test"),
            reason: "Test reason".into(),
        };
        let _err12 = NailsError::SwapDisableFailed;
        let _err13 = NailsError::NixOSProfileNotFound {
            profile: "test-profile".into(),
        };
        let _err14 = NailsError::NixOSBuildFailed {
            profile: "test-profile".into(),
        };
        let _err15 = NailsError::NixOSSwitchFailed {
            profile: "test-profile".into(),
        };
    }

    #[test]
    fn test_error_context_preserved() {
        // Verify that context strings are preserved in error messages
        let context = "specific error context with details";
        let err = NailsError::PermissionDenied(context.to_string());
        assert!(err.to_string().contains(context));
    }

    #[test]
    fn test_io_error_preserves_kind() {
        // Verify that IoError preserves the original error kind
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let nails_err: NailsError = io_err.into();

        match nails_err {
            NailsError::IoError(inner) => {
                assert_eq!(inner.kind(), std::io::ErrorKind::PermissionDenied);
            }
            _ => panic!("Expected IoError variant"),
        }
    }
}
