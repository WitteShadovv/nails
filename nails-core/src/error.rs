use thiserror::Error;

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
    /// Used when system validation fails before activation.
    #[error("Pre-flight check failed: {0}")]
    PreFlightCheckFailed(String),

    /// Configuration error (missing file, invalid format, etc.)
    #[error("Configuration error: {0}")]
    ConfigError(String),

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
            NailsError::IoError(_) => {}, // Expected
            _ => panic!("Expected IoError variant"),
        }
    }

    #[test]
    fn test_error_display_messages() {
        let err = NailsError::PermissionDenied("Root required".into());
        assert_eq!(err.to_string(), "Permission denied: Root required");

        let err = NailsError::InvalidState("Cannot activate when already active".into());
        assert_eq!(err.to_string(), "Invalid state: Cannot activate when already active");

        let err = NailsError::OverlayError("Mount failed".into());
        assert_eq!(err.to_string(), "Overlay operation failed: Mount failed");

        let err = NailsError::NixOSError("Profile switch failed".into());
        assert_eq!(err.to_string(), "NixOS operation failed: Profile switch failed");

        let err = NailsError::PreFlightCheckFailed("Hidden volume not mounted".into());
        assert_eq!(err.to_string(), "Pre-flight check failed: Hidden volume not mounted");

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
            NailsError::IoError(_) => {}, // Expected
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
        let _err5 = NailsError::PreFlightCheckFailed("test".into());
        let _err6 = NailsError::ConfigError("test".into());
        let _err7 = NailsError::IoError(std::io::Error::new(std::io::ErrorKind::Other, "test"));
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
            },
            _ => panic!("Expected IoError variant"),
        }
    }
}
