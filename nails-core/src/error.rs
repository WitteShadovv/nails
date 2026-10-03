use nix::errno::Errno;
use thiserror::Error;

/// One failed pre-flight check: its name, the problem, and the concrete action
/// that clears it (when the check named one).
///
/// Carrying the remediation alongside the message lets the CLI state each
/// problem once and then print a single deduplicated list of actions, rather
/// than inlining `Run: ...` fragments into every failure line.
pub type PreFlightFailure = (String, String, Option<String>);

/// A collection of [`PreFlightFailure`]s in check-execution order.
pub type PreFlightFailures = Vec<PreFlightFailure>;

/// Format pre-flight check failures for display
///
/// Converts the (check_name, message, remediation) tuples into a formatted
/// multi-line string for error output. The remediation, when present, is shown
/// on its own indented line so the problem and its fix read as a pair.
fn format_preflight_errors(errors: &[PreFlightFailure]) -> String {
    errors
        .iter()
        .map(|(name, msg, remediation)| match remediation {
            Some(fix) => format!("  - [{}] {}\n    fix: {}", name, msg, fix),
            None => format!("  - [{}] {}", name, msg),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// ` <file>` when a configuration file is known, otherwise nothing.
fn in_file(file: Option<&std::path::Path>) -> String {
    file.map(|f| format!(" {}", f.display()))
        .unwrap_or_default()
}

/// Comma-joined mount paths for the deactivation-incomplete message.
fn format_remaining_mounts(mounts: &[std::path::PathBuf]) -> String {
    mounts
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Comprehensive error types for NAILS operations
///
/// All NAILS operations return Result<T, NailsError> for explicit error handling.
/// This enum covers all error conditions across the system with rich context.
#[derive(Error, Debug)]
pub enum NailsError {
    #[error("NixOS preflight failed: {category}: {message}")]
    NixOSPreflightError {
        category: &'static str,
        message: String,
    },

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

    /// Overlay mount rejected by the kernel, carrying the raw errno.
    ///
    /// The errno is what the overlay strategy branches on: `EINVAL`, `EBUSY`,
    /// and `EOPNOTSUPP` mean the target is busy or unsupported for a direct
    /// mount, so a pivot fallback is attempted; any other errno is fatal.
    /// The errno is also exposed as the error `source` so a cause chain can
    /// surface it to structured output.
    #[error("Failed to mount overlay at {target}: {errno}")]
    Mount {
        target: std::path::PathBuf,
        #[source]
        errno: Errno,
    },

    /// NixOS-specific operation failed
    ///
    /// Covers profile switching, NixOS rebuild, and configuration errors.
    #[error("NixOS operation failed: {0}")]
    NixOSError(String),

    /// Rebooting the host could not be dispatched.
    ///
    /// The post-deactivation reboot (which boots the decoy from the bootloader
    /// default) is a generic step that runs on every platform, so its failure is
    /// not a NixOS fault. The string names the dispatch commands that were tried,
    /// or why the reboot was refused.
    #[error("Reboot failed: {0}")]
    RebootFailed(String),

    /// The hidden volume's filesystem lacks a capability NAILS requires.
    ///
    /// Raised by the symlink-support probe before any staging: FAT32/exFAT cannot
    /// hold the symlinks the overlay layout needs. This is a filesystem fault, not
    /// a NixOS one, so it carries its own typed variant rather than reusing the
    /// NixOS error.
    #[error("Unsupported filesystem at {path}: {reason}")]
    UnsupportedFilesystem {
        path: std::path::PathBuf,
        reason: String,
    },

    /// Pre-flight validation check failed
    ///
    /// Contains a list of (check_name, error_message) tuples for all failed checks.
    /// This allows comprehensive reporting of multiple validation failures.
    ///
    /// # Example
    /// ```
    /// # use nails_core::NailsError;
    /// let failures = vec![
    ///     ("swap-check".to_string(), "Swap is enabled".to_string(), Some("sudo swapoff -a".to_string())),
    ///     ("space-check".to_string(), "Insufficient disk space: 100 MB available, 500 MB required".to_string(), None),
    /// ];
    /// let err = NailsError::PreFlightCheckFailed(failures);
    /// ```
    #[error("Pre-flight checks failed:\n{}", format_preflight_errors(.0))]
    PreFlightCheckFailed(crate::error::PreFlightFailures),

    /// Configuration error (invalid format, missing required field, etc.)
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Configuration file does not exist at the resolved path.
    ///
    /// Kept distinct from [`NailsError::ConfigError`] so callers can fall back
    /// to defaults (`Config::load_or_default`) by matching the variant rather
    /// than the error text.
    #[error("Config file not found: {path}")]
    ConfigNotFound { path: std::path::PathBuf },

    /// A configured path breaks one of the path rules.
    ///
    /// Raised while a configuration is loaded or built, before anything is
    /// mounted. `problem` says which rule was broken, so callers and tests
    /// can match it without parsing the message.
    #[error("invalid config{}: {key} = {path:?}: {problem}", in_file(.file.as_deref()))]
    UnsafeConfigPath {
        /// The configuration file the path came from, if any.
        file: Option<std::path::PathBuf>,
        /// The setting that holds the path, such as `overlays[0].upper`.
        key: String,
        path: std::path::PathBuf,
        problem: crate::config::PathProblem,
    },

    /// Invalid command-line argument or option
    ///
    /// Used when CLI flags or options are invalid or conflicting.
    /// User Prompts and CLI Flags for Overlay Strategy
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

    /// Refused to unmount a path that NAILS did not mount.
    ///
    /// The teardown path escalates to `MNT_FORCE | MNT_DETACH`, which would
    /// lazily detach a real filesystem (`/home`, `/nix`, `/boot`) if stale state
    /// pointed NAILS at a mount it never created. Every `unmount` first confirms
    /// the target is a NAILS-owned overlay, pivot/staging bind, or the
    /// `/nix/store` restore bind; anything else is refused with this error and
    /// `umount2` is never called. Kept distinct from [`NailsError::UnmountError`]
    /// so callers and structured output can tell a safety refusal apart from a
    /// kernel failure.
    #[error("Refused to unmount unmanaged mount: {path}")]
    RefusedUnmanagedUnmount { path: std::path::PathBuf },

    /// Deactivation teardown left one or more NAILS mounts live.
    ///
    /// After attempting to unmount every tracked overlay, some targets are still
    /// mounted (a kernel failure that even `MNT_DETACH` could not clear). The
    /// teardown never remounts what it has already detached and never returns to
    /// `Active`: the system is recorded as
    /// [`SystemState::Degraded`](crate::SystemState) so that hidden-session
    /// writes cannot land on the decoy disk. The operator finishes the job with
    /// `nails emergency` or `nails recover`.
    #[error(
        "Deactivation incomplete: {} NAILS mount(s) still live: {}\nRun `nails emergency` or `nails recover` to finish the teardown.",
        .remaining_mounts.len(),
        format_remaining_mounts(.remaining_mounts)
    )]
    DeactivationIncomplete {
        remaining_mounts: Vec<std::path::PathBuf>,
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

    /// Lock poisoned - a thread panicked while holding a mutex
    #[error("Lock poisoned: {0}")]
    LockPoisoned(String),

    /// Cleanup operation failed
    ///
    /// Used when artifact cleanup fails during deactivation.
    /// Cleanup failures trigger rollback to ACTIVE state.
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

    /// Another nails process already holds the state lock.
    ///
    /// Every state-mutating command takes an exclusive lock on the hidden
    /// volume's state directory before touching mounts or the state file, so a
    /// second invocation fails fast instead of racing the first. The PID is the
    /// one the current holder recorded in the lock file (`0` if unknown).
    #[error("another nails operation is running (pid {pid})")]
    OperationInProgress { pid: u32 },

    /// Fork operation failed during emergency deactivation
    ///
    /// Used when the emergency shutdown cannot fork a child process.
    /// The system falls back to executing in the current process (degraded resilience).
    ///
    /// # Example
    /// ```
    /// # use nails_core::NailsError;
    /// let err = NailsError::ForkFailed(
    ///     "Resource temporarily unavailable".to_string()
    /// );
    /// ```
    #[error("Failed to fork emergency process: {0}")]
    ForkFailed(String),

    /// An external control command was killed for running past its deadline.
    ///
    /// Only probes and idempotent control commands run under a deadline;
    /// `nixos-rebuild build/test` and `switch-to-configuration` never do, so
    /// this never interrupts a half-finished switch. `budget` is the deadline
    /// that elapsed. The command's whole process group is killed before this is
    /// returned, so no descendant is left running, except a D-state
    /// (uninterruptible) descendant, which no signal can remove.
    #[error("command timed out after {budget:?}: {command}")]
    Timeout {
        command: String,
        budget: std::time::Duration,
    },

    /// The host is not one NAILS can operate on.
    ///
    /// Raised by the platform seam when host detection resolves to an
    /// unsupported target (an ostree / image-based system, or a host whose PID 1
    /// is not systemd). The refusal is deliberate: these hosts cannot be given a
    /// hidden overlay environment safely, so NAILS declines before touching any
    /// state. `reason` is an actionable, human-readable explanation.
    #[error("Unsupported host: {reason}")]
    UnsupportedPlatform { reason: String },

    /// I/O error (transparently converted from std::io::Error)
    ///
    /// This variant has #[from] attribute, enabling automatic conversion
    /// from std::io::Error via the ? operator.
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

impl NailsError {
    /// A single, concrete next step for this error, when one exists.
    ///
    /// The CLI shows this below the error line so a failure names not just what
    /// went wrong but what to do about it. Errors whose message is already fully
    /// actionable, or for which no general advice applies, return `None` and are
    /// shown without a hint rather than with filler guidance.
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            NailsError::PermissionDenied(_) => Some("Re-run the command as root (sudo)."),
            NailsError::OperationInProgress { .. } => Some(
                "Wait for the running operation to finish, or clear a stale lock if none is running.",
            ),
            NailsError::LockPoisoned(_) => Some(
                "A previous run crashed while holding the lock; re-run once no nails process is active.",
            ),
            NailsError::SwapDisableFailed => Some("Disable swap manually: sudo swapoff -a"),
            NailsError::ConfigNotFound { .. } => {
                Some("Create nails.toml or pass its path with --config.")
            }
            NailsError::UnsafeConfigPath { .. } => Some(
                "Point the configuration paths at the hidden volume, not a decoy or world-writable location.",
            ),
            NailsError::UnsupportedPlatform { .. } => {
                Some("This host is not a supported platform; see the platform requirements.")
            }
            NailsError::UnsupportedFilesystem { .. } => Some(
                "Format the hidden volume with a Linux filesystem such as ext4; FAT32 and exFAT cannot hold the required symlinks.",
            ),
            NailsError::DeactivationIncomplete { .. } => {
                Some("Reboot to clear the remaining mounts, then verify with `nails status`.")
            }
            NailsError::RefusedUnmanagedUnmount { .. } => Some(
                "Unmount the path yourself if it is safe to do so; nails will not touch a mount it did not create.",
            ),
            // Pre-flight failures carry their own per-check remediation list, and
            // the remaining variants are already specific about the fault.
            _ => None,
        }
    }
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

        let err = NailsError::NixOSPreflightError {
            category: "flake lock",
            message: "manual update required".into(),
        };
        assert_eq!(
            err.to_string(),
            "NixOS preflight failed: flake lock: manual update required"
        );

        let err = NailsError::PreFlightCheckFailed(vec![(
            "hidden-volume".to_string(),
            "Hidden volume not mounted".to_string(),
            None,
        )]);
        assert!(err.to_string().contains("Pre-flight checks failed"));
        assert!(err.to_string().contains("hidden-volume"));
        assert!(err.to_string().contains("Hidden volume not mounted"));

        let err = NailsError::ConfigError("Missing config key".into());
        assert_eq!(err.to_string(), "Configuration error: Missing config key");

        let err = NailsError::ForkFailed("Resource temporarily unavailable".into());
        assert_eq!(
            err.to_string(),
            "Failed to fork emergency process: Resource temporarily unavailable"
        );

        let err = NailsError::Mount {
            target: std::path::PathBuf::from("/home"),
            errno: Errno::EINVAL,
        };
        let msg = err.to_string();
        assert!(msg.contains("Failed to mount overlay at /home"), "{msg}");
        assert!(msg.contains(&Errno::EINVAL.to_string()), "{msg}");

        let err = NailsError::ConfigNotFound {
            path: std::path::PathBuf::from("/etc/nails/nails.toml"),
        };
        assert_eq!(
            err.to_string(),
            "Config file not found: /etc/nails/nails.toml"
        );

        let err = NailsError::RefusedUnmanagedUnmount {
            path: std::path::PathBuf::from("/home"),
        };
        assert_eq!(err.to_string(), "Refused to unmount unmanaged mount: /home");

        let err = NailsError::OperationInProgress { pid: 4242 };
        assert_eq!(
            err.to_string(),
            "another nails operation is running (pid 4242)"
        );

        let err = NailsError::Timeout {
            command: "systemctl is-active gdm.service".into(),
            budget: std::time::Duration::from_secs(10),
        };
        let msg = err.to_string();
        assert!(msg.contains("command timed out after 10s"), "{msg}");
        assert!(msg.contains("systemctl is-active gdm.service"), "{msg}");
    }

    #[test]
    fn test_mount_error_exposes_errno_as_source() {
        use std::error::Error;

        let err = NailsError::Mount {
            target: std::path::PathBuf::from("/var"),
            errno: Errno::EBUSY,
        };

        let source = err.source().expect("Mount error should chain a source");
        let errno = source
            .downcast_ref::<Errno>()
            .expect("Mount source should be an Errno");
        assert_eq!(*errno, Errno::EBUSY);
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
        let _err5 = NailsError::PreFlightCheckFailed(vec![(
            "test-check".to_string(),
            "test".to_string(),
            None,
        )]);
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
        let _err16 = NailsError::ForkFailed("Resource temporarily unavailable".into());
        let _err17 = NailsError::LockPoisoned("test lock poisoned".into());
        let _err18 = NailsError::Mount {
            target: PathBuf::from("/test"),
            errno: Errno::EINVAL,
        };
        let _err19 = NailsError::ConfigNotFound {
            path: PathBuf::from("/test/nails.toml"),
        };
        let _err20 = NailsError::RefusedUnmanagedUnmount {
            path: PathBuf::from("/test"),
        };
        let _err21 = NailsError::OperationInProgress { pid: 1234 };
        let _err22 = NailsError::Timeout {
            command: "nix store ping".into(),
            budget: std::time::Duration::from_secs(5),
        };
    }

    #[test]
    fn unsafe_config_path_names_the_file_key_and_rule() {
        use crate::config::PathProblem;
        use std::path::PathBuf;

        let err = NailsError::UnsafeConfigPath {
            file: Some(PathBuf::from("/mnt/hv/config/nails.toml")),
            key: "overlays[0].upper".into(),
            path: PathBuf::from("/mnt/hv/a,b"),
            problem: PathProblem::ForbiddenCharacter(','),
        };
        assert_eq!(
            err.to_string(),
            "invalid config /mnt/hv/config/nails.toml: overlays[0].upper = \"/mnt/hv/a,b\": must not contain ','"
        );

        let err = NailsError::UnsafeConfigPath {
            file: None,
            key: "log_path".into(),
            path: PathBuf::from("/var/log\nx"),
            problem: PathProblem::ForbiddenCharacter('\n'),
        };
        assert_eq!(
            err.to_string(),
            "invalid config: log_path = \"/var/log\\nx\": must not contain a newline"
        );
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
