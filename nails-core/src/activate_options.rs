//! Activation Options and Configuration
//!
//! Provides configuration structures for controlling activation behavior, including
//! user prompts, process restart strategies, and pivot mount policies.
//!
//! Part of Story 4.15: User Prompts and CLI Flags for Overlay Strategy

use crate::{NailsError, Result};

/// Options for controlling activation behavior
///
/// These options map directly to CLI flags and control:
/// - Session management (`--kill-session`)
/// - Security trade-offs (`--accept-pivot-risks`, `--no-pivot`)
/// - User interaction (`--yes`)
/// - Output formatting (`--quiet`, `--json`, `--no-color`)
///
/// # Validation
///
/// Call [`ActivateOptions::validate()`] to check for conflicting flags before use.
///
/// # Examples
///
/// ```rust
/// use nails_core::ActivateOptions;
///
/// // Interactive mode (default)
/// let opts = ActivateOptions::default();
/// assert!(opts.validate().is_ok());
///
/// // Strict security mode
/// let opts = ActivateOptions {
///     no_pivot: true,
///     ..Default::default()
/// };
/// assert!(opts.validate().is_ok());
///
/// // Invalid: conflicting flags
/// let opts = ActivateOptions {
///     no_pivot: true,
///     accept_pivot_risks: true,
///     ..Default::default()
/// };
/// assert!(opts.validate().is_err());
/// ```
/// Default value for pre_activation_cleanup option
const DEFAULT_PRE_ACTIVATION_CLEANUP: bool = true;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivateOptions {
    /// Kill graphical session before activation (enables all direct mounts)
    pub kill_session: bool,

    /// Accept pivot mount fallback for any volume (degraded security)
    pub accept_pivot_risks: bool,

    /// Abort if any volume requires pivot mount (strict security)
    pub no_pivot: bool,

    /// Skip all confirmation prompts (auto-accept)
    pub yes: bool,

    /// Suppress progress output
    pub quiet: bool,

    /// Verbosity level (0=normal, 1=verbose, 2+=debug)
    pub verbosity: u8,

    /// Output results in JSON format
    pub json: bool,

    /// Disable colored output
    pub no_color: bool,

    /// Skip NixOS profile build and switch (overlay mounts only)
    pub overlay_only: bool,

    /// Override skip_process_detection behavior (for testing)
    ///
    /// This field is hidden from public documentation and is intended for
    /// internal testing purposes only. When None (default), process detection
    /// is skipped in test builds (cfg!(test)). Set to Some(false) in tests
    /// that need to verify process detection logic.
    #[doc(hidden)]
    pub skip_process_detection_override: Option<bool>,

    /// Skip session kill confirmation prompt (internal use)
    ///
    /// This is set by the CLI when the user already confirmed before detaching.
    #[doc(hidden)]
    pub session_kill_confirmed: bool,

    /// Enable pre-activation history cleanup (default: true)
    ///
    /// When enabled, shell history is cleaned BEFORE overlays are mounted to remove
    /// evidence of sensitive commands (nails, cryptsetup, veracrypt, luks, etc.)
    /// from the REAL disk. This is a security feature that runs even when
    /// `--no-preflight` is set.
    ///
    /// Best-effort approach: cleanup failures are logged but don't fail activation.
    pub pre_activation_cleanup: bool,
}

impl Default for ActivateOptions {
    fn default() -> Self {
        Self {
            kill_session: false,
            accept_pivot_risks: false,
            no_pivot: false,
            yes: false,
            quiet: false,
            verbosity: 0,
            json: false,
            no_color: false,
            overlay_only: false,
            skip_process_detection_override: None,
            session_kill_confirmed: false,
            pre_activation_cleanup: DEFAULT_PRE_ACTIVATION_CLEANUP,
        }
    }
}

impl ActivateOptions {
    /// Validate options for conflicting flags
    ///
    /// # Errors
    ///
    /// Returns [`NailsError::InvalidArgument`] if:
    /// - Both `--no-pivot` and `--accept-pivot-risks` are set (mutually exclusive)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nails_core::ActivateOptions;
    ///
    /// let opts = ActivateOptions {
    ///     no_pivot: true,
    ///     accept_pivot_risks: true,
    ///     ..Default::default()
    /// };
    /// assert!(opts.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<()> {
        if self.no_pivot && self.accept_pivot_risks {
            return Err(NailsError::InvalidArgument(
                "--no-pivot and --accept-pivot-risks are mutually exclusive".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_options_are_valid() {
        let opts = ActivateOptions::default();
        assert!(opts.validate().is_ok());
    }

    #[test]
    fn test_kill_session_flag_alone() {
        let opts = ActivateOptions {
            kill_session: true,
            ..Default::default()
        };
        assert!(opts.validate().is_ok());
    }

    #[test]
    fn test_accept_pivot_risks_flag_alone() {
        let opts = ActivateOptions {
            accept_pivot_risks: true,
            ..Default::default()
        };
        assert!(opts.validate().is_ok());
    }

    #[test]
    fn test_no_pivot_flag_alone() {
        let opts = ActivateOptions {
            no_pivot: true,
            ..Default::default()
        };
        assert!(opts.validate().is_ok());
    }

    #[test]
    fn test_yes_flag_alone() {
        let opts = ActivateOptions {
            yes: true,
            ..Default::default()
        };
        assert!(opts.validate().is_ok());
    }

    #[test]
    fn test_no_pivot_and_accept_pivot_risks_are_mutually_exclusive() {
        let opts = ActivateOptions {
            no_pivot: true,
            accept_pivot_risks: true,
            ..Default::default()
        };
        assert!(opts.validate().is_err());
        if let Err(NailsError::InvalidArgument(msg)) = opts.validate() {
            assert!(msg.contains("mutually exclusive"));
        } else {
            panic!("Expected InvalidArgument error");
        }
    }

    #[test]
    fn test_kill_session_with_accept_pivot_risks() {
        // This combination is valid (kill session first, then accept pivot if needed)
        let opts = ActivateOptions {
            kill_session: true,
            accept_pivot_risks: true,
            ..Default::default()
        };
        assert!(opts.validate().is_ok());
    }

    #[test]
    fn test_kill_session_with_no_pivot() {
        // This combination is valid (kill session first, abort if pivot needed)
        let opts = ActivateOptions {
            kill_session: true,
            no_pivot: true,
            ..Default::default()
        };
        assert!(opts.validate().is_ok());
    }

    #[test]
    fn test_yes_with_accept_pivot_risks() {
        // This combination is valid (auto-accept all prompts including pivot)
        let opts = ActivateOptions {
            yes: true,
            accept_pivot_risks: true,
            ..Default::default()
        };
        assert!(opts.validate().is_ok());
    }

    #[test]
    fn test_yes_with_no_pivot() {
        // This combination is valid (auto-confirm other prompts, but abort on pivot)
        let opts = ActivateOptions {
            yes: true,
            no_pivot: true,
            ..Default::default()
        };
        assert!(opts.validate().is_ok());
    }

    #[test]
    fn test_quiet_and_json_flags() {
        // Quiet and JSON can coexist (quiet affects human output, JSON is machine output)
        let opts = ActivateOptions {
            quiet: true,
            json: true,
            ..Default::default()
        };
        assert!(opts.validate().is_ok());
    }

    #[test]
    fn test_verbosity_levels() {
        for level in 0..=10 {
            let opts = ActivateOptions {
                verbosity: level,
                ..Default::default()
            };
            assert!(opts.validate().is_ok());
        }
    }

    #[test]
    fn test_all_flags_compatible_except_mutual_exclusions() {
        // All flags set EXCEPT no_pivot (which conflicts with accept_pivot_risks)
        let opts = ActivateOptions {
            kill_session: true,
            accept_pivot_risks: true,
            no_pivot: false,
            yes: true,
            quiet: true,
            verbosity: 2,
            json: true,
            no_color: true,
            overlay_only: false,
            skip_process_detection_override: None,
            session_kill_confirmed: false,
            pre_activation_cleanup: true,
        };
        assert!(opts.validate().is_ok());
    }

    #[test]
    fn test_skip_process_detection_override() {
        // Test that skip_process_detection_override can be set
        let opts = ActivateOptions {
            skip_process_detection_override: Some(false),
            ..Default::default()
        };
        assert_eq!(opts.skip_process_detection_override, Some(false));
    }

    #[test]
    fn test_overlay_only_flag() {
        let opts = ActivateOptions {
            overlay_only: true,
            ..Default::default()
        };
        assert!(opts.validate().is_ok());
        assert!(opts.overlay_only);
    }

    #[test]
    fn test_pre_activation_cleanup_defaults_to_true() {
        let opts = ActivateOptions::default();
        assert!(opts.pre_activation_cleanup);
    }

    #[test]
    fn test_pre_activation_cleanup_can_be_disabled() {
        let opts = ActivateOptions {
            pre_activation_cleanup: false,
            ..Default::default()
        };
        assert!(!opts.pre_activation_cleanup);
        assert!(opts.validate().is_ok());
    }
}
