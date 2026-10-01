//! Core types for overlay mounting strategy
//!
//! Provides configuration options and result types for the universal
//! overlay mounting algorithm.

/// Options for controlling overlay mounting strategy
///
/// Controls how the universal overlay mounting algorithm behaves regarding:
/// - Process restart decisions (safe/risky)
/// - User prompts for risky operations
/// - Pivot mount fallback policy
///
/// Part of Story 4.15: User Prompts and CLI Flags for Overlay Strategy
///
/// # Examples
///
/// ```rust
/// use nails_core::overlay::OverlayStrategyOptions;
///
/// // Interactive mode (default) - prompt for risky operations
/// let opts = OverlayStrategyOptions::default();
/// assert_eq!(opts.auto_restart_safe, true);
/// assert_eq!(opts.prompt_for_risky, true);
///
/// // Automated mode - restart safe processes, skip risky prompts
/// let opts = OverlayStrategyOptions {
///     auto_restart_safe: true,
///     prompt_for_risky: false,
///     allow_pivot: true,
///     auto_accept_pivot: true,
///     skip_process_detection: false,
/// };
///
/// // Strict mode - no pivots allowed
/// let opts = OverlayStrategyOptions {
///     allow_pivot: false,
///     ..Default::default()
/// };
///
/// // Test mode - skip process detection entirely (for unit tests)
/// let opts = OverlayStrategyOptions {
///     skip_process_detection: true,
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayStrategyOptions {
    /// Automatically restart processes classified as "Safe" without prompting
    ///
    /// Safe processes are those that:
    /// - Are designed for restarts (systemd services)
    /// - Have no user state to lose
    /// - Restart quickly without service disruption
    ///
    /// Examples: systemd-journald, nix-daemon, systemd-resolved
    pub auto_restart_safe: bool,

    /// Prompt user before restarting processes classified as "Risky"
    ///
    /// Risky processes may cause brief service disruption:
    /// - NetworkManager (brief network drop)
    /// - dbus-daemon (affects desktop notifications)
    /// - pulseaudio/pipewire (audio interruption)
    ///
    /// If false, skip risky process restarts (may require pivot mount)
    pub prompt_for_risky: bool,

    /// Allow pivot mount fallback when direct mount fails
    ///
    /// Pivot mount creates split-view behavior with security degradation.
    /// Set to false for strict mode (abort if pivot needed).
    pub allow_pivot: bool,

    /// Automatically accept pivot mount without user confirmation
    ///
    /// If false, user will be prompted to accept security trade-off.
    /// Only has effect if `allow_pivot` is true.
    pub auto_accept_pivot: bool,

    /// Skip process detection entirely (for tests with mock filesystems)
    ///
    /// When true, bypasses Phase 1 and Phase 2 of the universal algorithm,
    /// directly attempting mount. This is useful for unit tests that use
    /// MockFilesystem and cannot handle real process detection.
    pub skip_process_detection: bool,
}

impl Default for OverlayStrategyOptions {
    fn default() -> Self {
        Self {
            auto_restart_safe: true,       // Always restart safe processes
            prompt_for_risky: true,        // Interactive by default
            allow_pivot: true,             // Allow pivot as last resort
            auto_accept_pivot: false,      // Prompt by default for security awareness
            skip_process_detection: false, // Don't skip process detection by default
        }
    }
}

/// Method used to mount overlay filesystem
///
/// Records *how* the overlay was mounted. The method alone carries no security
/// meaning: a process that opened the directory before the mount keeps resolving
/// the original inode under both methods, so leakage is tracked separately via
/// [`MountResult::surviving_writers`] rather than inferred from the method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountMethod {
    /// Direct overlay mount over the target directory.
    Direct,
    /// Pivot fallback: the overlay is mounted on a staging path and then
    /// bind-mounted over the target (used when a direct mount is rejected).
    Pivot,
}

/// Full result of universal overlay mounting algorithm
///
/// Includes the mount method, the services stopped during Phase 2, and the count
/// of writer processes that survived Phase 2 still referencing the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountResult {
    /// Which mount method was used
    pub method: MountMethod,
    /// Service names that were stopped in Phase 2 (should be restarted post-mount)
    pub stopped_services: Vec<String>,
    /// Count of write-capable processes still referencing the target after Phase 2
    /// (processes that could not be, or were not, restarted). Such a process keeps
    /// resolving and writing to the decoy lower tree regardless of mount method, so
    /// a non-zero count is a leak that degrades the security posture. Read-only
    /// ("Skip") processes are excluded because they cannot write to the decoy.
    pub surviving_writers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overlay_strategy_options_default() {
        let opts = OverlayStrategyOptions::default();
        assert!(opts.auto_restart_safe);
        assert!(opts.prompt_for_risky);
        assert!(opts.allow_pivot);
        assert!(!opts.auto_accept_pivot);
        assert!(!opts.skip_process_detection);
    }

    #[test]
    fn test_overlay_strategy_options_custom() {
        let opts = OverlayStrategyOptions {
            auto_restart_safe: false,
            prompt_for_risky: false,
            allow_pivot: false,
            auto_accept_pivot: true,
            skip_process_detection: true,
        };
        assert!(!opts.auto_restart_safe);
        assert!(!opts.prompt_for_risky);
        assert!(!opts.allow_pivot);
        assert!(opts.auto_accept_pivot);
        assert!(opts.skip_process_detection);
    }

    #[test]
    fn test_mount_method_variants() {
        let direct = MountMethod::Direct;
        let pivot = MountMethod::Pivot;
        assert_ne!(direct, pivot);
    }

    #[test]
    fn test_mount_result_creation() {
        let result = MountResult {
            method: MountMethod::Direct,
            stopped_services: vec!["systemd-journald".to_string()],
            surviving_writers: 0,
        };
        assert_eq!(result.method, MountMethod::Direct);
        assert_eq!(result.stopped_services.len(), 1);
        assert_eq!(result.surviving_writers, 0);
    }
}
