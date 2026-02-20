//! # NAILS Core Library
//!
//! Business logic for NixOS Anti-forensics Isolation & Layering System.
//!
//! This crate contains all core functionality including:
//! - State management and transitions
//! - Filesystem operations and validation
//! - Pre-flight checks
//! - NixOS integration and profile management
//! - Cleanup orchestration
//!
//! The core library is designed to be reusable by different interfaces:
//! - CLI (nails-cli)
//! - GUI (future: nails-gui)
//! - Daemon (future: nails-daemon)
//!
//! # Architecture
//!
//! The core library follows a strict separation of concerns:
//! - No CLI-specific code
//! - No direct user interaction
//! - Pure business logic with clear error handling
//! - Well-defined traits for extensibility

// Error handling module
pub mod error;

// Filesystem operations module
pub mod filesystem;

// State management module
pub mod state;

// Configuration module
pub mod config;

// Manager module (core orchestrator)
pub mod manager;

// Pre-flight validation system
pub mod preflight;

// Forensic validation system
pub mod verify;

// NixOS profile builder
pub mod nixos;

// Timing utilities
pub mod timing;

// Verbosity configuration
pub mod verbosity;

// Overlay operations module (Story 4.11: Extended Overlay Strategy)
pub mod overlay;

// Process detection and classification module (Story 4.13: Process Detection)
pub mod process;

// Activation options module (Story 4.15: User Prompts and CLI Flags)
pub mod activate_options;

// User prompts module (Story 4.15: User Prompts and CLI Flags)
pub mod prompts;

// Cleanup management module (Story 5.1: CleanupManager with Thorough and Fast Modes)
pub mod cleanup;

// Deactivation orchestrator module (Story 5.5: DeactivationOrchestrator with Cleanup + Unmount + Rollback)
pub mod deactivation;

// Emergency deactivation module (Story 6.1: Emergency Countdown with Ctrl+C Abort)
pub mod emergency;

// Status command module (Story 7.1: State Query with Overlay Verification)
pub mod status;

// Shell instrumentation module (Story 8.1: Shell Prompt Instrumentation Scripts)
pub mod shell;

// Logging infrastructure module (Story 9.1: Logging with Hidden Volume Validation)
pub mod logging;

// Structured CLI output formatting module (Story 14.7: Standardize CLI Output)
pub mod output;

// Re-export for convenience
pub use config::{
    CliOverrides, Config, ConfigBuilder, EphemeralOverlayDir, ExtendedOverlayConfig, OverlayConfig,
    OverlayMode,
};
pub use error::{NailsError, Result};
pub use filesystem::{Filesystem, MockFilesystem, RealFilesystem};
pub use manager::{
    MountInfo, MountTracker, MountType, NailsManager, apply_exclusion_filter, build_overlay_targets,
};

// State management exports
pub use state::{FailedOverlayInfo, OverlayInfo, StateFile, SystemState};

// Pre-flight validation exports
pub use preflight::{
    CheckResult, HiddenVolumeCheck, NixOSConfigCheck, OverlayDirs, PreFlightCheck,
    PreFlightRegistry, SpaceCheck, StateCheck, StorageReadinessCheck, SwapCheck,
};

// Forensic validation exports
pub use verify::{Finding, ScanDepth, Severity, Verifier, VerifyResult, VerifyStatus};

// NixOS profile builder exports
pub use nixos::{
    NixOSBuilder, NixOSConfigInfo, inject_import_block, prepare_nixos_config_overlay,
    stage_hidden_config_symlink, verify_base_config_clean,
};

// Timing utilities exports
pub use timing::Stopwatch;

// Verbosity configuration exports
pub use verbosity::Verbosity;

// Overlay operations exports (Story 4.11: Extended Overlay Strategy)
pub use overlay::{
    EphemeralMountInfo, MountMethod, OverlayStrategyOptions, mount_ephemeral_overlay,
    unmount_ephemeral_overlay,
};

// Process detection and classification exports (Story 4.13: Process Detection)
pub use process::{
    // Story 4.14: Session Detection and Shutdown Support
    DisplayManager,
    ProcessInfo,
    RestartMethod,
    RestartStrategy,
    RestartedProcess,
    SessionKillResult,
    SessionType,
    classify_process,
    detect_processes_using,
    detect_session_type,
    kill_graphical_session,
    prompt_session_kill_confirmation,
    restart_display_manager,
    restart_processes,
};

// Activation options exports (Story 4.15: User Prompts and CLI Flags)
pub use activate_options::ActivateOptions;

// User prompts exports (Story 4.15: User Prompts and CLI Flags)
pub use prompts::{
    display_abort_message, prompt_pivot_mount_acceptance, prompt_risky_process_restart,
    prompt_yes_no,
};

// Cleanup management exports (Story 5.1: CleanupManager with Thorough and Fast Modes)
pub use cleanup::{
    CleanupConfig,
    CleanupManager,
    CleanupMode,
    CleanupReport,
    history::{HistoryCleaner, ShellType}, // Story 5.2 - nested to access private imports
    logs::LogCleaner,                     // Story 5.4 - nested to access private imports
    temp_files::TempFilesCleaner,         // Story 5.3 - nested to access private imports
};

// Deactivation orchestrator exports (Story 5.5: DeactivationOrchestrator with Cleanup + Unmount + Rollback)
pub use deactivation::{DeactivationOrchestrator, DeactivationReport};

// Emergency deactivation exports (Story 6.1-6.3: Countdown, Fork, Orchestrator)
pub use emergency::{
    EmergencyCountdown, EmergencyOrchestrator, EmergencyReport, ForkStrategy, fork_and_execute,
};

// Status command exports (Story 7.1: State Query with Overlay Verification)
pub use status::{
    OpSecReminder, ReminderSeverity, SecurityPosture, StatusCommand, StatusReport,
    VerificationStatus,
};

// Shell instrumentation exports (Story 8.1: Shell Prompt Instrumentation Scripts)
pub use shell::{ShellCleanupResult, ShellInstrumentation, ShellSetupResult};

// Logging infrastructure exports (Story 9.1: Logging with Hidden Volume Validation)
pub use logging::{LoggingConfig, LoggingManager};

// Structured CLI output exports (Story 14.7: Standardize CLI Output)
pub use output::{error, format_error, format_info, format_warn, info, set_plain_mode, warn};

/// RAII guard for automatic state rollback on failure
///
/// # ⚠️ EXPERIMENTAL API
///
/// **This API is experimental and may change in future versions.**
///
/// `StateGuard` is primarily intended for **internal use** by `NailsManager`
/// methods (`activate()`, `deactivate()`) to provide automatic rollback on
/// failure or panic.
///
/// ## External Usage Considerations
///
/// While this type is public to allow advanced use cases and testing, most
/// consumers of this library should **NOT** need to create `StateGuard`
/// instances directly. Instead:
///
/// - **Use high-level methods**: Call `NailsManager::activate()` and
///   `NailsManager::deactivate()` which handle StateGuard internally
/// - **Let RAII work for you**: These methods automatically create guards
///   and handle commit/rollback
///
/// ## When You Might Use This Directly
///
/// 1. **Testing**: Verifying rollback behavior in custom test scenarios
/// 2. **Advanced operations**: Building new manager methods that need rollback
/// 3. **Manual recovery**: Emergency state restoration tools
///
/// ## API Stability
///
/// Until this warning is removed:
/// - Method signatures may change
/// - Fields may be reorganized
/// - Behavior may be refined
///
/// We will maintain semantic versioning - breaking changes will bump the
/// major version.
///
/// ## Example (Internal Pattern)
///
/// ```text
/// // Internal pattern used by NailsManager methods
/// let guard = StateGuard::new(Arc::clone(&manager), previous_state);
/// // ... perform operations ...
/// if success {
///     guard.commit();  // Prevent rollback
/// }
/// // If operations fail, guard drops and rolls back automatically
/// ```
///
/// For the complete API documentation, see [`StateGuard`].
pub use state::StateGuard;

#[cfg(test)]
mod tests {
    #[test]
    fn test_library_compiles() {
        // Smoke test to verify core library compiles
        // Test body removed - compilation success is sufficient
    }

    #[test]
    fn test_workspace_version_exists() {
        // Verify workspace version is accessible
        let version = env!("CARGO_PKG_VERSION");
        assert_eq!(version, "0.1.0");
    }
}
