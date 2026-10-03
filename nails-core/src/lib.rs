//! # NAILS Core Library
//!
//! Core library for the nails overlay environment manager.
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

// Unsafe code is denied workspace-wide (see the root Cargo.toml). Test code
// may use it freely; production code opts in per site with a scoped allow.
#![cfg_attr(test, allow(unsafe_code))]

// Error handling module
pub mod error;

pub mod cancel;

// Artifact registry: the single source of what an activation can leave behind
pub mod artifacts;

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

/// Actionable diagnostics rendering (remediation lists, error hints).
pub mod reporter;

// Forensic validation system
pub mod verify;

// NixOS profile builder
pub mod nixos;

// Timing utilities
pub mod timing;

// Verbosity configuration
pub mod verbosity;

// Overlay operations module (Extended Overlay Strategy)
pub mod overlay;

// Process detection and classification module (Process Detection)
pub mod process;

// Activation options module (User Prompts and CLI Flags)
pub mod activate_options;

// User prompts module (User Prompts and CLI Flags)
pub mod prompts;

// Cleanup management module (CleanupManager with Thorough and Fast Modes)
pub mod cleanup;

// Deactivation orchestrator module (DeactivationOrchestrator with Cleanup + Unmount + Rollback)
pub mod deactivation;

// Status command module (State Query with Overlay Verification)
pub mod status;

// Shell instrumentation module (Shell Prompt Instrumentation Scripts)
pub mod shell;

// Logging infrastructure module (Logging with Hidden Volume Validation)
pub mod logging;

// Shared marks and per-stream styles for CLI output
pub mod output;

// Desktop notification signal files (post-activation user feedback)
pub mod notification;

pub mod runtime_copy;

pub mod watcher;

// Shared string constants (environment-variable names).
pub mod constants;

// Target-user resolution (who a privileged run acts on behalf of).
pub mod target_user;

// Attach gate: write nothing unless the hidden root is positively mounted.
pub mod hidden_root;

// Platform seam: host detection and per-platform behaviour (NixOS / FHS / refused).
pub mod platform;

// Persona inventory: the decoy autostart/user-unit/linger/autologin state the
// hidden session would inherit from the decoy account.
pub mod persona;

mod runtime_safety;

// Test helpers shared across modules and with downstream test code (the
// process-environment guard). Off in release builds.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

// Re-export for convenience
pub use artifacts::{
    ARTIFACTS, Artifact, ArtifactKind, ArtifactScope, ArtifactSeverity, indicators_json,
};
#[cfg(any(test, feature = "test-support"))]
pub use config::TestWorld;
pub use config::{
    CliOverrides, ColorProfile, ColorSchemeConfig, Config, ConfigBuilder, DecoyProfile,
    EphemeralOverlayDir, LoadedConfig, OverlayConfig, OverlayMode, ValueSource,
};
pub use error::{NailsError, Result};
pub use filesystem::{Filesystem, RealFilesystem};
#[cfg(any(test, feature = "test-support"))]
pub use filesystem::{MockFilesystem, PathKind};
pub use hidden_root::{AttachState, HiddenRoot};
pub use manager::deactivation::{DeactivationMode, DeactivationOrchestrator};
pub use manager::{
    ActivationOutcome, HiddenConfigOutcome, HostEffects, MountInfo, MountTracker, MountType,
    NailsManager, RecoverOutcome, RegistryInputs, ResetUpperPlan, apply_exclusion_filter,
    build_overlay_targets, build_registry,
};
#[cfg(any(test, feature = "test-hooks"))]
pub use manager::{SimulatedHostEffects, SimulatedReboot};
// Platform seam exports
pub use platform::{
    ConfigLayer, ConfigPlan, HostProfile, HostTarget, MountHooks, NixOsConfigLayer, OverlayPolicy,
    Platform, PlatformKind, RestoreOutcome, detect, detect_platform, discover_host_target,
    guard_read_only_trees, platform_for,
};
pub use target_user::TargetUser;

// Persona inventory exports
pub use persona::{InheritedSource, PersonaEntry, PersonaInventory, collect_inherited_persona};

// State management exports
pub use state::{
    DecoyWriter, EMERGENCY_LOCK_TIMEOUT, FailedOverlayInfo, LoadOutcome, LoadResult, OverlayInfo,
    PlatformState, StateFile, StateLock, SubmountAttachment, SystemState, decoy_writers_headline,
    summarize_decoy_writers,
};

// Pre-flight validation exports
pub use preflight::{
    CheckResult, HiddenVolumeCheck, NixOSConfigCheck, OverlayDirs, PreFlightCheck,
    PreFlightRegistry, SpaceCheck, StateCheck, StorageReadinessCheck,
    SuspiciousNailsReferenceCheck, SwapCheck,
};
pub use reporter::{Diagnostic, remediation_steps};

// Forensic validation exports
pub use verify::{
    Finding, ScanDepth, Severity, StateFileStatus, Verifier, VerifyResult, VerifyStatus,
};

// NixOS profile builder exports
pub use nixos::{
    NixOSBuilder, NixOSConfigInfo, NixParser, RealNixParser, compute_config_fingerprint,
    ensure_hidden_configuration_module, ensure_hidden_hardware_configuration, inject_import_block,
    parse_check_composed_config, prepare_nixos_config_overlay, stage_hidden_config_symlink,
    stage_hidden_nixos_config, verify_base_config_clean,
};
pub(crate) use nixos::{classify_nixos_failure_category, format_classified_nixos_failure};

// Timing utilities exports
pub use timing::Stopwatch;

// Verbosity configuration exports
pub use verbosity::Verbosity;

// Overlay operations exports (Extended Overlay Strategy)
pub use overlay::{
    EphemeralMountInfo, MountMethod, MountResult, OverlayStrategyOptions, SurvivingWriter,
    mount_ephemeral_overlay, unmount_ephemeral_overlay,
};

// Process detection and classification exports (Process Detection)
pub use process::{
    // Session Detection and Shutdown Support
    ProcessInfo,
    RealSessionCommandExecutor,
    RestartMethod,
    RestartStrategy,
    RestartedProcess,
    RiskyServicePolicy,
    SessionCommandExecutor,
    SessionContext,
    SessionKillResult,
    SessionKind,
    SessionRestartPlan,
    classify_process,
    detect_processes_using,
    detect_session_context,
    kill_graphical_session,
    prompt_session_kill_confirmation,
    restart_display_manager,
    restart_processes,
    restart_user_manager,
};

// Activation options exports (User Prompts and CLI Flags)
pub use activate_options::ActivateOptions;

// User prompts exports (User Prompts and CLI Flags)
pub use prompts::{
    display_abort_message, prompt_pivot_mount_acceptance, prompt_risky_process_restart,
    prompt_yes_no,
};

// Cleanup management exports (CleanupManager with Thorough and Fast Modes)
pub use cleanup::{
    CleanupConfig,
    CleanupManager,
    CleanupMode,
    CleanupReport,
    history::{HistoryCleaner, ShellType}, // nested to access private imports
    logs::LogCleaner,                     // nested to access private imports
    temp_files::TempFilesCleaner,         // nested to access private imports
};

// Deactivation report exports (the deactivation sequence lives in `manager::deactivation`)
pub use deactivation::{DeactivationReport, PostUnmountCleanupReport};

// Status command exports (State Query with Overlay Verification)
pub use status::{
    OpSecReminder, Posture, ReminderSeverity, StatusCommand, StatusReport, VerificationStatus,
};

// Shell instrumentation exports (Shell Prompt Instrumentation Scripts)
pub use shell::{ShellCleanupResult, ShellInstrumentation, ShellSetupResult};

// Logging infrastructure exports (Logging with Hidden Volume Validation)
pub use logging::{LoggingConfig, LoggingManager};

// Shared marks and per-stream styles for CLI output
pub use output::{
    Mark, Stream, Style, Tone, error, format_error, format_info, format_warn, info, warn,
};

// Desktop notification exports
pub use notification::{Notification, dispatch_all as dispatch_notifications};

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
/// let mut guard = StateGuard::new(&mut manager, previous_state);
/// // ... perform operations through `&mut *guard` ...
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
        assert_eq!(version, "0.2.0");
    }
}
