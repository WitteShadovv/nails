// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # NAILS Core Library
//!
//! Core library for the nails overlay environment manager: a hidden session
//! on a decoy system, entered and left with `systemctl soft-reboot` into a
//! whole-root overlay (ADR 0008).
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

// The residue catalog: every trace class, its probes, docs and VM test.
pub mod residue_catalog;

// `nails rehearse`: the canary self-test.
pub mod rehearse;

// Filesystem operations module
pub mod filesystem;

// Read-only raw-device, layout and tree readers for the forensic self-checks
pub mod forensic;

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

// Running external programs, and process hardening.
pub mod process;

// Status command module (live session view)
pub mod status;

// Backend chain resolution (the hidden volume's device-mapper stack).
pub mod backend_lock;

// Logging infrastructure module (Logging with Hidden Volume Validation)
pub mod logging;

// Shared marks and per-stream styles for CLI output
pub mod output;

// Immediate desktop alerts for the backend watcher
pub mod notification;

pub mod runtime_copy;

pub mod sleep_guard;

// The whole-root session (ADR 0008): entry, way back, fstab policy, probes.
pub mod session;

pub mod watcher;

// Shared string constants (environment-variable names).
pub mod constants;

// Startup snapshot of the process environment NAILS reads.
pub mod runtime_env;

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

// Real-kernel test support: re-run a test in a child process, optionally inside
// an unprivileged user + mount namespace. Test-only; never in a shipped binary.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

// The captured kernel and systemd output the parser tests read. Test-only.
#[cfg(any(test, feature = "test-support"))]
pub mod kernel_fixtures;

// Property-based parser tests (`just fuzz` runs them with many more cases).
#[cfg(test)]
mod fuzz;

// Re-export for convenience
pub use artifacts::{
    ARTIFACTS, Artifact, ArtifactKind, ArtifactScope, ArtifactSeverity, indicators_json,
};
#[cfg(any(test, feature = "test-support"))]
pub use config::TestWorld;
pub use config::{CliOverrides, Config, ConfigBuilder, LoadedConfig, ValueSource};
pub use error::{IoResultExt, NailsError, Result};
pub use filesystem::{Filesystem, RealFilesystem};
#[cfg(any(test, feature = "test-support"))]
pub use filesystem::{MockFilesystem, PathKind};
pub use hidden_root::{AttachState, HiddenRoot, ensure_state_dir_attached};
pub use manager::{
    EnterOptions, EnterOutcome, NailsManager, RegistryInputs, ResetUpperPlan, SessionRecovery,
    build_registry,
};
// Platform seam exports
pub use platform::{
    ConfigLayer, HostProfile, HostTarget, NixOsConfigLayer, Platform, PlatformKind, detect,
    detect_platform, discover_host_target, discover_with_platform, platform_for,
};
pub use runtime_env::RuntimeEnv;
pub use target_user::TargetUser;

// Persona inventory exports
pub use persona::{InheritedSource, PersonaEntry, PersonaInventory, collect_inherited_persona};

// State management exports
pub use state::{
    EMERGENCY_LOCK_TIMEOUT, LastActivation, LoadOutcome, LoadResult, PlatformState, StateFile,
    StateLock, SystemState,
};

// Pre-flight validation exports
pub use preflight::{
    CheckResult, HiddenVolumeCheck, NixOSConfigCheck, PreFlightCheck, PreFlightRegistry,
    SpaceCheck, StateCheck, StorageReadinessCheck, SuspiciousNailsReferenceCheck, SwapCheck,
};
pub use reporter::{Diagnostic, remediation_steps};

// Forensic validation exports
pub use verify::{
    ExaminerFinding, ExaminerGroup, ExaminerOptions, ExaminerReport, Finding, RESIDUE_REPORT_DIR,
    RESIDUE_REPORT_SCHEMA_VERSION, ResidueReport, ResidueReportSummary, ScanDepth, Severity,
    StateFileStatus, Verifier, VerifyResult, VerifyStatus, write_activation_residue_report,
};

// NixOS profile builder exports
pub use nixos::{
    NixOSBuilder, NixOSConfigInfo, NixParser, RealNixParser, ensure_hidden_configuration_module,
    ensure_hidden_hardware_configuration, inject_import_block, parse_check_composed_config,
    prepare_nixos_config_overlay, stage_hidden_config_symlink, stage_hidden_nixos_config,
    verify_base_config_clean,
};

// Timing utilities exports
pub use timing::Stopwatch;

// Verbosity configuration exports
pub use verbosity::Verbosity;

// Status command exports
pub use status::{OpSecReminder, Posture, ReminderSeverity, StatusCommand, StatusReport};

// Logging infrastructure exports (Logging with Hidden Volume Validation)
pub use logging::{LoggingConfig, LoggingManager};

// Shared marks and per-stream styles for CLI output
pub use output::{
    Mark, Stream, Style, Tone, error, format_error, format_info, format_warn, info, warn,
};

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
