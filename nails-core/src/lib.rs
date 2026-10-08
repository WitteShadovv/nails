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

// This crate's unit tests never reach the host, like the base crate's own.
nails_base::unit_test_mode!();

// The foundation: errors, the filesystem and process seams, configuration,
// state, the artifact registry, logging, output and the pre-flight framework.
// Re-exported so `nails_core::<module>` paths keep working for the CLI.
pub(crate) use nails_base::runtime_safety;
pub use nails_base::{
    artifacts, cancel, constants, error, filesystem, hidden_root, logging, notification, output,
    process, reporter, runtime_env, state, target_user, timing, verbosity,
};

// Configuration module: the base crate's, plus the manager-building test
// fixture that needs the whole stack.
pub mod config {
    pub use nails_base::config::*;

    #[cfg(any(test, feature = "test-support"))]
    pub use crate::test_world::TestWorld;
}

#[cfg(any(test, feature = "test-support"))]
mod test_world;

// The residue catalog: every trace class, its probes, docs and VM test.
pub mod residue_catalog;

// `nails rehearse`: the canary self-test.
pub mod rehearse;

// Read-only raw-device, layout and tree readers for the forensic self-checks
pub mod forensic;

// Manager module (core orchestrator)
pub mod manager;

// Pre-flight validation system: the framework from nails-base and the checks.
pub mod preflight;

// Forensic validation system
pub mod verify;

// NixOS profile builder
pub mod nixos;

// Status command module (live session view)
pub mod status;

// Backend chain resolution (the hidden volume's device-mapper stack).
pub mod backend_lock;

pub mod runtime_copy;

pub mod sleep_guard;

// The whole-root session (ADR 0008): entry, way back, fstab policy, probes.
pub mod session;

pub mod watcher;

// Platform seam: host detection and per-platform behaviour (NixOS / FHS / refused).
pub mod platform;

// Persona inventory: the decoy autostart/user-unit/linger/autologin state the
// hidden session would inherit from the decoy account.
pub mod persona;

// Real-kernel test support and the captured kernel fixtures. Test-only.
#[cfg(any(test, feature = "test-support"))]
pub use nails_base::{kernel_fixtures, test_path, test_support};

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

// Shared marks and per-stream styles for CLI output. `nails_base::error`
// above brings both the `error` module and the `output::error` function.
pub use output::{Mark, Stream, Style, Tone, format_error, format_info, format_warn, info, warn};

#[cfg(test)]
mod tests {
    #[test]
    fn test_library_compiles() {
        // Smoke test to verify core library compiles
        // Test body removed - compilation success is sufficient
    }

    #[test]
    fn unit_tests_never_reach_the_host() {
        // `unit_test_mode!` marks this binary before the first test, so the
        // base crate's host switches answer as they do in its own unit tests.
        assert!(crate::runtime_safety::in_unit_tests());
        assert!(crate::runtime_safety::should_skip_host_interaction());
    }

    #[test]
    fn test_workspace_version_exists() {
        // Verify workspace version is accessible
        let version = env!("CARGO_PKG_VERSION");
        assert_eq!(version, "0.2.0");
    }
}
