// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # NAILS base library
//!
//! The foundation every other NAILS library crate builds on: the error type,
//! the `Filesystem` and process seams, the strict TOML configuration, the
//! recorded state, the artifact registry, the attach gate, logging and output,
//! and the pre-flight check framework.
//!
//! It knows nothing about a platform backend, the whole-root session or
//! verification; those live in `nails-platform`, `nails-session` and
//! `nails-forensics`, and `nails-core` ties them together. The dependency
//! direction is recorded in ADR 0010.

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

// Pre-flight check framework: the trait, the result and the registry.
pub mod preflight;

/// Actionable diagnostics rendering (remediation lists, error hints).
pub mod reporter;

// Timing utilities
pub mod timing;

// Verbosity configuration
pub mod verbosity;

// Running external programs, and process hardening.
pub mod process;

// Logging infrastructure module (Logging with Hidden Volume Validation)
pub mod logging;

// Shared marks and per-stream styles for CLI output
pub mod output;

// Immediate desktop alerts for the backend watcher
pub mod notification;

// Shared string constants (environment-variable names).
pub mod constants;

// Startup snapshot of the process environment NAILS reads.
pub mod runtime_env;

// Target-user resolution (who a privileged run acts on behalf of).
pub mod target_user;

// Attach gate: write nothing unless the hidden root is positively mounted.
pub mod hidden_root;

// Words that give hidden storage away in a mount path, mapper name or label.
pub mod naming;

// The parsers of `/etc/fstab` and `/etc/crypttab`.
pub mod crypttab;
pub mod fstab;

// Test-runtime guards for host interaction. Public for the other NAILS crates
// only; not part of any interface.
#[doc(hidden)]
pub mod runtime_safety;

// Real-kernel test support: re-run a test in a child process, optionally inside
// an unprivileged user + mount namespace. Test-only; never in a shipped binary.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

// The captured kernel and systemd output the parser tests read. Test-only.
#[cfg(any(test, feature = "test-support"))]
pub mod kernel_fixtures;

pub use artifacts::{
    ARTIFACTS, Artifact, ArtifactKind, ArtifactScope, ArtifactSeverity, indicators_json,
};
pub use config::{CliOverrides, Config, ConfigBuilder, LoadedConfig, ValueSource};
pub use error::{IoResultExt, NailsError, Result};
pub use filesystem::{Filesystem, RealFilesystem};
#[cfg(any(test, feature = "test-support"))]
pub use filesystem::{MockFilesystem, PathKind};
pub use hidden_root::{AttachState, HiddenRoot, ensure_state_dir_attached};
pub use runtime_env::RuntimeEnv;
pub use target_user::TargetUser;

pub use state::{
    EMERGENCY_LOCK_TIMEOUT, LastActivation, LoadOutcome, LoadResult, PlatformState, StateFile,
    StateLock, SystemState,
};

pub use preflight::{CheckResult, PreFlightCheck, PreFlightRegistry, SwapCheck};
pub use reporter::{Diagnostic, remediation_steps};

pub use timing::Stopwatch;

pub use verbosity::Verbosity;

pub use logging::{LoggingConfig, LoggingManager};

pub use output::{
    Mark, Stream, Style, Tone, error, format_error, format_info, format_warn, info, warn,
};
