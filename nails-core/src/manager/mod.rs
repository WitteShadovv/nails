//! # NailsManager - Core Orchestrator for NAILS Operations
//!
//! Central orchestrator that coordinates all NAILS operations including state
//! transitions, filesystem operations, and validation logic.
//!
//! # Design Pattern: Generic Manager with Dependency Injection
//!
//! NailsManager uses generic programming to enable compile-time polymorphism:
//! - Production: `NailsManager<RealFilesystem>` uses actual syscalls
//! - Testing: `NailsManager<MockFilesystem>` uses in-memory state (no root required)
//!
//! This pattern enables 99% of tests to run without root privileges (AR4, NFR37).
//!
//! # Module Structure
//!
//! - **mod.rs** - Core NailsManager struct, constructors, and helper functions
//! - **helpers.rs** - Free helper functions (overlay targets, system profiles, etc.)
//! - **mount_tracker.rs** - RAII mount tracking for automatic rollback
//! - **state_management.rs** - State transitions and verification
//! - **preflight_runner.rs** - Pre-flight check registration and execution
//! - **activation.rs** - 10-step activation flow
//! - **deactivation.rs** - Deactivation and emergency mode
//!
//! # Example
//!
//! ```rust
//! use nails_core::{NailsManager, MockFilesystem, Config};
//! use std::path::PathBuf;
//!
//! // Testing: MockFilesystem (no root required)
//! let fs = MockFilesystem::new();
//! let config = Config::default();
//! let state_path = PathBuf::from("/tmp/test-state.json");
//! let manager = NailsManager::new(fs, config, state_path);
//!
//! // Production: RealFilesystem (requires root)
//! // let fs = RealFilesystem;
//! // let manager = NailsManager::new(fs, config, state_path);
//! ```

use crate::{Config, Filesystem, NailsError, Result};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

// Module declarations
pub mod activation;
pub mod deactivation;
pub(crate) mod helpers;
pub mod mount_tracker;
pub mod preflight_runner;
pub mod state_management;

// Tests are kept in a separate module file
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

// Re-export key types for convenience
pub use mount_tracker::{MountInfo, MountTracker, MountType};

// Re-export public functions from helpers
pub use helpers::{apply_exclusion_filter, build_overlay_targets};

// Re-export crate-internal helpers so sub-modules (e.g., activation) can use `super::*`
pub(crate) use helpers::{
    clean_stale_network_config, create_overlay_config, ensure_run_current_system_symlink,
    select_system_profile, start_service_and_socket,
};

/// Central orchestrator for all NAILS operations
///
/// NailsManager coordinates state transitions, filesystem operations,
/// and validation logic. The generic Filesystem parameter enables
/// testing without root privileges.
///
/// # Fields
///
/// - `filesystem`: Generic filesystem implementation (real or mock)
/// - `config`: Application configuration
/// - `state_file_path`: Path to state file (on hidden volume)
/// - `cached_state`: Cached state file (lazy loaded, thread-safe)
///
/// # Thread Safety
///
/// `cached_state` uses `Arc<Mutex<_>>` for thread-safe lazy loading.
/// While NAILS is single-threaded in Phase 1 (AR47), this pattern enables
/// future extensions and parallel testing.
///
/// # Requirements
///
/// - AR3: Core library contains all business logic
/// - AR4: Testable without root via trait abstraction
/// - AR44: Generic NailsManager<F: Filesystem> pattern
pub struct NailsManager<F: Filesystem> {
    /// Filesystem implementation (real or mock)
    filesystem: F,

    /// Application configuration
    config: Config,

    /// Path to state file (on hidden volume)
    state_file_path: PathBuf,

    /// Cached state file (lazy loaded, thread-safe)
    /// Arc<Mutex<_>> enables thread-safe access and clone implementation
    cached_state: Arc<Mutex<Option<crate::StateFile>>>,

    /// NixOS profile builder (optional, for activation with NixOS switching)
    /// If None, activation will skip NixOS build/switch steps
    nixos_builder: Option<crate::nixos::NixOSBuilder>,

    /// Verbosity level for progress output
    verbosity: crate::verbosity::Verbosity,
}

// Manual Debug implementation because NixOSBuilder contains trait objects
impl<F: Filesystem> std::fmt::Debug for NailsManager<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NailsManager")
            .field("filesystem", &"<filesystem>")
            .field("config", &self.config)
            .field("state_file_path", &self.state_file_path)
            .field("cached_state", &"<Arc<Mutex<...>>>")
            .field(
                "nixos_builder",
                &self.nixos_builder.as_ref().map(|_| "<NixOSBuilder>"),
            )
            .field("verbosity", &self.verbosity)
            .finish()
    }
}

impl<F: Filesystem> NailsManager<F> {
    /// Create a new NailsManager with lazy loading
    ///
    /// The constructor stores all parameters but does NOT load state from disk.
    /// State is loaded lazily on first access via `current_state()`.
    ///
    /// # Arguments
    ///
    /// * `filesystem` - Filesystem implementation (RealFilesystem or MockFilesystem)
    /// * `config` - Application configuration
    /// * `state_file_path` - Path to state file (must be on hidden volume)
    ///
    /// # Returns
    ///
    /// New NailsManager instance with unloaded state (None) and no NixOS builder.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    /// let manager = NailsManager::new(fs, config, state_path);
    /// ```
    pub fn new(filesystem: F, config: Config, state_file_path: PathBuf) -> Self {
        Self {
            filesystem,
            config,
            state_file_path,
            cached_state: Arc::new(Mutex::new(None)),
            nixos_builder: None,
            verbosity: crate::verbosity::Verbosity::default(),
        }
    }

    /// Create a new NailsManager with NixOS builder for full activation support
    ///
    /// Use this constructor when you need NixOS profile building and switching
    /// during activation. The standard `new()` constructor creates a manager
    /// without NixOS support (activation will skip NixOS steps).
    ///
    /// # Arguments
    ///
    /// * `filesystem` - Filesystem implementation (RealFilesystem or MockFilesystem)
    /// * `config` - Application configuration
    /// * `state_file_path` - Path to state file (must be on hidden volume)
    /// * `nixos_builder` - NixOS profile builder instance
    ///
    /// # Returns
    ///
    /// New NailsManager instance with NixOS support enabled.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config, NixOSBuilder};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    /// let nixos_builder = NixOSBuilder::new(
    ///     PathBuf::from("/mnt/hidden/nixos"),
    ///     PathBuf::from("/nix/var/nix/profiles/nails-system"),
    /// );
    /// let manager = NailsManager::with_nixos(fs, config, state_path, nixos_builder);
    /// ```
    pub fn with_nixos(
        filesystem: F,
        config: Config,
        state_file_path: PathBuf,
        nixos_builder: crate::nixos::NixOSBuilder,
    ) -> Self {
        Self {
            filesystem,
            config,
            state_file_path,
            cached_state: Arc::new(Mutex::new(None)),
            nixos_builder: Some(nixos_builder),
            verbosity: crate::verbosity::Verbosity::default(),
        }
    }

    /// Set verbosity level for progress output
    ///
    /// Controls the amount of detail in progress messages during operations.
    ///
    /// # Arguments
    ///
    /// * `verbosity` - Desired verbosity level
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config, Verbosity};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/tmp/state.json");
    /// let mut manager = NailsManager::new(fs, config, state_path);
    /// manager.set_verbosity(Verbosity::Verbose);
    /// ```
    pub fn set_verbosity(&mut self, verbosity: crate::verbosity::Verbosity) {
        self.verbosity = verbosity;
    }

    /// Unmount overlays in reverse order (LIFO)
    ///
    /// Unmounts overlays in reverse of mount order to respect dependencies.
    /// Uses best-effort rollback: continues unmounting even if individual unmounts fail.
    ///
    /// # Arguments
    ///
    /// * `mounted_paths` - Vec of mounted overlay paths in mount order
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All unmounts succeeded
    /// * `Err(NailsError)` - One or more unmounts failed (with aggregate error details)
    ///
    /// # Behavior (Story 4.6, AC4-AC5)
    ///
    /// - Unmounts in LIFO order (reverse iteration)
    /// - Tries graceful unmount first, then force unmount on failure
    /// - Logs each unmount operation
    /// - Best-effort: continues even if one unmount fails
    /// - Returns aggregate error listing all failures
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let manager = NailsManager::new(fs, config, PathBuf::from("/tmp/state.json"));
    ///
    /// let mounted = vec![PathBuf::from("/home"), PathBuf::from("/etc")];
    /// manager.unmount_overlays(mounted).unwrap();
    /// // Unmounts in reverse: /etc first, then /home
    /// ```
    pub fn unmount_overlays(&self, mounted_paths: Vec<PathBuf>) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();

        // LIFO: unmount in reverse order
        for path in mounted_paths.iter().rev() {
            tracing::info!(
                path = %path.display(),
                order = "LIFO",
                "Unmounting overlay"
            );

            // Try graceful unmount first (Epic 4.2 requirement)
            if let Err(e) = self.filesystem.unmount(path, false) {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    attempt = "graceful",
                    "Unmount failed, trying force unmount"
                );

                // If graceful fails, try force unmount
                if let Err(force_err) = self.filesystem.unmount(path, true) {
                    let msg = format!(
                        "Failed to unmount {} (graceful and force both failed): {}",
                        path.display(),
                        force_err
                    );
                    tracing::warn!(
                        path = %path.display(),
                        error = %force_err,
                        attempts = "both",
                        "Force unmount also failed"
                    );
                    errors.push(msg); // Collect error but continue (best-effort)
                } else {
                    tracing::info!(
                        path = %path.display(),
                        method = "force",
                        "Unmount succeeded"
                    );
                }
            } else {
                tracing::info!(
                    path = %path.display(),
                    method = "graceful",
                    "Unmount succeeded"
                );
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(NailsError::OverlayError(format!(
                "Unmount completed with errors: {}",
                errors.join("; ")
            )))
        }
    }

    /// Get reference to filesystem implementation
    ///
    /// Provides access to filesystem operations for advanced use cases like
    /// ActivationOrchestrator (Story 4.5).
    ///
    /// # Returns
    ///
    /// Reference to the filesystem implementation (RealFilesystem or MockFilesystem)
    pub fn filesystem(&self) -> &F {
        &self.filesystem
    }

    /// Get reference to configuration
    ///
    /// Provides access to configuration for advanced use cases like
    /// ActivationOrchestrator (Story 4.5).
    ///
    /// # Returns
    ///
    /// Reference to the configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get current verbosity level for internal orchestration flows.
    pub(crate) fn verbosity(&self) -> crate::verbosity::Verbosity {
        self.verbosity
    }
}
