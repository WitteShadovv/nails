// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # System State Management
//!
//! Core state machine for NAILS with type-safe transitions.
//!
//! ## Overview
//!
//! The `SystemState` enum represents all possible states of the NAILS system,
//! ensuring compile-time guarantees that invalid states are impossible.
//!
//! ## Valid State Transitions
//!
//! ```text
//! Inactive → Activating → Active → Deactivating → Inactive
//! Active/Deactivating → Degraded (partial teardown) → Inactive (recover)
//! ```
//!
//! ## Example
//!
//! ```
//! use nails_core::SystemState;
//!
//! // Start from inactive state
//! let state = SystemState::Inactive;
//!
//! // Begin activation (valid transition)
//! let activating = state.begin_activation().expect("Should transition to Activating");
//! assert!(matches!(activating, SystemState::Activating { .. }));
//!
//! // Complete activation
//! let active = activating
//!     .complete_activation(vec![], vec![])
//!     .expect("Should transition to Active");
//! assert!(active.is_active());
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// Re-export imports needed by tests (via `use super::*`)
#[cfg(test)]
pub(crate) use crate::NailsError;

mod file;
mod guard;
mod lock;
mod reconcile;
#[cfg(test)]
mod tests;
mod transitions;

// Re-export all public items.
pub use file::{HiddenSession, LastActivation, LoadOutcome, LoadResult, PlatformState, StateFile};
pub use guard::StateGuard;
pub use lock::{EMERGENCY_LOCK_TIMEOUT, StateLock};
pub use reconcile::{DegradedKind, EffectiveState, InterruptedPhase, reconcile};

// Kernel boot id reader, shared with state reconciliation in the manager.
pub(crate) use file::read_boot_id;

// Test-only save-failure seam, reachable crate-wide for the deactivation
// regression tests even though `file` is a private module.
#[cfg(test)]
pub(crate) use file::save_probe;

// Test-only boot-id override, so the manager's reconcile tests can drive the
// stale-from-previous-boot path without a real reboot.
#[cfg(test)]
pub(crate) use file::test_boot_id;

/// Check if a path is within the hidden volume
///
/// Validates that the given path is within the hidden volume root to prevent
/// forensic leakage of state information to the decoy system.
///
/// # Arguments
///
/// * `path` - Path to validate
/// * `hidden_volume_root` - Root path of the hidden volume (from config)
///
/// # Returns
///
/// * `true` if path is within hidden volume
/// * `false` otherwise
pub fn is_on_hidden_volume(path: &Path, hidden_volume_root: &str) -> bool {
    is_on_hidden_volume_internal(path, hidden_volume_root)
}

/// Check if a path is a symlink using `symlink_metadata`
fn is_symlink_path(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => meta.file_type().is_symlink(),
        Err(_) => false,
    }
}

/// Internal implementation of hidden volume path checking
///
/// Fail-closed: rejects symlinked roots and paths that escape the hidden
/// volume boundary via symlinks or traversal. When the root doesn't exist
/// on disk (e.g., during config validation before mount), falls back to
/// cleaned string-prefix comparison.
fn is_on_hidden_volume_internal(path: &Path, hidden_volume_root: &str) -> bool {
    let root_path = Path::new(hidden_volume_root);

    // Reject symlinked hidden-volume roots
    if is_symlink_path(root_path) {
        return false;
    }

    // Try to canonicalize the root to get its real path
    let canonical_root = match root_path.canonicalize() {
        Ok(cr) => cr,
        Err(_) => {
            // Root doesn't exist — can't do filesystem-level checks.
            // Fall through to string-based validation for config-time checks.
            // Clean both paths to prevent traversal attacks.
            let cleaned_root = clean_path_components(root_path);
            let cleaned_path = if path.is_absolute() {
                clean_path_components(path)
            } else {
                // Relative paths can't be on an absolute hidden volume root
                return false;
            };
            return cleaned_path.starts_with(&cleaned_root);
        }
    };

    // Try to canonicalize the target path to resolve symlinks
    match path.canonicalize() {
        Ok(canonical) => canonical.starts_with(&canonical_root),
        // If path doesn't exist yet, we need to clean it manually
        Err(_) => {
            let absolute = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()
                    .ok()
                    .and_then(|cwd| cwd.join(path).canonicalize().ok())
                    .unwrap_or_else(|| path.to_path_buf())
            };

            let cleaned = clean_path_components(&absolute);

            // Check if the nearest existing ancestor is a symlink
            // pointing outside the hidden volume
            let mut check = cleaned.clone();
            while let Some(parent) = check.parent() {
                if parent.exists() {
                    if is_symlink_path(parent) {
                        match parent.canonicalize() {
                            Ok(real_parent) => {
                                if !real_parent.starts_with(&canonical_root) {
                                    return false;
                                }
                            }
                            Err(_) => return false,
                        }
                    }
                    break;
                }
                if parent == Path::new("/") {
                    break;
                }
                check = parent.to_path_buf();
            }

            cleaned.starts_with(&canonical_root)
        }
    }
}

/// Clean a path by resolving ".." and "." components without filesystem access
fn clean_path_components(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::Normal(c) => {
                components.push(c);
            }
            std::path::Component::RootDir => {
                components.clear();
            }
            _ => {}
        }
    }
    let mut cleaned = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        PathBuf::new()
    };
    for component in components {
        cleaned.push(component);
    }
    cleaned
}

/// System state enum with type-safe transitions
///
/// Each variant represents a distinct system state with associated metadata.
/// Invalid states are impossible at compile time due to Rust's type system.
///
/// # Requirements
///
/// - Track current state
/// - Track timestamp for each state transition
/// - Serialize state to JSON
/// - Impossible invalid states via enum pattern matching
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SystemState {
    /// System is inactive (decoy state)
    Inactive,

    /// Activation in progress
    Activating {
        /// When activation started
        started_at: DateTime<Utc>,
    },

    /// System is active (hidden environment mounted)
    Active {
        /// When activation completed
        activated_at: DateTime<Utc>,
        /// List of mounted overlay paths
        overlays: Vec<PathBuf>,
        /// Writers that still referenced the decoy lower tree once the overlays
        /// were up (empty when activation left none behind).
        ///
        /// Captured at activation time: these processes were deliberately not
        /// restarted, so they keep writing to the decoy for as long as they run.
        /// Recording them here lets `status`, which runs as a separate process,
        /// report the leak without re-scanning `/proc`.
        #[serde(default)]
        decoy_writers: Vec<DecoyWriter>,
    },

    /// Deactivation in progress
    Deactivating {
        /// When deactivation started
        started_at: DateTime<Utc>,
    },

    /// Teardown or rollback left the system partly dismantled.
    ///
    /// Reached when a deactivation, rollback, or emergency teardown could not
    /// unmount every overlay. The system is neither cleanly active nor cleanly
    /// inactive: some overlays listed in `remaining_mounts` may still be live,
    /// so the operator must recover (retry teardown) before activating again.
    Degraded {
        /// When the system entered the degraded state.
        since: DateTime<Utc>,
        /// Why teardown could not complete, for operator diagnosis.
        reason: String,
        /// Mount points that may still be live and need manual attention.
        remaining_mounts: Vec<PathBuf>,
    },
}

/// Information about a mounted overlay filesystem
///
/// # Requirements
///
/// - Track overlay status with mount paths and directories
/// - State file contains overlay status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverlayInfo {
    /// Target mount point (e.g., /home, /etc)
    pub mount_path: PathBuf,

    /// Lower (read-only) directory from base system
    pub lower_dir: PathBuf,

    /// Upper (writable) directory on hidden volume
    pub upper_dir: PathBuf,

    /// Work directory for overlay metadata
    pub work_dir: PathBuf,

    /// Timestamp when this overlay was mounted
    pub mounted_at: DateTime<Utc>,

    /// How this overlay was mounted (direct mount, or pivot fallback).
    ///
    /// Recorded per target so `status` can report the method without
    /// re-deriving it from the live mount table. A state file written before
    /// this field existed deserializes to [`MountMethod::Direct`].
    #[serde(default)]
    pub mount_method: crate::overlay::MountMethod,
}

/// Information about a failed overlay mount attempt
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FailedOverlayInfo {
    /// Target mount point that failed (e.g., /var, /tmp)
    pub target: PathBuf,

    /// Error message explaining why mount failed
    pub error_message: String,

    /// Timestamp when the mount attempt failed
    pub failed_at: DateTime<Utc>,
}

/// A mount activation created to keep a submount visible under an overlaid
/// target, recorded so teardown can undo exactly what it made, in the right
/// order.
///
/// A submount hidden beneath a parent overlay is first staged (a recursive bind
/// to a path under the hidden root), then either re-attached over the overlay
/// (another bind) or given its own nested overlay. Each resulting mount is
/// recorded here in creation order; deactivation and rollback undo the list in
/// reverse, so a nested overlay always comes off before the staging bind that
/// backs its lower layer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SubmountAttachment {
    /// A bind mount (a staging bind under the hidden root, or a read-only
    /// re-attach over the overlay). Undone with an idempotent bind unmount.
    Bind { path: PathBuf },
    /// A nested overlay mounted over the parent overlay, with its upper/work under
    /// the hidden root. Undone with an overlay unmount.
    Overlay { path: PathBuf },
}

impl SubmountAttachment {
    /// The mount point this attachment lives at.
    pub fn path(&self) -> &std::path::Path {
        match self {
            SubmountAttachment::Bind { path } | SubmountAttachment::Overlay { path } => path,
        }
    }
}

/// A process that still referenced the decoy lower tree after activation.
///
/// A process that opened an overlay target before the mount keeps resolving the
/// original inodes, so whatever it writes lands on the decoy rather than the
/// hidden volume. Activation restarts the writers it can; the ones it cannot (or
/// was told to leave running) are recorded with their identity so the activation
/// outcome, the login notification and `status` can name them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoyWriter {
    /// Process ID at activation time.
    pub pid: u32,
    /// Process name (from `/proc/{pid}/comm`).
    pub name: String,
    /// Systemd service backing the process, without the `.service` suffix.
    #[serde(default)]
    pub service: Option<String>,
    /// Overlay targets the process still references through the decoy.
    pub targets: Vec<PathBuf>,
}

impl DecoyWriter {
    /// Who the writer is: `tail (PID 812)` or
    /// `NetworkManager (NetworkManager.service, PID 600)`.
    pub fn label(&self) -> String {
        match &self.service {
            Some(service) => format!("{} ({}.service, PID {})", self.name, service, self.pid),
            None => format!("{} (PID {})", self.name, self.pid),
        }
    }
}

impl std::fmt::Display for DecoyWriter {
    /// The label followed by the targets it still writes to:
    /// `tail (PID 812) on /var`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let targets = self
            .targets
            .iter()
            .map(|target| target.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{} on {}", self.label(), targets)
    }
}

/// The headline for a set of decoy writers: `1 writer still on the decoy` or
/// `3 writers still on the decoy`.
///
/// Shared by the activation outcome, the login notification and `status` so all
/// three name the leak the same way.
pub fn decoy_writers_headline(count: usize) -> String {
    let noun = if count == 1 { "writer" } else { "writers" };
    format!("{count} {noun} still on the decoy")
}

/// A one-line summary naming at most `limit` writers, then how many more there
/// are: `tail (PID 812) on /var, bash (PID 77) on /srv and 2 more`.
///
/// Used where space is short (the desktop notification); full listings print
/// every writer.
pub fn summarize_decoy_writers(writers: &[DecoyWriter], limit: usize) -> String {
    let shown = writers
        .iter()
        .take(limit)
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let hidden = writers.len().saturating_sub(limit);
    if hidden == 0 {
        shown
    } else {
        format!("{shown} and {hidden} more")
    }
}
