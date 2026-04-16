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
//! Any State → Emergency
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
//!     .complete_activation(vec![])
//!     .expect("Should transition to Active");
//! assert!(active.is_active());
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// Re-export imports needed by tests (via `use super::*`)
#[cfg(test)]
pub(crate) use crate::NailsError;
#[cfg(test)]
pub(crate) use std::sync::{Arc, Mutex};

mod file;
mod guard;
#[cfg(test)]
mod tests;
mod transitions;

// Re-export all public items for backward compatibility
pub use file::StateFile;
pub use guard::StateGuard;

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

/// Internal implementation of hidden volume path checking
fn is_on_hidden_volume_internal(path: &Path, hidden_volume_root: &str) -> bool {
    // Try to canonicalize to resolve symlinks
    match path.canonicalize() {
        Ok(canonical) => canonical.starts_with(hidden_volume_root),
        // If path doesn't exist yet, we need to clean it manually
        // to prevent path traversal attacks
        Err(_) => {
            // Convert to absolute path and clean ".." components
            let absolute = if path.is_absolute() {
                path.to_path_buf()
            } else {
                // If relative, make it absolute from current dir
                std::env::current_dir()
                    .ok()
                    .and_then(|cwd| cwd.join(path).canonicalize().ok())
                    .unwrap_or_else(|| path.to_path_buf())
            };

            // Manually clean path by resolving ".." components
            let mut components = Vec::new();
            for component in absolute.components() {
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

            // Reconstruct path from components
            let mut cleaned = PathBuf::from("/");
            for component in components {
                cleaned.push(component);
            }

            cleaned.starts_with(hidden_volume_root)
        }
    }
}

/// System state enum with type-safe transitions
///
/// Each variant represents a distinct system state with associated metadata.
/// Invalid states are impossible at compile time due to Rust's type system.
///
/// # Requirements
///
/// - FR26: Track current state
/// - FR27: Track timestamp for each state transition
/// - FR29: Serialize state to JSON
/// - NFR12: Impossible invalid states via enum pattern matching
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
    },

    /// Deactivation in progress
    Deactivating {
        /// When deactivation started
        started_at: DateTime<Utc>,
    },

    /// Emergency shutdown triggered
    Emergency {
        /// When emergency was triggered
        triggered_at: DateTime<Utc>,
    },
}

/// Information about a mounted overlay filesystem
///
/// # Requirements
///
/// - FR28: Track overlay status with mount paths and directories
/// - AR25: State file contains overlay status
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
}

/// Information about a failed overlay mount attempt (Story 14.10, AC9)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FailedOverlayInfo {
    /// Target mount point that failed (e.g., /var, /tmp)
    pub target: PathBuf,

    /// Error message explaining why mount failed
    pub error_message: String,

    /// Timestamp when the mount attempt failed
    pub failed_at: DateTime<Utc>,
}
