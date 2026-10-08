// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # System State
//!
//! The state file on the hidden volume records whether a hidden session was
//! entered, when, with which hidden system, and how long the entry took.
//!
//! A soft-reboot keeps the boot ID and kills the activating process, so the
//! state file is not where NAILS learns where the machine is: the live facts
//! (`nails_session::session::probe`) are authoritative, and the state file is the
//! record next to them.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

mod file;
mod lock;
#[cfg(test)]
mod tests;

pub use file::{LastActivation, LoadOutcome, LoadResult, PlatformState, StateFile};
pub use lock::{EMERGENCY_LOCK_TIMEOUT, StateLock};

// Kernel boot id reader.
pub use file::read_boot_id;

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

/// The recorded state of the hidden session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SystemState {
    /// No hidden session (the decoy).
    Inactive,

    /// A hidden session was entered.
    Active {
        /// When the entry was committed, right before the soft-reboot.
        activated_at: DateTime<Utc>,
    },

    /// Something went wrong that needs the operator's attention.
    Degraded {
        /// Since when.
        since: DateTime<Utc>,
        /// Why, for the operator.
        reason: String,
    },
}

impl SystemState {
    /// A hidden session was entered.
    pub fn is_active(&self) -> bool {
        matches!(self, SystemState::Active { .. })
    }

    /// No hidden session.
    pub fn is_inactive(&self) -> bool {
        matches!(self, SystemState::Inactive)
    }

    /// Degraded.
    pub fn is_degraded(&self) -> bool {
        matches!(self, SystemState::Degraded { .. })
    }

    /// A short label: `inactive`, `active` or `degraded`.
    pub fn label(&self) -> &'static str {
        match self {
            SystemState::Inactive => "inactive",
            SystemState::Active { .. } => "active",
            SystemState::Degraded { .. } => "degraded",
        }
    }
}
