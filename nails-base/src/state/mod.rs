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
use std::ffi::OsStr;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

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
/// forensic leakage of state information to the decoy system. Fail-closed:
/// whatever the check cannot settle on disk is refused, among it every path
/// when the root does not exist. Whether a volume is mounted at the root is
/// not its question but the attach gate's (`crate::hidden_root`).
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
///
/// Fail-closed: the root must be an absolute path to a directory that exists,
/// is no symlink and is not `/`, and the path's real location
/// ([`real_location`]) must lie below the root's: the place it lies, or would
/// be created with the directories it lacks, every symlink and `..` on the way
/// resolved as the kernel resolves them. A root that does not exist holds no
/// path: no volume is mounted there, and what is made below it lands on the
/// filesystem that holds its parent.
fn is_on_hidden_volume_internal(path: &Path, hidden_volume_root: &str) -> bool {
    // The root as its components give it: lstat follows a symlinked root
    // written with a trailing `/`.
    let root_path: PathBuf = Path::new(hidden_volume_root).components().collect();

    // A relative or empty root is no hidden volume: cleaned, it can shrink to
    // nothing, and every path starts with that.
    if !root_path.is_absolute() {
        return false;
    }

    // A directory itself, not a symlink to one: lstat says so for a root that
    // exists and can be looked at, and refuses every other root.
    match std::fs::symlink_metadata(&root_path) {
        Ok(meta) if meta.is_dir() => {}
        _ => return false,
    }
    let Ok(canonical_root) = root_path.canonicalize() else {
        return false;
    };
    // `/` holds every path.
    if canonical_root.parent().is_none() {
        return false;
    }

    real_location(path).is_some_and(|real| real.starts_with(&canonical_root))
}

/// Where `path` lies, or would be created together with the directories it
/// lacks, as the kernel resolves it. From `/`, each component that exists is
/// followed to its real place: a symlink to where it leads, a `..` to the
/// parent of the real directory reached. The components that do not exist yet
/// are added below the last one that does.
///
/// `None`, which the check refuses, wherever that place is not certain:
/// - for a relative path that does not exist;
/// - at a symlink on the way that leads nowhere (to nothing, or round in a
///   loop): the kernel follows a dangling symlink when it creates the file, so
///   what it would create could lie anywhere;
/// - at a component that lstat cannot look at for any other reason than that
///   it is not there, as below a directory that may not be searched or below a
///   file: whether it is a symlink, and where it leads, is not known;
/// - at a `..` after a file, which the kernel refuses too;
/// - at a `..` after a component that does not exist yet: making the
///   directories (`mkdir -p`) makes that one first, wherever the components
///   before it lead, before the `..` leaves it again.
fn real_location(path: &Path) -> Option<PathBuf> {
    if let Ok(real) = path.canonicalize() {
        return Some(real);
    }
    if !path.is_absolute() {
        return None;
    }
    let mut real = PathBuf::from("/");
    // The components below `real` that do not exist yet.
    let mut missing: Vec<&OsStr> = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) if missing.is_empty() => {
                let next = real.join(name);
                match next.canonicalize() {
                    Ok(resolved) => real = resolved,
                    Err(_) if is_not_there(&next) => missing.push(name),
                    Err(_) => return None,
                }
            }
            Component::Normal(name) => missing.push(name),
            Component::ParentDir if missing.is_empty() && real.is_dir() => {
                real.pop();
            }
            Component::ParentDir => return None,
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    real.extend(missing);
    Some(real)
}

/// Whether lstat finds nothing at `path`: no file, directory or symlink, and
/// no other error that would hide one.
fn is_not_there(path: &Path) -> bool {
    matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == ErrorKind::NotFound)
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
