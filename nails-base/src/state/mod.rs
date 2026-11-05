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
/// when the root does not exist, and so is a path whose last name is a
/// symlink. Whether a volume is mounted at the root is not its question but
/// the attach gate's (`crate::hidden_root`).
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
/// resolved as the kernel resolves them. The kernel must reach the root at its
/// real location too (see [`is_same_file`]). A root that does not exist holds
/// no path: no volume is mounted there, and what is made below it lands on the
/// filesystem that holds its parent.
fn is_on_hidden_volume_internal(path: &Path, hidden_volume_root: &str) -> bool {
    // The root as its components give it: lstat follows a symlinked root
    // written with a trailing `/`.
    let root_path: PathBuf = Path::new(hidden_volume_root).components().collect();

    // A relative or empty root names no hidden volume: lstat and canonicalize
    // would read it from the working directory, whichever that is.
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
    if !is_same_file(&root_path, &canonical_root) {
        return false;
    }
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
/// - at a symlink at the last name, wherever it lies and leads: the state
///   file's write renames its file over that name, which replaces the symlink
///   where it lies, while a write that opens the name follows the symlink to
///   where it leads, and no state file is a symlink;
/// - at a symlink on the way that leads nowhere (to nothing, or round in a
///   loop): there is no place it leads to that could be checked;
/// - at a component that lstat cannot look at for any other reason than that
///   it is not there, as below a directory that may not be searched or below a
///   file: whether it is a symlink, and where it leads, is not known;
/// - at a `..` after a file, which the kernel refuses too;
/// - at a `..` after a component that does not exist yet: making the
///   directories (`mkdir -p`) makes that one first, wherever the components
///   before it lead, before the `..` leaves it again;
/// - where the kernel reaches another file than the one at the place found
///   (see [`is_same_file`]).
fn real_location(path: &Path) -> Option<PathBuf> {
    // The last name as the components give it: lstat follows a symlink
    // written with a trailing `/`.
    let named: PathBuf = path.components().collect();
    if std::fs::symlink_metadata(&named).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return None;
    }
    if let Ok(real) = path.canonicalize() {
        return is_same_file(path, &real).then_some(real);
    }
    if !path.is_absolute() {
        return None;
    }
    let mut real = PathBuf::from("/");
    // The part of `path` that exists, as written, for the kernel to resolve.
    let mut existing = PathBuf::from("/");
    // The components below `real` that do not exist yet.
    let mut missing: Vec<&OsStr> = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) if missing.is_empty() => {
                let next = real.join(name);
                match next.canonicalize() {
                    Ok(resolved) => {
                        real = resolved;
                        existing.push(name);
                    }
                    Err(_) if is_not_there(&next) => missing.push(name),
                    Err(_) => return None,
                }
            }
            Component::Normal(name) => missing.push(name),
            Component::ParentDir if missing.is_empty() && real.is_dir() => {
                real.pop();
                existing.push(component);
            }
            Component::ParentDir => return None,
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    if !is_same_file(&existing, &real) {
        return None;
    }
    real.extend(missing);
    Some(real)
}

/// Whether the kernel, following every symlink, reaches the same file at the
/// path `written` as at the place `found` that canonicalize gave for it.
///
/// canonicalize reads the text of each symlink on the way and goes on from
/// the path it names. A magic link of `/proc`, such as `/proc/self/fd/3`,
/// leads the kernel straight to the file it stands for, and its text, the path
/// of that file, may lead elsewhere: to a mount that covers the file now, or,
/// once the file is removed, to whatever was made at its old path with
/// ` (deleted)` added.
fn is_same_file(written: &Path, found: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(written), std::fs::metadata(found)) {
        (Ok(written), Ok(found)) => written.dev() == found.dev() && written.ino() == found.ino(),
        _ => false,
    }
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
