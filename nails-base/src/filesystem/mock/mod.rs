// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Mock filesystem for testing (no root privileges required)
//!
//! Uses in-memory state tracking to simulate filesystem operations.
//! All operations are thread-safe via `Arc<Mutex<_>>`.

mod assertions;
mod filesystem_impl;
mod operations_files;
mod operations_mounts;
mod operations_paths;
mod operations_profiles;
mod setup_directory;
mod setup_state;
mod state;

#[cfg(test)]
mod tests_basic;
#[cfg(test)]
mod tests_mounts;

pub use setup_state::PathKind;
pub use state::{MockFilesystem, MockOp};
