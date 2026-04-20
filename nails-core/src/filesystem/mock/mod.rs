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
mod tests_overlay;

pub use state::{MockFilesystem, MockOp};
