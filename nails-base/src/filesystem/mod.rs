// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Filesystem abstraction for testing and production
//!
//! The Filesystem trait enables 99% of tests to run without root privileges:
//! - **Production:** RealFilesystem uses actual syscalls (requires root)
//! - **Testing:** MockFilesystem uses in-memory state (no root needed)
//!
//! # Architecture
//!
//! This trait abstraction is foundational to the entire NAILS testing strategy.
//! By abstracting all filesystem operations behind a trait boundary, we can:
//! - Run tests in parallel without root privileges
//! - Test error conditions that are hard to trigger with real syscalls
//! - Achieve fast CI/CD pipelines (seconds, not minutes)
//! - Maintain type safety with Send + Sync + Clone bounds
//!
//! # Example
//!
//! ```rust
//! use nails_base::filesystem::{Filesystem, MockFilesystem};
//! use std::path::Path;
//!
//! // Testing: No root required
//! let fs = MockFilesystem::new();
//! fs.mock_set_mounted(Path::new("/mnt/hidden"), true);
//! assert!(fs.is_mounted(Path::new("/mnt/hidden")).unwrap());
//! ```

// Submodules
// The in-memory mock is test-only infrastructure: it exists so downstream tests
// can drive the filesystem seam without real syscalls. Gating it behind the same
// switch as the other test fixtures keeps it out of release builds and out of the
// coverage figure, so the headline measures production code alone.
#[cfg(any(test, feature = "test-support"))]
pub mod mock;
pub mod mountinfo;
pub mod real;
pub mod safe_path;
mod traits;

// Re-exports
#[cfg(any(test, feature = "test-support"))]
pub use mock::{MockFilesystem, MockOp, PathKind};
pub use mountinfo::{
    MountEntry, OverlayOpts, escape_overlay_path, parse_mountinfo, parse_overlay_opts,
    read_mountinfo,
};
pub use real::RealFilesystem;
pub use safe_path::SafeRoot;
pub use traits::*;
