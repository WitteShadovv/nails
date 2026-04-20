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
//! use nails_core::filesystem::{Filesystem, MockFilesystem};
//! use std::path::Path;
//!
//! // Testing: No root required
//! let fs = MockFilesystem::new();
//!
//! // Set up paths to exist
//! fs.mock_set_path_exists("/", true);
//! fs.mock_set_path_exists("/mnt/hidden/upper", true);
//! fs.mock_set_path_exists("/mnt/hidden/work", true);
//!
//! let result = fs.mount_overlay(
//!     &[Path::new("/")],
//!     Path::new("/mnt/hidden/upper"),
//!     Path::new("/mnt/hidden/work"),
//!     Path::new("/home")
//! );
//! assert!(result.is_ok());
//! ```

// Submodules
pub mod mock;
pub mod mount_info;
pub mod real;
mod traits;

// Re-exports
pub use mock::{MockFilesystem, MockOp};
pub use mount_info::MountInfo;
pub use real::RealFilesystem;
pub use traits::*;
