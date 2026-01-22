//! # NAILS Core Library
//!
//! Business logic for NixOS Anti-forensics Isolation & Layering System.
//!
//! This crate contains all core functionality including:
//! - State management and transitions
//! - Filesystem operations and validation
//! - Pre-flight checks
//! - NixOS integration and profile management
//! - Cleanup orchestration
//!
//! The core library is designed to be reusable by different interfaces:
//! - CLI (nails-cli)
//! - GUI (future: nails-gui)
//! - Daemon (future: nails-daemon)
//!
//! # Architecture
//!
//! The core library follows a strict separation of concerns:
//! - No CLI-specific code
//! - No direct user interaction
//! - Pure business logic with clear error handling
//! - Well-defined traits for extensibility

// Error handling module
pub mod error;

// Filesystem operations module
pub mod filesystem;

// Re-export for convenience
pub use error::{NailsError, Result};
pub use filesystem::{Filesystem, MockFilesystem, RealFilesystem};

#[cfg(test)]
mod tests {
    #[test]
    fn test_library_compiles() {
        // Smoke test to verify core library compiles
        assert!(true);
    }

    #[test]
    fn test_workspace_version_exists() {
        // Verify workspace version is accessible
        let version = env!("CARGO_PKG_VERSION");
        assert_eq!(version, "0.1.0");
    }
}
