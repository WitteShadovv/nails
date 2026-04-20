//! # Deactivation Orchestrator Module
//!
//! Coordinates atomic deactivation operations for NAILS, including:
//! - Artifact cleanup (history, temp files, logs)
//! - Overlay unmounting in reverse LIFO order
//! - Automatic rollback on failures (via StateGuard RAII)
//!
//! # Architecture
//!
//! DeactivationOrchestrator follows a 6-step sequence (Story 5.5, AC2):
//! 1. **State transition:** ACTIVE → DEACTIVATING with StateGuard
//! 2. **Artifact cleanup:** Call CleanupManager with Thorough mode
//! 3. **Overlay unmount:** Unmount overlays in reverse LIFO order
//! 4. **State transition:** DEACTIVATING → INACTIVE
//! 5. **Decoy switch:** Switch to newest available base system generation
//! 6. **Commit StateGuard:** Finalize deactivation
//!
//! If any step fails, StateGuard automatically rolls back to ACTIVE state (FR51).
//!
//! # Rollback Scenarios (TR49, TR50)
//!
//! **TR49 - Cleanup Fails:**
//! - State: ACTIVE → DEACTIVATING → (cleanup fails) → ACTIVE
//! - Overlays: Remain mounted (never unmounted)
//! - Action: StateGuard drops without commit, rolls back state
//!
//! **TR50 - Unmount Fails:**
//! - State: ACTIVE → DEACTIVATING → (unmount fails) → ACTIVE
//! - Overlays:
//!   - Successfully unmounted ones get remounted
//!   - Failed one remains mounted (was never unmounted)
//! - Action:
//!   1. Remount successfully unmounted overlays
//!   2. StateGuard drops without commit, rolls back state
//!
//! # Example
//!
//! ```rust,ignore
//! use nails_core::{DeactivationOrchestrator, DeactivationReport, CleanupConfig};
//! use std::sync::{Arc, Mutex};
//!
//! let orchestrator = DeactivationOrchestrator::new(
//!     Arc::clone(&manager),
//!     CleanupConfig::default(),
//! );
//!
//! match orchestrator.run() {
//!     Ok(report) => println!("{}", report),
//!     Err(e) => eprintln!("Deactivation failed: {}", e),
//! }
//! ```

mod orchestrator;
mod report;

#[cfg(test)]
mod tests;

// Public exports
pub use orchestrator::{DeactivationMode, DeactivationOrchestrator};
pub use report::{DeactivationReport, PostUnmountCleanupReport};
