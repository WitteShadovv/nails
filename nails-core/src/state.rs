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

use crate::{NailsError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// System state enum with type-safe transitions
///
/// Each variant represents a distinct system state with associated metadata.
/// Invalid states are impossible at compile time due to Rust's type system.
///
/// # State Variants
///
/// - **Inactive**: System is in decoy state, no hidden environment active
/// - **Activating**: Activation in progress (mounts being set up)
/// - **Active**: Hidden environment fully activated and mounted
/// - **Deactivating**: Deactivation in progress (unmounting, cleanup)
/// - **Emergency**: Emergency shutdown triggered (forensic threat detected)
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

impl SystemState {
    /// Transition from Inactive to Activating state
    ///
    /// # Valid From States
    /// - `Inactive`
    ///
    /// # Invalid From States
    /// - `Activating` - Already activating
    /// - `Active` - Already active
    /// - `Deactivating` - Must complete deactivation first
    /// - `Emergency` - Cannot activate from emergency state
    ///
    /// # Returns
    /// - `Ok(SystemState::Activating)` - Transition successful
    /// - `Err(NailsError::InvalidState)` - Invalid transition
    ///
    /// # Example
    /// ```
    /// use nails_core::SystemState;
    ///
    /// let state = SystemState::Inactive;
    /// let activating = state.begin_activation().expect("Valid transition");
    /// ```
    pub fn begin_activation(&self) -> Result<SystemState> {
        match self {
            SystemState::Inactive => Ok(SystemState::Activating {
                started_at: Utc::now(),
            }),
            SystemState::Active { .. } => Err(NailsError::InvalidState(
                "Cannot activate: already active".into(),
            )),
            SystemState::Activating { .. } => Err(NailsError::InvalidState(
                "Cannot activate: activation already in progress".into(),
            )),
            SystemState::Deactivating { .. } => Err(NailsError::InvalidState(
                "Cannot activate: deactivation in progress".into(),
            )),
            SystemState::Emergency { .. } => Err(NailsError::InvalidState(
                "Cannot activate: system in emergency state".into(),
            )),
        }
    }

    /// Transition from Activating to Active state
    ///
    /// # Arguments
    /// - `overlays` - List of overlay mount paths that were successfully mounted
    ///
    /// # Valid From States
    /// - `Activating`
    ///
    /// # Invalid From States
    /// - `Inactive` - Must call begin_activation first
    /// - `Active` - Already active
    /// - `Deactivating` - Cannot activate while deactivating
    /// - `Emergency` - Cannot activate from emergency state
    ///
    /// # Returns
    /// - `Ok(SystemState::Active)` - Transition successful
    /// - `Err(NailsError::InvalidState)` - Invalid transition
    pub fn complete_activation(&self, overlays: Vec<PathBuf>) -> Result<SystemState> {
        match self {
            SystemState::Activating { .. } => Ok(SystemState::Active {
                activated_at: Utc::now(),
                overlays,
            }),
            SystemState::Inactive => Err(NailsError::InvalidState(
                "Cannot complete activation: not in activating state (call begin_activation first)"
                    .into(),
            )),
            SystemState::Active { .. } => Err(NailsError::InvalidState(
                "Cannot complete activation: already active".into(),
            )),
            SystemState::Deactivating { .. } => Err(NailsError::InvalidState(
                "Cannot complete activation: deactivation in progress".into(),
            )),
            SystemState::Emergency { .. } => Err(NailsError::InvalidState(
                "Cannot complete activation: system in emergency state".into(),
            )),
        }
    }

    /// Transition from Active to Deactivating state
    ///
    /// # Valid From States
    /// - `Active`
    ///
    /// # Invalid From States
    /// - `Inactive` - Nothing to deactivate
    /// - `Activating` - Must complete or rollback activation first
    /// - `Deactivating` - Already deactivating
    /// - `Emergency` - Use emergency shutdown instead
    ///
    /// # Returns
    /// - `Ok(SystemState::Deactivating)` - Transition successful
    /// - `Err(NailsError::InvalidState)` - Invalid transition
    pub fn begin_deactivation(&self) -> Result<SystemState> {
        match self {
            SystemState::Active { .. } => Ok(SystemState::Deactivating {
                started_at: Utc::now(),
            }),
            SystemState::Inactive => Err(NailsError::InvalidState(
                "Cannot deactivate: system is not active".into(),
            )),
            SystemState::Activating { .. } => Err(NailsError::InvalidState(
                "Cannot deactivate: activation in progress (complete or rollback first)".into(),
            )),
            SystemState::Deactivating { .. } => Err(NailsError::InvalidState(
                "Cannot deactivate: deactivation already in progress".into(),
            )),
            SystemState::Emergency { .. } => Err(NailsError::InvalidState(
                "Cannot deactivate: system in emergency state".into(),
            )),
        }
    }

    /// Transition from Deactivating to Inactive state
    ///
    /// # Valid From States
    /// - `Deactivating`
    ///
    /// # Invalid From States
    /// - `Inactive` - Already inactive
    /// - `Activating` - Must complete or rollback activation first
    /// - `Active` - Must call begin_deactivation first
    /// - `Emergency` - Cannot complete deactivation from emergency state
    ///
    /// # Returns
    /// - `Ok(SystemState::Inactive)` - Transition successful
    /// - `Err(NailsError::InvalidState)` - Invalid transition
    pub fn complete_deactivation(&self) -> Result<SystemState> {
        match self {
            SystemState::Deactivating { .. } => Ok(SystemState::Inactive),
            SystemState::Inactive => Err(NailsError::InvalidState(
                "Cannot complete deactivation: already inactive".into(),
            )),
            SystemState::Activating { .. } => Err(NailsError::InvalidState(
                "Cannot complete deactivation: activation in progress".into(),
            )),
            SystemState::Active { .. } => Err(NailsError::InvalidState(
                "Cannot complete deactivation: not in deactivating state (call begin_deactivation first)"
                    .into(),
            )),
            SystemState::Emergency { .. } => Err(NailsError::InvalidState(
                "Cannot complete deactivation: system in emergency state".into(),
            )),
        }
    }

    /// Trigger emergency shutdown from any state
    ///
    /// # Valid From States
    /// - **Any state** (including Emergency - idempotent)
    ///
    /// Emergency transitions are always allowed regardless of current state,
    /// as they represent a critical security response to forensic threats.
    ///
    /// # Returns
    /// - `Ok(SystemState::Emergency)` - Always succeeds
    ///
    /// # Example
    /// ```
    /// use nails_core::SystemState;
    ///
    /// let state = SystemState::Active {
    ///     activated_at: chrono::Utc::now(),
    ///     overlays: vec![],
    /// };
    /// let emergency = state.trigger_emergency().expect("Emergency always succeeds");
    /// ```
    pub fn trigger_emergency(&self) -> Result<SystemState> {
        // Emergency transition is always allowed from any state
        Ok(SystemState::Emergency {
            triggered_at: Utc::now(),
        })
    }

    /// Check if system is in Active state
    ///
    /// # Returns
    /// - `true` if state is `Active`
    /// - `false` otherwise
    pub fn is_active(&self) -> bool {
        matches!(self, SystemState::Active { .. })
    }

    /// Check if system is in Inactive state
    ///
    /// # Returns
    /// - `true` if state is `Inactive`
    /// - `false` otherwise
    pub fn is_inactive(&self) -> bool {
        matches!(self, SystemState::Inactive)
    }

    /// Check if system can be deactivated
    ///
    /// Returns true if the system is in a state where deactivation is valid.
    ///
    /// # Returns
    /// - `true` if state is `Active` (can call begin_deactivation)
    /// - `false` otherwise
    pub fn can_deactivate(&self) -> bool {
        matches!(self, SystemState::Active { .. })
    }
}
