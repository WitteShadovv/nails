//! # State Transitions
//!
//! Type-safe state transition functions for the NAILS state machine.
//!
//! ## Valid State Transitions
//!
//! ```text
//! Inactive → Activating → Active → Deactivating → Inactive
//! Active/Activating/Deactivating → Degraded (partial teardown)
//! Degraded → Inactive (recover / completed emergency teardown)
//! ```

use super::{DecoyWriter, SystemState};
use crate::{NailsError, Result};
use chrono::Utc;
use std::path::PathBuf;

impl SystemState {
    /// Transition from Inactive to Activating state
    ///
    /// # Valid From States
    /// - `Inactive`
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
            SystemState::Degraded { .. } => Err(NailsError::InvalidState(
                "Cannot activate: system is degraded (run recover first)".into(),
            )),
        }
    }

    /// Transition from Activating to Active state
    ///
    /// # Arguments
    /// - `overlays` - List of overlay mount paths that were successfully mounted
    /// - `decoy_writers` - Writers still referencing the decoy after the mounts,
    ///   recorded so `status` can report them later
    ///
    /// # Valid From States
    /// - `Activating`
    ///
    /// # Returns
    /// - `Ok(SystemState::Active)` - Transition successful
    /// - `Err(NailsError::InvalidState)` - Invalid transition
    pub fn complete_activation(
        &self,
        overlays: Vec<PathBuf>,
        decoy_writers: Vec<DecoyWriter>,
    ) -> Result<SystemState> {
        match self {
            SystemState::Activating { .. } => Ok(SystemState::Active {
    decoy_writers: Vec::new(),
                activated_at: Utc::now(),
                overlays,
                decoy_writers,
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
            SystemState::Degraded { .. } => Err(NailsError::InvalidState(
                "Cannot complete activation: system is degraded (run recover first)".into(),
            )),
        }
    }

    /// Transition from Active to Deactivating state
    ///
    /// # Valid From States
    /// - `Active`
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
            SystemState::Degraded { .. } => Err(NailsError::InvalidState(
                "Cannot deactivate: system is degraded (run recover to finish teardown)".into(),
            )),
        }
    }

    /// Transition from Deactivating to Inactive state
    ///
    /// # Valid From States
    /// - `Deactivating`
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
            SystemState::Degraded { .. } => Err(NailsError::InvalidState(
                "Cannot complete deactivation: system is degraded (run recover instead)".into(),
            )),
        }
    }

    /// Enter the degraded state after a partial teardown or rollback.
    ///
    /// Allowed from any state: a teardown can leave overlays behind no matter
    /// where it started. `remaining_mounts` records the mount points that may
    /// still be live so the operator can finish the job.
    ///
    /// # Example
    /// ```
    /// use nails_core::SystemState;
    ///
    /// let state = SystemState::Active {
    ///     activated_at: chrono::Utc::now(),
    ///     overlays: vec![],
    ///     decoy_writers: vec![],
    /// };
    /// let degraded = state.enter_degraded("unmount of /home failed".into(), vec![]);
    /// assert!(degraded.is_degraded());
    /// ```
    pub fn enter_degraded(&self, reason: String, remaining_mounts: Vec<PathBuf>) -> SystemState {
        SystemState::Degraded {
            since: Utc::now(),
            reason,
            remaining_mounts,
        }
    }

    /// Recover from the degraded state back to Inactive.
    ///
    /// # Valid From States
    /// - `Degraded` - teardown has since completed
    /// - `Inactive` - idempotent no-op
    ///
    /// # Returns
    /// - `Ok(SystemState::Inactive)` - Recovery successful
    /// - `Err(NailsError::InvalidState)` - Nothing to recover from
    pub fn recover(&self) -> Result<SystemState> {
        match self {
            SystemState::Degraded { .. } | SystemState::Inactive => Ok(SystemState::Inactive),
            other => Err(NailsError::InvalidState(format!(
                "Cannot recover: system is not degraded (current state: {other:?})"
            ))),
        }
    }

    /// Drive the system to Inactive as the target of an emergency teardown.
    ///
    /// Always allowed from any state: emergency teardown is a critical security
    /// response that must never be blocked by the current state. A *successful*
    /// emergency teardown ends Inactive; a teardown that leaves overlays behind
    /// is recorded with [`enter_degraded`](Self::enter_degraded) instead.
    ///
    /// # Example
    /// ```
    /// use nails_core::SystemState;
    ///
    /// let state = SystemState::Active {
    ///     activated_at: chrono::Utc::now(),
    ///     overlays: vec![],
    ///     decoy_writers: vec![],
    /// };
    /// let after = state.trigger_emergency().expect("Emergency always succeeds");
    /// assert!(after.is_inactive());
    /// ```
    pub fn trigger_emergency(&self) -> Result<SystemState> {
        Ok(SystemState::Inactive)
    }

    /// Check if system is in Active state
    pub fn is_active(&self) -> bool {
        matches!(self, SystemState::Active { .. })
    }

    /// Check if system is in Inactive state
    pub fn is_inactive(&self) -> bool {
        matches!(self, SystemState::Inactive)
    }

    /// Check if system is in the Degraded state
    pub fn is_degraded(&self) -> bool {
        matches!(self, SystemState::Degraded { .. })
    }

    /// Check if system can be deactivated
    ///
    /// # Returns
    /// - `true` if state is `Active` (can call begin_deactivation)
    /// - `false` otherwise
    pub fn can_deactivate(&self) -> bool {
        matches!(self, SystemState::Active { .. })
    }
}
