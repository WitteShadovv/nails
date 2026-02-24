//! # Emergency Deactivation Module
//!
//! Re-exports the emergency deactivation functionality from NailsManager.
//!
//! Emergency deactivation performs thorough cleanup:
//! - Unmounts all overlays (ephemeral and persistent)
//! - Switches to decoy NixOS configuration
//! - Verifies forensic cleanliness
//! - Does NOT reboot (unlike `deactivate` which reboots immediately)

pub use crate::manager::NailsManager;

/// Emergency deactivate - thorough cleanup without reboot
///
/// This is a re-export of `NailsManager::emergency_deactivate()` for convenience.
pub fn emergency_deactivate<F: crate::Filesystem + 'static>(
    manager_arc: std::sync::Arc<std::sync::Mutex<NailsManager<F>>>,
) -> crate::Result<()> {
    NailsManager::emergency_deactivate(manager_arc)
}
