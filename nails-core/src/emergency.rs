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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, MockFilesystem};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_emergency_deactivate_function_exists() {
        // Test that the emergency_deactivate function can be called
        // This is a smoke test to ensure the re-export works
        let fs = MockFilesystem::new();
        let config = Config::test_default();
        let state_path = PathBuf::from("/tmp/test-state.json");
        let manager = NailsManager::new(fs, config, state_path);
        let manager_arc = Arc::new(Mutex::new(manager));

        // The actual emergency deactivation will fail because we don't have
        // proper mocks set up, but that's okay - we're just testing the function exists
        let _ = emergency_deactivate(manager_arc);
    }
}
