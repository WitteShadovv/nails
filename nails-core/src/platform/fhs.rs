//! The FHS backend: overlay-only hosts laid out on the Filesystem Hierarchy
//! Standard.
//!
//! Debian/Ubuntu is the first validated target; other FHS, systemd distributions
//! fall here too and are treated as provisional until they get their own
//! specialisation. The backend is deliberately plain: it overlays directories
//! with no distro-specific mount hooks and has no base-system restore step (a
//! reboot or the overlay teardown returns the host to its original state), so
//! [`Platform::restore_base_system`] keeps its no-op default.

use super::{OverlayPolicy, Platform, PlatformKind};
use crate::filesystem::Filesystem;

/// Directories an FHS host exposes host tools under.
const FHS_COMMAND_DIRS: &[&str] = &["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

/// Overlay-only backend for systemd FHS hosts (Debian/Ubuntu first).
#[derive(Debug, Clone, Copy, Default)]
pub struct FhsPlatform;

impl<F: Filesystem> Platform<F> for FhsPlatform {
    fn kind(&self) -> PlatformKind {
        PlatformKind::Fhs
    }

    fn overlay_policy(&self) -> OverlayPolicy {
        OverlayPolicy::Fhs
    }

    fn host_command_dirs(&self) -> &'static [&'static str] {
        FHS_COMMAND_DIRS
    }

    // restore_base_system: the default no-op is correct — an FHS host has no
    // generation to switch back to.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use crate::platform::RestoreOutcome;
    use crate::process::run::MockProcessRunner;

    #[test]
    fn restore_is_a_no_op_that_runs_nothing() {
        let fs = MockFilesystem::new();
        let runner = MockProcessRunner::new();
        let platform = FhsPlatform;

        let outcome =
            Platform::restore_base_system(&platform, &fs, &runner, true, &|| Ok(())).unwrap();

        assert_eq!(outcome, RestoreOutcome::NotRequired);
        assert!(
            runner.calls().is_empty(),
            "the FHS backend must never invoke switch-to-configuration"
        );
    }

    #[test]
    fn reports_overlay_only_policy() {
        let platform = FhsPlatform;
        assert_eq!(
            <FhsPlatform as Platform<MockFilesystem>>::overlay_policy(&platform),
            OverlayPolicy::Fhs
        );
    }
}
