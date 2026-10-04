// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The FHS backend: overlay-only hosts laid out on the Filesystem Hierarchy
//! Standard.
//!
//! Debian/Ubuntu is the first validated target; other FHS, systemd distributions
//! fall here too and are treated as provisional until they get their own
//! specialisation. The backend is deliberately plain: it overlays directories
//! with no distro-specific mount hooks and has no base-system restore step (a
//! reboot or the overlay teardown returns the host to its original state), so
//! [`Platform::restore_base_system`] keeps its no-op default.

use super::{ArtifactScanner, DebianPackageDriftScanner, OverlayPolicy, Platform, PlatformKind};
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
        OverlayPolicy::fhs()
    }

    fn host_command_dirs(&self) -> &'static [&'static str] {
        FHS_COMMAND_DIRS
    }

    fn display_manager_units(&self) -> &'static [&'static str] {
        // Debian/Ubuntu package GDM as `gdm3`; probe it before the upstream
        // `gdm` name so the session layer finds the real unit on those hosts.
        &["gdm3", "gdm", "sddm", "lightdm", "greetd", "ly"]
    }

    fn artifact_scanners(&self) -> Vec<Box<dyn ArtifactScanner<F>>>
    where
        F: 'static,
    {
        // The Debian package-drift scan is the validated FHS scanner. It is
        // self-gating: on a non-Debian FHS host the apt/dpkg databases simply do
        // not exist, so the scan finds nothing to compare and reports nothing.
        vec![Box::new(DebianPackageDriftScanner)]
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
    fn reports_fhs_mount_hooks_and_read_only_usr() {
        let platform = FhsPlatform;
        let policy = <FhsPlatform as Platform<MockFilesystem>>::overlay_policy(&platform);
        assert_eq!(policy.mount_hooks, crate::platform::MountHooks::Fhs);
        assert!(policy.read_only.contains(&std::path::PathBuf::from("/usr")));
    }
}
