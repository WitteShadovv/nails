// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The refusal backend.
//!
//! Chosen for ostree / image-based hosts and for hosts whose PID 1 is not
//! systemd. Its operations decline with a typed
//! [`NailsError::UnsupportedPlatform`](crate::NailsError::UnsupportedPlatform)
//! carrying the detector's actionable reason. The refusal is the deliverable for
//! these hosts, not an error path to work around.

use super::{OverlayPolicy, Platform, PlatformKind, RestoreOutcome};
use crate::filesystem::Filesystem;
use crate::process::ProcessRunner;
use crate::{NailsError, Result};

/// Backend for hosts NAILS refuses.
#[derive(Debug, Clone)]
pub struct UnsupportedPlatform {
    reason: String,
}

impl UnsupportedPlatform {
    /// Create a refusing backend with the detector's reason.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    fn refuse<T>(&self) -> Result<T> {
        Err(NailsError::UnsupportedPlatform {
            reason: self.reason.clone(),
        })
    }
}

impl<F: Filesystem> Platform<F> for UnsupportedPlatform {
    fn kind(&self) -> PlatformKind {
        PlatformKind::Unsupported
    }

    fn overlay_policy(&self) -> OverlayPolicy {
        OverlayPolicy::none()
    }

    fn host_command_dirs(&self) -> &'static [&'static str] {
        &[]
    }

    fn restore_base_system(
        &self,
        _fs: &F,
        _runner: &dyn ProcessRunner,
        _reboot_follows: bool,
        _dispatch_reboot: &dyn Fn() -> Result<()>,
    ) -> Result<RestoreOutcome> {
        self.refuse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use crate::process::run::MockProcessRunner;

    #[test]
    fn restore_refuses_with_typed_error() {
        let fs = MockFilesystem::new();
        let runner = MockProcessRunner::new();
        let platform = UnsupportedPlatform::new("this host is ostree / image-based");

        let result = Platform::restore_base_system(&platform, &fs, &runner, true, &|| Ok(()));
        match result {
            Err(NailsError::UnsupportedPlatform { reason }) => {
                assert!(reason.contains("ostree"));
            }
            other => panic!("expected an UnsupportedPlatform refusal, got {other:?}"),
        }
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn reports_no_overlay_policy() {
        let platform = UnsupportedPlatform::new("nope");
        let policy = <UnsupportedPlatform as Platform<MockFilesystem>>::overlay_policy(&platform);
        assert_eq!(policy.mount_hooks, crate::platform::MountHooks::None);
        assert!(policy.read_only.is_empty());
        assert!(policy.default_exclusions.is_empty());
    }
}
