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
        OverlayPolicy::None
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
        assert_eq!(
            <UnsupportedPlatform as Platform<MockFilesystem>>::overlay_policy(&platform),
            OverlayPolicy::None
        );
    }
}
