// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The refusal backend.
//!
//! Chosen for ostree / image-based hosts and for hosts whose PID 1 is not
//! systemd. It offers no host tools, no config layer and no build target; the
//! detector's reason reaches the operator through
//! [`HostProfile::require_supported`](super::HostProfile::require_supported).

use super::{Platform, PlatformKind};
use crate::filesystem::Filesystem;

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

    /// Why this host is refused.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl<F: Filesystem> Platform<F> for UnsupportedPlatform {
    fn kind(&self) -> PlatformKind {
        PlatformKind::Unsupported
    }

    fn host_command_dirs(&self) -> &'static [&'static str] {
        &[]
    }
}
