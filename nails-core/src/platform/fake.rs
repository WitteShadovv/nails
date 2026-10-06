// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A configurable [`Platform`] for core tests.
//!
//! Lets a test pin a platform's kind, overlay policy and restore outcome without
//! standing up os-release fixtures or a real backend, so manager, overlay and
//! state tests can run against a platform directly. Its build target is pinned
//! too ([`FakePlatform::with_build_target`]), so callers of discovery need no
//! `/etc/nixos` fixtures.

use std::path::Path;

use super::{
    ConfigLayer, HostProfile, HostTarget, NixOsConfigLayer, OverlayPolicy, Platform, PlatformKind,
    RestoreOutcome,
};
use crate::Result;
use crate::filesystem::Filesystem;
use crate::process::ProcessRunner;

/// A platform whose answers are fixed by the test.
#[derive(Debug, Clone)]
pub struct FakePlatform {
    kind: PlatformKind,
    restore_outcome: RestoreOutcome,
    has_config_layer: bool,
    build_target: HostTarget,
}

impl Default for FakePlatform {
    fn default() -> Self {
        Self {
            kind: PlatformKind::Fhs,
            restore_outcome: RestoreOutcome::NotRequired,
            has_config_layer: false,
            build_target: HostTarget::None,
        }
    }
}

impl FakePlatform {
    /// A fake with the given kind and matching defaults.
    pub fn new(kind: PlatformKind) -> Self {
        Self {
            kind,
            restore_outcome: RestoreOutcome::NotRequired,
            // Only NixOS carries a declarative config layer by default.
            has_config_layer: kind == PlatformKind::NixOs,
            build_target: HostTarget::None,
        }
    }

    /// A fake standing in for a NixOS host.
    pub fn nixos() -> Self {
        Self::new(PlatformKind::NixOs)
    }

    /// A fake standing in for an FHS host.
    pub fn fhs() -> Self {
        Self::new(PlatformKind::Fhs)
    }

    /// Override the restore outcome returned by
    /// [`Platform::restore_base_system`].
    pub fn with_restore_outcome(mut self, outcome: RestoreOutcome) -> Self {
        self.restore_outcome = outcome;
        self
    }

    /// Override whether the fake reports a declarative config layer.
    pub fn with_config_layer(mut self, has_config_layer: bool) -> Self {
        self.has_config_layer = has_config_layer;
        self
    }

    /// Pin the build target [`Platform::discover_build_target`] auto-discovers.
    /// Ignored (the answer is [`HostTarget::None`]) when the fake has no config
    /// layer, matching the real backends.
    pub fn with_build_target(mut self, target: HostTarget) -> Self {
        self.build_target = target;
        self
    }

    /// The [`HostProfile`] a host of this fake's kind would detect.
    ///
    /// Lets a test hand the manager (or a discovery call) a profile coherent with
    /// the fake instead of spelling out every os-release field.
    pub fn host_profile(&self) -> HostProfile {
        let (id, unsupported_reason) = match self.kind {
            PlatformKind::NixOs => (Some("nixos"), None),
            PlatformKind::Fhs => (Some("debian"), None),
            PlatformKind::Unsupported => (None, Some("unsupported test host".to_string())),
        };
        HostProfile {
            kind: self.kind,
            id: id.map(str::to_string),
            id_like: Vec::new(),
            version_id: None,
            is_systemd: true,
            is_ostree: false,
            has_current_system: self.kind == PlatformKind::NixOs,
            unsupported_reason,
        }
    }
}

impl<F: Filesystem> Platform<F> for FakePlatform {
    fn kind(&self) -> PlatformKind {
        self.kind
    }

    fn overlay_policy(&self) -> OverlayPolicy {
        match self.kind {
            PlatformKind::NixOs => OverlayPolicy::nixos(),
            PlatformKind::Fhs => OverlayPolicy::fhs(),
            PlatformKind::Unsupported => OverlayPolicy::none(),
        }
    }

    fn host_command_dirs(&self) -> &'static [&'static str] {
        &["/usr/bin", "/bin"]
    }

    fn config_layer(&self) -> Option<Box<dyn ConfigLayer<F>>>
    where
        F: 'static,
    {
        self.has_config_layer
            .then(|| Box::new(NixOsConfigLayer) as Box<dyn ConfigLayer<F>>)
    }

    fn discover_build_target(&self, _fs: &F, _hidden_volume_root: &Path) -> Result<HostTarget> {
        Ok(if self.has_config_layer {
            self.build_target.clone()
        } else {
            HostTarget::None
        })
    }

    fn restore_base_system(
        &self,
        _fs: &F,
        _runner: &dyn ProcessRunner,
        _reboot_follows: bool,
        _dispatch_reboot: &dyn Fn() -> Result<()>,
    ) -> Result<RestoreOutcome> {
        Ok(self.restore_outcome)
    }
}
