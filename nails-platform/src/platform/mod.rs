// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # Platform seam
//!
//! A single place where host-specific decisions are made, so the rest of the
//! codebase never branches on "is this NixOS?" directly.
//!
//! Host facts are gathered once by [`detect`] into a [`HostProfile`] (reading
//! `/etc/os-release`, `/run/current-system`, `/run/ostree-booted` and PID 1),
//! and the matching backend is chosen once by [`platform_for`]. Each backend
//! implements the [`Platform`] trait, which collects the decisions the CLI, the
//! manager and the pre-flight checks need:
//!
//! - [`Platform::host_command_dirs`] — where host tools are found.
//! - [`Platform::config_layer`] — the host's declarative configuration layer
//!   (the hidden NixOS configuration), if it has one.
//! - [`Platform::discover_build_target`] — which declarative build target
//!   activation, `check`/`--dry-run` and the build-target pre-flight check use.
//!
//! ## Backends
//!
//! - [`NixOsPlatform`] carries the current, first-class NixOS behaviour.
//! - [`FhsPlatform`] is the backend for systemd FHS hosts (no hidden build); its
//!   first validated target is Debian/Ubuntu, with other FHS families treated as
//!   provisional until they get their own specialisation.
//! - [`UnsupportedPlatform`] refuses ostree / image-based hosts and non-systemd
//!   PID 1 with a typed [`NailsError::UnsupportedPlatform`]. That refusal is the
//!   deliverable for those hosts.
//!
//! Build-target discovery is a backend question: [`discover_host_target`] picks
//! the backend from the detected [`HostProfile`] and asks it, so activation,
//! `--dry-run`/`check` and the `nixos-build-target` pre-flight check share one
//! result, and core tests pin it with [`FakePlatform`] instead of staging
//! `/etc/nixos` fixtures.

use crate::Result;
use crate::filesystem::Filesystem;

mod config_layer;
mod debian;
mod detect;
mod discover;
mod fhs;
mod nixos;
mod unsupported;

#[cfg(any(test, feature = "test-support"))]
mod fake;

#[cfg(test)]
mod contract;

pub use crate::process::host_commands::{self, HostCommands};
pub use config_layer::{ConfigLayer, NixOsConfigLayer};
pub use detect::detect;
pub use discover::{HostTarget, discover_host_target, discover_with_platform};
pub use fhs::FhsPlatform;
pub use nixos::{HiddenFlake, NixOsPlatform, hidden_flake};
pub use unsupported::UnsupportedPlatform;

#[cfg(any(test, feature = "test-support"))]
pub use fake::FakePlatform;

/// Which family of host NAILS resolved, and therefore which backend runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformKind {
    /// A NixOS host (immutable system generations, `/run/current-system`).
    NixOs,
    /// A systemd host laid out on the Filesystem Hierarchy Standard
    /// (Debian/Ubuntu and, provisionally, other FHS distributions).
    Fhs,
    /// A host NAILS refuses: ostree / image-based, or non-systemd PID 1.
    Unsupported,
}

/// Facts about the running host, gathered once and shared.
///
/// Built by [`detect`]. [`platform_for`] turns it into a backend; the retained
/// `id`/`id_like`/`version_id` let later, distro-specific code specialise
/// without re-reading `/etc/os-release`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProfile {
    /// Resolved family, and therefore which backend runs.
    pub kind: PlatformKind,
    /// `ID` from `/etc/os-release` (e.g. `nixos`, `debian`, `ubuntu`), lowercased.
    pub id: Option<String>,
    /// `ID_LIKE` tokens from `/etc/os-release`, lowercased (e.g. `debian`).
    pub id_like: Vec<String>,
    /// `VERSION_ID` from `/etc/os-release` (e.g. `12`, `24.04`), unquoted.
    pub version_id: Option<String>,
    /// Whether PID 1 is systemd.
    pub is_systemd: bool,
    /// Whether `/run/ostree-booted` is present (ostree / image-based host).
    pub is_ostree: bool,
    /// Whether `/run/current-system` is present (a live NixOS generation).
    pub has_current_system: bool,
    /// When [`kind`](Self::kind) is [`PlatformKind::Unsupported`], why.
    pub unsupported_reason: Option<String>,
    /// When the host is admitted on a release NAILS has not been tested on (a
    /// Debian or Ubuntu release at or above the minimum that the support table
    /// does not list as tested), the warning that says so.
    pub support_warning: Option<String>,
}

impl HostProfile {
    /// The host as people name it, for messages: `NixOS 26.05`, `Ubuntu 24.04`,
    /// or the os-release `ID` and `VERSION_ID` of another host (`linuxmint 22`).
    pub fn name(&self) -> String {
        let distribution = match (self.kind, self.id.as_deref()) {
            (PlatformKind::NixOs, _) => "NixOS",
            (_, Some(id)) => debian::label(id).unwrap_or(id),
            (_, None) => return "this host".to_string(),
        };
        match self.version_id.as_deref() {
            Some(version) => format!("{distribution} {version}"),
            None => distribution.to_string(),
        }
    }

    /// Return `Err(NailsError::UnsupportedPlatform)` when this host is one NAILS
    /// refuses, otherwise `Ok(())`.
    ///
    /// Call sites use this to decline early, before any state is written. The
    /// message is the detector's own actionable reason.
    pub fn require_supported(&self) -> Result<()> {
        if self.kind == PlatformKind::Unsupported {
            return Err(crate::NailsError::UnsupportedPlatform {
                reason: self
                    .unsupported_reason
                    .clone()
                    .unwrap_or_else(|| "this host is not supported by NAILS".to_string()),
            });
        }
        Ok(())
    }

    /// Whether the host declares itself part of the Debian family (its `ID` is
    /// `debian`/`ubuntu`, or `debian` appears in `ID_LIKE`).
    ///
    /// The generic [`FhsPlatform`] serves every FHS host today; this predicate
    /// lets the Debian-specific chunk light up without re-parsing os-release.
    pub fn is_debian_like(&self) -> bool {
        let id_is_debian = matches!(self.id.as_deref(), Some("debian") | Some("ubuntu"));
        id_is_debian || self.id_like.iter().any(|token| token == "debian")
    }

    /// Whether this host carries a declarative [`ConfigLayer`].
    ///
    /// Only NixOS does; FHS / `DebianFamily` and refused hosts have no
    /// `nixos-rebuild`, `switch-to-configuration` or `/run/current-system` to
    /// drive one. This is the fact [`Platform::config_layer`] turns into a backend
    /// object, exposed on the profile so the manager can take the same decision
    /// without constructing a backend.
    pub fn has_config_layer(&self) -> bool {
        self.kind == PlatformKind::NixOs
    }
}

/// Host-specific decisions, chosen once per run.
///
/// Generic over the [`Filesystem`] in use so the fs-touching hooks stay
/// object-safe (the [`Filesystem`] trait requires `Clone`, so it cannot be used
/// as `&dyn Filesystem`). The [`ProcessRunner`] is passed as `&dyn` so a backend
/// consumes the single process runner rather than creating its own.
pub trait Platform<F: Filesystem>: std::fmt::Debug + Send + Sync {
    /// Which family this backend serves.
    fn kind(&self) -> PlatformKind;

    /// Directories searched, in order, for host tools on this platform.
    fn host_command_dirs(&self) -> &'static [&'static str];

    /// The declarative hidden-config layer for this host, if it has one.
    ///
    /// Returns `Some` only on NixOS; FHS / `DebianFamily` and refused hosts have
    /// no `nixos-rebuild`, `switch-to-configuration` or `/run/current-system`, so
    /// they return `None` and the manager skips hidden-config staging,
    /// fingerprinting, the `/etc` import, the build and the switch entirely.
    /// "Overlay-only" is therefore "no layer", not a parallel code path.
    fn config_layer(&self) -> Option<Box<dyn ConfigLayer<F>>>
    where
        F: 'static,
    {
        None
    }

    /// The build target this host auto-discovers when no explicit flake is
    /// configured.
    ///
    /// Only a backend with a [`config_layer`](Self::config_layer) probes for
    /// one: the NixOS backend runs the single discovery cascade (hidden flake,
    /// `/etc/nixos` flake, legacy configuration or system profile). The default
    /// — FHS and refused hosts — is [`HostTarget::None`] without probing
    /// anything, so NixOS files present on such a host (Nix installed on Debian,
    /// a stray `/etc/nixos`) never select a build target. `--overlay-only` and an
    /// explicit flake reference are resolved by [`discover_with_platform`] before
    /// the backend is asked.
    fn discover_build_target(
        &self,
        fs: &F,
        hidden_volume_root: &std::path::Path,
    ) -> Result<HostTarget> {
        let _ = (fs, hidden_volume_root);
        Ok(HostTarget::None)
    }
}

/// Choose the backend for a detected host.
///
/// The returned trait object is the one decision point: every host-specific
/// branch elsewhere consults it instead of re-testing the host. An unsupported
/// host yields [`UnsupportedPlatform`], whose operations refuse with the typed
/// [`NailsError::UnsupportedPlatform`](crate::NailsError::UnsupportedPlatform).
pub fn platform_for<F: Filesystem>(profile: &HostProfile) -> Box<dyn Platform<F> + Send + Sync> {
    match profile.kind {
        PlatformKind::NixOs => Box::new(NixOsPlatform),
        PlatformKind::Fhs => Box::new(FhsPlatform),
        PlatformKind::Unsupported => Box::new(UnsupportedPlatform::new(
            profile
                .unsupported_reason
                .clone()
                .unwrap_or_else(|| "this host is not supported by NAILS".to_string()),
        )),
    }
}

/// Detect the host and choose its backend in one step.
///
/// Convenience for call sites that do not need the intermediate [`HostProfile`].
pub fn detect_platform<F: Filesystem>(fs: &F) -> Result<Box<dyn Platform<F> + Send + Sync>> {
    let profile = detect(fs)?;
    Ok(platform_for(&profile))
}
