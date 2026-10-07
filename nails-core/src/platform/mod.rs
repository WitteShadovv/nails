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
//! implements the [`Platform`] trait, which collects every decision that used to
//! be scattered across the CLI, the manager, the mount loop and the pre-flight
//! checks:
//!
//! - [`Platform::overlay_policy`] — the trees this host overlays, never overlays
//!   or keeps read-only, plus which mount hooks the loop runs (the NixOS
//!   `/nix` + `/var` + `/etc` handling, a plain FHS overlay, or nothing).
//! - [`Platform::host_command_dirs`] — where host tools are found.
//! - [`Platform::discover_build_target`] — which declarative build target
//!   activation, `check`/`--dry-run` and the build-target pre-flight check use.
//! - [`Platform::restore_base_system`] — the decoy-restore step on deactivation.
//!
//! ## Backends
//!
//! - [`NixOsPlatform`] carries the current, first-class NixOS behaviour.
//! - [`FhsPlatform`] is the overlay-only backend for systemd FHS hosts; its
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
use crate::process::ProcessRunner;

mod config_layer;
mod debian;
mod detect;
mod discover;
mod fhs;
pub mod host_commands;
pub(crate) mod nix_foreign;
mod nixos;
mod process_classes;
pub mod ro_guard;
mod scanners;
pub mod service_manager;
mod unsupported;

#[cfg(any(test, feature = "test-support"))]
mod fake;
#[cfg(any(test, feature = "test-support"))]
mod fake_layer;

#[cfg(test)]
mod contract;

pub use config_layer::{ConfigLayer, ConfigPlan, NixOsConfigLayer};
pub use detect::detect;
pub use discover::{HostTarget, discover_host_target, discover_with_platform};
pub use fhs::FhsPlatform;
pub use host_commands::HostCommands;
pub use nixos::NixOsPlatform;
pub(crate) use process_classes::host_process_classes;
pub use ro_guard::{MountHooks, OverlayPolicy, guard_read_only_trees};
pub use scanners::{
    ArtifactScan, ArtifactScanner, DebianPackageDriftScanner, NixOsStateNoteScanner,
    PACKAGE_BASELINE_DIR,
};
pub use service_manager::{ServiceManager, SessionManager, SystemdControl};
pub use unsupported::UnsupportedPlatform;

/// The single literal for the NixOS system-profile binary directory, and the
/// NixOS host-command search list built from it. Re-exported so the process
/// runner and the manager's runtime-command cache reference them instead of
/// re-spelling the store path.
pub(crate) use nixos::NIXOS_SYSTEM_PROFILE_BIN;

#[cfg(any(test, feature = "test-support"))]
pub use fake::FakePlatform;
#[cfg(any(test, feature = "test-support"))]
pub use fake_layer::{
    FAKE_BASE_REFERENCE_CHECK, FAKE_CONFIG_CHECK, FakeConfigLayer, FakeVerdict, LayerCall,
};

/// The display-manager service units probed by default, in order, after the
/// generic `display-manager.service` alias. A backend overrides
/// [`Platform::display_manager_units`] to adjust this (Debian adds `gdm3`).
pub(crate) const DEFAULT_DISPLAY_MANAGER_UNITS: &[&str] =
    &["gdm", "sddm", "lightdm", "greetd", "ly"];

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

/// How the `/nix` runtime must be handled while `/nix` is overlaid, resolved from
/// the host rather than from the target name.
///
/// Overlaying `/nix` requires nix-daemon to be stopped first (so it does not keep
/// the pre-overlay store busy or serve from it) and restarted afterwards. *How
/// much more* than that is needed depends on the host:
///
/// - On a real NixOS host the overlay hides the boot-time read-only `/nix/store`
///   bind and the `/run/current-system` generation, so both must be restored —
///   the full security-model restoration.
/// - On a non-NixOS host that merely has Nix installed (Nix on Debian/Ubuntu),
///   none of that applies: there is no `/run/current-system` to re-point and no
///   boot-time store bind to recreate, so only the daemon is cycled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NixRuntime {
    /// A real NixOS host: cycle the daemon *and* restore the `/nix/store` bind and
    /// `/run/current-system` symlink after the overlay.
    Native,
    /// Nix installed on a non-NixOS host: only stop and start nix-daemon.
    Foreign,
    /// `/nix` is not a target, or the host runs no nix machinery: nothing to do.
    None,
}

/// What [`Platform::restore_base_system`] did to return the host to the decoy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// The platform has no base-system restore step (FHS / overlay-only).
    NotRequired,
    /// The live `/run/current-system` symlink was re-pointed at the decoy
    /// generation and nothing else was run, because a reboot follows and will
    /// finalise the decoy from the bootloader default. No
    /// `switch-to-configuration` was invoked, so the ESP, bootloader and EFI
    /// NVRAM are untouched.
    SymlinkRestored,
    /// A reboot was requested but failed, so the decoy generation was activated
    /// for the running session with `switch-to-configuration test` as a
    /// fallback. `test` never reinstalls the bootloader or writes the ESP/NVRAM.
    FellBackToSessionSwitch,
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
}

impl HostProfile {
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

    /// The overlay policy for this host: which trees are overlaid, never
    /// overlaid, or kept read-only, and which distro-specific mount hooks run.
    fn overlay_policy(&self) -> OverlayPolicy;

    /// How the `/nix` runtime must be handled while a hidden session is active,
    /// given whether `/nix` is among the overlay targets.
    ///
    /// Resolved from the host's mount hooks, not from the target name: a NixOS
    /// host does the full security-model restoration, a non-NixOS host that
    /// happens to have `/nix` overlaid only cycles nix-daemon, and when `/nix` is
    /// not a target there is nothing to do. The default covers every backend from
    /// its [`overlay_policy`](Self::overlay_policy), so a backend only overrides it
    /// to special-case a degraded host.
    fn nix_runtime(&self, nix_is_target: bool) -> NixRuntime {
        if !nix_is_target {
            return NixRuntime::None;
        }
        match self.overlay_policy().mount_hooks {
            MountHooks::NixOs => NixRuntime::Native,
            // A non-NixOS host with /nix overlaid (Nix on Debian/Ubuntu), and the
            // refused/undetected case: in both, only the daemon is cycled — the
            // NixOS-only store bind and current-system restore must never run.
            MountHooks::Fhs | MountHooks::None => NixRuntime::Foreign,
        }
    }

    /// Directories searched, in order, for host tools on this platform.
    fn host_command_dirs(&self) -> &'static [&'static str];

    /// Display-manager service units probed, in order, when the generic
    /// `display-manager.service` alias is not active.
    ///
    /// The alias is always tried first by the session layer; this list is the
    /// fallback for hosts that do not ship it. Keeping it platform data lets a
    /// backend name the units its distribution actually uses — Debian/Ubuntu
    /// ships GDM as `gdm3`, not `gdm` — instead of a single hard-coded array in
    /// the session code. The default covers the common systemd display managers.
    fn display_manager_units(&self) -> &'static [&'static str] {
        DEFAULT_DISPLAY_MANAGER_UNITS
    }

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

    /// The read-only drift scanners this platform contributes to `verify`.
    ///
    /// A generic artifact-path check only finds the files NAILS writes; it
    /// cannot tell that a hidden session changed the host's package set, because
    /// the package manager's databases are not NAILS files. Each backend returns
    /// the scanners that cover its own system state (see [`ArtifactScanner`]).
    /// The default is none, so a platform only lights up the scans it actually
    /// has.
    fn artifact_scanners(&self) -> Vec<Box<dyn ArtifactScanner<F>>>
    where
        F: 'static,
    {
        Vec::new()
    }

    /// Restore the base (decoy) system during deactivation.
    ///
    /// `reboot_follows` says whether the caller will reboot after this returns;
    /// `dispatch_reboot` performs that reboot (passed in so the decision is
    /// testable without dispatching a real one). A backend that has no base
    /// system to restore returns [`RestoreOutcome::NotRequired`] without
    /// touching `runner` or `dispatch_reboot`.
    fn restore_base_system(
        &self,
        fs: &F,
        runner: &dyn ProcessRunner,
        reboot_follows: bool,
        dispatch_reboot: &dyn Fn() -> Result<()>,
        env: &crate::RuntimeEnv,
    ) -> Result<RestoreOutcome> {
        let _ = (fs, runner, reboot_follows, dispatch_reboot, env);
        Ok(RestoreOutcome::NotRequired)
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
