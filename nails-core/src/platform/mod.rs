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
//! - [`Platform::overlay_policy`] — whether the mount loop applies the NixOS
//!   `/nix` + `/var` + `/etc` handling, a plain FHS overlay, or nothing.
//! - [`Platform::host_command_dirs`] — where host tools are found.
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
//! The call sites that still carry their own NixOS discovery cascades
//! (`activate`, `--dry-run` via `check`, and the `nixos-build-target` pre-flight
//! check) are rewired onto [`discover_host_target`] in their owning chunks; this
//! module provides the one discovery result they will share.

use crate::Result;
use crate::filesystem::Filesystem;
use crate::process::ProcessRunner;

mod detect;
mod discover;
mod fhs;
mod nixos;
mod unsupported;

#[cfg(any(test, feature = "test-support"))]
mod fake;

#[cfg(test)]
mod contract;

pub use detect::detect;
pub use discover::{HostTarget, discover_host_target};
pub use fhs::FhsPlatform;
pub use nixos::NixOsPlatform;
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

/// How the overlay mount loop should treat this host.
///
/// Informational for now: the mount loop is rewired onto it in the chunk that
/// owns the overlay code. It records the decision so no other layer has to ask
/// "is this NixOS?" again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayPolicy {
    /// Overlay directories plus the NixOS-specific `/nix`, `/var` and `/etc`
    /// handling (pivot/bind mounts, service stop/start around `/nix`).
    NixOs,
    /// Overlay directories with no distro-specific mount hooks.
    Fhs,
    /// No overlays: the host is refused.
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

    /// How the overlay mount loop should treat this host.
    fn overlay_policy(&self) -> OverlayPolicy;

    /// Directories searched, in order, for host tools on this platform.
    fn host_command_dirs(&self) -> &'static [&'static str];

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
    ) -> Result<RestoreOutcome> {
        let _ = (fs, runner, reboot_follows, dispatch_reboot);
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
