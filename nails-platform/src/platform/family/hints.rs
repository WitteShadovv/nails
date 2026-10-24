// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the pre-flight checks tell the operator to do on the detected host:
//! how to install the package that provides a missing tool (`host-tools`), and
//! how to reach a release whose systemd supports soft-reboot
//! (`systemd-version`).
//!
//! Both hints are built here, from the family table, so they place a host in
//! the same family: each row of the table carries how its hosts upgrade, and
//! the package manager each family installs with sits beside it. Every command
//! is the one the distribution's own documentation gives; where it documents
//! no single command, the hint names its guide instead.

use super::{FamilyRow, Gate, Kind, TABLE, Upgrade, either, supported_platforms};
use crate::platform::{HostProfile, PlatformKind};
use nails_base::Family;

/// The package that provides a tool on each family, where the names can
/// differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Package {
    /// The Debian and Ubuntu package, also named on a host of unknown family.
    pub debian: &'static str,
    /// The Fedora package.
    pub fedora: &'static str,
    /// The Arch package.
    pub arch: &'static str,
    /// The nixpkgs package, for a NixOS host.
    pub nixos: &'static str,
}

impl Package {
    /// A package of the same name on every family.
    pub const fn everywhere(name: &'static str) -> Self {
        Self {
            debian: name,
            fedora: name,
            arch: name,
            nixos: name,
        }
    }
}

/// How to install `package` on a host of `kind` and `family`, named for the
/// family's package manager. On NixOS the package goes into the decoy's
/// configuration: the tools NAILS runs there are the decoy's.
pub fn install_hint(kind: PlatformKind, family: Option<Family>, package: Package) -> String {
    if kind == PlatformKind::NixOs {
        return format!(
            "add {} to the decoy's environment.systemPackages",
            package.nixos
        );
    }
    match family {
        Some(Family::Debian) => format!("apt install {}", package.debian),
        Some(Family::Fedora) => format!("dnf install {}", package.fedora),
        Some(Family::Arch) => format!("pacman -S {}", package.arch),
        None => format!("install the {} package", package.debian),
    }
}

/// How a NixOS decoy reaches a newer systemd: the release of its nixpkgs, set
/// by a channel or a flake input, decides it, and PID 1 runs the new one once
/// the rebuilt system is booted.
const NIXOS_UPGRADE: &str = "Move the decoy's nixpkgs (its channel or flake input) to a current \
     NixOS release, rebuild it with `nixos-rebuild boot`, and reboot.";

/// How a derivative the table does not list upgrades: NAILS knows its base
/// family, not its tools.
const DERIVATIVE_UPGRADE: &str = "as your distribution's upgrade guide describes, then reboot";

/// How the detected `host` reaches a release whose systemd supports
/// soft-reboot, the way its distribution documents it.
///
/// - NixOS moves the decoy to a current release.
/// - A distribution the table lists follows its row: an upgrade to its tested
///   releases, or for a derivative to a release built on those of its base
///   family, or a full update of a rolling system.
/// - A derivative NAILS runs on without listing it upgrades to a release built
///   on one its base family is tested on.
/// - Any other host, and a run without a detected host, is pointed at the
///   platforms NAILS runs on.
pub fn upgrade_hint(host: Option<&HostProfile>) -> String {
    let Some(host) = host else {
        return supported_hint();
    };
    if host.kind == PlatformKind::NixOs {
        return NIXOS_UPGRADE.to_string();
    }
    if let Some(row) = TABLE.iter().find(|row| host.id.as_deref() == Some(row.id)) {
        return row_hint(row);
    }
    let derivative = host
        .family
        .filter(|_| host.kind == PlatformKind::Fhs)
        .and_then(built_on);
    match derivative {
        Some(target) => format!("Upgrade to {target} {DERIVATIVE_UPGRADE}."),
        None => supported_hint(),
    }
}

/// The upgrade a host of `row` makes.
fn row_hint(row: &FamilyRow) -> String {
    match row.upgrade {
        Upgrade::Rolling(how) => format!("Update the whole system {how}."),
        Upgrade::Release(how) => match target(row) {
            Some(target) => format!("Upgrade to {target} {how}."),
            None => supported_hint(),
        },
    }
}

/// The releases a host of `row` upgrades to: a base row's own tested releases
/// (`Ubuntu 24.04 or 26.04`), or for a derivative, a release built on those of
/// its base family.
fn target(row: &FamilyRow) -> Option<String> {
    match row.kind {
        Kind::Base => tested(row),
        Kind::Derivative => built_on(row.family),
    }
}

/// A versioned row's tested releases as alternatives (`Ubuntu 24.04 or
/// 26.04`), or `None` for a rolling row, which has no release to name.
fn tested(row: &FamilyRow) -> Option<String> {
    match row.gate {
        Gate::Versioned { validated, .. } => Some(format!("{} {}", row.label, either(validated))),
        Gate::Rolling => None,
    }
}

/// `a release built on Debian 13, Ubuntu 24.04 or 26.04`: the tested releases
/// of `family`'s base rows, or `None` when none of them has a release.
fn built_on(family: Family) -> Option<String> {
    let bases: Vec<String> = TABLE
        .iter()
        .filter(|row| row.kind == Kind::Base && row.family == family)
        .filter_map(tested)
        .collect();
    (!bases.is_empty()).then(|| format!("a release built on {}", bases.join(", ")))
}

/// The hint for a host whose own upgrade NAILS cannot name: the platforms it
/// runs on.
fn supported_hint() -> String {
    format!(
        "Use a current NixOS or a release NAILS supports ({}).",
        supported_platforms()
    )
}

#[cfg(test)]
#[path = "hints_tests.rs"]
mod tests;
