// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for the install and upgrade hints, family by family.

use super::*;
use crate::filesystem::MockFilesystem;

/// The host detection finds for `os_release` on a systemd machine.
fn host(os_release: &str) -> HostProfile {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/os-release", os_release);
    fs.mock_add_file("/proc/1/comm", "systemd");
    crate::platform::detect(&fs).expect("detection reads through the mock")
}

/// The upgrade hint for a host whose os-release is `os_release`.
fn hint_for(os_release: &str) -> String {
    upgrade_hint(Some(&host(os_release)))
}

/// The hint for a host whose own upgrade NAILS cannot name.
const SUPPORTED: &str =
    "Use a current NixOS or a release NAILS supports (Debian 13, Ubuntu 24.04 and 26.04).";

// --- The install hint ----------------------------------------------------

#[test]
fn the_install_hint_names_each_family_s_package_manager() {
    let ip = Package {
        debian: "iproute2",
        fedora: "iproute",
        arch: "iproute2",
        nixos: "iproute2",
    };
    for (family, expected) in [
        (Some(Family::Debian), "apt install iproute2"),
        (Some(Family::Fedora), "dnf install iproute"),
        (Some(Family::Arch), "pacman -S iproute2"),
        (None, "install the iproute2 package"),
    ] {
        assert_eq!(
            install_hint(PlatformKind::Fhs, family, ip),
            expected,
            "{family:?}"
        );
    }
}

#[test]
fn on_nixos_the_package_goes_into_the_decoy_configuration() {
    let dmsetup = Package {
        debian: "dmsetup",
        fedora: "device-mapper",
        arch: "device-mapper",
        nixos: "lvm2",
    };
    assert_eq!(
        install_hint(PlatformKind::NixOs, None, dmsetup),
        "add lvm2 to the decoy's environment.systemPackages"
    );
}

#[test]
fn a_package_of_one_name_has_that_name_on_every_family() {
    assert_eq!(
        Package::everywhere("systemd"),
        Package {
            debian: "systemd",
            fedora: "systemd",
            arch: "systemd",
            nixos: "systemd",
        }
    );
}

// --- The upgrade hint, per family ----------------------------------------

#[test]
fn debian_upgrades_as_its_release_notes_describe() {
    assert_eq!(
        hint_for("ID=debian\nVERSION_ID=\"12\"\n"),
        "Upgrade to Debian 13 as its release notes describe, then reboot."
    );
}

#[test]
fn ubuntu_upgrades_with_do_release_upgrade() {
    assert_eq!(
        hint_for("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"22.04\"\n"),
        "Upgrade to Ubuntu 24.04 or 26.04 with `do-release-upgrade`, then reboot."
    );
}

#[test]
fn fedora_upgrades_with_dnf_system_upgrade() {
    assert_eq!(
        hint_for("ID=fedora\nVERSION_ID=38\n"),
        "Upgrade to Fedora 44 with `dnf system-upgrade`, at most two releases at a time."
    );
}

#[test]
fn a_fedora_derivative_upgrades_its_own_way_to_a_release_built_on_fedora() {
    // Nobara warns against `dnf system-upgrade`; Ultramarine documents it.
    assert_eq!(
        hint_for("ID=nobara\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=38\n"),
        "Upgrade to a release built on Fedora 44 as Nobara's upgrade guide describes, then reboot."
    );
    assert_eq!(
        hint_for("ID=ultramarine\nID_LIKE=fedora\nVERSION_ID=38\n"),
        "Upgrade to a release built on Fedora 44 with `dnf system-upgrade`."
    );
}

#[test]
fn arch_and_its_derivatives_update_the_whole_system() {
    // A partial upgrade is unsupported on each of them, so the hint is the
    // full `pacman -Syu`, never `pacman -S systemd` alone.
    for os_release in [
        "ID=arch\nBUILD_ID=rolling\n",
        "ID=endeavouros\nID_LIKE=arch\n",
        "ID=cachyos\nID_LIKE=arch\n",
        "ID=manjaro\nID_LIKE=arch\n",
    ] {
        assert_eq!(
            hint_for(os_release),
            "Update the whole system with `pacman -Syu`, then reboot.",
            "{os_release}"
        );
    }
}

#[test]
fn nixos_moves_the_decoy_to_a_current_release() {
    assert_eq!(
        hint_for("ID=nixos\nVERSION_ID=\"23.05\"\n"),
        "Move the decoy's nixpkgs (its channel or flake input) to a current NixOS release, \
         rebuild it with `nixos-rebuild boot`, and reboot."
    );
}

#[test]
fn an_unlisted_debian_derivative_upgrades_to_a_release_built_on_a_tested_one() {
    assert_eq!(
        hint_for("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_ID=\"21.3\"\n"),
        "Upgrade to a release built on Debian 13, Ubuntu 24.04 or 26.04 as your \
         distribution's upgrade guide describes, then reboot."
    );
}

#[test]
fn a_host_it_cannot_advise_on_is_pointed_at_the_platforms_nails_runs_on() {
    assert_eq!(upgrade_hint(None), SUPPORTED);
    for os_release in [
        // An unknown distribution, one refused by name, one like a family NAILS
        // has not validated, and a host that declares no ID.
        "ID=gentoo\n",
        "ID=rhel\nVERSION_ID=\"9.4\"\n",
        "ID=risios\nID_LIKE=fedora\n",
        "VERSION_ID=1\n",
    ] {
        assert_eq!(hint_for(os_release), SUPPORTED, "{os_release}");
    }
}

#[test]
fn a_rolling_family_has_no_release_to_build_on() {
    assert_eq!(built_on(Family::Arch), None);
    assert_eq!(
        built_on(Family::Fedora).as_deref(),
        Some("a release built on Fedora 44")
    );
}

#[test]
fn a_release_upgrade_without_a_release_to_name_falls_back_to_the_platforms() {
    // A base row upgrades to its own tested releases; a rolling one has none,
    // so the hint must not end up as "Upgrade to  ...".
    let row = FamilyRow {
        id: "rolling",
        label: "Rolling",
        family: Family::Arch,
        gate: Gate::Rolling,
        kind: Kind::Base,
        admitted: false,
        upgrade: Upgrade::Release("as its guide describes"),
    };
    assert_eq!(row_hint(&row), SUPPORTED);
}

// --- Table consistency ---------------------------------------------------

#[test]
fn every_row_names_an_upgrade_of_its_own() {
    for row in TABLE {
        if let Upgrade::Release(_) = row.upgrade {
            assert!(target(row).is_some(), "{} names no release", row.id);
        }
        assert_ne!(row_hint(row), SUPPORTED, "{}", row.id);
    }
}

#[test]
fn the_releases_named_follow_the_tested_releases_in_the_table() {
    for row in TABLE {
        if let (Kind::Base, Gate::Versioned { validated, .. }) = (row.kind, row.gate) {
            let named = format!("{} {}", row.label, either(validated));
            let hint = row_hint(row);
            assert!(hint.contains(&named), "{}: {hint}", row.id);
        }
    }
}
