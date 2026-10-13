// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! One contract every [`Platform`] backend must satisfy.
//!
//! Each backend runs the same assertions so a new backend cannot quietly skip an
//! invariant: only a refused host has no host-command directories, only NixOS
//! has a config layer, and discovery agrees with the layer.

use super::{
    FakePlatform, FhsPlatform, HostTarget, NixOsPlatform, Platform, PlatformKind,
    UnsupportedPlatform, discover_with_platform,
};
use crate::filesystem::{Filesystem, MockFilesystem, PathKind};

/// Assert the invariants that hold for every backend.
fn assert_contract<F: Filesystem + 'static, P: Platform<F>>(platform: &P, fs: &F) {
    let kind = platform.kind();

    // Only a refused host offers no host-command directories.
    assert_eq!(
        platform.host_command_dirs().is_empty(),
        kind == PlatformKind::Unsupported,
    );

    // Only NixOS carries a declarative config layer; FHS and refused hosts have
    // none, so "overlay-only" is "no layer" rather than a parallel code path.
    assert_eq!(
        platform.config_layer().is_some(),
        kind == PlatformKind::NixOs,
    );

    // Only a backend with a config layer auto-discovers a build target; the
    // others answer `None` even with NixOS files present. An explicit flake is
    // reported as given and `--overlay-only` short-circuits, on every backend.
    let hidden_root = std::path::Path::new("/mnt/hidden");
    let discovered = platform
        .discover_build_target(fs, hidden_root)
        .expect("discovery never fails on a mock host");
    if platform.config_layer().is_none() {
        assert_eq!(discovered, HostTarget::None);
    }
    assert_eq!(
        discover_with_platform(platform, fs, hidden_root, Some("gh:me/cfg"), false).unwrap(),
        HostTarget::ExplicitFlake("gh:me/cfg".to_string()),
    );
    assert_eq!(
        discover_with_platform(platform, fs, hidden_root, Some("gh:me/cfg"), true).unwrap(),
        HostTarget::OverlayOnly,
    );
}

/// A mock NixOS host with a decoy system profile, so the symlink restore works.
fn nixos_host() -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/nix/var/nix/profiles/system", PathKind::Dir);
    fs
}

/// A host carrying every NixOS discovery location, so a backend without a
/// config layer is shown to ignore them rather than merely finding nothing.
fn host_with_nixos_files() -> MockFilesystem {
    super::nixos::tests_support::full_nixos_host()
}

#[test]
fn nixos_backend_honours_contract() {
    assert_contract(&NixOsPlatform, &nixos_host());
}

#[test]
fn fhs_backend_honours_contract() {
    assert_contract(&FhsPlatform, &host_with_nixos_files());
}

#[test]
fn fake_backend_honours_contract() {
    assert_contract(&FakePlatform::nixos(), &MockFilesystem::new());
    assert_contract(&FakePlatform::fhs(), &host_with_nixos_files());
}

#[test]
fn unsupported_backend_honours_contract() {
    assert_contract(
        &UnsupportedPlatform::new("this host is not supported"),
        &host_with_nixos_files(),
    );
}
