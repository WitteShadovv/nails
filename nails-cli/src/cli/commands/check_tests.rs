// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the `check` command's helpers.
//!
//! Exit codes, the JSON envelope and parity with `activate --dry-run` are
//! covered end to end against the compiled binary in
//! `nails-cli/tests/cli_integration.rs`; these focus on the pure helpers.

use super::{profile_summary, session_summary};
use nails_core::platform::FakePlatform;
use nails_core::{Config, HostTarget, MockFilesystem, NailsManager};
use std::path::PathBuf;

#[test]
fn profile_summary_reports_overlay_only() {
    assert_eq!(
        profile_summary(HostTarget::OverlayOnly).mode,
        "overlay-only"
    );
}

#[test]
fn profile_summary_reports_an_explicit_flake() {
    let profile = profile_summary(HostTarget::ExplicitFlake("/cfg#host".into()));
    assert_eq!(profile.mode, "flake");
    assert!(profile.detail.unwrap().contains("/cfg#host"));
}

#[test]
fn profile_summary_reports_a_discovered_flake() {
    let profile = profile_summary(HostTarget::Flake(PathBuf::from("/mnt/vault/nixos")));
    assert_eq!(profile.mode, "flake");
    assert!(profile.detail.unwrap().contains("/mnt/vault/nixos"));
}

#[test]
fn profile_summary_reports_a_legacy_target() {
    let profile = profile_summary(HostTarget::Legacy(PathBuf::from("/cfg/configuration.nix")));
    assert_eq!(profile.mode, "legacy");
    assert!(profile.detail.unwrap().contains("/cfg/configuration.nix"));
}

#[test]
fn profile_summary_is_none_without_any_target() {
    let profile = profile_summary(HostTarget::None);
    assert_eq!(profile.mode, "none");
    assert!(profile.detail.is_none());
}

fn manager_on(fake: FakePlatform, nixos_flake: Option<&str>) -> NailsManager<MockFilesystem> {
    let config = Config {
        hidden_volume_root: PathBuf::from("/mnt/vault"),
        nixos_flake: nixos_flake.map(str::to_string),
        ..Config::default()
    };
    let mut manager = NailsManager::new(
        MockFilesystem::new(),
        config,
        PathBuf::from("/mnt/vault/state.json"),
    );
    manager.set_fake_platform(fake);
    manager
}

/// The summary is derived from the manager's platform-driven discovery: the
/// target the (fake) NixOS backend reports is what `check`/`--dry-run` shows.
#[test]
fn summary_follows_the_platform_discovery() {
    let manager = manager_on(
        FakePlatform::nixos()
            .with_build_target(HostTarget::Legacy(PathBuf::from("/cfg/configuration.nix"))),
        None,
    );
    let profile = profile_summary(manager.discover_host_target(false).unwrap());
    assert_eq!(profile.mode, "legacy");

    let profile = profile_summary(manager.discover_host_target(true).unwrap());
    assert_eq!(profile.mode, "overlay-only");
}

/// A host without a config layer auto-discovers no profile switch, matching
/// activation, which wires no builder there.
#[test]
fn summary_is_none_on_a_host_without_a_config_layer() {
    let manager = manager_on(FakePlatform::fhs(), None);
    let profile = profile_summary(manager.discover_host_target(false).unwrap());
    assert_eq!(profile.mode, "none");
}

/// An explicit flake is the operator's own choice and is reported on every
/// host, exactly as before discovery moved behind the platform.
#[test]
fn summary_reports_an_explicit_flake_on_any_host() {
    let manager = manager_on(FakePlatform::fhs(), Some("/cfg#host"));
    let profile = profile_summary(manager.discover_host_target(false).unwrap());
    assert_eq!(profile.mode, "flake");
}

#[test]
fn session_summary_reports_a_known_kind() {
    let summary = session_summary();
    assert!(
        matches!(
            summary.kind,
            "tty" | "graphical-user" | "graphical-root" | "ssh" | "unknown"
        ),
        "unexpected session kind: {}",
        summary.kind
    );
}
