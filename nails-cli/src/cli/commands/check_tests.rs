// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the `check` command's helpers.
//!
//! Exit codes, the JSON envelope and parity with `activate --dry-run` are
//! covered end to end against the compiled binary in
//! `nails-cli/tests/cli_integration.rs`; these focus on the pure helpers.

use super::{profile_summary, session_summary};
use nails_core::{Config, MockFilesystem};
use std::path::PathBuf;

#[test]
fn profile_summary_reports_overlay_only() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    let profile = profile_summary(true, &config, &fs);
    assert_eq!(profile.mode, "overlay-only");
}

#[test]
fn profile_summary_reports_an_explicit_flake() {
    let fs = MockFilesystem::new();
    let config = Config {
        nixos_flake: Some("/etc/nixos#host".to_string()),
        ..Config::default()
    };

    let profile = profile_summary(false, &config, &fs);
    assert_eq!(profile.mode, "flake");
    assert!(profile.detail.unwrap().contains("/etc/nixos#host"));
}

#[test]
fn profile_summary_detects_a_flake_in_the_hidden_volume() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt/vault/nixos/flake.nix", true);
    let config = Config {
        hidden_volume_root: PathBuf::from("/mnt/vault"),
        nixos_flake: None,
        ..Config::default()
    };

    let profile = profile_summary(false, &config, &fs);
    assert_eq!(profile.mode, "flake");
}

#[test]
fn profile_summary_reports_legacy_for_a_lone_system_profile() {
    // The drift this fixes: `--dry-run`/`check` used to omit the system-profile
    // probe and report "no profile switch" where activation does a legacy build.
    // Sharing `discover_host_target` makes the summary agree: a lone system
    // profile is a legacy build target.
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/nix/var/nix/profiles/system", true);
    let config = Config {
        hidden_volume_root: PathBuf::from("/mnt/vault"),
        nixos_flake: None,
        ..Config::default()
    };

    let profile = profile_summary(false, &config, &fs);
    assert_eq!(profile.mode, "legacy");
    assert!(
        profile
            .detail
            .unwrap()
            .contains("/etc/nixos/configuration.nix")
    );
}

#[test]
fn profile_summary_is_none_without_any_nixos_target() {
    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: PathBuf::from("/mnt/vault"),
        nixos_flake: None,
        ..Config::default()
    };

    let profile = profile_summary(false, &config, &fs);
    assert_eq!(profile.mode, "none");
    assert!(profile.detail.is_none());
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
