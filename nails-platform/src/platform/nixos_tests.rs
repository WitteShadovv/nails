// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The discovery cascade, exercised against NixOS host fixtures. These are the
//! only `/etc/nixos` discovery fixtures: callers (manager, pre-flight, CLI) pin
//! the target with a `FakePlatform` instead.

use super::*;
use crate::filesystem::{MockFilesystem, PathKind};

const HIDDEN_ROOT: &str = "/mnt/hidden";

fn discover(fs: &MockFilesystem) -> HostTarget {
    Platform::discover_build_target(&NixOsPlatform, fs, Path::new(HIDDEN_ROOT)).unwrap()
}

#[test]
fn explicit_flake_wins_over_probes() {
    let fs = tests_support::full_nixos_host();
    let target = super::super::discover_with_platform(
        &NixOsPlatform,
        &fs,
        Path::new(HIDDEN_ROOT),
        Some("gh:me/cfg#host"),
        false,
    )
    .unwrap();
    assert_eq!(
        target,
        HostTarget::ExplicitFlake("gh:me/cfg#host".to_string())
    );
}

#[test]
fn hidden_volume_flake_preferred() {
    let fs = tests_support::full_nixos_host();
    assert_eq!(
        discover(&fs),
        HostTarget::Flake(PathBuf::from("/mnt/hidden/nixos"))
    );
}

/// The decoy's own flake is reported for refusal, never built, and the
/// legacy configuration beside it (which the flake imports) is not taken
/// instead.
#[test]
fn etc_flake_without_a_hidden_flake_is_the_refused_decoy_flake() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/etc/nixos/flake.nix", PathKind::File);
    fs.mock_set_path_type("/etc/nixos/configuration.nix", PathKind::File);
    fs.mock_set_path_type("/nix/var/nix/profiles/system", PathKind::Dir);
    assert_eq!(
        discover(&fs),
        HostTarget::DecoyFlake {
            dir: PathBuf::from("/etc/nixos"),
            hidden_volume_root: PathBuf::from(HIDDEN_ROOT),
        }
    );
}

/// The decoy's own flake named explicitly, in each spelling Nix accepts
/// for it, is the refused decoy flake; another directory is not, and
/// neither is `/etc/nixos` without a flake in it.
#[test]
fn the_decoy_flake_named_explicitly_is_the_refused_decoy_flake() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/etc/nixos/flake.nix", PathKind::File);
    fs.create_symlink(Path::new("/etc/nixos"), Path::new("/srv/config"))
        .unwrap();
    for spelling in [
        "/etc/nixos#host",
        "/etc/nixos/#host",
        "/etc/./nixos",
        "path:/etc/nixos?lastModified=1#host",
        "git+file:///etc/nixos?ref=main#host",
        "git+file:/etc/nixos#host",
        "/srv/config#host",
        "/etc/nixos?dir=.#host",
        "/etc/nixos/?ref=main#host",
        "path:/etc?dir=nixos#host",
        "git+file:///etc?dir=nixos#host",
        "file:///etc?ref=main&dir=nixos",
    ] {
        let target = super::super::discover_with_platform(
            &NixOsPlatform,
            &fs,
            Path::new(HIDDEN_ROOT),
            Some(spelling),
            false,
        )
        .unwrap();
        assert_eq!(
            target,
            HostTarget::DecoyFlake {
                dir: PathBuf::from("/etc/nixos"),
                hidden_volume_root: PathBuf::from(HIDDEN_ROOT),
            },
            "{spelling}"
        );
    }
    for other in [
        "/mnt/hidden/nixos#host",
        "/etc/nixos2#host",
        "github:me/cfg#host",
        "path:/etc?dir=nixos2#host",
        "git+file:///etc#host",
    ] {
        assert_eq!(explicit_decoy_flake(&fs, other), None, "{other}");
    }
    assert_eq!(
        explicit_decoy_flake(&MockFilesystem::new(), "/etc/nixos#host"),
        None,
        "no flake in /etc/nixos"
    );
}

/// A hidden flake directory that is a link to `/etc/nixos` is the
/// decoy's own flake, refused like the flake it leads to; a flake of its
/// own beside it is taken.
#[test]
fn a_hidden_flake_that_links_to_the_decoy_flake_is_the_refused_decoy_flake() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/etc/nixos/flake.nix", PathKind::File);
    fs.mock_set_path_type("/mnt/hidden/nixos/flake.nix", PathKind::File);
    fs.create_symlink(Path::new("/etc/nixos"), Path::new("/mnt/hidden/nixos"))
        .unwrap();
    let decoy = HostTarget::DecoyFlake {
        dir: PathBuf::from("/etc/nixos"),
        hidden_volume_root: PathBuf::from(HIDDEN_ROOT),
    };
    assert_eq!(discover(&fs), decoy);
    assert_eq!(
        hidden_flake(&fs, Path::new(HIDDEN_ROOT)),
        HiddenFlake::DecoyFlake
    );
    // Named with --nixos-flake, the link is refused the same way.
    let named = super::super::discover_with_platform(
        &NixOsPlatform,
        &fs,
        Path::new(HIDDEN_ROOT),
        Some("/mnt/hidden/nixos#host"),
        false,
    )
    .unwrap();
    assert_eq!(named, decoy);

    let fs = tests_support::full_nixos_host();
    assert_eq!(
        hidden_flake(&fs, Path::new(HIDDEN_ROOT)),
        HiddenFlake::Present
    );
    assert_eq!(
        hidden_flake(&MockFilesystem::new(), Path::new(HIDDEN_ROOT)),
        HiddenFlake::Missing
    );
}

#[test]
fn legacy_config_when_present() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/etc/nixos/configuration.nix", PathKind::File);
    assert_eq!(
        discover(&fs),
        HostTarget::Legacy(PathBuf::from("/etc/nixos/configuration.nix"))
    );
}

/// The agreement case: with only the system profile present, every path must
/// resolve to the same legacy target activation uses — no drift between
/// activate, `--dry-run`/`check`, and the `nixos-build-target` pre-flight.
#[test]
fn only_system_profile_resolves_to_legacy() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/nix/var/nix/profiles/system", PathKind::Dir);
    assert_eq!(
        discover(&fs),
        HostTarget::Legacy(PathBuf::from("/etc/nixos/configuration.nix"))
    );
}

#[test]
fn nothing_found_is_none() {
    assert_eq!(discover(&MockFilesystem::new()), HostTarget::None);
}
