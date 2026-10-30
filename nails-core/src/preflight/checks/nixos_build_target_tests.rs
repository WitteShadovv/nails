// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the `nixos-build-target` check: an explicit flake
//! reference, a selected flake directory and the discovered target.

use super::*;
use crate::filesystem::MockFilesystem;

// ========================================================================
// Trait metadata
// ========================================================================

#[test]
fn test_name_and_description() {
    let check = NixOSBuildTargetCheck::new(None, HostTarget::None);
    assert_eq!(
        PreFlightCheck::<MockFilesystem>::name(&check),
        "nixos-build-target"
    );
    assert_eq!(
        PreFlightCheck::<MockFilesystem>::description(&check),
        "Validates NixOS build target reference will resolve"
    );
}

// ========================================================================
// Branch A: Explicit flake reference
// ========================================================================

#[test]
fn test_explicit_flake_with_attr_all_paths_exist() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/srv/flake", true);
    fs.mock_set_path_exists("/srv/flake/flake.nix", true);

    let check = NixOSBuildTargetCheck::new(
        Some("/srv/flake#amnesia-virtualbox".to_string()),
        HostTarget::None,
    );
    let result = check.run(&fs).unwrap();

    assert!(result.is_pass());
    assert!(result.message().contains("/srv/flake#amnesia-virtualbox"));
}

#[test]
fn test_explicit_flake_without_attr() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/srv/flake", true);
    fs.mock_set_path_exists("/srv/flake/flake.nix", true);

    let check = NixOSBuildTargetCheck::new(Some("/srv/flake".to_string()), HostTarget::None);
    let result = check.run(&fs).unwrap();

    assert!(result.is_pass());
    assert!(result.message().contains("/srv/flake"));
}

#[test]
fn test_explicit_generic_github_flake_ref_passes_without_local_path_checks() {
    let fs = MockFilesystem::new();

    let check = NixOSBuildTargetCheck::new(
        Some("github:owner/repo#machine".to_string()),
        HostTarget::None,
    );
    let result = check.run(&fs).unwrap();

    assert!(result.is_pass());
    assert!(result.message().contains("github:owner/repo#machine"));
}

#[test]
fn test_explicit_path_scheme_flake_ref_with_query_uses_local_directory() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/some/dir", true);
    fs.mock_set_path_exists("/some/dir/flake.nix", true);

    let check = NixOSBuildTargetCheck::new(
        Some("path:/some/dir?foo=bar#machine".to_string()),
        HostTarget::None,
    );
    let result = check.run(&fs).unwrap();

    assert!(result.is_pass());
    assert!(result.message().contains("path:/some/dir?foo=bar#machine"));
}

#[test]
fn test_explicit_relative_flake_ref_with_dot_slash_passes() {
    // The check resolves the relative ref against the working directory, which
    // no test changes.
    let fs = MockFilesystem::new();
    let current_dir = std::env::current_dir().unwrap();
    let flake_dir = current_dir.join("relative-flake");
    let flake_nix = flake_dir.join("flake.nix");

    fs.mock_set_path_exists(&flake_dir.to_string_lossy(), true);
    fs.mock_set_path_exists(&flake_nix.to_string_lossy(), true);

    let check = NixOSBuildTargetCheck::new(
        Some("./relative-flake#host-alpha".to_string()),
        HostTarget::None,
    );
    let result = check.run(&fs).unwrap();

    assert!(result.is_pass());
    assert!(result.message().contains("./relative-flake#host-alpha"));
}

#[test]
fn test_explicit_relative_current_directory_flake_ref_passes() {
    // The check resolves the relative ref against the working directory, which
    // no test changes.
    let fs = MockFilesystem::new();
    let current_dir = std::env::current_dir().unwrap();
    let flake_nix = current_dir.join("flake.nix");

    fs.mock_set_path_exists(&current_dir.to_string_lossy(), true);
    fs.mock_set_path_exists(&flake_nix.to_string_lossy(), true);

    let check = NixOSBuildTargetCheck::new(Some(".#host-alpha".to_string()), HostTarget::None);
    let result = check.run(&fs).unwrap();

    assert!(result.is_pass());
    assert!(result.message().contains(".#host-alpha"));
}

#[test]
fn test_explicit_flake_directory_missing() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/nonexistent/path", false);

    let check = NixOSBuildTargetCheck::new(
        Some("/nonexistent/path#hostname".to_string()),
        HostTarget::None,
    );
    let result = check.run(&fs).unwrap();

    assert!(result.is_fail());
    assert!(result.message().contains("/nonexistent/path"));
}

#[test]
fn test_explicit_flake_no_flake_nix() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/srv/flake", true);
    fs.mock_set_path_exists("/srv/flake/flake.nix", false);

    let check = NixOSBuildTargetCheck::new(
        Some("/srv/flake#amnesia-virtualbox".to_string()),
        HostTarget::None,
    );
    let result = check.run(&fs).unwrap();

    assert!(result.is_fail());
    assert!(result.message().contains("/srv/flake"));
}

#[test]
fn test_selected_flake_dir_no_flake_nix_does_not_fall_back_to_legacy() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt/hidden/nixos", true);
    fs.mock_set_path_exists("/mnt/hidden/nixos/flake.nix", false);

    // Even with a legacy target discovered, a selected flake directory is
    // validated on its own and never falls back to it.
    let check = NixOSBuildTargetCheck::with_selected_flake_dir(
        None,
        Some(PathBuf::from("/mnt/hidden/nixos")),
        HostTarget::Legacy(PathBuf::from("/cfg/configuration.nix")),
    );
    let result = check.run(&fs).unwrap();

    assert!(result.is_fail());
    assert!(result.message().contains("/mnt/hidden/nixos"));
    assert!(!result.message().contains("legacy"));
}

#[test]
fn test_selected_flake_dir_with_flake_nix_passes() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt/hidden/nixos", true);
    fs.mock_set_path_exists("/mnt/hidden/nixos/flake.nix", true);

    let check = NixOSBuildTargetCheck::with_selected_flake_dir(
        None,
        Some(PathBuf::from("/mnt/hidden/nixos")),
        HostTarget::None,
    );
    let result = check.run(&fs).unwrap();

    assert!(result.is_pass());
    assert!(result.message().contains("/mnt/hidden/nixos"));
}

// ========================================================================
// Branch B: Auto-discovery (the target comes from the platform; the
// discovery cascade itself is tested in `platform::nixos`)
// ========================================================================

fn auto(target: HostTarget) -> CheckResult {
    NixOSBuildTargetCheck::new(None, target)
        .run(&MockFilesystem::new())
        .unwrap()
}

#[test]
fn test_auto_discovery_reports_discovered_flake() {
    let result = auto(HostTarget::Flake(PathBuf::from("/mnt/hidden/nixos")));
    assert!(result.is_pass());
    assert!(result.message().contains("/mnt/hidden/nixos"));
}

#[test]
fn test_auto_discovery_reports_discovered_legacy_config() {
    let result = auto(HostTarget::Legacy(PathBuf::from("/cfg/configuration.nix")));
    assert!(result.is_pass());
    assert!(result.message().contains("/cfg/configuration.nix"));
}

#[test]
fn test_auto_discovery_overlay_only_and_explicit_pass() {
    assert!(auto(HostTarget::OverlayOnly).is_pass());
    let result = auto(HostTarget::ExplicitFlake("gh:me/cfg".into()));
    assert!(result.is_pass());
    assert!(result.message().contains("gh:me/cfg"));
}

/// The decoy's own flake fails with instructions that name the hidden
/// flake directory, the decoy's configuration and the hidden module.
#[test]
fn test_auto_discovery_refuses_the_decoy_flake_with_instructions() {
    let result = auto(HostTarget::DecoyFlake {
        dir: PathBuf::from("/etc/nixos"),
        hidden_volume_root: PathBuf::from("/mnt/data"),
    });
    assert!(result.is_fail());
    assert!(
        result
            .message()
            .starts_with("/etc/nixos holds the decoy's own flake and /mnt/data/nixos holds none"),
        "{result:?}"
    );
    let remedy = result.remediation().expect("instructions");
    for part in [
        "Write a self-contained flake in /mnt/data/nixos and lock it",
        "from inside a hidden session",
        "never on the decoy",
        "the hidden module /mnt/data/config/nixos/configuration.nix",
        "reads no file of the decoy: copy what it needs from /etc/nixos",
        "flake.lock, so it must exist",
        "--nixos-flake",
        "--overlay-only",
    ] {
        assert!(remedy.contains(part), "{part} missing: {remedy}");
    }
}

/// A hidden flake directory that is a link to the decoy's flake is
/// refused with what to put in its place.
#[test]
fn a_hidden_flake_linked_to_the_decoy_flake_is_refused_with_instructions() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/etc/nixos", true);
    fs.mock_set_path_exists("/etc/nixos/flake.nix", true);
    fs.mock_set_path_exists("/mnt/data/nixos/flake.nix", true);
    fs.create_symlink(Path::new("/etc/nixos"), Path::new("/mnt/data/nixos"))
        .unwrap();
    let result = NixOSBuildTargetCheck::new(
        None,
        HostTarget::DecoyFlake {
            dir: PathBuf::from("/etc/nixos"),
            hidden_volume_root: PathBuf::from("/mnt/data"),
        },
    )
    .run(&fs)
    .unwrap();
    assert!(
        result.message().starts_with(
            "/mnt/data/nixos is /etc/nixos or a directory below it, the decoy's own flake"
        ),
        "{result:?}"
    );
    assert!(
        result.remediation().is_some_and(|fix| fix.starts_with(
            "Remove the link or the bind mount /mnt/data/nixos. Write a self-contained flake in \
             /mnt/data/nixos"
        )),
        "{result:?}"
    );
}

#[test]
fn test_auto_discovery_nothing_found() {
    let result = auto(HostTarget::None);
    assert!(result.is_fail());
    assert!(result.message().contains("--nixos-flake"));
}

/// The check reports the platform's answer, not a filesystem probe of its
/// own: NixOS files on disk cannot override what the platform discovered.
#[test]
fn test_auto_discovery_does_not_probe_the_filesystem() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/etc/nixos/flake.nix", true);
    let result = NixOSBuildTargetCheck::new(None, HostTarget::None)
        .run(&fs)
        .unwrap();
    assert!(result.is_fail());
}
