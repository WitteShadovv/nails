// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for splitting flake references and finding a local flake
//! directory.

use super::*;

#[test]
fn split_flake_ref_separates_base_and_fragment() {
    assert_eq!(split_flake_ref("/cfg#host"), ("/cfg", Some("host")));
    assert_eq!(split_flake_ref("/cfg#"), ("/cfg", None));
    assert_eq!(split_flake_ref("github:me/cfg"), ("github:me/cfg", None));
}

#[test]
fn local_flake_dir_only_returns_paths_for_local_refs() {
    assert_eq!(
        local_flake_dir("/etc/nixos"),
        Some(PathBuf::from("/etc/nixos"))
    );
    assert_eq!(
        local_flake_dir("path:/etc/nixos?x=1"),
        Some(PathBuf::from("/etc/nixos"))
    );
    assert_eq!(local_flake_dir("github:me/cfg"), None);
    assert!(resolve_local_flake_dir("relative").is_err());
    assert!(local_flake_dir("./cfg").unwrap().ends_with("cfg"));
}

/// A query is no part of the directory, and its `dir` parameter names
/// the subdirectory that holds `flake.nix`.
#[test]
fn a_query_is_dropped_and_its_dir_applied() {
    for (base, dir) in [
        ("/etc/nixos?ref=main", "/etc/nixos"),
        ("/etc/nixos/?dir=.", "/etc/nixos"),
        ("/etc?dir=nixos", "/etc/nixos"),
        ("path:/etc?dir=nixos&lastModified=1", "/etc/nixos"),
        ("path:/srv/cfg?narHash=x", "/srv/cfg"),
    ] {
        assert_eq!(local_flake_dir(base), Some(PathBuf::from(dir)), "{base}");
    }
    assert!(
        local_flake_dir("./cfg?dir=sub")
            .unwrap()
            .ends_with("cfg/sub")
    );
    assert_eq!(local_flake_dir("git+file:///etc?dir=nixos"), None);
    assert_eq!(
        location_and_dir("git+file:///etc?ref=main&dir=nixos"),
        ("git+file:///etc", Some("nixos"))
    );
    assert_eq!(location_and_dir("/etc/nixos?dir="), ("/etc/nixos", None));
}

#[test]
fn an_explicit_fragment_wins_over_the_hostname() {
    assert_eq!(
        selected_nixos_configuration_fragment(Some("hidden")).unwrap(),
        ("hidden".to_string(), true)
    );
    let (name, explicit) = selected_nixos_configuration_fragment(None).unwrap();
    assert!(!name.is_empty());
    assert!(!explicit);
}
