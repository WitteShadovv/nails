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
        ("git+file:///etc", Some(PathBuf::from("nixos")))
    );
    assert_eq!(location_and_dir("/etc/nixos?dir="), ("/etc/nixos", None));
}

/// The directory Nix reads: it decodes the percent-escapes of a `path:`
/// reference and of the `dir` parameter, not those of a plain path, and
/// appends the `dir` parameter even when it starts with a `/`.
#[test]
fn the_directory_is_read_as_nix_decodes_it() {
    for (base, dir) in [
        ("path:/srv/my%20flake", "/srv/my flake"),
        ("path:%2Fsrv%2Fcfg", "/srv/cfg"),
        ("/srv?dir=%63fg", "/srv/cfg"),
        ("path:/srv?dir=cf%67&ref=main", "/srv/cfg"),
        ("/srv?dir=/cfg", "/srv/cfg"),
        ("/srv/my%20flake", "/srv/my%20flake"),
        ("path:/srv/100%", "/srv/100%"),
    ] {
        assert_eq!(local_flake_dir(base), Some(PathBuf::from(dir)), "{base}");
    }
}

/// A registry alias names a flake only through Nix's registries, so the
/// pre-flight refuses it: written `flake:<name>` as an alias, and as a name
/// alone, as before, as a relative path without `./`.
#[test]
fn a_registry_alias_is_refused() {
    for alias in ["flake:nixos-config", "flake:nixos-config/main"] {
        let error = resolve_local_flake_dir(alias).unwrap_err().to_string();
        assert!(error.contains("is a registry alias"), "{alias}: {error}");
        assert!(error.contains("/etc/nixos"), "{alias}: {error}");
    }
    for name in ["nixos-config", "nixos-config/main", "self", "cfg.d/sub"] {
        let error = resolve_local_flake_dir(name).unwrap_err().to_string();
        assert!(error.contains("is relative"), "{name}: {error}");
    }
    assert_eq!(local_flake_dir("github:me/cfg"), None);
}

/// Every directory a local reference may name, for the refusal of the
/// decoy's flake, which takes `/etc/nixos` and every directory below it:
/// each URL that reads local files, the location as written and decoded,
/// the work tree of a repository's `.git` directory, every `dir` parameter,
/// and `.` and `..` applied.
#[test]
fn every_directory_a_local_reference_may_name_is_listed() {
    let names = |base: &str| {
        local_flake_dirs(base)
            .iter()
            .any(|dir| dir.starts_with("/etc/nixos"))
    };
    for spelling in [
        "/etc/nixos",
        "hg+file:///etc/nixos",
        "hg+file:/etc/nixos",
        "tarball+file:///etc/nixos",
        "git+file:///etc/nix%6Fs?ref=main",
        "path:/etc/%6Eixos",
        "path:/etc/%6eixos",
        "path:%2Fetc%2Fnixos",
        "file:///%65tc/nixos",
        "/etc/%6Eixos",
        "/etc?dir=%6Eixos",
        "path:/etc?dir=/nixos",
        "path:/etc?dir=%2Fnixos",
        "path:/etc?%64ir=nixos",
        "hg+file:///etc?ref=default&dir=nixos",
        "/etc/nixos/x/..",
        "path:/etc/nixos/x/%2E%2E",
        "/etc/./nixos/",
        "/etc/nixos?%64ir=sub",
        "/etc/nixos?dir=sub",
        "/etc/nixos/sub",
        "git+file:///etc/nixos/.git",
        "git+file:///etc/nixos/.git/",
        "git+file:///etc/.git?dir=nixos",
        "file:///etc/.git?ref=main&dir=nixos",
        "/etc/.git?dir=nixos",
        "git+file://?dir=etc/nixos",
        "git+file:?dir=etc/nixos",
    ] {
        assert!(
            names(spelling),
            "{spelling}: {:?}",
            local_flake_dirs(spelling)
        );
    }
    // Nix reads a file URL with an authority as a path relative to the
    // working directory, the whole reference: enough `..` lead from any
    // working directory to `/`.
    let climb = format!("git+file://{}etc/nixos", "../".repeat(64));
    assert!(names(&climb), "{:?}", local_flake_dirs(&climb));
    for other in [
        "/etc/nixos2",
        "path:/etc/%6Eixos2",
        "/etc/x?dir=nixos",
        "git+file:///etc/nixos2/.git",
        "hg+https://example.org/etc/nixos",
        "git+ssh://localhost/etc/nixos",
        "file://localhost/etc/nixos",
        "github:me/cfg",
        "flake:nixos-config",
        "nixos-config",
        "path:/etc/nixos2/..",
        "git+file:///etc",
    ] {
        assert!(!names(other), "{other}: {:?}", local_flake_dirs(other));
    }
    assert!(local_flake_dirs("github:me/cfg").is_empty());
}

/// Nix takes no authority in a local URL: it reads a file URL with one as a
/// path relative to the working directory, and refuses a `path:` one. The
/// pre-flight refuses each of them, whatever it names, and takes the URL
/// with an empty authority or none.
#[test]
fn a_local_url_with_an_authority_is_refused() {
    for base in [
        "git+file://localhost/srv/flake",
        "file://../../etc/nixos",
        "hg+file://host/srv/flake",
        "path://localhost/srv/flake",
    ] {
        let error = resolve_local_flake_dir(base).unwrap_err().to_string();
        assert!(error.contains("the authority"), "{base}: {error}");
    }
    for base in [
        "git+file:///srv/flake",
        "git+file:/srv/flake",
        "file:///srv/flake?dir=x",
    ] {
        assert_eq!(resolve_local_flake_dir(base).unwrap(), None, "{base}");
    }
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
