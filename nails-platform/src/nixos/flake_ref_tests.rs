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
/// alone, as before, as a relative path without `./`, as every relative
/// path without one.
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

/// The working directories the readings are taken from: the root, a home,
/// a deep project, and the decoy's own configuration and one below it.
const WORKING_DIRECTORIES: [&str; 5] = [
    "/",
    "/root",
    "/home/alice/src/cfg",
    "/etc/nixos",
    "/etc/nixos/hosts",
];

/// The forms Nix cannot parse as a URL and an input, which it reads as a
/// path relative to the working directory: a forge with no owner, a remote
/// transport with no host, and a scheme that is no scheme.
const FALLBACK_FORMS: [&str; 8] = [
    "github:/",
    "gitlab:/",
    "sourcehut:/",
    "git+https:/",
    "git+ssh:/",
    "git:/",
    "a_b:/",
    "1a:/",
];

/// `form` followed by enough `..` to climb from any working directory to
/// `/`, and `etc/nixos`.
fn climbing(form: &str) -> String {
    format!("{form}{}etc/nixos", "../".repeat(64))
}

/// Every directory a local reference may name, for the refusal of the
/// decoy's flake, which takes `/etc/nixos` and every directory below it:
/// each URL that reads local files, the location as written and decoded,
/// the work tree of a repository's `.git` directory, every `dir` parameter,
/// and `.` and `..` applied, from every working directory.
#[test]
fn every_directory_a_local_reference_may_name_is_listed() {
    for cwd in WORKING_DIRECTORIES {
        let names = |base: &str| {
            flake_ref_readings(base, Path::new(cwd))
                .local
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
            assert!(names(spelling), "{cwd}: {spelling}");
        }
        for other in [
            "/etc/nixos2",
            "path:/etc/%6Eixos2",
            "/etc/x?dir=nixos",
            "git+file:///etc/nixos2/.git",
            "hg+https://example.org/etc/nixos",
            "git+ssh://localhost/etc/nixos",
            "github:me/cfg",
            "flake:nixos-config",
            "nixos-config",
            "path:/etc/nixos2/..",
            "git+file:///etc",
        ] {
            assert!(!names(other), "{cwd}: {other}");
        }
        // A file URL with an authority names no local directory: Nix reads
        // it as a path, which the fallback below holds.
        assert!(
            flake_ref_readings("file://localhost/etc/nixos", Path::new(cwd))
                .local
                .is_empty()
        );
    }
}

/// A relative reference is read against the working directory: `./nixos`
/// is `/etc/nixos` from `/etc` and no other.
#[test]
fn a_relative_reference_is_read_against_the_working_directory() {
    let local = |base: &str, cwd: &str| flake_ref_readings(base, Path::new(cwd)).local;
    assert_eq!(local("./nixos", "/etc"), [PathBuf::from("/etc/nixos")]);
    assert_eq!(local("./nixos", "/root"), [PathBuf::from("/root/nixos")]);
    assert_eq!(local("../nixos", "/etc/x"), [PathBuf::from("/etc/nixos")]);
    assert_eq!(local("path:nixos", "/etc"), [PathBuf::from("/etc/nixos")]);
    assert_eq!(local(".", "/etc/nixos"), [PathBuf::from("/etc/nixos")]);
}

/// The whole reference as a path relative to the working directory, as Nix
/// reads one it cannot parse as a URL and an input, `..` applied: every
/// form that climbs to `/etc/nixos` leads there from every working
/// directory, and so does a file URL with an authority and a name alone.
#[test]
fn the_fallback_reading_is_the_reference_as_a_relative_path() {
    for cwd in WORKING_DIRECTORIES {
        let fallback = |base: &str| flake_ref_readings(base, Path::new(cwd)).fallback;
        for form in FALLBACK_FORMS
            .iter()
            .map(|form| climbing(form))
            .chain([climbing("git+file://"), climbing("path://")])
        {
            assert!(
                fallback(&form).contains(&PathBuf::from("/etc/nixos")),
                "{cwd}: {form}: {:?}",
                fallback(&form)
            );
        }
        assert_eq!(
            fallback("github:me/cfg"),
            [Path::new(cwd).join("github:me/cfg")]
        );
    }
    assert_eq!(
        flake_ref_readings("nixos", Path::new("/etc")).fallback,
        [PathBuf::from("/etc/nixos")]
    );
    assert_eq!(
        flake_ref_readings("a_b:/x/../../nixos?dir=sub", Path::new("/etc")).fallback,
        [PathBuf::from("/etc/nixos/sub")]
    );
}

/// A plain remote reference is one NAILS can tell Nix takes for a URL of
/// its input; anything else with a scheme, which Nix may read as a path
/// relative to the working directory, is refused, whatever it names.
#[test]
fn only_a_plain_remote_reference_passes_as_one() {
    for remote in [
        "github:me/cfg",
        "github:me/cfg/main",
        "github:me/cfg/feature/x",
        "github:me/.dotfiles?dir=hosts/x",
        "gitlab:me/cfg?ref=main",
        "sourcehut:~me/cfg",
        "git+https://example.org/me/cfg.git?ref=main&dir=hosts/x",
        "git+ssh://git@example.org/me/cfg.git",
        "git+http://example.org:8080/me/cfg",
        "git://example.org/me/cfg",
        "hg+https://example.org/me/cfg",
        "https://example.org/cfg.tar.gz",
        "tarball+https://example.org/cfg.tar.gz",
        "github:me/cfg?narHash=sha256-AbC+/12=",
    ] {
        assert!(is_remote_flake_ref(remote), "{remote}");
        assert_eq!(resolve_local_flake_dir(remote).unwrap(), None, "{remote}");
    }
    let mut unknown: Vec<String> = FALLBACK_FORMS.iter().map(|form| climbing(form)).collect();
    unknown.extend(
        [
            "a_b:x",
            "1a:x",
            "gh:me/cfg",
            "github:me",
            "github:me/../cfg",
            "github:me/cfg/..",
            "github:me//cfg",
            "github:me/c%66g",
            "github:me/cfg?dir=../..",
            "github:me/cfg?dir",
            "git+https:/example.org/x",
            "git+https://example.org/../x",
            "git+https://exa_mple.org/x",
            "git+https://example.org:x/cfg",
            "git+https://example.org/x/",
            "https://example.org/a b",
            "s3://bucket/cfg",
        ]
        .map(str::to_string),
    );
    for base in &unknown {
        assert!(!is_remote_flake_ref(base), "{base}");
        let error = resolve_local_flake_dir(base).unwrap_err().to_string();
        assert!(
            error.contains("cannot tell how Nix reads it"),
            "{base}: {error}"
        );
    }
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
