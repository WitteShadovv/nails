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

/// The decoy's own flake named explicitly, or a directory below it, in each
/// local spelling discovery resolves, is the refused decoy flake; another
/// directory is not, and neither is `/etc/nixos` without a flake in it.
#[test]
fn the_decoy_flake_named_explicitly_is_the_refused_decoy_flake() {
    let fs = decoy_flake_host();
    fs.create_symlink(Path::new("/etc/nixos"), Path::new("/srv/config"))
        .unwrap();
    // Nix reads a reference it cannot parse as a URL and an input as a path
    // relative to the working directory: enough `..` lead from any working
    // directory to `/`.
    let climbs: Vec<String> = FALLBACK_FORMS
        .iter()
        .map(|form| format!("{form}{}etc/nixos#host", "../".repeat(64)))
        .collect();
    for spelling in climbs.iter().map(String::as_str).chain([
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
        "hg+file:///etc/nixos#host",
        "hg+file:/etc?dir=nixos#host",
        "path:/etc/%6Eixos#host",
        "git+file:///etc?dir=%6Eixos#host",
        "path:/etc?dir=/nixos#host",
        "/etc/nixos/x/..#host",
        "git+file:///etc/nixos/.git#host",
        "git+file:///etc/nixos/.git/#host",
        "git+file:///etc/.git?dir=nixos#host",
        "/etc/nixos/sub#host",
        "path:/etc/nixos?dir=sub#host",
    ]) {
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
        "hg+https://example.org/etc/nixos#host",
        "path:/etc/%6Eixos2#host",
        "flake:nixos-config#host",
        "/etc/x?dir=nixos#host",
        "git+file:///etc/nixos2/.git#host",
        "file://localhost/etc/nixos#host",
    ] {
        assert_eq!(explicit_decoy_flake(&fs, other).unwrap(), None, "{other}");
    }
    assert_eq!(
        explicit_decoy_flake(&MockFilesystem::new(), "/etc/nixos#host").unwrap(),
        None,
        "no flake in /etc/nixos"
    );
}

/// The working directories references are read against: the root, a home,
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
/// transport with no host, a scheme that is no scheme, and a local URL with
/// an authority.
const FALLBACK_FORMS: [&str; 10] = [
    "github:/",
    "gitlab:/",
    "sourcehut:/",
    "git+https:/",
    "git+ssh:/",
    "git:/",
    "a_b:/",
    "1a:/",
    "git+file://",
    "path://",
];

/// A host whose `/etc/nixos` holds the decoy's flake, and whose working
/// directories exist.
fn decoy_flake_host() -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/etc/nixos", PathKind::Dir);
    fs.mock_set_path_type("/etc/nixos/flake.nix", PathKind::File);
    for cwd in WORKING_DIRECTORIES {
        fs.mock_set_path_type(cwd, PathKind::Dir);
    }
    fs
}

/// Each spelling of the decoy's flake, or of a directory below it, is
/// refused from every working directory, the forms Nix reads as a path
/// relative to it included; a plain remote reference and another directory
/// pass from every one, from inside `/etc/nixos` too. A relative reference
/// names it from where it leads there.
#[test]
fn the_decoy_flake_is_refused_from_every_working_directory() {
    let fs = decoy_flake_host();
    let climbs: Vec<String> = FALLBACK_FORMS
        .iter()
        .map(|form| format!("{form}{}etc/nixos#host", "../".repeat(64)))
        .collect();
    for cwd in WORKING_DIRECTORIES.map(Path::new) {
        for spelling in climbs.iter().map(String::as_str).chain([
            "/etc/nixos#host",
            "/etc/nixos/hosts/x#host",
            "git+file:///etc/nixos/.git#host",
            "git+file:///etc/.git?dir=nixos#host",
            "path:/etc/%6Eixos#host",
        ]) {
            assert!(
                names_decoy_flake(&fs, spelling, cwd).unwrap(),
                "{}: {spelling}",
                cwd.display()
            );
        }
        for other in [
            "github:me/cfg#host",
            "github:me/cfg/main#host",
            "gitlab:me/cfg?ref=main#host",
            "sourcehut:~me/cfg#host",
            "git+https://example.org/me/cfg.git?ref=main&dir=hosts/x#host",
            "git+ssh://git@example.org/me/cfg.git#host",
            "https://example.org/cfg.tar.gz#host",
            "/mnt/hidden/nixos#host",
            "/etc/nixos2#host",
        ] {
            assert!(
                !names_decoy_flake(&fs, other, cwd).unwrap(),
                "{}: {other}",
                cwd.display()
            );
        }
    }
    let named = |spelling: &str, cwd: &str| names_decoy_flake(&fs, spelling, Path::new(cwd));
    assert!(named("./nixos#host", "/etc").unwrap());
    assert!(!named("./nixos#host", "/root").unwrap());
    assert!(named(".#host", "/etc/nixos/hosts").unwrap());
    // A name alone that is no alias is a path relative to the working
    // directory to Nix, where it exists.
    assert!(named("nixos#host", "/etc").unwrap());
    assert!(!named("nixos#host", "/root").unwrap());
}

/// A directory counts by what it is, not by its name: impermanence's
/// `/persist/etc/nixos`, bind-mounted at `/etc/nixos`, has its device and
/// inode, so naming it, or a directory below it, is refused, and a
/// directory beside it is not.
#[test]
fn a_bind_mount_of_the_decoy_flake_is_refused() {
    let fs = decoy_flake_host();
    fs.mock_set_path_type("/persist/etc/nixos", PathKind::Dir);
    fs.mock_set_path_type("/persist/etc/nixos2", PathKind::Dir);
    for path in ["/etc/nixos", "/persist/etc/nixos"] {
        fs.mock_set_device_id(Path::new(path), 7);
        fs.mock_set_inode(Path::new(path), 42);
    }
    let cwd = Path::new("/root");
    for spelling in [
        "/persist/etc/nixos#host",
        "path:/persist/etc/nixos/hosts#host",
        "git+file:///persist/etc/nixos#host",
        "git+file:///persist/etc/.git?dir=nixos#host",
    ] {
        assert!(names_decoy_flake(&fs, spelling, cwd).unwrap(), "{spelling}");
    }
    assert!(!names_decoy_flake(&fs, "/persist/etc/nixos2#host", cwd).unwrap());
}

/// Only a missing `flake.nix` means `/etc/nixos` holds no flake: another
/// error looking it up refuses whatever is named, and so does one at a
/// directory on the way, through discovery too.
#[test]
fn a_lookup_that_fails_refuses() {
    let fs = decoy_flake_host();
    fs.mock_set_inode_error(
        Path::new("/srv/locked"),
        std::io::ErrorKind::PermissionDenied,
    );
    assert!(names_decoy_flake(&fs, "/srv/locked/cfg#host", Path::new("/root")).is_err());

    let fs = MockFilesystem::new();
    fs.mock_set_inode_error(
        Path::new("/etc/nixos/flake.nix"),
        std::io::ErrorKind::PermissionDenied,
    );
    assert!(names_decoy_flake(&fs, "github:me/cfg#host", Path::new("/root")).is_err());
    let target = super::super::discover_with_platform(
        &NixOsPlatform,
        &fs,
        Path::new(HIDDEN_ROOT),
        Some("/mnt/hidden/nixos#host"),
        false,
    );
    assert!(target.is_err(), "{target:?}");

    assert!(
        !names_decoy_flake(
            &MockFilesystem::new(),
            "/etc/nixos#host",
            Path::new("/root")
        )
        .unwrap()
    );
}

/// A hidden flake directory that is a link to `/etc/nixos` is the
/// decoy's own flake, refused like the flake it leads to; a flake of its
/// own beside it is taken.
#[test]
fn a_hidden_flake_that_links_to_the_decoy_flake_is_the_refused_decoy_flake() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/etc/nixos", PathKind::Dir);
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
        hidden_flake(&fs, Path::new(HIDDEN_ROOT)).unwrap(),
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
        hidden_flake(&fs, Path::new(HIDDEN_ROOT)).unwrap(),
        HiddenFlake::Present
    );
    assert_eq!(
        hidden_flake(&MockFilesystem::new(), Path::new(HIDDEN_ROOT)).unwrap(),
        HiddenFlake::Missing
    );
    // While /etc/nixos holds no flake, there is no decoy flake to be: the
    // hidden flake is one of its own.
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/mnt/hidden/nixos/flake.nix", PathKind::File);
    assert_eq!(
        hidden_flake(&fs, Path::new(HIDDEN_ROOT)).unwrap(),
        HiddenFlake::Present
    );
}

/// A hidden flake directory counts by what it is, not by its name: a link
/// to a directory below `/etc/nixos`, and a bind mount of `/etc/nixos` (the
/// same device and inode), are the decoy's own flake, refused by discovery
/// and when named; a directory of its own beside them is taken.
#[test]
fn a_hidden_flake_below_the_decoy_flake_or_bound_to_it_is_refused() {
    let decoy = HostTarget::DecoyFlake {
        dir: PathBuf::from("/etc/nixos"),
        hidden_volume_root: PathBuf::from(HIDDEN_ROOT),
    };
    let named = |fs: &MockFilesystem| {
        super::super::discover_with_platform(
            &NixOsPlatform,
            fs,
            Path::new(HIDDEN_ROOT),
            Some("/mnt/hidden/nixos#host"),
            false,
        )
        .unwrap()
    };

    let fs = decoy_flake_host();
    fs.mock_set_path_type("/etc/nixos/hosts/flake.nix", PathKind::File);
    fs.create_symlink(
        Path::new("/etc/nixos/hosts"),
        Path::new("/mnt/hidden/nixos"),
    )
    .unwrap();
    fs.mock_set_path_type("/mnt/hidden/nixos/flake.nix", PathKind::File);
    assert_eq!(
        hidden_flake(&fs, Path::new(HIDDEN_ROOT)).unwrap(),
        HiddenFlake::DecoyFlake
    );
    assert_eq!(discover(&fs), decoy);
    assert_eq!(named(&fs), decoy);

    let fs = decoy_flake_host();
    fs.mock_set_path_type("/mnt/hidden/nixos", PathKind::Dir);
    fs.mock_set_path_type("/mnt/hidden/nixos/flake.nix", PathKind::File);
    for path in ["/etc/nixos", "/mnt/hidden/nixos"] {
        fs.mock_set_device_id(Path::new(path), 7);
        fs.mock_set_inode(Path::new(path), 42);
    }
    assert_eq!(
        hidden_flake(&fs, Path::new(HIDDEN_ROOT)).unwrap(),
        HiddenFlake::DecoyFlake
    );
    assert_eq!(discover(&fs), decoy);
    assert_eq!(named(&fs), decoy);

    fs.mock_set_inode(Path::new("/mnt/hidden/nixos"), 43);
    assert_eq!(
        hidden_flake(&fs, Path::new(HIDDEN_ROOT)).unwrap(),
        HiddenFlake::Present
    );
    assert_eq!(
        discover(&fs),
        HostTarget::Flake(PathBuf::from("/mnt/hidden/nixos"))
    );
}

/// Only a missing `flake.nix` means no flake, for the hidden flake as for
/// the decoy's: an error looking at either, or at a directory on the way,
/// refuses through discovery, and is no flake of its own.
#[test]
fn a_hidden_flake_that_cannot_be_looked_at_refuses() {
    let fs = decoy_flake_host();
    fs.mock_set_inode_error(
        Path::new("/mnt/hidden/nixos/flake.nix"),
        std::io::ErrorKind::PermissionDenied,
    );
    assert!(hidden_flake(&fs, Path::new(HIDDEN_ROOT)).is_err());
    let target = Platform::discover_build_target(&NixOsPlatform, &fs, Path::new(HIDDEN_ROOT));
    assert!(target.is_err(), "{target:?}");

    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/mnt/hidden/nixos/flake.nix", PathKind::File);
    fs.mock_set_inode_error(
        Path::new("/etc/nixos/flake.nix"),
        std::io::ErrorKind::PermissionDenied,
    );
    assert!(hidden_flake(&fs, Path::new(HIDDEN_ROOT)).is_err());

    let fs = decoy_flake_host();
    fs.mock_set_path_type("/mnt/hidden/nixos/flake.nix", PathKind::File);
    fs.mock_set_inode_error(
        Path::new("/mnt/hidden"),
        std::io::ErrorKind::PermissionDenied,
    );
    assert!(hidden_flake(&fs, Path::new(HIDDEN_ROOT)).is_err());
}

/// A link that leads below `/etc/nixos` counts as the directory it leads
/// to, as Nix follows it, also where the named directory below the link
/// does not exist.
#[test]
fn a_reference_through_a_link_below_the_decoy_flake_is_refused() {
    let fs = decoy_flake_host();
    fs.create_symlink(Path::new("/etc/nixos/hosts"), Path::new("/srv/below"))
        .unwrap();
    let cwd = Path::new("/root");
    for spelling in [
        "/srv/below#host",
        "/srv/below/x#host",
        "path:/srv/below?dir=x#host",
    ] {
        assert!(names_decoy_flake(&fs, spelling, cwd).unwrap(), "{spelling}");
    }
    fs.create_symlink(Path::new("/srv/elsewhere"), Path::new("/srv/aside"))
        .unwrap();
    assert!(!names_decoy_flake(&fs, "/srv/aside#host", cwd).unwrap());
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

/// Nix follows a link before it applies the `..` after it, for a plain path
/// and for `git+file:`. In a scratch tree that stands for `/`, where
/// `var/run` is a link to `../run` as on every systemd host,
/// `var/run/../etc/nixos` is `etc/nixos`, though by the text it is
/// `var/etc/nixos`, and `/proc/self/root/..` is `/`. Each such spelling of
/// the decoy's flake is refused from every working directory, on the real
/// filesystem, and a directory beside it is not, whichever way its `..`
/// leads.
#[test]
fn a_link_before_a_dot_dot_leads_where_nix_follows_it() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    std::fs::create_dir_all(root.join("etc/nixos")).unwrap();
    std::fs::write(root.join("etc/nixos/flake.nix"), "{ }\n").unwrap();
    std::fs::create_dir_all(root.join("etc/nixos2")).unwrap();
    std::fs::create_dir_all(root.join("run")).unwrap();
    std::fs::create_dir_all(root.join("var")).unwrap();
    std::os::unix::fs::symlink("../run", root.join("var/run")).unwrap();
    let decoy = root.join("etc/nixos");
    let fs = crate::RealFilesystem;
    let r = root.display();
    let run = root.join("run");
    for cwd in [Path::new("/"), root, run.as_path(), decoy.as_path()] {
        for spelling in [
            format!("{r}/var/run/../etc/nixos#host"),
            format!("git+file://{r}/var/run/../etc/nixos#host"),
            format!("/proc/self/root/..{r}/etc/nixos#host"),
        ] {
            assert!(
                names_flake_in(&fs, &spelling, cwd, &decoy).unwrap(),
                "{}: {spelling}",
                cwd.display()
            );
        }
        for other in [
            format!("{r}/var/run/../etc/nixos2#host"),
            format!("{r}/etc/nixos/../nixos2#host"),
            "github:me/cfg#host".to_string(),
        ] {
            assert!(
                !names_flake_in(&fs, &other, cwd, &decoy).unwrap(),
                "{}: {other}",
                cwd.display()
            );
        }
    }
    let named = |spelling: &str, cwd: &Path| names_flake_in(&fs, spelling, cwd, &decoy).unwrap();
    assert!(named("./var/run/../etc/nixos#host", root));
    assert!(!named("./var/run/../etc/nixos#host", &run));
}

/// Discovery with no hidden flake looks at `/etc/nixos/flake.nix` under the
/// same rule as a named reference: only a missing one means none, and
/// another error refuses.
#[test]
fn discovery_refuses_a_decoy_flake_it_cannot_look_at() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/etc/nixos/configuration.nix", PathKind::File);
    fs.mock_set_inode_error(
        Path::new("/etc/nixos/flake.nix"),
        std::io::ErrorKind::PermissionDenied,
    );
    let target = Platform::discover_build_target(&NixOsPlatform, &fs, Path::new(HIDDEN_ROOT));
    assert!(target.is_err(), "{target:?}");
}

/// Nix never reads a plain remote reference as a path, so an error looking
/// at that reading, from a working directory that cannot be searched (an NFS
/// home with root squashed), does not refuse it; for any other reference it
/// does.
#[test]
fn an_error_reading_a_remote_reference_as_a_path_does_not_count() {
    let fs = decoy_flake_host();
    let cwd = Path::new("/nfs/home/alice");
    for name in ["github:me/cfg", "a_b:cfg"] {
        fs.mock_set_inode_error(&cwd.join(name), std::io::ErrorKind::PermissionDenied);
    }
    assert!(!names_decoy_flake(&fs, "github:me/cfg#host", cwd).unwrap());
    assert!(names_decoy_flake(&fs, "a_b:cfg#host", cwd).is_err());
}
