// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the next-root primitives that need no privileges.

use super::*;
use crate::test_support::write_executable;
use std::os::unix::fs::symlink;

fn executable(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    write_executable(path, "#!/bin/sh\n", 0o755);
}

#[test]
fn an_fhs_root_with_its_init_and_os_release_passes() {
    let root = tempfile::tempdir().unwrap();
    executable(&root.path().join("usr/lib/systemd/systemd"));
    std::fs::create_dir_all(root.path().join("usr/lib")).unwrap();
    std::fs::write(root.path().join("usr/lib/os-release"), "ID=debian\n").unwrap();
    std::fs::create_dir_all(root.path().join("etc")).unwrap();
    symlink("../usr/lib/os-release", root.path().join("etc/os-release")).unwrap();
    precheck(root.path(), Path::new("/usr/lib/systemd/systemd")).unwrap();
}

#[test]
fn absolute_symlinks_resolve_inside_the_root_like_pid1_does() {
    // NixOS: /run/current-system -> /nix/store/…, an absolute symlink that
    // must resolve inside the next root, never on the running system.
    let root = tempfile::tempdir().unwrap();
    let system = root.path().join("nix/store/aaa-nixos-system");
    executable(&system.join("systemd/lib/systemd/systemd"));
    std::fs::create_dir_all(root.path().join("run")).unwrap();
    symlink(
        "/nix/store/aaa-nixos-system",
        root.path().join("run/current-system"),
    )
    .unwrap();
    std::fs::create_dir_all(root.path().join("etc/static")).unwrap();
    std::fs::write(system.join("os-release"), "ID=nixos\n").unwrap();
    symlink(
        "/nix/store/aaa-nixos-system/os-release",
        root.path().join("etc/os-release"),
    )
    .unwrap();
    precheck(
        root.path(),
        Path::new("/run/current-system/systemd/lib/systemd/systemd"),
    )
    .unwrap();
    // A symlink that escapes upwards is clamped to the root.
    symlink(
        "../../../../../../nix/store/aaa-nixos-system",
        root.path().join("run/up"),
    )
    .unwrap();
    precheck(
        root.path(),
        Path::new("/run/up/systemd/lib/systemd/systemd"),
    )
    .unwrap();
}

#[test]
fn files_are_read_through_symlinks_resolved_inside_the_root() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("etc/static")).unwrap();
    std::fs::write(root.path().join("etc/static/fstab"), "inside\n").unwrap();
    symlink("/etc/static/fstab", root.path().join("etc/fstab")).unwrap();
    assert_eq!(
        read_in_root(root.path(), Path::new("/etc/fstab")).unwrap(),
        b"inside\n"
    );
    assert!(read_in_root(root.path(), Path::new("/etc/absent")).is_err());
}

#[test]
fn only_regular_files_count_as_files_inside_the_root() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("etc/static")).unwrap();
    std::fs::write(root.path().join("etc/static/sddm.conf"), "x").unwrap();
    symlink("/etc/static/sddm.conf", root.path().join("etc/sddm.conf")).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        root.path().join("etc/fifo"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    for (path, file) in [
        ("/etc/static/sddm.conf", true),
        // The absolute link resolves inside the root.
        ("/etc/sddm.conf", true),
        ("/etc/static", false),
        ("/etc/fifo", false),
        ("/etc/absent", false),
    ] {
        assert_eq!(
            is_file_in_root(root.path(), Path::new(path)),
            file,
            "{path}"
        );
    }
}

/// Lookups through a `..` link while another thread renames files: the
/// kernel gives some of them up with `EAGAIN` (about one in twenty here
/// without the retry), and none of them may fail.
#[test]
fn lookups_through_a_parent_link_survive_concurrent_renames() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("usr/lib")).unwrap();
    std::fs::write(root.path().join("usr/lib/os-release"), "ID=debian\n").unwrap();
    std::fs::create_dir_all(root.path().join("etc")).unwrap();
    symlink("../usr/lib/os-release", root.path().join("etc/os-release")).unwrap();
    std::fs::create_dir_all(root.path().join("home/alice/dotfiles/config")).unwrap();
    symlink("dotfiles/config", root.path().join("home/alice/.config")).unwrap();
    symlink("../home/alice/.config", root.path().join("home/.shared")).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let renamer = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let dir = tempfile::tempdir().unwrap();
            let (a, b) = (dir.path().join("a"), dir.path().join("b"));
            std::fs::write(&a, "x").unwrap();
            while !stop.load(Ordering::Relaxed) {
                std::fs::rename(&a, &b).unwrap();
                std::fs::rename(&b, &a).unwrap();
            }
        })
    };
    let mut failures = Vec::new();
    for _ in 0..20_000 {
        if let Err(e) = read_in_root(root.path(), Path::new("/etc/os-release")) {
            failures.push(e.to_string());
        }
        if let Err(e) = create_dir_all_in_root(
            root.path(),
            Path::new("/home/.shared/autostart"),
            &mut |_, _| Ok(()),
        ) {
            failures.push(e.to_string());
        }
    }
    stop.store(true, Ordering::Relaxed);
    renamer.join().unwrap();
    assert!(
        failures.is_empty(),
        "{} lookups failed, first: {}",
        failures.len(),
        failures[0]
    );
    assert!(
        root.path()
            .join("home/alice/dotfiles/config/autostart")
            .is_dir()
    );
}

#[test]
fn directories_are_created_and_listed_through_links_resolved_inside_the_root() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("srv/people")).unwrap();
    // Absolute, and a name no host has: a lookup on the running system
    // would fail, one inside the root reaches srv/people.
    symlink("/srv/people", root.path().join("nails-test-home")).unwrap();
    let mut made = Vec::new();
    let fd = create_dir_all_in_root(
        root.path(),
        Path::new("/nails-test-home/alice/.config"),
        &mut |_, name| {
            made.push(name.to_owned());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(made, ["alice", ".config"]);
    assert_eq!(
        real_path(&fd).unwrap(),
        root.path()
            .canonicalize()
            .unwrap()
            .join("srv/people/alice/.config")
    );
    assert_eq!(
        list_in_root(root.path(), Path::new("/nails-test-home")).unwrap(),
        [OsString::from("alice")]
    );
    // An existing directory is opened, not made again.
    create_dir_all_in_root(root.path(), Path::new("/srv"), &mut |_, _| {
        panic!("nothing to make")
    })
    .unwrap();
}

#[test]
fn canonical_in_root_resolves_symlinked_mount_points() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("var/home/alice")).unwrap();
    // The decoy's /home is a link to var/home (as on an ostree host).
    symlink("var/home", root.path().join("home")).unwrap();

    let canon = |p: &str| canonical_in_root(root.path(), Path::new(p));
    // A symlinked mount point resolves to its real path inside the root, and so
    // does a path through it, whether or not the tail exists yet.
    assert_eq!(canon("/home"), Path::new("/var/home"));
    assert_eq!(canon("/home/alice"), Path::new("/var/home/alice"));
    assert_eq!(canon("/home/bob/x"), Path::new("/var/home/bob/x"));
    // A plain path with no symlink on the way is unchanged.
    assert_eq!(canon("/var/home"), Path::new("/var/home"));
    assert_eq!(canon("/srv/data"), Path::new("/srv/data"));
    // A relative path is returned as is (swap's `none`, an odd fstab target).
    assert_eq!(
        canonical_in_root(root.path(), Path::new("none")),
        Path::new("none")
    );
}

#[test]
fn canonical_in_root_follows_a_link_whose_target_is_not_there_yet() {
    // systemd's fstab generator follows a link to a mount point that does not
    // exist yet and mounts at the target, so the unit to mask is the target's.
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("var")).unwrap();
    symlink("var/data", root.path().join("data")).unwrap();
    // An absolute link resolves inside the root, also when it leads nowhere.
    symlink("/srv/backup", root.path().join("backup")).unwrap();
    // A link to a link that leads nowhere is followed through both.
    symlink("data", root.path().join("data2")).unwrap();
    // A loop of links resolves to nothing: the path comes back as it is.
    symlink("loop-b", root.path().join("loop-a")).unwrap();
    symlink("loop-a", root.path().join("loop-b")).unwrap();

    let canon = |p: &str| canonical_in_root(root.path(), Path::new(p));
    assert_eq!(canon("/data"), Path::new("/var/data"));
    assert_eq!(canon("/data/sub"), Path::new("/var/data/sub"));
    assert_eq!(canon("/backup"), Path::new("/srv/backup"));
    assert_eq!(canon("/data2"), Path::new("/var/data"));
    assert_eq!(canon("/loop-a"), Path::new("/loop-a"));
    assert_eq!(canon("/loop-a/x"), Path::new("/loop-a/x"));
}

#[test]
fn nothing_is_created_through_a_dangling_link_or_a_dot_dot() {
    let root = tempfile::tempdir().unwrap();
    symlink("/gone", root.path().join("away")).unwrap();
    let mut none = |_: BorrowedFd<'_>, _: &OsStr| -> io::Result<()> { panic!("nothing made") };
    assert!(create_dir_all_in_root(root.path(), Path::new("/away/x"), &mut none).is_err());
    assert!(create_dir_all_in_root(root.path(), Path::new("/a/../b"), &mut none).is_err());
    assert!(!root.path().join("gone").exists() && !root.path().join("a").exists());
}

#[test]
fn a_file_the_caller_does_not_own_is_read_without_o_noatime() {
    // The kernel refuses O_NOATIME (EPERM) on a file the caller neither
    // owns nor holds CAP_FOWNER for, and the read falls back to a plain
    // open. /proc/version is root's and has no access time to protect; as
    // root the first open already succeeds.
    let text = read_in_root(Path::new("/"), Path::new("/proc/version")).unwrap();
    assert!(text.starts_with(b"Linux version"), "{text:?}");
}

#[test]
fn a_missing_or_unusable_init_or_a_non_os_tree_is_refused() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("etc")).unwrap();
    std::fs::write(root.path().join("etc/os-release"), "ID=x\n").unwrap();
    assert!(matches!(
        precheck(root.path(), Path::new("/sbin/init")),
        Err(PrecheckError::InitMissing(..))
    ));
    std::fs::create_dir_all(root.path().join("sbin")).unwrap();
    std::fs::write(root.path().join("sbin/init"), "").unwrap();
    assert!(matches!(
        precheck(root.path(), Path::new("/sbin/init")),
        Err(PrecheckError::InitNotExecutable(_))
    ));
    std::fs::remove_file(root.path().join("etc/os-release")).unwrap();
    executable(&root.path().join("sbin/init"));
    assert_eq!(
        precheck(root.path(), Path::new("/sbin/init")),
        Err(PrecheckError::NotAnOsTree)
    );
}

#[test]
fn overlay_data_pins_the_feature_options_off() {
    let data = overlay_data(
        Path::new("/run/nextroot/lower"),
        Path::new("/mnt/data/root/upper"),
        Path::new("/mnt/data/root/work"),
    )
    .unwrap();
    assert_eq!(
        data,
        "lowerdir=/run/nextroot/lower,upperdir=/mnt/data/root/upper,\
         workdir=/mnt/data/root/work,index=off,metacopy=off,redirect_dir=nofollow"
    );
    // The dangerous on-states are never emitted, on any kernel's defaults.
    assert!(!data.contains("index=on"));
    assert!(!data.contains("metacopy=on"));
    // xino is left unpinned.
    assert!(!data.contains("xino"));
}

#[test]
fn overlay_params_are_the_mount_data_one_option_each() {
    // The probe hands these pairs to fsconfig(2) one by one, the real mount
    // joins them into its data string: both pass the kernel the same options.
    let (lower, upper, work) = (
        Path::new("/l,ower"),
        Path::new("/mnt/data/root/upper"),
        Path::new("/mnt/data/root/work"),
    );
    let params = overlay_params(lower, upper, work).unwrap();
    let expected: Vec<(&str, String)> = vec![
        ("lowerdir", "/l\\,ower".to_string()),
        ("upperdir", "/mnt/data/root/upper".to_string()),
        ("workdir", "/mnt/data/root/work".to_string()),
        ("index", "off".to_string()),
        ("metacopy", "off".to_string()),
        ("redirect_dir", "nofollow".to_string()),
    ];
    assert_eq!(params, expected);
    let joined: Vec<String> = params.iter().map(|(k, v)| format!("{k}={v}")).collect();
    assert_eq!(joined.join(","), overlay_data(lower, upper, work).unwrap());
}

#[test]
fn overlay_params_refuse_an_unescapable_layer() {
    let err = overlay_params(
        Path::new("/lower"),
        Path::new("/up\nper"),
        Path::new("/work"),
    )
    .expect_err("a newline cannot be an overlay option");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn overlay_data_escapes_awkward_layer_paths() {
    // A layer path with the characters the overlay option field escapes is
    // escaped once, so the pinned options still parse as their own fields.
    let data = overlay_data(
        Path::new("/l,ower"),
        Path::new("/up:per"),
        Path::new("/work"),
    )
    .unwrap();
    assert!(
        data.ends_with(&format!(",{OVERLAY_FEATURE_OPTIONS}")),
        "{data}"
    );
    assert!(data.contains("lowerdir=/l\\,ower"), "{data}");
    assert!(data.contains("upperdir=/up\\:per"), "{data}");
}

#[test]
fn mount_overlay_refuses_an_unescapable_layer_before_mounting() {
    // mount_overlay builds its option string with overlay_data before the
    // mount(2) syscall. A layer path that cannot be represented in a mount
    // option line (a newline, which escape_overlay_path rejects) makes that
    // step fail, so the real mount_overlay returns an error and never reaches
    // the kernel. This needs no privileges; it pins that mount_overlay does
    // the work overlay_data describes rather than reporting success blindly.
    let err = mount_overlay(
        Path::new("/run/nextroot/low\ner"),
        Path::new("/mnt/data/root/upper"),
        Path::new("/mnt/data/root/work"),
        Path::new("/run/nextroot"),
    )
    .expect_err("a newline in a layer path cannot be an overlay layer");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(
        err.to_string().contains("cannot be an overlay layer"),
        "{err}"
    );
}

#[test]
fn detach_under_takes_the_deepest_mounts_first_and_only_below_the_path() {
    // Not mounted in this test: nothing is detached, nothing panics, and
    // the selection is by path component, never by string prefix.
    let points = vec![
        PathBuf::from("/run/nextroot"),
        PathBuf::from("/run/nextroot/boot"),
        PathBuf::from("/run/nextrootx"),
    ];
    assert!(detach_under(Path::new("/nonexistent-root"), &points).is_empty());
}
