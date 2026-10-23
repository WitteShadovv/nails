// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the fstab view of the session.

use super::*;

#[test]
fn units_are_named_the_way_systemd_names_them() {
    assert_eq!(mount_unit(Path::new("/")), "-.mount");
    assert_eq!(mount_unit(Path::new("/boot/efi")), "boot-efi.mount");
    assert_eq!(mount_unit(Path::new("/home/")), "home.mount");
    assert_eq!(
        mount_unit(Path::new("/mnt/my-disk")),
        "mnt-my\\x2ddisk.mount"
    );
    assert_eq!(
        mount_unit(Path::new("/mnt/My Disk")),
        "mnt-My\\x20Disk.mount"
    );
    assert_eq!(mount_unit(Path::new("/.snapshots")), "\\x2esnapshots.mount");
    assert_eq!(automount_unit(Path::new("/srv/x")), "srv-x.automount");
    assert_eq!(swap_unit("/dev/vda3").as_deref(), Some("dev-vda3.swap"));
    assert_eq!(
        swap_unit("UUID=0a-1b").as_deref(),
        Some("dev-disk-by\\x2duuid-0a\\x2d1b.swap")
    );
    assert_eq!(swap_unit("/swapfile").as_deref(), Some("swapfile.swap"));
    assert_eq!(swap_unit("none"), None);
    // Simplified first, as systemd simplifies a path.
    assert_eq!(mount_unit(Path::new("/mnt/./data/.")), "mnt-data.mount");
    assert_eq!(
        swap_unit("/dev/disk/by-/./label/swap").as_deref(),
        Some("dev-disk-by\\x2d-label-swap.swap")
    );
}

/// A swap on a label with a space is the unit systemd-fstab-generator makes
/// for the link udev makes, `swap\x20space`, whose backslash the unit name
/// escapes again. Found by the `fstab_crypttab` fuzz target, when the unit
/// masked was `dev-disk-by\x2dlabel-swap\x20space.swap`.
#[test]
fn a_swap_on_a_label_is_the_unit_of_its_link() {
    assert_eq!(
        swap_unit("LABEL=swap space").as_deref(),
        Some("dev-disk-by\\x2dlabel-swap\\x5cx20space.swap")
    );
}

/// Every absolute mount point is resolved inside the root, through a symlink
/// to its real path; a swap's `none` and a relative target are kept as they are.
#[test]
fn entries_are_resolved_inside_the_root() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("var/home")).unwrap();
    std::os::unix::fs::symlink("var/home", root.path().join("home")).unwrap();
    let entries = parse_in_root(
        b"UUID=a /home ext4 defaults,x-systemd.automount 0 2\n\
          /dev/sdb1 /srv/data ext4 defaults 0 2\n\
          /dev/vda3 none swap sw 0 0\n\
          /dev/sdc1 relative ext4 defaults 0 2\n",
        root.path(),
    );
    let files: Vec<&Path> = entries.iter().map(|entry| entry.file.as_path()).collect();
    assert_eq!(
        files,
        [
            Path::new("/var/home"),
            Path::new("/srv/data"),
            Path::new("none"),
            Path::new("relative"),
        ]
    );
    // Everything else of an entry is as the fstab wrote it.
    assert_eq!(entries[0].spec, "UUID=a");
    assert!(entries[0].is_automount());
    assert_eq!(automount_unit(&entries[0].file), "var-home.automount");
}

/// A missing fstab has no entries; one that cannot be read is an error.
#[test]
fn only_a_missing_fstab_reads_as_empty() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("etc")).unwrap();
    assert_eq!(read_in_root(root.path()).unwrap(), b"");

    std::fs::write(
        root.path().join("etc/fstab"),
        "/dev/vda2 / ext4 defaults 0 1\n",
    )
    .unwrap();
    assert_eq!(
        read_in_root(root.path()).unwrap(),
        b"/dev/vda2 / ext4 defaults 0 1\n"
    );

    std::fs::remove_file(root.path().join("etc/fstab")).unwrap();
    std::fs::create_dir(root.path().join("etc/fstab")).unwrap();
    let error = read_in_root(root.path()).unwrap_err();
    assert_ne!(error.kind(), std::io::ErrorKind::NotFound, "{error}");
}
