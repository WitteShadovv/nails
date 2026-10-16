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
