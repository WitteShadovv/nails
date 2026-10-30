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

/// What requires an entry's unit at boot, as systemd's fstab generator links
/// it: the boot target unless `nofail`, nothing for `noauto` without an
/// automount, the units `x-systemd.required-by=` names in the target's place.
#[test]
fn what_requires_an_entry_s_unit_is_read_as_the_generator_links_it() {
    let required = |line: &str| required_by(&parse_fstab(line)[0]);
    for (line, expected) in [
        ("/dev/sdb1 /data ext4 defaults 0 2", Some("local-fs.target")),
        ("/dev/sdb1 /data ext4 nofail 0 2", None),
        (
            "/dev/sdb1 /data ext4 nofail,fail 0 2",
            Some("local-fs.target"),
        ),
        ("/dev/sdb1 /data ext4 noauto 0 2", None),
        (
            "/dev/sdb1 /data ext4 noauto,auto 0 2",
            Some("local-fs.target"),
        ),
        (
            "/dev/sdb1 /data ext4 noauto,x-systemd.automount 0 2",
            Some("local-fs.target"),
        ),
        ("/dev/sdb1 /data ext4 _netdev 0 2", Some("remote-fs.target")),
        (
            "server:/export /net nfs4 defaults 0 0",
            Some("remote-fs.target"),
        ),
        ("server:/export /net nfs bg 0 0", None),
        (
            "server:/export /net nfs bg,x-systemd.automount 0 0",
            Some("remote-fs.target"),
        ),
        (
            "/dev/sdb1 /data ext4 x-systemd.wanted-by=a.service 0 2",
            None,
        ),
        (
            "/dev/sdb1 /data ext4 nofail,x-systemd.required-by=a.service,x-systemd.required-by=b.service 0 2",
            Some("a.service b.service"),
        ),
        ("/dev/vda5 none swap sw 0 0", Some("swap.target")),
        // swap.target up to systemd 260, remote-fs.target from 261 on.
        (
            "/dev/vda5 none swap sw,_netdev 0 0",
            Some("swap.target (remote-fs.target from systemd 261)"),
        ),
        ("/dev/vda5 none swap sw,nofail 0 0", None),
        ("/dev/vda5 none swap noauto 0 0", None),
        // A swap entry has no automount, so noauto keeps it out of the boot.
        ("/dev/vda5 none swap noauto,x-systemd.automount 0 0", None),
    ] {
        assert_eq!(required(line).as_deref(), expected, "{line}");
    }
}

/// The device an entry's unit waits for, and the units its fstab line has it
/// pull in that act on that device or its filesystem, named as the generator
/// names them.
#[test]
fn the_device_and_the_checkers_of_an_entry_are_named_as_the_generator_names_them() {
    let entry = |line: &str| parse_fstab(line).remove(0);
    let data = entry("LABEL=My\\040Data /srv/my-data ext4 x-systemd.makefs,x-systemd.growfs 0 2");
    assert_eq!(
        waits_for(&data).as_deref(),
        Some(Path::new("/dev/disk/by-label/My\\x20Data"))
    );
    assert_eq!(
        checkers(&data),
        [
            "systemd-fsck@dev-disk-by\\x2dlabel-My\\x5cx20Data.service",
            "systemd-makefs@dev-disk-by\\x2dlabel-My\\x5cx20Data.service",
            "systemd-growfs@srv-my\\x2ddata.service",
        ]
    );
    let checked = entry("/dev/sdb1 /srv ext4 x-systemd.pcrfs,x-systemd.validatefs,prjquota 0 0");
    assert_eq!(
        checkers(&checked),
        [
            "systemd-fsck@dev-sdb1.service",
            "systemd-pcrfs@srv.service",
            "systemd-validatefs@srv.service",
            "systemd-quotacheck@srv.service",
            "quotaon@srv.service",
        ]
    );
    // A bind, a network share, a swap file and the kernel's own names wait
    // for no device, and pull in no fsck.
    for line in [
        "/srv/src /data none bind 0 0",
        "/dev/shm/x /data none rbind 0 0",
        "server:/export /net nfs4 defaults 0 0",
        "/swapfile none swap sw 0 0",
        "/dev/root /data ext4 defaults 0 2",
        "/dev/nfs /data nfs defaults 0 0",
    ] {
        let entry = entry(line);
        assert_eq!(waits_for(&entry), None, "{line}");
        assert!(
            checkers(&entry).is_empty(),
            "{line}: {:?}",
            checkers(&entry)
        );
    }
    // A swap device's mkswap, and no fsck or filesystem unit.
    let swap = entry("/dev/vdb2 none swap x-systemd.makefs,x-systemd.growfs 0 0");
    assert_eq!(checkers(&swap), ["systemd-mkswap@dev-vdb2.service"]);
    assert!(checkers(&entry("/dev/vdb2 none swap sw 0 0")).is_empty());
}
