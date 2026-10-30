// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::session::fstab::parse_fstab;
use nails_teardown::mountinfo::parse_mountinfo;
use nails_teardown::whole_root::decoy_mounts::Why;

#[test]
fn the_initrd_s_ram_filesystems_that_are_mounted_are_carried() {
    let fstab = parse_fstab(
        "/dev/vda / ext4 x-initrd.mount 0 1\n\
         tmpfs /nix/.rw-store tmpfs mode=0755,x-initrd.mount 0 0\n\
         tmpfs /tmp tmpfs mode=1777 0 0\n\
         none /run/keys ramfs x-initrd.mount 0 0\n\
         tmpfs /mnt/data/cache tmpfs x-initrd.mount 0 0\n\
         tmpfs /var/unmounted tmpfs x-initrd.mount 0 0\n",
    );
    let mounts = parse_mountinfo(
        "1 0 253:0 / / rw - ext4 /dev/vda rw\n\
         2 1 0:31 / /nix/.rw-store rw - tmpfs tmpfs rw\n\
         3 1 0:32 / /tmp rw - tmpfs tmpfs rw\n\
         4 1 0:33 / /run rw - tmpfs tmpfs rw\n\
         5 4 0:34 / /run/keys rw - ramfs none rw\n\
         6 1 254:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
         7 6 0:35 / /mnt/data/cache rw - tmpfs tmpfs rw\n",
    );
    assert_eq!(
        initrd_ram_filesystems(&fstab, &mounts, Path::new("/mnt/data")),
        [PathBuf::from("/nix/.rw-store")]
    );
}

#[test]
fn the_hidden_volume_is_named_as_the_decoy_sees_it() {
    assert_eq!(
        hidden_in_decoy(&Paths::system(), Path::new("/no/such/mnt/data")),
        Path::new("/no/such/mnt/data")
    );
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("mnt/data")).unwrap();
    let paths = Paths {
        root: root.clone(),
        run: root.join("run"),
    };
    assert_eq!(
        hidden_in_decoy(&paths, &root.join("mnt/data")),
        Path::new("/mnt/data")
    );
    assert_eq!(
        hidden_in_decoy(&paths, Path::new("/elsewhere")),
        Path::new("/elsewhere")
    );
}

fn lost(target: &str, fstype: &str, why: Why) -> Lost {
    Lost {
        id: 90,
        target: PathBuf::from(target),
        fstype: fstype.to_string(),
        source: PathBuf::from("/dev/vdc"),
        why,
    }
}

#[test]
fn only_a_mount_lost_at_a_carried_filesystem_is_a_warning() {
    let carried = [CarriedMount {
        target: PathBuf::from("/srv/data"),
        at: PathBuf::from("/mnt/data/root/decoy/srv-data"),
        read_only: false,
        dev: Some("253:32".into()),
        root: Some(PathBuf::from("/")),
    }];
    let found = warnings(
        &[
            lost("/srv/data", "ext4", Why::NoWayBack),
            lost("/srv/data/sub", "ext4", Why::ParentLost),
            lost("/srv/data/remote", "fuse.sshfs", Why::NoWayBack),
            lost("/srv/data", "ext4", Why::Automounted),
            lost("/media/usb", "vfat", Why::NoWayBack),
            lost("/srv/database", "ext4", Why::NoWayBack),
        ],
        &carried,
        &KeptBySystemd {
            fstab: &[],
            initrd: Vec::new(),
        },
    );
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(
        found[0].contains("/srv/data (ext4 /dev/vdc)"),
        "{}",
        found[0]
    );
    assert!(found[0].contains("carries no mount"), "{}", found[0]);
    assert!(found[1].contains("/srv/data/sub"), "{}", found[1]);
    assert!(found[1].contains("does not come back"), "{}", found[1]);
}

#[test]
fn a_lost_mount_systemd_keeps_at_a_soft_reboot_is_a_warning() {
    // NixOS's /etc overlay, a separate /usr, and initrd mounts by the fstab
    // or by utab: a plain soft-reboot keeps each, and nothing but the next
    // boot may mount it again.
    let fstab = parse_fstab("tmpfs /srv/scratch tmpfs mode=0755,x-initrd.mount 0 0\n");
    let mut by_utab = lost("/srv/keys", "ramfs", Why::NoWayBack);
    by_utab.id = 41;
    let found = warnings(
        &[
            lost("/etc", "overlay", Why::NoWayBack),
            lost("/usr", "ext4", Why::NoWayBack),
            lost("/srv/scratch", "tmpfs", Why::NoWayBack),
            by_utab,
            // Neither carried nor kept by systemd: the debug log alone.
            lost("/srv/other", "tmpfs", Why::NoWayBack),
            lost("/etc/nested", "tmpfs", Why::NoWayBack),
        ],
        &[],
        &KeptBySystemd {
            fstab: &fstab,
            initrd: vec![41],
        },
    );
    let targets: Vec<&str> = found
        .iter()
        .map(|warning| warning.split(' ').nth(5).unwrap_or(""))
        .collect();
    assert_eq!(
        targets,
        ["/etc", "/usr", "/srv/scratch", "/srv/keys"],
        "{found:?}"
    );
    assert!(
        found
            .iter()
            .all(|w| w.contains("a plain soft-reboot keeps it")),
        "{found:?}"
    );
}

/// The mount unit systemd names for each carried filesystem starts with the
/// prefix of their directory up to the dash, which is what makes it read the
/// prefix's drop-ins for that unit.
#[test]
fn the_carried_filesystems_units_share_the_prefix_of_their_directory() {
    assert_eq!(
        carried_units_prefix(Path::new("/mnt/data/root/decoy")),
        "mnt-data-root-decoy-.mount"
    );
    assert_eq!(
        carried_units_prefix(Path::new("/mnt/my-data/root/decoy")),
        "mnt-my\\x2ddata-root-decoy-.mount"
    );
    let layout = Layout::new(Path::new("/mnt/data"));
    let prefix = carried_units_prefix(&layout.carried_dir());
    let stem = prefix.trim_end_matches(".mount");
    for target in ["/nix/.ro-store", "/boot", "/home", "/srv/my-share"] {
        let unit = crate::session::fstab::mount_unit(&layout.carried(Path::new(target)));
        let rest = unit.strip_prefix(stem).unwrap_or_else(|| panic!("{unit}"));
        assert!(!rest.contains('-'), "{unit}: one level below the prefix");
    }
    assert_eq!(
        crate::session::fstab::mount_unit(&layout.carried(Path::new("/nix/.ro-store"))),
        "mnt-data-root-decoy-nix\\x2d.ro\\x5cx2dstore.mount"
    );
}
