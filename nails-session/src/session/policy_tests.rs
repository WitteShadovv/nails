// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the fstab policy.

use super::*;
use crate::session::fstab::parse_fstab;
use nails_teardown::mountinfo::parse_mountinfo;

const HIDDEN: &str = "/mnt/data";

fn mounts() -> Vec<MountEntry> {
    parse_mountinfo(
        "1 0 8:2 / / rw,relatime - ext4 /dev/vda2 rw\n\
         2 1 8:1 / /boot rw - vfat /dev/vda1 rw\n\
         3 1 8:3 / /home rw - ext4 /dev/vda3 rw\n\
         4 1 8:4 / /srv ro - ext4 /dev/vda4 ro\n\
         5 1 0:5 / /tmp rw - tmpfs tmpfs rw\n\
         6 1 0:6 / /nix/.rw-store rw - tmpfs tmpfs rw\n\
         7 1 0:7 / /nix/store rw - overlay overlay rw,lowerdir=/nix/.ro-store,upperdir=/nix/.rw-store/store,workdir=/nix/.rw-store/work\n\
         8 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
         9 1 0:9 / /nix/.ro-store rw - 9p store rw,trans=virtio\n",
    )
}

fn decide_line(line: &str) -> Decision {
    let entries = parse_fstab(line);
    decide(&entries[0], &mounts(), Path::new(HIDDEN))
}

#[test]
fn boot_filesystems_and_read_only_mounts_are_bound_read_only() {
    assert_eq!(
        decide_line("UUID=AB /boot vfat umask=0077 0 2"),
        Decision::ReadOnlyBind {
            target: "/boot".into()
        }
    );
    assert_eq!(
        decide_line("/dev/vda4 /srv ext4 ro 0 2"),
        Decision::ReadOnlyBind {
            target: "/srv".into()
        }
    );
}

#[test]
fn other_mounted_local_filesystems_are_overlaid() {
    assert_eq!(
        decide_line("LABEL=home /home ext4 defaults 0 2"),
        Decision::Overlay {
            target: "/home".into()
        }
    );
}

#[test]
fn swap_unmounted_and_network_filesystems_are_masked() {
    assert_eq!(
        decide_line("/dev/vda5 none swap sw 0 0").masked_units(),
        ["dev-vda5.swap"]
    );
    assert_eq!(
        decide_line("/dev/sdb1 /data ext4 defaults 0 2").masked_units(),
        ["data.mount"]
    );
    assert_eq!(
        decide_line("/dev/sdb1 /data ext4 noauto,x-systemd.automount 0 2").masked_units(),
        ["data.mount", "data.automount"]
    );
    assert_eq!(
        decide_line("server:/export /net nfs4 defaults 0 0").masked_units(),
        ["net.mount"]
    );
}

#[test]
fn ram_kernel_noauto_root_and_hidden_entries_are_left_alone() {
    for line in [
        "/dev/vda2 / ext4 defaults 0 1",
        "tmpfs /tmp tmpfs defaults 0 0",
        "share /mnt/share virtiofs defaults 0 0",
        "/dev/sdb1 /mnt/usb vfat noauto 0 0",
        "/dev/mapper/data /mnt/data ext4 noauto 0 0",
        "overlay /var/cache overlay lowerdir=/usr,upperdir=/tmp/up,workdir=/tmp/w 0 0",
    ] {
        assert!(
            matches!(decide_line(line), Decision::Leave { .. }),
            "{line}: {:?}",
            decide_line(line)
        );
    }
}

#[test]
fn a_mounted_host_share_or_overlay_is_overlaid_into_the_next_root() {
    // A NixOS test VM: the store is an overlay of a 9p share and a tmpfs.
    for (line, target) in [
        ("store /nix/.ro-store 9p trans=virtio 0 0", "/nix/.ro-store"),
        (
            "overlay /nix/store overlay lowerdir=/nix/.ro-store,upperdir=/nix/.rw-store/store,workdir=/nix/.rw-store/work 0 0",
            "/nix/store",
        ),
    ] {
        assert_eq!(
            decide_line(line),
            Decision::Overlay {
                target: target.into()
            },
            "{line}"
        );
    }
}

#[test]
fn an_overlay_entry_with_its_upper_on_disk_is_masked() {
    assert_eq!(
        decide_line(
            "overlay /opt overlay lowerdir=/usr,upperdir=/persist/up,workdir=/persist/w 0 0"
        )
        .masked_units(),
        ["opt.mount"]
    );
}

#[test]
fn a_redirected_entry_inside_the_hidden_volume_is_masked() {
    // The decoy's /data entry, which a link the hidden session left leads
    // to /mnt/data/data: a decoy disk the hidden systemd would mount
    // read-write inside the hidden volume.
    let decide_redirected_line =
        |line: &str| decide_redirected(&parse_fstab(line)[0], &mounts(), Path::new(HIDDEN));
    assert_eq!(
        decide_redirected_line("UUID=X /mnt/data/data ext4 defaults,nofail 0 2").masked_units(),
        ["mnt-data-data.mount"]
    );
    assert_eq!(
        decide_redirected_line("UUID=X /mnt/data ext4 x-systemd.automount 0 2").masked_units(),
        ["mnt-data.mount", "mnt-data.automount"]
    );
    // Where the hidden volume's own rule leaves it: the bind is there.
    assert!(matches!(
        decide_line("UUID=X /mnt/data/data ext4 defaults,nofail 0 2"),
        Decision::Leave { .. }
    ));
    // Elsewhere, and for RAM or the root, the same decisions as decide.
    for line in [
        "tmpfs /mnt/data/tmp tmpfs defaults 0 0",
        "/dev/vda2 / ext4 defaults 0 1",
        "LABEL=home /home ext4 defaults 0 2",
        "/dev/sdb1 /data ext4 defaults 0 2",
    ] {
        assert_eq!(decide_redirected_line(line), decide_line(line), "{line}");
    }
}

#[test]
fn decisions_come_parents_first_and_odd_mount_points_are_refused() {
    let entries = parse_fstab(
        "/dev/vda6 /home/alice/media ext4 defaults 0 2\n\
         LABEL=home /home ext4 defaults 0 2\n\
         /dev/vda7 relative ext4 defaults 0 2\n",
    );
    let decisions = decide_all(&entries, &mounts(), Path::new(HIDDEN));
    assert!(matches!(&decisions[0], Decision::Refuse { .. }));
    assert_eq!(
        decisions[1],
        Decision::Overlay {
            target: "/home".into()
        }
    );
    assert!(matches!(&decisions[2], Decision::Mask { .. }));
    assert_eq!(masked_units(&decisions), ["home-alice-media.mount"]);
}

#[test]
fn the_automount_of_a_filesystem_put_in_place_is_masked_once() {
    // The ESP and /home behind automounts, both put in place; /data
    // masked with its automount; /srv put in place without one. The
    // hidden generation's fstab names /boot again.
    let fstab = parse_fstab(
        "UUID=AB /boot vfat umask=0077,x-systemd.automount 0 2
         LABEL=home /home ext4 x-systemd.automount,nofail 0 2
         /dev/sdb1 /data ext4 noauto,x-systemd.automount 0 2
         /dev/vda4 /srv ext4 ro 0 2
         UUID=AB /boot vfat x-systemd.automount 0 2
",
    );
    let decisions = decide_all(&fstab, &mounts(), Path::new(HIDDEN));
    assert_eq!(
        masks(&fstab, &decisions),
        [
            "data.mount",
            "data.automount",
            "boot.automount",
            "home.automount"
        ]
    );
}
