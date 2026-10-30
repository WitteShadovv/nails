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

/// No device is there.
fn absent(_: &Path) -> bool {
    false
}

/// Every device is there.
fn present(_: &Path) -> bool {
    true
}

/// The decision for the first entry of `line`, with no device there.
fn decide_line(line: &str) -> Decision {
    let entries = parse_fstab(line);
    decide(&entries[0], &mounts(), Path::new(HIDDEN), &absent)
}

/// The decision for the first entry of `line`, with every device there.
fn decide_present(line: &str) -> Decision {
    let entries = parse_fstab(line);
    decide(&entries[0], &mounts(), Path::new(HIDDEN), &present)
}

/// The units a decision skips, and those they pull in.
fn skipped(decision: &Decision) -> (Vec<String>, Vec<String>) {
    let skip = decision.skip().expect("a skip");
    (skip.units.clone(), skip.pulled.clone())
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
fn swap_unmounted_and_network_filesystems_are_kept_off() {
    // Their devices are not there: masked.
    assert_eq!(
        decide_line("/dev/vda5 none swap sw 0 0").masked_units(),
        ["dev-vda5.swap"]
    );
    assert_eq!(
        decide_line("/dev/sdb1 /data ext4 defaults 0 2").masked_units(),
        ["data.mount"]
    );
    // An automount waits for no device: local-fs.target requires it, so it
    // is skipped, and the mount behind it, which nothing starts then, masked.
    let automount = decide_line("/dev/sdb1 /data ext4 noauto,x-systemd.automount 0 2");
    assert_eq!(automount.masked_units(), ["data.mount"]);
    assert_eq!(skipped(&automount), (vec!["data.automount".into()], vec![]));
    // A network filesystem has no device to wait for: remote-fs.target
    // requires it, so it is skipped.
    let network = decide_line("server:/export /net nfs4 defaults 0 0");
    assert!(network.masked_units().is_empty(), "{network:?}");
    assert_eq!(skipped(&network), (vec!["net.mount".into()], vec![]));
    assert_eq!(network.skip().unwrap().device, None);
}

#[test]
fn a_unit_a_boot_target_requires_is_skipped_while_its_device_is_there() {
    // A mount local-fs.target requires: skipped, with every unit its fstab
    // line has it pull in that acts on the disk.
    let data = decide_present(
        "/dev/sdb1 /data ext4 defaults,x-systemd.makefs,x-systemd.growfs,usrquota 0 2",
    );
    assert_eq!(
        skipped(&data),
        (
            vec!["data.mount".into()],
            [
                "systemd-fsck@dev-sdb1.service",
                "systemd-makefs@dev-sdb1.service",
                "systemd-growfs@data.service",
                "systemd-quotacheck@data.service",
                "quotaon@data.service",
            ]
            .map(String::from)
            .to_vec()
        )
    );
    assert_eq!(
        data.skip().unwrap().device.as_deref(),
        Some(Path::new("/dev/sdb1"))
    );
    assert!(data.masked_units().is_empty());
    assert_eq!(
        data.describe(),
        "/data: skipped (not mounted now; the hidden session would mount it read-write)"
    );
    assert_eq!(data.warning(), None);

    // A swap line swap.target requires, on a tag, with its mkswap.
    let swap = decide_present("UUID=0a-1b none swap defaults,x-systemd.makefs 0 0");
    assert_eq!(
        skipped(&swap),
        (
            vec!["dev-disk-by\\x2duuid-0a\\x2d1b.swap".into()],
            vec!["systemd-mkswap@dev-disk-by\\x2duuid-0a\\x2d1b.service".into()]
        )
    );
    assert_eq!(
        swap.skip().unwrap().device.as_deref(),
        Some(Path::new("/dev/disk/by-uuid/0a-1b"))
    );

    // A swap file and a bind wait for no device: skipped either way.
    for line in [
        "/swapfile none swap sw 0 0",
        "/srv/src /data none bind 0 0",
        "overlay /opt overlay lowerdir=/usr,upperdir=/persist/up,workdir=/persist/w 0 0",
    ] {
        let decision = decide_line(line);
        let skip = decision
            .skip()
            .unwrap_or_else(|| panic!("{line}: {decision:?}"));
        assert_eq!(skip.device, None, "{line}");
        assert!(skip.pulled.is_empty(), "{line}: {:?}", skip.pulled);
    }

    // A local mount marked _netdev is a network filesystem to systemd, on a
    // device it waits for all the same.
    let iscsi = decide_present("/dev/sdc1 /iscsi ext4 _netdev 0 0");
    assert_eq!(
        skipped(&iscsi),
        (
            vec!["iscsi.mount".into()],
            vec!["systemd-fsck@dev-sdc1.service".into()]
        )
    );
}

#[test]
fn a_required_unit_whose_device_is_not_there_is_masked_with_a_warning() {
    // A skipped mount would wait for the device until the timeout and then
    // start emergency mode; the mask keeps the hidden session from waiting,
    // and leaves local-fs.target unreached, which the warning says.
    let data = decide_line("/dev/sdb1 /data ext4 defaults 0 2");
    assert_eq!(
        data,
        Decision::Mask {
            target: "/data".into(),
            units: vec!["data.mount".into()],
            reason: "not mounted now; the hidden session would mount it read-write",
            unreached: Some(Unreached {
                target: "local-fs.target".into(),
                cause: Unskippable::NoDevice("/dev/sdb1".into()),
                native: false,
            }),
        }
    );
    let warning = data.warning().expect("a warning");
    for part in ["/data", "/dev/sdb1", "local-fs.target", "nofail"] {
        assert!(warning.contains(part), "{part}: {warning}");
    }
    let swap = decide_line("LABEL=swap none swap sw 0 0");
    assert!(
        matches!(&swap, Decision::Mask { unreached: Some(u), .. } if u.target == "swap.target"),
        "{swap:?}"
    );
    let netdev_swap = decide_line("/dev/sdd2 none swap sw,_netdev 0 0");
    assert!(
        matches!(&netdev_swap, Decision::Mask { unreached: Some(u), .. } if u.target == "swap.target (remote-fs.target from systemd 261)"),
        "{netdev_swap:?}"
    );
}

#[test]
fn a_unit_no_boot_target_requires_stays_masked() {
    // nofail (the target only wants it), x-systemd.wanted-by= alone, an NFS
    // background mount (the generator makes it nofail), a swap line that is
    // noauto or nofail: a masked unit there keeps no target from being
    // reached, and starts nothing.
    for line in [
        "/dev/sdb1 /data ext4 defaults,nofail 0 2",
        "/dev/sdb1 /data ext4 nofail,x-systemd.automount 0 2",
        "/dev/sdb1 /data ext4 x-systemd.wanted-by=multi-user.target 0 2",
        "server:/export /net nfs bg 0 0",
        "/dev/vda5 none swap sw,noauto 0 0",
        "/dev/vda5 none swap sw,nofail 0 0",
    ] {
        for decision in [decide_line(line), decide_present(line)] {
            assert!(
                matches!(
                    &decision,
                    Decision::Mask {
                        unreached: None,
                        ..
                    }
                ),
                "{line}: {decision:?}"
            );
            assert_eq!(decision.warning(), None, "{line}");
        }
    }
    // A unit x-systemd.required-by= names a unit for is skipped, an NFS mount
    // in the foreground too.
    for line in [
        "/dev/sdb1 /data ext4 nofail,x-systemd.required-by=backup.service 0 2",
        "server:/export /net nfs bg,fg 0 0",
    ] {
        assert!(decide_present(line).skip().is_some(), "{line}");
    }
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
fn an_overlay_entry_with_its_upper_on_disk_is_kept_off() {
    // local-fs.target requires it, and it waits for no device: skipped.
    let opt = decide_line(
        "overlay /opt overlay lowerdir=/usr,upperdir=/persist/up,workdir=/persist/w 0 0",
    );
    assert_eq!(skipped(&opt), (vec!["opt.mount".into()], vec![]));
    assert_eq!(
        decide_line(
            "overlay /opt overlay lowerdir=/usr,upperdir=/persist/up,workdir=/persist/w,nofail 0 0"
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
    let decide_redirected_line = |line: &str| {
        decide_redirected(&parse_fstab(line)[0], &mounts(), Path::new(HIDDEN), &absent)
    };
    assert_eq!(
        decide_redirected_line("UUID=X /mnt/data/data ext4 defaults,nofail 0 2").masked_units(),
        ["mnt-data-data.mount"]
    );
    let automount = decide_redirected_line("UUID=X /mnt/data ext4 x-systemd.automount 0 2");
    assert_eq!(automount.masked_units(), ["mnt-data.mount"]);
    assert_eq!(
        skipped(&automount),
        (vec!["mnt-data.automount".into()], vec![])
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
    let decisions = decide_all(&entries, &mounts(), Path::new(HIDDEN), &absent);
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
fn the_automount_of_a_filesystem_put_in_place_is_kept_off_once() {
    // The ESP and /home behind automounts, both put in place; /data kept
    // unmounted behind its automount; /srv put in place without one. The
    // hidden generation's fstab names /boot again. local-fs.target requires
    // the automounts of /boot and /data, which are skipped, and only wants
    // that of /home, which is masked.
    let fstab = parse_fstab(
        "UUID=AB /boot vfat umask=0077,x-systemd.automount 0 2
         LABEL=home /home ext4 x-systemd.automount,nofail 0 2
         /dev/sdb1 /data ext4 noauto,x-systemd.automount 0 2
         /dev/vda4 /srv ext4 ro 0 2
         UUID=AB /boot vfat x-systemd.automount 0 2
",
    );
    let decisions = decide_all(&fstab, &mounts(), Path::new(HIDDEN), &absent);
    let kept = runtime_units(&fstab, &decisions);
    assert_eq!(kept.masks, ["data.mount", "home.automount"]);
    let skipped: Vec<&[String]> = kept.skips.iter().map(|s| s.units.as_slice()).collect();
    assert_eq!(skipped, [["data.automount"], ["boot.automount"]]);
    assert!(
        kept.skips
            .iter()
            .all(|s| s.pulled.is_empty() && s.device.is_none())
    );
    assert_eq!(masks(&fstab, &decisions), kept.masks);
}

#[test]
fn two_fstabs_that_disagree_about_a_unit_keep_it_masked() {
    // The decoy's fstab requires /data, the hidden generation's only wants
    // it: the hidden systemd reads the latter, where a mask reaches every
    // target, and a skip made for the decoy's line could miss a checker of
    // the hidden line.
    let decoy = parse_fstab(
        "/dev/sdb1 /data ext4 defaults 0 2
",
    );
    let hidden = parse_fstab(
        "/dev/sdb1 /data ext4 defaults,nofail,x-systemd.makefs 0 2
",
    );
    let mut decisions = decide_all(&decoy, &mounts(), Path::new(HIDDEN), &present);
    decisions.extend(decide_all(&hidden, &mounts(), Path::new(HIDDEN), &present));
    let fstab: Vec<FstabEntry> = decoy.iter().chain(&hidden).cloned().collect();
    let kept = runtime_units(&fstab, &decisions);
    assert_eq!(kept.masks, ["data.mount"]);
    assert!(kept.skips.is_empty(), "{:?}", kept.skips);
    let conflict = [RequiredMask {
        unit: "data.mount".into(),
        cause: MaskCause::ConflictingLines,
        device: None,
    }];
    assert_eq!(kept.required_masks, conflict);

    // Both require it: one skip, pulling in what either line pulls in.
    let hidden = parse_fstab(
        "/dev/sdb1 /data ext4 defaults,x-systemd.makefs 0 2
",
    );
    let mut decisions = decide_all(&decoy, &mounts(), Path::new(HIDDEN), &present);
    decisions.extend(decide_all(&hidden, &mounts(), Path::new(HIDDEN), &present));
    let kept = runtime_units(&fstab, &decisions);
    assert!(kept.masks.is_empty(), "{:?}", kept.masks);
    assert!(kept.required_masks.is_empty(), "{:?}", kept.required_masks);
    assert_eq!(
        kept.skips,
        [Skip {
            units: vec!["data.mount".into()],
            pulled: vec![
                "systemd-fsck@dev-sdb1.service".into(),
                "systemd-makefs@dev-sdb1.service".into()
            ],
            device: Some("/dev/sdb1".into()),
        }]
    );

    // On two devices: which one the hidden systemd waits for depends on the
    // fstab it reads, so the unit is masked.
    let hidden = parse_fstab(
        "/dev/sdc1 /data ext4 defaults 0 2
",
    );
    let mut decisions = decide_all(&decoy, &mounts(), Path::new(HIDDEN), &present);
    decisions.extend(decide_all(&hidden, &mounts(), Path::new(HIDDEN), &present));
    let kept = runtime_units(&fstab, &decisions);
    assert_eq!(kept.masks, ["data.mount"]);
    assert!(kept.skips.is_empty(), "{:?}", kept.skips);
    assert_eq!(kept.required_masks, conflict);
}

#[test]
fn a_required_unit_masked_for_its_absent_device_is_recorded_with_it() {
    // What `status` lists: the mask of a unit a boot target requires, its
    // device not there, once although two fstabs name it; neither a mask no
    // target needs nor a skip.
    let fstab = parse_fstab(
        "/dev/sdb1 /data ext4 defaults 0 2
         /dev/sdb2 /media ext4 nofail 0 2
         /dev/sdb1 /data ext4 defaults 0 2
",
    );
    let decisions = decide_all(&fstab, &mounts(), Path::new(HIDDEN), &absent);
    let kept = runtime_units(&fstab, &decisions);
    assert_eq!(kept.masks, ["data.mount", "media.mount"]);
    assert_eq!(
        kept.required_masks,
        [RequiredMask {
            unit: "data.mount".into(),
            cause: MaskCause::DeviceAbsent,
            device: Some("/dev/sdb1".into()),
        }]
    );
    let kept = runtime_units(
        &fstab,
        &decide_all(&fstab, &mounts(), Path::new(HIDDEN), &present),
    );
    assert!(kept.required_masks.is_empty(), "{:?}", kept.required_masks);
    assert_eq!(kept.skips.len(), 1, "{:?}", kept.skips);
}

#[test]
fn deciding_an_fstab_twice_keeps_off_what_deciding_it_once_does() {
    // The hidden generation's fstab often repeats the decoy's.
    let fstab = parse_fstab(
        "UUID=AB /boot vfat umask=0077,x-systemd.automount 0 2
         /dev/sdb1 /data ext4 defaults,x-systemd.makefs 0 2
         /dev/sdb2 /media ext4 nofail 0 2
         server:/export /net nfs4 defaults 0 0
         /dev/vda5 none swap sw 0 0
",
    );
    for devices in [present as fn(&Path) -> bool, absent] {
        let once = decide_all(&fstab, &mounts(), Path::new(HIDDEN), &devices);
        let twice: Vec<Decision> = once.iter().chain(&once).cloned().collect();
        let doubled: Vec<FstabEntry> = fstab.iter().chain(&fstab).cloned().collect();
        assert_eq!(
            runtime_units(&doubled, &twice),
            runtime_units(&fstab, &once)
        );
    }
}

#[test]
fn a_device_without_its_node_is_not_there() {
    assert!(!device_present(Path::new(
        "/dev/disk/by-id/nails-test-no-such-disk"
    )));
}
