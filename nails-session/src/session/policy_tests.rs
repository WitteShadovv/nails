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
                origin: Origin::Fstab,
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
fn ram_kernel_noauto_and_root_entries_are_left_alone() {
    for line in [
        "/dev/vda2 / ext4 defaults 0 1",
        "tmpfs /tmp tmpfs defaults 0 0",
        "share /mnt/share virtiofs defaults 0 0",
        "/dev/sdb1 /mnt/usb vfat noauto 0 0",
        "overlay /var/cache overlay lowerdir=/usr,upperdir=/tmp/up,workdir=/tmp/w 0 0",
    ] {
        assert!(
            matches!(decide_line(line), Decision::Leave { .. }),
            "{line}: {:?}",
            decide_line(line)
        );
    }
}

/// The decision for the first entry of `line` with the hidden volume at
/// `root`, mounted there, and every device there.
fn decide_below(root: &str, line: &str) -> Decision {
    let mounts = parse_mountinfo(&format!(
        "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n\
         2 1 253:0 / {root} rw - ext4 /dev/mapper/data rw\n\
         3 2 8:17 / {root}/backup rw - ext4 /dev/vdb1 rw\n"
    ));
    decide(&parse_fstab(line)[0], &mounts, Path::new(root), &present)
}

#[test]
fn every_entry_at_or_below_the_hidden_root_is_refused() {
    // The hidden volume is bound at /mnt in the hidden root: the hidden
    // systemd would mount each of these over it or inside it. The decoy's own
    // disk mounted there now, a RAM filesystem, a noauto line that a unit or a
    // plain mount pulls in, an automount and a line for the hidden volume
    // itself alike.
    for line in [
        "/dev/mapper/data /mnt ext4 noauto 0 0",
        "/dev/vdb1 /mnt/backup ext4 defaults 0 2",
        "tmpfs /mnt/ram tmpfs defaults 0 0",
        "/dev/sdb1 /mnt/usb vfat noauto 0 0",
        "/dev/sdb2 /mnt/archive ext4 noauto,x-systemd.automount 0 2",
        "/dev/sdb3 /mnt/media/disk ext4 defaults,nofail 0 2",
    ] {
        let decision = decide_below("/mnt", line);
        let Decision::Refuse { reason, .. } = &decision else {
            panic!("{line}: {decision:?}");
        };
        assert!(
            reason.contains("at or below /mnt, where the hidden volume is mounted"),
            "{line}: {reason}"
        );
        // What to do names the root: mount the volume elsewhere, or move the
        // decoy's mount.
        assert_eq!(
            decision.remedy(Whose::Decoy).as_deref(),
            Some(
                "Mount the hidden volume where the decoy mounts nothing, or move this mount out \
                 from below /mnt or remove it, before activating."
            ),
            "{line}"
        );
        assert!(decision.masked_units().is_empty(), "{line}: {decision:?}");
    }
    // Swap has no mount point, and is kept off as always.
    assert_eq!(
        skipped(&decide_below("/mnt", "/dev/vdb2 none swap sw 0 0")),
        (vec!["dev-vdb2.swap".to_string()], vec![])
    );
    // A path that only begins with the root's name is not below it.
    assert!(matches!(
        decide_below("/mnt", "/dev/sdb4 /mnt2 ext4 noauto 0 0"),
        Decision::Leave { .. }
    ));
    assert_eq!(
        decide_below("/mnt", "/dev/sdb4 /mnt2 ext4 defaults,nofail 0 2").masked_units(),
        ["mnt2.mount"]
    );
    // An odd mount point is refused as before, with no remedy of its own.
    let odd = decide_below("/mnt", "/dev/sdb5 mnt/x ext4 defaults 0 2");
    for whose in [
        Whose::Decoy,
        Whose::HiddenSystem,
        Whose::HiddenSession,
        Whose::HiddenRoot,
    ] {
        assert_eq!(odd.remedy(whose), None);
    }
    assert_eq!(
        odd.fstab_refusal(Whose::Decoy).as_deref(),
        Some("fstab entry mnt/x: the mount point is not a plain absolute path")
    );
    // In the hidden session's own fstab too, which says whose it is.
    assert_eq!(
        odd.fstab_refusal(Whose::HiddenSession).as_deref(),
        Some(
            "the hidden session's fstab entry mnt/x: the mount point is not a plain absolute \
             path"
        )
    );
}

/// The decision for the first entry of `line` as a line of the next root's
/// own fstab, with the hidden volume at `/mnt/data`, mounted there, and
/// every device there or none (`there`).
fn decide_hidden(line: &str, there: bool) -> Decision {
    let mounts = parse_mountinfo(
        "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n\
         2 1 8:3 / /home rw - ext4 /dev/vda3 rw\n\
         3 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
         4 3 8:17 / /mnt/data/backup rw - ext4 /dev/vdb1 rw\n",
    );
    let devices = |_: &Path| there;
    decide_hidden_fstab(&parse_fstab(line)[0], &mounts, Path::new(HIDDEN), &devices)
}

#[test]
fn every_entry_of_the_hidden_fstab_at_or_below_the_hidden_root_is_kept_off() {
    // What decide refuses, a line of the next root's own fstab keeps off:
    // the hidden volume's own line, a disk mounted there now, a RAM
    // filesystem, a noauto line, an automount and a nofail line, each under
    // the names systemd gives its units, never left to the hidden systemd or
    // put in place.
    let skip = |units: &[&str], pulled: &[&str], device: Option<&str>| Skip {
        units: units.iter().map(|unit| unit.to_string()).collect(),
        pulled: pulled.iter().map(|unit| unit.to_string()).collect(),
        device: device.map(PathBuf::from),
    };
    let mask = |target: &str, units: &[&str]| Decision::Mask {
        target: target.into(),
        units: units.iter().map(|unit| unit.to_string()).collect(),
        reason: KEPT_BELOW,
        unreached: None,
    };
    let cases = [
        (
            "/dev/mapper/data /mnt/data ext4 defaults 0 2",
            Decision::Skip {
                target: "/mnt/data".into(),
                skip: skip(
                    &["mnt-data.mount"],
                    &["systemd-fsck@dev-mapper-data.service"],
                    Some("/dev/mapper/data"),
                ),
                masked: Vec::new(),
                reason: KEPT_BELOW,
            },
        ),
        (
            "/dev/vdb1 /mnt/data/backup ext4 defaults 0 2",
            Decision::Skip {
                target: "/mnt/data/backup".into(),
                skip: skip(
                    &["mnt-data-backup.mount"],
                    &["systemd-fsck@dev-vdb1.service"],
                    Some("/dev/vdb1"),
                ),
                masked: Vec::new(),
                reason: KEPT_BELOW,
            },
        ),
        (
            "tmpfs /mnt/data/ram tmpfs defaults 0 0",
            Decision::Skip {
                target: "/mnt/data/ram".into(),
                skip: skip(&["mnt-data-ram.mount"], &[], None),
                masked: Vec::new(),
                reason: KEPT_BELOW,
            },
        ),
        (
            "/dev/sdb1 /mnt/data/usb vfat noauto 0 0",
            mask("/mnt/data/usb", &["mnt-data-usb.mount"]),
        ),
        (
            "/dev/sdb2 /mnt/data/archive ext4 noauto,x-systemd.automount 0 2",
            Decision::Skip {
                target: "/mnt/data/archive".into(),
                skip: skip(&["mnt-data-archive.automount"], &[], None),
                masked: vec!["mnt-data-archive.mount".into()],
                reason: KEPT_BELOW,
            },
        ),
        (
            "/dev/sdb3 /mnt/data/media/disk ext4 defaults,nofail 0 2",
            mask("/mnt/data/media/disk", &["mnt-data-media-disk.mount"]),
        ),
    ];
    for (line, expected) in cases {
        assert_eq!(decide_hidden(line, true), expected, "{line}");
    }
    // A disk a boot target requires whose device is not there is masked,
    // and the mask warns that the target is not reached.
    let absent_disk = decide_hidden("/dev/vdb9 /mnt/data/gone ext4 defaults 0 2", false);
    assert_eq!(absent_disk.masked_units(), ["mnt-data-gone.mount"]);
    assert!(absent_disk.warning().is_some(), "{absent_disk:?}");
}

#[test]
fn an_entry_of_the_hidden_fstab_elsewhere_is_decided_as_the_decoy_s() {
    let mounts = parse_mountinfo(
        "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n\
         2 1 8:3 / /home rw - ext4 /dev/vda3 rw\n\
         3 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n",
    );
    for line in [
        "/dev/vda2 / ext4 defaults 0 1",
        "/dev/vda3 /home ext4 noatime 0 2",
        "/dev/vdc1 /srv/backup ext4 defaults 0 2",
        "/dev/vdc2 /srv/media ext4 defaults,nofail 0 2",
        "/dev/vdc3 /srv/later ext4 noauto 0 0",
        "tmpfs /tmp tmpfs defaults 0 0",
        "server:/export /net nfs4 defaults 0 0",
        "/dev/vda4 none swap sw 0 0",
        // A swap file on the hidden volume has no mount point there.
        "/mnt/data/swapfile none swap sw 0 0",
        // A parent of the hidden root, not mounted now: kept off as the
        // decoy's line would be, so nothing covers the hidden volume.
        "/dev/vdc4 /mnt ext4 defaults 0 2",
        "/dev/vdc5 mnt/relative ext4 defaults 0 2",
    ] {
        let entry = &parse_fstab(line)[0];
        for devices in [present as fn(&Path) -> bool, absent] {
            assert_eq!(
                decide_hidden_fstab(entry, &mounts, Path::new(HIDDEN), &devices),
                decide(entry, &mounts, Path::new(HIDDEN), &devices),
                "{line}"
            );
        }
    }
}

#[test]
fn the_warning_for_a_line_kept_off_names_it_the_root_and_what_to_do() {
    let line = "/dev/vdd1 /mnt/data/archive ext4 defaults 0 2";
    let entry = &parse_fstab(line)[0];
    let root = Path::new(HIDDEN);
    // Only its units are kept off: the line stays in the file, which a plain
    // mount reads.
    let what = "lies at or below /mnt/data, where the hidden volume is mounted: its units are \
                kept off, so the hidden systemd does not mount it over the hidden volume or \
                inside it, though a plain `mount` in the session still would";
    // The hidden NixOS system's: its configuration has the line.
    assert_eq!(
        kept_below_warning(entry, line, root, Whose::HiddenSystem),
        Some(format!(
            "the hidden NixOS system's fstab entry /mnt/data/archive (`{line}`) {what}\nIn the \
             hidden session, remove this mount from the hidden NixOS configuration, or move it \
             out from below /mnt/data there, and rebuild."
        ))
    );
    // The hidden session's own: its /etc/fstab has the line.
    let session = kept_below_warning(entry, line, root, Whose::HiddenSession).unwrap();
    assert_eq!(
        session,
        format!(
            "the hidden session's fstab entry /mnt/data/archive (`{line}`) {what}\nIn the hidden \
             session, remove this line from /etc/fstab, or move its mount out from below \
             /mnt/data."
        )
    );
    assert!(!session.contains("decoy"), "{session}");
    // An entry the policy refuses there has no such remedy.
    for whose in [Whose::Decoy, Whose::HiddenRoot] {
        let warning = kept_below_warning(entry, line, root, whose).unwrap();
        assert!(!warning.contains('\n'), "{warning}");
    }
    // No warning for an entry elsewhere, nor for a swap file below the root.
    for line in [
        "/dev/vdd1 /mnt/data2 ext4 defaults 0 2",
        "/dev/vdd1 /srv/archive ext4 defaults 0 2",
        "/mnt/data/swapfile none swap sw 0 0",
    ] {
        let entry = &parse_fstab(line)[0];
        assert_eq!(
            kept_below_warning(entry, line, root, Whose::HiddenSession),
            None,
            "{line}"
        );
    }
    // Nor below a hidden root of /, which validation refuses anyway.
    assert_eq!(
        kept_below_warning(entry, line, Path::new("/"), Whose::HiddenSession),
        None
    );
}

#[test]
fn a_refusal_of_the_hidden_session_s_fstab_below_the_root_says_to_change_it_there() {
    let decision = decide_below("/mnt/data", "/dev/sdb1 /mnt/data/usb vfat noauto 0 0");
    assert_eq!(
        decision.remedy(Whose::HiddenSession).as_deref(),
        Some(
            "Remove this line from /etc/fstab, or move its mount out from below /mnt/data, in a \
             hidden session."
        )
    );
    assert!(
        decision
            .fstab_refusal(Whose::HiddenSession)
            .unwrap()
            .starts_with("the hidden session's fstab entry /mnt/data/usb: it lies at or below")
    );
}

#[test]
fn a_refusal_below_the_hidden_root_says_what_to_do_about_whose_mount_it_is() {
    let decision = decide_below("/mnt/data", "/dev/sdb1 /mnt/data/usb vfat noauto 0 0");
    let reason = "it lies at or below /mnt/data, where the hidden volume is mounted: the hidden \
                  session could mount it over the hidden volume or inside it";
    // The decoy's fstab line: mount the volume elsewhere or move the line.
    assert_eq!(
        decision.fstab_refusal(Whose::Decoy),
        Some(format!(
            "fstab entry /mnt/data/usb: {reason}. Mount the hidden volume where the decoy mounts \
             nothing, or move this mount out from below /mnt/data or remove it, before \
             activating."
        ))
    );
    // A hidden NixOS generation's: its configuration has the line, and a
    // session entered without the build can change it. The decoy is not named.
    let hidden = decision.fstab_refusal(Whose::HiddenSystem).unwrap();
    assert_eq!(
        hidden,
        format!(
            "the hidden NixOS system's fstab entry /mnt/data/usb: {reason}. Remove this mount \
             from the hidden NixOS configuration, or move it out from below /mnt/data there, in \
             a hidden session entered with `activate --overlay-only`."
        )
    );
    // A unit activation decides in the hidden root, which may be the hidden
    // system's: the decoy is not named either.
    let unit = decision.unit_refusal();
    assert_eq!(
        unit,
        format!(
            "/mnt/data/usb: refused ({reason}). Mount the hidden volume where no mount unit \
             mounts anything, or move this mount out from below /mnt/data or remove its unit, \
             before activating."
        )
    );
    for text in [&hidden, &unit] {
        assert!(!text.contains("decoy"), "{text}");
    }
    // Any other decision is no refusal.
    let overlaid = decide_below("/mnt/data", "/dev/vda3 /home ext4 defaults 0 2");
    assert_eq!(overlaid.fstab_refusal(Whose::Decoy), None);
}

#[test]
fn an_entry_at_a_parent_of_the_hidden_root_is_decided_as_before() {
    // The hidden volume at /mnt/data, on a decoy disk mounted at /mnt: that
    // disk is overlaid like any other, and the hidden volume bound again over
    // it at entry.
    let mounts = parse_mountinfo(
        "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n\
         2 1 8:17 / /mnt rw - ext4 /dev/vdb1 rw\n\
         3 2 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n",
    );
    let entry = &parse_fstab("/dev/vdb1 /mnt ext4 defaults 0 2")[0];
    assert_eq!(
        decide(entry, &mounts, Path::new("/mnt/data"), &present),
        Decision::Overlay {
            target: "/mnt".into()
        }
    );
    // Not mounted now: kept off, as before.
    assert_eq!(
        decide_line("/dev/vdb1 /mnt ext4 defaults,nofail 0 2").masked_units(),
        ["mnt.mount"]
    );
}

#[test]
fn a_noauto_entry_a_named_unit_pulls_in_is_kept_off_not_left() {
    // systemd's fstab generator links such an entry's mount into the named
    // unit's directory whatever noauto says: left alone, the hidden systemd
    // would mount the disk read-write when that unit starts.
    let wanted =
        decide_present("/dev/vdb1 /srv/x ext4 noauto,x-systemd.wanted-by=multi-user.target 0 2");
    assert_eq!(wanted.masked_units(), ["srv-x.mount"], "{wanted:?}");
    let required =
        decide_present("/dev/vdb1 /srv/x ext4 noauto,x-systemd.required-by=multi-user.target 0 2");
    assert_eq!(
        skipped(&required),
        (
            vec!["srv-x.mount".to_string()],
            vec!["systemd-fsck@dev-vdb1.service".to_string()]
        )
    );
    assert!(matches!(
        decide_present("/dev/vdb1 /srv/x ext4 noauto 0 2"),
        Decision::Leave { .. }
    ));
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
    // A line of the decoy's own at that path is refused instead: the decoy
    // itself would mount it there. Led there by a link of the hidden root's,
    // the line names a path outside the hidden volume, and is kept off.
    assert!(matches!(
        decide_line("UUID=X /mnt/data/data ext4 defaults,nofail 0 2"),
        Decision::Refuse { .. }
    ));
    // A RAM filesystem a link leads there is left to the hidden systemd.
    assert!(matches!(
        decide_redirected_line("tmpfs /mnt/data/tmp tmpfs defaults 0 0"),
        Decision::Leave { .. }
    ));
    // Elsewhere, and for RAM or the root, the same decisions as decide.
    for line in [
        "tmpfs /tmp tmpfs defaults 0 0",
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
