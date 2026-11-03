// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The attach gate on disks that sysfs shows nothing below, as mock decoys
//! with the `/proc/devices` of [`super::PROC_DEVICES`]: a network block device
//! (`nbd`), a userspace block device (`ublk`) and a ZFS volume (`zvol`), each
//! as the root's own disk and below a partition, an encrypted mapping, a
//! logical volume, an md array and an image file, with the override and
//! without; disks whose kind cannot be read, loop devices that show no file
//! or read a device node, zram devices and what they write back to, and
//! sysfs listings that cannot be read; and the disks that stay accepted.

#[path = "collect_extra_tests.rs"]
mod extra;

use super::{Decoy, NVME, P3, SDB};
use crate::filesystem::{Filesystem, LoopRecord};
use crate::hidden_root::separation::{Served, Untraced, Verdict};
use crate::hidden_root::{Allow, Assessment, HiddenRoot, RefusalKind};
use std::path::{Path, PathBuf};

const NBD0: &str = "/sys/devices/virtual/block/nbd0";
const UBLKB0: &str = "/sys/devices/virtual/block/ublkb0";
const ZD0: &str = "/sys/devices/virtual/block/zd0";
const SDC: &str = "/sys/devices/pci0/usb/sdc";

/// The plain decoy on `nvme0n1p3`, with `lines` the mount lines below its
/// `/`, the hidden root's at `/mnt` among them.
fn decoy(lines: &str) -> Decoy {
    Decoy::new(&format!(
        "1 0 259:3 / / rw - ext4 /dev/nvme0n1p3 rw\n{lines}"
    ))
    .device(NVME, "nvme0n1", "259:0", &[])
    .partition(P3, "nvme0n1p3", "259:3")
    .file("/etc/fstab", "/dev/nvme0n1p3 / ext4 defaults 0 1\n")
}

/// The whole disk `name` at sysfs `dir`, numbered `dev` by its driver, with
/// a first partition `<name>p1` numbered `part`.
struct Disk {
    name: &'static str,
    dir: &'static str,
    dev: &'static str,
    part: &'static str,
}

impl Disk {
    fn on(&self, decoy: Decoy) -> Decoy {
        decoy.device(self.dir, self.name, self.dev, &[]).partition(
            &self.partition_dir(),
            &format!("{}p1", self.name),
            self.part,
        )
    }

    fn partition_dir(&self) -> String {
        format!("{}/{}p1", self.dir, self.name)
    }
}

/// Every way a root sits on `disk` in these tests, each named: the disk
/// itself, its partition, LUKS on the disk, a logical volume on its
/// partition, an md array over it and an ordinary disk, and an image file on
/// a filesystem on the disk.
fn layouts(disk: &Disk) -> Vec<(&'static str, Decoy)> {
    let name = disk.name;
    let part = format!("{name}p1");
    let part_dir = disk.partition_dir();
    let mut scenes = vec![
        (
            "the disk itself",
            disk.on(decoy(&format!(
                "5 1 {} / /mnt rw - ext4 /dev/{name} rw\n",
                disk.dev
            ))),
        ),
        (
            "its partition",
            disk.on(decoy(&format!(
                "5 1 {} / /mnt rw - ext4 /dev/{part} rw\n",
                disk.part
            ))),
        ),
        (
            "LUKS on the disk",
            disk.on(decoy("5 1 254:5 / /mnt rw - ext4 /dev/mapper/data rw\n"))
                .mapping(
                    "/sys/devices/virtual/block/dm-5",
                    "dm-5",
                    "254:5",
                    ("data", "CRYPT-LUKS2-0c-data"),
                    &[(name, disk.dir)],
                ),
        ),
        (
            "a logical volume on its partition",
            disk.on(decoy(
                "5 1 254:6 / /mnt rw - ext4 /dev/mapper/vg2-data rw\n",
            ))
            .mapping(
                "/sys/devices/virtual/block/dm-6",
                "dm-6",
                "254:6",
                ("vg2-data", "LVM-cc"),
                &[(part.as_str(), part_dir.as_str())],
            ),
        ),
        (
            "an md array over it and an ordinary disk",
            disk.on(decoy("5 1 9:0 / /mnt rw - ext4 /dev/md0 rw\n"))
                .device(SDC, "sdc", "8:32", &[])
                .device(
                    "/sys/devices/virtual/block/md0",
                    "md0",
                    "9:0",
                    &[(name, disk.dir), ("sdc", SDC)],
                ),
        ),
    ];
    let image = disk
        .on(decoy(&format!(
            "4 1 {} / /media/x rw - ext4 /dev/{name} rw\n\
             5 1 7:0 / /mnt rw - ext4 /dev/loop0 rw\n",
            disk.dev
        )))
        .device("/sys/devices/virtual/block/loop0", "loop0", "7:0", &[]);
    image.attr(
        "/sys/devices/virtual/block/loop0",
        "loop/backing_file",
        "/media/x/disk.img",
    );
    let (major, minor) = disk.dev.split_once(':').unwrap();
    image.fs.mock_set_loop_backing_device(
        Path::new("/dev/loop0"),
        rustix::fs::makedev(major.parse().unwrap(), minor.parse().unwrap()),
    );
    scenes.push(("an image file on a filesystem on the disk", image));
    scenes
}

fn assess(decoy: &Decoy, allow: Allow) -> Assessment {
    HiddenRoot::assess_allowing(&decoy.fs, Path::new("/mnt"), allow).unwrap()
}

/// `decoy` refuses its root as stored on a disk `kind` serves, and the
/// override attaches it with its warning.
fn assert_served(what: &str, decoy: &Decoy, kind: Served) {
    let verdict = Verdict::ServedDevice { kind };
    match assess(decoy, Allow::Nothing) {
        Assessment::Refused(refusal) => {
            assert_eq!(
                refusal.kind,
                RefusalKind::DecoyStorage {
                    verdict: verdict.clone()
                },
                "{what}"
            );
            assert_eq!(refusal.code(), "not_separate_volume", "{what}");
            assert!(Allow::DecoyStorage.covers(&refusal.kind), "{what}");
        }
        other => panic!("{what}: {other:?}"),
    }
    match assess(decoy, Allow::DecoyStorage) {
        Assessment::Warned(refusal) => {
            assert!(refusal.overridden(), "{what}");
            assert_eq!(
                refusal.warning(),
                format!(
                    "--allow-decoy-storage: using /mnt although {}; everything written there \
                     lands on that storage",
                    verdict.reason()
                ),
                "{what}"
            );
        }
        other => panic!("{what}: {other:?}"),
    }
}

/// `decoy` refuses its root as untraced, `kind`, with the override too.
fn assert_untraced(what: &str, decoy: &Decoy, kind: Untraced) {
    for allow in [Allow::Nothing, Allow::DecoyStorage] {
        match assess(decoy, allow) {
            Assessment::Refused(refusal) => {
                assert_eq!(
                    refusal.kind,
                    RefusalKind::StorageUntraced {
                        verdict: Verdict::UntracedDevice { kind }
                    },
                    "{what}, {allow:?}"
                );
                assert_eq!(refusal.code(), "storage_unjudged", "{what}");
            }
            other => panic!("{what}, {allow:?}: {other:?}"),
        }
    }
}

#[test]
fn a_root_on_a_network_block_device_is_refused_unless_the_override_accepts_it() {
    let nbd = Disk {
        name: "nbd0",
        dir: NBD0,
        dev: "43:0",
        part: "43:1",
    };
    for (what, decoy) in layouts(&nbd) {
        assert_served(what, &decoy, Served::Network);
    }
}

#[test]
fn a_root_on_a_userspace_block_device_is_refused_unless_the_override_accepts_it() {
    // The driver takes its numbers from the range the kernel shares, as an
    // NVMe disk does: only the name the driver gives it tells it.
    let ublk = Disk {
        name: "ublkb0",
        dir: UBLKB0,
        dev: "259:7",
        part: "259:8",
    };
    for (what, decoy) in layouts(&ublk) {
        assert_served(what, &decoy, Served::Userspace);
    }
}

#[test]
fn a_root_on_a_zfs_volume_is_refused_whatever_the_override() {
    let zvol = Disk {
        name: "zd0",
        dir: ZD0,
        dev: "230:0",
        part: "230:1",
    };
    for (what, decoy) in layouts(&zvol) {
        assert_untraced(what, &decoy, Untraced::ZfsVolume);
    }
}

#[test]
fn the_same_roots_on_an_ordinary_disk_attach() {
    let sdb = Disk {
        name: "sdb",
        dir: SDB,
        dev: "8:16",
        part: "8:17",
    };
    for (what, decoy) in layouts(&sdb) {
        assert_eq!(decoy.assess(), Assessment::Attached, "{what}");
    }
}

#[test]
fn the_major_number_tells_a_disk_whatever_its_name() {
    // A disk is known by the driver /proc/devices lists for its number, and
    // by its driver's name for it: either makes the verdict stricter.
    let itself = |disk: Disk| layouts(&disk).remove(0).1;
    let numbered = itself(Disk {
        name: "vol0",
        dir: "/sys/devices/virtual/block/vol0",
        dev: "43:0",
        part: "43:1",
    });
    assert_served("an nbd number", &numbered, Served::Network);
    let numbered = itself(Disk {
        name: "vol1",
        dir: "/sys/devices/virtual/block/vol1",
        dev: "230:16",
        part: "230:17",
    });
    assert_untraced("a zvol number", &numbered, Untraced::ZfsVolume);
    let named = itself(Disk {
        name: "nbd3",
        dir: "/sys/devices/virtual/block/nbd3",
        dev: "8:48",
        part: "8:49",
    });
    assert_served("an nbd name", &named, Served::Network);
}

#[test]
fn a_name_that_only_begins_as_a_drivers_does_is_a_plain_disk() {
    // A driver's own name for a disk ends in its number.
    for disk in [
        Disk {
            name: "zdisk",
            dir: "/sys/devices/pci0/usb/zdisk",
            dev: "8:64",
            part: "8:65",
        },
        Disk {
            name: "ublkb",
            dir: "/sys/devices/pci0/nvme/ublkb",
            dev: "259:12",
            part: "259:13",
        },
    ] {
        let (_, decoy) = layouts(&disk).remove(0);
        assert_eq!(decoy.assess(), Assessment::Attached, "{}", disk.name);
    }
}

#[test]
fn a_disk_whose_kind_cannot_be_read_is_refused_whatever_the_override() {
    let sdb = Disk {
        name: "sdb",
        dir: SDB,
        dev: "8:16",
        part: "8:17",
    };
    let refused = |decoy: &Decoy| {
        let Assessment::Refused(allowed) = assess(decoy, Allow::DecoyStorage) else {
            panic!("the override attached it");
        };
        let Assessment::Refused(refusal) = assess(decoy, Allow::Nothing) else {
            panic!("it attached");
        };
        assert_eq!(allowed, refusal);
        assert_eq!(refusal.code(), "storage_unjudged");
        refusal
    };

    // Without /proc/devices nothing names any disk's driver.
    for (what, decoy) in layouts(&sdb) {
        decoy.fs.remove_file(Path::new("/proc/devices")).unwrap();
        let refusal = refused(&decoy);
        assert_eq!(
            refusal.kind,
            RefusalKind::StorageUnjudged {
                unreadable: vec![PathBuf::from("/proc/devices")]
            },
            "{what}"
        );
        assert_eq!(
            refusal.reason,
            "could not read /proc/devices to tell where /mnt lives"
        );
        assert_eq!(
            refusal.hint(None),
            ["Run the command where /proc is mounted and readable."]
        );
    }

    // A disk whose number /proc/devices lists no driver for.
    let (_, unnamed) = layouts(&Disk {
        name: "xvdq",
        dir: "/sys/devices/vbd-51776/block/xvdq",
        dev: "202:16",
        part: "202:17",
    })
    .remove(2);
    assert_untraced("an unnamed driver", &unnamed, Untraced::UnnamedDriver);
    let Assessment::Refused(refusal) = unnamed.assess() else {
        unreachable!()
    };
    assert_eq!(
        refusal.reason,
        "/mnt is stored on a device whose driver the kernel does not name, so where it lives \
         cannot be told"
    );

    // A disk whose own number cannot be read.
    let (_, numberless) = layouts(&sdb).remove(2);
    numberless
        .fs
        .remove_file(&Path::new(SDB).join("dev"))
        .unwrap();
    let refusal = refused(&numberless);
    assert_eq!(
        refusal.kind,
        RefusalKind::StorageUnjudged {
            unreadable: vec![Path::new(SDB).join("dev")]
        }
    );
    assert_eq!(
        refusal.hint(None),
        [
            "Run the command again as root, on the host rather than in a container, with /sys \
             mounted."
        ]
    );
}

#[test]
fn a_disk_the_root_does_not_reach_changes_nothing() {
    // The decoy's own network block device, a ZFS volume and a disk of a
    // driver nothing names, none of them below the root.
    let decoy = decoy(
        "4 1 43:0 / /srv rw - ext4 /dev/nbd0 rw\n\
         5 1 254:5 / /mnt rw - ext4 /dev/mapper/data rw\n",
    )
    .device(NBD0, "nbd0", "43:0", &[])
    .device(ZD0, "zd0", "230:0", &[])
    .device("/sys/devices/vbd-51776/block/xvdq", "xvdq", "202:16", &[])
    .device(SDB, "sdb", "8:16", &[])
    .mapping(
        "/sys/devices/virtual/block/dm-5",
        "dm-5",
        "254:5",
        ("data", "CRYPT-LUKS2-0c-data"),
        &[("sdb", SDB)],
    );
    for allow in [Allow::Nothing, Allow::DecoyStorage] {
        assert_eq!(assess(&decoy, allow), Assessment::Attached, "{allow:?}");
    }
}

#[test]
fn iscsi_nvme_and_zram_disks_attach_as_before() {
    let luks_on = |dir: &str, name: &str, dev: &str| {
        decoy("5 1 254:5 / /mnt rw - ext4 /dev/mapper/data rw\n")
            .device(dir, name, dev, &[])
            .mapping(
                "/sys/devices/virtual/block/dm-5",
                "dm-5",
                "254:5",
                ("data", "CRYPT-LUKS2-0c-data"),
                &[(name, dir)],
            )
    };
    // An iSCSI disk is a SCSI disk below its session.
    let iscsi = luks_on(
        "/sys/devices/platform/host3/session1/target3:0:0/3:0:0:0/block/sdd",
        "sdd",
        "8:48",
    );
    assert_eq!(iscsi.assess(), Assessment::Attached);
    // A second NVMe disk takes its number from the shared range, as a
    // userspace block device does, and is no such device.
    let nvme = luks_on("/sys/devices/pci0/nvme/nvme1n1", "nvme1n1", "259:4");
    assert_eq!(nvme.assess(), Assessment::Attached);
    // zram keeps its data in RAM.
    let zram = decoy("5 1 252:0 / /mnt rw - ext4 /dev/zram0 rw\n").device(
        "/sys/devices/virtual/block/zram0",
        "zram0",
        "252:0",
        &[],
    );
    assert_eq!(zram.assess(), Assessment::Attached);
}

#[test]
fn a_zfs_volume_is_refused_whatever_the_decoy_makes_of_it() {
    // The decoy's fstab mounts the volume at the root, by its node or by a
    // link under /dev/zvol, or mounts an encrypted mapping on it there; or
    // the root is a bind of a folder of a filesystem the decoy mounts from
    // the volume. Each is the decoy's own filesystem, which the override
    // lifts elsewhere; on a ZFS volume nothing does.
    let fstab = |line: &str| format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{line}");
    let itself = decoy("5 1 230:0 / /mnt rw - ext4 /dev/zd0 rw\n")
        .device(ZD0, "zd0", "230:0", &[])
        .file("/etc/fstab", &fstab("/dev/zd0 /mnt ext4 defaults 0 2\n"));
    assert_untraced("the volume the fstab mounts", &itself, Untraced::ZfsVolume);
    let linked = decoy("5 1 230:0 / /mnt rw - ext4 /dev/zd0 rw\n")
        .device(ZD0, "zd0", "230:0", &[])
        .file(
            "/etc/fstab",
            &fstab("/dev/zvol/tank/hidden /mnt ext4 defaults 0 2\n"),
        );
    linked.link("/dev/zvol/tank/hidden", "/dev/zd0");
    assert_untraced("its link the fstab names", &linked, Untraced::ZfsVolume);
    let mapping = decoy("5 1 254:5 / /mnt rw - ext4 /dev/mapper/data rw\n")
        .device(ZD0, "zd0", "230:0", &[])
        .mapping(
            "/sys/devices/virtual/block/dm-5",
            "dm-5",
            "254:5",
            ("data", "CRYPT-LUKS2-0c-data"),
            &[("zd0", ZD0)],
        )
        .file(
            "/etc/fstab",
            &fstab("/dev/mapper/data /mnt ext4 defaults 0 2\n"),
        );
    assert_untraced(
        "a mapping on it the fstab mounts",
        &mapping,
        Untraced::ZfsVolume,
    );
    let bind = decoy(
        "4 1 230:0 / /srv rw - ext4 /dev/zd0 rw\n\
         5 1 230:0 /x /mnt rw - ext4 /dev/zd0 rw\n",
    )
    .device(ZD0, "zd0", "230:0", &[])
    .file("/etc/fstab", &fstab("/dev/zd0 /srv ext4 defaults 0 2\n"));
    assert_untraced(
        "a bind of the decoy's /srv on it",
        &bind,
        Untraced::ZfsVolume,
    );

    // On an ordinary disk the fstab's volume is a refusal the override lifts.
    let plain = decoy("5 1 8:16 / /mnt rw - ext4 /dev/sdb rw\n")
        .device(SDB, "sdb", "8:16", &[])
        .file("/etc/fstab", &fstab("/dev/sdb /mnt ext4 defaults 0 2\n"));
    assert!(matches!(
        assess(&plain, Allow::DecoyStorage),
        Assessment::Warned(_)
    ));
}

#[test]
fn an_image_file_on_a_decoy_filesystem_on_a_served_disk_is_refused_as_the_image_file() {
    // The decoy's /home is on a network block device. Wherever the server
    // keeps that, the root's data lands in a file on /home: the refusal and
    // the override's warning name that file.
    let loop_dir = "/sys/devices/virtual/block/loop0";
    let image = decoy(
        "4 1 43:0 / /home rw - ext4 /dev/nbd0 rw\n\
         5 1 7:0 / /mnt rw - ext4 /dev/loop0 rw\n",
    )
    .device(NBD0, "nbd0", "43:0", &[])
    .device(loop_dir, "loop0", "7:0", &[])
    .file(
        "/etc/fstab",
        "/dev/nvme0n1p3 / ext4 defaults 0 1\n/dev/nbd0 /home ext4 defaults 0 2\n",
    );
    image.attr(loop_dir, "loop/backing_file", "/home/op/x.img");
    image
        .fs
        .mock_set_loop_backing_device(Path::new("/dev/loop0"), rustix::fs::makedev(43, 0));
    let verdict = Verdict::ImageFileOnDecoy {
        file: PathBuf::from("/home/op/x.img"),
        at: PathBuf::from("/home"),
    };
    let Assessment::Refused(refusal) = assess(&image, Allow::Nothing) else {
        panic!("it attached");
    };
    assert_eq!(
        refusal.kind,
        RefusalKind::DecoyStorage {
            verdict: verdict.clone()
        }
    );
    assert_eq!(
        refusal.message(),
        "/mnt is not a volume of its own: it is an unencrypted image file (/home/op/x.img) on \
         /home. Nothing was written."
    );
    assert!(
        refusal.hint(None)[0].starts_with("Setting up here would leave files"),
        "{:?}",
        refusal.hint(None)
    );
    let Assessment::Warned(warned) = assess(&image, Allow::DecoyStorage) else {
        panic!("the override did not attach it");
    };
    assert_eq!(
        warned.warning(),
        "--allow-decoy-storage: using /mnt although it is an unencrypted image file \
         (/home/op/x.img) on /home; everything written there lands on that storage"
    );
}

/// `decoy` refuses its root, with the override too, as storage whose `input`
/// could not be read.
fn assert_unjudged(what: &str, decoy: &Decoy, input: &str) {
    for allow in [Allow::Nothing, Allow::DecoyStorage] {
        match assess(decoy, allow) {
            Assessment::Refused(refusal) => assert_eq!(
                refusal.kind,
                RefusalKind::StorageUnjudged {
                    unreadable: vec![PathBuf::from(input)]
                },
                "{what}, {allow:?}"
            ),
            other => panic!("{what}, {allow:?}: {other:?}"),
        }
    }
}

#[test]
fn a_loop_device_that_shows_no_file_is_refused_where_the_root_reaches_it() {
    // The kernel shows no file of a loop device whose path does not fit in a
    // page: the root on it, and one in an image file on a filesystem on it,
    // cannot be judged.
    let loop1 = "/sys/devices/virtual/block/loop1";
    let file = "/sys/devices/virtual/block/loop1/loop/backing_file";
    let itself =
        decoy("5 1 7:1 / /mnt rw - ext4 /dev/loop1 rw\n").device(loop1, "loop1", "7:1", &[]);
    assert_unjudged("the loop device itself", &itself, file);
    let Assessment::Refused(refusal) = itself.assess() else {
        unreachable!()
    };
    assert_eq!(
        refusal.hint(None),
        [
            "Set the loop device up again from a file with a shorter path, then run the command again."
        ]
    );
    let loop0 = "/sys/devices/virtual/block/loop0";
    let image = decoy(
        "4 1 7:1 / /media/x rw - ext4 /dev/loop1 rw\n\
         5 1 7:0 / /mnt rw - ext4 /dev/loop0 rw\n",
    )
    .device(loop1, "loop1", "7:1", &[])
    .device(loop0, "loop0", "7:0", &[]);
    image.attr(loop0, "loop/backing_file", "/media/x/disk.img");
    image
        .fs
        .mock_set_loop_backing_device(Path::new("/dev/loop0"), rustix::fs::makedev(7, 1));
    assert_unjudged("an image file on a filesystem on it", &image, file);
    // A loop device bound to nothing holds no data, and nothing reaches it.
    let apart = decoy("5 1 8:16 / /mnt rw - ext4 /dev/sdb rw\n")
        .device(SDB, "sdb", "8:16", &[])
        .device(loop1, "loop1", "7:1", &[]);
    assert_eq!(apart.assess(), Assessment::Attached);
}

#[test]
fn a_zram_device_is_judged_with_the_device_it_writes_back_to() {
    let zram = "/sys/devices/virtual/block/zram0";
    let on_zram = |backing: Option<&str>| {
        let decoy = decoy("5 1 252:0 / /mnt rw - ext4 /dev/zram0 rw\n")
            .device(zram, "zram0", "252:0", &[])
            .device(NBD0, "nbd0", "43:0", &[])
            .device(SDB, "sdb", "8:16", &[]);
        if let Some(backing) = backing {
            decoy.attr(zram, "backing_dev", backing);
        }
        decoy
    };
    // Without writeback, or with none set up, its pages stay in RAM.
    assert_eq!(on_zram(None).assess(), Assessment::Attached);
    assert_eq!(on_zram(Some("none")).assess(), Assessment::Attached);
    assert_eq!(on_zram(Some("/dev/sdb")).assess(), Assessment::Attached);
    assert_served(
        "pages written back to an nbd device",
        &on_zram(Some("/dev/nbd0")),
        Served::Network,
    );
    // Pages written back to the decoy's own disk.
    let decoys = on_zram(Some("/dev/nvme0n1p3"));
    assert!(
        matches!(
            decoys.assess(),
            Assessment::Refused(ref refusal)
                if matches!(refusal.kind, RefusalKind::DecoyStorage { .. })
        ),
        "{:?}",
        decoys.assess()
    );
    // A device it cannot name, or an attribute it cannot read.
    assert_untraced(
        "a device node outside /dev",
        &on_zram(Some("/tmp/blk")),
        Untraced::NotFound,
    );
    let input = "/sys/devices/virtual/block/zram0/backing_dev";
    let unread = on_zram(None).unreadable(input);
    assert_unjudged("an attribute it cannot read", &unread, input);
}

#[test]
fn what_sysfs_cannot_list_on_the_way_down_cannot_be_judged() {
    // The devices below the root's mapping.
    let dm5 = "/sys/devices/virtual/block/dm-5";
    let mapping = decoy("5 1 254:5 / /mnt rw - ext4 /dev/mapper/data rw\n")
        .device(NBD0, "nbd0", "43:0", &[])
        .mapping(
            dm5,
            "dm-5",
            "254:5",
            ("data", "CRYPT-LUKS2-0c-data"),
            &[("nbd0", NBD0)],
        );
    mapping.fs.mock_set_unreadable_dir(&format!("{dm5}/slaves"));
    assert_unjudged(
        "the devices below a mapping",
        &mapping,
        &format!("{dm5}/slaves"),
    );

    // The devices of a btrfs filesystem.
    let fsid = "/sys/fs/btrfs/0a1b2c3d-0000-4000-8000-000000000009";
    let btrfs = decoy("5 1 0:60 / /mnt rw - btrfs /dev/sdb rw,subvol=/\n")
        .device(SDB, "sdb", "8:16", &[])
        .device(NBD0, "nbd0", "43:0", &[]);
    btrfs
        .fs
        .mock_set_directory_contents(Path::new("/sys/fs/btrfs"), vec![PathBuf::from(fsid)]);
    btrfs.fs.mock_set_unreadable_dir(&format!("{fsid}/devices"));
    assert_unjudged(
        "the devices of a btrfs filesystem",
        &btrfs,
        &format!("{fsid}/devices"),
    );

    // A partition whose `partition` attribute cannot be read is still a
    // partition of the disk whose directory holds it.
    let ublk = Disk {
        name: "ublkb0",
        dir: UBLKB0,
        dev: "259:7",
        part: "259:8",
    };
    let part = decoy("5 1 259:8 / /mnt rw - ext4 /dev/ublkb0p1 rw\n")
        .device(ublk.dir, ublk.name, ublk.dev, &[])
        .device(&ublk.partition_dir(), "ublkb0p1", ublk.part, &[]);
    assert_served(
        "a partition read without its number",
        &part,
        Served::Userspace,
    );
}

#[test]
fn a_loop_device_over_a_device_node_outside_dev_lies_on_that_device() {
    // The loop driver's record shows the loop device reads the node of a
    // device, which the node's path outside /dev does not tell.
    let loop1 = "/sys/devices/virtual/block/loop1";
    let over = |dir: &str, name: &str, dev: &str, node: &str, on: (u32, u32), lines: &str| {
        let decoy = decoy(&format!("{lines}5 1 7:1 / /mnt rw - ext4 /dev/loop1 rw\n"))
            .device(dir, name, dev, &[])
            .device(loop1, "loop1", "7:1", &[]);
        decoy.attr(loop1, "loop/backing_file", node);
        decoy.link(&format!("/sys/dev/block/{dev}"), dir);
        let (major, minor) = dev.split_once(':').unwrap();
        decoy.fs.mock_set_loop_record(
            Path::new("/dev/loop1"),
            LoopRecord {
                device: rustix::fs::makedev(on.0, on.1),
                rdevice: rustix::fs::makedev(major.parse().unwrap(), minor.parse().unwrap()),
            },
        );
        decoy
    };
    // A node on a tmpfs, which keeps nothing on a disk itself.
    let tmpfs = over(
        NBD0,
        "nbd0",
        "43:0",
        "/media/tmp/blk",
        (0, 46),
        "3 1 0:46 / /media/tmp rw - tmpfs tmpfs rw\n",
    );
    assert_served("an nbd node on a tmpfs", &tmpfs, Served::Network);
    // A node on the decoy's own /: not an image file there, but the volume.
    let on_root = over(ZD0, "zd0", "230:0", "/root/blk", (259, 3), "");
    assert_untraced(
        "a zvol node on the decoy's /",
        &on_root,
        Untraced::ZfsVolume,
    );
    let plain = over(SDB, "sdb", "8:16", "/root/blk", (259, 3), "");
    assert_eq!(plain.assess(), Assessment::Attached);
    // A device sysfs shows by no such number.
    let gone = over(SDB, "sdb", "8:16", "/root/blk", (259, 3), "");
    gone.fs.mock_set_loop_record(
        Path::new("/dev/loop1"),
        LoopRecord {
            device: rustix::fs::makedev(259, 3),
            rdevice: rustix::fs::makedev(43, 9),
        },
    );
    assert_untraced("a device sysfs does not show", &gone, Untraced::NotFound);
}
