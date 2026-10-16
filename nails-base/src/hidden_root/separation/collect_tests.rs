// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The collector on `MockFilesystem` fixtures, and the attach gate over the
//! decoy-storage scenes built as mock filesystems.
//!
//! The fixtures follow real sysfs: a device's attributes live in its own
//! directory under `/sys/devices`, and `/sys/class/block/<name>` and every
//! `slaves/` entry are symlinks to it.

use super::super::{FileHolder, LoopFile, NodeKind, Verdict};
use super::collect;
use crate::filesystem::mountinfo::parse_mountinfo;
use crate::filesystem::{Filesystem, MockFilesystem};
use crate::hidden_root::{Assessment, HiddenRoot, RefusalKind};
use std::path::{Path, PathBuf};

/// A mock decoy, built one device and file at a time.
struct Decoy {
    fs: MockFilesystem,
    class: Vec<PathBuf>,
}

impl Decoy {
    /// A decoy whose mount table is `mountinfo`, with the hidden root `/mnt`.
    fn new(mountinfo: &str) -> Self {
        let fs = MockFilesystem::new();
        fs.mock_set_mount_table(mountinfo);
        fs.mock_set_path_exists("/mnt", true);
        fs.mock_set_path_exists("/sys/class/block", true);
        fs.mock_set_device_id(Path::new("/"), 1);
        fs.mock_set_device_id(Path::new("/mnt"), 2);
        let decoy = Self {
            fs,
            class: Vec::new(),
        };
        decoy.publish();
        decoy
    }

    fn publish(&self) {
        self.fs
            .mock_set_directory_contents(Path::new("/sys/class/block"), self.class.clone());
    }

    fn attr(&self, dir: &str, attribute: &str, value: &str) {
        self.fs
            .mock_set_file_content(&format!("{dir}/{attribute}"), &format!("{value}\n"));
    }

    fn link(&self, link: &str, target: &str) {
        self.fs
            .create_symlink(Path::new(target), Path::new(link))
            .unwrap();
    }

    /// A device `name` at `dir`, listed in `/sys/class/block`, with the
    /// devices at `slaves` below it.
    fn device(mut self, dir: &str, name: &str, dev: &str, slaves: &[(&str, &str)]) -> Self {
        self.attr(dir, "dev", dev);
        self.fs
            .mock_set_file_content(&format!("{dir}/uevent"), &format!("DEVNAME={name}\n"));
        let slave_dir = Path::new(dir).join("slaves");
        let mut entries = Vec::new();
        for (slave, target) in slaves {
            let path = slave_dir.join(slave);
            self.link(path.to_str().unwrap(), target);
            entries.push(path);
        }
        self.fs.mock_set_directory_contents(&slave_dir, entries);
        let class = format!("/sys/class/block/{name}");
        self.link(&class, dir);
        self.class.push(PathBuf::from(class));
        self.publish();
        self
    }

    fn partition(self, dir: &str, name: &str, dev: &str) -> Self {
        let decoy = self.device(dir, name, dev, &[]);
        decoy.attr(dir, "partition", "1");
        decoy
    }

    fn mapping(
        self,
        dir: &str,
        name: &str,
        dev: &str,
        dm: (&str, &str),
        slaves: &[(&str, &str)],
    ) -> Self {
        let decoy = self.device(dir, name, dev, slaves);
        decoy.attr(dir, "dm/name", dm.0);
        decoy.attr(dir, "dm/uuid", dm.1);
        decoy.link(&format!("/dev/mapper/{}", dm.0), &format!("/dev/{name}"));
        decoy
    }

    fn file(self, path: &str, text: &str) -> Self {
        self.fs.mock_set_file_content(path, text);
        self
    }

    /// `path` exists, but reading it fails, as a file readable by root only
    /// does for an unprivileged reader.
    fn unreadable(self, path: &str) -> Self {
        self.fs.mock_set_path_exists(path, true);
        self
    }

    fn assess(&self) -> Assessment {
        HiddenRoot::assess(&self.fs, Path::new("/mnt")).unwrap()
    }
}

const NVME: &str = "/sys/devices/pci0/nvme/nvme0n1";
const P3: &str = "/sys/devices/pci0/nvme/nvme0n1/nvme0n1p3";
const DM0: &str = "/sys/devices/virtual/block/dm-0";
const DM1: &str = "/sys/devices/virtual/block/dm-1";
const DM3: &str = "/sys/devices/virtual/block/dm-3";
const DM4: &str = "/sys/devices/virtual/block/dm-4";
const SDB: &str = "/sys/devices/pci0/usb/sdb";
const DM9: &str = "/sys/devices/virtual/block/dm-9";

/// Debian's LVM on LUKS, with the hidden volume a LUKS volume in a second
/// logical volume of the decoy's group.
fn lv_in_the_decoys_group() -> Decoy {
    Decoy::new(
        "1 0 254:1 / / rw - ext4 /dev/mapper/vg-root rw\n\
         5 1 254:4 / /mnt rw - ext4 /dev/mapper/vault rw\n",
    )
    .device(NVME, "nvme0n1", "259:0", &[])
    .partition(P3, "nvme0n1p3", "259:3")
    .mapping(
        DM0,
        "dm-0",
        "254:0",
        ("cryptroot", "CRYPT-LUKS2-0a-cryptroot"),
        &[("nvme0n1p3", P3)],
    )
    .mapping(
        DM1,
        "dm-1",
        "254:1",
        ("vg-root", "LVM-aa"),
        &[("dm-0", DM0)],
    )
    .mapping(
        DM3,
        "dm-3",
        "254:3",
        ("vg-vault", "LVM-bb"),
        &[("dm-0", DM0)],
    )
    .mapping(
        DM4,
        "dm-4",
        "254:4",
        ("vault", "CRYPT-LUKS2-0b-vault"),
        &[("dm-3", DM3)],
    )
    .file("/etc/fstab", "/dev/mapper/vg-root / ext4 defaults 0 1\n")
    .file("/etc/crypttab", "cryptroot UUID=e1 none luks,discard\n")
}

/// The plain decoy on nvme0n1p3 and a whole-device VeraCrypt volume on the
/// external sdb at `/mnt`.
fn external_veracrypt() -> Decoy {
    Decoy::new(
        "1 0 259:3 / / rw - ext4 /dev/nvme0n1p3 rw\n\
         5 1 254:9 / /mnt rw - ext4 /dev/mapper/veracrypt1 rw\n",
    )
    .device(NVME, "nvme0n1", "259:0", &[])
    .partition(P3, "nvme0n1p3", "259:3")
    .device(SDB, "sdb", "8:16", &[])
    .mapping(DM9, "dm-9", "254:9", ("veracrypt1", ""), &[("sdb", SDB)])
    .file("/etc/fstab", "/dev/nvme0n1p3 / ext4 defaults 0 1\n")
}

#[test]
fn the_collector_reads_the_devices_and_the_names_the_files_use() {
    let decoy = lv_in_the_decoys_group();
    decoy.link("/dev/disk/by-uuid/e1", "/dev/nvme0n1p3");
    let mounts = decoy.fs.mount_table().unwrap();
    let collected = collect(&decoy.fs, &mounts, Path::new("/"));

    assert!(
        collected.unreadable.is_empty(),
        "{:?}",
        collected.unreadable
    );
    assert_eq!(collected.fstab.len(), 1);
    assert_eq!(collected.crypttab[0].name, "cryptroot");
    let devices = &collected.devices;
    assert_eq!(
        devices.nodes["dm-0"].kind,
        NodeKind::Crypt {
            name: "cryptroot".to_string()
        }
    );
    assert_eq!(devices.nodes["dm-0"].below, vec!["nvme0n1p3".to_string()]);
    assert_eq!(
        devices.nodes["dm-3"].kind,
        NodeKind::Mapper {
            name: "vg-vault".to_string()
        }
    );
    assert_eq!(
        devices.nodes["nvme0n1p3"].kind,
        NodeKind::Partition {
            disk: "nvme0n1".to_string()
        }
    );
    assert_eq!(devices.nodes["nvme0n1"].kind, NodeKind::Disk);
    assert_eq!(devices.node_of_spec("UUID=e1"), Some("nvme0n1p3"));
    assert_eq!(devices.node_of_spec("/dev/mapper/vault"), Some("dm-4"));
    assert_eq!(devices.by_dev["254:4"], "dm-4");
}

#[test]
fn the_collector_reads_btrfs_members_and_loop_files() {
    let decoy = Decoy::new("1 0 0:30 / / rw - btrfs /dev/nvme0n1p3 rw,subvol=/\n")
        .device(NVME, "nvme0n1", "259:0", &[])
        .partition(P3, "nvme0n1p3", "259:3")
        .device("/sys/devices/pci0/usb/sdb", "sdb", "8:16", &[])
        .device("/sys/devices/virtual/block/loop0", "loop0", "7:0", &[])
        .device("/sys/devices/virtual/block/loop1", "loop1", "7:1", &[]);
    decoy.attr(
        "/sys/devices/virtual/block/loop0",
        "loop/backing_file",
        "/home/op/vault.hc",
    );
    decoy.attr(
        "/sys/devices/virtual/block/loop1",
        "loop/backing_file",
        "/dev/sdb",
    );
    let fsid = Path::new("/sys/fs/btrfs/f1");
    decoy
        .fs
        .mock_set_directory_contents(Path::new("/sys/fs/btrfs"), vec![fsid.to_path_buf()]);
    decoy.fs.mock_set_directory_contents(
        &fsid.join("devices"),
        vec![fsid.join("devices/nvme0n1p3"), fsid.join("devices/sdb")],
    );
    decoy
        .fs
        .mock_set_loop_backing_device(Path::new("/dev/loop0"), rustix::fs::makedev(0, 30));
    let mounts = decoy.fs.mount_table().unwrap();
    let devices = collect(&decoy.fs, &mounts, Path::new("/")).devices;
    // One filesystem on two devices is listed once.
    assert_eq!(
        devices.btrfs,
        vec![
            ["nvme0n1p3".to_string(), "sdb".to_string()]
                .into_iter()
                .collect()
        ]
    );
    // A loop over a block device sits on that device.
    assert_eq!(devices.nodes["loop1"].kind, NodeKind::Loop { file: None });
    assert_eq!(devices.nodes["loop1"].below, vec!["sdb".to_string()]);
    // A loop over a file is held by the filesystem on the device the loop
    // driver recorded.
    assert_eq!(
        devices.nodes["loop0"].kind,
        NodeKind::Loop {
            file: Some(LoopFile {
                path: PathBuf::from("/home/op/vault.hc"),
                holder: FileHolder::Mount("0:30".into()),
            })
        }
    );
}

#[test]
fn an_absent_crypttab_is_empty_but_an_unreadable_one_is_listed() {
    let absent = external_veracrypt();
    let mounts = absent.fs.mount_table().unwrap();
    assert!(
        collect(&absent.fs, &mounts, Path::new("/"))
            .unreadable
            .is_empty()
    );

    for path in ["/etc/fstab", "/etc/crypttab"] {
        let decoy = Decoy::new("1 0 259:3 / / rw - ext4 /dev/nvme0n1p3 rw\n").unreadable(path);
        let mounts = decoy.fs.mount_table().unwrap();
        let collected = collect(&decoy.fs, &mounts, Path::new("/"));
        assert_eq!(collected.unreadable, vec![PathBuf::from(path)]);
    }
}

#[test]
fn an_unlistable_or_missing_sysfs_is_listed_as_unreadable() {
    // Without the list of block devices nothing can be followed to a device.
    let mounts = parse_mountinfo("1 0 259:3 / / rw - ext4 /dev/nvme0n1p3 rw\n");
    for exists in [true, false] {
        let fs = MockFilesystem::new();
        fs.mock_hide_block_devices();
        fs.mock_set_path_exists("/sys/class/block", exists);
        assert_eq!(
            collect(&fs, &mounts, Path::new("/")).unreadable,
            vec![PathBuf::from("/sys/class/block")],
            "{exists}"
        );
    }
}

#[test]
fn the_files_are_read_under_another_root_when_asked() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content("/media/decoy/etc/fstab", "/dev/sda1 / ext4 defaults 0 1\n");
    let mounts = parse_mountinfo("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n");
    let collected = collect(&fs, &mounts, Path::new("/media/decoy"));
    assert_eq!(collected.fstab.len(), 1);
    assert!(collected.crypttab.is_empty());
}

#[test]
fn the_gate_refuses_a_volume_in_the_decoys_group() {
    match lv_in_the_decoys_group().assess() {
        Assessment::Refused(refusal) => {
            assert!(
                matches!(
                    refusal.kind,
                    RefusalKind::DecoyStorage {
                        verdict: Verdict::InsideDecoyStorage { .. }
                    }
                ),
                "{refusal:?}"
            );
            assert_eq!(
                refusal.reason,
                "/mnt is not a volume of its own: it is stored on a device that also holds the \
                 filesystem at /"
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_gate_accepts_an_external_whole_device_volume() {
    assert_eq!(external_veracrypt().assess(), Assessment::Attached);
}

/// A VeraCrypt container file on the decoy's `/home` (`259:4`), opened
/// through `loop0` and mounted at `/mnt`, with `extra` mount lines. The loop
/// driver's record of the file's device is left to the test.
fn container_on_home(extra: &str) -> Decoy {
    let decoy = Decoy::new(&format!(
        "1 0 259:3 / / rw - ext4 /dev/nvme0n1p3 rw\n\
         2 1 259:4 / /home rw - ext4 /dev/nvme0n1p4 rw\n\
         5 1 254:8 / /mnt rw - ext4 /dev/mapper/veracrypt1 rw\n{extra}"
    ))
    .device(NVME, "nvme0n1", "259:0", &[])
    .partition(P3, "nvme0n1p3", "259:3")
    .partition(
        "/sys/devices/pci0/nvme/nvme0n1/nvme0n1p4",
        "nvme0n1p4",
        "259:4",
    )
    .device("/sys/devices/virtual/block/loop0", "loop0", "7:0", &[])
    .mapping(
        "/sys/devices/virtual/block/dm-8",
        "dm-8",
        "254:8",
        ("veracrypt1", ""),
        &[("loop0", "/sys/devices/virtual/block/loop0")],
    )
    .file("/etc/fstab", "/dev/nvme0n1p3 / ext4 defaults 0 1\n");
    decoy.attr(
        "/sys/devices/virtual/block/loop0",
        "loop/backing_file",
        "/home/op/vault.hc",
    );
    decoy
}

const LOOP0_NODE: &str = "/dev/loop0";

fn assert_container_warning(decoy: &Decoy) {
    match decoy.assess() {
        Assessment::Warned(warning) => {
            assert!(
                warning
                    .reason
                    .contains("an encrypted container file (/home/op/vault.hc) on /home"),
                "{}",
                warning.reason
            );
            assert!(
                warning.reason.contains("copy-on-write snapshots"),
                "{}",
                warning.reason
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_gate_warns_for_a_container_file_on_the_decoys_home() {
    let decoy = container_on_home("");
    decoy
        .fs
        .mock_set_loop_backing_device(Path::new(LOOP0_NODE), rustix::fs::makedev(259, 4));
    assert_container_warning(&decoy);
    let state = HiddenRoot::verify_attached(&decoy.fs, Path::new("/mnt"), false).unwrap();
    assert!(state.is_attached());
}

#[test]
fn a_mount_over_the_containers_folder_does_not_hide_where_it_lives() {
    // A tmpfs mounted over /home/op later leads the path elsewhere; the loop
    // driver's device still names /home's filesystem.
    let decoy = container_on_home(
        "6 2 0:90 / /home/op rw - tmpfs tmpfs rw
",
    );
    decoy
        .fs
        .mock_set_loop_backing_device(Path::new(LOOP0_NODE), rustix::fs::makedev(259, 4));
    assert_container_warning(&decoy);
}

#[test]
fn a_file_on_a_subvolume_device_is_placed_through_its_path() {
    // btrfs gives the files of a subvolume a device of their own, which no
    // mount line shows; the path still leads to a file on that device.
    let decoy = container_on_home("");
    let subvolume = rustix::fs::makedev(0, 77);
    decoy
        .fs
        .mock_set_loop_backing_device(Path::new(LOOP0_NODE), subvolume);
    decoy
        .fs
        .mock_set_device_id(Path::new("/home/op/vault.hc"), subvolume);
    assert_container_warning(&decoy);
}

#[test]
fn an_image_no_mounted_filesystem_holds_is_refused() {
    // The recorded device is mounted nowhere here, and the path now leads to
    // a file on another device.
    let decoy = container_on_home("");
    decoy
        .fs
        .mock_set_loop_backing_device(Path::new(LOOP0_NODE), rustix::fs::makedev(8, 99));
    match decoy.assess() {
        Assessment::Refused(refusal) => {
            assert_eq!(refusal.code(), "storage_unjudged");
            assert_eq!(
                refusal.reason,
                "/mnt is an image file (/home/op/vault.hc) that no filesystem mounted here \
                 holds, so where it lives cannot be told"
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_unreadable_loop_record_refuses_only_the_root_stored_on_it() {
    // Unprivileged, the node of the loop device under a container file cannot
    // be read: the container that would only warn is refused, with the sudo
    // hint, and the override does not cover it.
    let decoy = container_on_home("");
    match decoy.assess() {
        Assessment::Refused(refusal) => {
            assert_eq!(
                refusal.kind,
                RefusalKind::StorageUnjudged {
                    unreadable: vec![PathBuf::from(LOOP0_NODE)]
                }
            );
            assert_eq!(
                refusal.reason,
                "could not read the record of a loop device to tell where /mnt lives"
            );
            assert_eq!(refusal.hint(None), ["Run the command again with sudo."]);
            assert!(!crate::hidden_root::Allow::DecoyStorage.covers(&refusal.kind));
        }
        other => panic!("{other:?}"),
    }
    // An unrelated loop device whose record cannot be read changes nothing.
    let other =
        external_veracrypt().device("/sys/devices/virtual/block/loop5", "loop5", "7:5", &[]);
    other.attr(
        "/sys/devices/virtual/block/loop5",
        "loop/backing_file",
        "/var/lib/snapd/snaps/core.snap",
    );
    assert_eq!(other.assess(), Assessment::Attached);
}

#[test]
fn an_unreadable_crypttab_refuses_a_disk_root_but_not_a_tmpfs() {
    let decoy = external_veracrypt().unreadable("/etc/crypttab");
    match decoy.assess() {
        Assessment::Refused(refusal) => {
            assert_eq!(
                refusal.kind,
                RefusalKind::StorageUnjudged {
                    unreadable: vec![PathBuf::from("/etc/crypttab")]
                }
            );
            assert_eq!(
                refusal.reason,
                "could not read /etc/crypttab to tell where /mnt lives"
            );
        }
        other => panic!("{other:?}"),
    }

    let tmpfs = Decoy::new(
        "1 0 259:3 / / rw - ext4 /dev/nvme0n1p3 rw\n\
         5 1 0:40 / /mnt rw - tmpfs tmpfs rw\n",
    )
    .unreadable("/etc/crypttab")
    .unreadable("/etc/fstab");
    assert_eq!(tmpfs.assess(), Assessment::Attached);
}

#[test]
fn the_session_does_not_consult_the_decoys_files() {
    // In the hidden session the decoy's storage is out of sight; the files
    // read here are the session's own, and an unreadable one does not matter.
    let decoy = Decoy::new(
        "1 0 0:30 / / rw - overlay overlay rw,lowerdir=/run/overlay-runtime/lower,\
         upperdir=/mnt/root/upper,workdir=/mnt/root/work\n\
         10 1 254:9 / /mnt rw - ext4 /dev/mapper/veracrypt1 rw\n",
    )
    .unreadable("/etc/crypttab");
    decoy.fs.mock_set_device_id(Path::new("/mnt/root/upper"), 2);
    assert_eq!(decoy.assess(), Assessment::Attached);
}
