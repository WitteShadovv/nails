// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the block-device walk, on `MockFilesystem` sysfs fixtures.
//!
//! The fixtures follow real sysfs: a device's attributes live in its own
//! directory under `/sys/devices`, and `/sys/class/block/<name>`,
//! `/sys/dev/block/<maj:min>` and every `slaves/` entry are symlinks to it.

use super::walk::{parse_backing_file, parse_u64, uevent_value};
use super::*;
use crate::filesystem::mountinfo::parse_mountinfo;
use crate::filesystem::{Filesystem, MockFilesystem};

/// A mock sysfs, built one device at a time.
struct Sysfs(MockFilesystem);

impl Sysfs {
    fn new() -> Self {
        Self(MockFilesystem::new())
    }

    /// A device at `dir` with its `dev` number and a `uevent` naming it.
    fn device(&self, dir: &str, name: &str, dev: &str) -> &Self {
        self.file(dir, "dev", dev);
        let (major, minor) = dev.split_once(':').unwrap();
        self.0.mock_set_file_content(
            &format!("{dir}/uevent"),
            &format!("MAJOR={major}\nMINOR={minor}\nDEVNAME={name}\nDEVTYPE=disk\n"),
        );
        self
    }

    /// A partition at `dir` of the disk whose directory is its parent.
    fn partition(&self, dir: &str, name: &str, dev: &str, number: u32, uuid: &str) -> &Self {
        let (major, minor) = dev.split_once(':').unwrap();
        self.file(dir, "dev", dev);
        self.file(dir, "partition", &number.to_string());
        self.file(dir, "start", "2048");
        self.0.mock_set_file_content(
            &format!("{dir}/uevent"),
            &format!(
                "MAJOR={major}\nMINOR={minor}\nDEVNAME={name}\nDEVTYPE=partition\n\
                 PARTN={number}\nPARTNAME=scratch\nPARTUUID={uuid}\n"
            ),
        );
        self
    }

    /// A one-line attribute.
    fn file(&self, dir: &str, attribute: &str, value: &str) -> &Self {
        self.0
            .mock_set_file_content(&format!("{dir}/{attribute}"), &format!("{value}\n"));
        self
    }

    /// The entries of `dir/sub` (`slaves`, `holders`, `devices`), each a
    /// symlink to the directory given with it.
    fn links(&self, dir: &str, sub: &str, entries: &[(&str, &str)]) -> &Self {
        let parent = Path::new(dir).join(sub);
        let mut paths = Vec::new();
        for (name, target) in entries {
            let path = parent.join(name);
            self.link(path.to_str().unwrap(), target);
            paths.push(path);
        }
        self.0.mock_set_directory_contents(&parent, paths);
        self
    }

    fn link(&self, link: &str, target: &str) -> &Self {
        self.0
            .create_symlink(Path::new(target), Path::new(link))
            .unwrap();
        self
    }

    fn stack(&self, top: &str, follow: LoopFollow) -> Vec<Layer> {
        stack(&self.0, Path::new(top), follow)
    }
}

fn layer_names(layers: &[Layer]) -> Vec<&str> {
    layers.iter().map(|layer| layer.name.as_str()).collect()
}

const SDB: &str = "/sys/devices/pci0/block/sdb";
const SDB2: &str = "/sys/devices/pci0/block/sdb/sdb2";
const DM4: &str = "/sys/devices/virtual/block/dm-4";
const LOOP0: &str = "/sys/devices/virtual/block/loop0";

/// `sdb` with its partition `sdb2`, reachable by kernel name.
fn disk_with_partition(sysfs: &Sysfs) {
    sysfs
        .device(SDB, "sdb", "8:16")
        .partition(SDB2, "sdb2", "8:18", 2, "7f3a-02")
        .link("/sys/class/block/sdb2", SDB2)
        .link("/sys/dev/block/8:18", SDB2);
}

/// `loop0` bound to `backing`.
fn loop_device(sysfs: &Sysfs, backing: &str) {
    sysfs
        .device(LOOP0, "loop0", "7:0")
        .file(LOOP0, "loop/backing_file", backing)
        .file(LOOP0, "loop/offset", "1048576")
        .file(LOOP0, "loop/sizelimit", "0")
        .file(LOOP0, "loop/autoclear", "1");
}

// ------------------------------------------------------------------------
// Parsing seams
// ------------------------------------------------------------------------

#[test]
fn parse_backing_file_strips_newline_and_rejects_empty() {
    assert_eq!(
        parse_backing_file("/home/alice/family photos\n"),
        Some(PathBuf::from("/home/alice/family photos"))
    );
    assert_eq!(parse_backing_file("\n"), None);
    assert_eq!(parse_backing_file(""), None);
}

#[test]
fn parse_u64_handles_zero_value_and_garbage() {
    assert_eq!(parse_u64("0\n"), Some(0));
    assert_eq!(parse_u64("2147450880\n"), Some(2_147_450_880));
    assert_eq!(parse_u64("not-a-number"), None);
}

#[test]
fn uevent_values_are_read_by_exact_key() {
    let uevent = "MAJOR=8\nMINOR=18\nDEVNAME=sdb2\nDEVTYPE=partition\nPARTN=2\nPARTNAME=\n";
    assert_eq!(uevent_value(uevent, "DEVNAME").as_deref(), Some("sdb2"));
    assert_eq!(uevent_value(uevent, "PARTN").as_deref(), Some("2"));
    assert_eq!(uevent_value(uevent, "PARTNAME"), None, "empty");
    assert_eq!(uevent_value(uevent, "PARTUUID"), None, "absent");
    assert_eq!(uevent_value("MAJOR=7\nMINOR=0\n", "DEVNAME"), None);
}

#[test]
fn device_mapper_uuids_and_names_are_classified() {
    let kind = |uuid: &str, name: &str| classify_dm(uuid, name);
    assert_eq!(
        kind(
            "CRYPT-LUKS2-2f8d0c6a9b8e4f1ea1b2c3d4e5f60718-data\n",
            "data"
        ),
        DmKind::Crypt("LUKS2".into())
    );
    assert_eq!(
        kind("CRYPT-TCRYPT-veracrypt1", "veracrypt1"),
        DmKind::Crypt("TCRYPT".into()),
        "a cryptsetup mapping is known by its uuid, whatever its name"
    );
    assert_eq!(kind("CRYPT-SUBDEV-vault_1", "vault_1"), DmKind::CryptSubdev);
    assert_eq!(
        kind("CRYPT-INTEGRITY-0a1b-data_dif", "data_dif"),
        DmKind::Integrity
    );
    assert_eq!(kind("CRYPT-VERITY-0a1b-usr", "usr"), DmKind::Verity);
    assert_eq!(kind("", "veracrypt1"), DmKind::VeraCrypt);
    assert_eq!(kind("\n", "veracrypt12_0"), DmKind::VeraCrypt);
    assert_eq!(kind("", "veracrypt"), DmKind::Other);
    assert_eq!(kind("", "veracrypt1_"), DmKind::Other);
    assert_eq!(kind("", "veracryptX"), DmKind::Other);
    assert_eq!(
        kind(
            "LVM-Xo3dKq0f2l8Nn6VhR6x8V0Z3eY3QxVQkq6l9q7f3M2a3W2vR1nS7vB2ZqE4yT1aA",
            "vg-lv"
        ),
        DmKind::Lvm
    );
    assert_eq!(
        kind("mpath-3600508b400105e210000900000490000", "mpatha"),
        DmKind::Other
    );
    assert_eq!(kind("CRYPT-", "x"), DmKind::Other);
    assert_eq!(kind("crypt-tcrypt-lowercase", "x"), DmKind::Other);
}

// ------------------------------------------------------------------------
// The walk
// ------------------------------------------------------------------------

#[test]
fn a_partition_names_its_disk_number_start_name_and_uuid() {
    let sysfs = Sysfs::new();
    disk_with_partition(&sysfs);
    sysfs.file(SDB2, "size", "204800").file(SDB2, "ro", "0");

    let layers = sysfs.stack("/sys/class/block/sdb2", LoopFollow::default());

    assert_eq!(layer_names(&layers), vec!["sdb2"]);
    let sdb2 = &layers[0];
    assert_eq!(sdb2.sysfs, PathBuf::from(SDB2), "symlinks resolved");
    assert_eq!(sdb2.dev.as_deref(), Some("8:18"));
    assert_eq!(sdb2.size_sectors, Some(204_800));
    assert!(!sdb2.read_only);
    assert_eq!(
        sdb2.partition,
        Some(Partition {
            number: 2,
            start: Some(2048),
            disk: Some("sdb".into()),
            name: Some("scratch".into()),
            uuid: Some("7f3a-02".into()),
        })
    );
    assert_eq!(sdb2.dm, None);
    assert_eq!(sdb2.loop_device, None);
}

#[test]
fn a_whole_disk_is_no_partition() {
    let sysfs = Sysfs::new();
    sysfs.device(SDB, "sdb", "8:16");
    let layers = sysfs.stack(SDB, LoopFollow::default());
    assert_eq!(layers[0].partition, None);
}

#[test]
fn a_loop_over_a_block_node_walks_into_that_device() {
    let sysfs = Sysfs::new();
    disk_with_partition(&sysfs);
    loop_device(&sysfs, "/dev/sdb2");

    let layers = sysfs.stack(LOOP0, LoopFollow::default());

    assert_eq!(layer_names(&layers), vec!["loop0", "sdb2"]);
    assert_eq!(
        layers[0].loop_device,
        Some(LoopDevice {
            backing: LoopBacking::Block {
                path: PathBuf::from("/dev/sdb2"),
                name: "sdb2".into(),
            },
            offset: 1_048_576,
            size_limit: 0,
            autoclear: true,
        })
    );
    assert!(
        layers[0].slaves.is_empty(),
        "the loop driver links no slaves"
    );
    assert_eq!(
        layers[1]
            .partition
            .as_ref()
            .and_then(|part| part.disk.as_deref()),
        Some("sdb")
    );

    // Told to stop at loop devices, the walk does.
    let layers = sysfs.stack(LOOP0, LoopFollow::Never);
    assert_eq!(layer_names(&layers), vec!["loop0"]);
}

#[test]
fn a_loop_over_a_mapper_node_walks_into_the_crypt_layer_and_below() {
    let sysfs = Sysfs::new();
    disk_with_partition(&sysfs);
    loop_device(&sysfs, "/dev/mapper/vault");
    sysfs
        .link("/dev/mapper/vault", "/dev/dm-4")
        .device(DM4, "dm-4", "253:4")
        .file(DM4, "dm/name", "vault")
        .file(DM4, "dm/uuid", "CRYPT-TCRYPT-vault")
        .link("/sys/class/block/dm-4", DM4)
        .links(DM4, "slaves", &[("sdb2", SDB2)]);

    let layers = sysfs.stack(LOOP0, LoopFollow::default());

    assert_eq!(layer_names(&layers), vec!["loop0", "dm-4", "sdb2"]);
    assert_eq!(
        layers[0].loop_device.as_ref().map(|l| &l.backing),
        Some(&LoopBacking::Block {
            path: PathBuf::from("/dev/mapper/vault"),
            name: "dm-4".into(),
        })
    );
    assert_eq!(
        layers[1].dm,
        Some(DeviceMapper {
            name: "vault".into(),
            uuid: "CRYPT-TCRYPT-vault".into(),
            kind: DmKind::Crypt("TCRYPT".into()),
        })
    );
    assert_eq!(layers[1].slaves, vec!["sdb2"]);
}

#[test]
fn a_loop_over_a_regular_file_stops_unless_told_to_follow_it() {
    let sysfs = Sysfs::new();
    loop_device(&sysfs, "/home/alice/photos.img");
    // The file lies on an ext4 filesystem on a LUKS mapping of nvme0n1p3.
    let dm1 = "/sys/devices/virtual/block/dm-1";
    let p3 = "/sys/devices/pci0/nvme/nvme0n1/nvme0n1p3";
    sysfs
        .device(dm1, "dm-1", "254:1")
        .file(dm1, "dm/name", "luks-home")
        .file(
            dm1,
            "dm/uuid",
            "CRYPT-LUKS2-00112233445566778899aabbccddeeff-luks-home",
        )
        .link("/sys/dev/block/254:1", dm1)
        .links(dm1, "slaves", &[("nvme0n1p3", p3)])
        .device("/sys/devices/pci0/nvme/nvme0n1", "nvme0n1", "259:0")
        .partition(p3, "nvme0n1p3", "259:3", 3, "c0ffee-03");
    sysfs.0.mock_set_device_id(
        Path::new("/home/alice/photos.img"),
        rustix::fs::makedev(254, 1),
    );

    let stops = sysfs.stack(LOOP0, LoopFollow::default());
    assert_eq!(layer_names(&stops), vec!["loop0"]);
    assert_eq!(
        stops[0].loop_device.as_ref().map(|l| &l.backing),
        Some(&LoopBacking::File(PathBuf::from("/home/alice/photos.img")))
    );

    let follows = sysfs.stack(LOOP0, LoopFollow::BackingFiles);
    assert_eq!(layer_names(&follows), vec!["loop0", "dm-1", "nvme0n1p3"]);
    assert_eq!(
        follows[2]
            .partition
            .as_ref()
            .and_then(|part| part.disk.as_deref()),
        Some("nvme0n1")
    );
}

#[test]
fn a_backing_file_on_btrfs_is_followed_through_its_mount() {
    // btrfs gives its files an anonymous device number, so the walk falls
    // back to the device of the mount that holds the file.
    let sysfs = Sysfs::new();
    loop_device(&sysfs, "/srv/vm/box.img");
    sysfs.0.mock_set_file_content(
        "/proc/self/mountinfo",
        "1 0 254:0 / / rw - ext4 /dev/mapper/root rw\n\
         40 1 0:52 /@srv /srv rw - btrfs /dev/mapper/pool rw,subvol=/@srv\n",
    );
    let dm7 = "/sys/devices/virtual/block/dm-7";
    sysfs
        .device(dm7, "dm-7", "254:7")
        .file(dm7, "dm/name", "pool")
        .file(
            dm7,
            "dm/uuid",
            "CRYPT-LUKS2-ffeeddccbbaa99887766554433221100-pool",
        )
        .links("/sys", "block", &[("dm-7", dm7)]);

    let layers = sysfs.stack(LOOP0, LoopFollow::BackingFiles);
    assert_eq!(layer_names(&layers), vec!["loop0", "dm-7"]);
}

#[test]
fn a_backing_file_in_ram_has_nothing_below() {
    let sysfs = Sysfs::new();
    loop_device(&sysfs, "/run/scratch.img");
    sysfs.0.mock_set_file_content(
        "/proc/self/mountinfo",
        "1 0 254:0 / / rw - ext4 /dev/vda2 rw\n\
         22 1 0:25 / /run rw - tmpfs tmpfs rw\n",
    );
    let layers = sysfs.stack(LOOP0, LoopFollow::BackingFiles);
    assert_eq!(layer_names(&layers), vec!["loop0"]);
}

#[test]
fn holders_and_the_read_only_flag_are_read() {
    let sysfs = Sysfs::new();
    let dm1 = "/sys/devices/virtual/block/dm-1";
    sysfs
        .device(dm1, "dm-1", "254:1")
        .file(dm1, "ro", "1")
        .file(dm1, "size", "409600")
        .file(dm1, "queue/discard_max_bytes", "2147450880")
        .links(
            dm1,
            "holders",
            &[
                ("dm-3", "/sys/devices/virtual/block/dm-3"),
                ("dm-2", "/sys/devices/virtual/block/dm-2"),
            ],
        );

    let layer = &sysfs.stack(dm1, LoopFollow::default())[0];
    assert!(layer.read_only);
    assert_eq!(layer.size_sectors, Some(409_600));
    assert_eq!(layer.discard_max_bytes, 2_147_450_880);
    assert_eq!(layer.holders, vec!["dm-2", "dm-3"], "sorted");
}

#[test]
fn a_cascade_classifies_its_veracrypt_and_subdev_layers() {
    let sysfs = Sysfs::new();
    let (top, inner) = (
        "/sys/devices/virtual/block/dm-5",
        "/sys/devices/virtual/block/dm-6",
    );
    sysfs
        .device(top, "dm-5", "253:5")
        .file(top, "dm/name", "vault")
        .file(top, "dm/uuid", "CRYPT-TCRYPT-vault")
        .links(top, "slaves", &[("dm-6", inner)])
        .device(inner, "dm-6", "253:6")
        .file(inner, "dm/name", "vault_1")
        .file(inner, "dm/uuid", "CRYPT-SUBDEV-vault_1");
    let layers = sysfs.stack(top, LoopFollow::default());
    let kinds: Vec<_> = layers
        .iter()
        .map(|layer| layer.dm.as_ref().map(|dm| dm.kind.clone()))
        .collect();
    assert_eq!(
        kinds,
        vec![
            Some(DmKind::Crypt("TCRYPT".into())),
            Some(DmKind::CryptSubdev)
        ]
    );

    // The VeraCrypt application's own mapping carries no uuid.
    let sysfs = Sysfs::new();
    let vc = "/sys/devices/virtual/block/dm-9";
    sysfs
        .device(vc, "dm-9", "253:9")
        .file(vc, "dm/name", "veracrypt1")
        .file(vc, "dm/uuid", "");
    let layer = &sysfs.stack(vc, LoopFollow::default())[0];
    assert_eq!(
        layer.dm.as_ref().map(|dm| &dm.kind),
        Some(&DmKind::VeraCrypt)
    );
    assert_eq!(layer.dm.as_ref().map(|dm| dm.uuid.as_str()), Some(""));
}

#[test]
fn a_device_reached_twice_is_read_once() {
    // An LVM snapshot: its -real and -cow halves both sit on the same PV.
    let sysfs = Sysfs::new();
    let (dm1, dm2, dm3) = (
        "/sys/devices/virtual/block/dm-1",
        "/sys/devices/virtual/block/dm-2",
        "/sys/devices/virtual/block/dm-3",
    );
    sysfs
        .device(dm3, "dm-3", "254:3")
        .links(dm3, "slaves", &[("dm-1", dm1), ("dm-2", dm2)])
        .device(dm1, "dm-1", "254:1")
        .links(dm1, "slaves", &[("sdb", SDB)])
        .device(dm2, "dm-2", "254:2")
        .links(dm2, "slaves", &[("sdb", SDB)])
        .device(SDB, "sdb", "8:16");

    let layers = sysfs.stack(dm3, LoopFollow::default());
    assert_eq!(layer_names(&layers), vec!["dm-3", "dm-1", "dm-2", "sdb"]);
}

#[test]
fn the_walk_reads_at_most_the_bound() {
    let sysfs = Sysfs::new();
    let dir = |n: usize| format!("/sys/devices/virtual/block/dm-{n}");
    for n in 0..MAX_STACK_DEVICES + 4 {
        sysfs.device(&dir(n), &format!("dm-{n}"), &format!("254:{n}"));
        let (name, below) = (format!("dm-{}", n + 1), dir(n + 1));
        sysfs.links(&dir(n), "slaves", &[(name.as_str(), below.as_str())]);
    }
    assert_eq!(
        sysfs.stack(&dir(0), LoopFollow::default()).len(),
        MAX_STACK_DEVICES
    );
}

#[test]
fn an_unreadable_top_is_one_empty_layer_named_by_its_directory() {
    let layers = stack(
        &MockFilesystem::new(),
        Path::new("/sys/dev/block/8:99"),
        LoopFollow::default(),
    );
    assert_eq!(layer_names(&layers), vec!["8:99"]);
    assert_eq!(layers[0].dev, None);
}

// ------------------------------------------------------------------------
// Finding the device: mounts, specs and btrfs
// ------------------------------------------------------------------------

#[test]
fn a_mount_is_found_by_number_by_mapper_name_or_by_kernel_name() {
    let sysfs = Sysfs::new();
    disk_with_partition(&sysfs);
    sysfs
        .device(DM4, "dm-4", "253:4")
        .file(DM4, "dm/name", "data")
        .links("/sys", "block", &[("dm-4", DM4), ("sdb", SDB)]);
    let mount = |line: &str| parse_mountinfo(line).remove(0);

    let by_number = mount("40 1 8:18 / /mnt/data rw - ext4 /dev/sdb2 rw");
    assert_eq!(
        device_of_mount(&sysfs.0, &by_number),
        Some(PathBuf::from(SDB2))
    );
    let btrfs_mapper = mount("40 1 0:45 / /mnt/data rw - btrfs /dev/mapper/data rw");
    assert_eq!(
        device_of_mount(&sysfs.0, &btrfs_mapper),
        Some(PathBuf::from(DM4))
    );
    let btrfs_name = mount("40 1 0:46 / /mnt/data rw - btrfs /dev/sdb2 rw");
    assert_eq!(
        device_of_mount(&sysfs.0, &btrfs_name),
        Some(PathBuf::from(SDB2))
    );
    let zfs = mount("40 1 0:47 / /mnt/data rw - zfs tank/data rw");
    assert_eq!(device_of_mount(&sysfs.0, &zfs), None);
}

#[test]
fn specs_resolve_through_dev_to_their_device() {
    let sysfs = Sysfs::new();
    disk_with_partition(&sysfs);
    sysfs
        .device(DM4, "dm-4", "253:4")
        .link("/sys/class/block/dm-4", DM4)
        .link("/dev/disk/by-uuid/0a1b-2c3d", "/dev/dm-4")
        .link("/dev/disk/by-partuuid/7f3a-02", "/dev/sdb2")
        .link("/dev/disk/by-label/data", "/dev/sdb2")
        .link("/dev/disk/by-partlabel/scratch", "/dev/sdb2")
        .link("/dev/mapper/data", "/dev/dm-4");

    let resolve = |spec: &str| resolve_spec(&sysfs.0, spec);
    assert_eq!(resolve("UUID=0a1b-2c3d"), Some(PathBuf::from(DM4)));
    assert_eq!(resolve("PARTUUID=7f3a-02"), Some(PathBuf::from(SDB2)));
    assert_eq!(resolve("LABEL=data"), Some(PathBuf::from(SDB2)));
    assert_eq!(resolve("PARTLABEL=scratch"), Some(PathBuf::from(SDB2)));
    assert_eq!(resolve("/dev/mapper/data"), Some(PathBuf::from(DM4)));
    assert_eq!(resolve("/dev/sdb2"), Some(PathBuf::from(SDB2)));
    // A missing device, a file, a pseudo source.
    assert_eq!(resolve("UUID=ffff"), None);
    assert_eq!(resolve("/dev/sdz9"), None);
    assert_eq!(resolve("/home/alice/box.img"), None);
    assert_eq!(resolve("tmpfs"), None);
}

#[test]
fn btrfs_members_are_every_device_of_the_filesystem() {
    // The fsid directories are real directories; their devices/ entries are
    // links to the member devices.
    let sysfs = Sysfs::new();
    let fsid = "/sys/fs/btrfs/0a1b2c3d-0000-4000-8000-000000000001";
    sysfs.0.mock_set_directory_contents(
        Path::new("/sys/fs/btrfs"),
        vec![PathBuf::from("/sys/fs/btrfs/features"), PathBuf::from(fsid)],
    );
    sysfs.links(
        fsid,
        "devices",
        &[
            ("sdb3", "/sys/devices/pci0/block/sdb/sdb3"),
            ("dm-1", "/sys/devices/virtual/block/dm-1"),
        ],
    );
    assert_eq!(btrfs_members(&sysfs.0, "sdb3"), vec!["dm-1", "sdb3"]);
    assert_eq!(btrfs_members(&sysfs.0, "dm-1"), vec!["dm-1", "sdb3"]);
    assert!(btrfs_members(&sysfs.0, "sda1").is_empty());
    assert!(btrfs_members(&MockFilesystem::new(), "sdb3").is_empty());
}

// ------------------------------------------------------------------------
// A captured scene
// ------------------------------------------------------------------------

/// Load a `capture-kernel-fixtures.sh blockdev` capture into a mock: `link`,
/// `file` and `dir` records become symlinks, files and listings. Returns the
/// `mount` records.
fn load_capture(fs: &MockFilesystem, capture: &str) -> Vec<String> {
    let mut mounts = Vec::new();
    for line in capture.lines() {
        let mut fields = line.splitn(3, '\t');
        match (fields.next(), fields.next(), fields.next()) {
            (Some("mount"), Some(entry), None) => mounts.push(entry.to_string()),
            (Some("link"), Some(link), Some(target)) => fs
                .create_symlink(Path::new(target), Path::new(link))
                .unwrap(),
            (Some("file"), Some(path), Some(content)) => {
                fs.mock_set_file_content(path, &unescape_capture(content));
            }
            (Some("dir"), Some(dir), entries) => fs.mock_set_directory_contents(
                Path::new(dir),
                entries
                    .unwrap_or_default()
                    .split(' ')
                    .filter(|name| !name.is_empty())
                    .map(|name| Path::new(dir).join(name))
                    .collect(),
            ),
            _ => {}
        }
    }
    mounts
}

/// Undo the capture's escapes: `\n` is a newline, `\\` a backslash.
fn unescape_capture(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut chars = content.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// The LVM-on-LUKS scene captured as root in a VM (the fixture README): an
/// ext4 logical volume on a LUKS2 mapping of the first GPT partition of a
/// loop device.
#[test]
fn the_captured_lvm_on_luks_scene_is_walked_to_its_partition() {
    let path = crate::kernel_fixtures::root().join("vm/blockdev-lvm-on-luks.txt");
    let Ok(capture) = std::fs::read_to_string(&path) else {
        eprintln!(
            "the LVM-on-LUKS capture is not taken yet; the research-blockdev-fixtures VM \
             test produces it (tests/fixtures/kernel/README.md)"
        );
        return;
    };
    let fs = MockFilesystem::new();
    let mounts = load_capture(&fs, &capture);
    let mount = parse_mountinfo(&mounts.join("\n"))
        .pop()
        .expect("the capture records the volume's mount");
    let top = device_of_mount(&fs, &mount).expect("the volume's device");

    let layers = stack(&fs, &top, LoopFollow::default());

    let kinds: Vec<_> = layers
        .iter()
        .map(|layer| layer.dm.as_ref().map(|dm| dm.kind.clone()))
        .collect();
    assert_eq!(
        kinds,
        vec![Some(DmKind::Lvm), Some(DmKind::Crypt("LUKS2".into())), None]
    );
    assert_eq!(layers[1].holders, vec![layers[0].name.clone()]);
    assert_eq!(layers[2].holders, vec![layers[1].name.clone()]);
    let partition = layers[2].partition.as_ref().expect("a partition");
    assert_eq!(partition.number, 1);
    assert_eq!(partition.name.as_deref(), Some("scene"));
    assert!(
        partition
            .disk
            .as_deref()
            .is_some_and(|disk| disk.starts_with("loop")),
        "{partition:?}"
    );
    for layer in &layers {
        assert!(layer.dev.is_some(), "{layer:?}");
        assert!(layer.size_sectors.is_some_and(|size| size > 0), "{layer:?}");
        assert!(!layer.read_only, "{layer:?}");
    }
}
