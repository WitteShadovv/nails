// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the storage below the hidden volume and its names.

use super::*;
use crate::filesystem::MockFilesystem;
use nails_base::filesystem::parse_mountinfo;

const DM0: &str = "/sys/devices/virtual/block/dm-0";
const DM1: &str = "/sys/devices/virtual/block/dm-1";
const SDB2: &str = "/sys/devices/pci0/block/sdb/sdb2";
const LOOP0: &str = "/sys/devices/virtual/block/loop0";
const LUKS: &str = "CRYPT-LUKS2-7d2c9e14e8a14b3c9f6b0e1a2d3c4b5a-data";

/// A mock sysfs: each device's directory, with `/sys/dev/block` and
/// `slaves` and `holders` links, as the kernel lays them out.
struct Sysfs(MockFilesystem);

impl Sysfs {
    fn new() -> Self {
        Self(MockFilesystem::new())
    }
    fn device(&self, dir: &str, dev: &str, uevent: &str) -> &Self {
        self.0
            .mock_set_file_content(&format!("{dir}/dev"), &format!("{dev}\n"));
        self.0
            .mock_set_file_content(&format!("{dir}/uevent"), &format!("{uevent}\n"));
        self.link(&format!("/sys/dev/block/{dev}"), dir)
    }
    fn dm(&self, dir: &str, dev: &str, name: &str, uuid: &str) -> &Self {
        self.device(dir, dev, "DEVTYPE=disk");
        self.0
            .mock_set_file_content(&format!("{dir}/dm/name"), &format!("{name}\n"));
        self.0
            .mock_set_file_content(&format!("{dir}/dm/uuid"), &format!("{uuid}\n"));
        self
    }
    fn links(&self, dir: &str, sub: &str, targets: &[&str]) -> &Self {
        let parent = Path::new(dir).join(sub);
        let mut paths = Vec::new();
        for target in targets {
            let link = parent.join(Path::new(target).file_name().unwrap());
            self.link(link.to_str().unwrap(), target);
            paths.push(link);
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
    /// udev's record of the device `dev`.
    fn udev(&self, dev: &str, record: &str) -> &Self {
        self.0
            .mock_set_file_content(&format!("/run/udev/data/b{dev}"), record);
        self
    }
    /// The `/dev/disk` directories, each with its links to device nodes.
    fn dev_disk(&self, links: &[(&str, &str)]) -> &Self {
        let mut dirs: Vec<PathBuf> = Vec::new();
        for (link, node) in links {
            self.link(link, node);
            let dir = Path::new(link).parent().unwrap().to_path_buf();
            if !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
        for dir in &dirs {
            let entries = links
                .iter()
                .map(|(link, _)| PathBuf::from(link))
                .filter(|link| link.parent() == Some(dir.as_path()))
                .collect();
            self.0.mock_set_directory_contents(dir, entries);
        }
        self.0
            .mock_set_directory_contents(Path::new("/dev/disk"), dirs);
        self
    }
    fn below(&self, mountinfo: &str) -> Storage {
        below(&self.0, &parse_mountinfo(mountinfo), Path::new("/mnt/data"))
    }
    /// The whole check on `content`, as (line, text, kind).
    fn scan(&self, content: &str) -> Vec<(usize, String, super::super::ReferenceKind)> {
        let file = "/etc/nixos/configuration.nix";
        self.0
            .mock_set_file_content("/proc/self/mountinfo", DATA_MOUNT);
        self.0
            .mock_set_files_with_pattern("/etc/nixos", ".nix", &[Path::new(file)]);
        self.0.mock_set_file_content(file, content);
        super::super::verify_base_config_clean(&self.0, Path::new("/mnt/data"))
            .unwrap()
            .references
            .into_iter()
            .map(|r| (r.line, r.text, r.kind))
            .collect()
    }
}

/// The documented layout: `data`, a LUKS2 mapping on the partition sdb2.
fn luks_on_a_partition() -> Sysfs {
    let sysfs = Sysfs::new();
    sysfs
        .dm(DM0, "254:0", "data", LUKS)
        .links(DM0, "slaves", &[SDB2])
        .device(
            SDB2,
            "8:18",
            "DEVTYPE=partition\nPARTN=2\nPARTUUID=4f1b0a7d-02",
        )
        .links(SDB2, "holders", &[DM0]);
    sysfs
        .0
        .mock_set_file_content(&format!("{SDB2}/partition"), "2\n");
    sysfs
}

/// What udev records for that layout: the partition's links and its LUKS
/// header's uuid and label, the mapping's links, and the uuid and label of
/// the filesystem in it.
fn with_udev(sysfs: Sysfs) -> Sysfs {
    sysfs
        .udev(
            "8:18",
            "S:disk/by-id/ata-QEMU_HARDDISK_QM00002-part2\n\
             S:disk/by-path/pci-0000:00:17.0-ata-2-part2\n\
             S:disk/by-partlabel/vault\n\
             S:disk/by-partuuid/4f1b0a7d-02\n\
             S:disk/by-uuid/7d2c9e14-e8a1-4b3c-9f6b-0e1a2d3c4b5a\n\
             S:disk/by-label/My\\x20Vault\n\
             S:disk/by-diskseq/2-part2\n\
             I:12345\n\
             E:ID_FS_UUID=7d2c9e14-e8a1-4b3c-9f6b-0e1a2d3c4b5a\n\
             E:ID_FS_LABEL=My_Vault\n\
             E:ID_FS_LABEL_ENC=My\\x20Vault\n\
             E:ID_FS_TYPE=crypto_LUKS\n\
             E:ID_PART_ENTRY_NAME=vault\n\
             E:ID_PART_ENTRY_UUID=4f1b0a7d-02\n\
             G:systemd\n",
        )
        .udev(
            "254:0",
            "S:mapper/data\n\
             S:disk/by-id/dm-name-data\n\
             S:disk/by-id/dm-uuid-CRYPT-LUKS2-7d2c9e14e8a14b3c9f6b0e1a2d3c4b5a-data\n\
             S:disk/by-uuid/0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7b\n\
             S:disk/by-label/secrets\n\
             E:ID_FS_UUID=0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7b\n\
             E:ID_FS_LABEL=secrets\n\
             E:ID_FS_LABEL_ENC=secrets\n\
             E:ID_FS_TYPE=ext4\n",
        );
    sysfs
}

const DATA_MOUNT: &str = "36 35 254:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n";

fn path(text: &str) -> Pattern {
    Pattern::Path(text.into())
}

fn tag(tag: &str, value: &str) -> Pattern {
    Pattern::Tag {
        tag: tag.into(),
        value: value.into(),
    }
}

#[test]
fn a_luks_mapping_on_a_partition_is_named_by_both_and_their_uuids() {
    let storage = luks_on_a_partition().below(DATA_MOUNT);
    assert_eq!(storage.names, ["data"]);
    assert_eq!(
        storage.markers,
        [
            path(&format!("/dev/disk/by-id/dm-uuid-{}", LUKS.to_lowercase())),
            Pattern::Text("7d2c9e14-e8a1-4b3c-9f6b-0e1a2d3c4b5a".into()),
            path("/dev/sdb2"),
            Pattern::Text("4f1b0a7d-02".into()),
        ]
    );
}

/// Every link udev made for a layer, and the uuids and labels it records:
/// the partition's and its LUKS header's, and the filesystem's own.
#[test]
fn every_name_udev_gives_a_layer_is_a_marker() {
    let storage = with_udev(luks_on_a_partition()).below(DATA_MOUNT);
    for marker in [
        path("/dev/mapper/data"),
        path("/dev/disk/by-id/dm-name-data"),
        path("/dev/disk/by-uuid/0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7b"),
        path("/dev/disk/by-label/secrets"),
        Pattern::Text("0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7b".into()),
        tag("label", "secrets"),
        path("/dev/disk/by-id/ata-qemu_harddisk_qm00002-part2"),
        path("/dev/disk/by-path/pci-0000:00:17.0-ata-2-part2"),
        path("/dev/disk/by-partlabel/vault"),
        path("/dev/disk/by-partuuid/4f1b0a7d-02"),
        path("/dev/disk/by-diskseq/2-part2"),
        path("/dev/disk/by-label/my\\x20vault"),
        path("/dev/disk/by-label/my\\\\x20vault"),
        tag("label", "my vault"),
        tag("partlabel", "vault"),
    ] {
        assert!(
            storage.markers.contains(&marker),
            "{marker:?}: {storage:#?}"
        );
    }
    // Each once, the LUKS uuid and the partition uuid included.
    for (index, marker) in storage.markers.iter().enumerate() {
        assert!(
            !storage.markers[..index].contains(marker),
            "{marker:?} twice"
        );
    }
    assert!(!storage.markers.contains(&tag("label", "my_vault")));
}

/// Without udev's database, the `/dev/disk` links that resolve to a layer
/// still count, and so do the uuid and the labels in their names.
#[test]
fn the_dev_disk_links_count_without_udev_s_database() {
    let sysfs = luks_on_a_partition();
    sysfs.dev_disk(&[
        ("/dev/disk/by-id/ata-DISK-part2", "../../sdb2"),
        ("/dev/disk/by-id/ata-DISK-part1", "../../sdb1"),
        ("/dev/disk/by-uuid/0b6e2a51", "../../dm-0"),
        ("/dev/disk/by-label/My\\x20Vault", "../../sdb2"),
        ("/dev/disk/by-partlabel/vault", "../../sdb2"),
        ("/dev/disk/by-uuid/5a1b-2c3d", "../../sda1"),
    ]);
    let storage = sysfs.below(DATA_MOUNT);
    for marker in [
        path("/dev/disk/by-id/ata-disk-part2"),
        path("/dev/disk/by-uuid/0b6e2a51"),
        Pattern::Text("0b6e2a51".into()),
        tag("label", "my vault"),
        tag("partlabel", "vault"),
    ] {
        assert!(
            storage.markers.contains(&marker),
            "{marker:?}: {storage:#?}"
        );
    }
    for other in [
        path("/dev/disk/by-id/ata-disk-part1"),
        Pattern::Text("5a1b-2c3d".into()),
    ] {
        assert!(!storage.markers.contains(&other), "{other:?}");
    }
}

/// `vg-hidden`, a logical volume on the LUKS mapping `data`, which holds
/// another logical volume too when `shared`.
fn lvm_on_luks(shared: bool) -> Sysfs {
    let sysfs = Sysfs::new();
    let mut holders = vec![DM1];
    if shared {
        holders.push("/sys/devices/virtual/block/dm-2");
    }
    sysfs
        .dm(DM1, "254:1", "vg-hidden", "LVM-abc")
        .links(DM1, "slaves", &[DM0])
        .dm(DM0, "254:0", "data", LUKS)
        .links(DM0, "holders", &holders)
        .links(DM0, "slaves", &[SDB2])
        .device(SDB2, "8:18", "DEVTYPE=partition")
        .links(SDB2, "holders", &[DM0])
        .udev("254:1", "S:vg/hidden\nS:mapper/vg-hidden\n")
        .udev("254:0", "S:disk/by-id/dm-name-data\n")
        .udev("8:18", "S:disk/by-id/ata-DISK-part2\n");
    sysfs
}

const LV_MOUNT: &str = "36 35 254:1 / /mnt/data rw - ext4 /dev/mapper/vg-hidden rw\n";

/// A logical volume of a volume group that holds the decoy's own volumes
/// too: the LUKS mapping and the partition below it are the decoy's, and so
/// are their names.
#[test]
fn storage_the_decoy_shares_is_not_the_hidden_volume_s() {
    let storage = lvm_on_luks(true).below(LV_MOUNT);
    assert_eq!(storage.names, ["vg-hidden"]);
    assert_eq!(
        storage.markers,
        [
            path("/dev/disk/by-id/dm-uuid-lvm-abc"),
            path("/dev/vg/hidden"),
            path("/dev/mapper/vg-hidden"),
        ]
    );

    // Alone on the mapping, the mapping and the partition are its own.
    let storage = lvm_on_luks(false).below(LV_MOUNT);
    assert_eq!(storage.names, ["vg-hidden", "data"]);
    for marker in [
        path("/dev/sdb2"),
        path("/dev/disk/by-id/dm-name-data"),
        path("/dev/disk/by-id/ata-disk-part2"),
    ] {
        assert!(storage.markers.contains(&marker), "{marker:?}");
    }
}

#[test]
fn an_image_file_behind_a_loop_device_is_named_by_its_path() {
    let sysfs = Sysfs::new();
    sysfs
        .dm(DM0, "254:0", "data", "CRYPT-TCRYPT-data")
        .links(DM0, "slaves", &[LOOP0])
        .device(LOOP0, "7:0", "DEVTYPE=disk")
        .links(LOOP0, "holders", &[DM0]);
    sysfs.0.mock_set_file_content(
        &format!("{LOOP0}/loop/backing_file"),
        "/var/lib/Vault.img\n",
    );
    let storage = sysfs.below(DATA_MOUNT);
    assert_eq!(storage.names, ["data"]);
    assert_eq!(
        storage.markers,
        [
            path("/dev/disk/by-id/dm-uuid-crypt-tcrypt-data"),
            path("/var/lib/vault.img"),
        ]
    );
}

/// The whole check: a decoy configuration that names the volume by what
/// it is stored on is refused, whatever the case of the text.
#[test]
fn a_configuration_naming_the_storage_below_the_volume_is_refused() {
    use super::super::ReferenceKind::Storage;
    let sysfs = luks_on_a_partition();
    for (content, text) in [
        (
            "{ boot.initrd.luks.devices.root.device =\n  \"/dev/disk/by-uuid/7d2c9e14-e8a1-4b3c-9f6b-0e1a2d3c4b5a\"; }",
            "7d2c9e14-e8a1-4b3c-9f6b-0e1a2d3c4b5a",
        ),
        (
            "{ }\n# vault UUID=7D2C9E14-E8A1-4B3C-9F6B-0E1A2D3C4B5A none\n",
            "7D2C9E14-E8A1-4B3C-9F6B-0E1A2D3C4B5A",
        ),
        ("{ }\n# was /dev/sdb2 before\n", "/dev/sdb2"),
        ("{ }\n# /dev/disk/by-partuuid/4f1b0a7d-02\n", "4f1b0a7d-02"),
    ] {
        assert_eq!(
            sysfs.scan(content),
            [(2, text.to_string(), Storage)],
            "{content}"
        );
    }
}

/// The names a hand-written configuration gives the hidden storage most
/// often, live or commented out, each refused on its line: the partition's
/// `by-id`, `by-path` and `by-partlabel` links, the filesystem's uuid and
/// label, a VeraCrypt mount by `by-id`, the old list form.
#[test]
fn every_other_name_of_the_hidden_storage_is_refused() {
    use super::super::ReferenceKind::Storage;
    let sysfs = with_udev(luks_on_a_partition());
    for (content, expected) in [
        (
            "{ boot.initrd.luks.devices.cryptdata.device = \"/dev/disk/by-id/ata-QEMU_HARDDISK_QM00002-part2\"; }",
            (
                1,
                "/dev/disk/by-id/ata-QEMU_HARDDISK_QM00002-part2",
                Storage,
            ),
        ),
        (
            "{ boot.initrd.luks.devices.cryptdata.device = \"/dev/disk/by-path/pci-0000:00:17.0-ata-2-part2\"; }",
            (1, "/dev/disk/by-path/pci-0000:00:17.0-ata-2-part2", Storage),
        ),
        (
            "{ boot.initrd.luks.devices.cryptdata.device = \"/dev/disk/by-partlabel/vault\"; }",
            (1, "/dev/disk/by-partlabel/vault", Storage),
        ),
        (
            "{ systemd.services.x.script = \"veracrypt --text --mount /dev/disk/by-id/ata-QEMU_HARDDISK_QM00002-part2 --slot 3\"; }",
            (
                1,
                "/dev/disk/by-id/ata-QEMU_HARDDISK_QM00002-part2",
                Storage,
            ),
        ),
        (
            "{ }\n# boot.initrd.luks.devices = [ { name = \"vault\"; device = \"/dev/disk/by-id/ata-QEMU_HARDDISK_QM00002-part2\"; } ];\n",
            (
                2,
                "/dev/disk/by-id/ata-QEMU_HARDDISK_QM00002-part2",
                Storage,
            ),
        ),
        (
            "{ fileSystems.\"/srv\".device = \"/dev/disk/by-uuid/0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7b\"; }",
            (
                1,
                "/dev/disk/by-uuid/0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7b",
                Storage,
            ),
        ),
        (
            "{ }\n# UUID=0B6E2A51-93C4-4D7E-8F1A-2C3D4E5F6A7B /srv ext4 defaults 0 2\n",
            (2, "0B6E2A51-93C4-4D7E-8F1A-2C3D4E5F6A7B", Storage),
        ),
        (
            "{ fileSystems.\"/srv\".label = \"secrets\"; }",
            (1, "secrets", Storage),
        ),
        (
            "{ }\n# LABEL=secrets /srv ext4 defaults 0 2\n",
            (2, "secrets", Storage),
        ),
        (
            "{ fileSystems.\"/srv\".device = \"/dev/disk/by-label/secrets\"; }",
            (1, "/dev/disk/by-label/secrets", Storage),
        ),
        ("{ }\n# PARTLABEL=vault\n", (2, "vault", Storage)),
    ] {
        let (line, text, kind) = expected;
        assert_eq!(
            sysfs.scan(content),
            [(line, text.to_string(), kind)],
            "{content}"
        );
    }
}

/// The decoy's own storage, and words that equal a label, pass.
#[test]
fn the_decoy_s_own_storage_and_ordinary_words_pass() {
    let sysfs = with_udev(luks_on_a_partition());
    for content in [
        "{ fileSystems.\"/\".device = \"/dev/disk/by-uuid/0f6c1a3e-2b51-4c0e-9d9a-4f1b0a7d2c11\"; }",
        "{ fileSystems.\"/home\".device = \"/dev/disk/by-id/ata-QEMU_HARDDISK_QM00002-part1\"; }",
        "{ services.vault.enable = true; }",
        "{ }\n# keep secrets out of the store\n",
        "{ networking.hostName = \"secrets\"; }",
        "{ fileSystems.\"/srv\".device = \"/dev/disk/by-id/dm-uuid-CRYPT-LUKS2-0123456789abcdef0123456789abcdef-user-data\"; }",
    ] {
        assert_eq!(sysfs.scan(content), [], "{content}");
    }
}

#[test]
fn without_sysfs_or_a_mount_nothing_is_added() {
    assert_eq!(Sysfs::new().below(DATA_MOUNT), Storage::default());
    assert_eq!(luks_on_a_partition().below(""), Storage::default());
}

#[test]
fn udev_escapes_are_decoded() {
    assert_eq!(unescape("My\\x20Vault"), "My Vault");
    assert_eq!(unescape("a\\x2fb\\xzz"), "a/b\\xzz");
    assert_eq!(unescape("plain"), "plain");
}
