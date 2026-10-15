// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the hidden volume is stored on, and the names a decoy configuration
//! could give it.
//!
//! The mount table names only the top device (`/dev/mapper/data`). A
//! configuration can name the volume by what lies below it as well: the
//! partition (`/dev/sdb2`), its partition uuid, the LUKS uuid that
//! `/dev/disk/by-uuid` and crypttab's `UUID=` use, the LUKS mapping below a
//! logical volume, or the image file behind a loop device. [`below`] reads
//! them from sysfs through the [`Filesystem`] trait.

use super::nix_text::Pattern;
use crate::filesystem::Filesystem;
use nails_base::blockdev::{self, DeviceMapper, DmKind, Layer, LoopBacking, LoopFollow};
use nails_base::filesystem::MountEntry;
use std::path::Path;

/// The storage below the hidden volume's mount, lowercased like the text it
/// is matched against.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Storage {
    /// The device-mapper name of every layer, top first.
    pub(super) names: Vec<String>,
    /// The paths and identifiers of the layers: `/dev/disk/by-id/dm-uuid-…`
    /// links, LUKS uuids, partitions and disks, partition uuids, image files.
    pub(super) markers: Vec<Pattern>,
}

/// The storage below the top mount at `root` in `mounts`. A device below the
/// top one counts only while everything built on it belongs to the hidden
/// volume: when the hidden root is a logical volume in the decoy's own
/// encrypted volume group, the LUKS mapping and the partition below it are
/// the decoy's, and its configuration names them.
pub(super) fn below<F: Filesystem>(fs: &F, mounts: &[MountEntry], root: &Path) -> Storage {
    let mut storage = Storage::default();
    let Some(mount) = mounts.iter().rev().find(|m| m.mount_point == root) else {
        return storage;
    };
    let Some(top) = blockdev::device_of_mount(fs, mount) else {
        return storage;
    };
    let layers = blockdev::stack(fs, &top, LoopFollow::BlockDevices);
    let mut own: Vec<&str> = Vec::new();
    for (index, layer) in layers.iter().enumerate() {
        let alone = index == 0
            || (!layer.holders.is_empty()
                && layer
                    .holders
                    .iter()
                    .all(|holder| own.contains(&holder.as_str())));
        if alone {
            own.push(&layer.name);
            storage.add(layer);
        }
    }
    storage
}

impl Storage {
    fn add(&mut self, layer: &Layer) {
        if let Some(dm) = &layer.dm {
            let name = dm.name.trim().to_ascii_lowercase();
            if !name.is_empty() && !self.names.contains(&name) {
                self.names.push(name);
            }
            let uuid = dm.uuid.trim();
            if !uuid.is_empty() {
                self.markers.push(Pattern::Path(
                    format!("/dev/disk/by-id/dm-uuid-{uuid}").to_ascii_lowercase(),
                ));
            }
            if let Some(uuid) = luks_uuid(dm) {
                self.markers.push(Pattern::Text(uuid));
            }
        } else if let Some(device) = &layer.loop_device {
            // A loop over a block device has that device as a layer of its own.
            if let LoopBacking::File(path) = &device.backing {
                self.markers
                    .push(Pattern::Path(path.to_string_lossy().to_ascii_lowercase()));
            }
        } else if !layer.name.is_empty() {
            self.markers.push(Pattern::Path(
                format!("/dev/{}", layer.name).to_ascii_lowercase(),
            ));
            if let Some(uuid) = layer.partition.as_ref().and_then(|p| p.uuid.as_deref()) {
                self.markers
                    .push(Pattern::Text(uuid.trim().to_ascii_lowercase()));
            }
        }
    }
}

/// The LUKS uuid of a LUKS mapping, as `/dev/disk/by-uuid` and crypttab's
/// `UUID=` write it: cryptsetup names the mapping
/// `CRYPT-LUKS2-<32 hex digits>-<name>`.
fn luks_uuid(dm: &DeviceMapper) -> Option<String> {
    if !matches!(&dm.kind, DmKind::Crypt(kind) if kind.starts_with("LUKS")) {
        return None;
    }
    let hex = dm.uuid.trim().split('-').nth(2)?.to_ascii_lowercase();
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

#[cfg(test)]
mod tests {
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
        fn below(&self, mountinfo: &str) -> Storage {
            below(&self.0, &parse_mountinfo(mountinfo), Path::new("/mnt/data"))
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

    const DATA_MOUNT: &str = "36 35 254:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n";

    #[test]
    fn a_luks_mapping_on_a_partition_is_named_by_both_and_their_uuids() {
        let storage = luks_on_a_partition().below(DATA_MOUNT);
        assert_eq!(storage.names, ["data"]);
        assert_eq!(
            storage.markers,
            [
                Pattern::Path(format!("/dev/disk/by-id/dm-uuid-{}", LUKS.to_lowercase())),
                Pattern::Text("7d2c9e14-e8a1-4b3c-9f6b-0e1a2d3c4b5a".into()),
                Pattern::Path("/dev/sdb2".into()),
                Pattern::Text("4f1b0a7d-02".into()),
            ]
        );
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
            .links(SDB2, "holders", &[DM0]);
        sysfs
    }

    const LV_MOUNT: &str = "36 35 254:1 / /mnt/data rw - ext4 /dev/mapper/vg-hidden rw\n";

    /// A logical volume of a volume group that holds the decoy's own volumes
    /// too: the LUKS mapping and the partition below it are the decoy's.
    #[test]
    fn storage_the_decoy_shares_is_not_the_hidden_volume_s() {
        let storage = lvm_on_luks(true).below(LV_MOUNT);
        assert_eq!(storage.names, ["vg-hidden"]);
        assert_eq!(
            storage.markers,
            [Pattern::Path("/dev/disk/by-id/dm-uuid-lvm-abc".into())]
        );

        // Alone on the mapping, the mapping and the partition are its own.
        let storage = lvm_on_luks(false).below(LV_MOUNT);
        assert_eq!(storage.names, ["vg-hidden", "data"]);
        assert!(storage.markers.contains(&Pattern::Path("/dev/sdb2".into())));
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
                Pattern::Path("/dev/disk/by-id/dm-uuid-crypt-tcrypt-data".into()),
                Pattern::Path("/var/lib/vault.img".into()),
            ]
        );
    }

    /// The whole check: a decoy configuration that names the volume by what
    /// it is stored on is refused, whatever the case of the text.
    #[test]
    fn a_configuration_naming_the_storage_below_the_volume_is_refused() {
        let sysfs = luks_on_a_partition();
        sysfs
            .0
            .mock_set_file_content("/proc/self/mountinfo", DATA_MOUNT);
        let file = "/etc/nixos/configuration.nix";
        sysfs
            .0
            .mock_set_files_with_pattern("/etc/nixos", ".nix", &[Path::new(file)]);
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
            sysfs.0.mock_set_file_content(file, content);
            let scan =
                super::super::verify_base_config_clean(&sysfs.0, Path::new("/mnt/data")).unwrap();
            let found: Vec<_> = scan
                .references
                .iter()
                .map(|r| (r.line, r.text.as_str(), r.kind))
                .collect();
            assert_eq!(
                found,
                [(2, text, super::super::ReferenceKind::Storage)],
                "{content}"
            );
        }
    }

    #[test]
    fn without_sysfs_or_a_mount_nothing_is_added() {
        assert_eq!(Sysfs::new().below(DATA_MOUNT), Storage::default());
        assert_eq!(luks_on_a_partition().below(""), Storage::default());
    }
}
