// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The scan with the filesystem that `--allow-decoy-storage` accepted the
//! hidden root on: the names of that filesystem's devices are let be, each
//! only where sysfs shows the device by the kernel name and the device number
//! the judge read, and everything else still counts.
//!
//! The layout is the documented one, read here as the decoy's own encrypted
//! filesystem: `data`, a LUKS2 mapping (dm-0, 254:0) on the partition sdb2
//! (8:18), with the names udev gives both.

use super::*;
use crate::nixos::config::{BaseConfigScan, ReferenceKind, verify_base_config_clean_allowing};
use nails_base::hidden_root::separation::{OwnDevice, OwnFilesystem, Sharing};

/// The filesystem the flag accepted a folder root on, on `devices`, by
/// kernel name and device number.
fn own_on(devices: &[(&str, &str)]) -> OwnFilesystem {
    OwnFilesystem {
        how: Sharing::Bind,
        at: PathBuf::from("/"),
        devices: devices
            .iter()
            .map(|(name, dev)| OwnDevice {
                name: (*name).to_string(),
                dev: (*dev).to_string(),
            })
            .collect(),
        folders: Vec::new(),
        subvolume: None,
        subvolid: None,
    }
}

/// The mapping and the partition below it, as the judge read them.
fn own_luks() -> OwnFilesystem {
    own_on(&[("dm-0", "254:0"), ("sdb2", "8:18")])
}

/// The scan of `content` in the one file of `/etc/nixos` on `sysfs`, with
/// the root at `/mnt/data` mounted from the mapping, and `own`.
fn scan(sysfs: &Sysfs, own: Option<&OwnFilesystem>, content: &str) -> BaseConfigScan {
    let file = "/etc/nixos/configuration.nix";
    sysfs
        .0
        .mock_set_file_content("/proc/self/mountinfo", DATA_MOUNT);
    sysfs
        .0
        .mock_set_files_with_pattern("/etc/nixos", ".nix", &[Path::new(file)]);
    sysfs.0.mock_set_file_content(file, content);
    verify_base_config_clean_allowing(&sysfs.0, Path::new("/mnt/data"), own).unwrap()
}

/// The (line, text, kind) of each reference in `found`.
fn shown(found: &[crate::nixos::config::BaseConfigReference]) -> Vec<(usize, &str, ReferenceKind)> {
    found
        .iter()
        .map(|r| (r.line, r.text.as_str(), r.kind))
        .collect()
}

/// Each name of the mapping and of the partition, in each form the scan
/// reads: refused without the filesystem the flag accepted, let be with it.
const NAMES: &[&str] = &[
    // The mapping: its device path, its udev links, its mapper links, the
    // filesystem's uuid and label as a link, a tag and a `label`, its kernel
    // name as a device node, a word and a `/dev/block` link, its unit.
    "fileSystems.\"/\".device = \"/dev/mapper/data\";",
    "fileSystems.\"/\".device = \"/dev/disk/by-id/dm-name-data\";",
    "fileSystems.\"/\".device = \"/dev/disk/by-id/dm-uuid-CRYPT-LUKS2-7d2c9e14e8a14b3c9f6b0e1a2d3c4b5a-data\";",
    "fileSystems.\"/\".device = \"/dev/disk/by-uuid/0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7b\";",
    "# UUID=0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7b",
    "fileSystems.\"/\".device = \"/dev/disk/by-label/secrets\";",
    "# LABEL=secrets",
    "fileSystems.\"/\".label = \"secrets\";",
    "boot.resumeDevice = \"/dev/dm-0\";",
    "boot.resumeDevice = \"/dev/block/254:0\";",
    "services.udev.extraRules = ''KERNEL==\"dm-0\", OPTIONS+=\"watch\"'';",
    "systemd.services.x.after = [ \"dev-mapper-data.device\" ];",
    // Its mapping as a NixOS LUKS entry names it, opened from the partition
    // by the LUKS header's uuid.
    "boot.initrd.luks.devices.\"data\".allowDiscards = true;",
    "boot.initrd.luks.device = \"/dev/disk/by-uuid/7d2c9e14-e8a1-4b3c-9f6b-0e1a2d3c4b5a\";",
    // The partition: its device path, PARTUUID and PARTLABEL as links and
    // tags, its other udev links, its label as a link and a tag, its kernel
    // name as a word and its `/dev/block` link.
    "boot.initrd.luks.device = \"/dev/sdb2\";",
    "boot.initrd.luks.device = \"/dev/disk/by-partuuid/4f1b0a7d-02\";",
    "# PARTUUID=4f1b0a7d-02",
    "boot.initrd.luks.device = \"/dev/disk/by-partlabel/vault\";",
    "# PARTLABEL=vault",
    "boot.initrd.luks.device = \"/dev/disk/by-id/ata-QEMU_HARDDISK_QM00002-part2\";",
    "boot.initrd.luks.device = \"/dev/disk/by-path/pci-0000:00:17.0-ata-2-part2\";",
    "boot.initrd.luks.device = \"/dev/disk/by-diskseq/2-part2\";",
    "boot.initrd.luks.device = \"/dev/disk/by-label/My\\\\x20Vault\";",
    "# LABEL=\"My Vault\"",
    "services.udev.extraRules = ''KERNEL==\"sdb2\", OPTIONS+=\"watch\"'';",
    "boot.resumeDevice = \"/dev/block/8:18\";",
];

#[test]
fn every_name_of_the_accepted_filesystems_devices_is_let_be() {
    let own = own_luks();
    for name in NAMES {
        let content = format!("{{\n  {name}\n}}\n");
        let sysfs = with_udev(luks_on_a_partition());
        let without = scan(&sysfs, None, &content);
        assert_eq!(without.references.len(), 1, "{name}: {without:?}");
        assert!(without.let_be.is_empty(), "{name}");
        let with = scan(&sysfs, Some(&own), &content);
        assert!(with.references.is_empty(), "{name}: {:?}", with.references);
        assert_eq!(
            shown(&with.let_be),
            [(
                2,
                without.references[0].text.as_str(),
                without.references[0].kind
            )],
            "{name}"
        );
        assert!(with.unread.is_empty(), "{name}: {:?}", with.unread);
    }
}

/// Without udev's database the mount source `/dev/mapper/data` is a name of
/// the accepted filesystem's mapping by the mapping's name alone, and is let
/// be as well.
#[test]
fn the_mount_source_of_the_accepted_mapping_is_let_be_by_its_name() {
    let sysfs = luks_on_a_partition();
    let content = "{ fileSystems.\"/\".device = \"/dev/mapper/data\"; }\n";
    let without = scan(&sysfs, None, content);
    assert_eq!(
        shown(&without.references),
        [(1, "/dev/mapper/data", ReferenceKind::Device)]
    );
    let with = scan(&sysfs, Some(&own_luks()), content);
    assert!(with.references.is_empty(), "{with:?}");
    assert_eq!(
        shown(&with.let_be),
        [(1, "/dev/mapper/data", ReferenceKind::Device)]
    );
}

/// A layer counts as a device of the accepted filesystem only by both its
/// kernel name and its device number: one sysfs shows otherwise now, as a
/// device that took the name or the number since the judge read them,
/// keeps every name.
#[test]
fn a_layer_with_another_number_or_name_than_the_judge_read_keeps_its_names() {
    let sysfs = with_udev(luks_on_a_partition());
    for own in [
        own_on(&[("dm-0", "254:9"), ("sdb2", "8:18")]),
        own_on(&[("dm-7", "254:0"), ("sdb2", "8:18")]),
    ] {
        let found = scan(
            &sysfs,
            Some(&own),
            "{\n  fileSystems.\"/\".device = \"/dev/mapper/data\";\n  \
             boot.resumeDevice = \"/dev/sdb2\";\n}\n",
        );
        assert_eq!(
            shown(&found.references),
            [(2, "/dev/mapper/data", ReferenceKind::Device)],
            "{own:?}"
        );
        assert_eq!(
            shown(&found.let_be),
            [(3, "/dev/sdb2", ReferenceKind::Storage)],
            "{own:?}"
        );
    }
    // The partition alone is the accepted filesystem's: the mapping's names
    // still count, the mount source among them.
    let found = scan(
        &sysfs,
        Some(&own_on(&[("sdb2", "8:18")])),
        "{ x = \"/dev/disk/by-uuid/0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7b\"; }\n",
    );
    assert_eq!(found.references.len(), 1, "{found:?}");
}

/// What names the hidden root itself, NAILS or the session's own text
/// still counts with the filesystem the flag accepted, and so does a line
/// that names the device and such a thing too.
#[test]
fn the_root_nails_and_its_text_still_count_with_the_accepted_filesystem() {
    let sysfs = with_udev(luks_on_a_partition());
    let own = own_luks();
    for (content, text, kind) in [
        ("{ x = /mnt/data; }", "/mnt/data", ReferenceKind::MountPoint),
        (
            "{ systemd.services.x.after = [ \"mnt-data.mount\" ]; }",
            "mnt-data.mount",
            ReferenceKind::MountUnit,
        ),
        (
            "{ services.nails.enable = true; }",
            "nails",
            ReferenceKind::ToolName,
        ),
        (
            "{ fileSystems.\"/mnt/data\".device = \"/dev/disk/by-label/secrets\"; }",
            "/mnt/data",
            ReferenceKind::MountPoint,
        ),
    ] {
        let found = scan(&sysfs, Some(&own), content);
        assert_eq!(shown(&found.references), [(1, text, kind)], "{content}");
        assert!(found.let_be.is_empty(), "{content}");
    }
}

/// The root's own folder, as another mount of the filesystem shows it, and
/// its btrfs subvolume, by `subvol=` and `subvolid=`, count with the
/// filesystem the flag accepted; a folder or subvolume whose name only
/// starts alike does not.
#[test]
fn the_roots_own_folder_and_subvolume_count() {
    let sysfs = with_udev(luks_on_a_partition());
    let own = OwnFilesystem {
        folders: vec![PathBuf::from("/srv/Vault")],
        subvolume: Some("@vault".to_string()),
        subvolid: Some("258".to_string()),
        ..own_luks()
    };
    for (content, text) in [
        ("{ services.x.dataDir = \"/srv/Vault/db\"; }", "/srv/Vault"),
        ("{ x = /srv//Vault; }", "/srv//Vault"),
        (
            "{ fileSystems.\"/x\".options = [ \"subvol=@vault\" ]; }",
            "@vault",
        ),
        (
            "{ fileSystems.\"/x\".options = [ \"subvol=/@vault/inner\" ]; }",
            "/@vault",
        ),
        (
            "{ fileSystems.\"/x\".options = [ \"subvolid=258\" ]; }",
            "258",
        ),
    ] {
        let found = scan(&sysfs, Some(&own), content);
        assert_eq!(
            shown(&found.references),
            [(1, text, ReferenceKind::RootPlace)],
            "{content}"
        );
    }
    for content in [
        "{ services.x.dataDir = \"/srv/Vaults\"; }",
        "{ fileSystems.\"/x\".options = [ \"subvol=@vaults\" ]; }",
        "{ fileSystems.\"/x\".options = [ \"subvolid=2580\" ]; }",
        "{ fileSystems.\"/\".options = [ \"subvol=@\" ]; }",
    ] {
        let found = scan(&sysfs, Some(&own), content);
        assert!(found.references.is_empty(), "{content}: {found:?}");
    }
    // Without the flag nothing of it is known, and the folder passes.
    let found = scan(&sysfs, None, "{ x = \"/srv/Vault/db\"; }");
    assert!(found.references.is_empty(), "{found:?}");
}

/// A place that may give a name of the storage and cannot be read keeps
/// the scan from telling, with the filesystem the flag accepted too, also
/// where it is a device of that filesystem.
#[test]
fn a_place_that_cannot_be_read_is_kept_with_the_accepted_filesystem() {
    let sysfs = with_udev(luks_on_a_partition());
    sysfs
        .0
        .mock_set_lookup_error("/run/udev/data/b8:18", std::io::ErrorKind::Other);
    let found = scan(&sysfs, Some(&own_luks()), "{ }");
    assert_eq!(found.unread, ["/run/udev/data/b8:18"]);
}
