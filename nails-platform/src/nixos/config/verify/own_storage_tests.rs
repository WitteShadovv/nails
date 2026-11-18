// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The scan with the filesystem that `--allow-decoy-storage` accepted the
//! hidden root on: the names of that filesystem's devices are let be in the
//! decoy's own entries for its own mounts, each only where sysfs shows the
//! device by the kernel name and the device number the judge read, and
//! everything else still counts.
//!
//! The layout is the documented one, read here as the decoy's own encrypted
//! filesystem: `data`, a LUKS2 mapping (dm-0, 254:0) on the partition sdb2
//! (8:18), with the names udev gives both.

use super::*;
use crate::nixos::config::{BaseConfigScan, ReferenceKind, verify_base_config_clean_allowing};
use nails_base::hidden_root::separation::{OwnDevice, OwnFilesystem, Sharing};

/// The filesystem the flag accepted a folder root at `/mnt/data` on, on
/// `devices`, by kernel name and device number.
fn own_on(devices: &[(&str, &str)]) -> OwnFilesystem {
    OwnFilesystem {
        how: Sharing::Bind,
        at: PathBuf::from("/"),
        root: PathBuf::from("/mnt/data"),
        devices: devices
            .iter()
            .map(|(name, dev)| OwnDevice {
                name: (*name).to_string(),
                dev: (*dev).to_string(),
            })
            .collect(),
        folders: Vec::new(),
        inside: PathBuf::from("/srv/hidden-root"),
        btrfs: false,
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

/// Each name of the mapping and of the partition below it, in each form the
/// scan reads that a device string can hold: the mapping's device path, its
/// mapper and dm-uuid links, the filesystem's uuid and label as links and
/// tags, its kernel name as a device node and a `/dev/block` link; the
/// partition's device path, the LUKS header's uuid, its PARTUUID and
/// PARTLABEL as links and tags, its other udev links, its label as a link,
/// and its `/dev/block` link.
const DEVICE_NAMES: &[&str] = &[
    "/dev/mapper/data",
    "/dev/disk/by-id/dm-name-data",
    "/dev/disk/by-id/dm-uuid-CRYPT-LUKS2-7d2c9e14e8a14b3c9f6b0e1a2d3c4b5a-data",
    "/dev/disk/by-uuid/0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7b",
    "UUID=0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7b",
    "/dev/disk/by-label/secrets",
    "LABEL=secrets",
    "/dev/dm-0",
    "/dev/block/254:0",
    "/dev/sdb2",
    "/dev/disk/by-uuid/7d2c9e14-e8a1-4b3c-9f6b-0e1a2d3c4b5a",
    "/dev/disk/by-partuuid/4f1b0a7d-02",
    "PARTUUID=4f1b0a7d-02",
    "/dev/disk/by-partlabel/vault",
    "PARTLABEL=vault",
    "/dev/disk/by-id/ata-QEMU_HARDDISK_QM00002-part2",
    "/dev/disk/by-path/pci-0000:00:17.0-ata-2-part2",
    "/dev/disk/by-diskseq/2-part2",
    "/dev/disk/by-label/My\\\\x20Vault",
    "/dev/block/8:18",
];

/// Each name, as the `device` of a `fileSystems` entry for `/` and for
/// system folders, written as a path and as nested sets, and as the
/// `device` of a `boot.initrd.luks.devices` entry: refused without the
/// filesystem the flag accepted, let be with it.
#[test]
fn every_name_of_the_accepted_filesystems_devices_is_let_be_in_the_decoys_own_entries() {
    let own = own_luks();
    for name in DEVICE_NAMES {
        for line in [
            format!("fileSystems.\"/\".device = \"{name}\";"),
            format!("fileSystems.\"/home\".device = \"{name}\";"),
            format!("fileSystems.\"/var/log\".device = \"{name}\";"),
            format!("fileSystems.\"/.snapshots\" = {{ device = \"{name}\"; }};"),
            format!("fileSystems = {{ \"/nix\" = {{ device = lib.mkForce \"{name}\"; }}; }};"),
            format!("config.fileSystems.\"/srv\".device = \"{name}\";"),
            format!("boot.initrd.luks.devices.\"cryptroot\".device = \"{name}\";"),
            format!("boot.initrd.luks.devices = {{ cryptroot = {{ device = \"{name}\"; }}; }};"),
        ] {
            let content = format!("{{\n  {line}\n}}\n");
            let sysfs = with_udev(luks_on_a_partition());
            let without = scan(&sysfs, None, &content);
            assert_eq!(without.references.len(), 1, "{line}: {without:?}");
            assert!(without.let_be.is_empty(), "{line}");
            let with = scan(&sysfs, Some(&own), &content);
            assert!(with.references.is_empty(), "{line}: {:?}", with.references);
            assert_eq!(
                shown(&with.let_be),
                [(
                    2,
                    without.references[0].text.as_str(),
                    without.references[0].kind
                )],
                "{line}"
            );
            assert!(with.unread.is_empty(), "{line}: {:?}", with.unread);
        }
    }
}

/// The label as a `fileSystems` entry's `label`, the mapping's name as the
/// name of a `boot.initrd.luks.devices` entry (NixOS names it after the
/// LUKS header's uuid), and the layout `nixos-generate-config` writes over
/// several lines are let be as well.
#[test]
fn the_label_the_luks_entry_and_a_generated_entry_are_let_be() {
    let own = own_luks();
    for content in [
        "{\n  fileSystems.\"/\".label = \"secrets\";\n}\n",
        "{\n  boot.initrd.luks.devices.\"data\".allowDiscards = true;\n}\n",
        "{\n  boot.initrd.luks.devices.data.keyFile = \"/crypto_keyfile.bin\";\n}\n",
        "{\n  fileSystems.\"/\" =\n    { device = \"/dev/mapper/data\";\n      fsType = \"ext4\";\n    };\n}\n",
        "{\n  # fileSystems.\"/home\".device = \"/dev/sdb2\";\n}\n",
    ] {
        let sysfs = with_udev(luks_on_a_partition());
        let without = scan(&sysfs, None, content);
        assert_eq!(without.references.len(), 1, "{content}: {without:?}");
        let with = scan(&sysfs, Some(&own), content);
        assert!(
            with.references.is_empty(),
            "{content}: {:?}",
            with.references
        );
        assert_eq!(with.let_be.len(), 1, "{content}: {with:?}");
    }
}

/// A name of a device of the accepted filesystem anywhere else than the
/// decoy's own entries for its own mounts still counts: in the entry for a
/// folder that is no system folder, the hidden root's own among them, in an
/// entry's options, in a `let` binding, a service's settings, a udev rule,
/// a unit's dependencies, a comment outside such an entry, an attribute
/// written in another case than Nix reads, and beside an own entry on the
/// same line.
#[test]
fn a_name_of_the_accepted_filesystem_elsewhere_still_counts() {
    let own = own_luks();
    for (line, text, kind) in [
        (
            "fileSystems.\"/btr_pool\".device = \"/dev/mapper/data\";",
            "/dev/mapper/data",
            ReferenceKind::Device,
        ),
        (
            "fileSystems.\"/HOME\".device = \"/dev/mapper/data\";",
            "/dev/mapper/data",
            ReferenceKind::Device,
        ),
        (
            "fileSystems.\"/home/../srv/x\".device = \"/dev/sdb2\";",
            "/dev/sdb2",
            ReferenceKind::Storage,
        ),
        (
            "filesystems.\"/\".device = \"/dev/mapper/data\";",
            "/dev/mapper/data",
            ReferenceKind::Device,
        ),
        (
            "fileSystems.\"/\".options = [ \"x-systemd.requires=/dev/sdb2\" ];",
            "/dev/sdb2",
            ReferenceKind::Storage,
        ),
        (
            "fileSystems.\"/\".encrypted.blkDev = \"/dev/sdb2\";",
            "/dev/sdb2",
            ReferenceKind::Storage,
        ),
        (
            "boot.resumeDevice = \"/dev/dm-0\";",
            "/dev/dm-0",
            ReferenceKind::Storage,
        ),
        (
            "services.beesd.filesystems.root.spec = \"UUID=0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7b\";",
            "0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7b",
            ReferenceKind::Storage,
        ),
        (
            "services.udev.extraRules = ''KERNEL==\"sdb2\", OPTIONS+=\"watch\"'';",
            "sdb2",
            ReferenceKind::Storage,
        ),
        (
            "systemd.services.x.after = [ \"dev-mapper-data.device\" ];",
            "dev-mapper-data.device",
            ReferenceKind::DeviceUnit,
        ),
        (
            "# UUID=0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7b",
            "0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7b",
            ReferenceKind::Storage,
        ),
        (
            "x = let disk = \"/dev/sdb2\"; in disk;",
            "/dev/sdb2",
            ReferenceKind::Storage,
        ),
        (
            "fileSystems.\"/\".device = \"/dev/mapper/data\"; boot.resumeDevice = \"/dev/sdb2\";",
            "/dev/sdb2",
            ReferenceKind::Storage,
        ),
        (
            "boot.initrd.luks.devices.\"data\".header = \"/dev/sdb2\";",
            "/dev/sdb2",
            ReferenceKind::Storage,
        ),
    ] {
        let content = format!("{{\n  {line}\n}}\n");
        let sysfs = with_udev(luks_on_a_partition());
        let found = scan(&sysfs, Some(&own), &content);
        assert_eq!(shown(&found.references), [(2, text, kind)], "{line}");
        assert!(found.let_be.is_empty(), "{line}: {:?}", found.let_be);
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
             fileSystems.\"/home\".device = \"/dev/sdb2\";\n}\n",
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
        "{ fileSystems.\"/\".device = \"/dev/disk/by-uuid/0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7b\"; }\n",
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
            "{ x = /mnt/./data; }",
            "/mnt/./data",
            ReferenceKind::MountPoint,
        ),
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

/// The root's own place counts with the filesystem the flag accepted: its
/// folder as another mount of the filesystem shows it, its btrfs
/// subvolume's name wherever it stands whole in a path or a string, however
/// a `subvol=` spells the path to it, its id in any base `subvolid=` is read
/// in, and a `subvol=` or `subvolid=` value the scan cannot read. A name
/// that only starts or ends alike, another id, and another subvolume do
/// not.
#[test]
fn the_roots_own_folder_and_subvolume_count() {
    let sysfs = with_udev(luks_on_a_partition());
    let own = OwnFilesystem {
        how: Sharing::Subvolume,
        folders: vec![PathBuf::from("/srv/Vault")],
        inside: PathBuf::from("/@vault"),
        btrfs: true,
        subvolid: Some(258),
        ..own_luks()
    };
    for (content, text) in [
        ("{ services.x.dataDir = \"/srv/Vault/db\"; }", "/srv/Vault"),
        ("{ x = /srv//Vault; }", "/srv//Vault"),
        ("{ x = \"/srv/./Vault\"; }", "/srv/./Vault"),
        (
            "{ fileSystems.\"/x\".options = [ \"subvol=@vault\" ]; }",
            "@vault",
        ),
        (
            "{ fileSystems.\"/x\".options = [ \"subvol=/@vault/inner\" ]; }",
            "@vault",
        ),
        (
            "{ fileSystems.\"/x\".options = [ \"subvol=//@vault\" ]; }",
            "@vault",
        ),
        (
            "{ fileSystems.\"/x\".options = [ \"subvol=./@vault\" ]; }",
            "@vault",
        ),
        (
            "{ fileSystems.\"/x\".options = [ \"subvol=@home/../@vault\" ]; }",
            "@vault",
        ),
        (
            "{ fileSystems.\"/home\".options = [ \"compress=zstd,subvol=@vault/.\" ]; }",
            "@vault",
        ),
        (
            "{ fileSystems.\"/data\" = { device = \"/btr_pool/@vault\"; options = [ \"bind\" ]; }; }",
            "@vault",
        ),
        (
            "{ services.btrbk.instances.daily.settings.volume.\"/btr_pool\".subvolume.\"@vault\" = { }; }",
            "@vault",
        ),
        (
            "{ fileSystems.\"/x\".options = [ \"subvolid=258\" ]; }",
            "subvolid=258",
        ),
        (
            "{ fileSystems.\"/x\".options = [ \"subvolid=0x102\" ]; }",
            "subvolid=0x102",
        ),
        (
            "{ fileSystems.\"/x\".options = [ \"subvolid=0402\" ]; }",
            "subvolid=0402",
        ),
        (
            "{ fileSystems.\"/x\".options = [ \"subvolid=+258\" ]; }",
            "subvolid=+258",
        ),
        (
            "{ fileSystems.\"/x\".options = [ \"subvolid=${toString id}\" ]; }",
            "subvolid=${toString",
        ),
        (
            "{ fileSystems.\"/x\".options = [ \"subvolid=\" ]; }",
            "subvolid=",
        ),
        (
            "{ fileSystems.\"/x\".options = [ \"subvol=${name}\" ]; }",
            "subvol=${name}",
        ),
        (
            "{ fileSystems.\"/x\".options = [ (\"subvol=\" + name) ]; }",
            "subvol=",
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
        "{ fileSystems.\"/x\".options = [ \"subvol=@vault-old\" ]; }",
        "{ fileSystems.\"/x\".options = [ \"subvol=old@vault\" ]; }",
        "{ fileSystems.\"/x\".options = [ \"subvolid=2580\" ]; }",
        "{ fileSystems.\"/x\".options = [ \"subvolid=0x1020\" ]; }",
        "{ fileSystems.\"/x\".options = [ \"subvolid=257\" ]; }",
        "{ fileSystems.\"/\".options = [ \"subvol=@\" ]; }",
        "{ fileSystems.\"/home\".options = [ \"subvol=/@home\" ]; }",
    ] {
        let found = scan(&sysfs, Some(&own), content);
        assert!(found.references.is_empty(), "{content}: {found:?}");
    }
    // Without the flag nothing of it is known, and none of it counts.
    for content in [
        "{ x = \"/srv/Vault/db\"; }",
        "{ fileSystems.\"/x\".options = [ \"subvol=@vault\" ]; }",
        "{ fileSystems.\"/x\".options = [ \"subvolid=258\" ]; }",
    ] {
        let found = scan(&sysfs, None, content);
        assert!(found.references.is_empty(), "{content}: {found:?}");
    }
}

/// A folder root's own name counts wherever it stands whole in a path or a
/// string, through any mount of the filesystem, and as an attribute name the
/// file defines; on a filesystem that is not btrfs, `subvol=` and
/// `subvolid=` mean nothing and do not count.
#[test]
fn a_folder_roots_own_name_counts_as_a_part_of_a_path_a_string_or_an_attribute() {
    let sysfs = with_udev(luks_on_a_partition());
    let own = OwnFilesystem {
        inside: PathBuf::from("/home/alice/vault"),
        folders: vec![PathBuf::from("/home/alice/vault")],
        ..own_luks()
    };
    for (content, text, kind) in [
        (
            "{ fileSystems.\"/data\" = { device = \"/mnt/rootfs/home/alice/vault\"; options = [ \"bind\" ]; }; }",
            "vault",
            ReferenceKind::RootPlace,
        ),
        (
            "{ fileSystems.\"/data\".device = \"/home/alice/./vault\"; }",
            "/home/alice/./vault",
            ReferenceKind::RootPlace,
        ),
        (
            "{ fileSystems.\"/data\".device = \"/home/bob/../alice/vault\"; }",
            "vault",
            ReferenceKind::RootPlace,
        ),
        (
            "{ fileSystems.\"/data\".options = [ \"X-mount.subdir=home/alice/vault\" ]; }",
            "vault",
            ReferenceKind::RootPlace,
        ),
        (
            "{ services.syncthing.folders.vault = { }; }",
            "vault",
            ReferenceKind::RootPlace,
        ),
        ("{ x = \"vault\"; }", "vault", ReferenceKind::RootPlace),
    ] {
        let found = scan(&sysfs, Some(&own), content);
        assert_eq!(shown(&found.references), [(1, text, kind)], "{content}");
    }
    for content in [
        "{ environment.systemPackages = [ pkgs.vault ]; }",
        "{ x = \"/etc/vault.conf\"; }",
        "{ x = \"/srv/vaults\"; }",
        "{ fileSystems.\"/x\".options = [ \"subvolid=${toString id}\" ]; }",
        "{ fileSystems.\"/x\".options = [ \"subvol=${name}\" ]; }",
    ] {
        let found = scan(&sysfs, Some(&own), content);
        assert!(found.references.is_empty(), "{content}: {found:?}");
    }
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

#[path = "own_escape_tests.rs"]
mod escapes;
