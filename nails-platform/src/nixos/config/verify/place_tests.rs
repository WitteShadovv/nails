// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The scan for a hidden root that is a folder or a btrfs subvolume of a
//! filesystem the decoy uses (a placed root): the names of the devices that
//! filesystem lies on count as for any other root, also in the decoy's own
//! entries for its own mounts, and the root's own folder and subvolume count
//! as well. The scan reads names written with Nix string escapes as Nix
//! evaluates them.
//!
//! The layout is the documented one, read here as the decoy's own encrypted
//! filesystem: `data`, a LUKS2 mapping (dm-0, 254:0) on the partition sdb2
//! (8:18), with the names udev gives both.

use super::*;
use crate::nixos::config::{BaseConfigScan, ReferenceKind, verify_base_config_clean_placed};
use nails_base::hidden_root::separation::RootPlace;

/// The place of a folder root `home/alice/vault` of the filesystem, which
/// `/` shows at `/home/alice/vault`.
fn folder_place() -> RootPlace {
    RootPlace {
        folders: vec![PathBuf::from("/home/alice/vault")],
        inside: PathBuf::from("/home/alice/vault"),
        btrfs: false,
        subvolid: None,
    }
}

/// The place of a btrfs subvolume root `@vault`, id 258.
fn subvolume_place() -> RootPlace {
    RootPlace {
        folders: Vec::new(),
        inside: PathBuf::from("/@vault"),
        btrfs: true,
        subvolid: Some(258),
    }
}

/// The scan of `content` in the one file of `/etc/nixos` on `sysfs`, with
/// the root at `/mnt/data` mounted from the mapping, and its `place`.
fn scan(sysfs: &Sysfs, place: Option<&RootPlace>, content: &str) -> BaseConfigScan {
    let file = "/etc/nixos/configuration.nix";
    sysfs
        .0
        .mock_set_file_content("/proc/self/mountinfo", DATA_MOUNT);
    sysfs
        .0
        .mock_set_files_with_pattern("/etc/nixos", ".nix", &[Path::new(file)]);
    sysfs.0.mock_set_file_content(file, content);
    verify_base_config_clean_placed(&sysfs.0, Path::new("/mnt/data"), place).unwrap()
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
/// `device` of a `boot.initrd.luks.devices` entry, the form
/// `hardware-configuration.nix` takes: for a placed root it counts as it
/// does for any other root, and the scan says the root is placed.
#[test]
fn every_name_of_the_devices_counts_in_the_decoys_own_entries_for_a_placed_root() {
    let place = folder_place();
    for name in DEVICE_NAMES {
        for line in [
            format!("fileSystems.\"/\".device = \"{name}\";"),
            format!("fileSystems.\"/home\".device = \"{name}\";"),
            format!("fileSystems.\"/var/log\".device = \"{name}\";"),
            format!("fileSystems.\"/.snapshots\" = {{ device = \"{name}\"; }};"),
            format!("fileSystems = {{ \"/nix\" = {{ device = \"{name}\"; }}; }};"),
            format!("boot.initrd.luks.devices.\"cryptroot\".device = \"{name}\";"),
            format!("boot.initrd.luks.devices = {{ cryptroot = {{ device = \"{name}\"; }}; }};"),
        ] {
            let content = format!("{{\n  {line}\n}}\n");
            let sysfs = with_udev(luks_on_a_partition());
            let other = scan(&sysfs, None, &content);
            assert_eq!(other.references.len(), 1, "{line}: {other:?}");
            assert!(!other.placed, "{line}");
            let placed = scan(&sysfs, Some(&place), &content);
            assert_eq!(placed.references, other.references, "{line}");
            assert!(placed.placed, "{line}");
        }
    }
}

/// The label as a `fileSystems` entry's `label`, the mapping's name as the
/// name of a `boot.initrd.luks.devices` entry (NixOS names it after the
/// LUKS header's uuid), and the layout `nixos-generate-config` writes over
/// several lines count for a placed root as well.
#[test]
fn the_label_the_luks_entry_and_a_generated_entry_count_for_a_placed_root() {
    let place = folder_place();
    for content in [
        "{\n  fileSystems.\"/\".label = \"secrets\";\n}\n",
        "{\n  boot.initrd.luks.devices.\"data\".allowDiscards = true;\n}\n",
        "{\n  boot.initrd.luks.devices.data.keyFile = \"/crypto_keyfile.bin\";\n}\n",
        "{\n  fileSystems.\"/\" =\n    { device = \"/dev/mapper/data\";\n      fsType = \"ext4\";\n    };\n}\n",
    ] {
        let sysfs = with_udev(luks_on_a_partition());
        let other = scan(&sysfs, None, content);
        assert_eq!(other.references.len(), 1, "{content}: {other:?}");
        let placed = scan(&sysfs, Some(&place), content);
        assert_eq!(placed.references, other.references, "{content}");
    }
}

/// What names the hidden root itself, NAILS or the session's own text
/// still counts for a placed root.
#[test]
fn the_root_nails_and_its_text_count_for_a_placed_root() {
    let sysfs = with_udev(luks_on_a_partition());
    let place = folder_place();
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
    ] {
        let found = scan(&sysfs, Some(&place), content);
        assert_eq!(shown(&found.references), [(1, text, kind)], "{content}");
    }
}

/// The root's own place counts for a placed root, with the flag or without: its
/// folder as another mount of the filesystem shows it, its btrfs
/// subvolume's name wherever it stands whole in a path or a string, however
/// a `subvol=` spells the path to it, its id in any base `subvolid=` is read
/// in, and a `subvol=` or `subvolid=` value the scan cannot read. A name
/// that only starts or ends alike, another id, and another subvolume do
/// not.
#[test]
fn the_roots_own_folder_and_subvolume_count() {
    let sysfs = with_udev(luks_on_a_partition());
    let place = RootPlace {
        folders: vec![PathBuf::from("/srv/Vault")],
        ..subvolume_place()
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
        let found = scan(&sysfs, Some(&place), content);
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
        let found = scan(&sysfs, Some(&place), content);
        assert!(found.references.is_empty(), "{content}: {found:?}");
    }
    // For a root on storage of its own nothing of it is known, and none of
    // it counts.
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
    let place = folder_place();
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
        let found = scan(&sysfs, Some(&place), content);
        assert_eq!(shown(&found.references), [(1, text, kind)], "{content}");
    }
    for content in [
        "{ environment.systemPackages = [ pkgs.vault ]; }",
        "{ x = \"/etc/vault.conf\"; }",
        "{ x = \"/srv/vaults\"; }",
        "{ fileSystems.\"/x\".options = [ \"subvolid=${toString id}\" ]; }",
        "{ fileSystems.\"/x\".options = [ \"subvol=${name}\" ]; }",
    ] {
        let found = scan(&sysfs, Some(&place), content);
        assert!(found.references.is_empty(), "{content}: {found:?}");
    }
}

/// The hidden root's own name, written with an escape, counts for a placed
/// root: Nix reads each of these as `@vault`, `258` or `/home/alice/vault`.
/// An escape that Nix reads as another name does not.
#[test]
fn an_escape_in_the_roots_own_name_counts() {
    let sysfs = with_udev(luks_on_a_partition());
    let subvolume = subvolume_place();
    let folder = folder_place();
    let options =
        |at: &str, options: &str| format!("{{ fileSystems.\"{at}\".options = [ {options} ]; }}");
    let multiline = "{\n  fileSystems.\"/srv\" =\n    { fsType = \"btrfs\";\n      \
                     options = [ \"subvol=@v\\ault\" ];\n    };\n}"
        .to_string();
    for (place, content, line, text) in [
        (&subvolume, options("/srv", "\"subvol=@v\\ault\""), 1, "@v\\ault"),
        (&subvolume, options("/srv", "\"subvol=/@v\\ault\""), 1, "@v\\ault"),
        (&subvolume, options("/home", "\"subvol=@v\\ault\""), 1, "@v\\ault"),
        (&subvolume, options("/srv", "\"subvolid=2\\58\""), 1, "subvolid=2\\58"),
        (&subvolume, options("/srv", "\"subvolid=0x1\\02\""), 1, "subvolid=0x1\\02"),
        (&subvolume, options("/srv", "\"subvolid=258\\n\""), 1, "subvolid=258"),
        (&subvolume, options("/srv", "\"X-mount.subdir=@v\\ault\""), 1, "@v\\ault"),
        (&subvolume, options("/srv", "''subvol=@v''\\ault''"), 1, "@v''\\ault"),
        (&subvolume, multiline, 4, "@v\\ault"),
        (
            &subvolume,
            "{ fileSystems.\"/data\" = { device = \"/var/lib/pool/@v\\ault\"; options = [ \"bind\" ]; }; }"
                .to_string(),
            1,
            "@v\\ault",
        ),
        (&folder, "{ x = \"/home/alice/va\\ult\"; }".to_string(), 1, "/home/alice/va\\ult"),
        (
            &folder,
            "{ fileSystems.\"/srv\" = { device = \"/home/alice/va\\ult\"; options = [ \"bind\" ]; }; }"
                .to_string(),
            1,
            "/home/alice/va\\ult",
        ),
    ] {
        let found = scan(&sysfs, Some(place), &content);
        assert_eq!(
            shown(&found.references),
            [(line, text, ReferenceKind::RootPlace)],
            "{content}"
        );
    }
    for content in [
        options("/srv", "\"subvol=@v\\\\ault\""),
        options("/srv", "\"subvolid=2\\\\58\""),
        options("/srv", "\"subvolid=257\\n\""),
    ] {
        let found = scan(&sysfs, Some(&subvolume), &content);
        assert!(found.references.is_empty(), "{content}: {found:?}");
    }
}

/// The root's own name written with fstab's octal escapes, which NixOS
/// passes to `/etc/fstab` unchanged and libmount decodes, counts as it does
/// written out: in a `subvol=` or `X-mount.subdir=` option and in a bind's
/// device.
#[test]
fn the_roots_own_name_written_with_fstab_s_octal_escapes_counts() {
    let sysfs = with_udev(luks_on_a_partition());
    let subvolume = subvolume_place();
    let folder = folder_place();
    let options = |options: &str| format!("{{ fileSystems.\"/srv\".options = [ {options} ]; }}");
    for (place, content, text) in [
        (&subvolume, options("\"subvol=@va\\\\165lt\""), "@va\\\\165lt"),
        (&subvolume, options("\"X-mount.subdir=@va\\\\165lt\""), "@va\\\\165lt"),
        (
            &subvolume,
            "{ fileSystems.\"/data\" = { device = \"/var/lib/pool/@va\\\\165lt\"; options = [ \"bind\" ]; }; }"
                .to_string(),
            "@va\\\\165lt",
        ),
        (
            &folder,
            "{ fileSystems.\"/srv\" = { device = \"/home/alice/va\\\\165lt\"; fsType = \"none\"; options = [ \"bind\" ]; }; }"
                .to_string(),
            "/home/alice/va\\\\165lt",
        ),
    ] {
        let found = scan(&sysfs, Some(place), &content);
        assert_eq!(
            shown(&found.references),
            [(1, text, ReferenceKind::RootPlace)],
            "{content}"
        );
    }
}

/// A name of the hidden volume written with an escape counts as it does written out, as Nix reads it: its mount point, its
/// device, a link and a label of its storage, and its mapping's name in a
/// `luks.devices` entry, in an `inherit` there, as `encrypted.label`, as a
/// cryptsetup unit and in a crypttab line after a newline written as an
/// escape, in code and in a comment.
#[test]
fn an_escape_in_a_name_of_the_hidden_volume_counts() {
    let sysfs = with_udev(luks_on_a_partition());
    for (content, text, kind) in [
        (
            "{ x = \"/mnt/d\\ata\"; }",
            "/mnt/d\\ata",
            ReferenceKind::MountPoint,
        ),
        (
            "{ x = ''/mnt/d''\\ata''; }",
            "/mnt/d''\\ata",
            ReferenceKind::MountPoint,
        ),
        (
            "# x = \"/mnt/d\\ata\";",
            "/mnt/d\\ata",
            ReferenceKind::MountPoint,
        ),
        (
            "{ x = \"/dev/mapper/d\\ata\"; }",
            "/dev/mapper/d\\ata",
            ReferenceKind::Device,
        ),
        (
            "{ x = \"/dev/disk/by-uuid/0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7\\b\"; }",
            "/dev/disk/by-uuid/0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7\\b",
            ReferenceKind::Storage,
        ),
        (
            "{ x = \"LABEL=secr\\ets\"; }",
            "secr\\ets",
            ReferenceKind::Storage,
        ),
        (
            "{ fileSystems.\"/x\".label = \"secr\\ets\"; }",
            "secr\\ets",
            ReferenceKind::Storage,
        ),
        (
            "{ boot.initrd.luks.devices.\"d\\ata\" = { }; }",
            "d\\ata",
            ReferenceKind::MapperName,
        ),
        (
            "{ fileSystems.\"/x\".encrypted.label = \"d\\ata\"; }",
            "d\\ata",
            ReferenceKind::MapperName,
        ),
        (
            "{ x = \"systemd-cryptsetup@d\\ata.service\"; }",
            "d\\ata",
            ReferenceKind::MapperName,
        ),
        (
            "{ boot.initrd.luks.devices = { inherit \"d\\ata\"; }; }",
            "d\\ata",
            ReferenceKind::MapperName,
        ),
        (
            "{ boot.initrd.luks.devices = { inherit (cfg) \"d\\ata\"; }; }",
            "d\\ata",
            ReferenceKind::MapperName,
        ),
        (
            "{ environment.etc.crypttab.text = \"x /dev/a none\\ndata /dev/sdc1 none luks\"; }",
            "data",
            ReferenceKind::MapperName,
        ),
        (
            "{ environment.etc.crypttab.text = ''x /dev/a none''\\ndata /dev/sdc1 none luks''; }",
            "data",
            ReferenceKind::MapperName,
        ),
    ] {
        let found = scan(&sysfs, None, content);
        assert_eq!(shown(&found.references), [(1, text, kind)], "{content}");
    }
    // Escapes Nix reads as another name pass, and so does a crypttab line
    // after a backslash Nix keeps.
    for content in [
        "{ x = \"/mnt/d\\\\ata\"; }",
        "{ x = ''/mnt/d\\ata''; }",
        "{ environment.etc.crypttab.text = \"x /dev/a none\\\\ndata /dev/sdc1 none luks\"; }",
        "{ boot.initrd.luks.devices = { inherit \"d\\\\ata\"; }; }",
    ] {
        let found = scan(&sysfs, None, content);
        assert!(found.is_clean(), "{content}: {found:?}");
    }
}

/// A place that may give a name of the storage and cannot be read keeps
/// the scan from telling for a placed root too.
#[test]
fn a_place_that_cannot_be_read_is_kept_for_a_placed_root() {
    let sysfs = with_udev(luks_on_a_partition());
    sysfs
        .0
        .mock_set_lookup_error("/run/udev/data/b8:18", std::io::ErrorKind::Other);
    let found = scan(&sysfs, Some(&folder_place()), "{ }");
    assert_eq!(found.unread, ["/run/udev/data/b8:18"]);
}
