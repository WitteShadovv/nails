// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The scan reads a name written with Nix string escapes as Nix evaluates
//! it, with the filesystem the flag accepted and without; with it, a value
//! the scan cannot read whole where one could name the root counts.

use super::*;

/// The filesystem's uuid, a name the flag lets be in the decoy's own places.
const OWN: &str = "/dev/disk/by-uuid/0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7b";

/// The filesystem the flag accepted a btrfs subvolume root `@vault`, id
/// 258, on.
fn own_subvolume() -> OwnFilesystem {
    OwnFilesystem {
        how: Sharing::Subvolume,
        inside: PathBuf::from("/@vault"),
        btrfs: true,
        subvolid: Some(258),
        ..own_luks()
    }
}

/// The filesystem the flag accepted a folder root `home/alice/vault` of /
/// on.
fn own_folder() -> OwnFilesystem {
    OwnFilesystem {
        inside: PathBuf::from("/home/alice/vault"),
        folders: vec![PathBuf::from("/home/alice/vault")],
        ..own_luks()
    }
}

/// The decoy's own entry for `at` on the accepted filesystem, with
/// `options`, on one line.
fn entry(at: &str, options: &str) -> String {
    format!("{{ fileSystems.\"{at}\" = {{ device = \"{OWN}\"; options = [ {options} ]; }}; }}")
}

/// The hidden root's own name, written with an escape, counts with the
/// flag where the decoy's own entry would let the device be: Nix reads each
/// of these as `@vault`, `258` or `/home/alice/vault`. Without the flag the
/// line counts for the device's name.
#[test]
fn an_escape_in_the_roots_own_name_counts() {
    let sysfs = with_udev(luks_on_a_partition());
    let subvolume = own_subvolume();
    let folder = own_folder();
    let multiline = format!(
        "{{\n  fileSystems.\"/srv\" =\n    {{ device = \"{OWN}\";\n      \
         options = [ \"subvol=@v\\ault\" ];\n    }};\n}}"
    );
    let bind = format!(
        "{}\n{{ fileSystems.\"/data\" = {{ device = \"/var/lib/pool/@v\\ault\"; options = [ \"bind\" ]; }}; }}",
        entry("/var/lib/pool", "\"subvolid=5\"")
    );
    for (own, content, line, text) in [
        (&subvolume, entry("/srv", "\"subvol=@v\\ault\""), 1, "@v\\ault"),
        (&subvolume, entry("/srv", "\"subvol=/@v\\ault\""), 1, "@v\\ault"),
        (&subvolume, entry("/home", "\"subvol=@v\\ault\""), 1, "@v\\ault"),
        (&subvolume, entry("/var/lib/x", "\"subvol=@v\\ault\""), 1, "@v\\ault"),
        (&subvolume, entry("/srv", "\"subvolid=2\\58\""), 1, "subvolid=2\\58"),
        (&subvolume, entry("/srv", "\"subvolid=0x1\\02\""), 1, "subvolid=0x1\\02"),
        (&subvolume, entry("/srv", "\"subvolid=258\\n\""), 1, "subvolid=258"),
        (&subvolume, entry("/srv", "\"X-mount.subdir=@v\\ault\""), 1, "@v\\ault"),
        (&subvolume, entry("/srv", "''subvol=@v''\\ault''"), 1, "@v''\\ault"),
        (&subvolume, multiline, 4, "@v\\ault"),
        (&subvolume, bind, 2, "@v\\ault"),
        (&folder, "{ x = \"/home/alice/va\\ult\"; }".to_string(), 1, "/home/alice/va\\ult"),
        (
            &folder,
            "{ fileSystems.\"/srv\" = { device = \"/home/alice/va\\ult\"; options = [ \"bind\" ]; }; }"
                .to_string(),
            1,
            "/home/alice/va\\ult",
        ),
    ] {
        let found = scan(&sysfs, Some(own), &content);
        assert_eq!(
            shown(&found.references),
            [(line, text, ReferenceKind::RootPlace)],
            "{content}"
        );
        if content.contains(OWN) {
            assert!(!scan(&sysfs, None, &content).is_clean(), "{content}");
        }
    }
    // An escape that Nix reads as another name passes.
    for content in [
        entry("/srv", "\"subvol=@v\\\\ault\""),
        entry("/srv", "\"subvolid=2\\\\58\""),
        entry("/srv", "\"subvolid=257\\n\""),
    ] {
        let found = scan(&sysfs, Some(&subvolume), &content);
        assert!(found.references.is_empty(), "{content}: {found:?}");
    }
}

/// With the flag, a value the scan cannot read whole where one could name
/// the root counts: a `subvol=`, `subvolid=` or `X-mount.subdir=` value a
/// `+` goes on with, on its line or the next, and in a place of the
/// decoy's own a `device` or `label` string with an interpolation in it,
/// one a `+` joins to something, or one that goes on over the next line.
/// Without the flag these lines count for the device's name, or pass where
/// they name nothing else.
#[test]
fn a_value_the_scan_cannot_read_whole_counts_with_the_flag() {
    let sysfs = with_udev(luks_on_a_partition());
    let subvolume = own_subvolume();
    for (content, line, text) in [
        (entry("/srv", "(\"subvol=@va\" + \"ult\")"), 1, "subvol=@va"),
        (entry("/srv", "(\"subvolid=25\" + \"8\")"), 1, "subvolid=25"),
        (
            entry("/srv", "(\"X-mount.subdir=@va\" + \"ult\")"),
            1,
            "X-mount.subdir=@va",
        ),
        (
            entry("/srv", "\"X-mount.subdir=${name}\""),
            1,
            "X-mount.subdir=${name}",
        ),
        (
            format!(
                "{{ fileSystems.\"/srv\" = {{ device = \"{OWN}\"; options = [ (\"subvol=@va\"\n  \
                 + \"ult\") ]; }}; }}"
            ),
            1,
            "subvol=@va",
        ),
        (
            "{ fileSystems.\"/data\" = { device = \"/var/lib/pool/@va\" + \"ult\"; }; }"
                .to_string(),
            0,
            "",
        ),
        (
            "{ fileSystems.\"/srv\" = { device = \"/var/lib/pool/@va\" + \"ult\"; }; }".to_string(),
            1,
            "/var/lib/pool/@va",
        ),
        (
            "{ fileSystems.\"/srv\".device = prefix + \"ult\"; }".to_string(),
            1,
            "ult",
        ),
        (
            "{ fileSystems.\"/\".device = \"/dev/disk/by-uuid/${uuid}\"; }".to_string(),
            1,
            "/dev/disk/by-uuid/${uuid}",
        ),
        (
            "{ fileSystems.\"/home\".label = \"${label}\"; }".to_string(),
            1,
            "${label}",
        ),
        (
            "{ boot.initrd.luks.devices.root.device = \"/dev/disk/by-uuid/${uuid}\"; }".to_string(),
            1,
            "/dev/disk/by-uuid/${uuid}",
        ),
        (
            "{ fileSystems.\"/\".device = ''\n  /srv/x\n''; }".to_string(),
            1,
            "''",
        ),
    ] {
        let found = scan(&sysfs, Some(&subvolume), &content);
        if line == 0 {
            // `/data` is no system folder: its device is no place of the
            // decoy's own, and a name Nix builds there passes.
            assert!(found.references.is_empty(), "{content}: {found:?}");
            continue;
        }
        assert_eq!(
            shown(&found.references),
            [(line, text, ReferenceKind::RootPlace)],
            "{content}"
        );
        let without = scan(&sysfs, None, &content);
        assert_eq!(
            without.is_clean(),
            !content.contains(OWN),
            "{content}: {without:?}"
        );
    }
    // A value read whole passes: one that ends before its string does, one
    // a `+` comes only before, and the decoy's own literal entries.
    for content in [
        entry("/srv", "(\"subvol=@home,compress=zstd\" + extra)"),
        entry("/srv", "(prefix + \"subvol=@home\")"),
        entry("/srv", "\"subvol=@srv\" ] ++ [ \"compress=zstd\""),
        format!("{{ fileSystems.\"/\".device = lib.mkForce \"{OWN}\"; }}"),
        format!("{{ fileSystems.\"/\" = {{ device = \"{OWN}\"; fsType = \"btrfs\"; }}; }}"),
        "{ fileSystems.\"/data\".device = \"/dev/disk/by-uuid/${uuid}\"; }".to_string(),
    ] {
        let found = scan(&sysfs, Some(&subvolume), &content);
        assert!(found.references.is_empty(), "{content}: {found:?}");
    }
}

/// Without the flag, a name of the hidden volume written with an escape
/// counts as it does written out, as Nix reads it: its mount point, its
/// device, a link and a label of its storage, and its mapping's name in a
/// `luks.devices` entry, as `encrypted.label` and as a cryptsetup unit,
/// in code and in a comment.
#[test]
fn an_escape_in_a_name_of_the_hidden_volume_counts_without_the_flag() {
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
    ] {
        let found = scan(&sysfs, None, content);
        assert_eq!(shown(&found.references), [(1, text, kind)], "{content}");
    }
    // Escapes Nix reads as another name pass.
    for content in ["{ x = \"/mnt/d\\\\ata\"; }", "{ x = ''/mnt/d\\ata''; }"] {
        let found = scan(&sysfs, None, content);
        assert!(found.is_clean(), "{content}: {found:?}");
    }
}
