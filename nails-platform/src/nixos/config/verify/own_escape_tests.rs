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

/// With the flag, an entry of the decoy's own lets the device's names be
/// only as `nixos-generate-config` writes it: every other expression in it
/// counts, on the line it stands on, whatever it builds. These are the
/// forms through which a text scan cannot tell what Nix evaluates: a `+`
/// behind a bracket, `if … then … else`, a function call
/// (`lib.concatStrings`, `toString`, `lib.mkForce`), an interpolation in a
/// string or a path, a reference to another entry's device, a `let`, an
/// `inherit`, a `''…''` string and one that goes on over the next line, in
/// an entry for `/` or a system folder, in a `boot.initrd.luks.devices`
/// entry and in the set of such entries. Without the flag these lines count
/// for the device's name, or pass where they name nothing else.
#[test]
fn every_other_expression_in_an_own_entry_counts_with_the_flag() {
    let sysfs = with_udev(luks_on_a_partition());
    let subvolume = own_subvolume();
    let folder = own_folder();
    let top = entry("/var/lib/pool", "\"subvolid=5\"");
    let bind = |device: &str| {
        format!(
            "{top}\n{{ fileSystems.\"/srv\" = {{ device = {device}; options = [ \"bind\" ]; }}; }}"
        )
    };
    for (own, content, line, text) in [
        (&subvolume, entry("/srv", "((\"subvol=@va\") + \"ult\")"), 1, "("),
        (&subvolume, entry("/srv", "((\"subvolid=25\") + \"8\")"), 1, "("),
        (&subvolume, entry("/srv", "((\"X-mount.subdir=@va\") + \"ult\")"), 1, "("),
        (
            &subvolume,
            entry("/srv", "((if true then \"subvol=@va\" else \"x\") + \"ult\")"),
            1,
            "(",
        ),
        (&subvolume, entry("/srv", "(rest + (\"ult\"))"), 1, "("),
        (&subvolume, entry("/srv", "\"subvol=@va\" + \"ult\""), 1, "+"),
        (
            &subvolume,
            format!(
                "{{ fileSystems.\"/srv\" = {{ device = \"{OWN}\"; options = [\n  \"subvol=@va\"\n  + \"ult\" ]; }}; }}"
            ),
            3,
            "+",
        ),
        (&subvolume, bind("(\"/var/lib/pool/@va\") + rest"), 2, "("),
        (&subvolume, bind("rest + (\"ult\")"), 2, "rest"),
        (
            &subvolume,
            bind("lib.concatStrings [ \"/var/lib/pool/@va\" \"ult\" ]"),
            2,
            "lib.concatStrings",
        ),
        (
            &subvolume,
            "{ fileSystems.\"/srv\".label = (\"nix\") + os; }".to_string(),
            1,
            "(",
        ),
        (
            &subvolume,
            "{ fileSystems.\"/srv\" = { device = config.fileSystems.\"/\".device; fsType = \"btrfs\"; options = [ \"subvol=@srv\" ]; }; }".to_string(),
            1,
            "config.fileSystems.",
        ),
        (
            &folder,
            "{ fileSystems.\"/srv\" = { device = (\"/home/alice/va\") + rest; options = [ \"bind\" ]; }; }".to_string(),
            1,
            "(",
        ),
        (
            &folder,
            "{ fileSystems.\"/srv\" = { device = toString /home/alice/va${\"ult\"}; options = [ \"bind\" ]; }; }".to_string(),
            1,
            "toString",
        ),
        (
            &folder,
            "{ fileSystems.\"/srv\" = { device = lib.concatStrings [ \"/home/alice/va\" \"ult\" ]; options = [ \"bind\" ]; }; }".to_string(),
            1,
            "lib.concatStrings",
        ),
        (
            &subvolume,
            format!("{{ fileSystems.\"/\".device = lib.mkForce \"{OWN}\"; }}"),
            1,
            "lib.mkForce",
        ),
        (
            &subvolume,
            "{ fileSystems.\"/\".device = \"/dev/disk/by-uuid/${uuid}\"; }".to_string(),
            1,
            "${",
        ),
        (
            &subvolume,
            "{ fileSystems.\"/home\".label = \"${label}\"; }".to_string(),
            1,
            "${",
        ),
        (
            &subvolume,
            "{ fileSystems.\"/\".device = ''\n  /srv/x\n''; }".to_string(),
            1,
            "''",
        ),
        (
            &subvolume,
            format!("{{ fileSystems.\"/\".device = \"{OWN}\n\"; }}"),
            1,
            OWN,
        ),
        (
            &subvolume,
            format!("{{ fileSystems.\"/\" = let d = \"{OWN}\"; in {{ device = d; }}; }}"),
            1,
            "let",
        ),
        (
            &subvolume,
            format!("{{ fileSystems.\"/\" = {{ inherit device; label = \"{OWN}\"; }}; }}"),
            1,
            "inherit",
        ),
        (
            &subvolume,
            format!("{{ fileSystems = lib.mkForce {{ \"/\".device = \"{OWN}\"; }}; }}"),
            1,
            "lib.mkForce",
        ),
        (
            &subvolume,
            format!("{{ boot.initrd.luks.devices.root.device = \"{OWN}\" + \"x\"; }}"),
            1,
            "+",
        ),
        (
            &subvolume,
            format!(
                "{{ boot.initrd.luks.devices.root = {{ device = \"{OWN}\"; keyFile = \"/var/lib/pool/@va\" + \"ult\"; }}; }}"
            ),
            1,
            "+",
        ),
    ] {
        let found = scan(&sysfs, Some(own), &content);
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
    // Outside such entries the same expressions pass: the scan evaluates no
    // Nix, and `/data` is no system folder, whose device names count anyway.
    for content in [
        "{ x = (\"subvol=@va\") + \"ult\"; }".to_string(),
        "{ fileSystems.\"/data\".device = \"/var/lib/pool/@va\" + \"ult\"; }".to_string(),
        "{ services.x.device = lib.mkForce \"/dev/x\"; }".to_string(),
        "{ x = let fileSystems.\"/\".device = f \"y\"; in 1; }".to_string(),
    ] {
        let found = scan(&sysfs, Some(&subvolume), &content);
        assert!(found.references.is_empty(), "{content}: {found:?}");
    }
    // The form `nixos-generate-config` writes passes, and so do `true`,
    // `false` and a number as a whole value and a comment in the entry.
    for content in [
        format!("{{ fileSystems.\"/\" = {{ device = \"{OWN}\"; fsType = \"btrfs\"; }}; }}"),
        format!(
            "{{\n  fileSystems.\"/home\" =\n    {{ device = \"{OWN}\";\n      fsType = \"btrfs\";\n      options = [ \"subvol=@home\" \"compress=zstd\" ];\n      neededForBoot = true; # (early)\n    }};\n}}"
        ),
        format!(
            "{{ boot.initrd.luks.devices.\"luks-x\" = {{ device = \"{OWN}\"; allowDiscards = true; keyFileSize = 4096; }}; }}"
        ),
        "{ fileSystems.\"/data\".device = \"/dev/disk/by-uuid/${uuid}\"; }".to_string(),
    ] {
        let found = scan(&sysfs, Some(&subvolume), &content);
        assert!(found.references.is_empty(), "{content}: {found:?}");
    }
}

/// A `let` block is no definition of the configuration, nor is a comment:
/// a name of the accepted filesystem's devices in one that ends like an
/// entry of the decoy's own counts with the flag, as it does without.
#[test]
fn a_name_in_a_binding_or_a_comment_counts_with_the_flag() {
    let sysfs = with_udev(luks_on_a_partition());
    let subvolume = own_subvolume();
    for content in [
        format!("{{ x = let fileSystems.\"/srv\".device = \"{OWN}\"; in 1; }}"),
        format!("{{ x = let y = {{ fileSystems.\"/\".device = \"{OWN}\"; }}; in y; }}"),
        format!("{{ # fileSystems.\"/\".device = \"{OWN}\";\n}}"),
        format!("{{ /* boot.initrd.luks.devices.root.device = \"{OWN}\"; */ }}"),
    ] {
        let found = scan(&sysfs, Some(&subvolume), &content);
        assert_eq!(found.references.len(), 1, "{content}: {found:?}");
        assert_eq!(
            found.references[0].kind,
            ReferenceKind::Storage,
            "{content}"
        );
        assert!(found.let_be.is_empty(), "{content}");
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
