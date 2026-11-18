// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the line matching of the reference check.

use super::super::scan::Scanner;
use super::*;

fn found(pattern: &Pattern, text: &str) -> Option<String> {
    let mut scanner = Scanner::default();
    let mut shell = Shell::default();
    let lower = text.to_ascii_lowercase();
    let mut lines = Vec::new();
    for line in lower.split('\n') {
        let context = Context {
            names: scanner.line(line.as_bytes()),
            arguments: shell.line(line.as_bytes()),
            places: scanner.places(),
            joined: Vec::new(),
        };
        lines.push((line, context));
    }
    for joined in scanner.joined() {
        lines[joined.line]
            .1
            .joined
            .push((joined.text.clone(), joined.continued));
    }
    lines.iter().find_map(|(line, context)| {
        pattern
            .find(line.as_bytes(), context)
            .map(|range| line[range].to_string())
    })
}

fn data() -> Pattern {
    Pattern::Name {
        name: "data".into(),
        escaped: vec!["data".into()],
    }
}

#[test]
fn a_path_ends_at_a_component_boundary() {
    let path = Pattern::Path("/mnt/data".into());
    for hit in [
        "fileSystems.\"/mnt/data\" = {",
        "imports = [ /mnt/data/nixos ];",
        "url = \"git+file:///mnt/data/nixos\";",
        "# mount it at /mnt/data first",
        "x = /mnt/data;",
    ] {
        assert_eq!(found(&path, hit).as_deref(), Some("/mnt/data"), "{hit}");
    }
    for miss in [
        "fileSystems.\"/mnt/data2\" = {",
        "x = \"/mnt/data-old\";",
        "x = \"/mnt/data.bak\";",
        "x = \"/srv/mnt/data\";",
    ] {
        assert_eq!(found(&path, miss), None, "{miss}");
    }
    let unit = Pattern::Path("mnt-data.mount".into());
    assert_eq!(
        found(&unit, "after = [ \"mnt-data.mount\" ];").as_deref(),
        Some("mnt-data.mount")
    );
    for miss in [
        "after = [ \"srv-mnt-data.mount\" ];",
        "after = [ \"mnt-data.mounts\" ];",
    ] {
        assert_eq!(found(&unit, miss), None, "{miss}");
    }
}

/// The kernel reads a run of slashes as one, so a path counts however many
/// separate its parts; the text reported is the path as written. A path
/// that only begins at a doubled slash inside another one is that other
/// path (`/srv//mnt/data` is `/srv/mnt/data`), and a unit name keeps the
/// rule it had: a `/` before it is no part of its name. A `.` part counts
/// as the kernel reads it.
#[test]
fn a_path_counts_however_many_slashes_part_it() {
    let path = Pattern::Path("/mnt/data".into());
    for (hit, text) in [
        ("fileSystems.\"/mnt//data\" = {", "/mnt//data"),
        ("imports = [ /mnt///data/nixos ];", "/mnt///data"),
        ("x = \"//mnt/data\";", "/mnt/data"),
        ("x = \"///mnt//data//nixos\";", "/mnt//data"),
        ("url = \"git+file:///mnt//data/nixos\";", "/mnt//data"),
        ("# mount it at /MNT//DATA first", "/mnt//data"),
        ("x = \"/mnt/./data\";", "/mnt/./data"),
    ] {
        assert_eq!(found(&path, hit).as_deref(), Some(text), "{hit}");
    }
    for miss in [
        "x = \"/mnt//data2\";",
        "x = \"/mnt//data-old\";",
        "x = \"/mnt///database\";",
        "x = \"/srv//mnt/data\";",
        "x = \"/srv///mnt//data\";",
        "x = \"srv//mnt/data\";",
    ] {
        assert_eq!(found(&path, miss), None, "{miss}");
    }
    let device = Pattern::Path("/dev/mapper/data".into());
    for (hit, text) in [
        ("device = \"/dev/mapper//data\";", "/dev/mapper//data"),
        ("device = \"/dev//mapper/data\";", "/dev//mapper/data"),
    ] {
        assert_eq!(found(&device, hit).as_deref(), Some(text), "{hit}");
    }
    for miss in [
        "device = \"/dev/mapper//data2\";",
        "device = \"/dev/mapper//data-swap\";",
    ] {
        assert_eq!(found(&device, miss), None, "{miss}");
    }
    let unit = Pattern::Path("mnt-data.mount".into());
    assert_eq!(
        found(&unit, "x = \"/etc/systemd/system/mnt-data.mount\";").as_deref(),
        Some("mnt-data.mount")
    );
}

/// systemd allows prefixes before a path in a setting (`-` for a file that
/// may be missing, `+`, `!`, `!!`, `@`, `:`): a run of them that starts a
/// value, after `=`, a quote, a blank or at the start of the line, is no
/// part of the path. A prefix inside a word or after a slash is.
#[test]
fn a_path_after_systemd_s_prefixes_counts() {
    let path = Pattern::Path("/mnt/data".into());
    for (hit, text) in [
        (
            "serviceConfig.EnvironmentFile = \"-/mnt/data/app.env\";",
            "/mnt/data",
        ),
        (
            "serviceConfig.ExecStart = \"+/mnt/data/bin/x\";",
            "/mnt/data",
        ),
        (
            "serviceConfig.ExecStart = \"@/mnt/data/bin/x x\";",
            "/mnt/data",
        ),
        (
            "serviceConfig.ReadWritePaths = [ \"-/mnt/data\" ];",
            "/mnt/data",
        ),
        ("text = ''\n  ExecStart=!!-/mnt/data/x\n'';", "/mnt/data"),
        ("text = ''\n-//mnt//data/app.env\n'';", "/mnt//data"),
        ("x = ''-/mnt/data'';", "/mnt/data"),
        ("# EnvironmentFile= -/mnt/data/app.env", "/mnt/data"),
    ] {
        assert_eq!(found(&path, hit).as_deref(), Some(text), "{hit}");
    }
    for miss in [
        "x = \"x-/mnt/data\";",
        "x = \"/srv/-/mnt/data\";",
        "x = \"a+/mnt/data\";",
        "x = \"user@/mnt/data\";",
        "x = \"-/mnt/data2\";",
        "x = \"./-/mnt/data\";",
    ] {
        assert_eq!(found(&path, miss), None, "{miss}");
    }
}

#[test]
fn a_word_is_bounded_by_non_identifier_bytes() {
    let word = Pattern::Word("nails".into());
    assert_eq!(
        found(&word, "config.nails.enable").as_deref(),
        Some("nails")
    );
    assert_eq!(found(&word, "# nails").as_deref(), Some("nails"));
    assert_eq!(found(&word, "hostName = \"snails-box\";"), None);
    assert_eq!(found(&word, "x = nails_y;"), None);
}

#[test]
fn the_mapping_name_counts_where_it_names_the_mapping_comments_included() {
    for hit in [
        "boot.initrd.luks.devices.data.device = \"/dev/disk/by-uuid/1\";",
        "boot.initrd.luks.devices.\"data\".device = \"/dev/disk/by-uuid/1\";",
        "# boot.initrd.luks.devices.data.device = \"/dev/disk/by-uuid/7d2c9e14\";",
        "/* boot.initrd.luks.devices.\"data\".device = \"/dev/sdb2\"; */",
        "boot.initrd.luks.devices = {\n  data = { device = \"/dev/disk/by-uuid/1\"; };\n};",
        "boot.initrd.luks.devices = { other = { }; data.device = \"/dev/sdb2\"; };",
        "# boot.initrd.luks.devices = {\n#   data = {\n#     device = \"/dev/sdb2\";",
        "environment.etc.crypttab.text = \"data /dev/sdb2 none tcrypt\";",
        "# environment.etc.crypttab.text = \"data /dev/sdb2 none tcrypt\";",
        "text = ''\n  data UUID=7d2c9e14 none luks\n'';",
        "text = ''\n  data /var/lib/vault.img none luks\n'';",
        "# data /dev/sdb2 none tcrypt",
        "script = \"cryptsetup open /dev/sdb2 data\";",
        "# cryptsetup open /dev/sdb2 data",
        "after = [ \"systemd-cryptsetup@data.service\" ];",
        "script = ''\n  cryptsetup open --type luks \\\n    /dev/disk/by-id/ata-x-part2 data\n'';",
        "script = ''\n  cryptsetup \\\n    luksOpen /dev/sdb2 data\n'';",
        "script = \"/run/current-system/sw/bin/cryptsetup close data\";",
        "script = \"cryptsetup create data $DEV\";",
        "script = ''\n  cryptsetup create data /dev/sdb2\n'';",
        "script = \"cryptsetup plainClose data\";",
        "# cryptsetup tcryptClose data",
        "# cryptsetup loopaesClose data; cryptsetup bitlkClose x",
        "script = \"cryptsetup fvault2Close data\";",
        "# use cryptsetup open for the data volume",
        "# systemd-cryptsetup attach data /dev/sdb2 none",
        "text = \"data\\t/dev/sdb2\\tnone\\tluks\";",
        "environment.etc.\"crypttab\" = {\n  text = \"data UUID=7d2c9e14 none luks\";\n};",
        "boot.initrd.clevis.devices.data.secretFile = ./data.jwe;",
        "# boot.initrd.luks.devices = [ { name = \"data\"; device = \"/dev/sdb2\"; } ];",
        "boot.initrd.luks.devices.vault.name = \"data\";",
        "fileSystems.\"/srv/x\" = {\n  encrypted = { enable = true; label = \"data\"; };\n};",
    ] {
        assert_eq!(found(&data(), hit).as_deref(), Some("data"), "{hit}");
    }
    let dashed = Pattern::Name {
        name: "vg-root".into(),
        escaped: vec!["vg\\x2droot".into(), "vg\\\\x2droot".into()],
    };
    for (hit, text) in [
        (
            "requires = [ ''systemd-cryptsetup@vg\\x2droot.service'' ];",
            "vg\\x2droot",
        ),
        (
            "requires = [ \"systemd-cryptsetup@vg\\\\x2droot.service\" ];",
            "vg\\\\x2droot",
        ),
    ] {
        assert_eq!(found(&dashed, hit).as_deref(), Some(text), "{hit}");
    }
}

/// Every way Nix lets a configuration define a `luks.devices` entry,
/// live or commented out.
#[test]
fn a_luks_entry_counts_however_its_blocks_nest() {
    for hit in [
        "boot.initrd.luks = { devices.data.device = \"/dev/sdb2\"; };",
        "boot.initrd.luks = {\n  devices.\"data\" = { device = \"/dev/sdb2\"; };\n};",
        "{\n  boot = {\n    initrd = {\n      luks = {\n        devices = {\n          \
         data = { device = \"/dev/sdb2\"; };\n        };\n      };\n    };\n  };\n}",
        "# boot.initrd.luks = {\n#   devices.data.device = \"/dev/sdb2\";\n# };",
        "boot.initrd.luks.devices = lib.mkForce {\n  data = { device = \"/dev/sdb2\"; };\n};",
        "boot.initrd.luks.devices = lib.mkMerge [\n  { root = { }; }\n  { data.device = \"/dev/sdb2\"; }\n];",
        "boot.initrd.luks.devices = # the vault\n  {\n    data.device = \"/dev/sdb2\";\n  };",
        "boot.initrd.luks.devices . data . device = \"/dev/sdb2\";",
        "boot.initrd.luks.devices = { inherit data; };",
        "boot.initrd.luks.devices = { inherit (cfg) root data; };",
        "imports = [ ({ ... }: { boot.initrd.luks.devices.data.device = \"/dev/sdb2\"; }) ];",
    ] {
        assert_eq!(found(&data(), hit).as_deref(), Some("data"), "{hit}");
    }
}

#[test]
fn the_mapping_name_as_an_ordinary_word_or_directory_passes() {
    for miss in [
        "# and is used to maintain compatibility with application data (e.g. databases)",
        "x = 1; # keep user data on /home",
        "description = \"Back up user data\";",
        "services.postgresql.dataDir = \"/var/lib/postgresql/data\";",
        "fileSystems.\"/srv/data\".device = \"/dev/sdb1\";",
        "services.evolution-data-server.enable = true;",
        "x = \"data2\";",
        "users.users.alice = {\n  data = 1;\n};",
        "boot.initrd.luks.devices.database.device = \"/dev/sdb2\";",
        "boot.initrd.luks.devices = { root = { }; };\nservices.x = {\n  data = 1;\n};",
        "boot.initrd.luks = { devices.root.device = \"/dev/sda2\"; };\ndata = 1;",
        "boot.initrd.luks = {\n  devices.root = { device = \"/dev/sda2\"; };\n  data = 1;\n};",
        "boot.initrd.luks.devices.root = {\n  data = 1;\n};",
        "boot.initrd.luks.devices = lib.mkMerge [ { root = { }; } ];\nx = { data = 1; };",
        "x = \"${pkgs.foo}\"; y = { data = 1; };",
        "# the data / logs split",
        "/data /dev/sdb1 none",
        "# data /home is backed up nightly",
        "environment.systemPackages = with pkgs; [ cryptsetup data ];",
        "# cryptsetup keeps the data safe",
        "# cryptsetup: see the data sheet",
        "# cryptsetup creates nothing in data",
        "script = ''\n  cryptsetup open /dev/sdb2 vault\n  cp -a /srv/data /mnt/x\n'';",
        "script = \"cryptsetup open /dev/sdb2 vault; echo data\";",
        "script = ''\n  cryptsetup open /dev/sdb2 vault \n  echo data\n'';",
        "fileSystems.\"/srv\".label = \"data\";",
        "system.nixos.label = \"data\";",
    ] {
        assert_eq!(found(&data(), miss), None, "{miss}");
    }
}

/// Only cryptsetup's whole name for the mapping counts, whatever its uuid:
/// the decoy's own `user-data` ends like `data` but is another mapping.
#[test]
fn a_dm_uuid_link_counts_when_it_is_the_mapping_s_whole_name() {
    let link = Pattern::DmUuid("data".into());
    for path in [
        "/dev/disk/by-id/dm-uuid-crypt-luks2-7d2c9e14e8a14b3c9f6b0e1a2d3c4b5a-data",
        "/dev/disk/by-id/dm-uuid-crypt-plain-data",
        "/dev/disk/by-id/dm-uuid-crypt-tcrypt-data",
        "/dev/disk//by-id/dm-uuid-crypt-plain-data",
        "/dev//disk/by-id//dm-uuid-crypt-luks2-7d2c9e14e8a14b3c9f6b0e1a2d3c4b5a-data",
    ] {
        assert_eq!(
            found(&link, &format!("# device = \"{path}\";")).as_deref(),
            Some(path)
        );
    }
    for miss in [
        "device = \"/dev/disk/by-id/dm-uuid-crypt-luks2-0123456789abcdef0123456789abcdef-user-data\";",
        "device = \"/dev/disk/by-id/dm-uuid-crypt-plain-user-data\";",
        "device = \"/dev/disk/by-id/dm-uuid-crypt-luks2-7d2c-root\";",
        "device = \"/dev/disk/by-id/dm-uuid-crypt-luks2-7d2c-data2\";",
        "device = \"/srv/dev/disk/by-id/dm-uuid-crypt-luks2-7d2c-data\";",
        "device = \"/srv//dev/disk/by-id/dm-uuid-crypt-plain-data\";",
        "device = \"/dev/disk//by-id/dm-uuid-crypt-plain-data2\";",
        "device = \"/dev/disk/by-id/dm-uuid-crypt--data\";",
        "device = \"/dev/disk/by-id/dm-uuid-lvm-abcdef-data\";",
    ] {
        assert_eq!(found(&link, miss), None, "{miss}");
    }
}

/// A label counts as a tag or as the `label` of a filesystem or swap
/// entry, never as an ordinary word; a partition label only as a tag.
#[test]
fn a_label_counts_as_a_tag_or_a_filesystem_s_label() {
    let label = Pattern::Tag {
        tag: "label".into(),
        value: "vault".into(),
    };
    for hit in [
        "# /dev/sdb2: LABEL=vault",
        "text = ''\n  x LABEL=\"vault\" none luks\n'';",
        "fileSystems.\"/srv\".label = \"vault\";",
        "fileSystems.\"/srv\" = { label = \"vault\"; fsType = \"ext4\"; };",
        "swapDevices = [ { label = \"vault\"; } ];",
        "# fileSystems.\"/srv\" = {\n#   label = \"vault\";\n# };",
    ] {
        assert_eq!(found(&label, hit).as_deref(), Some("vault"), "{hit}");
    }
    for miss in [
        "# PARTLABEL=vault",
        "# LABEL=vault2",
        "networking.hostName = \"vault\";",
        "system.nixos.label = \"vault\";",
        "services.vault.enable = true;",
        "fileSystems.\"/srv\".encrypted.label = \"vault\";",
    ] {
        assert_eq!(found(&label, miss), None, "{miss}");
    }
    let partlabel = Pattern::Tag {
        tag: "partlabel".into(),
        value: "vault".into(),
    };
    assert_eq!(
        found(&partlabel, "# PARTLABEL=vault").as_deref(),
        Some("vault")
    );
    assert_eq!(
        found(&partlabel, "fileSystems.\"/srv\".label = \"vault\";"),
        None
    );
}

/// A name stands as a component where it is a whole part of a path or a
/// whole string, whatever comes before it, or an attribute name the line
/// defines; never as part of a longer name or a dotted reference.
#[test]
fn a_component_stands_whole_in_a_path_a_string_or_a_defined_attribute() {
    let name = Pattern::Component("@vault".into());
    for hit in [
        "options = [ \"subvol=@vault\" ];",
        "options = [ \"subvol=//@vault\" ];",
        "options = [ \"subvol=./@vault/.\" ];",
        "options = [ \"subvol=@home/../@vault\" ];",
        "device = \"/btr_pool/@vault/inner\";",
        "subvolume.\"@vault\" = { };",
    ] {
        assert_eq!(found(&name, hit).as_deref(), Some("@vault"), "{hit}");
    }
    for miss in [
        "x = \"@vaults\";",
        "x = \"old@vault\";",
        "x = \"@vault-1\";",
    ] {
        assert_eq!(found(&name, miss), None, "{miss}");
    }
    let name = Pattern::Component("vault".into());
    assert_eq!(
        found(&name, "services.btrbk.subvolume.vault = { };").as_deref(),
        Some("vault")
    );
    for miss in [
        "environment.systemPackages = [ pkgs.vault ];",
        "x = \"/etc/vault.conf\";",
    ] {
        assert_eq!(found(&name, miss), None, "{miss}");
    }
}

/// `subvolid=` names the id in every base the kernel reads it in, and one
/// whose value cannot be read counts whatever the id; `subvol=` counts when
/// its value cannot be read.
#[test]
fn a_subvolume_id_is_read_as_the_kernel_reads_it() {
    let id = Pattern::SubvolId(Some(258));
    for hit in [
        "subvolid=258",
        "subvolid=0x102",
        "subvolid=0X102",
        "subvolid=0402",
        "subvolid=+258",
        "\"compress=zstd,subvolid=258\"",
        "\"subvolid=${toString id}\"",
        "\"subvolid=\"",
        "\"subvolid=258x\"",
    ] {
        assert!(found(&id, hit).is_some(), "{hit}");
    }
    for miss in [
        "subvolid=2580",
        "subvolid=257",
        "subvolid=0x1020",
        "xsubvolid=258",
        "subvol=258",
    ] {
        assert_eq!(found(&id, miss), None, "{miss}");
    }
    let none = Pattern::SubvolId(None);
    assert_eq!(found(&none, "subvolid=258"), None);
    assert!(found(&none, "subvolid=${id}").is_some());
    let unread = Pattern::Unread("subvol".into());
    for hit in ["\"subvol=${name}\"", "(\"subvol=\" + name)", "subvol=;"] {
        assert!(found(&unread, hit).is_some(), "{hit}");
    }
    for miss in ["\"subvol=@\"", "\"subvolid=\"", "\"subvol=/\""] {
        assert_eq!(found(&unread, miss), None, "{miss}");
    }
}

/// A `subvol=`, `x-mount.subdir=` or `subvolid=` value that runs to the end
/// of a string a `+` joins to something, on its line or the next, cannot be
/// read whole; one that ends before the end of its string, or a string
/// joined only before it, can.
#[test]
fn a_value_a_plus_goes_on_with_cannot_be_read() {
    let subvol = Pattern::Unread("subvol".into());
    let subdir = Pattern::Unread("x-mount.subdir".into());
    let id = Pattern::SubvolId(Some(258));
    for (pattern, hit) in [
        (&subvol, "(\"subvol=@va\" + \"ult\")"),
        (&subvol, "(\"subvol=@va\"+\"ult\")"),
        (&subvol, "(''subvol=@va'' + name)"),
        (&subvol, "options = [ (\"subvol=@va\"\n  + \"ult\") ];"),
        (&subvol, "# options = [ (\"subvol=@va\" + \"ult\") ];"),
        (&subdir, "(\"X-mount.subdir=@va\" + \"ult\")"),
        (&subdir, "\"X-mount.subdir=${name}\""),
        (&subdir, "\"X-mount.subdir=\""),
        (&id, "(\"subvolid=25\" + \"8\")"),
        (&id, "(\"subvolid=2\" + toString 58)"),
    ] {
        assert!(found(pattern, hit).is_some(), "{hit}");
    }
    for (pattern, miss) in [
        (&subvol, "(\"subvol=@home,compress=zstd\" + extra)"),
        (&subvol, "(prefix + \"subvol=@home\")"),
        (&subvol, "[ \"subvol=@home\" ] ++ [ \"x\" ]"),
        (&subdir, "\"X-mount.subdir=home\""),
        (&id, "(\"subvolid=257,ssd\" + extra)"),
        (&id, "\"subvolid=257\""),
    ] {
        assert_eq!(found(pattern, miss), None, "{miss}");
    }
}

/// A path read with `.` parts in it, as the kernel resolves them.
#[test]
fn a_path_matches_through_dot_parts() {
    let path = Pattern::Path("/home/alice/vault".into());
    for hit in [
        "x = \"/home/alice/./vault\";",
        "x = \"/home/./alice/.//vault/db\";",
    ] {
        assert!(found(&path, hit).is_some(), "{hit}");
    }
    assert_eq!(found(&path, "x = \"/home/alice/../vault\";"), None);
}
