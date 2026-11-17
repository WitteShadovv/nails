// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
fn a_typical_fstab_is_parsed_with_escapes_and_defaults() {
    let entries = parse_fstab(
        "# comment\n\
         UUID=1234-ABCD /boot vfat umask=0077 0 2\n\
         /dev/mapper/root / ext4 errors=remount-ro 0 1\n\
         LABEL=home /home ext4 defaults,noatime 0 2\n\
         /dev/sdb1 /mnt/My\\040Disk ntfs-3g noauto 0 0\n\
         /swapfile none swap sw 0 0\n\
         tmpfs /tmp tmpfs\n\
         \n",
    );
    assert_eq!(entries.len(), 6);
    assert_eq!(entries[0].file, Path::new("/boot"));
    assert_eq!(
        entries[0].device(),
        Some(PathBuf::from("/dev/disk/by-uuid/1234-ABCD"))
    );
    assert_eq!(entries[3].file, Path::new("/mnt/My Disk"));
    assert!(entries[3].is_noauto());
    assert!(entries[4].is_swap());
    assert!(entries[5].is_virtual());
    assert_eq!(entries[5].options, vec!["defaults"]);
    assert_eq!(entries[1].option_value("errors"), Some("remount-ro"));
}

#[test]
fn filesystem_classes_are_told_apart() {
    let entry = |t: &str, o: &str| FstabEntry {
        spec: "x".into(),
        file: "/x".into(),
        vfstype: t.into(),
        options: o.split(',').map(str::to_string).collect(),
    };
    assert!(entry("9p", "trans=virtio").is_host_share());
    assert!(entry("nfs4", "defaults").is_network());
    assert!(entry("ext4", "_netdev").is_network());
    assert!(entry("none", "bind").is_bind());
    assert!(!entry("ext4", "noauto,x-systemd.automount").is_noauto());
    assert!(entry("ext4", "noauto,x-systemd.automount").is_automount());
}

/// `libmount` and systemd match an option by its name before `=`:
/// util-linux 2.42's `mount` binds for `bind=x`, `bind=` and `rbind=`
/// whatever the type, and systemd's `fstab_test_option()` takes them for
/// `bind` and `rbind`. A name in another case, in quotes or with more
/// after it is none.
#[test]
fn an_option_named_bind_or_rbind_makes_a_bind_with_a_value_too() {
    let entry = |t: &str, o: &str| FstabEntry {
        spec: "/srv/x".into(),
        file: "/mnt".into(),
        vfstype: t.into(),
        options: o.split(',').map(str::to_string).collect(),
    };
    for (vfstype, options) in [
        ("none", "bind"),
        ("none", "rbind,nofail"),
        ("tmpfs", "bind=x"),
        ("nfs", "nofail,bind="),
        ("overlay", "rbind="),
        ("9p", "bind=1,nofail"),
        ("none", "bind=\"a,b\""),
        ("proc", "rbind=yes"),
    ] {
        assert!(entry(vfstype, options).is_bind(), "{vfstype} {options}");
    }
    for (vfstype, options) in [
        ("none", "Bind"),
        ("none", "binds"),
        ("none", "\"bind\""),
        ("none", "x-a=bind"),
        ("none", "=bind"),
        ("none", "bin"),
        ("ext4", "defaults"),
    ] {
        assert!(!entry(vfstype, options).is_bind(), "{vfstype} {options}");
    }
    assert!(is_bind_option("rbind=x"));
    assert!(!is_bind_option("x-systemd.bind"));
}

/// An option is named by the part before its first `=`, as systemd's
/// `fstab_test_option()` names it.
#[test]
fn an_option_is_named_by_the_part_before_its_value() {
    for (option, name, named) in [
        ("noauto", "noauto", Some(None)),
        ("noauto=1", "noauto", Some(Some("1"))),
        ("noauto=", "noauto", Some(Some(""))),
        (
            "x-systemd.automount=0",
            "x-systemd.automount",
            Some(Some("0")),
        ),
        ("subvol=/a=b", "subvol", Some(Some("/a=b"))),
        (
            "comment=systemd.automount",
            "comment=systemd.automount",
            Some(None),
        ),
        ("noautox", "noauto", None),
        ("noauto", "auto", None),
        ("subvolid=5", "subvol", None),
        ("Noauto", "noauto", None),
    ] {
        assert_eq!(option_named(option, name), named, "{option} {name}");
    }
}

/// The lines are split as `libmount` splits them: only spaces and tabs
/// are trimmed, so a vertical tab, a form feed or a no-break space before
/// a `#` makes a line, and one carriage return before each newline goes.
#[test]
fn only_spaces_and_tabs_are_trimmed_before_a_comment() {
    let text = " \t# a comment\n\
                \u{b}#/srv/x /mnt3 none bind 0 0\n\
                \u{c}#/srv/x /mnt5 none bind 0 0\n\
                \u{a0}#/srv/x /mnt6 none bind 0 0\n\
                \t/dev/sdb1 /data ext4 defaults 0 2 \t\r\n\
                /dev/sdc1 /backup ext4 noauto 0 2\r";
    let lines = parse_fstab_lines(text);
    let read: Vec<&str> = lines.iter().map(|(_, line)| *line).collect();
    assert_eq!(
        read,
        [
            "\u{b}#/srv/x /mnt3 none bind 0 0",
            "\u{c}#/srv/x /mnt5 none bind 0 0",
            "\u{a0}#/srv/x /mnt6 none bind 0 0",
            "/dev/sdb1 /data ext4 defaults 0 2",
            "/dev/sdc1 /backup ext4 noauto 0 2",
        ]
    );
    assert_eq!(lines[0].0.spec, "#/srv/x");
    assert_eq!(lines[0].0.file, Path::new("/mnt3"));
    assert_eq!(lines[3].0.options, ["defaults"]);
    // A carriage return only goes right before the end of a line.
    let (entry, line) = &parse_fstab_lines("/dev/sdb1 /data ext4 rw\r\r\n")[0];
    assert_eq!(*line, "/dev/sdb1 /data ext4 rw\r");
    assert_eq!(entry.options, ["rw"]);
}

/// systemd's fstab generator takes the last of `noauto` and `auto`, and of
/// `nofail` and `fail`: an entry that reads `noauto` first and `auto`
/// after it is mounted at boot, and read as `noauto` the session left it
/// to the hidden systemd, which mounted it read-write.
#[test]
fn the_last_of_an_option_and_its_opposite_counts() {
    let entry = |t: &str, o: &str| FstabEntry {
        spec: "/dev/vdb1".into(),
        file: "/data".into(),
        vfstype: t.into(),
        options: o.split(',').map(str::to_string).collect(),
    };
    assert!(!entry("ext4", "noauto,auto").is_noauto());
    assert!(entry("ext4", "auto,noauto").is_noauto());
    assert!(!entry("ext4", "defaults").is_noauto());
    assert!(entry("ext4", "nofail").is_nofail());
    assert!(!entry("ext4", "nofail,fail").is_nofail());
    assert!(entry("ext4", "fail,defaults,nofail").is_nofail());
    assert!(!entry("ext4", "defaults").is_nofail());
    // By the name, whatever the value: systemd 260.5's fstab generator
    // read nofail=0 as nofail.
    assert!(entry("ext4", "nofail=no").is_nofail());
    // The older spelling of an automount, which systemd still reads; and
    // none for swap, which systemd never gives one.
    assert!(entry("ext4", "comment=systemd.automount").is_automount());
    assert!(!entry("ext4", "comment=systemd.automount,noauto").is_noauto());
    assert!(!entry("swap", "x-systemd.automount").is_automount());
    assert!(entry("swap", "noauto,x-systemd.automount").is_noauto());
    // A unit named to pull the entry in takes noauto back, as the fstab
    // generator then links the mount there; not for swap, nor with no
    // unit named.
    for options in [
        "noauto,x-systemd.wanted-by=multi-user.target",
        "x-systemd.required-by=backup.service,noauto",
    ] {
        assert!(!entry("ext4", options).is_noauto(), "{options}");
        assert!(entry("ext4", options).names_units_that_pull_it_in());
    }
    assert!(entry("ext4", "noauto,x-systemd.wanted-by=").is_noauto());
    assert!(entry("swap", "noauto,x-systemd.wanted-by=multi-user.target").is_noauto());
}

/// Each option is read by its name, alone or with a value, as systemd
/// 260.5's fstab generator read these lines on a test root: it linked
/// `noauto,auto=1` and `noauto,auto=0` into `local-fs.target.requires`,
/// set up an automount for `noauto,x-systemd.automount=0`,
/// `x-systemd.automount=no` and `comment=systemd.automount=1`, took
/// `nofail=1` for `nofail` and `nofail,fail=1` for `fail`, linked a line
/// with `_netdev=1` into `remote-fs.target` and an NFS line with `bg=1`
/// into its `.wants`, and mounted a `noauto` line for `/usr`.
#[test]
fn options_are_read_by_their_names_as_systemd_reads_them() {
    let entry = |file: &str, t: &str, o: &str| FstabEntry {
        spec: "/dev/vdb1".into(),
        file: file.into(),
        vfstype: t.into(),
        options: o.split(',').map(str::to_string).collect(),
    };
    for options in [
        "noauto,auto=1",
        "noauto,auto=0",
        "noauto,auto=",
        "noauto,x-systemd.automount=0",
        "noauto,x-systemd.automount=no",
        "noauto,comment=systemd.automount=1",
    ] {
        assert!(!entry("/data", "ext4", options).is_noauto(), "{options}");
    }
    for options in [
        "noauto=1",
        "auto,noauto=",
        "auto=1,noauto",
        "noauto,nofail=1",
    ] {
        assert!(entry("/data", "ext4", options).is_noauto(), "{options}");
    }
    assert!(entry("/data", "ext4", "noauto,x-systemd.automount=0").is_automount());
    assert!(entry("/data", "ext4", "comment=systemd.automount=1").is_automount());
    assert!(!entry("/data", "ext4", "x-systemd.automountx").is_automount());
    assert!(entry("/data", "ext4", "nofail=1").is_nofail());
    assert!(!entry("/data", "ext4", "nofail,fail=1").is_nofail());
    assert!(entry("/data", "ext4", "_netdev=1").is_network());
    assert!(!entry("/data", "ext4", "_netdevx").is_network());
    assert!(entry("/data", "ext4", "x-systemd.makefs=1").has_named("x-systemd.makefs"));
    assert!(!entry("/data", "ext4", "x-systemd.makefs=1").has_option("x-systemd.makefs"));
    // A mount of / or /usr is mandatory, as written with . and .. read.
    for file in ["/usr", "/", "/usr/", "/./usr", "/x/../usr"] {
        let line = entry(file, "ext4", "noauto");
        assert!(line.is_mandatory(), "{file}");
        assert!(!line.is_noauto(), "{file}");
    }
    // The generator ignores nofail and an automount there too: it linked
    // usr.mount into local-fs.target.requires for nofail,x-systemd.automount.
    let usr = entry("/usr", "ext4", "nofail,x-systemd.automount");
    assert!(!usr.is_nofail());
    assert!(!usr.is_automount());
    assert!(entry("/usr/local", "ext4", "nofail,x-systemd.automount").is_automount());
    assert!(!entry("/usr/local", "ext4", "noauto").is_mandatory());
    assert!(!entry("/usr", "swap", "noauto").is_mandatory());
    assert!(any_named(&["bg=1".to_string()], &["bg"]));
    assert!(last_named(
        &["fg".to_string(), "bg=1".to_string()],
        "bg",
        "fg"
    ));
    assert!(!last_named(
        &["bg".to_string(), "fg=1".to_string()],
        "bg",
        "fg"
    ));
    assert!(!last_named(&[], "bg", "fg"));
}

#[test]
fn specs_name_their_dev_paths() {
    assert_eq!(
        spec_device("PARTUUID=0a1b-02"),
        Some(PathBuf::from("/dev/disk/by-partuuid/0a1b-02"))
    );
    assert_eq!(
        spec_device("PARTLABEL=\"data\""),
        Some(PathBuf::from("/dev/disk/by-partlabel/data"))
    );
    assert_eq!(spec_device("/dev/vdb"), Some(PathBuf::from("/dev/vdb")));
    assert_eq!(spec_device("tmpfs"), None);
    assert_eq!(spec_device("ID=1"), None);
}

/// A path is simplified as systemd simplifies it before it is escaped.
/// Found by the `fstab_crypttab` fuzz target: the swap on
/// `/dev/disk/by-/./label/swap` kept its `.` in the unit the session
/// masked, so the unit systemd generates stayed free.
#[test]
fn a_path_is_simplified_as_systemd_simplifies_it() {
    for (path, name) in [
        ("/mnt/./data/.", "mnt-data"),
        ("/./x", "x"),
        ("//mnt//data//", "mnt-data"),
        ("/../../mnt/data", "mnt-data"),
        ("/.", "-"),
        ("/./.hidden", "\\x2ehidden"),
        ("./vg-root", "vg\\x2droot"),
    ] {
        assert_eq!(escape_path(Path::new(path)), name, "{path}");
    }
}

/// A tag names the link udev makes for it, in udev's encoding. Found by
/// the `fstab_crypttab` fuzz target: `LABEL=swap space` named
/// `/dev/disk/by-label/swap space`, which no link is, so the session
/// masked a swap unit systemd never generates and left the real one free.
#[test]
fn a_tag_names_the_link_udev_makes() {
    for (spec, device) in [
        ("LABEL=My Data", "/dev/disk/by-label/My\\x20Data"),
        ("LABEL=\"My Data\"", "/dev/disk/by-label/My\\x20Data"),
        (
            "PARTLABEL='EFI system'",
            "/dev/disk/by-partlabel/EFI\\x20system",
        ),
        ("LABEL=\"\"half\"", "/dev/disk/by-label/\\x22half"),
        ("LABEL=a/b", "/dev/disk/by-label/a\\x2fb"),
        // Not the absolute path /etc, which Path::join made of it.
        ("LABEL=/etc", "/dev/disk/by-label/\\x2fetc"),
        ("LABEL=back\\slash", "/dev/disk/by-label/back\\x5cslash"),
        ("LABEL=Données#2", "/dev/disk/by-label/Données#2"),
        ("UUID=0a1b-2c3d", "/dev/disk/by-uuid/0a1b-2c3d"),
    ] {
        assert_eq!(spec_device(spec), Some(PathBuf::from(device)), "{spec}");
    }
}
