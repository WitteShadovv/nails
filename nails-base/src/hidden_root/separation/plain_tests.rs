// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Which lines of a decoy's fstab are plain, and why the others are not.

use super::*;

/// Why the one line of `line`, as fstab text, is not plain.
fn why(line: &str) -> Vec<Unplain> {
    let (entries, unplain) = read_fstab(&format!("{line}\n"));
    assert_eq!(entries.len(), 1, "{line}");
    unplain
        .get(&0)
        .map(|line| line.why.clone())
        .unwrap_or_default()
}

fn escape(field: &'static str, written: &str) -> Unplain {
    Unplain::Escape {
        field,
        written: written.to_string(),
    }
}

#[test]
fn the_lines_of_common_decoys_are_plain() {
    // Debian, Ubuntu, Fedora, Arch and NixOS lines, a space and a tab in a
    // path written as their escapes, every tag libmount knows, and lines of
    // filesystems whose first field names no local path.
    for line in [
        "UUID=0a1b-2c3d / ext4 errors=remount-ro 0 1",
        "PARTUUID=5e0b-01 / ext4 rw,discard,errors=remount-ro,x-systemd.growfs 0 1",
        "UUID=f1 / btrfs subvol=root,compress=zstd:1 0 0",
        "LABEL=My\\040Data /mnt/My\\040Disk ntfs-3g noauto 0 0",
        "PARTLABEL=EFI\\011system /boot/efi vfat umask=0077 0 1",
        "/dev/mapper/vg-root / ext4 defaults 0 1",
        "/dev/disk/by-id/virtio-extra /srv/data ext4 defaults 0 2",
        "/swapfile none swap sw 0 0",
        "/srv/x /mnt none bind 0 0",
        "/srv/x /mnt tmpfs bind=x 0 0",
        "/a\\012b\\134c /srv/d none rbind,nofail 0 0",
        "/srv/img.raw /mnt/img ext4 loop 0 0",
        "tmpfs /tmp tmpfs mode=1777,nosuid 0 0",
        "none /dev/shm tmpfs defaults 0 0",
        "proc /proc proc defaults 0 0",
        "nfsd /proc/fs/nfsd nfsd defaults 0 0",
        "server:/export /net nfs4 _netdev 0 0",
        "//server/share /mnt/s cifs credentials=/etc/cifs 0 0",
        "rpool/data /data zfs defaults 0 0",
        "store /nix/.ro-store 9p trans=virtio,version=9p2000.L,cache=loose 0 0",
        "shared /mnt/host virtiofs defaults 0 0",
        "share /mnt/share vboxsf defaults 0 0",
        "overlay /nix/store overlay lowerdir=/nix/.ro-store,upperdir=/u,workdir=/w 0 0",
        "mybucket /mnt/s3 fuse.s3fs _netdev,allow_other 0 0",
        "sshfs#op@host:/ /mnt/host fuse defaults 0 0",
        "op@host:/ /mnt/host fuse.sshfs defaults 0 0",
        "remote:path /mnt/r fuse.rclone defaults 0 0",
        ".host:/ /mnt/hgfs fuse.vmhgfs-fuse defaults,allow_other 0 0",
        "bindfs#/srv/x /media/b fuse nofail 0 0",
        "/srv/x /media/b fuse.bindfs nofail 0 0",
        "fuse2fs#/dev/sdb1 /media/f fuse nofail 0 0",
        "UUID=0a1b /media/f fuse.fuse2fs nofail 0 0",
        "/dev/sdb1 /mnt ext4",
        "/dev/sdb1 /mnt",
    ] {
        assert_eq!(why(line), [], "{line}");
    }
}

#[test]
fn an_escape_other_than_a_space_tab_newline_or_backslash_is_not_plain() {
    // libmount decodes every \ooo, NAILS's parser some of them otherwise: a
    // backslash in the first two fields must begin \040, \011, \012 or \134.
    for (line, unplain) in [
        (
            "/data/\\170 /mnt none bind 0 0",
            escape("first field", "\\170"),
        ),
        (
            "/dev/mapper/d\\141ta /media/x ext4 nofail 0 0",
            escape("first field", "\\141"),
        ),
        (
            "/srv/x /m\\156t none bind 0 0",
            escape("mount point", "\\156"),
        ),
        (
            "/srv/x\\000 /mnt none bind 0 0",
            escape("first field", "\\000"),
        ),
        (
            "/srv/x\\777 /mnt none bind 0 0",
            escape("first field", "\\777"),
        ),
        ("/srv/a\\b /mnt none bind 0 0", escape("first field", "\\b")),
        ("/srv/x\\ /mnt none bind 0 0", escape("first field", "\\")),
        // A backslash before an escape is no escape: libmount reads it as
        // itself and decodes the escape after it.
        (
            "/srv/x\\\\040 /mnt none bind 0 0",
            escape("first field", "\\\\04"),
        ),
        (
            "LABEL=back\\slash /mnt ext4 defaults 0 0",
            escape("first field", "\\sla"),
        ),
    ] {
        assert_eq!(why(line), [unplain], "{line}");
    }
}

#[test]
fn a_backslash_in_the_type_or_the_options_is_not_plain() {
    // libmount reads `bin\144` as `bind`, which NAILS's parser does not
    // decode; any backslash there counts, whatever the type.
    for (line, unplain) in [
        ("/srv/x /mnt none bin\\144 0 0", Unplain::OptionsBackslash),
        ("/srv/x /mnt none \\162bind 0 0", Unplain::OptionsBackslash),
        ("/srv/x /mnt tmpfs bin\\144 0 0", Unplain::OptionsBackslash),
        (
            "/dev/sdb1 /srv ext4 x-systemd.requires=a\\x2db.service 0 0",
            Unplain::OptionsBackslash,
        ),
        (
            "/dev/mapper/data /media/x ext\\064 nofail 0 0",
            Unplain::TypeBackslash,
        ),
        (
            "/dev/mapper/data none s\\167ap sw 0 0",
            Unplain::TypeBackslash,
        ),
    ] {
        assert_eq!(why(line), [unplain], "{line}");
    }
}

#[test]
fn a_list_of_types_is_not_plain() {
    assert_eq!(
        why("/dev/sdb1 /media/x ext4,xfs nofail 0 0"),
        [Unplain::TypeList]
    );
    // libmount looks a relative first field up from the folder mount runs
    // in, for each type of the list.
    assert_eq!(
        why("dev/mapper/data /media/x ext4,xfs nofail 0 0"),
        [Unplain::TypeList, Unplain::Relative]
    );
    assert_eq!(
        why("tmpfs /tmp tmpfs,ramfs defaults 0 0"),
        [Unplain::TypeList, Unplain::Relative]
    );
}

#[test]
fn a_first_field_that_is_no_absolute_path_and_no_tag_is_not_plain() {
    // mount and swapon look such a path up from the folder they run in,
    // for every type that names a local path by it, a bind line's of any
    // type, and a tag libmount does not know is such a path too.
    for line in [
        "dev/mapper/data /media/x ext4 nofail 0 0",
        "dev/mapper/data /media/x ntfs-3g nofail,x-systemd.automount 0 0",
        "dev/dm-9 /media/x cramfs nofail 0 0",
        "dev/sdb1 /media/x fuseblk defaults 0 0",
        "swapfile none swap sw 0 0",
        "srv/img.raw /mnt/img auto loop 0 0",
        "srv/x /srv/b none bind 0 0",
        "srv/x /srv/b tmpfs rbind 0 0",
        "FOO=bar /media/x ext4 defaults 0 0",
        "uuid=0a1b /media/x ext4 defaults 0 0",
        "\\040/dev/sdb1 /media/x ext4 defaults 0 0",
    ] {
        assert_eq!(why(line), [Unplain::Relative], "{line}");
    }
    // A RAM, kernel, host-share, network, overlay, ZFS or FUSE line names a
    // source of another kind by it.
    for vfstype in [
        "tmpfs",
        "devpts",
        "nfs",
        "nfs4",
        "nfsd",
        "cifs",
        "afs",
        "9p",
        "virtiofs",
        "vboxsf",
        "prl_fs",
        "overlay",
        "zfs",
        "fuse.sshfs",
        "selinuxfs",
        "xenfs",
        "none",
    ] {
        let line = format!("source /srv/x {vfstype} defaults 0 0");
        assert_eq!(why(&line), [], "{line}");
        assert!(names_no_local_path(vfstype), "{vfstype}");
    }
    // A FUSE line is read by the source it gives its program instead.
    for vfstype in [
        "ext4",
        "swap",
        "auto",
        "fuseblk",
        "ntfs-3g",
        "squashfs",
        "bcachefs",
        "fuse",
        "fuse.rclone",
        "fuse.bindfs",
    ] {
        assert!(!names_no_local_path(vfstype), "{vfstype}");
    }
}

#[test]
fn a_bind_option_with_a_value_makes_a_bind_line() {
    // libmount binds for `bind=x`, `rbind=` and `bind="a,b"` whatever the
    // type: such a line's first field is the path of its source, so a
    // relative one is not plain whatever the type.
    for line in [
        "srv/x /mnt none bind=x 0 0",
        "srv/x /mnt none bind=\"a,b\" 0 0",
        "srv/x /mnt zfs bind=x 0 0",
        "srv/x /mnt fuse bind=x 0 0",
        "srv/x /mnt tmpfs rbind=,nofail 0 0",
        "a#/srv/x /mnt fuse.bindfs bind 0 0",
    ] {
        assert_eq!(why(line), [Unplain::Relative], "{line}");
    }
    // An absolute source is plain, and the judge reads it.
    for line in [
        "/srv/x /mnt tmpfs bind=x 0 0",
        "/srv/x /mnt nfs bind=x 0 0",
        "/srv/x /mnt overlay rbind= 0 0",
        "/srv/x/sub /srv/sub 9p bind=1,nofail 0 0",
        "/srv/x /mnt none bind=\"a,b\" 0 0",
        "/srv/x /mnt proc bind=x 0 0",
        "/srv/x /mnt tmpfs bind=x,noauto,x-systemd.automount 0 0",
    ] {
        assert_eq!(why(line), [], "{line}");
    }
}

/// The source the one fstab line `line` names, as the judge reads it.
fn source_of(line: &str) -> Option<String> {
    let (entries, _) = read_fstab(&format!("{line}\n"));
    source(&entries[0]).map(str::to_string)
}

#[test]
fn a_fuse_line_is_read_by_the_source_it_gives_its_program() {
    // mount.fuse runs the program before the first # of a `fuse` line's
    // first field on the part after it, and hands a `fuse.<program>` line's
    // whole first field to that program, a # included (mount.fuse3 3.17).
    for (line, source) in [
        ("bindfs#/srv/x /media/b fuse nofail 0 0", Some("/srv/x")),
        (
            "fuse2fs#/dev/mapper/data /media/f fuse nofail 0 0",
            Some("/dev/mapper/data"),
        ),
        (
            "sshfs#op@host:/a#b /mnt fuse defaults 0 0",
            Some("op@host:/a#b"),
        ),
        ("bindfs /media/b fuse nofail 0 0", None),
        ("/srv/x /media/b fuse.bindfs nofail 0 0", Some("/srv/x")),
        (
            "/srv/x/a#/tmp /media/b fuse.bindfs nofail 0 0",
            Some("/srv/x/a#/tmp"),
        ),
        // `mount` binds a bind line itself, whatever its type says.
        ("a#/srv/x /mnt fuse bind 0 0", Some("a#/srv/x")),
        ("/dev/sdb1 /mnt ext4 defaults 0 0", Some("/dev/sdb1")),
    ] {
        assert_eq!(source_of(line).as_deref(), source, "{line}");
    }
    // A source that is an absolute path or a tag NAILS resolves is plain,
    // and the judge reads it.
    for line in [
        "bindfs#/srv/x /media/b fuse nofail 0 0",
        "fuse2fs#/srv/x/disk.img /media/i fuse nofail 0 0",
        "/srv/x /media/b fuse.bindfs nofail 0 0",
        "fuse2fs#/dev/mapper/data /media/f fuse nofail 0 0",
        "fuse2fs#/dev/dm-9 /media/f fuse nofail 0 0",
        "fuse2fs#LABEL=data /media/f fuse nofail 0 0",
        "UUID=0a1b /media/f fuse.fuse2fs nofail 0 0",
    ] {
        assert_eq!(why(line), [], "{line}");
    }
    // Any other source is not plain, unless its program is one that takes
    // a remote source by it: rclone only for a remote's name, as rclone 1.75
    // reads `srv/x`, `:local:/srv/x` and `srv/x:y` as local paths.
    for line in [
        "srv/x /media/b fuse.bindfs nofail 0 0",
        "dev/mapper/data /media/f fuse.fuse2fs nofail 0 0",
        "bindfs#srv/x /media/b fuse nofail 0 0",
        "bindfs# /media/b fuse nofail 0 0",
        "/usr/bin/sshfs#op@host:/ /mnt fuse defaults 0 0",
        "srv/x /media/r fuse.rclone nofail 0 0",
        ":local:/srv/x /media/r fuse.rclone nofail 0 0",
        "srv/x:y /media/r fuse.rclone nofail 0 0",
        "lxcfs /var/lib/lxcfs fuse.lxcfs defaults 0 0",
    ] {
        assert_eq!(why(line), [Unplain::FuseSource], "{line}");
    }
    assert_eq!(
        why("bindfs /media/b fuse nofail 0 0"),
        [Unplain::FuseNoSource]
    );
    assert_eq!(
        why("fuse2fs#ID=dm-name-data /media/f fuse nofail 0 0"),
        [Unplain::IdTag]
    );
    for line in [
        "sshfs#op@host:/ /mnt fuse defaults 0 0",
        "sshfs /mnt fuse defaults 0 0",
        "op@host:/ /mnt fuse.sshfs defaults 0 0",
        "mybucket /mnt/s3 fuse.s3fs _netdev 0 0",
        "mybucket:/a /mnt/s3 fuse.goofys _netdev 0 0",
        "mybucket /mnt/g fuse.gcsfuse _netdev 0 0",
        "none /mnt/ceph fuse.ceph ceph.id=admin,_netdev 0 0",
        ".host:/ /mnt/hgfs fuse.vmhgfs-fuse defaults 0 0",
        "remote:path /mnt/r fuse.rclone nofail 0 0",
        "remote: /mnt/r fuse.rclone nofail 0 0",
    ] {
        assert_eq!(why(line), [], "{line}");
    }
    // mount.fuse3 reads the # of a `fuse3` line as of a `fuse` one, and a
    // program may read the # of a `fuse.<program>` line in its own way: a #
    // in the first field of a line of a type that begins with `fuse`, other
    // than `fuse`, is not plain.
    for line in [
        "/srv/x/a#/tmp /media/b fuse.bindfs nofail 0 0",
        "/srv/a#/srv/x /media/b fuse.bindfs nofail 0 0",
        "/usr/bin/fuse2fs#/srv/x/disk.img /media/i fuse3 nofail 0 0",
        "ntfs-3g#/dev/sdb1 /media/n fuseblk nofail 0 0",
        "op@host:/a#b /mnt fuse.sshfs defaults 0 0",
    ] {
        assert_eq!(why(line), [Unplain::FuseHash], "{line}");
    }
}

#[test]
fn an_id_tag_is_not_plain() {
    // libmount looks an ID= tag up in /dev/disk/by-id, which NAILS does
    // not, and systemd's fstab generator leaves it to mount.
    for line in [
        "ID=dm-name-data /media/x ext4 nofail,x-systemd.automount 0 0",
        "ID=dm-name-vg-home /home ext4 defaults 0 2",
        "ID=usb-x /srv/b none bind 0 0",
        "ID=dm-name-data none swap sw 0 0",
    ] {
        assert_eq!(why(line), [Unplain::IdTag], "{line}");
    }
    // A line whose type names no local path by its first field names no
    // device by such a tag either.
    assert_eq!(why("ID=x /mnt/t tmpfs defaults 0 0"), []);
}

#[test]
fn a_character_other_than_a_space_or_a_tab_is_not_plain() {
    // NAILS's parser splits a line at any white space, libmount at spaces
    // and tabs alone, and libmount reads a line only up to a NUL byte.
    for (line, c) in [
        ("/srv/x /m\u{a0}nt none bind 0 0", '\u{a0}'),
        ("LABEL=My\u{a0}Data /media/x ext4 defaults 0 0", '\u{a0}'),
        ("/srv/x\u{b}/mnt none bind 0 0", '\u{b}'),
        ("/srv/x /mnt none bind\u{0}x 0 0", '\u{0}'),
        ("/srv/x /mnt\u{2028}none bind 0 0", '\u{2028}'),
        ("/srv/x /mnt none bind\r,ro 0 0", '\r'),
    ] {
        assert_eq!(why(line), [Unplain::Character(c)], "{line:?}");
    }
    // A tab between the fields is plain, and so is a line that ends in CR LF.
    assert_eq!(why("/srv/x\t/mnt\tnone\tbind\t0\t0"), []);
    let (_, unplain) = read_fstab("/srv/x /mnt none bind 0 0\r\n");
    assert!(unplain.is_empty());
}

#[test]
fn a_line_that_is_not_plain_is_kept_by_the_index_of_its_entry() {
    // Comments, blank lines and lines of one field hold no entry. The line
    // shows its first three fields as written, never its options, and names
    // every reason.
    let text = "# comment\n\n/dev/sda1 / ext4 defaults 0 1\nlonely\n\
                dev/mapper/data /media/x ext4,xfs nofail 0 0\n\
                //server/share /mnt/s cifs user=DOMAIN\\op,password=secret 0 0\n\
                /srv/x /m\u{a0}nt none bind 0 0\n";
    let (entries, unplain) = read_fstab(text);
    assert_eq!(entries.len(), 4);
    assert_eq!(unplain.keys().copied().collect::<Vec<_>>(), [1, 2, 3]);
    assert_eq!(unplain[&1].shown, "dev/mapper/data /media/x ext4,xfs");
    assert_eq!(
        unplain[&1].reason(),
        "its type is a list of types and its first field is neither an absolute path nor a \
         UUID=, LABEL=, PARTUUID= or PARTLABEL= tag"
    );
    assert_eq!(unplain[&2].shown, "//server/share /mnt/s cifs");
    assert_eq!(unplain[&2].reason(), "its options hold a backslash");
    assert_eq!(unplain[&3].shown, "/srv/x /mU+00A0nt none");
    assert_eq!(
        unplain[&3].reason(),
        "it holds the character U+00A0, which is neither a space nor a tab"
    );
    let three = UnplainLine {
        shown: String::new(),
        why: vec![
            escape("first field", "\\170"),
            Unplain::TypeBackslash,
            Unplain::OptionsBackslash,
        ],
    };
    assert_eq!(
        three.reason(),
        "its first field holds \\170, which is no escape of a space, a tab, a newline or a \
         backslash, its type holds a backslash and its options hold a backslash"
    );
    // The entries are those parse_fstab reads.
    assert_eq!(entries, crate::fstab::parse_fstab(text));
}

#[test]
fn a_line_that_starts_with_other_white_space_before_a_hash_is_read() {
    // libmount skips only spaces and tabs before a #: systemd 260's fstab
    // generator wrote a mount unit for each of these, so they are lines,
    // and not plain.
    for (line, c, shown) in [
        (
            "\u{b}#/srv/x /mnt3 none bind 0 0",
            '\u{b}',
            "U+000B#/srv/x /mnt3 none",
        ),
        (
            "\u{a0}#/srv/x /mnt3 none bind 0 0",
            '\u{a0}',
            "U+00A0#/srv/x /mnt3 none",
        ),
        (
            "\u{c}#/srv/x /mnt5 none bind 0 0",
            '\u{c}',
            "U+000C#/srv/x /mnt5 none",
        ),
    ] {
        let (entries, unplain) = read_fstab(&format!("{line}\n"));
        assert_eq!(entries.len(), 1, "{line:?}");
        assert_eq!(unplain[&0].why, [Unplain::Character(c)], "{line:?}");
        assert_eq!(unplain[&0].shown, shown, "{line:?}");
    }
    // Spaces and tabs before a # make a comment, as they do to libmount.
    let (entries, _) = read_fstab(" \t#/srv/x /mnt3 none bind 0 0\n");
    assert!(entries.is_empty());
}

/// Why the one line of `line`, as crypttab text, is not plain.
fn why_crypttab(line: &str) -> Vec<Unplain> {
    let (entries, unplain) = read_crypttab(&format!("{line}\n"));
    assert_eq!(entries.len(), 1, "{line:?}");
    unplain
        .get(&0)
        .map(|line| line.why.clone())
        .unwrap_or_default()
}

#[test]
fn a_crypttab_line_with_a_quote_a_backslash_or_a_relative_source_is_not_plain() {
    // systemd's crypttab generator keeps quotes and backslashes and writes
    // them into the command that opens the volume, which reads them: it
    // opens /dev/sdb for '/dev/sdb'. It opens a relative source from /.
    for (line, why) in [
        (
            "vault2 '/dev/sdb' none luks,nofail",
            vec![Unplain::Quote, Unplain::RelativeSource],
        ),
        (
            "vault2 \"/dev/sdb\" none luks,nofail",
            vec![Unplain::Quote, Unplain::RelativeSource],
        ),
        ("'data' /dev/sdc none luks,nofail", vec![Unplain::Quote]),
        ("data /dev/sdc '/etc/key' luks", vec![Unplain::Quote]),
        ("data /dev/sdc none luks,x-a=\"b\"", vec![Unplain::Quote]),
        (
            "vault3 /dev/sd\\x62 none luks,nofail",
            vec![Unplain::Backslash],
        ),
        ("data UUID=\"0a1b\" none luks", vec![Unplain::Quote]),
        (
            "vr1 dev/sdb none luks,nofail",
            vec![Unplain::RelativeSource],
        ),
        (
            "vr2 ID=usb-x none luks,nofail",
            vec![Unplain::RelativeSource],
        ),
    ] {
        assert_eq!(why_crypttab(line), why, "{line}");
    }
    // systemd ends a line at a lone carriage return or a NUL, splits it at
    // a vertical tab but not at a no-break space, and looks for a # only
    // after spaces and tabs.
    for (line, c) in [
        (
            "vq5 /dev/sdc none luks,nofail\rvq6 /dev/sdb none luks,nofail",
            '\r',
        ),
        ("vq9 /dev/sdc none luks\0vq10 /dev/sdb none luks", '\0'),
        ("vq4\u{a0}x /dev/sdb none luks,nofail", '\u{a0}'),
        ("\u{a0}#vq7 /dev/sdb none luks,nofail", '\u{a0}'),
        ("\u{b}#vq8 /dev/sdb none luks,nofail", '\u{b}'),
        ("vq12\u{b}/dev/sdb none luks", '\u{b}'),
    ] {
        assert_eq!(why_crypttab(line), [Unplain::Character(c)], "{line:?}");
    }
    // Plain lines: a path, a tag NAILS resolves, a file, and a fifth field
    // systemd ignores.
    for line in [
        "data /dev/sdb none luks,nofail",
        "cryptroot UUID=0a1b none luks,discard",
        "swap PARTUUID=7f-02 /dev/urandom swap,cipher=aes-xts-plain64,size=512",
        "home LABEL=home /etc/keys/home.key luks",
        "box /home/alice/box.img none tcrypt",
        "data /dev/sdb",
        "data /dev/sdb none luks it's ignored",
    ] {
        assert_eq!(why_crypttab(line), [], "{line}");
    }
}

#[test]
fn a_crypttab_line_that_is_not_plain_shows_its_name_and_source() {
    // The name and the source as written, never the key or the options.
    let text = "# a comment\n\
                data /dev/sdb none luks\n\
                vault2 '/dev/sdb' /etc/keys/k luks,keyfile-offset=4\n\
                vq4\u{a0}x /dev/sdb none luks\n";
    let (entries, unplain) = read_crypttab(text);
    assert_eq!(entries.len(), 3);
    assert_eq!(unplain.keys().copied().collect::<Vec<_>>(), [1, 2]);
    assert_eq!(unplain[&1].shown, "vault2 '/dev/sdb'");
    assert_eq!(
        unplain[&1].reason(),
        "one of its fields holds a quote and its source is neither an absolute path nor a \
         UUID=, LABEL=, PARTUUID= or PARTLABEL= tag"
    );
    assert_eq!(unplain[&2].shown, "vq4U+00A0x /dev/sdb");
    // The entries are those parse_crypttab reads.
    assert_eq!(entries, crate::crypttab::parse_crypttab(text));
}
