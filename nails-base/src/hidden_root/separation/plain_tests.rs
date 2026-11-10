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
        "ID=dm-name-vg-home /home ext4 defaults 0 2",
        "/dev/mapper/vg-root / ext4 defaults 0 1",
        "/dev/disk/by-id/virtio-extra /srv/data ext4 defaults 0 2",
        "/swapfile none swap sw 0 0",
        "/srv/x /mnt none bind 0 0",
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
        "fuse",
        "fuse.rclone",
        "fuse.sshfs",
        "selinuxfs",
        "xenfs",
        "none",
    ] {
        let line = format!("source /srv/x {vfstype} defaults 0 0");
        assert_eq!(why(&line), [], "{line}");
        assert!(names_no_local_path(vfstype), "{vfstype}");
    }
    for vfstype in [
        "ext4", "swap", "auto", "fuseblk", "ntfs-3g", "squashfs", "bcachefs",
    ] {
        assert!(!names_no_local_path(vfstype), "{vfstype}");
    }
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
         UUID=, LABEL=, PARTUUID=, PARTLABEL= or ID= tag"
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
