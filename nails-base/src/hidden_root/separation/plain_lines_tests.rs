// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Lines of the decoy's fstab that are not plain, judged: each is an entry
//! where that cannot be told, the only one it makes, whatever it names, and
//! never the decoy's own line. It claims what NAILS reads in it, and makes no
//! mount of the decoy's own.

use super::*;

/// A bind of the folder `/data/x` of `/` at the root, with `line` in the
/// fstab after the line for `/`.
fn bind_of_a_folder(line: &str) -> World {
    plain_decoy("5 1 8:1 /data/x /mnt rw - ext4 /dev/sda1 rw\n")
        .fstab(&format!("/dev/sda1 / ext4 defaults 0 1\n{line}\n"))
}

/// The line for `/` below a bind of a folder of `/`.
const SLASH: (EntryKind, &str, bool) = (EntryKind::Blocking, "/dev/sda1 / ext4", true);

/// Why a line whose first field is no absolute path and no tag is not plain.
const RELATIVE: &str = "its first field is neither an absolute path nor a UUID=, LABEL=, \
                        PARTUUID= or PARTLABEL= tag";

/// That `entry` is the finding for a line that is not plain, which shows as
/// `shown`, for `reason`.
fn assert_not_plain(entry: &EntryFinding, shown: &str, reason: &str) {
    assert_eq!(entry.kind, EntryKind::Untold, "{entry:?}");
    assert_eq!(entry.file, FSTAB);
    assert_eq!(entry.line, shown);
    assert_eq!(
        entry.why,
        format!("NAILS reads only plain lines, and {reason}")
    );
    assert!(!entry.boot_needs, "{entry:?}");
    assert_eq!(entry.system_folder, None);
    assert!(entry.not_plain, "{entry:?}");
}

#[test]
fn an_escaped_option_or_source_of_a_bind_line_is_not_plain() {
    // libmount reads `bin\144` as `bind` and `\162bind` as `rbind` (E1 and E2
    // of the verify), and `/data/\170` as `/data/x`: each binds the root's
    // folder at boot, whatever its type. NAILS reads no such line, and says
    // so, as the line is written.
    for (line, shown, reason) in [
        (
            "/data/x /mnt none bin\\144 0 0",
            "/data/x /mnt none",
            "its options hold a backslash",
        ),
        (
            "/data/x /mnt none \\162bind 0 0",
            "/data/x /mnt none",
            "its options hold a backslash",
        ),
        (
            "/data/x /mnt tmpfs bin\\144,nofail 0 0",
            "/data/x /mnt tmpfs",
            "its options hold a backslash",
        ),
        (
            "/data/\\170 /mnt none bind 0 0",
            "/data/\\170 /mnt none",
            "its first field holds \\170, which is no escape of a space, a tab, a newline or a \
             backslash",
        ),
    ] {
        let judgement = bind_of_a_folder(line).judge("/mnt");
        assert_eq!(
            entry_needs(&judgement),
            [SLASH, (EntryKind::Untold, shown, false)],
            "{line}"
        );
        assert_not_plain(&judgement.entries[1], shown, reason);
    }
    // The same lines written plainly bind the volume.
    for line in ["/data/x /mnt none bind 0 0", "/data/x /mnt none rbind 0 0"] {
        let judgement = bind_of_a_folder(line).judge("/mnt");
        assert_eq!(judgement.entries[1].why, "it mounts the volume at /mnt");
    }
}

#[test]
fn a_relative_device_a_list_of_types_or_an_escaped_type_is_not_plain() {
    // The volume is veracrypt1 (dm-9) on the external sdb, at /mnt. libmount
    // looks a relative first field up from /, where systemd runs mount, so
    // each of these mounts or swaps on the volume (R1 to R4 and X5 of the
    // verify).
    for (line, shown, reason) in [
        (
            "dev/mapper/veracrypt1 /media/x ext4 nofail 0 0",
            "dev/mapper/veracrypt1 /media/x ext4",
            RELATIVE.to_string(),
        ),
        (
            "dev/mapper/veracrypt1 /media/x ntfs-3g nofail,x-systemd.automount 0 0",
            "dev/mapper/veracrypt1 /media/x ntfs-3g",
            RELATIVE.to_string(),
        ),
        (
            "dev/mapper/veracrypt1 /media/x ext4,xfs nofail 0 0",
            "dev/mapper/veracrypt1 /media/x ext4,xfs",
            format!("its type is a list of types and {RELATIVE}"),
        ),
        (
            "dev/dm-9 /media/x cramfs nofail 0 0",
            "dev/dm-9 /media/x cramfs",
            RELATIVE.to_string(),
        ),
        (
            "dev/mapper/veracrypt1 none swap sw 0 0",
            "dev/mapper/veracrypt1 none swap",
            RELATIVE.to_string(),
        ),
        (
            "/dev/mapper/veracrypt1 /media/x ext\\064 nofail 0 0",
            "/dev/mapper/veracrypt1 /media/x ext\\064",
            "its type holds a backslash".to_string(),
        ),
        (
            "/dev/mapper/veracrypt1 /media/x ext4,xfs nofail 0 0",
            "/dev/mapper/veracrypt1 /media/x ext4,xfs",
            "its type is a list of types".to_string(),
        ),
        (
            "/dev/mapper/veracrypt1 /media/x ext4 nofail,x-systemd.after=a\\x2db.service 0 0",
            "/dev/mapper/veracrypt1 /media/x ext4",
            "its options hold a backslash".to_string(),
        ),
    ] {
        let world = external_veracrypt().fstab(&with_the_decoys_lines(line));
        let judgement = world.judge("/mnt");
        assert_eq!(
            entry_needs(&judgement),
            [(EntryKind::Untold, shown, false)],
            "{line}"
        );
        assert_not_plain(&judgement.entries[0], shown, &reason);
    }
}

/// The plain decoy's lines for `/` and `/home`, before `line`.
fn with_the_decoys_lines(line: &str) -> String {
    format!("/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home ext4 defaults 0 2\n{line}\n")
}

#[test]
fn a_line_that_is_not_plain_claims_what_nails_reads_in_it() {
    // NAILS reads the volume's mapping in this line, which the decoy then
    // mounts at /media/x: the volume is the decoy's filesystem there, as
    // with the plain line, though the line's only finding is that it is not
    // plain.
    for line in [
        "/dev/mapper/veracrypt1 /media/x ext4 nofail 0 0",
        "/dev/mapper/veracrypt1 /media/x ext\\064 nofail 0 0",
    ] {
        let world = external_veracrypt().fstab(&with_the_decoys_lines(line));
        assert_eq!(
            world.verdict("/mnt"),
            Verdict::OnDecoyFilesystem {
                how: Sharing::Filesystem,
                at: PathBuf::from("/media/x"),
                in_fstab: true,
            },
            "{line}"
        );
        assert!(world.claimed("/mnt").contains_key("dm-9"), "{line}");
    }
}

#[test]
fn a_line_that_is_not_plain_is_never_the_decoys_own() {
    // The decoy's line for / below a bind of a folder of /, written with an
    // escape: the flag never lets it be.
    let world = plain_decoy("5 1 8:1 /data/x /mnt rw - ext4 /dev/sda1 rw\n")
        .fstab("/dev/sd\\141\\061 / ext4 defaults 0 1\n");
    let judgement = world.judge("/mnt");
    assert_eq!(judgement.entries.len(), 1, "{judgement:?}");
    assert_not_plain(
        &judgement.entries[0],
        "/dev/sd\\141\\061 / ext4",
        "its first field holds \\141, which is no escape of a space, a tab, a newline or a \
         backslash",
    );
    // A bind of the root's folder at /srv/again that a plain bind line makes
    // is the decoy's own mount, of any type, `_netdev` or not; one whose
    // line is not plain is none.
    let table = "5 1 8:1 /data/x /mnt rw - ext4 /dev/sda1 rw\n\
                 6 1 8:1 /data/x /srv/again rw - ext4 /dev/sda1 rw\n";
    let own = |line: &str| {
        plain_decoy(table)
            .fstab(&format!("/dev/sda1 / ext4 defaults 0 1\n{line}\n"))
            .ask("/mnt", |scene, hidden| {
                let again = top_mount_at(scene.mounts, Path::new("/srv/again")).unwrap();
                decoys_own_mount(scene, again, hidden)
            })
    };
    for line in [
        "/data/x /srv/again none bind 0 0",
        "/data/x /srv/again tmpfs bind 0 0",
        "/data/x /srv/again none bind,_netdev 0 0",
        "/data/x /srv/again tmpfs bind=x 0 0",
        "/data/x /srv/again none rbind= 0 0",
    ] {
        assert!(own(line), "{line}");
    }
    for line in [
        "/data/\\170 /srv/again none bind 0 0",
        "/data/x /srv/again none bind,x-a=\\x2d 0 0",
        "/data/x /srv/again none,tmpfs bind 0 0",
        "data/x /srv/again none bind=x 0 0",
        "\u{b}/data/x /srv/again none bind 0 0",
    ] {
        assert!(!own(line), "{line}");
    }
}

#[test]
fn a_fuse_line_is_judged_by_the_source_it_gives_its_program() {
    // The program a `fuse` line names before its # gets the root's folder,
    // or an image file in it, and so does a `fuse.<program>` line's: each is
    // a finding, never the decoy's own line.
    for line in [
        "bindfs#/data/x /media/b fuse nofail 0 0",
        "fuse2fs#/data/x/disk.img /media/i fuse nofail 0 0",
        "/data/x /media/b fuse.bindfs nofail 0 0",
        "/data/x/sub /media/b fuse.bindfs nofail 0 0",
    ] {
        let judgement = bind_of_a_folder(line).judge("/mnt");
        let shown: Vec<&str> = line.split_whitespace().take(3).collect();
        let shown = shown.join(" ");
        assert_eq!(
            entry_needs(&judgement),
            [SLASH, (EntryKind::Blocking, shown.as_str(), false)],
            "{line}"
        );
        assert_eq!(
            judgement.entries[1].why, "the file it names lies in the volume at /mnt",
            "{line}"
        );
        assert_eq!(judgement.entries[1].system_folder, None, "{line}");
    }
    // A relative source, or none, is not plain.
    for (line, shown, reason) in [
        (
            "data/x /media/b fuse.bindfs nofail 0 0",
            "data/x /media/b fuse.bindfs",
            Unplain::FuseSource,
        ),
        (
            "bindfs#data/x /media/b fuse nofail 0 0",
            "bindfs#data/x /media/b fuse",
            Unplain::FuseSource,
        ),
        (
            "bindfs /media/b fuse nofail 0 0",
            "bindfs /media/b fuse",
            Unplain::FuseNoSource,
        ),
        (
            "/data/x/a#/tmp /media/b fuse.bindfs nofail 0 0",
            "/data/x/a#/tmp /media/b fuse.bindfs",
            Unplain::FuseHash,
        ),
    ] {
        let judgement = bind_of_a_folder(line).judge("/mnt");
        assert_eq!(
            entry_needs(&judgement),
            [SLASH, (EntryKind::Untold, shown, false)],
            "{line}"
        );
        assert_not_plain(&judgement.entries[1], shown, &reason.reason());
    }
    // The volume's mapping, by its path or its node, mounts the volume
    // through the program.
    for line in [
        "fuse2fs#/dev/mapper/veracrypt1 /media/f fuse nofail 0 0",
        "fuse2fs#/dev/dm-9 /media/f fuse nofail 0 0",
    ] {
        let world = external_veracrypt().fstab(&with_the_decoys_lines(line));
        let judgement = world.judge("/mnt");
        let shown: Vec<&str> = line.split_whitespace().take(3).collect();
        assert_eq!(
            entry_needs(&judgement),
            [(EntryKind::Blocking, shown.join(" ").as_str(), false)],
            "{line}"
        );
        assert_eq!(
            judgement.entries[0].why, "it mounts the volume at /mnt",
            "{line}"
        );
    }
    // A remote source, and a path beside the root's folder, name no part of
    // it.
    for line in [
        "sshfs#op@host:/ /media/s fuse nofail 0 0",
        "op@host:/ /media/s fuse.sshfs nofail 0 0",
        "remote:path /media/r fuse.rclone nofail 0 0",
        "bindfs#/data/y /media/b fuse nofail 0 0",
        "/data/y /media/b fuse.bindfs nofail 0 0",
    ] {
        let judgement = bind_of_a_folder(line).judge("/mnt");
        assert_eq!(entry_needs(&judgement), [SLASH], "{line}");
    }
}

#[test]
fn a_fuse_line_makes_no_mount_of_the_decoys_own() {
    // The whole of / mounted again at /srv/again: a device line for it there
    // makes that mount, while a FUSE program makes a FUSE mount of its own,
    // never this one, whatever device it names.
    let table = "5 1 8:1 /data/x /mnt rw - ext4 /dev/sda1 rw\n\
                 6 1 8:1 / /srv/again rw - ext4 /dev/sda1 rw\n";
    let own = |line: &str| {
        plain_decoy(table)
            .fstab(&format!("/dev/sda1 / ext4 defaults 0 1\n{line}\n"))
            .ask("/mnt", |scene, hidden| {
                let again = top_mount_at(scene.mounts, Path::new("/srv/again")).unwrap();
                decoys_own_mount(scene, again, hidden)
            })
    };
    assert!(own("/dev/sda1 /srv/again ext4 defaults 0 0"));
    for line in [
        "/dev/sda1 /srv/again fuse.fuse2fs defaults 0 0",
        "fuse2fs#/dev/sda1 /srv/again fuse defaults 0 0",
    ] {
        assert!(!own(line), "{line}");
    }
}

/// Debian's encrypted ext4 root without LVM, with a bind of its folder
/// `/srv/x` at the root, and `crypttab` its crypttab.
fn encrypted_root(crypttab: &str) -> Judgement {
    World::new(
        "1 0 254:0 / / rw - ext4 /dev/mapper/cryptroot rw\n\
         5 1 254:0 /srv/x /mnt rw - ext4 /dev/mapper/cryptroot rw\n",
    )
    .disk("nvme0n1", "259:0")
    .part("nvme0n1p3", "259:3", "nvme0n1")
    .crypt("dm-0", "254:0", "cryptroot", &["nvme0n1p3"])
    .spec("UUID=e1", "nvme0n1p3")
    .fstab("/dev/mapper/cryptroot / ext4 defaults 0 1\n")
    .crypttab(crypttab)
    .judge("/mnt")
}

#[test]
fn a_crypttab_line_that_is_not_plain_is_its_only_finding() {
    // The volume is veracrypt1 (dm-9) on the external sdb. systemd opens
    // /dev/sdb for a source in quotes, and from / for a relative one: NAILS
    // reads no such line, and says so, never as the decoy's own line.
    for (crypttab, shown, reason) in [
        (
            "vault '/dev/sdb' none luks,nofail\n",
            "vault '/dev/sdb'",
            "one of its fields holds a quote and its source is neither an absolute path nor a \
             UUID=, LABEL=, PARTUUID= or PARTLABEL= tag",
        ),
        (
            "vault /dev/sd\\x62 none luks,nofail\n",
            "vault /dev/sd\\x62",
            "one of its fields holds a backslash",
        ),
        (
            "vault dev/sdb none luks,nofail\n",
            "vault dev/sdb",
            "its source is neither an absolute path nor a UUID=, LABEL=, PARTUUID= or PARTLABEL= \
             tag",
        ),
        (
            "'veracrypt1' /dev/sdc none luks,nofail\n",
            "'veracrypt1' /dev/sdc",
            "one of its fields holds a quote",
        ),
        (
            "\u{a0}#vq /dev/sdb none luks,nofail\n",
            "U+00A0#vq /dev/sdb",
            "it holds the character U+00A0, which is neither a space nor a tab",
        ),
    ] {
        let world = external_veracrypt().crypttab(crypttab);
        let judgement = world.judge("/mnt");
        assert_eq!(
            entry_needs(&judgement),
            [(EntryKind::Untold, shown, false)],
            "{crypttab:?}"
        );
        let entry = &judgement.entries[0];
        assert_eq!(entry.file, CRYPTTAB);
        assert_eq!(
            entry.why,
            format!("NAILS reads only plain lines, and {reason}"),
            "{crypttab:?}"
        );
        assert_eq!(entry.system_folder, None);
        assert!(entry.not_plain);
    }
    // The plain line opens the volume's drive.
    let world = external_veracrypt().crypttab("vault /dev/sdb none luks,nofail\n");
    assert_eq!(
        entry_needs(&world.judge("/mnt")),
        [(EntryKind::Blocking, "vault /dev/sdb", false)]
    );
    // The line that opens an encrypted decoy's root is its own line for /,
    // but written with quotes it is none, while its claim stays.
    let plain = encrypted_root("cryptroot UUID=e1 none luks\n");
    assert_eq!(
        plain.entries[1].system_folder.as_deref(),
        Some(Path::new("/"))
    );
    let quoted = encrypted_root("cryptroot UUID=\"e1\" none luks\n");
    assert_eq!(quoted.entries.len(), 2, "{quoted:?}");
    assert_eq!(quoted.entries[1].kind, EntryKind::Untold);
    assert_eq!(quoted.entries[1].line, "cryptroot UUID=\"e1\"");
    assert_eq!(quoted.entries[1].system_folder, None);
    assert_eq!(quoted.verdict, plain.verdict);
}
