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
                        PARTUUID=, PARTLABEL= or ID= tag";

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
    ] {
        assert!(own(line), "{line}");
    }
    for line in [
        "/data/\\170 /srv/again none bind 0 0",
        "/data/x /srv/again none bind,x-a=\\x2d 0 0",
        "/data/x /srv/again none,tmpfs bind 0 0",
    ] {
        assert!(!own(line), "{line}");
    }
}
