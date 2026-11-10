// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The fstab lines the claims place by a path, judged by the path as it is
//! written, with no link in it followed: a bind line whose source lies in
//! the volume mounts it, and a line whose path cannot be told (a link in it,
//! one that is not absolute, a device node, a folder the boot mounts that is
//! not mounted now) is an entry where that cannot be told.

use super::*;

/// A bind of the folder `/data/x` of `/` at the root, with `lines` in the
/// fstab after the line for `/`.
fn bind_of_a_folder(lines: &str) -> World {
    plain_decoy("5 1 8:1 /data/x /mnt rw - ext4 /dev/sda1 rw\n")
        .fstab(&format!("/dev/sda1 / ext4 defaults 0 1\n{lines}"))
}

/// The line for `/`, which mounts the filesystem a bind of a folder of `/`
/// is part of and which the decoy's boot needs.
const SLASH: (EntryKind, &str, bool) = (EntryKind::Blocking, "/dev/sda1 / ext4", true);

/// The plain decoy's lines for `/` and `/home`, before `line`.
fn with_the_decoys_lines(line: &str) -> String {
    format!("/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home ext4 defaults 0 2\n{line}\n")
}

/// Why a line whose first field is no absolute path and no tag is not plain.
const RELATIVE: &str = "its first field is neither an absolute path nor a UUID=, LABEL=, PARTUUID=, PARTLABEL= or \
     ID= tag";

/// The one entry of `judgement`, an entry where that cannot be told, for the
/// line that reads `shown`: why it is one.
fn untold_why<'a>(judgement: &'a Judgement, shown: &str) -> &'a str {
    assert_eq!(
        entry_needs(judgement),
        [(EntryKind::Untold, shown, false)],
        "{judgement:?}"
    );
    assert_eq!(judgement.entries[0].system_folder, None);
    &judgement.entries[0].why
}

#[test]
fn a_bind_line_whose_source_has_a_link_in_it_cannot_be_told() {
    // A link to the root's folder or to a folder inside it, written as an
    // absolute path or relative to the folder the link lies in, a chain of
    // links, a link in a parent folder and one that leads to nothing: the
    // boot's mount follows each, NAILS reads none, so where the line binds
    // cannot be told. It is never the decoy's own line, so the flag never
    // lets it be, and it says which link the source holds.
    for (links, line, link) in [
        (
            &[("/data/link", "/data/x")][..],
            "/data/link /mnt none bind 0 0",
            "/data/link",
        ),
        (
            &[("/data/link", "x/sub")][..],
            "/data/link /srv/sub none bind 0 0",
            "/data/link",
        ),
        (
            &[("/data/a", "/data/b"), ("/data/b", "x")][..],
            "/data/a /mnt none bind 0 0",
            "/data/a",
        ),
        (
            &[("/srv/d", "/data")][..],
            "/srv/d/x /mnt none bind 0 0",
            "/srv/d",
        ),
        (
            &[("/data/link", "/data/nothing")][..],
            "/data/link /mnt none bind 0 0",
            "/data/link",
        ),
        (
            &[("/data/link", "/data/x")][..],
            "/data/link /mnt none rbind,noauto 0 0",
            "/data/link",
        ),
    ] {
        let world = links.iter().fold(
            bind_of_a_folder(&format!("{line}\n")),
            |world, (link, target)| world.link(link, target),
        );
        let judgement = world.judge("/mnt");
        let shown: Vec<&str> = line.split_whitespace().take(3).collect();
        assert_eq!(
            entry_needs(&judgement),
            [SLASH, (EntryKind::Untold, shown.join(" ").as_str(), false)],
            "{line}"
        );
        assert_eq!(
            judgement.entries[1].why,
            format!(
                "where its source lies cannot be told: {link} is a symbolic link, which NAILS \
                 does not follow"
            ),
            "{line}"
        );
        assert_eq!(judgement.entries[1].system_folder, None, "{line}");
    }
}

#[test]
fn a_bind_line_whose_source_has_no_link_is_judged_as_it_reads() {
    // The source is the place it names: the root's folder mounts the volume,
    // a folder inside it a folder of the volume, written with `.` or `..`
    // too, and a folder beside it or above it none of it.
    for (line, why) in [
        ("/data/x /mnt none bind 0 0", "it mounts the volume at /mnt"),
        (
            "/data/./y/../x/ /mnt none bind 0 0",
            "it mounts the volume at /mnt",
        ),
        (
            "/data/x/sub /srv/sub none bind 0 0",
            "it mounts a folder of the volume at /mnt",
        ),
    ] {
        let judgement = bind_of_a_folder(&format!("{line}\n")).judge("/mnt");
        assert_eq!(judgement.entries[1].kind, EntryKind::Blocking, "{line}");
        assert_eq!(judgement.entries[1].why, why, "{line}");
    }
    for line in ["/data/y /srv/y none bind 0 0", "/data /srv/d none bind 0 0"] {
        let world = bind_of_a_folder(&format!("{line}\n"));
        assert_eq!(entry_needs(&world.judge("/mnt")), [SLASH], "{line}");
    }
}

#[test]
fn a_bind_line_whose_source_as_written_lies_in_the_volume_stays_a_finding() {
    // A volume on a drive of its own at /mnt. A bind line whose source lies
    // in it, as written, mounts it at boot by that path, and a link there,
    // on the volume, is read by no one now: either way the line is a
    // finding, never one that a link leading out of the volume lets go.
    let line = "/mnt/data /srv/d none bind,nofail 0 0";
    let judgement = external_veracrypt()
        .fstab(&with_the_decoys_lines(line))
        .judge("/mnt");
    assert_eq!(
        entry_needs(&judgement),
        [(EntryKind::Blocking, "/mnt/data /srv/d none", false)]
    );
    assert_eq!(
        judgement.entries[0].why,
        "it mounts a folder of the volume at /mnt"
    );
    let judgement = external_veracrypt()
        .fstab(&with_the_decoys_lines(line))
        .link("/mnt/data", "/var/d")
        .judge("/mnt");
    assert_eq!(
        untold_why(&judgement, "/mnt/data /srv/d none"),
        "where its source lies cannot be told: /mnt/data is a symbolic link, which NAILS does \
         not follow"
    );
}

#[test]
fn a_swap_or_image_line_through_a_link_to_the_volumes_device_cannot_be_told() {
    // The volume is veracrypt1 (dm-9) on the external sdb, at /mnt. A line
    // whose path is a link to its device node mounts it, or swaps on it, at
    // boot, as the line that names the device does: that one is refused,
    // and the one through a link is an entry where that cannot be told,
    // a noauto one too.
    let direct = external_veracrypt()
        .fstab(&with_the_decoys_lines(
            "/dev/mapper/veracrypt1 none swap sw 0 0",
        ))
        .judge("/mnt");
    assert_eq!(
        entry_needs(&direct),
        [(
            EntryKind::Blocking,
            "/dev/mapper/veracrypt1 none swap",
            false
        )]
    );
    for (link, target, line, shown) in [
        (
            "/hidden.link",
            "/dev/mapper/veracrypt1",
            "/hidden.link /media/x ext4 defaults,nofail 0 2",
            "/hidden.link /media/x ext4",
        ),
        (
            "/hidden.link",
            "/dev/dm-9",
            "/hidden.link /media/x ext4 noauto 0 0",
            "/hidden.link /media/x ext4",
        ),
        (
            "/swap.link",
            "/dev/mapper/veracrypt1",
            "/swap.link none swap sw 0 0",
            "/swap.link none swap",
        ),
        (
            "/swap.link",
            "/dev/sdb",
            "/swap.link none swap sw 0 0",
            "/swap.link none swap",
        ),
    ] {
        let world = external_veracrypt()
            .fstab(&with_the_decoys_lines(line))
            .link(link, target);
        assert_eq!(
            untold_why(&world.judge("/mnt"), shown),
            format!(
                "where the file it names lies cannot be told: {link} is a symbolic link, which \
                 NAILS does not follow"
            ),
            "{line}"
        );
    }
}

#[test]
fn a_swap_or_image_line_whose_path_is_a_device_node_cannot_be_told() {
    // A device node outside /dev, with no link on the way: swapon and mount
    // use the device it is, which nothing tells from its path.
    for (line, shown) in [
        ("/srv/node none swap sw 0 0", "/srv/node none swap"),
        (
            "/srv/node /media/x ext4 defaults,nofail 0 2",
            "/srv/node /media/x ext4",
        ),
        (
            "/dev/../srv/node none swap sw 0 0",
            "/dev/../srv/node none swap",
        ),
    ] {
        let world = external_veracrypt()
            .fstab(&with_the_decoys_lines(line))
            .device_node("/srv/node");
        assert_eq!(
            untold_why(&world.judge("/mnt"), shown),
            "where the file it names lies cannot be told: /srv/node is a device node",
            "{line}"
        );
    }
}

#[test]
fn a_swap_image_or_bind_line_whose_path_is_not_absolute_is_not_plain() {
    // swapon and mount look such a path up from the folder they run in: a
    // line that is not plain, which NAILS does not read. A line whose type
    // names its source otherwise, as a ZFS dataset's does, has no path in
    // it.
    for (line, shown) in [
        ("swapfile none swap sw 0 0", "swapfile none swap"),
        (
            "srv/img.raw /mnt/img ext4 loop 0 0",
            "srv/img.raw /mnt/img ext4",
        ),
        (
            "srv/img.raw /mnt/img ext4 defaults 0 0",
            "srv/img.raw /mnt/img ext4",
        ),
        ("srv/x /srv/b none bind 0 0", "srv/x /srv/b none"),
        ("srv/x /srv/b tmpfs bind 0 0", "srv/x /srv/b tmpfs"),
    ] {
        let world = external_veracrypt().fstab(&with_the_decoys_lines(line));
        assert_eq!(
            untold_why(&world.judge("/mnt"), shown),
            format!("NAILS reads only plain lines, and {RELATIVE}"),
            "{line}"
        );
    }
    let world =
        external_veracrypt().fstab(&with_the_decoys_lines("rpool/data /data zfs defaults 0 0"));
    assert!(world.judge("/mnt").entries.is_empty());
}

#[test]
fn a_path_through_a_folder_of_a_line_that_is_not_mounted_cannot_be_told() {
    // The root /mnt is a bind of /data/x of /. The fstab mounts sdc1 at
    // /backup, which is not mounted now: what /backup/link is once systemd
    // mounts it, a link to /data/x say, cannot be read now. So for a line
    // the boot mounts, one that only an automount mounts, and a noauto one,
    // which systemd mounts for the bind line's source below it (N1 to N3 of
    // the verify).
    for options in ["noauto", "defaults,nofail", "noauto,x-systemd.automount"] {
        let fstab = format!(
            "/dev/sda1 / ext4 defaults 0 1\n/dev/sdc1 /backup ext4 {options} 0 2\n\
             /backup/link /mnt none bind 0 0\n"
        );
        let unmounted = plain_decoy("5 1 8:1 /data/x /mnt rw - ext4 /dev/sda1 rw\n")
            .disk("sdc", "8:32")
            .part("sdc1", "8:33", "sdc")
            .fstab(&fstab)
            .missing("/backup/link");
        let judgement = unmounted.judge("/mnt");
        assert_eq!(
            entry_needs(&judgement),
            [SLASH, (EntryKind::Untold, "/backup/link /mnt none", false)],
            "{options}"
        );
        assert_eq!(
            judgement.entries[1].why,
            "where its source lies cannot be told: a line of /etc/fstab mounts /backup, and \
             that mount is not there now",
            "{options}"
        );
        // Mounted from sdc1, the place is read there: a link is one, and a
        // folder of that drive is judged as it reads.
        let mounted = |world: World| {
            world
                .disk("sdc", "8:32")
                .part("sdc1", "8:33", "sdc")
                .fstab(&fstab)
        };
        let table = "5 1 8:1 /data/x /mnt rw - ext4 /dev/sda1 rw\n\
                     7 1 8:33 / /backup rw - ext4 /dev/sdc1 rw\n";
        let judgement = mounted(plain_decoy(table))
            .link("/backup/link", "/data/x")
            .judge("/mnt");
        assert_eq!(
            judgement.entries[1].why,
            "where its source lies cannot be told: /backup/link is a symbolic link, which \
             NAILS does not follow",
            "{options}"
        );
        assert_eq!(
            entry_needs(&mounted(plain_decoy(table)).judge("/mnt")),
            [SLASH],
            "{options}"
        );
        // Something else mounted there, by hand, is no mount of that line.
        let by_hand = "5 1 8:1 /data/x /mnt rw - ext4 /dev/sda1 rw\n\
                       7 1 8:2 / /backup rw - ext4 /dev/sda2 rw\n";
        let judgement = mounted(plain_decoy(by_hand)).judge("/mnt");
        assert_eq!(judgement.entries[1].kind, EntryKind::Untold, "{options}");
    }
}

#[test]
fn a_bind_line_is_judged_by_its_source_whatever_its_type_or_netdev_says() {
    // mount binds whatever type a bind line gives, and `_netdev` only has
    // systemd mount it after the network: each of these binds the root's
    // folder at every boot, as the plain line does (T1 to T4 of the verify).
    for line in [
        "/data/x /mnt none bind 0 0",
        "/data/x /mnt tmpfs bind 0 0",
        "/data/x /mnt none bind,_netdev 0 0",
        "/data/x /mnt nfs bind 0 0",
        "/data/x /mnt overlay bind 0 0",
        "/data/x /mnt 9p rbind 0 0",
        "/data/x /mnt virtiofs bind,_netdev 0 0",
    ] {
        let judgement = bind_of_a_folder(&format!("{line}\n")).judge("/mnt");
        let shown: Vec<&str> = line.split_whitespace().take(3).collect();
        assert_eq!(
            entry_needs(&judgement),
            [
                SLASH,
                (EntryKind::Blocking, shown.join(" ").as_str(), false)
            ],
            "{line}"
        );
        assert_eq!(
            judgement.entries[1].why, "it mounts the volume at /mnt",
            "{line}"
        );
        assert_eq!(judgement.entries[1].system_folder, None, "{line}");
    }
    // From a volume of its own, X3, X4 and the _netdev bind of the verify.
    for line in [
        "/mnt/data /srv/d 9p bind,nofail 0 0",
        "/mnt/data /srv/d overlay bind,nofail 0 0",
        "/mnt/data /srv/d none bind,_netdev,nofail 0 0",
        "/mnt/data /srv/d tmpfs bind,nofail 0 0",
    ] {
        let judgement = external_veracrypt()
            .fstab(&with_the_decoys_lines(line))
            .judge("/mnt");
        let shown: Vec<&str> = line.split_whitespace().take(3).collect();
        assert_eq!(
            entry_needs(&judgement),
            [(EntryKind::Blocking, shown.join(" ").as_str(), false)],
            "{line}"
        );
        assert_eq!(
            judgement.entries[0].why, "it mounts a folder of the volume at /mnt",
            "{line}"
        );
    }
    // A RAM or network line that binds nothing names no storage: its first
    // field is no path of this computer's, even the volume's device.
    for line in [
        "tmpfs /mnt/t tmpfs defaults 0 0",
        "server:/x /net nfs _netdev 0 0",
        "/dev/mapper/veracrypt1 /net nfs defaults 0 0",
        "/dev/mapper/veracrypt1 /mnt/t tmpfs defaults 0 0",
    ] {
        let world = external_veracrypt().fstab(&with_the_decoys_lines(line));
        assert_eq!(entry_needs(&world.judge("/mnt")), [], "{line}");
    }
}

#[test]
fn netdev_lets_no_line_for_the_volumes_device_go() {
    // X1 and X2 of the verify: a device or swap line for the volume's own
    // mapping with `_netdev` mounts it, or swaps on it, after the network, as
    // the line without it does at boot.
    for (line, shown) in [
        (
            "/dev/mapper/veracrypt1 /media/x ext4 defaults,_netdev,nofail 0 0",
            "/dev/mapper/veracrypt1 /media/x ext4",
        ),
        (
            "/dev/mapper/veracrypt1 none swap sw,_netdev 0 0",
            "/dev/mapper/veracrypt1 none swap",
        ),
    ] {
        let world = external_veracrypt().fstab(&with_the_decoys_lines(line));
        let judgement = world.judge("/mnt");
        assert_eq!(
            entry_needs(&judgement),
            [(EntryKind::Blocking, shown, false)],
            "{line}"
        );
        assert_eq!(
            judgement.entries[0].why, "it mounts the volume at /mnt",
            "{line}"
        );
    }
    let world = external_veracrypt().fstab(&with_the_decoys_lines(
        "/dev/mapper/veracrypt1 /media/x ext4 defaults,_netdev,nofail 0 0",
    ));
    assert_eq!(
        world.verdict("/mnt"),
        Verdict::OnDecoyFilesystem {
            how: Sharing::Filesystem,
            at: PathBuf::from("/media/x"),
            in_fstab: true,
        }
    );
}

#[test]
fn a_swap_or_image_file_in_the_volume_is_a_finding() {
    // The root /mnt is a bind of /data/x of /. A swap file or an image file
    // in that folder lies in the volume, which the boot swaps on or mounts,
    // as a bind line from there mounts it (F1 to F3 of the verify).
    for line in [
        "/data/x/swapfile none swap sw 0 0",
        "/data/x/disk.img /media/i ext4 loop,nofail 0 0",
        "/data/x/disk.img /media/i ext4 nofail 0 0",
        "/data/x/sub/../swapfile none swap sw,noauto 0 0",
        "/data/x /media/i ext4 loop 0 0",
    ] {
        let judgement = bind_of_a_folder(&format!("{line}\n")).judge("/mnt");
        let shown: Vec<&str> = line.split_whitespace().take(3).collect();
        assert_eq!(
            entry_needs(&judgement),
            [
                SLASH,
                (EntryKind::Blocking, shown.join(" ").as_str(), false)
            ],
            "{line}"
        );
        assert_eq!(
            judgement.entries[1].why, "the file it names lies in the volume at /mnt",
            "{line}"
        );
        assert_eq!(judgement.entries[1].system_folder, None, "{line}");
    }
    // An image the boot mounts at a system folder is one its boot needs.
    let judgement = bind_of_a_folder("/data/x/srv.img /srv ext4 loop 0 0\n").judge("/mnt");
    assert_eq!(
        entry_needs(&judgement),
        [
            SLASH,
            (EntryKind::Blocking, "/data/x/srv.img /srv ext4", true)
        ]
    );
    // A swap file in a volume of its own (R10 of the verify).
    let judgement = external_veracrypt()
        .fstab(&with_the_decoys_lines("/mnt/swapfile none swap sw 0 0"))
        .judge("/mnt");
    assert_eq!(
        entry_needs(&judgement),
        [(EntryKind::Blocking, "/mnt/swapfile none swap", false)]
    );
    assert_eq!(
        judgement.entries[0].why,
        "the file it names lies in the volume at /mnt"
    );
    // A file beside the root's folder, or above it, lies outside the volume.
    for line in [
        "/data/y/swapfile none swap sw 0 0",
        "/data/swapfile none swap sw 0 0",
        "/data/xy.img /media/i ext4 loop 0 0",
    ] {
        let judgement = bind_of_a_folder(&format!("{line}\n")).judge("/mnt");
        assert_eq!(entry_needs(&judgement), [SLASH], "{line}");
    }
}

#[test]
fn a_line_whose_path_cannot_be_told_claims_the_filesystem_its_text_names() {
    // A volume on a drive of its own at /mnt: a bind line whose source, as
    // it reads, lies on it claims its filesystem as the decoy's, as the
    // direct form does, though it holds a link.
    let judgement = external_veracrypt()
        .fstab(&with_the_decoys_lines(
            "/mnt/link /srv/sub none bind,nofail 0 0",
        ))
        .link("/mnt/link", "/mnt/sub")
        .judge("/mnt");
    assert!(
        matches!(judgement.verdict, Verdict::OnDecoyFilesystem { .. }),
        "{:?}",
        judgement.verdict
    );
    assert_eq!(
        entry_needs(&judgement),
        [(EntryKind::Untold, "/mnt/link /srv/sub none", false)]
    );
    // A swap file through a link onto the volume is claimed where its text
    // places it, on the decoy's /: the volume stays separate, and the line
    // is an entry where that cannot be told.
    let through_a_link = external_veracrypt()
        .fstab(&with_the_decoys_lines("/swapfile none swap sw 0 0"))
        .link("/swapfile", "/mnt/swap.img");
    assert_eq!(through_a_link.verdict("/mnt"), Verdict::Separate);
    assert_eq!(
        entry_needs(&through_a_link.judge("/mnt")),
        [(EntryKind::Untold, "/swapfile none swap", false)]
    );
}

#[test]
fn a_path_that_was_not_looked_up_cannot_be_told() {
    // The scene holds each path the fstab names as it reads; one it does not
    // hold is no path that is known to lie anywhere.
    let mounts = parse_mountinfo("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n");
    let paths = NamedPaths::new();
    let scene = Scene {
        mounts: &mounts,
        fstab: &[],
        crypttab: &[],
        devices: &DeviceMap::default(),
        unreadable: &[],
        paths: &paths,
        unplain: &UnplainLines::new(),
    };
    assert_eq!(scene.named_path("/srv/x"), Err(UntoldPath::NotLookedUp));
}
