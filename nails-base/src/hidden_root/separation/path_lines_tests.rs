// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The fstab lines the claims place by a path, judged where the path leads
//! through its links: a bind line whose source leads into the volume mounts
//! it, a swap file is claimed where its links lead, and a line whose path
//! cannot be followed is an entry where that cannot be told.

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

#[test]
fn a_bind_line_whose_source_leads_into_the_volume_through_links_mounts_it() {
    // A link to the root's folder or to a folder inside it, written as an
    // absolute path or relative to the folder the link lies in, and a chain
    // of links: mount follows them, so the line binds the volume, or a
    // folder of it, at every boot, as its direct form does. The flag never
    // lets it be.
    let volume = "it mounts the volume at /mnt";
    let folder = "it mounts a folder of the volume at /mnt";
    for (links, line, why) in [
        (
            &[("/data/link", "/data/x")][..],
            "/data/link /mnt none bind 0 0",
            format!("its source leads to /data/x, so {volume}"),
        ),
        (
            &[("/data/link", "/data/x/sub")][..],
            "/data/link /srv/sub none bind 0 0",
            format!("its source leads to /data/x/sub, so {folder}"),
        ),
        (
            &[("/data/link", "x")][..],
            "/data/link/sub /srv/sub none bind 0 0",
            format!("its source leads to /data/x/sub, so {folder}"),
        ),
        (
            &[("/data/link", "../data/x")][..],
            "/data/link /mnt none bind 0 0",
            format!("its source leads to /data/x, so {volume}"),
        ),
        (
            &[
                ("/data/a", "/data/b"),
                ("/data/b", "link"),
                ("/data/link", "x"),
            ][..],
            "/data/a /mnt none bind 0 0",
            format!("its source leads to /data/x, so {volume}"),
        ),
        // A link above the root's folder, with the rest of the path in it.
        (
            &[("/srv/d", "/data")][..],
            "/srv/d/x /mnt none bind 0 0",
            format!("its source leads to /data/x, so {volume}"),
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
            [
                SLASH,
                (EntryKind::Blocking, shown.join(" ").as_str(), false)
            ],
            "{line}"
        );
        assert_eq!(judgement.entries[1].why, why, "{line}");
        assert_eq!(judgement.entries[1].system_folder, None, "{line}");
    }
}

#[test]
fn a_bind_line_whose_source_has_no_link_is_judged_as_it_reads() {
    // The source is the place it names: the root's folder mounts the volume,
    // a folder beside it or above it mounts none of it, and a link that
    // leads out of the root's folder takes the line out with it.
    let judgement = bind_of_a_folder("/data/x /mnt none bind 0 0\n").judge("/mnt");
    assert_eq!(judgement.entries[1].why, "it mounts the volume at /mnt");
    for world in [
        bind_of_a_folder("/data/y /srv/y none bind 0 0\n"),
        bind_of_a_folder("/data /srv/d none bind 0 0\n"),
        bind_of_a_folder("/data/x/link /srv/u none bind 0 0\n").link("/data/x/link", "/home/u"),
    ] {
        assert_eq!(entry_needs(&world.judge("/mnt")), [SLASH]);
    }
}

#[test]
fn a_line_whose_path_cannot_be_followed_is_an_entry_where_that_cannot_be_told() {
    // A bind line whose source leads through a link to nothing, and a swap
    // file whose path does: either may lead into the volume, which cannot
    // be told. Neither is a line the decoy's boot needs or its own.
    let judgement = bind_of_a_folder("/data/link /mnt none bind 0 0\n")
        .link("/data/link", "/data/nothing")
        .missing("/data/nothing")
        .judge("/mnt");
    assert_eq!(
        entry_needs(&judgement),
        [SLASH, (EntryKind::Untold, "/data/link /mnt none", false)]
    );
    assert_eq!(
        judgement.entries[1].why,
        "where its source leads cannot be told: the link /data/link leads to nothing"
    );
    assert_eq!(judgement.entries[1].system_folder, None);
    let judgement = bind_of_a_folder("/swapfile none swap sw 0 0\n")
        .link("/swapfile", "/swap/file")
        .missing("/swap")
        .judge("/mnt");
    assert_eq!(
        entry_needs(&judgement),
        [SLASH, (EntryKind::Untold, "/swapfile none swap", false)]
    );
    assert_eq!(
        judgement.entries[1].why,
        "where the file it names lies cannot be told: the link /swapfile leads to nothing"
    );
    // A source that is no absolute path.
    let judgement = bind_of_a_folder("none /srv/n none bind 0 0\n").judge("/mnt");
    assert_eq!(
        judgement.entries[1].why,
        "where its source leads cannot be told: it is no absolute path"
    );
}

#[test]
fn a_line_whose_path_cannot_be_followed_claims_the_filesystem_its_text_names() {
    // A volume on a drive of its own at /mnt: a bind line whose source, as
    // it reads, lies on it claims its filesystem as the decoy's, as the
    // direct form does, though its link leads to nothing.
    let judgement = external_veracrypt()
        .fstab(
            "/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home ext4 defaults 0 2\n\
             /mnt/link /srv/sub none bind,nofail 0 0\n",
        )
        .link("/mnt/link", "/mnt/nothing")
        .missing("/mnt/nothing")
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
}

#[test]
fn a_swap_file_is_claimed_where_its_links_lead() {
    // The decoy's swap file at /swapfile is a link onto the volume of a
    // drive of its own: swapon follows it, so the decoy swaps onto that
    // filesystem, which is then the decoy's own storage. Without the link
    // the file lies on the decoy's /, and the volume is separate.
    let fstab = "/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home ext4 defaults 0 2\n\
                 /swapfile none swap sw 0 0\n";
    let through_a_link = external_veracrypt()
        .fstab(fstab)
        .link("/swapfile", "/mnt/swap.img");
    assert_eq!(
        through_a_link.verdict("/mnt"),
        Verdict::OnDecoyFilesystem {
            how: Sharing::Filesystem,
            at: PathBuf::from("/mnt"),
            in_fstab: false,
        }
    );
    assert_eq!(
        through_a_link.claimed("/mnt").get("dm-9"),
        Some(&Claimed::Mount(PathBuf::from("/mnt")))
    );
    // It is no bind line, and no entry for the hidden drive.
    assert!(through_a_link.judge("/mnt").entries.is_empty());
    assert_eq!(
        external_veracrypt().fstab(fstab).verdict("/mnt"),
        Verdict::Separate
    );
}

#[test]
fn a_path_that_was_not_looked_up_cannot_be_told() {
    // The scene holds where each path the fstab names leads; one it does
    // not hold is no path that is known to lead anywhere.
    let mounts = parse_mountinfo("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n");
    let paths = FollowedPaths::new();
    let scene = Scene {
        mounts: &mounts,
        fstab: &[],
        crypttab: &[],
        devices: &DeviceMap::default(),
        unreadable: &[],
        paths: &paths,
    };
    assert_eq!(scene.followed("/srv/x"), Err(Unfollowed::NotLookedUp));
    assert_eq!(Unfollowed::NotLookedUp.reason(), "it was not looked up");
}
