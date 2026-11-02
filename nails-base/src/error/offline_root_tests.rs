// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::NailsError;
use std::path::PathBuf;

fn refused(problem: OfflineRootProblem) -> NailsError {
    NailsError::RefusedOfflineRoot {
        root: PathBuf::from("/mnt/decoy"),
        problem,
    }
}

fn subvolumes(names: &[&str]) -> OfflineRootProblem {
    OfflineRootProblem::NoEtcFolder {
        subvolumes: names.iter().map(|name| name.to_string()).collect(),
    }
}

#[test]
fn each_problem_says_what_is_wrong_with_the_root() {
    for (problem, says) in [
        (
            OfflineRootProblem::Missing,
            "does not exist, so there is nothing to scan",
        ),
        (
            OfflineRootProblem::NotAFolder,
            "is not a folder, so there is nothing to scan",
        ),
        (
            OfflineRootProblem::Empty,
            "is empty, so there is nothing to scan",
        ),
        (
            subvolumes(&[]),
            "holds no etc folder, so it is not the root of a decoy system",
        ),
        (
            subvolumes(&["@"]),
            "holds the btrfs subvolume @ but no etc folder, so it is not the root of a decoy \
             system",
        ),
        (
            subvolumes(&["@", "@home"]),
            "holds the btrfs subvolumes @ and @home but no etc folder, so it is not the root of \
             a decoy system",
        ),
    ] {
        assert_eq!(refused(problem).to_string(), format!("/mnt/decoy {says}"));
    }
}

#[test]
fn a_long_list_of_subvolumes_is_cut_short() {
    let names = |count: usize| (0..count).map(|n| format!("s{n}")).collect::<Vec<_>>();
    assert_eq!(listed(&names(3)), "s0, s1 and s2");
    assert_eq!(
        listed(&names(NAMES_SHOWN)),
        "s0, s1, s2, s3, s4, s5, s6 and s7"
    );
    assert_eq!(
        listed(&names(NAMES_SHOWN + 2)),
        "s0, s1, s2, s3, s4, s5, s6, s7 and 2 more"
    );
}

/// The lines of the next step every refusal gives, after the scan command.
const MOUNTS: [&str; 2] = [
    "A device that findmnt shows mounted already, as the decoy root is in a hidden session: mount \
     it again and make that mount read-only, `sudo mount <device> <mount> && sudo mount -o \
     remount,bind,ro <mount>` (where its filesystem is read-only already, `sudo mount -o ro \
     <device> <mount>`).",
    "Any other device, in a hidden session or not: make it read-only first (`sudo blockdev \
     --setro <device>`, and `--setrw` after the scan), then mount it with `-o ro,noload` for \
     ext4, `-o ro,rescue=nologreplay` for btrfs or `-o ro,norecovery` for XFS and f2fs: a plain \
     `-o ro` can replay a journal onto the disk.",
];

#[test]
fn the_next_step_mounts_without_writing_and_on_btrfs_names_the_subvolumes() {
    let first = "Mount the decoy's root filesystem on a folder so that nothing can write to it, \
                 and what its /etc/fstab mounts on the folders below it, then run `sudo ";
    let btrfs = "On btrfs the system is a subvolume: add `subvol=@` (Fedora: `subvol=root`) to \
                 its mount, and mount each subvolume its /etc/fstab mounts, such as @home, on its \
                 folder.";
    for (problem, lines) in [
        (OfflineRootProblem::Missing, 3),
        (OfflineRootProblem::NotAFolder, 3),
        (OfflineRootProblem::Empty, 3),
        (subvolumes(&[]), 4),
        (subvolumes(&["@", "@home"]), 4),
    ] {
        let hint = refused(problem).hint().expect("a next step");
        let hint: Vec<&str> = hint.lines().collect();
        assert_eq!(hint.len(), lines, "{hint:#?}");
        assert!(hint[0].starts_with(first), "{hint:#?}");
        assert!(
            hint[0].ends_with(" verify --offline --root <mount>`."),
            "{hint:#?}"
        );
        assert_eq!(hint[1..3], MOUNTS, "{hint:#?}");
        if lines == 4 {
            assert_eq!(hint[3], btrfs, "{hint:#?}");
        }
    }
}
