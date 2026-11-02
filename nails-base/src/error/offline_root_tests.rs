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

#[test]
fn the_next_step_says_what_to_mount_and_on_btrfs_which_subvolume() {
    let then_scan = "(`sudo mount -o ro <device> <mount>`), then run `sudo ";
    for problem in [
        OfflineRootProblem::Missing,
        OfflineRootProblem::NotAFolder,
        OfflineRootProblem::Empty,
    ] {
        let hint = refused(problem).hint().expect("a next step");
        assert!(
            hint.starts_with(&format!(
                "Mount the decoy image or partition read-only on a folder {then_scan}"
            )),
            "{hint}"
        );
        assert!(
            hint.ends_with(" verify --offline --root <mount>`."),
            "{hint}"
        );
    }
    let hint = refused(subvolumes(&["@", "@home"]))
        .hint()
        .expect("a next step");
    assert!(
        hint.starts_with(&format!(
            "Mount the decoy's root filesystem read-only on a folder {then_scan}"
        )),
        "{hint}"
    );
    assert!(
        hint.ends_with(
            " verify --offline --root <mount>`. On btrfs that root is a subvolume: give its \
             folder, such as /mnt/decoy/@ or /mnt/decoy/root."
        ),
        "{hint}"
    );
}
