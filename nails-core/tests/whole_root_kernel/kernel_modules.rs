// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `kernel-modules` row against the root overlay the entry mounts: what a
//! hidden session deletes through it is a whiteout the row names, the next
//! root lacks what the whiteout covers, and the `discard` the row names brings
//! the decoy's copy back.

use nails_core::next_step::{NextStep, sudo_line_for};
use nails_core::session::SessionView;
use nails_core::session::kernel_modules::{KernelModulesCheck, TrustedXattrs};
use nails_core::test_path;
use nails_core::test_support::{Rerun, ScratchTmpfs};
use nails_core::{Config, NailsManager, RealFilesystem};
use nails_teardown::whole_root::nextroot;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

const RELEASE: &str = "6.17.1-arch1-1";
const INDEX_TEXT: &str = "kernel/fs/ext4.ko:\n";
const INDEX_BINARY: &str = "binary index";

/// `usr/lib/modules/<release>` and its index, below a root.
fn tree() -> String {
    format!("usr/lib/modules/{RELEASE}")
}

fn index() -> String {
    format!("{}/modules.dep", tree())
}

/// The index's binary form, the one `modprobe` reads.
fn binary_index() -> String {
    format!("{}/modules.dep.bin", tree())
}

/// A decoy root with the running kernel's modules and both forms of their
/// index.
fn decoy() -> ScratchTmpfs {
    let decoy = ScratchTmpfs::new("");
    let fs = decoy.mkdir(&format!("{}/kernel/fs", tree()));
    std::fs::write(fs.join("ext4.ko"), "module").unwrap();
    std::fs::write(decoy.path().join(index()), INDEX_TEXT).unwrap();
    std::fs::write(decoy.path().join(binary_index()), INDEX_BINARY).unwrap();
    decoy
}

/// A hidden volume with the root overlay's upper and work directories.
fn hidden() -> ScratchTmpfs {
    let hidden = ScratchTmpfs::new("");
    hidden.mkdir("root/upper");
    hidden.mkdir("root/work");
    hidden
}

/// Mount the root overlay over `decoy` with `hidden`'s upper, as the entry
/// does, hand `f` the next root, and detach it again.
fn in_next_root(decoy: &Path, hidden: &Path, f: impl FnOnce(&Path)) {
    let next = hidden.join("next");
    std::fs::create_dir_all(&next).unwrap();
    nextroot::overlay_over(
        decoy,
        &hidden.join("lower"),
        &hidden.join("root/upper"),
        &hidden.join("root/work"),
        &next,
    )
    .expect("the root overlay");
    f(&next);
    nextroot::detach_tree(&next);
}

/// Delete the hidden copy of `target` (as the hidden root names it) with
/// the plan `discard` runs, and return what it removed.
fn discard(hidden: &Path, target: &str) -> Vec<std::path::PathBuf> {
    let config = Config {
        hidden_volume_root: hidden.to_path_buf(),
        state_file_path: hidden.join("state.json"),
        ..Config::default()
    };
    let manager = NailsManager::new(RealFilesystem, config, hidden.join("state.json"));
    let plan = manager
        .plan_reset_upper_on(Path::new(target), &SessionView::Decoy)
        .unwrap();
    manager.apply_reset_upper(&plan).unwrap();
    plan.removals
}

fn is_whiteout(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .is_ok_and(|meta| meta.file_type().is_char_device() && meta.rdev() == 0)
}

/// What a kernel update's hook does to the running kernel's index, done
/// through the root overlay: it deletes both forms, the kernel keeps each
/// deletion as a whiteout, the row names the text form with the `discard` of
/// the whole tree, and that discard brings the decoy's index back into the
/// next root.
#[test]
fn a_deleted_index_is_the_whiteout_the_row_names_and_its_discard_brings_it_back() {
    let _ = Rerun::new(test_path!(
        a_deleted_index_is_the_whiteout_the_row_names_and_its_discard_brings_it_back
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = decoy();
        let hidden = hidden();
        let upper = hidden.path().join("root/upper");
        let check =
            KernelModulesCheck::new(decoy.path().to_path_buf(), upper.clone(), RELEASE.into());

        in_next_root(decoy.path(), hidden.path(), |next| {
            for file in [index(), binary_index()] {
                std::fs::remove_file(next.join(&file)).unwrap();
                assert!(!next.join(&file).exists());
            }
        });
        for file in [index(), binary_index()] {
            assert!(is_whiteout(&upper.join(&file)), "the kernel's whiteout");
        }
        assert_eq!(
            std::fs::read_to_string(decoy.path().join(index())).unwrap(),
            INDEX_TEXT,
            "the decoy keeps its index"
        );

        // The namespace's root sees no opaque marker, and the whiteout settles
        // it all the same.
        let result = check.result(TrustedXattrs::of_this_process());
        assert!(result.is_warn(), "{result:?}");
        let shown = format!("/{}", tree());
        assert!(
            result
                .message()
                .starts_with(&format!("a hidden session deleted {shown}/modules.dep, ")),
            "{result:?}"
        );
        let line = sudo_line_for(NextStep::Discard, &shown);
        assert!(
            result.message().contains(&format!("`{line}`")),
            "{result:?}"
        );

        assert_eq!(discard(hidden.path(), &shown), vec![upper.join(tree())]);
        in_next_root(decoy.path(), hidden.path(), |next| {
            assert_eq!(
                std::fs::read_to_string(next.join(index())).unwrap(),
                INDEX_TEXT
            );
            assert_eq!(
                std::fs::read_to_string(next.join(binary_index())).unwrap(),
                INDEX_BINARY
            );
        });
        // Only the copied-up directories above it are left, merged.
        assert!(check.result(TrustedXattrs::Visible).is_pass());
    });
}

/// The whiteout a hidden kernel update leaves for the release directory
/// itself (written here in its on-disk form: the kernel cannot delete a
/// directory through an overlay without the `trusted.*` attributes a
/// namespace lacks) hides the whole tree from the next root until the
/// `discard` the row names deletes it.
#[test]
fn a_whiteout_of_the_release_hides_it_from_the_next_root_until_discarded() {
    let _ = Rerun::new(test_path!(
        a_whiteout_of_the_release_hides_it_from_the_next_root_until_discarded
    ))
    .in_user_mount_ns()
    .run(|| {
        use nix::sys::stat::{Mode, SFlag, mknod};
        let decoy = decoy();
        let hidden = hidden();
        let upper = hidden.path().join("root/upper");
        std::fs::create_dir_all(upper.join("usr/lib/modules")).unwrap();
        mknod(
            &upper.join(tree()),
            SFlag::S_IFCHR,
            Mode::from_bits_truncate(0o600),
            0,
        )
        .expect("a whiteout");

        in_next_root(decoy.path(), hidden.path(), |next| {
            assert!(next.join("usr/lib/modules").is_dir());
            assert!(!next.join(tree()).exists(), "the tree is hidden");
        });
        let check =
            KernelModulesCheck::new(decoy.path().to_path_buf(), upper.clone(), RELEASE.into());
        let result = check.result(TrustedXattrs::of_this_process());
        let shown = format!("/{}", tree());
        assert!(
            result.message().starts_with(&format!(
                "a hidden session deleted {shown}, the running kernel's modules"
            )),
            "{result:?}"
        );

        assert_eq!(discard(hidden.path(), &shown), vec![upper.join(tree())]);
        assert!(!is_whiteout(&upper.join(tree())));
        in_next_root(decoy.path(), hidden.path(), |next| {
            assert!(next.join(tree()).join("kernel/fs/ext4.ko").is_file());
            assert_eq!(
                std::fs::read_to_string(next.join(index())).unwrap(),
                INDEX_TEXT
            );
        });
        assert!(check.result(TrustedXattrs::Visible).is_pass());
    });
}

/// A whiteout above the release directory, here of `/usr/lib/modules` as a
/// hidden `rm -rf /usr/lib/modules` leaves it, hides every kernel's modules
/// from the next root, a release the decoy installs later included: the row
/// offers no kernel update for either release, and the `discard` it names
/// brings both trees back.
#[test]
fn a_whiteout_above_the_release_hides_a_new_kernels_tree_too_until_discarded() {
    let _ = Rerun::new(test_path!(
        a_whiteout_above_the_release_hides_a_new_kernels_tree_too_until_discarded
    ))
    .in_user_mount_ns()
    .run(|| {
        use nix::sys::stat::{Mode, SFlag, mknod};
        let decoy = decoy();
        let hidden = hidden();
        let upper = hidden.path().join("root/upper");
        std::fs::create_dir_all(upper.join("usr/lib")).unwrap();
        mknod(
            &upper.join("usr/lib/modules"),
            SFlag::S_IFCHR,
            Mode::from_bits_truncate(0o600),
            0,
        )
        .expect("a whiteout");
        // The decoy's kernel updated to a new release since.
        let new_release = "6.18.0-arch1-1";
        let new_index = format!("usr/lib/modules/{new_release}/modules.dep");
        decoy.mkdir(&format!("usr/lib/modules/{new_release}/kernel"));
        std::fs::write(decoy.path().join(&new_index), INDEX_TEXT).unwrap();

        in_next_root(decoy.path(), hidden.path(), |next| {
            assert!(next.join("usr/lib").is_dir());
            assert!(
                !next.join("usr/lib/modules").exists(),
                "every tree is hidden"
            );
        });
        let shown = "/usr/lib/modules";
        let line = sudo_line_for(NextStep::Discard, shown);
        let check = |release: &str| {
            KernelModulesCheck::new(decoy.path().to_path_buf(), upper.clone(), release.into())
        };
        for release in [RELEASE, new_release] {
            let result = check(release).result(TrustedXattrs::of_this_process());
            assert!(result.is_warn(), "{result:?}");
            let text = result.message();
            assert!(
                text.starts_with(&format!(
                    "a hidden session deleted {shown}, and with it {shown}/{release}, "
                )),
                "{text}"
            );
            assert!(
                text.contains(&format!("\nBring the decoy's {shown} back with `{line}`")),
                "{text}"
            );
            assert!(
                text.ends_with(
                    "A kernel update on the decoy would not bring its modules back, since the \
                     change hides them for every kernel."
                ),
                "{text}"
            );
        }

        assert_eq!(
            discard(hidden.path(), shown),
            vec![upper.join("usr/lib/modules")]
        );
        in_next_root(decoy.path(), hidden.path(), |next| {
            assert_eq!(
                std::fs::read_to_string(next.join(index())).unwrap(),
                INDEX_TEXT
            );
            assert_eq!(
                std::fs::read_to_string(next.join(&new_index)).unwrap(),
                INDEX_TEXT
            );
        });
        for release in [RELEASE, new_release] {
            assert!(check(release).result(TrustedXattrs::Visible).is_pass());
        }
    });
}
