// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The SELinux label copy, `nails_core::session::labels`, on real
//! filesystems: the label of a decoy directory lands on the upper and shows on
//! the root of an overlay over the two, without moving the decoy directory's
//! access time; the walk down to a fresh home labels a parent at the next walk
//! after one refused at it, and the hidden root shows the labels; the walk
//! along what the upper holds labels what a refused fresh-home entry left
//! there, or is refused again; and nothing is written where the decoy's
//! directories have no label, where a filesystem stores none (ramfs), or onto
//! or through a link in place of an upper directory.
//!
//! The namespace's root may write `security.selinux` on its own tmpfs, and a
//! kernel without SELinux stores the value as given. A kernel that labels every
//! file itself (SELinux active) checks each label against the loaded policy
//! instead, which needs a VM with that policy; these tests skip there.

use nails_core::session::labels::{
    Copied, LABEL_XATTR, Labels, Reason, copy_label, copy_labels_along, copy_labels_along_existing,
};
use nails_core::test_path;
use nails_core::test_support::{Rerun, ScratchTmpfs, skip, skip_host};
use nails_teardown::whole_root::nextroot;
use rustix::fs::XattrFlags;
use rustix::io::Errno;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A host whose facts report SELinux.
pub(crate) const REQUIRED: Labels = Labels::Required(Reason::SelinuxRunning);
/// The labels Fedora's policy gives `/`, `/home` and a home, as they are
/// stored: with their NUL.
pub(crate) const ROOT_LABEL: &[u8] = b"system_u:object_r:root_t:s0\0";
pub(crate) const HOME_ROOT_LABEL: &[u8] = b"system_u:object_r:home_root_t:s0\0";
pub(crate) const HOME_LABEL: &[u8] = b"unconfined_u:object_r:user_home_dir_t:s0\0";

/// The label stored on `path` itself, or the kernel's error.
pub(crate) fn label(path: &Path) -> Result<Vec<u8>, Errno> {
    let mut value = vec![0; 4096];
    let len = rustix::fs::lgetxattr(path, LABEL_XATTR, &mut value[..])?;
    value.truncate(len);
    Ok(value)
}

/// Write `value` as the label of `path` itself.
pub(crate) fn set_label(path: &Path, value: &[u8]) {
    rustix::fs::lsetxattr(path, LABEL_XATTR, value, XattrFlags::empty())
        .unwrap_or_else(|e| panic!("label {}: {e}", path.display()));
}

/// The status change time of `path`, which any attribute written moves.
pub(crate) fn ctime(path: &Path) -> (i64, i64) {
    let meta = std::fs::symlink_metadata(path).unwrap();
    (meta.ctime(), meta.ctime_nsec())
}

/// The access time of `path`, which every access moves on a strictatime
/// filesystem.
fn atime(path: &Path) -> (i64, i64) {
    let meta = std::fs::symlink_metadata(path).unwrap();
    (meta.atime(), meta.atime_nsec())
}

/// Long enough for a write or an access to move a time on tmpfs.
pub(crate) fn tick() {
    std::thread::sleep(Duration::from_millis(20));
}

/// A fresh strictatime tmpfs whose root carries no label. Skips on a host
/// whose kernel labels new files itself.
fn tmpfs_without_selinux() -> ScratchTmpfs {
    let tmpfs = ScratchTmpfs::strictatime();
    match label(tmpfs.path()) {
        Err(Errno::NODATA) => tmpfs,
        Ok(found) => skip_host(&format!(
            "the kernel labels new files on this host ({}): SELinux is active, and the label \
             copy under a loaded policy needs a VM",
            String::from_utf8_lossy(&found).trim_end_matches('\0')
        )),
        Err(errno) => panic!("{LABEL_XATTR} of a fresh tmpfs: {errno}"),
    }
}

/// A fresh ramfs, which stores no extended attributes, below `scratch`.
fn ramfs(scratch: &ScratchTmpfs) -> PathBuf {
    let dir = scratch.mkdir("ramfs");
    if let Err(errno) = nix::mount::mount(
        Some("ramfs"),
        &dir,
        Some("ramfs"),
        nix::mount::MsFlags::empty(),
        None::<&str>,
    ) {
        skip(&format!("cannot mount a ramfs in this namespace: {errno}"));
    }
    dir
}

#[test]
fn a_decoy_label_lands_on_the_upper_and_shows_through_the_overlay() {
    let _ = Rerun::new(test_path!(
        a_decoy_label_lands_on_the_upper_and_shows_through_the_overlay
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = tmpfs_without_selinux();
        set_label(decoy.path(), ROOT_LABEL);
        let hidden = ScratchTmpfs::new("");
        let upper = hidden.mkdir("root/upper");
        let work = hidden.mkdir("root/work");
        let decoy_before = (atime(decoy.path()), ctime(decoy.path()));
        tick();

        assert_eq!(
            copy_label(decoy.path(), &upper, REQUIRED).unwrap(),
            Copied::Label
        );
        assert_eq!(label(&upper).unwrap(), ROOT_LABEL);
        // Best effort copies a label the decoy has as well (a decoy that
        // carries labels on a host that runs without SELinux).
        let home = hidden.mkdir("root/mounts/home/upper");
        assert_eq!(
            copy_label(decoy.path(), &home, Labels::BestEffort).unwrap(),
            Copied::Label
        );
        assert_eq!(label(&home).unwrap(), ROOT_LABEL);

        // The next entry finds the label in place and writes nothing.
        let labelled = ctime(&upper);
        tick();
        assert_eq!(
            copy_label(decoy.path(), &upper, REQUIRED).unwrap(),
            Copied::Label
        );
        assert_eq!(ctime(&upper), labelled);
        // The decoy directory was only read, and not even its access time
        // moved, on a filesystem that updates it on every access.
        assert_eq!((atime(decoy.path()), ctime(decoy.path())), decoy_before);
        assert_eq!(label(decoy.path()).unwrap(), ROOT_LABEL);

        // The root of the overlay is the upper's root, with its label: the
        // hidden `/` as the policy would see it.
        let merged = hidden.mkdir("next");
        nextroot::overlay_over(
            decoy.path(),
            &hidden.path().join("lower"),
            &upper,
            &work,
            &merged,
        )
        .expect("the overlay over the decoy");
        assert_eq!(label(&merged).unwrap(), ROOT_LABEL);
    });
}

#[test]
fn a_decoy_directory_without_a_label_leaves_the_upper_as_it_was() {
    let _ = Rerun::new(test_path!(
        a_decoy_directory_without_a_label_leaves_the_upper_as_it_was
    ))
    .in_user_mount_ns()
    .run(|| {
        // A decoy on a host without SELinux: its directories carry no label.
        let decoy = tmpfs_without_selinux();
        let hidden = ScratchTmpfs::new("");
        let upper = hidden.mkdir("root/upper");
        let before = ctime(&upper);
        tick();

        assert_eq!(
            copy_label(decoy.path(), &upper, Labels::BestEffort).unwrap(),
            Copied::NoLabel
        );
        let refused = copy_label(decoy.path(), &upper, REQUIRED).unwrap_err();
        assert!(refused.to_string().ends_with("has no label"), "{refused}");

        // Neither wrote anything: the upper has no attribute at all and its
        // status is unchanged.
        let mut names: [u8; 0] = [];
        assert_eq!(rustix::fs::llistxattr(&upper, &mut names[..]), Ok(0));
        assert_eq!(ctime(&upper), before);
    });
}

#[test]
fn a_filesystem_without_extended_attributes_is_skipped_without_selinux_and_refused_with_it() {
    let _ = Rerun::new(test_path!(
        a_filesystem_without_extended_attributes_is_skipped_without_selinux_and_refused_with_it
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = tmpfs_without_selinux();
        set_label(decoy.path(), ROOT_LABEL);
        let hidden = ScratchTmpfs::new("");
        let on_ramfs = ramfs(&hidden);

        // The hidden volume's filesystem cannot store the label.
        assert_eq!(
            copy_label(decoy.path(), &on_ramfs, Labels::BestEffort).unwrap(),
            Copied::Unsupported
        );
        let refused = copy_label(decoy.path(), &on_ramfs, REQUIRED).unwrap_err();
        assert!(
            refused.to_string().ends_with("cannot store labels"),
            "{refused}"
        );
        assert_eq!(label(&on_ramfs), Err(Errno::NOTSUP));

        // The decoy directory's filesystem stores none.
        let upper = hidden.mkdir("root/upper");
        let before = ctime(&upper);
        tick();
        assert_eq!(
            copy_label(&on_ramfs, &upper, Labels::BestEffort).unwrap(),
            Copied::Unsupported
        );
        let refused = copy_label(&on_ramfs, &upper, REQUIRED).unwrap_err();
        assert!(
            refused.to_string().ends_with("stores no labels"),
            "{refused}"
        );
        assert_eq!(label(&upper), Err(Errno::NODATA));
        assert_eq!(ctime(&upper), before);
    });
}

#[test]
fn a_link_in_place_of_the_upper_is_refused_and_never_labelled() {
    let _ = Rerun::new(test_path!(
        a_link_in_place_of_the_upper_is_refused_and_never_labelled
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = tmpfs_without_selinux();
        set_label(decoy.path(), ROOT_LABEL);
        // Where a link planted on the hidden volume could point: another
        // filesystem, the decoy's for all the copy can tell.
        let elsewhere = ScratchTmpfs::new("");
        let hidden = ScratchTmpfs::new("");
        let upper = hidden.mkdir("root").join("upper");
        std::os::unix::fs::symlink(elsewhere.path(), &upper).unwrap();
        let before = ctime(elsewhere.path());
        tick();

        // An overlay given this path would take its root from the link's
        // target, which no label reaches: no success to report.
        let refused = copy_label(decoy.path(), &upper, REQUIRED).unwrap_err();
        assert!(
            refused.to_string().ends_with(&format!(
                "but {} is a link or a file, not a directory",
                upper.display()
            )),
            "{refused}"
        );
        assert_eq!(
            copy_label(decoy.path(), &upper, Labels::BestEffort).unwrap(),
            Copied::NotADirectory
        );
        // Neither copy labelled the link itself or its target.
        assert_eq!(label(&upper), Err(Errno::NODATA));
        assert_eq!(label(elsewhere.path()), Err(Errno::NODATA));
        assert_eq!(ctime(elsewhere.path()), before);
    });
}

#[test]
fn a_walk_refused_at_a_parent_of_the_home_labels_that_parent_at_the_next_walk() {
    let _ = Rerun::new(test_path!(
        a_walk_refused_at_a_parent_of_the_home_labels_that_parent_at_the_next_walk
    ))
    .in_user_mount_ns()
    .run(|| {
        // The decoy's `/home/alice`, whose `/home` carries no label yet.
        let decoy = tmpfs_without_selinux();
        let decoy_home = decoy.mkdir("home/alice");
        set_label(&decoy_home, HOME_LABEL);
        // The root upper with the empty home and its parent, as the persona
        // creates them before the walk.
        let hidden = ScratchTmpfs::new("");
        let upper = hidden.mkdir("root/upper");
        let parent = hidden.mkdir("root/upper/home");
        let home = hidden.mkdir("root/upper/home/alice");
        let rest = Path::new("home/alice");
        let decoy_before = (atime(&decoy.path().join("home")), atime(&decoy_home));
        tick();

        // The copy for the parent fails, and the walk is refused there,
        // before it reaches the home.
        let refused = copy_labels_along(decoy.path(), &upper, rest, REQUIRED).unwrap_err();
        assert!(
            refused.to_string().ends_with(&format!(
                "but {} has no label",
                decoy.path().join("home").display()
            )),
            "{refused}"
        );
        assert_eq!(label(&parent), Err(Errno::NODATA));
        assert_eq!(label(&home), Err(Errno::NODATA));

        // At the next entry the parent and the home are in place, and the
        // walk labels both: a directory made earlier is labelled all the same.
        set_label(&decoy.path().join("home"), HOME_ROOT_LABEL);
        copy_labels_along(decoy.path(), &upper, rest, REQUIRED).unwrap();
        assert_eq!(label(&parent).unwrap(), HOME_ROOT_LABEL);
        assert_eq!(label(&home).unwrap(), HOME_LABEL);
        // The upper root is not the walk's: `make_layer` labels it.
        assert_eq!(label(&upper), Err(Errno::NODATA));

        // Labels in place are not written again, and the decoy's directories
        // were only read.
        let labelled = (ctime(&parent), ctime(&home));
        tick();
        copy_labels_along(decoy.path(), &upper, rest, REQUIRED).unwrap();
        assert_eq!((ctime(&parent), ctime(&home)), labelled);
        assert_eq!(
            (atime(&decoy.path().join("home")), atime(&decoy_home)),
            decoy_before
        );

        // With the root labelled as `make_layer` labels it, the hidden root
        // shows the decoy's labels on `/`, `/home` and the home.
        set_label(decoy.path(), ROOT_LABEL);
        assert_eq!(
            copy_label(decoy.path(), &upper, REQUIRED).unwrap(),
            Copied::Label
        );
        let work = hidden.mkdir("root/work");
        let merged = hidden.mkdir("next");
        nextroot::overlay_over(
            decoy.path(),
            &hidden.path().join("lower"),
            &upper,
            &work,
            &merged,
        )
        .expect("the overlay over the decoy");
        assert_eq!(label(&merged).unwrap(), ROOT_LABEL);
        assert_eq!(label(&merged.join("home")).unwrap(), HOME_ROOT_LABEL);
        assert_eq!(label(&merged.join("home/alice")).unwrap(), HOME_LABEL);
    });
}

#[test]
fn a_walk_never_labels_through_a_link_below_the_upper_root() {
    let _ = Rerun::new(test_path!(
        a_walk_never_labels_through_a_link_below_the_upper_root
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = tmpfs_without_selinux();
        let decoy_home = decoy.mkdir("home/alice");
        set_label(&decoy.path().join("home"), HOME_ROOT_LABEL);
        set_label(&decoy_home, HOME_LABEL);
        // A hidden `/home` replaced by a link to another filesystem, the
        // decoy's for all the walk can tell, that has an `alice` too.
        let elsewhere = ScratchTmpfs::new("");
        let target = elsewhere.mkdir("alice");
        let hidden = ScratchTmpfs::new("");
        let upper = hidden.mkdir("root/upper");
        std::os::unix::fs::symlink(elsewhere.path(), upper.join("home")).unwrap();
        let before = (ctime(elsewhere.path()), ctime(&target));
        tick();

        let rest = Path::new("home/alice");
        let refused = copy_labels_along(decoy.path(), &upper, rest, REQUIRED).unwrap_err();
        assert!(
            refused
                .to_string()
                .ends_with("is a link or a file, not a directory"),
            "{refused}"
        );
        copy_labels_along(decoy.path(), &upper, rest, Labels::BestEffort).unwrap();
        // Neither walk labelled the link, its target or the home behind it.
        assert_eq!(label(&upper.join("home")), Err(Errno::NODATA));
        assert_eq!(label(elsewhere.path()), Err(Errno::NODATA));
        assert_eq!(label(&target), Err(Errno::NODATA));
        assert_eq!((ctime(elsewhere.path()), ctime(&target)), before);
    });
}

#[test]
fn a_walk_over_decoy_directories_without_labels_leaves_the_way_as_it_was() {
    let _ = Rerun::new(test_path!(
        a_walk_over_decoy_directories_without_labels_leaves_the_way_as_it_was
    ))
    .in_user_mount_ns()
    .run(|| {
        // A decoy on a host without SELinux: its `/home` and `/home/alice`
        // carry no label.
        let decoy = tmpfs_without_selinux();
        let decoy_parent = decoy.mkdir("home");
        let decoy_home = decoy.mkdir("home/alice");
        // The root upper with the home and its parent, as the persona creates
        // them before the walk.
        let hidden = ScratchTmpfs::new("");
        let upper = hidden.mkdir("root/upper");
        let parent = hidden.mkdir("root/upper/home");
        let home = hidden.mkdir("root/upper/home/alice");
        let rest = Path::new("home/alice");
        let before = (ctime(&parent), ctime(&home));
        let decoy_before = (atime(&decoy_parent), atime(&decoy_home));
        tick();

        // The walk of a fresh-home entry and that of a shared-home one, on a
        // host whose facts report no SELinux and on one that requires the
        // labels, which refuses at the parent.
        for walk in [copy_labels_along, copy_labels_along_existing] {
            walk(decoy.path(), &upper, rest, Labels::BestEffort).unwrap();
            let refused = walk(decoy.path(), &upper, rest, REQUIRED).unwrap_err();
            assert!(
                refused
                    .to_string()
                    .ends_with(&format!("but {} has no label", decoy_parent.display())),
                "{refused}"
            );
        }

        // None of them wrote anything: neither directory has an attribute at
        // all, and their status is unchanged.
        for dir in [&parent, &home] {
            let mut names: [u8; 0] = [];
            assert_eq!(
                rustix::fs::llistxattr(dir, &mut names[..]),
                Ok(0),
                "{}",
                dir.display()
            );
        }
        assert_eq!((ctime(&parent), ctime(&home)), before);
        // The decoy's directories were only read.
        assert_eq!((atime(&decoy_parent), atime(&decoy_home)), decoy_before);
    });
}

#[test]
fn a_walk_along_what_the_upper_holds_labels_what_a_refused_entry_left() {
    let _ = Rerun::new(test_path!(
        a_walk_along_what_the_upper_holds_labels_what_a_refused_entry_left
    ))
    .in_user_mount_ns()
    .run(|| {
        // The decoy's `/home/alice`, whose `/home` carries no label yet, so the
        // fresh-home walk is refused at the parent, as where the policy denies
        // that relabel.
        let decoy = tmpfs_without_selinux();
        let decoy_home = decoy.mkdir("home/alice");
        set_label(&decoy_home, HOME_LABEL);
        let hidden = ScratchTmpfs::new("");
        let upper = hidden.mkdir("root/upper");
        let parent = hidden.mkdir("root/upper/home");
        let home = hidden.mkdir("root/upper/home/alice");
        let rest = Path::new("home/alice");
        copy_labels_along(decoy.path(), &upper, rest, REQUIRED).unwrap_err();
        assert_eq!(label(&parent), Err(Errno::NODATA));
        assert_eq!(label(&home), Err(Errno::NODATA));

        // The persona is set to shared-home, so no entry makes the fresh home
        // again. The walk along what the upper holds labels the parent and the
        // home the refused entry left.
        set_label(&decoy.path().join("home"), HOME_ROOT_LABEL);
        copy_labels_along_existing(decoy.path(), &upper, rest, REQUIRED).unwrap();
        assert_eq!(label(&parent).unwrap(), HOME_ROOT_LABEL);
        assert_eq!(label(&home).unwrap(), HOME_LABEL);
        assert_eq!(label(&upper), Err(Errno::NODATA));

        // Labels in place are not written again.
        let labelled = (ctime(&parent), ctime(&home));
        tick();
        copy_labels_along_existing(decoy.path(), &upper, rest, REQUIRED).unwrap();
        assert_eq!((ctime(&parent), ctime(&home)), labelled);

        // An entry that stopped after it made the parent left only that: the
        // walk labels it and ends where the upper holds no more, though every
        // label is required.
        let other = hidden.mkdir("other/upper");
        let other_parent = hidden.mkdir("other/upper/home");
        copy_labels_along_existing(decoy.path(), &other, rest, REQUIRED).unwrap();
        assert_eq!(label(&other_parent).unwrap(), HOME_ROOT_LABEL);
        assert!(!other_parent.join("alice").exists());
    });
}

#[test]
fn a_home_left_for_an_operator_the_decoy_has_no_home_for_is_refused_in_either_persona() {
    let _ = Rerun::new(test_path!(
        a_home_left_for_an_operator_the_decoy_has_no_home_for_is_refused_in_either_persona
    ))
    .in_user_mount_ns()
    .run(|| {
        // The decoy has a labelled `/home`, but no home for alice.
        let decoy = tmpfs_without_selinux();
        let decoy_parent = decoy.mkdir("home");
        set_label(&decoy_parent, HOME_ROOT_LABEL);
        let hidden = ScratchTmpfs::new("");
        let upper = hidden.mkdir("root/upper");
        let parent = hidden.mkdir("root/upper/home");
        let home = hidden.mkdir("root/upper/home/alice");
        let rest = Path::new("home/alice");
        let missing = format!(
            "but {} does not exist",
            decoy_parent.join("alice").display()
        );

        // The fresh-home walk labels the parent and is refused at the home.
        let refused = copy_labels_along(decoy.path(), &upper, rest, REQUIRED).unwrap_err();
        assert!(refused.to_string().ends_with(&missing), "{refused}");
        assert_eq!(label(&parent).unwrap(), HOME_ROOT_LABEL);
        assert_eq!(label(&home), Err(Errno::NODATA));

        // With the persona set to shared-home, the home left in the upper is
        // refused again, never passed over. Without SELinux it is left alone.
        let refused = copy_labels_along_existing(decoy.path(), &upper, rest, REQUIRED).unwrap_err();
        assert!(refused.to_string().ends_with(&missing), "{refused}");
        copy_labels_along_existing(decoy.path(), &upper, rest, Labels::BestEffort).unwrap();
        assert_eq!(label(&home), Err(Errno::NODATA));

        // Once that home is gone from the upper, the walk ends at the parent.
        std::fs::remove_dir(&home).unwrap();
        copy_labels_along_existing(decoy.path(), &upper, rest, REQUIRED).unwrap();
        assert_eq!(label(&parent).unwrap(), HOME_ROOT_LABEL);
    });
}
