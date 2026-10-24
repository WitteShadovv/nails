// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The SELinux label copy, `nails_core::session::labels`, on real
//! filesystems: the label of a decoy directory lands on the upper and shows on
//! the root of an overlay over the two, without moving the decoy directory's
//! access time, and nothing is written where the decoy directory has no label,
//! where a filesystem stores none (ramfs), or through a link in place of the
//! upper.
//!
//! The namespace's root may write `security.selinux` on its own tmpfs, and a
//! kernel without SELinux stores the value as given. A kernel that labels every
//! file itself (SELinux active) checks each label against the loaded policy
//! instead, which only the VM tests have; these tests skip there.

use nails_core::session::labels::{Copied, LABEL_XATTR, Labels, copy_label};
use nails_core::test_path;
use nails_core::test_support::{Rerun, ScratchTmpfs, skip_host};
use nails_teardown::whole_root::nextroot;
use rustix::fs::XattrFlags;
use rustix::io::Errno;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The label Fedora's policy gives `/`, as it is stored: with its NUL.
const ROOT_LABEL: &[u8] = b"system_u:object_r:root_t:s0\0";

/// The label stored on `path` itself, or the kernel's error.
fn label(path: &Path) -> Result<Vec<u8>, Errno> {
    let mut value = vec![0; 4096];
    let len = rustix::fs::lgetxattr(path, LABEL_XATTR, &mut value[..])?;
    value.truncate(len);
    Ok(value)
}

/// Write `value` as the label of `path` itself.
fn set_label(path: &Path, value: &[u8]) {
    rustix::fs::lsetxattr(path, LABEL_XATTR, value, XattrFlags::empty())
        .unwrap_or_else(|e| panic!("label {}: {e}", path.display()));
}

/// The status change time of `path`, which any attribute written moves.
fn ctime(path: &Path) -> (i64, i64) {
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
fn tick() {
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
             copy under a loaded policy is tested in a VM",
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
        skip_host(&format!("cannot mount a ramfs in this namespace: {errno}"));
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
            copy_label(decoy.path(), &upper, Labels::Required).unwrap(),
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
            copy_label(decoy.path(), &upper, Labels::Required).unwrap(),
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
        let refused = copy_label(decoy.path(), &upper, Labels::Required).unwrap_err();
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
        let refused = copy_label(decoy.path(), &on_ramfs, Labels::Required).unwrap_err();
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
        let refused = copy_label(&on_ramfs, &upper, Labels::Required).unwrap_err();
        assert!(
            refused.to_string().ends_with("stores no labels"),
            "{refused}"
        );
        assert_eq!(label(&upper), Err(Errno::NODATA));
        assert_eq!(ctime(&upper), before);
    });
}

#[test]
fn a_link_in_place_of_the_upper_is_labelled_itself_never_its_target() {
    let _ = Rerun::new(test_path!(
        a_link_in_place_of_the_upper_is_labelled_itself_never_its_target
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

        assert_eq!(
            copy_label(decoy.path(), &upper, Labels::BestEffort).unwrap(),
            Copied::Label
        );
        assert_eq!(label(&upper).unwrap(), ROOT_LABEL);
        assert_eq!(label(elsewhere.path()), Err(Errno::NODATA));
        assert_eq!(ctime(elsewhere.path()), before);
    });
}
