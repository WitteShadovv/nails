// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use std::ffi::OsStr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use super::*;

const NAME: &str = "nails.toml";

fn name() -> &'static OsStr {
    OsStr::new(NAME)
}

/// A root holding `config/`, pinned.
fn pinned() -> (tempfile::TempDir, PinnedDir) {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("config")).unwrap();
    let dir = PinnedDir::open(root.path(), Path::new("config"), None).unwrap();
    (root, dir)
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn a_missing_file_reads_as_none_and_a_file_with_its_owner_and_mode() {
    let (root, dir) = pinned();
    assert_eq!(dir.read(name(), 1024).unwrap(), None);
    let file = root.path().join("config").join(NAME);
    std::fs::write(&file, "minimum_space_mb = 750\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
    let read = dir.read(name(), 1024).unwrap().unwrap();
    assert_eq!(read.bytes, b"minimum_space_mb = 750\n");
    let meta = std::fs::metadata(&file).unwrap();
    assert_eq!(
        read.owner,
        Owner {
            uid: meta.uid(),
            gid: meta.gid(),
            mode: 0o640,
        }
    );
}

#[test]
fn a_link_at_the_file_is_refused_and_its_target_is_left_alone() {
    let (root, dir) = pinned();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("decoy.toml");
    std::fs::write(&target, "decoy").unwrap();
    std::os::unix::fs::symlink(&target, root.path().join("config").join(NAME)).unwrap();
    assert!(matches!(dir.read(name(), 1024), Err(PinError::Linked(_))));
    let replaced = dir.replace(name(), b"minimum_space_mb = 1\n", None);
    // The rename replaces the link itself, never what it points at.
    assert!(replaced.is_ok(), "{replaced:?}");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "decoy");
    let file = root.path().join("config").join(NAME);
    assert!(
        !std::fs::symlink_metadata(&file)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn a_link_on_the_way_to_the_directory_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("config")).unwrap();
    let error = PinnedDir::open(root.path(), Path::new("config"), None).unwrap_err();
    assert!(matches!(error, PinError::Linked(_)), "{error:?}");
    // And a link as the root itself.
    let link = outside.path().join("root-link");
    std::os::unix::fs::symlink(root.path(), &link).unwrap();
    let error = PinnedDir::open(&link, Path::new(""), None).unwrap_err();
    assert!(matches!(error, PinError::Linked(_)), "{error:?}");
    // A path that climbs out of the root.
    let error = PinnedDir::open(root.path(), Path::new("../x"), None).unwrap_err();
    assert!(matches!(error, PinError::Linked(_)), "{error:?}");
}

#[test]
fn a_hard_link_a_directory_and_a_fifo_at_the_name_are_refused() {
    let (root, dir) = pinned();
    let file = root.path().join("config").join(NAME);
    std::fs::write(&file, "").unwrap();
    std::fs::hard_link(&file, root.path().join("other-name")).unwrap();
    assert!(matches!(
        dir.read(name(), 1024),
        Err(PinError::HardLinked(_))
    ));
    std::fs::remove_file(&file).unwrap();

    std::fs::create_dir(&file).unwrap();
    assert!(matches!(dir.read(name(), 1024), Err(PinError::NotAFile(_))));
    std::fs::remove_dir(&file).unwrap();

    nix::unistd::mkfifo(&file, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
    // The open does not wait for a writer.
    assert!(matches!(dir.read(name(), 1024), Err(PinError::NotAFile(_))));
}

#[test]
fn a_file_past_the_limit_is_refused() {
    let (root, dir) = pinned();
    std::fs::write(root.path().join("config").join(NAME), [b'#'; 11]).unwrap();
    assert!(matches!(
        dir.read(name(), 10),
        Err(PinError::TooLarge(_, 10))
    ));
    assert_eq!(dir.read(name(), 11).unwrap().unwrap().bytes.len(), 11);
}

#[test]
fn a_replacement_keeps_the_owner_and_mode_and_leaves_no_other_file() {
    let (root, dir) = pinned();
    let config = root.path().join("config");
    let file = config.join(NAME);
    std::fs::write(&file, "old\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
    let before = std::fs::metadata(&file).unwrap();
    let owner = dir.read(name(), 1024).unwrap().unwrap().owner;
    dir.replace(name(), b"new\n", Some(owner)).unwrap();
    let after = std::fs::metadata(&file).unwrap();
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "new\n");
    assert_eq!(after.mode() & 0o7777, 0o640);
    assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
    assert_ne!(
        after.ino(),
        before.ino(),
        "a new file took the old one's place"
    );
    assert_eq!(entries(&config), vec![NAME.to_string()]);
}

#[test]
fn a_new_file_is_root_only() {
    let (root, dir) = pinned();
    dir.replace(name(), b"minimum_space_mb = 1\n", None)
        .unwrap();
    let meta = std::fs::metadata(root.path().join("config").join(NAME)).unwrap();
    assert_eq!(meta.mode() & 0o7777, NEW_FILE_MODE);
}

#[test]
fn a_failed_replacement_leaves_the_old_entry_and_removes_its_new_file() {
    let (root, dir) = pinned();
    let config = root.path().join("config");
    // A directory with an entry at the name: the rename cannot replace it.
    std::fs::create_dir(config.join(NAME)).unwrap();
    std::fs::write(config.join(NAME).join("kept"), "").unwrap();
    assert!(dir.replace(name(), b"x", None).is_err());
    assert_eq!(entries(&config), vec![NAME.to_string()]);
    assert_eq!(entries(&config.join(NAME)), vec!["kept".to_string()]);
}

#[test]
fn an_owner_only_root_can_give_is_refused_without_root() {
    if nix::unistd::geteuid().is_root() {
        return;
    }
    let (root, dir) = pinned();
    let owner = Owner {
        uid: 0,
        gid: 0,
        mode: 0o600,
    };
    let error = dir.replace(name(), b"x", Some(owner)).unwrap_err();
    assert!(matches!(error, PinError::Io(_)), "{error:?}");
    assert!(entries(&root.path().join("config")).is_empty());
}

#[test]
fn the_root_must_be_the_mount_that_was_checked() {
    let root = tempfile::tempdir().unwrap();
    let id = rustix::fs::statx(
        rustix::fs::CWD,
        root.path(),
        rustix::fs::AtFlags::empty(),
        rustix::fs::StatxFlags::MNT_ID,
    )
    .unwrap()
    .stx_mnt_id;
    assert!(PinnedDir::open(root.path(), Path::new(""), Some(id)).is_ok());
    let error = PinnedDir::open(root.path(), Path::new(""), Some(id.wrapping_add(1))).unwrap_err();
    assert!(matches!(error, PinError::OtherMount(_)), "{error:?}");
}

#[test]
fn a_second_lock_waits_for_the_first_and_gives_up_after_its_wait() {
    let (_root, dir) = pinned();
    let first = dir
        .lock(Duration::ZERO)
        .unwrap()
        .expect("a free directory locks");
    assert!(dir.lock(Duration::from_millis(50)).unwrap().is_none());
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        drop(first);
    });
    assert!(dir.lock(Duration::from_secs(10)).unwrap().is_some());
    release.join().unwrap();
}

mod kernel_tests {
    use super::*;
    use crate::test_support::{Rerun, ScratchTmpfs};

    #[test]
    fn another_filesystem_mounted_on_the_way_or_at_the_file_is_refused() {
        let _ = Rerun::new(crate::test_path!(
            another_filesystem_mounted_on_the_way_or_at_the_file_is_refused
        ))
        .in_user_mount_ns()
        .run(|| {
            let volume = ScratchTmpfs::new("");
            let config = volume.path().join("config");
            std::fs::create_dir(&config).unwrap();
            let file = config.join(NAME);
            std::fs::write(&file, "minimum_space_mb = 1\n").unwrap();
            let elsewhere = tempfile::tempdir().unwrap();
            let decoy = elsewhere.path().join("decoy.toml");
            std::fs::write(&decoy, "decoy").unwrap();

            // A file bound over the name.
            nix::mount::mount(
                Some(&decoy),
                &file,
                None::<&str>,
                nix::mount::MsFlags::MS_BIND,
                None::<&str>,
            )
            .expect("bind a file over the name");
            let dir = PinnedDir::open(volume.path(), Path::new("config"), None).unwrap();
            assert!(matches!(dir.read(name(), 1024), Err(PinError::Linked(_))));
            assert!(dir.replace(name(), b"x", None).is_err());
            assert_eq!(std::fs::read_to_string(&decoy).unwrap(), "decoy");
            nix::mount::umount(&file).unwrap();

            // A directory bound over the way.
            nix::mount::mount(
                Some(elsewhere.path()),
                &config,
                None::<&str>,
                nix::mount::MsFlags::MS_BIND,
                None::<&str>,
            )
            .expect("bind a directory over config");
            let error = PinnedDir::open(volume.path(), Path::new("config"), None).unwrap_err();
            assert!(matches!(error, PinError::Linked(_)), "{error:?}");
        });
    }
}
