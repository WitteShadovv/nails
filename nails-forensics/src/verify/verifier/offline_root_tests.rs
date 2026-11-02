// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! An offline scan refuses a root that holds nothing to scan: a path that does
//! not exist, one that is not a folder, and a folder with no `etc` in it, such
//! as an empty mount point (the image never mounted on it), a fresh filesystem
//! that holds only `lost+found`, or the top level of a btrfs filesystem mounted
//! whole, whose system lies in a subvolume. Each of them used to read as a
//! secure image, the examiner's view with no trace.

use super::Verifier;
use crate::filesystem::PathKind;
use crate::verify::{ExaminerOptions, VerifyResult, VerifyStatus};
use crate::{MockFilesystem, NailsError, RealFilesystem, Result};
use nails_base::error::OfflineRootProblem;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// An offline scan of `root`, with the examiner's view when `examiner` is set.
fn scan(root: &Path, examiner: bool) -> Result<VerifyResult> {
    let mut verifier = Verifier::new(RealFilesystem).offline_under(root.to_path_buf());
    if examiner {
        verifier = verifier.with_examiner(ExaminerOptions::default());
    }
    verifier.run(false)
}

/// What the refusal of `root` names, the same with the examiner's view and
/// without it.
fn refused(root: &Path) -> OfflineRootProblem {
    let mut named = Vec::new();
    for examiner in [false, true] {
        match scan(root, examiner) {
            Err(NailsError::RefusedOfflineRoot {
                root: refused,
                problem,
            }) => {
                assert_eq!(refused, root);
                named.push(problem);
            }
            other => panic!("{} must be refused, got {other:?}", root.display()),
        }
    }
    assert_eq!(named[0], named[1]);
    named.swap_remove(0)
}

/// A folder with no `etc` in it, among whose entries no btrfs subvolume was
/// found.
fn no_etc_folder() -> OfflineRootProblem {
    OfflineRootProblem::NoEtcFolder {
        subvolumes: Vec::new(),
    }
}

/// A temporary folder holding `dirs` and the empty files `files`.
fn tree(dirs: &[&str], files: &[&str]) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    for dir in dirs {
        std::fs::create_dir_all(root.path().join(dir)).unwrap();
    }
    for file in files {
        std::fs::write(root.path().join(file), b"").unwrap();
    }
    root
}

#[test]
fn a_root_that_does_not_exist_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let absent = dir.path().join("absent");
    assert_eq!(refused(&absent), OfflineRootProblem::Missing);
    // A link to nothing names nothing, and neither does a path below a file.
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&absent, &link).unwrap();
    assert_eq!(refused(&link), OfflineRootProblem::Missing);
    let file = dir.path().join("file");
    std::fs::write(&file, b"").unwrap();
    assert_eq!(refused(&file.join("below")), OfflineRootProblem::Missing);
}

#[test]
fn a_root_that_is_not_a_folder_is_refused() {
    // The image file itself, given in place of the folder it is mounted on.
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("decoy.img");
    std::fs::write(&image, vec![0u8; 4096]).unwrap();
    assert_eq!(refused(&image), OfflineRootProblem::NotAFolder);
}

#[test]
fn an_empty_root_is_refused() {
    let mount_point = tempfile::tempdir().unwrap();
    assert_eq!(refused(mount_point.path()), OfflineRootProblem::Empty);
}

#[test]
fn a_root_that_holds_no_etc_folder_is_refused() {
    let cases: [(&[&str], &[&str]); 5] = [
        // A fresh filesystem: nothing but lost+found.
        (&["lost+found"], &[]),
        // A folder kept by a dot file.
        (&[], &[".keep"]),
        // A btrfs filesystem mounted whole, as a plain mount of a Fedora,
        // Ubuntu or archinstall partition does: its top level holds the
        // subvolumes, the system in one of them. (A copy of one here, whose
        // folders are no subvolumes, so none is named.)
        (&["@/etc", "@home/alice"], &[]),
        // A separate /home.
        (&["alice"], &["alice/.bash_history"]),
        // etc as a file.
        (&["usr"], &["etc"]),
    ];
    for (dirs, files) in cases {
        let root = tree(dirs, files);
        assert_eq!(refused(root.path()), no_etc_folder(), "{dirs:?} {files:?}");
    }
    // A link named etc is not followed, and does not count.
    let root = tree(&["usr/etc"], &[]);
    std::os::unix::fs::symlink("usr/etc", root.path().join("etc")).unwrap();
    assert_eq!(refused(root.path()), no_etc_folder());
    // The subvolume that holds the system is scanned.
    let top = tree(&["@/etc", "@home"], &[]);
    let result = scan(&top.path().join("@"), false).unwrap();
    assert_eq!(result.status, VerifyStatus::Secure, "{:?}", result.findings);
}

#[test]
fn a_btrfs_top_level_names_its_subvolumes() {
    // The root folder of each subvolume has inode 256 and a device of its own.
    let top = Path::new("/mnt/decoy");
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/mnt/decoy", PathKind::Dir);
    fs.mock_set_device_id(top, 40);
    let names = ["@home", "@", "plain", "same-device", "link"];
    fs.mock_set_directory_contents(top, names.iter().map(|name| top.join(name)).collect());
    for name in names {
        let entry = top.join(name);
        fs.mock_set_path_type(entry.to_str().unwrap(), PathKind::Dir);
        if name != "plain" {
            fs.mock_set_inode(&entry, 256);
        }
    }
    // A folder with inode 256 on the top level's own device is no subvolume,
    // and a link to one is not followed.
    fs.mock_set_device_id(&top.join("same-device"), 40);
    fs.mock_set_is_symlink("/mnt/decoy/link", true);

    let error = Verifier::new(fs)
        .offline_under(top.to_path_buf())
        .run(false)
        .unwrap_err();
    match error {
        NailsError::RefusedOfflineRoot { problem, .. } => assert_eq!(
            problem,
            OfflineRootProblem::NoEtcFolder {
                subvolumes: vec!["@".to_string(), "@home".to_string()]
            }
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_root_that_holds_files_is_scanned() {
    let root = tree(&["etc"], &["etc/passwd"]);
    let result = scan(root.path(), true).unwrap();
    assert_eq!(result.status, VerifyStatus::Secure, "{:?}", result.findings);
    assert!(result.examiner.is_some(), "the examiner's view runs");

    // What it holds is read: a runtime folder left on the image is a trace.
    std::fs::create_dir_all(root.path().join("run/nails")).unwrap();
    let result = scan(root.path(), false).unwrap();
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.category == "file" && f.message.contains("/run/nails")),
        "{:?}",
        result.findings
    );
}

#[test]
fn a_root_that_cannot_be_looked_up_or_listed_fails_closed() {
    // Neither is taken for a missing, an empty or a populated root: the scan
    // does not run, and the error says what could not be read.
    let root = Path::new("/mnt/image");
    let unlooked = MockFilesystem::new();
    unlooked.mock_set_inode_error(root, std::io::ErrorKind::PermissionDenied);
    // A folder with no etc, which the mock was given no listing of: listing
    // it fails.
    let unlisted = MockFilesystem::new();
    unlisted.mock_set_path_type("/mnt/image", PathKind::Dir);
    for fs in [unlooked, unlisted] {
        let error = Verifier::new(fs)
            .offline_under(root.to_path_buf())
            .run(false)
            .unwrap_err();
        assert!(matches!(error, NailsError::IoError { .. }), "{error:?}");
    }
}

/// The access time of `path`, to the nanosecond.
fn atime(path: &Path) -> (i64, i64) {
    let meta = std::fs::metadata(path).unwrap();
    (meta.atime(), meta.atime_nsec())
}

/// Set the access time of `path` well behind its modification time, so that
/// `relatime` updates it on the next plain read.
fn backdate_atime(path: &Path) {
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    std::fs::File::open(path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_accessed(old))
        .unwrap();
}

#[test]
fn the_check_moves_no_access_time_of_what_it_looks_at() {
    let dir = tempfile::tempdir().unwrap();
    // Unless a plain listing moves a folder's access time here, keeping it
    // proves nothing.
    let probe = dir.path().join("probe");
    std::fs::create_dir(&probe).unwrap();
    backdate_atime(&probe);
    let before = atime(&probe);
    let _ = std::fs::read_dir(&probe).unwrap().count();
    if atime(&probe) == before {
        eprintln!("skipping: the temp filesystem does not record access times");
        return;
    }

    // A root that is scanned, and a top level that is refused after its
    // listing and a look at each of its entries.
    let decoy = dir.path().join("decoy");
    let top = dir.path().join("top");
    let looked_at = [
        decoy.join("etc"),
        decoy.clone(),
        top.join("@/etc"),
        top.join("@"),
        top.join("@home"),
        top.clone(),
    ];
    for path in &looked_at[..3] {
        std::fs::create_dir_all(path).unwrap();
    }
    std::fs::create_dir(&looked_at[4]).unwrap();
    for path in &looked_at {
        backdate_atime(path);
    }
    let before: Vec<_> = looked_at.iter().map(|path| atime(path)).collect();
    let verifier = Verifier::new(RealFilesystem);
    verifier.refuse_a_root_with_nothing_to_scan(&decoy).unwrap();
    verifier
        .refuse_a_root_with_nothing_to_scan(&top)
        .unwrap_err();
    let after: Vec<_> = looked_at.iter().map(|path| atime(path)).collect();
    assert_eq!(after, before, "an access time moved: {looked_at:?}");
}
