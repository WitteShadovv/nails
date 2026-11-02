// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! An offline scan refuses a root that holds nothing to scan: a path that does
//! not exist, one that is not a folder, and an empty folder, which is what the
//! mount point of an image looks like when the image was never mounted. Each
//! of them used to read as a secure image, the examiner's view with no trace.

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
    named[0]
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
fn a_root_that_holds_files_is_scanned() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("etc")).unwrap();
    std::fs::write(
        root.path().join("etc/passwd"),
        "root:x:0:0::/root:/bin/sh\n",
    )
    .unwrap();
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
    // A folder the mock was given no listing of: listing it fails.
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
fn the_check_moves_no_access_time_of_the_root() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("etc")).unwrap();
    // Unless a plain listing moves the folder's access time here, keeping it
    // proves nothing.
    backdate_atime(root.path());
    let before = atime(root.path());
    let _ = std::fs::read_dir(root.path()).unwrap().count();
    if atime(root.path()) == before {
        eprintln!("skipping: the temp filesystem does not record access times");
        return;
    }

    backdate_atime(root.path());
    let before = atime(root.path());
    Verifier::new(RealFilesystem)
        .refuse_a_root_with_nothing_to_scan(root.path())
        .unwrap();
    assert_eq!(atime(root.path()), before, "the root's access time moved");
}
