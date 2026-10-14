// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for the upper-filesystem capability check: the verdicts it maps a
//! probe to, and the probe steps against a real kernel, unprivileged or in a
//! private user and mount namespace for the xattr and the trial overlay.

use super::*;
use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
use crate::filesystem::MockFilesystem;
use crate::test_support::{Rerun, ScratchTmpfs};

#[test]
fn default_uses_default_hidden_root() {
    let check = UpperFsCapabilityCheck::default();
    assert_eq!(
        check.hidden_volume_root,
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
    );
}

#[test]
fn new_keeps_custom_root() {
    let custom = PathBuf::from("/custom/root");
    let check = UpperFsCapabilityCheck::new(custom.clone());
    assert_eq!(check.hidden_volume_root, custom);
}

#[test]
fn clone_preserves_root() {
    let check = UpperFsCapabilityCheck::new(PathBuf::from("/a/b"));
    assert_eq!(check.clone().hidden_volume_root, check.hidden_volume_root);
}

#[test]
fn trait_metadata_is_stable() {
    let check = UpperFsCapabilityCheck::default();
    assert_eq!(
        <UpperFsCapabilityCheck as PreFlightCheck<MockFilesystem>>::name(&check),
        "upper-fs-capability"
    );
    assert!(
        <UpperFsCapabilityCheck as PreFlightCheck<MockFilesystem>>::description(&check)
            .contains("overlayfs upper")
    );
}

#[test]
fn runs_hermetically_under_test_runtime() {
    // The host probe is skipped under the test binary, so the check passes
    // against the mock without touching any real filesystem. This also keeps
    // the registry wiring compiled and exercised. The mock presents an
    // attached hidden root (a volume mounted there) so the attach gate passes
    // and the check reaches the test-runtime skip rather than the not-attached
    // skip.
    let root = PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT);
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(root.to_str().unwrap(), true);
    fs.mock_set_mounted(&root, true);
    fs.mock_set_device_id(std::path::Path::new("/"), 1);
    fs.mock_set_device_id(&root, 42);
    let check = UpperFsCapabilityCheck::default();
    let result = check.run(&fs).unwrap();
    assert!(result.is_pass());
    assert!(result.message().contains("skipped"));
}

#[test]
fn skips_without_writing_when_hidden_root_is_not_attached() {
    // A hidden root that exists but is no mount point is an unmounted mount
    // point on the decoy disk. The probe must not create its `.probe-*`
    // scratch directory there, so the attach gate turns the check into a skip
    // (the hidden-volume check owns the operator-facing failure) before any
    // host interaction is attempted.
    let root = PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT);
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(root.to_str().unwrap(), true);
    let check = UpperFsCapabilityCheck::default();
    let result = check.run(&fs).unwrap();
    assert!(result.is_skipped(), "expected a skip, got {result:?}");
    assert!(
        result.message().contains("not attached"),
        "skip should explain the root is not attached: {}",
        result.message()
    );
}

#[test]
fn classify_xattr_names_fstype_and_recommends_local_fs() {
    let result = classify(MissingCapability::TrustedXattr, Some("nfs"));
    assert!(result.is_fail());
    let message = result.message();
    assert!(message.contains("nfs"));
    assert!(message.contains("xattr"));
    assert!(message.contains("ext4"));
}

#[test]
fn classify_trial_overlay_names_vfat() {
    let result = classify(MissingCapability::TrialOverlay, Some("vfat"));
    assert!(result.is_fail());
    let message = result.message();
    assert!(message.contains("vfat"));
    assert!(message.contains("overlay mount"));
}

#[test]
fn classify_dtype_without_fstype_is_still_actionable() {
    let result = classify(MissingCapability::DirEntryType, None);
    assert!(result.is_fail());
    let message = result.message();
    assert!(message.contains("d_type") || message.contains("DT_UNKNOWN"));
    assert!(message.contains("ext4"));
    // No fstype known: the "on a <fs> filesystem" clause is omitted entirely.
    assert!(!message.contains("is on a"));
}

#[test]
fn classify_overlay_backed_upper_names_overlay() {
    // A hidden root that is itself an overlayfs cannot be stacked as another
    // overlay's upperdir: the probe's first step (the reserved trusted.overlay
    // xattr) is already refused. The failure must name the overlay backend and
    // still recommend a local Linux filesystem. This mirrors the
    // `preflight-upper-fs-capability` e2e fixture, which drives the check with
    // an overlay-backed hidden root.
    let result = classify(MissingCapability::TrustedXattr, Some("overlay"));
    assert!(result.is_fail());
    let message = result.message();
    assert!(message.contains("cannot host an overlayfs upper layer"));
    assert!(message.contains("on a overlay filesystem"));
    assert!(message.contains("ext4"));
}

#[test]
fn classify_lists_unsupported_remote_and_fat_backends() {
    let result = classify(MissingCapability::TrustedXattr, Some("cifs"));
    let message = result.message();
    assert!(message.contains("NFS"));
    assert!(message.contains("FUSE"));
    assert!(message.contains("FAT/exFAT/NTFS"));
}

#[test]
fn a_probe_that_passes_names_the_hidden_root() {
    let check = UpperFsCapabilityCheck::new(PathBuf::from("/mnt/data"));
    let result = check.verdict(&MockFilesystem::new(), Ok(()));
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        result.message(),
        "Hidden root at /mnt/data can host an overlayfs upper layer"
    );
}

#[test]
fn a_missing_capability_names_the_filesystem_the_mount_table_reports() {
    let root = PathBuf::from("/mnt/data");
    let fs = MockFilesystem::new();
    fs.mock_set_filesystem_type(&root, "nfs4");
    let check = UpperFsCapabilityCheck::new(root);
    let result = check.verdict(
        &fs,
        Err(ProbeError::Missing(MissingCapability::DirEntryType)),
    );
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().contains("DT_UNKNOWN"),
        "{}",
        result.message()
    );
    assert!(
        result
            .message()
            .contains("The hidden root is on a nfs4 filesystem."),
        "{}",
        result.message()
    );
}

#[test]
fn a_missing_capability_names_the_filesystem_on_top_of_the_hidden_root() {
    // A FAT stick mounted over the hidden volume: the probe ran on the stick,
    // so the message names its filesystem, not the volume's below it.
    let fs = MockFilesystem::new();
    fs.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         30 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
         31 30 8:17 / /mnt/data rw - vfat /dev/sdb1 rw\n",
    );
    let check = UpperFsCapabilityCheck::new(PathBuf::from("/mnt/data"));
    let result = check.verdict(
        &fs,
        Err(ProbeError::Missing(MissingCapability::TrustedXattr)),
    );
    assert!(
        result
            .message()
            .contains("The hidden root is on a vfat filesystem."),
        "{}",
        result.message()
    );
}

#[test]
fn a_missing_capability_on_an_unknown_filesystem_leaves_the_type_out() {
    let check = UpperFsCapabilityCheck::new(PathBuf::from("/mnt/data"));
    let result = check.verdict(
        &MockFilesystem::new(),
        Err(ProbeError::Missing(MissingCapability::TrialOverlay)),
    );
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .contains("overlay mount over the hidden root failed")
    );
    assert!(
        !result.message().contains("is on a"),
        "{}",
        result.message()
    );
}

#[test]
fn a_broken_probe_fails_closed_with_the_io_error() {
    let check = UpperFsCapabilityCheck::new(PathBuf::from("/mnt/data"));
    let error = std::io::Error::from_raw_os_error(nix::libc::EROFS);
    let result = check.verdict(&MockFilesystem::new(), Err(ProbeError::Scaffold(error)));
    assert!(result.is_fail(), "{result:?}");
    let message = result.message();
    assert!(
        message.starts_with(
            "Could not verify the hidden root at /mnt/data can host an overlayfs upper layer"
        ),
        "{message}"
    );
    assert!(message.contains("Read-only file system"), "{message}");
    assert!(
        message.contains("writable, local Linux filesystem"),
        "{message}"
    );
}

#[test]
fn a_missing_hidden_root_is_a_scaffold_error_and_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("absent");
    match probe_upper_capabilities(&root) {
        Err(ProbeError::Scaffold(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
        other => panic!("expected a scaffold error, got {other:?}"),
    }
    assert!(!root.exists());
}

#[test]
fn a_path_with_a_nul_byte_is_refused_before_any_syscall() {
    use std::os::unix::ffi::OsStrExt;
    let path = Path::new(std::ffi::OsStr::from_bytes(b"/mnt/da\0ta"));
    match cstring(path) {
        Err(ProbeError::Scaffold(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
        }
        other => panic!("expected a scaffold error, got {other:?}"),
    }
    assert!(matches!(
        probe_trusted_xattr(path),
        Err(ProbeError::Scaffold(_))
    ));
    assert!(matches!(
        probe_dir_entry_type(path),
        Err(ProbeError::Scaffold(_))
    ));
}

#[test]
fn readdir_on_a_local_directory_reports_file_types() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("lower")).unwrap();
    std::fs::write(dir.path().join("seed"), b"seed").unwrap();
    probe_dir_entry_type(dir.path()).expect("tmp supports d_type");
}

#[test]
fn readdir_on_a_missing_directory_is_a_scaffold_error() {
    let dir = tempfile::tempdir().unwrap();
    match probe_dir_entry_type(&dir.path().join("absent")) {
        Err(ProbeError::Scaffold(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
        other => panic!("expected a scaffold error, got {other:?}"),
    }
}

#[test]
fn exercising_the_merged_view_creates_and_deletes_its_files() {
    // On a plain directory the same steps run as on the merged overlay: a
    // fresh file is written and removed, and the lower-only seed is removed.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("seed"), b"seed").unwrap();
    exercise_mounted_overlay(dir.path()).expect("the steps succeed");
    assert!(!dir.path().join("probe-create").exists());
    assert!(!dir.path().join("seed").exists());
}

#[test]
fn a_merged_view_that_lost_the_seed_cannot_store_a_whiteout() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        exercise_mounted_overlay(dir.path()),
        Err(ProbeError::Missing(MissingCapability::TrialOverlay))
    ));
    // The created file is still cleaned up before the seed step fails.
    assert!(!dir.path().join("probe-create").exists());
}

#[test]
fn a_trial_overlay_without_a_lower_dir_is_a_scaffold_error() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    assert!(matches!(
        probe_trial_overlay(
            &p.join("lower"),
            &p.join("upper"),
            &p.join("work"),
            &p.join("merged")
        ),
        Err(ProbeError::Scaffold(_))
    ));
}

#[test]
fn the_scratch_suffix_carries_the_pid_and_differs_between_calls() {
    let first = unique_suffix();
    let (pid, nanos) = first.split_once('-').unwrap();
    assert_eq!(pid, std::process::id().to_string());
    assert!(nanos.parse::<u128>().unwrap() > 0);
    std::thread::sleep(std::time::Duration::from_millis(1));
    assert_ne!(unique_suffix(), first);
}

#[test]
fn a_namespaced_root_lacks_trusted_xattrs_and_the_probe_leaves_no_scratch_dir() {
    // `trusted.*` needs CAP_SYS_ADMIN in the initial user namespace, which the
    // namespaced uid 0 never has: the probe stops at its first step, names
    // the xattr, and removes its scratch directory.
    let _ = Rerun::new(crate::test_path!(
        a_namespaced_root_lacks_trusted_xattrs_and_the_probe_leaves_no_scratch_dir
    ))
    .in_user_mount_ns()
    .run(|| {
        let hidden = ScratchTmpfs::new("");
        assert!(matches!(
            probe_upper_capabilities(hidden.path()),
            Err(ProbeError::Missing(MissingCapability::TrustedXattr))
        ));
        let left: Vec<_> = std::fs::read_dir(hidden.path()).unwrap().collect();
        assert!(left.is_empty(), "the probe left {left:?}");
    });
}

#[test]
fn a_trial_overlay_on_tmpfs_stores_a_whiteout_and_unmounts() {
    let _ = Rerun::new(crate::test_path!(
        a_trial_overlay_on_tmpfs_stores_a_whiteout_and_unmounts
    ))
    .in_user_mount_ns()
    .run(|| {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let scratch = ScratchTmpfs::new("");
        let [lower, upper, work, merged] =
            ["lower", "upper", "work", "merged"].map(|d| scratch.mkdir(d));
        probe_trial_overlay(&lower, &upper, &work, &merged).expect("the trial overlay");

        // Deleting the lower-only seed left a whiteout (a 0:0 character
        // device) in the upper, and the lower itself is untouched.
        let whiteout = std::fs::symlink_metadata(upper.join("seed")).unwrap();
        assert!(whiteout.file_type().is_char_device());
        assert_eq!(whiteout.rdev(), 0);
        assert_eq!(std::fs::read(lower.join("seed")).unwrap(), b"seed");
        assert!(!upper.join("probe-create").exists());

        // The overlay is gone again: `merged` is an empty directory.
        let mounts = nails_teardown::mountinfo::read_mountinfo().unwrap();
        assert!(mounts.iter().all(|m| m.mount_point != merged));
        assert_eq!(std::fs::read_dir(&merged).unwrap().count(), 0);
    });
}
