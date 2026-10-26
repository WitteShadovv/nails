// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for the upper-filesystem capability check: the verdicts it maps a
//! probe to, the probe steps that need no privileges, and, in
//! [`kernel_tests`], the probe against a real kernel in a private user and
//! mount namespace.

use super::*;
use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
use crate::filesystem::MockFilesystem;

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
    assert!(message.contains("overlay with its layers on the hidden root"));
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
            .contains("overlay with its layers on the hidden root could not be mounted or used")
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
fn a_kernel_without_a_detached_mount_fails_closed_and_says_why() {
    // fsopen(2) refused: no root, a kernel before 5.2, or a sandbox. The check
    // fails, says the probe never mounts where a mount table shows it, and
    // that nothing was written, rather than blaming the filesystem.
    let check = UpperFsCapabilityCheck::new(PathBuf::from("/mnt/data"));
    let error = std::io::Error::from_raw_os_error(nix::libc::EPERM);
    let result = check.verdict(
        &MockFilesystem::new(),
        Err(ProbeError::NoDetachedMount(error)),
    );
    assert!(result.is_fail(), "{result:?}");
    let message = result.message();
    assert!(
        message.starts_with(
            "Could not verify the hidden root at /mnt/data can host an overlayfs upper layer: \
             the kernel refused to set up a detached trial overlay (Operation not permitted"
        ),
        "{message}"
    );
    assert!(
        message.contains("never mounts one where a mount table would show it"),
        "{message}"
    );
    assert!(message.contains("Nothing was written."), "{message}");
    assert!(message.contains("as root"), "{message}");
    assert!(!message.contains("ext4"), "{message}");
}

#[test]
fn without_a_detached_mount_the_probe_writes_nothing() {
    // The context comes first: when the kernel cannot give one, the probe
    // stops before it creates its scratch directory, since the only other way
    // to try an overlay would be a mount the system can see.
    let dir = tempfile::tempdir().unwrap();
    let refused = Err(std::io::Error::from_raw_os_error(nix::libc::ENOSYS));
    match probe_upper_capabilities(dir.path(), refused) {
        Err(ProbeError::NoDetachedMount(e)) => {
            assert_eq!(e.raw_os_error(), Some(nix::libc::ENOSYS));
        }
        other => panic!("expected the detached-mount refusal, got {other:?}"),
    }
    let left: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert!(left.is_empty(), "the probe wrote {left:?}");
}

/// A descriptor to stand in for the overlay context in a test that fails
/// before the probe reaches it.
fn unused_context(dir: &Path) -> std::io::Result<OwnedFd> {
    std::fs::File::open(dir).map(OwnedFd::from)
}

#[test]
fn a_missing_hidden_root_is_a_scaffold_error_and_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("absent");
    match probe_upper_capabilities(&root, unused_context(dir.path())) {
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

/// `dir` opened the way `fsmount(2)` hands back a mount's root: a path-only
/// descriptor.
fn path_fd(dir: &Path) -> OwnedFd {
    use rustix::fs::{Mode, OFlags};
    rustix::fs::open(
        dir,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open the directory")
}

#[test]
fn exercising_the_merged_view_creates_and_deletes_its_files() {
    // On a plain directory the same steps run as on the overlay's root: a
    // fresh file is written and removed, and the lower-only seed is removed.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("seed"), b"seed").unwrap();
    exercise_mounted_overlay(path_fd(dir.path()).as_fd()).expect("the steps succeed");
    assert!(!dir.path().join("probe-create").exists());
    assert!(!dir.path().join("seed").exists());
}

#[test]
fn a_merged_view_that_lost_the_seed_cannot_store_a_whiteout() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        exercise_mounted_overlay(path_fd(dir.path()).as_fd()),
        Err(ProbeError::Missing(MissingCapability::TrialOverlay))
    ));
    // The created file is still cleaned up before the seed step fails.
    assert!(!dir.path().join("probe-create").exists());
}

#[test]
fn a_merged_view_that_already_holds_the_probe_file_is_refused() {
    // The probe creates its file exclusively, so it never writes through a
    // file (or a link) it did not make itself.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("probe-create"), b"kept").unwrap();
    std::fs::write(dir.path().join("seed"), b"seed").unwrap();
    assert!(matches!(
        exercise_mounted_overlay(path_fd(dir.path()).as_fd()),
        Err(ProbeError::Missing(MissingCapability::TrialOverlay))
    ));
    assert_eq!(
        std::fs::read(dir.path().join("probe-create")).unwrap(),
        b"kept"
    );
    assert!(dir.path().join("seed").exists());
}

#[test]
fn a_layer_path_that_cannot_be_an_overlay_option_is_a_scaffold_error() {
    // The options are built before the context is touched, so a stand-in
    // descriptor is never configured.
    let dir = tempfile::tempdir().unwrap();
    let result = mount_trial_overlay(
        unused_context(dir.path()).unwrap(),
        Path::new("/low\ner"),
        &dir.path().join("upper"),
        &dir.path().join("work"),
    );
    match result {
        Err(ProbeError::Scaffold(e)) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput),
        other => panic!("expected a scaffold error, got {other:?}"),
    }
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

/// The probe against a real kernel, each test as root of a private user and
/// mount namespace (`Rerun::in_user_mount_ns`), which stands in for the host:
/// what the probe would show PID 1, it shows this namespace. `trusted.*`
/// xattrs need root in the initial user namespace, so the whole probe stops at
/// its first step here; the steps after it are driven one by one. The whole
/// probe as real root is `the_upper_fs_probe_as_root_passes_and_leaves_nothing`
/// in `nails-core/tests/privileged_mounts.rs`.
mod kernel_tests {
    use super::*;
    use crate::test_support::{Rerun, ScratchTmpfs};

    /// The mount table, as a process that watches it sees it: its text, and
    /// the change event systemd (through libmount's monitor) waits for, a
    /// `POLLPRI` on `/proc/self/mountinfo`. A mount or an unmount anywhere in
    /// the namespace raises it; a detached mount never does.
    struct MountTableWatch {
        watched: std::fs::File,
        table: String,
    }

    impl MountTableWatch {
        fn start() -> Self {
            let watched = std::fs::File::open("/proc/self/mountinfo").expect("open mountinfo");
            Self {
                watched,
                table: Self::read(),
            }
        }

        fn read() -> String {
            std::fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo")
        }

        /// Whether a change was signalled since the last look.
        fn signalled(&self) -> bool {
            use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
            let mut fds = [PollFd::new(self.watched.as_fd(), PollFlags::POLLPRI)];
            poll(&mut fds, PollTimeout::ZERO).expect("poll mountinfo");
            fds[0]
                .revents()
                .is_some_and(|r| r.intersects(PollFlags::POLLPRI | PollFlags::POLLERR))
        }

        /// Fail unless the table reads as it did at the start and no change
        /// was signalled since the last look.
        fn assert_unchanged(&self, when: &str) {
            assert!(
                !self.signalled(),
                "{when}: the mount table signalled a change"
            );
            assert_eq!(Self::read(), self.table, "{when}: the mount table changed");
        }
    }

    #[test]
    fn the_watch_sees_an_overlay_mounted_the_ordinary_way() {
        // The control for the tests below: the same trial overlay mounted with
        // mount(2) in the namespace, as the probe once did, is signalled and
        // listed, and so is its unmount, so an unchanged table is no blind spot.
        let _ = Rerun::new(crate::test_path!(
            the_watch_sees_an_overlay_mounted_the_ordinary_way
        ))
        .in_user_mount_ns()
        .run(|| {
            let scratch = ScratchTmpfs::new("");
            let [lower, upper, work, merged] =
                ["lower", "upper", "work", "merged"].map(|d| scratch.mkdir(d));
            let watch = MountTableWatch::start();

            nails_teardown::whole_root::nextroot::mount_overlay(&lower, &upper, &work, &merged)
                .expect("an ordinary overlay mount");
            assert!(watch.signalled(), "the mount raised the change event");
            assert_ne!(MountTableWatch::read(), watch.table, "the table lists it");

            nix::mount::umount2(&merged, nix::mount::MntFlags::MNT_DETACH).expect("unmount");
            assert!(watch.signalled(), "the unmount raised it again");
            assert_eq!(MountTableWatch::read(), watch.table);
        });
    }

    /// Whether an overlay instance still holds `upper`: overlayfs refuses a
    /// second instance on an upper in use with `EBUSY` when the index is on.
    /// The second instance is never mounted; closing its context drops it.
    fn upper_in_use(lower: &Path, upper: &Path, work: &Path) -> bool {
        let context = overlay_context().expect("an overlay context");
        let params = nails_teardown::whole_root::nextroot::overlay_params(lower, upper, work)
            .expect("the layer options");
        for (key, value) in &params {
            let value = if *key == "index" {
                "on"
            } else {
                value.as_str()
            };
            rustix::mount::fsconfig_set_string(&context, *key, value).expect("an overlay option");
        }
        match rustix::mount::fsconfig_create(&context) {
            Ok(()) => false,
            Err(rustix::io::Errno::BUSY) => true,
            Err(errno) => panic!("a second overlay on the layers failed otherwise: {errno}"),
        }
    }

    #[test]
    fn the_trial_overlay_works_while_no_mount_table_lists_it() {
        let _ = Rerun::new(crate::test_path!(
            the_trial_overlay_works_while_no_mount_table_lists_it
        ))
        .in_user_mount_ns()
        .run(|| {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            let scratch = ScratchTmpfs::new("");
            let [lower, upper, work] = ["lower", "upper", "work"].map(|d| scratch.mkdir(d));
            std::fs::write(lower.join("seed"), b"seed").unwrap();
            let watch = MountTableWatch::start();

            let overlay = mount_trial_overlay(overlay_context().unwrap(), &lower, &upper, &work)
                .expect("the trial overlay");
            // It is a live overlay: its root shows the lower's seed, and it
            // carries the attributes the probe asks for...
            let seed = rustix::fs::statat(&overlay, "seed", rustix::fs::AtFlags::SYMLINK_NOFOLLOW);
            assert!(
                seed.is_ok(),
                "the overlay root shows the seed: {:?}",
                seed.err()
            );
            let flags = rustix::fs::fstatvfs(&overlay)
                .expect("statfs the overlay")
                .f_flag;
            let asked = rustix::fs::StatVfsMountFlags::NOSUID
                | rustix::fs::StatVfsMountFlags::NODEV
                | rustix::fs::StatVfsMountFlags::NOEXEC;
            assert!(flags.contains(asked), "{flags:?}");
            // ...yet the mount table neither lists it nor signalled a mount.
            watch.assert_unchanged("with the trial overlay mounted");

            exercise_mounted_overlay(overlay.as_fd()).expect("a new file and a whiteout");
            drop(overlay);
            watch.assert_unchanged("after the trial overlay was dropped");

            // The whiteout (a 0:0 character device) is in the upper, the
            // lower is untouched, and the new file is gone.
            let whiteout = std::fs::symlink_metadata(upper.join("seed")).unwrap();
            assert!(whiteout.file_type().is_char_device());
            assert_eq!(whiteout.rdev(), 0);
            assert_eq!(std::fs::read(lower.join("seed")).unwrap(), b"seed");
            assert!(!upper.join("probe-create").exists());
        });
    }

    #[test]
    fn the_trial_overlay_is_gone_once_its_descriptor_is() {
        let _ = Rerun::new(crate::test_path!(
            the_trial_overlay_is_gone_once_its_descriptor_is
        ))
        .in_user_mount_ns()
        .run(|| {
            let scratch = ScratchTmpfs::new("");
            let [lower, upper, work] = ["lower", "upper", "work"].map(|d| scratch.mkdir(d));
            std::fs::write(lower.join("seed"), b"seed").unwrap();

            let overlay = mount_trial_overlay(overlay_context().unwrap(), &lower, &upper, &work)
                .expect("the trial overlay");
            assert!(
                upper_in_use(&lower, &upper, &work),
                "the live trial overlay holds its upper"
            );
            drop(overlay);
            assert!(
                !upper_in_use(&lower, &upper, &work),
                "nothing holds the upper once the descriptor is closed"
            );
        });
    }

    #[test]
    fn a_trial_overlay_the_kernel_refuses_mounts_nothing() {
        // overlayfs needs the upper and work directories on one filesystem;
        // here they are on two, so the superblock is refused.
        let _ = Rerun::new(crate::test_path!(
            a_trial_overlay_the_kernel_refuses_mounts_nothing
        ))
        .in_user_mount_ns()
        .run(|| {
            let scratch = ScratchTmpfs::new("");
            let elsewhere = ScratchTmpfs::new("");
            let [lower, upper] = ["lower", "upper"].map(|d| scratch.mkdir(d));
            let work = elsewhere.mkdir("work");
            let watch = MountTableWatch::start();

            assert!(matches!(
                mount_trial_overlay(overlay_context().unwrap(), &lower, &upper, &work),
                Err(ProbeError::Missing(MissingCapability::TrialOverlay))
            ));
            watch.assert_unchanged("after the refused trial overlay");
        });
    }

    #[test]
    fn a_trial_overlay_on_a_missing_layer_is_refused() {
        let _ = Rerun::new(crate::test_path!(
            a_trial_overlay_on_a_missing_layer_is_refused
        ))
        .in_user_mount_ns()
        .run(|| {
            let scratch = ScratchTmpfs::new("");
            let [upper, work] = ["upper", "work"].map(|d| scratch.mkdir(d));
            let watch = MountTableWatch::start();

            assert!(matches!(
                mount_trial_overlay(
                    overlay_context().unwrap(),
                    &scratch.path().join("lower"),
                    &upper,
                    &work
                ),
                Err(ProbeError::Missing(MissingCapability::TrialOverlay))
            ));
            watch.assert_unchanged("after the refused trial overlay");
        });
    }

    #[test]
    fn a_namespaced_root_lacks_trusted_xattrs_and_the_probe_leaves_nothing() {
        // `trusted.*` needs CAP_SYS_ADMIN in the initial user namespace, which
        // the namespaced uid 0 never has: the probe stops at its first step,
        // names the xattr, removes its scratch directory and never touches the
        // mount table.
        let _ = Rerun::new(crate::test_path!(
            a_namespaced_root_lacks_trusted_xattrs_and_the_probe_leaves_nothing
        ))
        .in_user_mount_ns()
        .run(|| {
            let hidden = ScratchTmpfs::new("");
            let watch = MountTableWatch::start();
            assert!(matches!(
                probe_upper_capabilities(hidden.path(), overlay_context()),
                Err(ProbeError::Missing(MissingCapability::TrustedXattr))
            ));
            let left: Vec<_> = std::fs::read_dir(hidden.path()).unwrap().collect();
            assert!(left.is_empty(), "the probe left {left:?}");
            watch.assert_unchanged("after the probe");
        });
    }
}
