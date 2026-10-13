// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Real-kernel semantics the mocks cannot show, without root.
//!
//! Each test re-runs itself in a fresh, unprivileged user + mount namespace (see
//! `nails_core::test_support`), mounts real tmpfs and overlayfs there, and asks
//! the production code to read the result back from the kernel. Every mount is
//! private to the child and vanishes when it exits. A host without user
//! namespaces skips the tests with a message; `NAILS_REQUIRE_USERNS=1` (set in
//! CI and by `just kernel-tests`) turns that skip into a failure.
//!
//! The overlays here are mounted with the production option string. Directory
//! whiteouts and opaque directories need `trusted.*` xattrs, which a user
//! namespace cannot set, so those stay in the root-only `privileged_mounts`
//! suite and the VM tests.

use nails_core::filesystem::{Filesystem, RealFilesystem, parse_overlay_opts, read_mountinfo};
use nails_core::test_path;
use nails_core::test_support::{Rerun, ScratchTmpfs};
use std::path::Path;
use std::time::{Duration, SystemTime};

/// The `mnt_id:` the kernel reports for an fd open on `path`.
fn fd_mount_id(file: &std::fs::File) -> i32 {
    use std::os::fd::AsRawFd;
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))
        .expect("read fdinfo");
    fdinfo
        .lines()
        .find_map(|l| l.strip_prefix("mnt_id:"))
        .and_then(|v| v.trim().parse().ok())
        .expect("fdinfo has a mnt_id line")
}

#[test]
fn live_overlay_mountinfo_round_trips_awkward_layer_paths() {
    let _ = Rerun::new(test_path!(
        live_overlay_mountinfo_round_trips_awkward_layer_paths
    ))
    .in_user_mount_ns()
    .run(|| {
        let scratch = ScratchTmpfs::new("");
        // Every character the overlay option parser or mountinfo escapes.
        let lower = scratch.mkdir("lower, with:colon");
        let upper = scratch.mkdir("upper\\dir");
        let work = scratch.mkdir("work dir");
        let target = scratch.mkdir("merged\tview");
        std::fs::write(lower.join("seed"), "from the lower").unwrap();

        let fs = RealFilesystem;
        nails_teardown::whole_root::nextroot::mount_overlay(&lower, &upper, &work, &target)
            .expect("mount the overlay");

        let entry = read_mountinfo()
            .unwrap()
            .into_iter()
            .find(|e| e.mount_point == target)
            .expect("the overlay is listed at its decoded mount point");
        assert_eq!(entry.fstype, "overlay");
        let opts = parse_overlay_opts(&entry.super_opts);
        assert_eq!(opts.lowerdir, vec![lower.clone()], "{}", entry.super_opts);
        assert_eq!(opts.upperdir.as_deref(), Some(upper.as_path()));
        assert_eq!(opts.workdir.as_deref(), Some(work.as_path()));
        assert_eq!(
            fs.get_filesystem_type(&target).unwrap().as_deref(),
            Some("overlay")
        );

        // An fd opened through the overlay carries exactly this mount id.
        let file = std::fs::File::open(target.join("seed")).unwrap();
        assert_eq!(fd_mount_id(&file), entry.mount_id);
        drop(file);

        nix::mount::umount(&target).expect("unmount the overlay");
        assert!(!fs.is_mounted(&target).unwrap());
    });
}

#[test]
fn copy_tree_leaves_source_atimes_untouched_on_a_strictatime_fs() {
    let _ = Rerun::new(test_path!(
        copy_tree_leaves_source_atimes_untouched_on_a_strictatime_fs
    ))
    .in_user_mount_ns()
    .run(|| {
        // strictatime: every read updates atime, so the control below proves
        // the filesystem would record a plain read. On a noatime host fs the
        // in-crate unit test passes whether or not O_NOATIME is used.
        let scratch = ScratchTmpfs::strictatime();
        let src = scratch.mkdir("src");
        let dst = scratch.mkdir("dst");
        let file = src.join("secret.txt");
        std::fs::write(&file, "watch my atime").unwrap();
        std::fs::write(src.join("control.txt"), "read me plainly").unwrap();
        let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        for path in [&file, &src.join("control.txt")] {
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_accessed(old))
                .unwrap();
        }
        set_dir_atime(&src, old);
        let atime = |p: &Path| std::fs::metadata(p).unwrap().accessed().unwrap();

        std::fs::read(src.join("control.txt")).unwrap();
        assert_ne!(
            atime(&src.join("control.txt")),
            old,
            "control: a plain read updates atime on this filesystem"
        );

        RealFilesystem.copy_tree(&src, &dst).expect("copy the tree");

        assert_eq!(atime(&file), old, "the copied file's atime is untouched");
        assert_eq!(atime(&src), old, "listing the source dir left its atime");
        assert_eq!(
            std::fs::read_to_string(dst.join("secret.txt")).unwrap(),
            "watch my atime"
        );
    });
}

#[test]
fn reading_the_fstab_in_a_root_leaves_its_atime_on_a_relatime_fs() {
    let _ = Rerun::new(test_path!(
        reading_the_fstab_in_a_root_leaves_its_atime_on_a_relatime_fs
    ))
    .in_user_mount_ns()
    .run(|| {
        // relatime, the kernel's default: a read updates an atime older than a
        // day, which the control below proves for this filesystem.
        let scratch = ScratchTmpfs::new("");
        let etc = scratch.mkdir("etc");
        let fstab = etc.join("fstab");
        let control = etc.join("control");
        std::fs::write(&fstab, "UUID=0a1b / ext4 defaults 0 1\n").unwrap();
        std::fs::write(&control, "read me plainly").unwrap();
        let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        for path in [&fstab, &control] {
            std::fs::File::open(path)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_accessed(old))
                .unwrap();
        }
        let atime = |p: &Path| std::fs::metadata(p).unwrap().accessed().unwrap();

        std::fs::read(&control).unwrap();
        assert_ne!(
            atime(&control),
            old,
            "control: a plain read updates atime on this filesystem"
        );

        let text = nails_teardown::whole_root::nextroot::read_in_root(
            scratch.path(),
            Path::new("/etc/fstab"),
        )
        .expect("read the fstab in the root");
        assert_eq!(text, b"UUID=0a1b / ext4 defaults 0 1\n");
        assert_eq!(atime(&fstab), old, "the fstab's atime is untouched");
    });
}

fn set_dir_atime(dir: &Path, when: SystemTime) {
    std::fs::File::open(dir)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_accessed(when))
        .unwrap();
}
