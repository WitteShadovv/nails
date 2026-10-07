// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The snapshot pivot against the kernel, in a private user + mount
//! namespace (see `crate::test_support`): the snapshot tmpfs is sized from
//! the measured content, as the kernel's own mount table reports it.

use super::{snapshot_pivot_overlay_mount, snapshot_tmpfs_bytes};
use crate::filesystem::{Filesystem, RealFilesystem, read_mountinfo};
use crate::test_support::{Rerun, ScratchTmpfs};

#[test]
fn snapshot_pivot_sizes_its_tmpfs_from_the_measured_content() {
    let _ = Rerun::new(crate::test_path!(
        snapshot_pivot_sizes_its_tmpfs_from_the_measured_content
    ))
    .in_user_mount_ns()
    .run(|| {
        let scratch = ScratchTmpfs::new("");
        let target = scratch.mkdir("boot");
        let runtime = scratch.mkdir("run");
        let upper = scratch.mkdir("hidden/boot-upper");
        let work = scratch.mkdir("hidden/boot-work");
        // A 40 MiB "kernel image" on the target (sparse: cheap to create).
        let image = std::fs::File::create(target.join("vmlinuz")).unwrap();
        image.set_len(40 * 1024 * 1024).unwrap();
        drop(image);
        let fs = RealFilesystem;
        let measured = fs.get_directory_size(&target).unwrap();

        let pivot = snapshot_pivot_overlay_mount(&fs, &runtime, &[], &upper, &work, &target)
            .expect("snapshot pivot");

        // The kernel prints a tmpfs size in KiB, rounded up to whole pages.
        let page = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
            .unwrap()
            .unwrap() as u64;
        let pages = snapshot_tmpfs_bytes(measured).div_ceil(page);
        let want = format!("size={}k", pages * page / 1024);
        let snapshot = read_mountinfo()
            .unwrap()
            .into_iter()
            .find(|e| e.mount_point == pivot.lower)
            .expect("the snapshot tmpfs is mounted");
        assert_eq!(snapshot.fstype, "tmpfs");
        assert!(
            snapshot.super_opts.split(',').any(|o| o == want),
            "{want} in {}",
            snapshot.super_opts
        );
        assert_ne!(want, "size=1048576k", "not the old fixed gigabyte");

        // The target now shows the snapshot through the overlay, and a write
        // there lands in the hidden upper, not in the snapshot.
        assert_eq!(
            std::fs::metadata(target.join("vmlinuz")).unwrap().len(),
            40 * 1024 * 1024
        );
        std::fs::write(target.join("grub.cfg"), "hidden").unwrap();
        assert!(upper.join("grub.cfg").exists());
        assert!(!pivot.lower.join("grub.cfg").exists());
    });
}
