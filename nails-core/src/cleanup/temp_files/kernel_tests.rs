// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The temp-file cleaner on a real `/tmp`: a private tmpfs mounted over it in
//! a user + mount namespace (see `crate::test_support`), so the real
//! directory walk, removal and preservation run with no effect on the host.

use super::TempFilesCleaner;
use crate::RealFilesystem;
use crate::test_support::Rerun;
use std::path::{Path, PathBuf};

#[test]
fn clean_removes_nails_temp_files_and_keeps_configs_and_preserved_paths() {
    let _ = Rerun::new(crate::test_path!(
        clean_removes_nails_temp_files_and_keeps_configs_and_preserved_paths
    ))
    .in_user_mount_ns()
    .run(|| {
        nix::mount::mount(
            Some("tmpfs"),
            "/tmp",
            Some("tmpfs"),
            nix::mount::MsFlags::empty(),
            None::<&str>,
        )
        .expect("a private /tmp");
        std::fs::create_dir("/tmp/sub").unwrap();
        for file in [
            "/tmp/nails-12345.lock",
            "/tmp/nails-status.stdout",
            "/tmp/sub/NAILS-inner.lock",
            "/tmp/nails-headless.yaml",
            "/tmp/nails-overlay.toml",
            "/tmp/nails-keep.lock",
            "/tmp/unrelated.txt",
        ] {
            std::fs::write(file, "x").unwrap();
        }

        let mut cleaned = TempFilesCleaner::new(RealFilesystem)
            .with_preserved_paths(vec![PathBuf::from("/tmp/nails-keep.lock")])
            .clean()
            .expect("clean /tmp");
        cleaned.sort();

        assert_eq!(
            cleaned,
            vec![
                "Removed /tmp/nails-12345.lock",
                "Removed /tmp/nails-status.stdout",
                "Removed /tmp/sub/NAILS-inner.lock",
            ]
        );
        for gone in [
            "/tmp/nails-12345.lock",
            "/tmp/nails-status.stdout",
            "/tmp/sub/NAILS-inner.lock",
        ] {
            assert!(!Path::new(gone).exists(), "{gone} is removed");
        }
        for kept in [
            "/tmp/nails-headless.yaml",
            "/tmp/nails-overlay.toml",
            "/tmp/nails-keep.lock",
            "/tmp/unrelated.txt",
            "/tmp/sub",
        ] {
            assert!(Path::new(kept).exists(), "{kept} is kept");
        }

        // A second pass finds nothing left to remove.
        assert!(
            TempFilesCleaner::new(RealFilesystem)
                .with_preserved_paths(vec![PathBuf::from("/tmp/nails-keep.lock")])
                .clean()
                .unwrap()
                .is_empty()
        );
    });
}
