// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Filesystem trait contract suite.
//!
//! The same set of behavioural assertions is run against both filesystem
//! implementations: the in-memory [`MockFilesystem`] used by unit tests and the
//! real syscall-backed [`RealFilesystem`] rooted in a throwaway temp directory.
//! Running one contract over both is how we keep the mock honest — a mock that
//! drifts from the real filesystem's observable behaviour (a write that should
//! fail but silently succeeds, a size that disagrees with the content, a delete
//! that leaves the path behind) fails here rather than only in production.
//!
//! The file contract covers what both implementations do without root: file
//! read/write, size, existence, type and permission queries, disk usage,
//! directory creation, symlinks, rename, removal and secure deletion. The
//! mount-query contract (mount point, filesystem type, read-only flag and
//! source, the queries the session code reads) runs the real filesystem as
//! root of an unprivileged user and mount namespace
//! (`nails_core::test_support::Rerun`), so it needs no root either. The
//! mock's own helpers are tested in `filesystem/mock/tests_*.rs`.

use nails_core::filesystem::{Filesystem, MockFilesystem, MountSource, PathKind, RealFilesystem};
use nails_core::test_path;
use nails_core::test_support::{Rerun, ScratchTmpfs};
use nix::mount::MsFlags;
use std::path::Path;

// ============================================================================
// Shared contract exercised by both implementations
// ============================================================================

/// Take write permission on a directory away from the caller. Returns `false`
/// when the backend cannot (the real filesystem as root ignores modes).
type DenyWrites<'a> = &'a dyn Fn(&Path) -> bool;

/// Exercise the shared, unprivileged filesystem contract against `fs`, using
/// `root` as a pre-existing, writable directory to work inside.
fn filesystem_contract<F: Filesystem>(fs: &F, root: &Path, deny_writes: DenyWrites<'_>) {
    permission_behaviour(fs, root, deny_writes);
    disk_usage_is_consistent(fs, root);
    file_round_trip(fs, root);
    file_size_tracks_content(fs, root);
    missing_file_queries(fs, root);
    directory_creation(fs, root);
    symlink_behaviour(fs, root);
    rename_behaviour(fs, root);
    removal_behaviour(fs, root);
    secure_delete_behaviour(fs, root);
    write_into_missing_parent_fails(fs, root);
}

fn permission_behaviour<F: Filesystem>(fs: &F, root: &Path, deny_writes: DenyWrites<'_>) {
    let dir = root.join("guarded_dir");
    fs.create_directory(&dir).unwrap();
    assert!(
        fs.is_readable(&dir).unwrap(),
        "a created directory is readable"
    );
    assert!(
        fs.is_writable(&dir).unwrap(),
        "a created directory is writable"
    );
    assert!(
        !fs.is_readable(&root.join("never_made")).unwrap(),
        "a missing path is not readable"
    );

    if deny_writes(&dir) {
        assert!(!fs.is_writable(&dir).unwrap(), "write permission is gone");
        let err = fs
            .create_directory(&dir.join("child"))
            .expect_err("creating under an unwritable directory fails");
        let text = err.to_string().to_lowercase();
        assert!(
            text.contains("permission") || text.contains("denied") || text.contains("writable"),
            "the failure is a permission one: {text}"
        );
    }
}

fn disk_usage_is_consistent<F: Filesystem>(fs: &F, root: &Path) {
    let usage = fs.disk_usage(root).expect("disk usage of the working root");
    assert!(usage.total > 0, "a filesystem has a size");
    assert!(usage.available <= usage.total, "{usage:?}");
    assert_eq!(usage.used(), usage.total - usage.available);
}

fn file_round_trip<F: Filesystem>(fs: &F, root: &Path) {
    let file = root.join("round_trip.txt");
    fs.write_file_content(&file, "hello contract")
        .expect("write to an existing directory should succeed");

    assert!(
        fs.path_exists(&file).unwrap(),
        "a written file should report as existing"
    );
    assert_eq!(
        fs.read_file_content(&file).unwrap(),
        "hello contract",
        "read should return exactly what was written"
    );
    assert!(
        !fs.is_directory(&file).unwrap(),
        "a written file is not a directory"
    );
}

fn file_size_tracks_content<F: Filesystem>(fs: &F, root: &Path) {
    let file = root.join("sized.txt");
    let content = "0123456789"; // 10 bytes
    fs.write_file_content(&file, content).unwrap();
    assert_eq!(
        fs.file_size(&file).unwrap(),
        content.len() as u64,
        "file_size should equal the byte length of the content"
    );
}

fn missing_file_queries<F: Filesystem>(fs: &F, root: &Path) {
    let missing = root.join("definitely_absent");
    assert!(
        !fs.path_exists(&missing).unwrap(),
        "an untouched path should not exist"
    );
    assert!(
        fs.read_file_content(&missing).is_err(),
        "reading a missing file should error"
    );
    assert!(
        fs.file_size(&missing).is_err(),
        "sizing a missing file should error"
    );
}

fn directory_creation<F: Filesystem>(fs: &F, root: &Path) {
    let dir = root.join("made_dir");
    fs.create_directory(&dir)
        .expect("creating a directory under a writable parent should succeed");
    assert!(fs.path_exists(&dir).unwrap(), "created directory exists");
    assert!(
        fs.is_directory(&dir).unwrap(),
        "created directory reports as a directory"
    );

    // Nested creation (create parents) is supported by both implementations.
    let nested = dir.join("a").join("b");
    fs.create_directory(&nested)
        .expect("nested directory creation should succeed");
    assert!(fs.is_directory(&nested).unwrap());
}

fn symlink_behaviour<F: Filesystem>(fs: &F, root: &Path) {
    let target = root.join("symlink_target.txt");
    fs.write_file_content(&target, "target body").unwrap();

    let link = root.join("the_symlink");
    fs.create_symlink(&target, &link)
        .expect("creating a symlink should succeed");
    assert!(
        fs.is_symlink(&link).unwrap(),
        "a created symlink reports as a symlink"
    );
    assert!(
        !fs.is_symlink(&target).unwrap(),
        "a regular file does not report as a symlink"
    );

    // Creating the same symlink again is idempotent.
    fs.create_symlink(&target, &link)
        .expect("recreating an identical symlink is a no-op");
}

fn rename_behaviour<F: Filesystem>(fs: &F, root: &Path) {
    let from = root.join("rename_from.txt");
    let to = root.join("rename_to.txt");
    fs.write_file_content(&from, "moving").unwrap();

    fs.rename_file(&from, &to).expect("rename should succeed");
    assert!(
        !fs.path_exists(&from).unwrap(),
        "the source no longer exists after a rename"
    );
    assert_eq!(
        fs.read_file_content(&to).unwrap(),
        "moving",
        "the destination holds the renamed content"
    );
}

fn removal_behaviour<F: Filesystem>(fs: &F, root: &Path) {
    let file = root.join("to_remove.txt");
    fs.write_file_content(&file, "bye").unwrap();
    fs.remove_file(&file)
        .expect("removing a file should succeed");
    assert!(
        !fs.path_exists(&file).unwrap(),
        "a removed file no longer exists"
    );

    let dir = root.join("empty_to_remove");
    fs.create_directory(&dir).unwrap();
    fs.remove_directory(&dir)
        .expect("removing an empty directory should succeed");
    assert!(!fs.path_exists(&dir).unwrap());

    let tree = root.join("tree_to_remove");
    fs.create_directory(&tree).unwrap();
    fs.write_file_content(&tree.join("inner.txt"), "x").unwrap();
    fs.remove_dir_all(&tree)
        .expect("recursive removal should succeed");
    assert!(!fs.path_exists(&tree).unwrap());
}

fn secure_delete_behaviour<F: Filesystem>(fs: &F, root: &Path) {
    let file = root.join("secret.txt");
    fs.write_file_content(&file, "scrub me").unwrap();
    fs.secure_delete(&file)
        .expect("secure delete of a file should succeed");
    assert!(
        !fs.path_exists(&file).unwrap(),
        "a securely deleted file no longer exists"
    );

    let dir = root.join("secret_dir");
    fs.create_directory(&dir).unwrap();
    fs.write_file_content(&dir.join("inner.txt"), "scrub me too")
        .unwrap();
    fs.secure_delete_dir_all(&dir)
        .expect("secure delete of a directory tree should succeed");
    assert!(!fs.path_exists(&dir).unwrap());
}

fn write_into_missing_parent_fails<F: Filesystem>(fs: &F, root: &Path) {
    // Stage a directory, remove it, then write beneath the now-missing parent.
    // The real filesystem stages a temp file in the parent and renames it into
    // place, so it fails with NotFound; the mock mirrors that.
    let gone = root.join("gone_parent");
    fs.create_directory(&gone).unwrap();
    fs.remove_dir_all(&gone).unwrap();

    let orphan = gone.join("orphan.txt");
    assert!(
        fs.write_file_content(&orphan, "should not land").is_err(),
        "writing under a missing parent directory should fail in both implementations"
    );
}

// ============================================================================
// Contract harnesses
// ============================================================================

#[test]
fn mock_filesystem_satisfies_contract() {
    let fs = MockFilesystem::new();
    // Stand up a writable root directory for the contract to work inside.
    let root = Path::new("/contract-root");
    fs.mock_set_path_type("/contract-root", PathKind::Dir);
    fs.mock_set_writable("/contract-root", true);
    fs.mock_set_disk_usage(root, 4 << 30, 1 << 30);
    let seed_fs = fs.clone();
    let deny_writes = move |dir: &Path| {
        seed_fs.mock_set_writable(dir.to_str().unwrap(), false);
        true
    };

    filesystem_contract(&fs, root, &deny_writes);
}

#[test]
fn real_filesystem_satisfies_contract() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let fs = RealFilesystem;
    let deny_writes = |dir: &Path| {
        fs.set_permissions(dir, 0o555).unwrap();
        !nix::unistd::geteuid().is_root()
    };

    filesystem_contract(&fs, temp.path(), &deny_writes);
}

// ============================================================================
// Shared mount-query contract: the mock against the kernel in a user namespace
// ============================================================================

/// Put a tmpfs at `target` (an existing directory), read-only or not, the way
/// the backend can: the kernel mounts one, the mock records one.
type MountTmpfs<'a> = &'a dyn Fn(&Path, bool);

/// The source both backends give the tmpfs they put in place.
const TMPFS_SOURCE: &str = "contract-tmpfs";

/// Exercise the mount queries the session code reads (`is_mounted`, the
/// filesystem type, the read-only flag and the mount source) against `fs`,
/// inside `root`, a writable directory.
fn mount_query_contract<F: Filesystem>(fs: &F, root: &Path, mount_tmpfs: MountTmpfs<'_>) {
    let plain = root.join("plain");
    fs.create_directory(&plain).unwrap();
    assert!(!fs.is_mounted(&plain).unwrap(), "a directory is no mount");
    assert_eq!(fs.get_filesystem_type(&plain).unwrap(), None);
    assert!(
        !fs.is_mount_read_only(&plain).unwrap(),
        "no mount point reads as writable"
    );
    assert!(fs.mount_source(&plain).unwrap().is_none());

    for (name, read_only) in [("writable", false), ("read-only", true)] {
        let target = root.join(name);
        fs.create_directory(&target).unwrap();
        mount_tmpfs(&target, read_only);
        assert!(fs.is_mounted(&target).unwrap(), "{name} is mounted");
        assert_eq!(
            fs.get_filesystem_type(&target).unwrap().as_deref(),
            Some("tmpfs"),
            "{name}"
        );
        assert_eq!(fs.is_mount_read_only(&target).unwrap(), read_only, "{name}");
        let source = fs
            .mount_source(&target)
            .unwrap()
            .expect("a mount point has a source");
        assert_eq!(source.device.as_deref(), Some(TMPFS_SOURCE), "{name}");
        assert_eq!(source.dm_name, None, "a tmpfs is no device-mapper device");
    }
}

#[test]
fn mock_filesystem_satisfies_mount_query_contract() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/contract-root", PathKind::Dir);
    fs.mock_set_writable("/contract-root", true);
    let seed = fs.clone();
    let mount_tmpfs = move |target: &Path, read_only: bool| {
        seed.mock_set_mounted(target, true);
        seed.mock_set_filesystem_type(target, "tmpfs");
        seed.mock_set_mount_source(
            target,
            MountSource {
                device: Some(TMPFS_SOURCE.to_string()),
                dm_name: None,
                label: None,
            },
        );
        if read_only {
            seed.mock_set_mount_read_only(target);
        }
    };

    mount_query_contract(&fs, Path::new("/contract-root"), &mount_tmpfs);
}

#[test]
fn real_filesystem_satisfies_mount_query_contract_in_a_user_namespace() {
    let _ = Rerun::new(test_path!(
        real_filesystem_satisfies_mount_query_contract_in_a_user_namespace
    ))
    .in_user_mount_ns()
    .run(|| {
        let scratch = ScratchTmpfs::new("");
        let root = scratch.path().canonicalize().unwrap();
        let mount_tmpfs = |target: &Path, read_only: bool| {
            let flags = if read_only {
                MsFlags::MS_RDONLY
            } else {
                MsFlags::empty()
            };
            nix::mount::mount(
                Some(TMPFS_SOURCE),
                target,
                Some("tmpfs"),
                flags,
                Some("size=1M"),
            )
            .expect("mount a tmpfs in the namespace");
        };

        mount_query_contract(&RealFilesystem, &root, &mount_tmpfs);
    });
}

// ============================================================================
// Generic manager compiles over any Filesystem implementation
// ============================================================================

#[test]
fn generic_manager_compiles_over_any_filesystem() {
    struct GenericManager<F: Filesystem> {
        fs: F,
    }

    impl<F: Filesystem> GenericManager<F> {
        fn new(fs: F) -> Self {
            Self { fs }
        }

        fn check_mounted(&self, path: &Path) -> nails_core::Result<bool> {
            self.fs.is_mounted(path)
        }
    }

    let mock = GenericManager::new(MockFilesystem::new());
    assert!(!mock.check_mounted(Path::new("/home")).unwrap());

    // Compiles with RealFilesystem too; no privileged method is called.
    let _real = GenericManager::new(RealFilesystem);
}
