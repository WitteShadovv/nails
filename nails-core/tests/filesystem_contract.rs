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
//! directory creation, symlinks, rename, removal and secure deletion. The mount
//! contract (overlay mount and description, layer validation, unmount
//! idempotence, busy and lazy detach, the ownership gate, tmpfs, binds and the
//! read-only guard) runs the real filesystem as root of an unprivileged user and
//! mount namespace (`nails_core::test_support::Rerun`), so it needs no root
//! either. The mock's own helpers are tested in `filesystem/mock/tests_*.rs`.

use nails_core::NailsError;
use nails_core::filesystem::{Filesystem, MockFilesystem, PathKind, RealFilesystem};
use nails_core::test_path;
use nails_core::test_support::{Rerun, ScratchTmpfs};
use std::path::{Path, PathBuf};

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
// Shared mount contract: the mock against the kernel in a user namespace
// ============================================================================

/// Keep the mount at a path busy until the returned guard drops. The one lever
/// the trait cannot pull by itself: the kernel needs an open file under the
/// mount, the mock a flag.
type HoldBusy<'a> = &'a dyn Fn(&Path) -> Box<dyn std::any::Any>;

/// Exercise the mount half of the contract against `fs`, inside `root`, a
/// writable directory on a filesystem that accepts an overlay upper layer.
fn mount_contract<F: Filesystem>(fs: &F, root: &Path, hold_busy: HoldBusy<'_>) {
    overlay_mount_is_visible_and_described(fs, root);
    every_lower_layer_is_kept(fs, root);
    second_overlay_on_a_target_is_refused(fs, root);
    missing_layers_are_refused(fs, root);
    unmount_is_idempotent(fs, root);
    busy_overlay_needs_force(fs, root, hold_busy);
    generic_mounts_are_not_overlays(fs, root);
    read_only_guard_round_trip(fs, root);
}

/// The lower, upper, work and target directories of one overlay.
struct Layers {
    lowers: Vec<PathBuf>,
    upper: PathBuf,
    work: PathBuf,
    target: PathBuf,
}

impl Layers {
    fn create<F: Filesystem>(fs: &F, root: &Path, name: &str, lowers: usize) -> Self {
        let base = root.join(name);
        let dir = |rel: &str| {
            let path = base.join(rel);
            fs.create_directory(&path)
                .expect("create a layer directory");
            path
        };
        Self {
            lowers: (0..lowers).map(|i| dir(&format!("lower{i}"))).collect(),
            upper: dir("upper"),
            work: dir("work"),
            target: dir("merged"),
        }
    }

    fn mount<F: Filesystem>(&self, fs: &F) -> nails_core::Result<()> {
        let lowers: Vec<&Path> = self.lowers.iter().map(PathBuf::as_path).collect();
        fs.mount_overlay(&lowers, &self.upper, &self.work, &self.target)
    }
}

fn overlay_mount_is_visible_and_described<F: Filesystem>(fs: &F, root: &Path) {
    let layers = Layers::create(fs, root, "visible", 1);
    layers
        .mount(fs)
        .expect("mount an overlay over existing layers");

    assert!(fs.is_mounted(&layers.target).unwrap());
    assert!(fs.is_overlay_mounted(&layers.target).unwrap());
    assert_eq!(
        fs.get_filesystem_type(&layers.target).unwrap().as_deref(),
        Some("overlay")
    );
    let info = fs
        .get_mount_info(&layers.target)
        .expect("a mounted overlay is described");
    assert_eq!(info.lowers, layers.lowers);
    assert_eq!(info.upper, layers.upper);
    assert_eq!(info.work, layers.work);
    assert_eq!(info.target, layers.target);

    fs.unmount(&layers.target, false)
        .expect("unmount an idle overlay");
    assert!(!fs.is_mounted(&layers.target).unwrap());
    assert!(!fs.is_overlay_mounted(&layers.target).unwrap());
    assert_eq!(fs.get_filesystem_type(&layers.target).unwrap(), None);
    assert!(fs.get_mount_info(&layers.target).is_none());
}

fn every_lower_layer_is_kept<F: Filesystem>(fs: &F, root: &Path) {
    let layers = Layers::create(fs, root, "stacked", 3);
    layers
        .mount(fs)
        .expect("mount an overlay over three lowers");

    let info = fs.get_mount_info(&layers.target).unwrap();
    assert_eq!(
        info.lowers, layers.lowers,
        "every lower layer must be retained, in order, not just the primary"
    );
    assert_eq!(info.primary_lower(), Some(layers.lowers[0].as_path()));
    fs.unmount(&layers.target, false).unwrap();
}

fn second_overlay_on_a_target_is_refused<F: Filesystem>(fs: &F, root: &Path) {
    let layers = Layers::create(fs, root, "twice", 1);
    layers.mount(fs).unwrap();

    let again = layers.mount(fs).unwrap_err();
    assert!(
        matches!(again, NailsError::AlreadyMounted { .. }),
        "a second overlay on the same target is refused: {again:?}"
    );
    fs.unmount(&layers.target, false).unwrap();
    assert!(
        !fs.is_mounted(&layers.target).unwrap(),
        "one unmount clears it"
    );
}

fn missing_layers_are_refused<F: Filesystem>(fs: &F, root: &Path) {
    let layers = Layers::create(fs, root, "missing", 1);
    let lower = layers.lowers[0].as_path();
    let gone = root.join("missing/nowhere/at-all");
    let refuse = |lower: &Path, upper: &Path, work: &Path, word: &str| {
        let err = fs
            .mount_overlay(&[lower], upper, work, &layers.target)
            .expect_err("a missing layer is refused");
        let text = err.to_string().to_lowercase();
        assert!(
            text.contains(word),
            "the error names the {word} layer: {text}"
        );
        assert!(!fs.is_mounted(&layers.target).unwrap());
    };
    refuse(&gone, &layers.upper, &layers.work, "lower");
    refuse(lower, &gone, &layers.work, "upper");
    refuse(lower, &layers.upper, &gone, "work");

    // An upper whose parent exists passes the precondition ("can be created"),
    // but nothing creates it: the mount itself fails and nothing is mounted.
    let absent_upper = root.join("missing/absent-upper");
    assert!(
        fs.mount_overlay(&[lower], &absent_upper, &layers.work, &layers.target)
            .is_err(),
        "an overlay needs its upper directory to exist"
    );
    assert!(!fs.is_mounted(&layers.target).unwrap());
}

fn unmount_is_idempotent<F: Filesystem>(fs: &F, root: &Path) {
    let layers = Layers::create(fs, root, "idempotent", 1);
    fs.unmount(&layers.target, false)
        .expect("unmounting a directory that is no mount point is a no-op");
    layers.mount(fs).unwrap();
    fs.unmount(&layers.target, false).unwrap();
    fs.unmount(&layers.target, false)
        .expect("a second unmount is a no-op");
    fs.unmount(&layers.target, true)
        .expect("a forced unmount of nothing is a no-op");
}

fn busy_overlay_needs_force<F: Filesystem>(fs: &F, root: &Path, hold_busy: HoldBusy<'_>) {
    let layers = Layers::create(fs, root, "busy", 1);
    layers.mount(fs).unwrap();
    let guard = hold_busy(&layers.target);

    let err = fs.unmount(&layers.target, false).unwrap_err();
    assert!(
        matches!(err, NailsError::MountBusy { .. }),
        "a held overlay is busy, not some other failure: {err:?}"
    );
    assert!(
        fs.is_overlay_mounted(&layers.target).unwrap(),
        "still mounted"
    );

    // The forced unmount (MNT_FORCE | MNT_DETACH) takes it off the tree at
    // once; the holder keeps a private reference.
    fs.unmount(&layers.target, true)
        .expect("a busy overlay comes off with force");
    assert!(!fs.is_mounted(&layers.target).unwrap());

    // The teardown plan's escalation, the lazy detach, does the same.
    layers.mount(fs).unwrap();
    let second_guard = hold_busy(&layers.target);
    fs.detach_lazily(&layers.target)
        .expect("a busy overlay detaches lazily");
    assert!(!fs.is_mounted(&layers.target).unwrap());
    drop(second_guard);
    drop(guard);
}

fn generic_mounts_are_not_overlays<F: Filesystem>(fs: &F, root: &Path) {
    let tmpfs = root.join("generic/tmpfs");
    fs.mount_tmpfs(&tmpfs, "1M").expect("mount a tmpfs");
    assert!(fs.is_mounted(&tmpfs).unwrap());
    assert!(
        !fs.is_overlay_mounted(&tmpfs).unwrap(),
        "a tmpfs is no overlay"
    );
    assert!(fs.get_mount_info(&tmpfs).is_none());
    // Plain unmount is gated on NAILS ownership: a tmpfs outside the runtime
    // root is not NAILS's, so it is refused and left mounted.
    assert!(matches!(
        fs.unmount(&tmpfs, false).unwrap_err(),
        NailsError::RefusedUnmanagedUnmount { .. }
    ));
    assert!(fs.is_mounted(&tmpfs).unwrap());
    fs.unmount_tmpfs(&tmpfs).expect("unmount the tmpfs");
    assert!(!fs.is_mounted(&tmpfs).unwrap());
    fs.unmount_tmpfs(&tmpfs)
        .expect("a second tmpfs unmount is a no-op");
    for size in ["512M", "1024"] {
        let sized = root.join(format!("generic/tmpfs-{size}"));
        fs.mount_tmpfs(&sized, size).expect("a valid tmpfs size");
        assert!(fs.is_mounted(&sized).unwrap());
        fs.unmount_tmpfs(&sized).unwrap();
    }
    let bad = root.join("generic/tmpfs-bad");
    let err = fs.mount_tmpfs(&bad, "invalid").unwrap_err().to_string();
    assert!(err.contains("Invalid tmpfs size"), "{err}");
    assert!(!fs.is_mounted(&bad).unwrap(), "nothing is mounted");

    let source = root.join("generic/bind-source");
    let target = root.join("generic/bind-target");
    fs.create_directory(&source).unwrap();
    fs.create_directory(&target).unwrap();
    fs.bind_mount(&source, &target).expect("bind a directory");
    assert!(fs.is_mounted(&target).unwrap());
    assert!(
        !fs.is_overlay_mounted(&target).unwrap(),
        "a bind is no overlay"
    );
    assert!(matches!(
        fs.unmount(&target, false).unwrap_err(),
        NailsError::RefusedUnmanagedUnmount { .. }
    ));
    fs.unmount_bind(&target).expect("unmount the bind");
    assert!(!fs.is_mounted(&target).unwrap());
    fs.unmount_bind(&target)
        .expect("a second bind unmount is a no-op");
    assert!(
        fs.bind_mount(&root.join("generic/no-source"), &target)
            .is_err(),
        "a bind needs its source"
    );
}

fn read_only_guard_round_trip<F: Filesystem>(fs: &F, root: &Path) {
    let tree = root.join("guarded");
    fs.create_directory(&tree).unwrap();
    assert!(!fs.is_read_only_guard(&tree).unwrap());

    fs.remount_read_only(&tree).expect("guard a tree read-only");
    assert!(fs.is_read_only_guard(&tree).unwrap());
    assert!(fs.is_mount_read_only(&tree).unwrap());
    assert!(fs.is_mounted(&tree).unwrap(), "the guard is a self-bind");

    fs.remove_read_only_guard(&tree).expect("lift the guard");
    assert!(!fs.is_read_only_guard(&tree).unwrap());
    assert!(!fs.is_mount_read_only(&tree).unwrap());
    assert!(!fs.is_mounted(&tree).unwrap());
    fs.remove_read_only_guard(&tree)
        .expect("lifting a lifted guard is a no-op");
}

#[test]
fn mock_filesystem_satisfies_mount_contract() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/contract-root", PathKind::Dir);
    fs.mock_set_writable("/contract-root", true);
    let busy_fs = fs.clone();
    let hold_busy = move |target: &Path| -> Box<dyn std::any::Any> {
        busy_fs.mock_set_busy(target, true);
        Box::new(())
    };

    mount_contract(&fs, Path::new("/contract-root"), &hold_busy);
}

#[test]
fn real_filesystem_satisfies_mount_contract_in_a_user_namespace() {
    let _ = Rerun::new(test_path!(
        real_filesystem_satisfies_mount_contract_in_a_user_namespace
    ))
    .in_user_mount_ns()
    .run(|| {
        let scratch = ScratchTmpfs::new("");
        let root = scratch.path().canonicalize().unwrap();
        let hold_busy = |target: &Path| -> Box<dyn std::any::Any> {
            Box::new(std::fs::File::create(target.join("held")).expect("open a file inside"))
        };

        mount_contract(&RealFilesystem, &root, &hold_busy);
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
