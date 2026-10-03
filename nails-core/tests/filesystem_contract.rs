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
//! The contract covers the non-privileged operations both implementations can
//! perform without root: file read/write, size, existence and type queries,
//! directory creation, symlinks, rename, removal and secure deletion. Mount,
//! swap and other privileged operations cannot run unprivileged against the real
//! filesystem, so they remain mock-only tests at the bottom of this file.

use nails_core::NailsError;
use nails_core::filesystem::{Filesystem, MockFilesystem, PathKind, RealFilesystem};
use nails_core::preflight::{SwapSeverity, classify_swap};
use std::path::Path;

// ============================================================================
// Shared contract exercised by both implementations
// ============================================================================

/// Exercise the shared, unprivileged filesystem contract against `fs`, using
/// `root` as a pre-existing, writable directory to work inside.
fn filesystem_contract<F: Filesystem>(fs: &F, root: &Path) {
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

    filesystem_contract(&fs, root);
}

#[test]
fn real_filesystem_satisfies_contract() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let fs = RealFilesystem;

    filesystem_contract(&fs, temp.path());
}

// ============================================================================
// Mock-only: Overlay mount operations (require privileges against the real FS)
// ============================================================================

#[test]
fn mount_overlay_succeeds_with_valid_paths() {
    let fs = MockFilesystem::new();
    let upper = Path::new("/mnt/hidden/upper");
    let work = Path::new("/mnt/hidden/work");
    let target = Path::new("/home");

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/upper", true);
    fs.mock_set_path_exists("/mnt/hidden/work", true);

    fs.mount_overlay(&[Path::new("/")], upper, work, target)
        .unwrap();
    assert!(fs.is_mounted(target).unwrap());
}

#[test]
fn mount_overlay_fails_if_target_already_overlay_mounted() {
    let fs = MockFilesystem::new();
    let target = Path::new("/home");

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/upper", true);
    fs.mock_set_path_exists("/mnt/hidden/work", true);
    fs.mock_set_overlay_mounted(target, true);

    let result = fs.mount_overlay(
        &[Path::new("/")],
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        target,
    );
    assert!(matches!(
        result.unwrap_err(),
        NailsError::AlreadyMounted { .. }
    ));
}

#[test]
fn mount_overlay_keeps_every_lower_layer() {
    let fs = MockFilesystem::new();
    let lowers = [
        Path::new("/"),
        Path::new("/extra-lower"),
        Path::new("/more"),
    ];
    let target = Path::new("/home");

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/extra-lower", true);
    fs.mock_set_path_exists("/more", true);
    fs.mock_set_path_exists("/mnt/hidden/upper", true);
    fs.mock_set_path_exists("/mnt/hidden/work", true);

    fs.mount_overlay(
        &lowers,
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        target,
    )
    .unwrap();

    let info = fs.mock_get_mount_info(target).unwrap();
    assert_eq!(
        info.lowers,
        vec![
            Path::new("/").to_path_buf(),
            Path::new("/extra-lower").to_path_buf(),
            Path::new("/more").to_path_buf(),
        ],
        "every lower layer must be retained, not just the primary"
    );
    assert_eq!(info.primary_lower(), Some(Path::new("/")));
}

#[test]
fn is_overlay_mounted_distinguishes_generic_mounts() {
    let fs = MockFilesystem::new();
    let target = Path::new("/home");

    fs.mock_set_mounted(target, true);
    assert!(fs.is_mounted(target).unwrap());
    assert!(!fs.is_overlay_mounted(target).unwrap());

    fs.mock_set_overlay_mounted(target, true);
    assert!(fs.is_overlay_mounted(target).unwrap());
}

#[test]
fn mount_overlay_validates_lower_path_exists() {
    let fs = MockFilesystem::new();
    let result = fs.mount_overlay(
        &[Path::new("/nonexistent")],
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    );
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string().to_lowercase();
    assert!(
        err_msg.contains("lower")
            || err_msg.contains("not found")
            || err_msg.contains("does not exist")
    );
}

#[test]
fn mount_overlay_validates_upper_path_exists() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/upper", false);

    let result = fs.mount_overlay(
        &[Path::new("/")],
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    );
    assert!(result.unwrap_err().to_string().contains("upper"));
}

#[test]
fn mount_overlay_validates_work_path_exists() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/upper", true);
    fs.mock_set_path_exists("/mnt/hidden/work", false);

    let result = fs.mount_overlay(
        &[Path::new("/")],
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    );
    assert!(result.unwrap_err().to_string().contains("work"));
}

// ============================================================================
// Mock-only: Unmount operations
// ============================================================================

#[test]
fn unmount_succeeds_when_mounted() {
    let fs = MockFilesystem::new();
    let target = Path::new("/home");
    fs.mock_set_mounted(target, true);

    fs.unmount(target, false).unwrap();
    assert!(!fs.is_mounted(target).unwrap());
}

#[test]
fn unmount_idempotent_when_not_mounted() {
    let fs = MockFilesystem::new();
    assert!(fs.unmount(Path::new("/home"), false).is_ok());
}

#[test]
fn unmount_force_flag_overrides_busy_check() {
    let fs = MockFilesystem::new();
    let target = Path::new("/home");
    fs.mock_set_mounted(target, true);
    fs.mock_set_busy(target, true);

    let no_force = fs.unmount(target, false);
    assert!(no_force.unwrap_err().to_string().contains("busy"));
    assert!(fs.unmount(target, true).is_ok());
}

#[test]
fn unmount_removes_from_mounted_state() {
    let fs = MockFilesystem::new();
    let target = Path::new("/home");
    fs.mock_set_mounted(target, true);
    assert!(fs.get_mounted_paths().contains(&target.to_path_buf()));

    fs.unmount(target, false).unwrap();
    assert!(!fs.get_mounted_paths().contains(&target.to_path_buf()));
}

// ============================================================================
// Mock-only: Mount status queries and swap management
// ============================================================================

#[test]
fn is_mounted_reflects_state() {
    let fs = MockFilesystem::new();
    let target = Path::new("/home");
    assert!(!fs.is_mounted(target).unwrap());
    fs.mock_set_mounted(target, true);
    assert!(fs.is_mounted(target).unwrap());
}

#[test]
fn swap_classifier_reflects_seeded_state() {
    let fs = MockFilesystem::new();
    assert_eq!(classify_swap(&fs).severity, SwapSeverity::Pass);
    fs.mock_set_swap_enabled(true);
    assert_eq!(classify_swap(&fs).severity, SwapSeverity::Fail);
}

// ============================================================================
// Mock-only: Permission and disk-usage helpers
// ============================================================================

#[test]
fn disk_usage_returns_total_and_available_bytes() {
    let fs = MockFilesystem::new();
    let path = Path::new("/mnt/hidden-volume");
    let total = 4 * 1024 * 1024 * 1024;
    let free = 1024 * 1024 * 1024;
    fs.mock_set_disk_usage(path, total, free);

    let usage = fs.disk_usage(path).unwrap();
    assert_eq!(usage.total, total);
    assert_eq!(usage.available, free);
    assert_eq!(usage.used(), total - free);
}

#[test]
fn create_directory_fails_without_write_permission() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt/hidden-volume", true);
    fs.mock_set_writable("/mnt/hidden-volume", false);

    let result = fs.create_directory(Path::new("/mnt/hidden-volume/upper"));
    let err_msg = result.unwrap_err().to_string().to_lowercase();
    assert!(
        err_msg.contains("permission")
            || err_msg.contains("writable")
            || err_msg.contains("denied")
    );
}

#[test]
fn is_readable_returns_false_for_untracked_path() {
    let fs = MockFilesystem::new();
    assert!(!fs.is_readable(Path::new("/mnt/hidden-volume")).unwrap());
}

#[test]
fn is_writable_reflects_state() {
    let fs = MockFilesystem::new();
    let path = "/mnt/hidden-volume";
    fs.mock_set_writable(path, true);
    assert!(fs.is_writable(Path::new(path)).unwrap());
    fs.mock_set_writable(path, false);
    assert!(!fs.is_writable(Path::new(path)).unwrap());
}

// ============================================================================
// Mock-only: State management, cloning and thread safety
// ============================================================================

#[test]
fn mock_filesystem_new_starts_empty() {
    let fs = MockFilesystem::new();
    assert!(fs.get_mounted_paths().is_empty());
    assert_eq!(classify_swap(&fs).severity, SwapSeverity::Pass);
}

#[test]
fn mock_filesystem_reset_clears_state() {
    let fs = MockFilesystem::new();
    fs.mock_set_mounted(Path::new("/home"), true);

    fs.reset();
    assert!(fs.get_mounted_paths().is_empty());
}

#[test]
fn mock_filesystem_clone_shares_state() {
    let fs1 = MockFilesystem::new();
    fs1.mock_set_mounted(Path::new("/home"), true);

    let fs2 = fs1.clone();
    assert!(fs2.is_mounted(Path::new("/home")).unwrap());

    fs2.unmount(Path::new("/home"), false).unwrap();
    assert!(!fs1.is_mounted(Path::new("/home")).unwrap());
    assert!(!fs2.is_mounted(Path::new("/home")).unwrap());
}

#[test]
fn mock_filesystem_default_matches_new() {
    let fs = MockFilesystem::default();
    assert!(fs.get_mounted_paths().is_empty());
    assert_eq!(classify_swap(&fs).severity, SwapSeverity::Pass);
}

#[test]
fn mock_filesystem_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MockFilesystem>();
}

#[test]
fn mock_filesystem_usable_across_threads() {
    let fs = MockFilesystem::new();
    let fs_clone = fs.clone();
    let handle = std::thread::spawn(move || {
        let _ = fs_clone.path_exists(Path::new("/test"));
    });
    handle.join().unwrap();
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
