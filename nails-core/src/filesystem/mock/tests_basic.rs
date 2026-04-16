use super::MockFilesystem;
use crate::filesystem::Filesystem;
use std::path::Path;

#[test]
fn test_mock_filesystem_new_starts_empty() {
    let fs = MockFilesystem::new();
    assert!(fs.get_mounted_paths().is_empty());
    assert!(!fs.swap_is_enabled().unwrap());
}

#[test]
fn test_mock_filesystem_reset_clears_state() {
    let fs = MockFilesystem::new();
    fs.mock_set_mounted(Path::new("/home"), true);
    fs.mock_set_swap_enabled(true);
    fs.reset();
    assert!(fs.get_mounted_paths().is_empty());
    assert!(!fs.swap_is_enabled().unwrap());
}

#[test]
fn test_mock_filesystem_clone_shares_state() {
    let fs1 = MockFilesystem::new();
    fs1.mock_set_mounted(Path::new("/home"), true);

    let fs2 = fs1.clone();
    assert!(fs2.is_mounted(Path::new("/home")).unwrap());

    fs2.mock_set_mounted(Path::new("/tmp"), true);
    assert!(fs1.is_mounted(Path::new("/tmp")).unwrap());
}

#[test]
fn test_mock_filesystem_nixos_build_profile_adds_profile() {
    let fs = MockFilesystem::new();

    assert!(fs.nixos_build_profile("test-profile").is_ok());
    assert!(fs.nixos_profile_exists("test-profile").unwrap());
    assert!(fs.nixos_build_profile("test-profile").is_ok());
}

#[test]
fn test_mock_set_mounted_can_unmount() {
    let fs = MockFilesystem::new();
    let path = Path::new("/test/mount");

    fs.mock_set_mounted(path, true);
    assert!(fs.is_mounted(path).unwrap());

    fs.mock_set_mounted(path, false);
    assert!(!fs.is_mounted(path).unwrap());
}

#[test]
fn test_mock_filesystem_swap_is_disabled_by_default() {
    let fs = MockFilesystem::new();
    assert!(!fs.swap_is_enabled().unwrap());

    fs.mock_set_swap_enabled(true);
    assert!(fs.swap_is_enabled().unwrap());

    fs.mock_set_swap_enabled(false);
    assert!(!fs.swap_is_enabled().unwrap());
}

#[test]
fn test_mock_filesystem_directory_operations() {
    let fs = MockFilesystem::new();
    let path = Path::new("/test/dir");

    fs.mock_set_path_exists("/test/dir", true);
    fs.mock_set_path_type("/test/dir", "directory");

    assert!(fs.path_exists(path).unwrap());
    assert!(fs.is_directory(path).unwrap());
}

#[test]
fn test_mock_filesystem_file_permissions() {
    let fs = MockFilesystem::new();
    let path = Path::new("/test/file");

    fs.mock_set_path_exists("/test/file", true);
    fs.mock_set_readable("/test/file", true);
    fs.mock_set_writable("/test/file", true);

    assert!(fs.is_readable(path).unwrap());
    assert!(fs.is_writable(path).unwrap());
}
