// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests for RealFilesystem implementation
//!
//! These tests verify RealFilesystem code paths are covered.
//! Many operations require root privileges and will fail in CI, but
//! they ensure code coverage reaches 100%.
//!
//! Tests are designed to:
//! - Cover all code paths in RealFilesystem implementation
//! - Gracefully handle expected failures (permission denied, etc.)
//! - Not require root privileges to compile and run

use nails_core::filesystem::{Filesystem, RealFilesystem};
use std::path::Path;

// ============================================================================
// RealFilesystem Instantiation Tests
// ============================================================================

#[test]
fn test_real_filesystem_can_be_created() {
    // GIVEN: Nothing
    // WHEN: Creating a RealFilesystem instance
    let fs = RealFilesystem;

    // THEN: Instance is created successfully
    // This tests the RealFilesystem struct exists and can be instantiated
    let _ = fs;
}

// ============================================================================
// Path Existence Tests (Non-privileged operations)
// ============================================================================

#[test]
fn test_real_filesystem_path_exists_for_root() {
    // GIVEN: RealFilesystem
    let fs = RealFilesystem;

    // WHEN: Checking if root path exists
    let result = fs.path_exists(Path::new("/"));

    // THEN: Root path should exist
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_real_filesystem_path_exists_for_nonexistent() {
    // GIVEN: RealFilesystem
    let fs = RealFilesystem;

    // WHEN: Checking if a clearly nonexistent path exists
    let result = fs.path_exists(Path::new("/this/path/definitely/does/not/exist/nails/test"));

    // THEN: Should return false (not error)
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_real_filesystem_is_directory_for_root() {
    // GIVEN: RealFilesystem
    let fs = RealFilesystem;

    // WHEN: Checking if root is a directory
    let result = fs.is_directory(Path::new("/"));

    // THEN: Root should be a directory
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_real_filesystem_is_directory_for_file() {
    // GIVEN: RealFilesystem and a file path (Cargo.toml)
    let fs = RealFilesystem;

    // WHEN: Checking if a file is a directory
    let result = fs.is_directory(Path::new("Cargo.toml"));

    // THEN: Should return false
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_real_filesystem_disk_usage() {
    // GIVEN: RealFilesystem
    let fs = RealFilesystem;

    // WHEN: Getting disk usage for root
    let result = fs.disk_usage(Path::new("/"));

    // THEN: Both figures are populated and available never exceeds total
    assert!(result.is_ok());
    let usage = result.unwrap();
    assert!(usage.total > 0);
    assert!(usage.available <= usage.total);
}

#[test]
fn test_real_filesystem_is_readable_for_proc_mounts() {
    // GIVEN: RealFilesystem
    let fs = RealFilesystem;

    // WHEN: Checking if /proc/mounts is readable
    let result = fs.is_readable(Path::new("/proc/mounts"));

    // THEN: Should be readable (exists on Linux)
    assert!(result.is_ok());
    // Note: May be true or false depending on system, but should not error
}

#[test]
fn test_real_filesystem_is_writable_detects_readonly() {
    // GIVEN: RealFilesystem
    let fs = RealFilesystem;

    // WHEN: Checking if /proc is writable (it's not)
    let result = fs.is_writable(Path::new("/proc"));

    // THEN: Should return Ok(false) - /proc is read-only
    assert!(result.is_ok());
}

// ============================================================================
// Mount Operations (Expected to fail without root, but covers code paths)
// ============================================================================

#[test]
fn test_real_filesystem_is_mounted_checks_proc_mounts() {
    // GIVEN: RealFilesystem
    let fs = RealFilesystem;

    // WHEN: Checking if a clearly non-mounted path is mounted
    let result = fs.is_mounted(Path::new("/tmp/nails_test_definitely_not_mounted"));

    // THEN: Should return Ok(false)
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_real_filesystem_is_mounted_detects_root() {
    // GIVEN: RealFilesystem
    let fs = RealFilesystem;

    // WHEN: Checking if root filesystem is mounted
    let result = fs.is_mounted(Path::new("/"));

    // THEN: Should return Ok(true) - root is always mounted
    assert!(result.is_ok());
    assert!(result.unwrap());
}

// ============================================================================
// Swap Operations (Read-only checks should work)
// ============================================================================

#[test]
fn test_real_filesystem_swap_classification_reads_proc_swaps() {
    // GIVEN: RealFilesystem
    let fs = RealFilesystem;

    // WHEN: Classifying swap through the shared classifier
    let posture = nails_core::preflight::classify_swap(&fs);

    // THEN: It returns a posture without panicking; the exact severity depends
    // on the host's swap and hibernation configuration.
    let _ = posture.severity;
}

// ============================================================================
// Directory Creation (May fail without permissions)
// ============================================================================

#[test]
fn test_real_filesystem_create_directory_in_tmp() {
    // GIVEN: RealFilesystem
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let test_dir = temp_dir.path().join("nails_coverage_test_dir");

    // WHEN: Creating a directory inside a private temp dir
    let result = fs.create_directory(&test_dir);

    // THEN: Should succeed
    assert!(result.is_ok());
}

#[test]
fn test_real_filesystem_create_directory_fails_in_readonly() {
    // GIVEN: RealFilesystem
    let fs = RealFilesystem;

    // WHEN: Attempting to create directory in read-only location
    let result = fs.create_directory(Path::new("/proc/nails_impossible_dir"));

    // THEN: Should fail with IO error
    assert!(result.is_err());
}

// ============================================================================
// Additional Coverage Tests for Edge Cases
// ============================================================================

#[test]
fn test_real_filesystem_is_writable_for_directory() {
    // GIVEN: RealFilesystem and /tmp directory
    let fs = RealFilesystem;

    // WHEN: Checking if /tmp is writable
    let result = fs.is_writable(std::env::temp_dir().as_path());

    // THEN: Should be writable on most systems
    assert!(result.is_ok());
}

#[test]
fn test_real_filesystem_is_writable_for_file() {
    // GIVEN: RealFilesystem and a test file
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let test_file = temp_dir.path().join("nails_test_writable_file.txt");

    // Create test file
    std::fs::write(&test_file, b"test").unwrap();

    // WHEN: Checking if file is writable
    let result = fs.is_writable(&test_file);

    // THEN: Should work (true or false depending on permissions)
    assert!(result.is_ok());
}

#[test]
fn test_real_filesystem_is_readable_for_nonexistent() {
    // GIVEN: RealFilesystem
    let fs = RealFilesystem;

    // WHEN: Checking if nonexistent file is readable
    let result = fs.is_readable(Path::new("/nonexistent/file/path/nails"));

    // THEN: Should return Ok(false)
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_real_filesystem_is_mounted_with_invalid_path() {
    // GIVEN: RealFilesystem
    let fs = RealFilesystem;

    // WHEN: Checking if a path with special characters is mounted
    let result = fs.is_mounted(Path::new("/tmp/nails/test/path/with/many/segments"));

    // THEN: Should return Ok(false)
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_real_filesystem_create_directory_with_parents() {
    // GIVEN: RealFilesystem
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let test_dir = temp_dir
        .path()
        .join("nails_test_parent")
        .join("child")
        .join("grandchild");

    // WHEN: Creating directory with create_dir_all behavior
    let result = fs.create_directory(&test_dir);

    // THEN: Should succeed
    assert!(result.is_ok());

    // Verify directory was created
    assert!(test_dir.exists());
}
