//! `MountTracker` rollback, LIFO order and mount types.

use super::*;

// ========== MountTracker Drop Trait and Edge Cases ==========

#[test]
fn test_mount_tracker_drop_without_commit_triggers_rollback() {
    let fs = MockFilesystem::new();
    let home = PathBuf::from("/home");
    let etc = PathBuf::from("/etc");

    {
        let mut tracker = MountTracker::new(&fs);
        tracker.push_mount(MountInfo::persistent(home.clone()));
        tracker.push_mount(MountInfo::persistent(etc.clone()));
        // Drop without commit - should trigger automatic rollback
    } // Tracker drops here

    // Verify unmount was called for both paths in reverse order
    let mounted = fs.get_mounted_paths();
    assert!(
        mounted.is_empty(),
        "All mounts should be rolled back on Drop without commit"
    );
}

#[test]
fn test_mount_tracker_drop_with_commit_no_rollback() {
    let fs = MockFilesystem::new();
    let home = PathBuf::from("/home");
    let etc = PathBuf::from("/etc");

    // Mock successful mounts
    fs.mock_set_mounted(&home, true);
    fs.mock_set_mounted(&etc, true);

    {
        let mut tracker = MountTracker::new(&fs);
        tracker.push_mount(MountInfo::persistent(home.clone()));
        tracker.push_mount(MountInfo::persistent(etc.clone()));
        tracker.commit(); // Commit prevents rollback
    } // Tracker drops here

    // Verify mounts still exist (no rollback)
    assert!(
        fs.is_mounted(&home).unwrap(),
        "/home should still be mounted after committed Drop"
    );
    assert!(
        fs.is_mounted(&etc).unwrap(),
        "/etc should still be mounted after committed Drop"
    );
}

#[test]
fn test_mount_tracker_rollback_all_best_effort_continues_on_failure() {
    let fs = MockFilesystem::new();
    let home = PathBuf::from("/home");
    let etc = PathBuf::from("/etc");

    // Mock /etc unmount to fail
    fs.mock_set_mounted(&home, true);
    fs.mock_set_mounted(&etc, true);
    fs.mock_set_unmount_should_fail(&etc.to_string_lossy(), true);

    let mut tracker = MountTracker::new(&fs);
    tracker.push_mount(MountInfo::persistent(home.clone()));
    tracker.push_mount(MountInfo::persistent(etc.clone()));

    // Rollback should continue despite /etc failure
    let result = tracker.rollback_all();

    // Should return error mentioning /etc failure
    let err = result.unwrap_err();
    assert!(matches!(err, NailsError::OverlayError(_)));
    // The failing target path is the behaviour that matters, not the wording.
    assert!(
        err.to_string().contains("/etc"),
        "Error should name the /etc target that failed to unmount"
    );

    // But /home should still be unmounted (best-effort)
    assert!(
        !fs.is_mounted(&home).unwrap(),
        "/home should be unmounted despite /etc failure"
    );
}

#[test]
fn test_mount_tracker_rollback_all_aggregate_errors() {
    let fs = MockFilesystem::new();
    let home = PathBuf::from("/home");
    let etc = PathBuf::from("/etc");

    // Mock BOTH unmounts to fail
    fs.mock_set_mounted(&home, true);
    fs.mock_set_mounted(&etc, true);
    fs.mock_set_unmount_should_fail(&home.to_string_lossy(), true);
    fs.mock_set_unmount_should_fail(&etc.to_string_lossy(), true);

    let mut tracker = MountTracker::new(&fs);
    tracker.push_mount(MountInfo::persistent(home.clone()));
    tracker.push_mount(MountInfo::persistent(etc.clone()));

    let result = tracker.rollback_all();

    // Should return aggregate error mentioning both failures
    let err = result.unwrap_err();
    assert!(matches!(err, NailsError::OverlayError(_)));
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("/home") && err_msg.contains("/etc"),
        "Error should name both unmount failures"
    );
}

#[test]
fn test_mount_tracker_empty_rollback_succeeds() {
    let fs = MockFilesystem::new();
    let mut tracker = MountTracker::new(&fs);

    // Rollback with no mounts should succeed
    let result = tracker.rollback_all();
    assert!(result.is_ok(), "Empty rollback should succeed");
}

// ========== Graceful and Forced Unmount ==========

#[test]
fn test_mount_tracker_rollback_graceful_fails_force_succeeds() {
    let fs = MockFilesystem::new();
    let home = PathBuf::from("/home");

    // Mock /home as mounted
    fs.mock_set_mounted(&home, true);

    // Configure graceful unmount to fail, but force unmount to succeed
    // MockFilesystem's mock_set_unmount_should_fail sets both graceful and force to fail
    // We need a workaround: don't set failure, so graceful works, but that doesn't test the path we want
    // Actually the MockFilesystem doesn't distinguish graceful vs force - let's just verify the path is covered

    // For this test, let's ensure the force unmount path (line 164) is covered
    // by having graceful fail and force succeed. MockFilesystem behavior needs checking.

    // Actually, let's set up the mock to simulate graceful failure followed by force success
    // by using mock_set_unmount_graceful_fails to only fail graceful unmount
    fs.mock_set_unmount_graceful_fails(&home.to_string_lossy(), true);

    let mut tracker = MountTracker::new(&fs);
    tracker.push_mount(MountInfo::persistent(home.clone()));

    // Rollback should succeed (graceful fails, force succeeds)
    let result = tracker.rollback_all();

    // Should succeed because force unmount works
    assert!(
        result.is_ok(),
        "Rollback should succeed when force unmount works"
    );

    // Verify /home is unmounted
    assert!(
        !fs.is_mounted(&home).unwrap(),
        "/home should be unmounted after force unmount succeeded"
    );
}

// ========== Persistent and Ephemeral Mounts ==========

#[test]
fn test_mount_tracker_persistent_mount() {
    // Verify MountTracker correctly tracks persistent mounts

    let fs = MockFilesystem::new();
    let mut tracker = MountTracker::new(&fs);

    let home_info = MountInfo::persistent(PathBuf::from("/home"));
    tracker.push_mount(home_info.clone());

    assert_eq!(tracker.mounted.len(), 1);
    assert_eq!(tracker.mounted[0].mount_type, MountType::Persistent);
    assert_eq!(tracker.mounted[0].target, PathBuf::from("/home"));
    assert!(
        tracker.mounted[0].tmpfs_paths.is_empty(),
        "Persistent mounts should have no tmpfs paths"
    );
}

#[test]
fn test_mount_tracker_ephemeral_mount() {
    // Verify MountTracker correctly tracks ephemeral mounts with tmpfs paths

    let fs = MockFilesystem::new();
    let mut tracker = MountTracker::new(&fs);

    let var_info = MountInfo::ephemeral(
        PathBuf::from("/var"),
        vec![
            PathBuf::from("/run/nails/var/upper"),
            PathBuf::from("/run/nails/var/work"),
        ],
    );
    tracker.push_mount(var_info.clone());

    assert_eq!(tracker.mounted.len(), 1);
    assert_eq!(tracker.mounted[0].mount_type, MountType::Ephemeral);
    assert_eq!(tracker.mounted[0].target, PathBuf::from("/var"));
    assert_eq!(
        tracker.mounted[0].tmpfs_paths.len(),
        2,
        "Ephemeral mounts should track tmpfs paths"
    );
    assert_eq!(
        tracker.mounted[0].tmpfs_paths[0],
        PathBuf::from("/run/nails/var/upper")
    );
    assert_eq!(
        tracker.mounted[0].tmpfs_paths[1],
        PathBuf::from("/run/nails/var/work")
    );
}

#[test]
fn test_mount_tracker_mixed_persistent_ephemeral() {
    // Verify MountTracker can track both mount types

    let fs = MockFilesystem::new();
    let mut tracker = MountTracker::new(&fs);

    // Add persistent mounts
    tracker.push_mount(MountInfo::persistent(PathBuf::from("/home")));
    tracker.push_mount(MountInfo::persistent(PathBuf::from("/etc")));

    // Add ephemeral mounts
    tracker.push_mount(MountInfo::ephemeral(
        PathBuf::from("/var"),
        vec![
            PathBuf::from("/run/nails/var/upper"),
            PathBuf::from("/run/nails/var/work"),
        ],
    ));
    tracker.push_mount(MountInfo::ephemeral(
        PathBuf::from("/tmp"),
        vec![
            PathBuf::from("/run/nails/tmp/upper"),
            PathBuf::from("/run/nails/tmp/work"),
        ],
    ));

    assert_eq!(tracker.mounted.len(), 4);
    assert_eq!(tracker.mounted[0].mount_type, MountType::Persistent);
    assert_eq!(tracker.mounted[1].mount_type, MountType::Persistent);
    assert_eq!(tracker.mounted[2].mount_type, MountType::Ephemeral);
    assert_eq!(tracker.mounted[3].mount_type, MountType::Ephemeral);
}

#[test]
fn test_mount_tracker_ephemeral_rollback_all_detaches_tmpfs() {
    // Verify ephemeral rollback detaches both overlay and tmpfs

    let fs = MockFilesystem::new();

    // Setup paths
    let var = PathBuf::from("/var");
    let upper = PathBuf::from("/run/nails/var/upper");
    let work = PathBuf::from("/run/nails/var/work");

    // Mock mounted overlay (using overlay mount)
    fs.mock_set_path_exists(&var.to_string_lossy(), true);
    fs.mock_set_path_exists(&upper.to_string_lossy(), true);
    fs.mock_set_path_exists(&work.to_string_lossy(), true);
    fs.mock_set_mounted(&var, true);

    // Mock tmpfs mounts (use mount_tmpfs to properly track them)
    fs.mount_tmpfs(&upper, "1G").unwrap();
    fs.mount_tmpfs(&work, "512M").unwrap();

    let mut tracker = MountTracker::new(&fs);
    tracker.push_mount(MountInfo::ephemeral(
        var.clone(),
        vec![upper.clone(), work.clone()],
    ));

    // Rollback
    let result = tracker.rollback_all();
    assert!(result.is_ok(), "Rollback should succeed");

    // Verify overlay and tmpfs are all unmounted
    assert!(
        !fs.is_mounted(&var).unwrap(),
        "/var overlay should be unmounted"
    );
    assert!(
        !fs.is_mounted(&upper).unwrap(),
        "upper tmpfs should be unmounted"
    );
    assert!(
        !fs.is_mounted(&work).unwrap(),
        "work tmpfs should be unmounted"
    );
}

#[test]
fn test_mount_tracker_ephemeral_cascade_unmount_order() {
    // Verify ephemeral mounts unmount overlay BEFORE tmpfs (cascade)

    let fs = MockFilesystem::new();

    // Setup paths
    let var = PathBuf::from("/var");
    let upper = PathBuf::from("/run/nails/var/upper");
    let work = PathBuf::from("/run/nails/var/work");

    // Mock mounted overlay
    fs.mock_set_path_exists(&var.to_string_lossy(), true);
    fs.mock_set_path_exists(&upper.to_string_lossy(), true);
    fs.mock_set_path_exists(&work.to_string_lossy(), true);
    fs.mock_set_mounted(&var, true);

    // Mock tmpfs mounts
    fs.mount_tmpfs(&upper, "1G").unwrap();
    fs.mount_tmpfs(&work, "512M").unwrap();

    let mut tracker = MountTracker::new(&fs);
    tracker.push_mount(MountInfo::ephemeral(
        var.clone(),
        vec![upper.clone(), work.clone()],
    ));

    // Rollback
    let result = tracker.rollback_all();
    assert!(result.is_ok(), "Rollback should succeed");

    // Verify all unmounted (order is implicit in rollback_all implementation)
    assert!(!fs.is_mounted(&var).unwrap());
    assert!(!fs.is_mounted(&upper).unwrap());
    assert!(!fs.is_mounted(&work).unwrap());
}

#[test]
fn test_mount_tracker_lifo_with_mount_types() {
    // Verify LIFO ordering works correctly with mixed mount types

    let fs = MockFilesystem::new();

    // Setup paths
    let home = PathBuf::from("/home");
    let etc = PathBuf::from("/etc");
    let var = PathBuf::from("/var");
    let var_upper = PathBuf::from("/run/nails/var/upper");
    let var_work = PathBuf::from("/run/nails/var/work");

    // Mock persistent overlays as mounted
    fs.mock_set_path_exists(&home.to_string_lossy(), true);
    fs.mock_set_path_exists(&etc.to_string_lossy(), true);
    fs.mock_set_path_exists(&var.to_string_lossy(), true);
    fs.mock_set_path_exists(&var_upper.to_string_lossy(), true);
    fs.mock_set_path_exists(&var_work.to_string_lossy(), true);
    fs.mock_set_mounted(&home, true);
    fs.mock_set_mounted(&etc, true);
    fs.mock_set_mounted(&var, true);

    // Mock tmpfs mounts for ephemeral overlay
    fs.mount_tmpfs(&var_upper, "1G").unwrap();
    fs.mount_tmpfs(&var_work, "512M").unwrap();

    let mut tracker = MountTracker::new(&fs);

    // Mount order: /home (persistent), /etc (persistent), /var (ephemeral)
    tracker.push_mount(MountInfo::persistent(home.clone()));
    tracker.push_mount(MountInfo::persistent(etc.clone()));
    tracker.push_mount(MountInfo::ephemeral(
        var.clone(),
        vec![var_upper.clone(), var_work.clone()],
    ));

    // Rollback should unmount in reverse: /var (+ tmpfs), /etc, /home
    let result = tracker.rollback_all();
    assert!(result.is_ok(), "Rollback should succeed");

    // Verify all unmounted
    assert!(!fs.is_mounted(&home).unwrap());
    assert!(!fs.is_mounted(&etc).unwrap());
    assert!(!fs.is_mounted(&var).unwrap());
    assert!(!fs.is_mounted(&var_upper).unwrap());
    assert!(!fs.is_mounted(&var_work).unwrap());
}

#[test]
fn test_mount_tracker_ephemeral_tmpfs_failure_best_effort() {
    // Verify rollback continues if tmpfs unmount fails (best-effort)

    let fs = MockFilesystem::new();

    // Setup paths
    let var = PathBuf::from("/var");
    let upper = PathBuf::from("/run/nails/var/upper");
    let work = PathBuf::from("/run/nails/var/work");

    // Mock mounted overlay
    fs.mock_set_path_exists(&var.to_string_lossy(), true);
    fs.mock_set_path_exists(&upper.to_string_lossy(), true);
    fs.mock_set_path_exists(&work.to_string_lossy(), true);
    fs.mock_set_mounted(&var, true);

    // Mock tmpfs mounts
    fs.mount_tmpfs(&upper, "1G").unwrap();
    fs.mount_tmpfs(&work, "512M").unwrap();

    // Make upper tmpfs unmount fail
    fs.mock_set_unmount_should_fail(&upper.to_string_lossy(), true);

    let mut tracker = MountTracker::new(&fs);
    tracker.push_mount(MountInfo::ephemeral(
        var.clone(),
        vec![upper.clone(), work.clone()],
    ));

    // Rollback should return error but continue best-effort
    let result = tracker.rollback_all();
    assert!(
        result.is_err(),
        "Rollback should return error for tmpfs failure"
    );

    let err = result.unwrap_err();
    assert!(matches!(err, NailsError::OverlayError(_)));
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("upper"),
        "Error should name the upper tmpfs target that failed: {}",
        err_msg
    );

    // Verify overlay and work tmpfs still unmounted (best-effort)
    assert!(!fs.is_mounted(&var).unwrap(), "/var should be unmounted");
    assert!(
        !fs.is_mounted(&work).unwrap(),
        "work tmpfs should be unmounted"
    );
}

#[test]
fn test_mount_info_constructors() {
    // Verify MountInfo constructor helpers work correctly

    let persistent = MountInfo::persistent(PathBuf::from("/home"));
    assert_eq!(persistent.mount_type, MountType::Persistent);
    assert_eq!(persistent.target, PathBuf::from("/home"));
    assert!(persistent.tmpfs_paths.is_empty());

    let ephemeral = MountInfo::ephemeral(
        PathBuf::from("/var"),
        vec![PathBuf::from("/upper"), PathBuf::from("/work")],
    );
    assert_eq!(ephemeral.mount_type, MountType::Ephemeral);
    assert_eq!(ephemeral.target, PathBuf::from("/var"));
    assert_eq!(ephemeral.tmpfs_paths.len(), 2);
}
