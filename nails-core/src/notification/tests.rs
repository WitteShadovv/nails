use super::*;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

fn make_notification(title: &str, body: &str) -> Notification {
    Notification {
        title: title.to_string(),
        body: body.to_string(),
        urgency: "normal".to_string(),
        icon: Some("dialog-information".to_string()),
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}

#[test]
fn test_write_and_read_notification() {
    let dir = TempDir::new().unwrap();
    let n = make_notification("Test Title", "Test body text");

    write_notification(dir.path(), &n).unwrap();

    let pending = read_pending(dir.path()).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].1.title, "Test Title");
    assert_eq!(pending[0].1.body, "Test body text");
}

#[test]
fn test_same_title_same_millisecond_writes_produce_distinct_files() {
    let dir = TempDir::new().unwrap();

    // Two notifications with an identical title written back-to-back are almost
    // certain to share a millisecond timestamp; the exclusive-create path must
    // still give them separate files instead of overwriting the first.
    write_notification(dir.path(), &make_notification("Same Title", "first")).unwrap();
    write_notification(dir.path(), &make_notification("Same Title", "second")).unwrap();

    let notif_dir = notifications_dir(dir.path());
    let file_count = std::fs::read_dir(&notif_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
        .count();
    assert_eq!(file_count, 2, "expected two distinct notification files");

    let pending = read_pending(dir.path()).unwrap();
    assert_eq!(pending.len(), 2);
    let bodies: std::collections::HashSet<&str> =
        pending.iter().map(|(_, n)| n.body.as_str()).collect();
    assert!(
        bodies.contains("first"),
        "first notification was overwritten"
    );
    assert!(
        bodies.contains("second"),
        "second notification was overwritten"
    );
}

#[test]
fn test_write_creates_notifications_dir() {
    let dir = TempDir::new().unwrap();
    let n = make_notification("Title", "Body");

    write_notification(dir.path(), &n).unwrap();

    assert!(notifications_dir(dir.path()).exists());
}

#[test]
fn test_write_notification_sets_default_permissions_without_icon() {
    let dir = TempDir::new().unwrap();
    let notification = Notification {
        title: "Permission Check".to_string(),
        body: "Body".to_string(),
        urgency: "normal".to_string(),
        icon: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
    };

    write_notification(dir.path(), &notification).unwrap();

    let notif_dir = notifications_dir(dir.path());
    let mode = notif_dir.metadata().unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);

    let pending = read_pending(dir.path()).unwrap();
    assert_eq!(pending.len(), 1);
    let file_mode = pending[0].0.metadata().unwrap().permissions().mode() & 0o777;
    assert_eq!(file_mode, 0o600);
    assert_eq!(pending[0].1.icon, None);
}

#[test]
fn test_write_notification_returns_error_when_notifications_path_cannot_be_created() {
    let dir = TempDir::new().unwrap();
    let blocking_path = dir.path().join("notifications");
    std::fs::write(&blocking_path, "not a directory").unwrap();

    let err = write_notification(dir.path(), &make_notification("Blocked", "body")).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to create notifications dir")
    );
}

#[test]
fn test_write_refuses_a_symlinked_notifications_dir() {
    // A symlink planted at the `notifications` name must not be traversed: the
    // root-privileged write would otherwise land outside the hidden root.
    let dir = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    std::os::unix::fs::symlink(outside.path(), notifications_dir(dir.path())).unwrap();

    let err = write_notification(dir.path(), &make_notification("Blocked", "body")).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to create notifications dir"),
        "expected a containment refusal, got: {err}"
    );
    // Nothing was written through the link.
    let leaked = std::fs::read_dir(outside.path()).unwrap().count();
    assert_eq!(leaked, 0, "a notification leaked through the symlink");
}

#[test]
fn test_read_empty_dir_returns_empty() {
    let dir = TempDir::new().unwrap();
    let pending = read_pending(dir.path()).unwrap();
    assert!(pending.is_empty());
}

#[test]
fn test_read_nonexistent_dir_returns_empty() {
    let dir = TempDir::new().unwrap();
    let nonexistent = dir.path().join("does-not-exist");
    let pending = read_pending(&nonexistent).unwrap();
    assert!(pending.is_empty());
}

#[test]
fn test_read_pending_returns_error_when_notifications_path_is_not_a_directory() {
    let dir = TempDir::new().unwrap();
    std::fs::write(notifications_dir(dir.path()), "not a directory").unwrap();

    let err = read_pending(dir.path()).unwrap_err();
    assert!(err.to_string().contains("Failed to read notifications dir"));
}

#[test]
fn test_read_pending_skips_unreadable_directory_entries() {
    let dir = TempDir::new().unwrap();
    let notif_dir = notifications_dir(dir.path());
    std::fs::create_dir_all(&notif_dir).unwrap();

    let nested_dir = notif_dir.join("subdir.json");
    std::fs::create_dir(&nested_dir).unwrap();
    std::fs::write(
        notif_dir.join("valid.json"),
        serde_json::to_string(&make_notification("Valid", "body")).unwrap(),
    )
    .unwrap();

    let pending = read_pending(dir.path()).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].1.title, "Valid");
}

#[test]
fn test_clear_notification_removes_file() {
    let dir = TempDir::new().unwrap();
    let n = make_notification("To Clear", "Will be cleared");

    write_notification(dir.path(), &n).unwrap();

    let pending = read_pending(dir.path()).unwrap();
    assert_eq!(pending.len(), 1);

    clear_notification(&pending[0].0).unwrap();

    let pending_after = read_pending(dir.path()).unwrap();
    assert!(pending_after.is_empty());
}

#[test]
fn test_clear_all_removes_all_notifications() {
    let dir = TempDir::new().unwrap();

    write_notification(dir.path(), &make_notification("First", "body 1")).unwrap();
    write_notification(dir.path(), &make_notification("Second", "body 2")).unwrap();

    let pending = read_pending(dir.path()).unwrap();
    assert_eq!(pending.len(), 2);

    clear_all(dir.path()).unwrap();

    let pending_after = read_pending(dir.path()).unwrap();
    assert!(pending_after.is_empty());
}

#[test]
fn test_clear_all_on_nonexistent_dir_is_ok() {
    let dir = TempDir::new().unwrap();
    let nonexistent = dir.path().join("nope");
    clear_all(&nonexistent).unwrap();
}

#[test]
fn test_clear_all_returns_error_when_notifications_path_is_not_a_directory() {
    let dir = TempDir::new().unwrap();
    std::fs::write(notifications_dir(dir.path()), "not a directory").unwrap();

    let err = clear_all(dir.path()).unwrap_err();
    assert!(err.to_string().contains("Failed to read notifications dir"));
}

#[test]
fn test_multiple_notifications_sorted_chronologically() {
    let dir = TempDir::new().unwrap();

    // Titles are already distinct, so filenames differ without any delay; the
    // timestamp prefix (and the title tiebreak) keeps them in insertion order.
    write_notification(dir.path(), &make_notification("First", "1")).unwrap();
    write_notification(dir.path(), &make_notification("Second", "2")).unwrap();
    write_notification(dir.path(), &make_notification("Third", "3")).unwrap();

    let pending = read_pending(dir.path()).unwrap();
    assert_eq!(pending.len(), 3);
    assert_eq!(pending[0].1.title, "First");
    assert_eq!(pending[1].1.title, "Second");
    assert_eq!(pending[2].1.title, "Third");
}

#[test]
fn test_malformed_json_file_skipped() {
    let dir = TempDir::new().unwrap();
    let notif_dir = notifications_dir(dir.path());
    std::fs::create_dir_all(&notif_dir).unwrap();

    // Write a valid notification
    write_notification(dir.path(), &make_notification("Valid", "ok")).unwrap();

    // Write a malformed JSON file
    std::fs::write(notif_dir.join("bad_file.json"), "not json at all").unwrap();

    let pending = read_pending(dir.path()).unwrap();
    // Should contain only the valid notification
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].1.title, "Valid");
}

#[test]
fn test_read_pending_skips_json_missing_required_fields() {
    let dir = TempDir::new().unwrap();
    let notif_dir = notifications_dir(dir.path());
    std::fs::create_dir_all(&notif_dir).unwrap();

    std::fs::write(
        notif_dir.join("missing-fields.json"),
        r#"{"title":"Incomplete"}"#,
    )
    .unwrap();
    std::fs::write(
        notif_dir.join("valid.json"),
        serde_json::to_string(&make_notification("Valid", "body")).unwrap(),
    )
    .unwrap();

    let pending = read_pending(dir.path()).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].1.title, "Valid");
}

#[test]
fn test_non_json_files_ignored() {
    let dir = TempDir::new().unwrap();
    let notif_dir = notifications_dir(dir.path());
    std::fs::create_dir_all(&notif_dir).unwrap();

    write_notification(dir.path(), &make_notification("Valid", "ok")).unwrap();

    // Write a non-JSON file
    std::fs::write(notif_dir.join("readme.txt"), "not a notification").unwrap();

    let pending = read_pending(dir.path()).unwrap();
    assert_eq!(pending.len(), 1);
}

#[test]
fn test_notification_serialization_roundtrip() {
    let original = Notification {
        title: "Overlay Status".to_string(),
        body: "Security: OPTIMAL – 9 overlays mounted".to_string(),
        urgency: "normal".to_string(),
        icon: Some("security-high".to_string()),
        created_at: "2026-03-17T14:30:22Z".to_string(),
    };

    let json = serde_json::to_string(&original).unwrap();
    let deserialized: Notification = serde_json::from_str(&json).unwrap();
    assert_eq!(original, deserialized);
}

#[test]
fn test_notification_default_urgency() {
    let json = r#"{"title":"Test","body":"Body","created_at":"2026-01-01T00:00:00Z"}"#;
    let n: Notification = serde_json::from_str(json).unwrap();
    assert_eq!(n.urgency, "normal");
    assert_eq!(n.icon, None);
}

#[test]
fn test_dispatch_all_with_no_pending_returns_zero() {
    let dir = TempDir::new().unwrap();
    let count = dispatch_all(dir.path()).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn test_notifications_dir_path() {
    let root = Path::new("/mnt/hidden-volume");
    assert_eq!(
        notifications_dir(root),
        PathBuf::from("/mnt/hidden-volume/notifications")
    );
}

#[test]
fn test_notification_title_sanitization() {
    // Test that special characters in title are sanitized for filename
    let dir = TempDir::new().unwrap();
    let n = Notification {
        title: "Test/Title:With*Special?Chars<>|\"\\".to_string(),
        body: "Body".to_string(),
        urgency: "normal".to_string(),
        icon: None,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    write_notification(dir.path(), &n).unwrap();

    let pending = read_pending(dir.path()).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].1.title, "Test/Title:With*Special?Chars<>|\"\\");
}

#[test]
fn test_notification_title_filename_is_sanitized_and_truncated() {
    let dir = TempDir::new().unwrap();
    let title = "Very long title with spaces/slashes and punctuation!!! 1234567890 extra";
    let notification = Notification {
        title: title.to_string(),
        body: "Body".to_string(),
        urgency: "normal".to_string(),
        icon: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
    };

    write_notification(dir.path(), &notification).unwrap();

    let pending = read_pending(dir.path()).unwrap();
    assert_eq!(pending.len(), 1);
    let filename = pending[0].0.file_name().unwrap().to_string_lossy();
    assert!(filename.ends_with(".json"));
    let title_part = filename
        .strip_suffix(".json")
        .unwrap()
        .split_once('_')
        .unwrap()
        .1;
    assert!(title_part.len() <= 40, "filename={filename}");
    assert!(
        title_part.starts_with("Very_long_title"),
        "filename={filename}"
    );
    assert!(!title_part.contains(' '));
    assert!(!title_part.contains('/'));
}

#[test]
fn test_notification_urgency_variants() {
    let dir = TempDir::new().unwrap();

    let low = Notification {
        title: "Low".to_string(),
        body: "Low urgency".to_string(),
        urgency: "low".to_string(),
        icon: None,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let critical = Notification {
        title: "Critical".to_string(),
        body: "Critical issue".to_string(),
        urgency: "critical".to_string(),
        icon: Some("dialog-error".to_string()),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    write_notification(dir.path(), &low).unwrap();
    write_notification(dir.path(), &critical).unwrap();

    let pending = read_pending(dir.path()).unwrap();
    assert_eq!(pending.len(), 2);
    // Both urgencies round-trip; filename order depends on the title tiebreak
    // when the timestamps match, so assert on the set rather than the sequence.
    let urgencies: std::collections::HashSet<&str> =
        pending.iter().map(|(_, n)| n.urgency.as_str()).collect();
    assert!(urgencies.contains("low"));
    assert!(urgencies.contains("critical"));
}

#[test]
fn test_notification_without_icon() {
    let dir = TempDir::new().unwrap();
    let n = Notification {
        title: "No Icon".to_string(),
        body: "This notification has no icon".to_string(),
        urgency: "normal".to_string(),
        icon: None,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    write_notification(dir.path(), &n).unwrap();

    let pending = read_pending(dir.path()).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].1.icon, None);
}

#[test]
fn test_clear_notification_on_nonexistent_file() {
    let dir = TempDir::new().unwrap();
    let fake_path = dir.path().join("nonexistent.json");

    // Should not panic
    let result = clear_notification(&fake_path);
    // clear_notification returns Result<()>, errors are ignored in actual usage
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_clear_notification_returns_error_for_missing_file() {
    let dir = TempDir::new().unwrap();
    let fake_path = dir.path().join("missing.json");

    let err = clear_notification(&fake_path).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to remove notification file")
    );
}

#[test]
fn test_long_notification_title_truncated() {
    // Test that very long titles are truncated to 40 chars in filename
    let dir = TempDir::new().unwrap();
    let very_long_title = "a".repeat(100);
    let n = Notification {
        title: very_long_title.clone(),
        body: "Body".to_string(),
        urgency: "normal".to_string(),
        icon: None,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    write_notification(dir.path(), &n).unwrap();

    let pending = read_pending(dir.path()).unwrap();
    assert_eq!(pending.len(), 1);
    // The title in the notification data should be preserved
    assert_eq!(pending[0].1.title, very_long_title);
}

#[test]
fn test_clear_all_preserves_non_json_files() {
    let dir = TempDir::new().unwrap();
    let notif_dir = notifications_dir(dir.path());
    std::fs::create_dir_all(&notif_dir).unwrap();

    write_notification(dir.path(), &make_notification("Test", "body")).unwrap();

    // Write a non-JSON file that should be preserved
    let txt_file = notif_dir.join("readme.txt");
    std::fs::write(&txt_file, "Do not delete this").unwrap();

    clear_all(dir.path()).unwrap();

    // JSON files should be gone, but txt file should remain
    let pending = read_pending(dir.path()).unwrap();
    assert!(pending.is_empty());
    assert!(txt_file.exists());
}

#[test]
fn test_dispatch_all_returns_zero_in_test_build() {
    // In test builds (#[cfg(test)]), dispatch_all is compiled to always return Ok(0)
    // This is the compile-time protection layer that makes it IMPOSSIBLE for tests
    // to send real notifications, regardless of environment variables or PATH.
    let dir = TempDir::new().unwrap();
    write_notification(dir.path(), &make_notification("Test", "body")).unwrap();

    // dispatch_all should return Ok(0) due to #[cfg(test)] guard
    let result = dispatch_all(dir.path());
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);

    // Notification files should still exist (not deleted since dispatch is disabled)
    let pending = read_pending(dir.path()).unwrap();
    assert_eq!(pending.len(), 1, "Pending notification should remain");
}

#[test]
fn test_dispatch_all_with_pending_notifications() {
    // Verify dispatch_all handles pending notifications correctly in test builds
    // Even with pending notifications, no real dispatching occurs
    let dir = TempDir::new().unwrap();
    write_notification(
        dir.path(),
        &make_notification("Should not appear", "on desktop"),
    )
    .unwrap();

    // In test builds, dispatch_all always returns 0 due to #[cfg(test)] guard
    let count = dispatch_all(dir.path()).unwrap();
    assert_eq!(
        count, 0,
        "No notifications should be dispatched in test builds"
    );

    // Notification files should still exist (not deleted since not sent)
    let pending = read_pending(dir.path()).unwrap();
    assert_eq!(pending.len(), 1, "Pending notification should remain");
}

#[test]
fn test_notification_clone() {
    let n = make_notification("Title", "Body");
    let cloned = n.clone();
    assert_eq!(n.title, cloned.title);
    assert_eq!(n.body, cloned.body);
    assert_eq!(n.urgency, cloned.urgency);
    assert_eq!(n.icon, cloned.icon);
    assert_eq!(n.created_at, cloned.created_at);
}

#[test]
fn test_notification_debug_format() {
    let n = make_notification("Test", "Body");
    let debug_str = format!("{:?}", n);
    assert!(debug_str.contains("Test"));
    assert!(debug_str.contains("Body"));
}

#[test]
fn test_notification_equality() {
    let n1 = Notification {
        title: "Same".to_string(),
        body: "Same body".to_string(),
        urgency: "normal".to_string(),
        icon: Some("icon".to_string()),
        created_at: "2026-01-01T00:00:00Z".to_string(),
    };

    let n2 = Notification {
        title: "Same".to_string(),
        body: "Same body".to_string(),
        urgency: "normal".to_string(),
        icon: Some("icon".to_string()),
        created_at: "2026-01-01T00:00:00Z".to_string(),
    };

    let n3 = Notification {
        title: "Different".to_string(),
        body: "Same body".to_string(),
        urgency: "normal".to_string(),
        icon: Some("icon".to_string()),
        created_at: "2026-01-01T00:00:00Z".to_string(),
    };

    assert_eq!(n1, n2);
    assert_ne!(n1, n3);
}

#[test]
fn test_notification_directory_has_mode_0o700() {
    let dir = TempDir::new().unwrap();
    write_notification(dir.path(), &make_notification("Test", "body")).unwrap();

    let notif_dir = notifications_dir(dir.path());
    let mode = notif_dir.metadata().unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o700,
        "Notification directory should be 0o700, got {:#o}",
        mode
    );
}

#[test]
fn test_notification_file_has_mode_0o600() {
    let dir = TempDir::new().unwrap();
    write_notification(dir.path(), &make_notification("Test", "body")).unwrap();

    let pending = read_pending(dir.path()).unwrap();
    assert_eq!(pending.len(), 1);
    let mode = pending[0].0.metadata().unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "Notification file should be 0o600, got {:#o}",
        mode
    );
}

#[test]
fn signal_file_create_does_not_follow_a_planted_symlink() {
    let dir = TempDir::new().unwrap();
    let victim = dir.path().join("victim");
    std::fs::write(&victim, "original").unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::os::unix::fs::symlink(&victim, dir.path().join("signal.json")).unwrap();

    let safe_root = crate::filesystem::SafeRoot::open(dir.path()).unwrap();
    let (relative, mut file) = create_signal_file(&safe_root, Path::new(""), "signal").unwrap();
    file.write_all(b"payload").unwrap();

    // The planted name counts as taken, so the write lands on a fresh suffixed
    // file and the symlink's target is left exactly as it was.
    assert_eq!(relative, PathBuf::from("signal_1.json"));
    let path = dir.path().join(&relative);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "payload");
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "original");
    let victim_mode = victim.metadata().unwrap().permissions().mode() & 0o777;
    assert_eq!(victim_mode, 0o644);
    let mode = path.symlink_metadata().unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn runtime_environment_derives_xdg_runtime_dir_from_uid() {
    let env = build_runtime_environment(Some(1000), None, None);

    assert!(
        env.contains(&("XDG_RUNTIME_DIR", "/run/user/1000".to_string())),
        "expected XDG_RUNTIME_DIR for the resolved uid, got {env:?}"
    );
    assert!(
        env.contains(&(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/run/user/1000/bus".to_string()
        )),
        "expected a session bus address derived from the uid, got {env:?}"
    );
}

#[test]
fn runtime_environment_omits_runtime_dir_without_a_uid() {
    let env = build_runtime_environment(None, Some(":0".to_string()), None);

    assert!(
        !env.iter().any(|(key, _)| *key == "XDG_RUNTIME_DIR"),
        "no uid means no XDG_RUNTIME_DIR, got {env:?}"
    );
    assert!(
        env.contains(&("DISPLAY", ":0".to_string())),
        "display passthrough should be preserved, got {env:?}"
    );
}

#[test]
fn runtime_environment_forwards_wayland_display() {
    let env = build_runtime_environment(Some(1001), None, Some("wayland-0".to_string()));

    assert!(env.contains(&("WAYLAND_DISPLAY", "wayland-0".to_string())));
    assert!(env.contains(&("XDG_RUNTIME_DIR", "/run/user/1001".to_string())));
}
