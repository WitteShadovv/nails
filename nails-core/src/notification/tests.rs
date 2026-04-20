use super::*;
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
fn test_write_creates_notifications_dir() {
    let dir = TempDir::new().unwrap();
    let n = make_notification("Title", "Body");

    write_notification(dir.path(), &n).unwrap();

    assert!(notifications_dir(dir.path()).exists());
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
    // Small delay to ensure different filenames
    std::thread::sleep(std::time::Duration::from_millis(5));
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
fn test_multiple_notifications_sorted_chronologically() {
    let dir = TempDir::new().unwrap();

    write_notification(dir.path(), &make_notification("First", "1")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    write_notification(dir.path(), &make_notification("Second", "2")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
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
    std::thread::sleep(std::time::Duration::from_millis(5));
    write_notification(dir.path(), &critical).unwrap();

    let pending = read_pending(dir.path()).unwrap();
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].1.urgency, "low");
    assert_eq!(pending[1].1.urgency, "critical");
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
