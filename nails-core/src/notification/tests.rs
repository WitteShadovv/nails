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
