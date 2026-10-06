// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
fn test_write_xdg_autostart_entry_creates_desktop_file() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    let shell = ShellInstrumentation::new(fs.clone(), config).with_target_user(
        crate::target_user::TargetUser::for_test(
            1000,
            1000,
            "testuser",
            "/home/testuser",
            "/bin/bash",
        ),
    );
    let result = shell.write_xdg_autostart_entry();

    assert!(result.is_ok());
    assert!(result.unwrap());

    // Verify the desktop file was written
    let desktop_path = PathBuf::from("/home/testuser/.config/autostart/nails-notify.desktop");
    let content = fs.read_file_content(&desktop_path).unwrap();

    assert!(content.contains("[Desktop Entry]"));
    assert!(content.contains("Type=Application"));
    assert!(content.contains("Name=Notification dispatch"));
    assert!(content.contains("notify-dispatch"));
    assert!(!content.contains("Exec=nails notify-dispatch"));
    assert!(content.contains("Terminal=false"));
    assert!(content.contains("NoDisplay=true"));
    assert!(content.contains("X-GNOME-Autostart-enabled=true"));
}
#[test]
fn test_write_xdg_autostart_entry_creates_autostart_directory() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    let shell = ShellInstrumentation::new(fs.clone(), config).with_target_user(
        crate::target_user::TargetUser::for_test(
            1000,
            1000,
            "testuser",
            "/home/testuser",
            "/bin/bash",
        ),
    );

    // Autostart directory doesn't exist yet
    let autostart_dir = PathBuf::from("/home/testuser/.config/autostart");
    assert!(!fs.path_exists(&autostart_dir).unwrap());

    // Writing should create it
    let result = shell.write_xdg_autostart_entry();

    assert!(result.is_ok());
    assert!(result.unwrap());

    // Directory should now exist
    assert!(fs.path_exists(&autostart_dir).unwrap());
}
#[test]
fn test_write_xdg_autostart_entry_uses_user_env_fallback() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/fallbackuser", true);

    let shell = ShellInstrumentation::new(fs.clone(), config).with_target_user(
        crate::target_user::TargetUser::for_test(
            1000,
            1000,
            "fallbackuser",
            "/home/fallbackuser",
            "/bin/bash",
        ),
    );
    let result = shell.write_xdg_autostart_entry();

    assert!(result.is_ok());
    assert!(result.unwrap());

    // Should use USER env var to find home directory
    let desktop_path = PathBuf::from("/home/fallbackuser/.config/autostart/nails-notify.desktop");
    assert!(fs.read_file_content(&desktop_path).is_ok());
}
#[test]
fn test_write_xdg_autostart_entry_uses_home_env_without_hardcoded_home_prefix() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let home = "/srv/users/fallbackuser";

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/srv", true);
    fs.mock_set_path_exists("/srv/users", true);
    fs.mock_set_path_exists(home, true);

    let shell = ShellInstrumentation::new(fs.clone(), config).with_target_user(
        crate::target_user::TargetUser::for_test(1000, 1000, "fallbackuser", home, "/bin/bash"),
    );
    let result = shell.write_xdg_autostart_entry();

    assert!(result.is_ok());
    assert!(result.unwrap());

    let desktop_path = PathBuf::from(format!("{home}/.config/autostart/nails-notify.desktop"));
    assert!(fs.read_file_content(&desktop_path).is_ok());
}
#[test]
fn test_write_xdg_autostart_entry_idempotent() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    let shell = ShellInstrumentation::new(fs.clone(), config).with_target_user(
        crate::target_user::TargetUser::for_test(
            1000,
            1000,
            "testuser",
            "/home/testuser",
            "/bin/bash",
        ),
    );

    // Write twice — should succeed both times
    let result1 = shell.write_xdg_autostart_entry();
    let result2 = shell.write_xdg_autostart_entry();

    assert!(result1.is_ok());
    assert!(result1.unwrap());
    assert!(result2.is_ok());
    assert!(result2.unwrap());

    // File should still be readable
    let desktop_path = PathBuf::from("/home/testuser/.config/autostart/nails-notify.desktop");
    let content = fs.read_file_content(&desktop_path).unwrap();
    assert!(content.contains("[Desktop Entry]"));
}
#[test]
fn test_write_xdg_autostart_entry_returns_false_on_write_failure() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    // Make the desktop file write fail
    fs.mock_set_write_should_fail(
        "/home/testuser/.config/autostart/nails-notify.desktop",
        true,
    );

    let shell = ShellInstrumentation::new(fs.clone(), config).with_target_user(
        crate::target_user::TargetUser::for_test(
            1000,
            1000,
            "testuser",
            "/home/testuser",
            "/bin/bash",
        ),
    );
    let result = shell.write_xdg_autostart_entry();

    // Should return Ok(false) on best-effort failure
    assert!(result.is_ok());
    assert!(!result.unwrap());
}
#[test]
fn test_write_xdg_autostart_desktop_file_content_format() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    let shell = ShellInstrumentation::new(fs.clone(), config).with_target_user(
        crate::target_user::TargetUser::for_test(
            1000,
            1000,
            "testuser",
            "/home/testuser",
            "/bin/bash",
        ),
    );
    shell.write_xdg_autostart_entry().unwrap();

    let desktop_path = PathBuf::from("/home/testuser/.config/autostart/nails-notify.desktop");
    let content = fs.read_file_content(&desktop_path).unwrap();

    // Verify exact desktop entry format (each field on its own line)
    assert!(content.starts_with("[Desktop Entry]\n"));
    assert!(content.contains("Comment=Dispatches pending desktop notifications on login\n"));
    assert!(content.contains(&format!(
        "Exec={} notify-dispatch\n",
        std::env::current_exe().unwrap().display()
    )));
    assert!(content.ends_with('\n'));
}
