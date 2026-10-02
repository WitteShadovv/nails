use super::*;

#[test]
#[serial]
fn test_write_xdg_autostart_entry_creates_desktop_file() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    env.set("SUDO_USER", "testuser");

    let shell = ShellInstrumentation::new(fs.clone(), config);
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
#[serial]
fn test_write_xdg_autostart_entry_creates_autostart_directory() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    env.set("SUDO_USER", "testuser");

    let shell = ShellInstrumentation::new(fs.clone(), config);

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
#[serial]
fn test_write_xdg_autostart_entry_uses_user_env_fallback() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/fallbackuser", true);

    env.remove("SUDO_USER").set("USER", "fallbackuser");

    let shell = ShellInstrumentation::new(fs.clone(), config);
    let result = shell.write_xdg_autostart_entry();

    assert!(result.is_ok());
    assert!(result.unwrap());

    // Should use USER env var to find home directory
    let desktop_path = PathBuf::from("/home/fallbackuser/.config/autostart/nails-notify.desktop");
    assert!(fs.read_file_content(&desktop_path).is_ok());
}
#[test]
#[serial]
fn test_write_xdg_autostart_entry_uses_home_env_without_hardcoded_home_prefix() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config::default();
    let home = "/srv/users/fallbackuser";

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/srv", true);
    fs.mock_set_path_exists("/srv/users", true);
    fs.mock_set_path_exists(home, true);

    env.remove("SUDO_USER")
        .set("USER", "fallbackuser")
        .set("HOME", home);

    let shell = ShellInstrumentation::new(fs.clone(), config);
    let result = shell.write_xdg_autostart_entry();

    assert!(result.is_ok());
    assert!(result.unwrap());

    let desktop_path = PathBuf::from(format!("{home}/.config/autostart/nails-notify.desktop"));
    assert!(fs.read_file_content(&desktop_path).is_ok());
}
#[test]
#[serial]
fn test_write_xdg_autostart_entry_idempotent() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    env.set("SUDO_USER", "testuser");

    let shell = ShellInstrumentation::new(fs.clone(), config);

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
#[serial]
fn test_write_xdg_autostart_entry_returns_false_on_write_failure() {
    let mut env = EnvGuard::lock();
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

    env.set("SUDO_USER", "testuser");

    let shell = ShellInstrumentation::new(fs.clone(), config);
    let result = shell.write_xdg_autostart_entry();

    // Should return Ok(false) on best-effort failure
    assert!(result.is_ok());
    assert!(!result.unwrap());
}
#[test]
#[serial]
fn test_write_xdg_autostart_desktop_file_content_format() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    env.set("SUDO_USER", "testuser");

    let shell = ShellInstrumentation::new(fs.clone(), config);
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
