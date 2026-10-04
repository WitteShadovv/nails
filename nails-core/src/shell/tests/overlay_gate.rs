// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
#[serial]
fn test_inject_rc_integration_skipped_when_home_not_on_hidden_overlay() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = gate_config();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    env.set("SUDO_USER", "testuser");

    let shell = ShellInstrumentation::new(fs.clone(), config);
    shell.set_mountinfo_override(HOME_ON_DECOY_DISK);
    let result = shell.inject_rc_integration(ShellType::Bash);

    // Gate returns Ok(false) and writes nothing.
    assert!(matches!(result, Ok(false)));
    let bashrc_path = PathBuf::from("/home/testuser/.bashrc");
    assert!(fs.read_file_content(&bashrc_path).is_err());
}
#[test]
#[serial]
fn test_write_xdg_autostart_entry_skipped_when_home_not_on_hidden_overlay() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = gate_config();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    env.set("SUDO_USER", "testuser");

    let shell = ShellInstrumentation::new(fs.clone(), config);
    shell.set_mountinfo_override(HOME_ON_DECOY_DISK);
    let result = shell.write_xdg_autostart_entry();

    assert!(matches!(result, Ok(false)));
    let desktop_path = PathBuf::from("/home/testuser/.config/autostart/nails-notify.desktop");
    assert!(fs.read_file_content(&desktop_path).is_err());
}
#[test]
#[serial]
fn test_inject_rc_integration_writes_when_home_on_hidden_overlay() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = gate_config();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    env.set("SUDO_USER", "testuser");

    let shell = ShellInstrumentation::new(fs.clone(), config);
    shell.set_mountinfo_override(HOME_ON_HIDDEN_OVERLAY);
    let result = shell.inject_rc_integration(ShellType::Bash);

    assert!(matches!(result, Ok(true)));
    let bashrc_path = PathBuf::from("/home/testuser/.bashrc");
    let content = fs.read_file_content(&bashrc_path).unwrap();
    assert!(content.contains("# >>> managed shell integration"));
    assert!(content.contains("# <<< managed shell integration <<<"));
    assert!(!content.contains("NAILS"));
}
#[test]
#[serial]
fn test_write_xdg_autostart_entry_writes_neutral_name_when_home_on_hidden_overlay() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = gate_config();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    env.set("SUDO_USER", "testuser");

    let shell = ShellInstrumentation::new(fs.clone(), config);
    shell.set_mountinfo_override(HOME_ON_HIDDEN_OVERLAY);
    let result = shell.write_xdg_autostart_entry();

    assert!(matches!(result, Ok(true)));
    let desktop_path = PathBuf::from("/home/testuser/.config/autostart/nails-notify.desktop");
    let content = fs.read_file_content(&desktop_path).unwrap();
    assert!(content.contains("Name=Notification dispatch"));
    assert!(!content.contains("NAILS"));
    assert!(content.contains("notify-dispatch"));
}
#[test]
#[serial]
fn test_inject_rc_integration_owns_file_when_target_user_attached() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/operator", true);

    env.set("SHELL", "/bin/bash").set("SUDO_USER", "operator");

    let user = crate::TargetUser::for_test(1000, 100, "operator", "/home/operator", "/bin/bash");
    let shell = ShellInstrumentation::new(fs.clone(), config).with_target_user(user);
    let result = shell.inject_rc_integration(ShellType::Bash);

    assert!(matches!(result, Ok(true)));
    let bashrc = PathBuf::from("/home/operator/.bashrc");
    assert!(
        fs.read_file_content(&bashrc)
            .unwrap()
            .contains("managed shell integration")
    );
    // The rc file ends up owned by the operator (numeric uid/gid), 0644.
    assert_eq!(fs.mock_get_owner(&bashrc), Some((1000, 100)));
    assert_eq!(fs.mock_get_permissions(&bashrc), Some(0o644));
}
#[test]
#[serial]
fn test_write_xdg_autostart_entry_owns_dir_and_file_when_target_user_attached() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/operator", true);

    env.set("SUDO_USER", "operator");

    let user = crate::TargetUser::for_test(1000, 100, "operator", "/home/operator", "/bin/bash");
    let shell = ShellInstrumentation::new(fs.clone(), config).with_target_user(user);
    let result = shell.write_xdg_autostart_entry();

    assert!(matches!(result, Ok(true)));
    let desktop = PathBuf::from("/home/operator/.config/autostart/nails-notify.desktop");
    let autostart_dir = PathBuf::from("/home/operator/.config/autostart");
    // Both the created directory chain and the file are operator-owned.
    assert_eq!(fs.mock_get_owner(&desktop), Some((1000, 100)));
    assert_eq!(fs.mock_get_owner(&autostart_dir), Some((1000, 100)));
    assert_eq!(fs.mock_get_permissions(&autostart_dir), Some(0o700));
}
