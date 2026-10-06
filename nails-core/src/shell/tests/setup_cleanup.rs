// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
fn test_shell_setup_with_bash() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell =
        ShellInstrumentation::new(fs.clone(), config).with_shell_env(Some("/bin/bash".to_string()));
    let result = shell.shell_setup();

    // Should succeed
    assert!(result.is_ok());
    let result = result.unwrap();

    // Should have a result (bash detected)
    assert!(result.is_some());
    let setup = result.unwrap();

    // Verify shell type
    assert_eq!(setup.shell_type, ShellType::Bash);

    // Verify instructions contain source commands
    assert_eq!(setup.instructions.len(), 2);
    assert!(setup.instructions[0].contains("nails_prompt.bash"));
    assert!(setup.instructions[1].contains("nails_alias.sh"));

    // Verify no warnings
    assert!(setup.warning.is_none());
}
#[test]
fn test_shell_setup_with_zsh() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs.clone(), config)
        .with_shell_env(Some("/usr/bin/zsh".to_string()));
    let result = shell.shell_setup();

    // Should succeed
    assert!(result.is_ok());
    let result = result.unwrap();

    // Should have a result (zsh detected)
    assert!(result.is_some());
    let setup = result.unwrap();

    // Verify shell type
    assert_eq!(setup.shell_type, ShellType::Zsh);

    // Verify instructions contain source commands
    assert!(setup.instructions[0].contains("nails_prompt.zsh"));
    assert!(setup.instructions[1].contains("nails_alias.sh"));
}
#[test]
fn test_shell_setup_with_fish() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs.clone(), config)
        .with_shell_env(Some("/usr/bin/fish".to_string()));
    let result = shell.shell_setup();

    // Should succeed
    assert!(result.is_ok());
    let result = result.unwrap();

    // Should have a result (fish detected)
    assert!(result.is_some());
    let setup = result.unwrap();

    // Verify shell type
    assert_eq!(setup.shell_type, ShellType::Fish);

    // Verify instructions contain source commands
    assert!(setup.instructions[0].contains("nails_prompt.fish"));
    assert!(setup.instructions[1].contains("nails_alias.fish"));
}
#[test]
fn test_shell_setup_no_shell_detected() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.shell_setup();

    // Should succeed but return None
    assert!(result.is_ok());
    assert!(matches!(result.as_ref(), Ok(None)));
}
#[test]
fn test_shell_setup_without_shell_env_still_sets_up_persistent_integration_for_target_user() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/amnesia", true);

    let shell = ShellInstrumentation::new(fs.clone(), config).with_target_user(
        crate::target_user::TargetUser::for_test(
            1000,
            1000,
            "amnesia",
            "/home/amnesia",
            "/bin/bash",
        ),
    );
    let result = shell.shell_setup();

    assert!(result.is_ok());
    let setup = result
        .unwrap()
        .expect("shell fallback should select a shell");
    assert_eq!(setup.shell_type, ShellType::Bash);

    let bashrc_path = PathBuf::from("/home/amnesia/.bashrc");
    let content = fs.read_file_content(&bashrc_path).unwrap();
    assert!(content.contains("# >>> managed shell integration"));
}
#[test]
fn test_shell_setup_returns_warning_without_source_commands_when_script_writes_fail() {
    let fs = MockFilesystem::new();
    // Pin the root: the default now derives from the binary location, which in a
    // test build is the build directory, not the install mount this test asserts on.
    let config = Config {
        hidden_volume_root: PathBuf::from("/mnt/data"),
        ..Default::default()
    };

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);
    fs.mock_set_write_should_fail("/mnt/data/scripts/nails_prompt.bash", true);
    fs.mock_set_write_should_fail("/mnt/data/scripts/nails_alias.sh", true);

    let shell = ShellInstrumentation::new(fs, config)
        .with_shell_env(Some("/bin/bash".to_string()))
        .with_target_user(crate::target_user::TargetUser::for_test(
            1000,
            1000,
            "testuser",
            "/home/testuser",
            "/bin/bash",
        ));
    let result = shell
        .shell_setup()
        .unwrap()
        .expect("shell should still be detected");

    assert_eq!(result.shell_type, ShellType::Bash);
    assert!(result.instructions.is_empty());
    let warning = result.warning.expect("warning should be reported");
    assert!(warning.contains("prompt scripts could not be generated"));
    assert!(warning.contains("alias scripts could not be generated"));
}
#[test]
fn test_shell_setup_continues_when_xdg_autostart_write_returns_false() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);
    fs.mock_set_write_should_fail(
        "/home/testuser/.config/autostart/nails-notify.desktop",
        true,
    );

    let shell = ShellInstrumentation::new(fs.clone(), config)
        .with_shell_env(Some("/bin/bash".to_string()))
        .with_target_user(crate::target_user::TargetUser::for_test(
            1000,
            1000,
            "testuser",
            "/home/testuser",
            "/bin/bash",
        ));
    let result = shell
        .shell_setup()
        .unwrap()
        .expect("setup should continue on best-effort autostart failure");

    assert_eq!(result.shell_type, ShellType::Bash);
    assert_eq!(result.instructions.len(), 2);
    assert!(result.warning.is_none());
    assert!(result.rc_modified);
}
#[test]
fn test_shell_setup_continues_when_xdg_autostart_resolution_errors() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs, config).with_shell_env(Some("/bin/bash".to_string()));
    let result = shell
        .shell_setup()
        .unwrap()
        .expect("setup should continue even when autostart setup errors");

    assert_eq!(result.shell_type, ShellType::Bash);
    assert_eq!(result.instructions.len(), 2);
    assert!(!result.rc_modified);
    assert!(result.warning.is_none());
}
#[test]
fn test_shell_setup_unsupported_shell() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs, config).with_shell_env(Some("/bin/tcsh".to_string()));
    let result = shell.shell_setup();

    // Should succeed but return None
    assert!(result.is_ok());
    assert!(matches!(result.as_ref(), Ok(None)));
}
#[test]
fn test_shell_setup_to_source_commands() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs, config).with_shell_env(Some("/bin/bash".to_string()));
    let result = shell.shell_setup();

    // Should have Some result
    assert!(matches!(result.as_ref(), Ok(Some(_))));
    let setup = result.unwrap().unwrap();
    let commands = setup.to_source_commands();

    assert_eq!(commands.len(), 2);
    assert!(commands[0].starts_with("source "));
    assert!(commands[0].ends_with("nails_prompt.bash"));
    assert!(commands[1].starts_with("source "));
    assert!(commands[1].ends_with("nails_alias.sh"));
}
#[test]
fn test_shell_cleanup_normal_deactivation() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs, config).with_shell_env(Some("/bin/bash".to_string()));
    let result = shell.shell_cleanup(false); // false = no alias removal

    // Should have shell type detected
    assert_eq!(result.shell_type, Some(ShellType::Bash));

    // Should only have prompt cleanup, not alias cleanup
    assert_eq!(result.instructions.len(), 1);
    assert!(result.instructions[0].contains("nails_prompt_cleanup.bash"));
    assert!(!result.instructions[0].contains("alias"));

    // No message
    assert!(result.message.is_none());
}
#[test]
fn test_shell_cleanup_emergency_deactivation() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs, config).with_shell_env(Some("/bin/bash".to_string()));
    let result = shell.shell_cleanup(true); // true = include alias removal

    // Should have shell type detected
    assert_eq!(result.shell_type, Some(ShellType::Bash));

    // Should have both prompt cleanup AND alias cleanup
    assert_eq!(result.instructions.len(), 2);
    assert!(result.instructions[0].contains("nails_prompt_cleanup.bash"));
    assert!(result.instructions[1].contains("nails_alias_cleanup.sh"));
}
#[test]
fn test_shell_cleanup_no_shell_detected() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.shell_cleanup(false);

    // Should have no shell type
    assert!(result.shell_type.is_none());

    // Should have no instructions
    assert!(result.instructions.is_empty());

    // Should have message
    assert!(result.message.is_some());
    assert!(result.message.unwrap().contains("Shell cleanup skipped"));
}
#[test]
fn test_shell_cleanup_with_fish() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    let shell =
        ShellInstrumentation::new(fs, config).with_shell_env(Some("/usr/bin/fish".to_string()));
    let result = shell.shell_cleanup(true); // emergency with alias removal

    // Should have fish shell type
    assert_eq!(result.shell_type, Some(ShellType::Fish));

    // Should have both cleanup scripts
    assert_eq!(result.instructions.len(), 2);
    assert!(result.instructions[0].contains("nails_prompt_cleanup.fish"));
    assert!(result.instructions[1].contains("nails_alias_cleanup.fish"));
}
#[test]
fn test_shell_setup_writes_xdg_autostart_entry() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    let shell = ShellInstrumentation::new(fs.clone(), config)
        .with_shell_env(Some("/bin/bash".to_string()))
        .with_target_user(crate::target_user::TargetUser::for_test(
            1000,
            1000,
            "testuser",
            "/home/testuser",
            "/bin/bash",
        ));
    let result = shell.shell_setup();

    assert!(result.is_ok());
    assert!(result.unwrap().is_some());

    // Verify that shell_setup also created the autostart entry
    let desktop_path = PathBuf::from("/home/testuser/.config/autostart/nails-notify.desktop");
    let content = fs.read_file_content(&desktop_path).unwrap();
    assert!(content.contains("notify-dispatch"));
    assert!(!content.contains("Exec=nails notify-dispatch"));
}

#[test]
fn test_shell_setup_skips_all_writes_when_home_not_on_overlay() {
    use crate::target_user::TargetUser;

    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: "/mnt/data".into(),
        ..Config::default()
    };

    let operator = TargetUser::for_test(1000, 1000, "testuser", "/home/testuser", "/bin/bash");
    let shell = ShellInstrumentation::new(fs.clone(), config)
        .with_target_user(operator)
        .with_shell_env(Some("/bin/bash".to_string()));
    // The operator's home sits on the bare decoy disk, not a NAILS overlay, so the
    // integration must write nothing: an rc block here would persist the hidden
    // binary path on the decoy disk.
    shell.set_mountinfo_override(HOME_ON_DECOY_DISK);

    let result = shell.shell_setup().expect("shell_setup never errors");
    assert!(
        result.is_none(),
        "shell_setup must be skipped when the home is not on a NAILS overlay"
    );

    // No rc block was written into the decoy home.
    assert!(
        fs.read_file_content(Path::new("/home/testuser/.bashrc"))
            .is_err(),
        "no rc file may be written off an overlay"
    );
}
