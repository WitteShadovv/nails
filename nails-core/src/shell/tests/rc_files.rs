// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
#[serial]
fn test_inject_rc_integration_bash_creates_bashrc() {
    let mut env = EnvGuard::lock();
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

    env.set("SHELL", "/bin/bash").set("SUDO_USER", "testuser");

    let shell = ShellInstrumentation::new(fs.clone(), config.clone());

    // Call inject_rc_integration
    let result = shell.inject_rc_integration(ShellType::Bash);

    assert!(result.is_ok());
    assert!(result.unwrap());

    // Verify .bashrc was created with integration block
    let bashrc_path = PathBuf::from("/home/testuser/.bashrc");
    let content = fs.read_file_content(&bashrc_path).unwrap();

    assert!(content.contains("# >>> managed shell integration"));
    assert!(content.contains("source /mnt/data/scripts/nails_prompt.bash"));
    assert!(content.contains("source /mnt/data/scripts/nails_alias.sh"));
    assert!(content.contains("printf '\\e]11;#1a1a2e\\a\\e]10;#e0e0e0\\a'"));
    assert!(content.contains("# <<< managed shell integration <<<"));
}
#[test]
#[serial]
fn test_inject_rc_integration_zsh_creates_zshrc() {
    let mut env = EnvGuard::lock();
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

    env.set("SHELL", "/bin/zsh").set("SUDO_USER", "testuser");

    let shell = ShellInstrumentation::new(fs.clone(), config.clone());

    let result = shell.inject_rc_integration(ShellType::Zsh);

    assert!(result.is_ok());
    assert!(result.unwrap());

    // Verify .zshrc was created
    let zshrc_path = PathBuf::from("/home/testuser/.zshrc");
    let content = fs.read_file_content(&zshrc_path).unwrap();

    assert!(content.contains("# >>> managed shell integration"));
    assert!(content.contains("source /mnt/data/scripts/nails_prompt.zsh"));
    assert!(content.contains("source /mnt/data/scripts/nails_alias.sh"));
}
#[test]
#[serial]
fn test_inject_rc_integration_fish_creates_config_fish() {
    let mut env = EnvGuard::lock();
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

    env.set("SHELL", "/bin/fish").set("SUDO_USER", "testuser");

    let shell = ShellInstrumentation::new(fs.clone(), config.clone());

    let result = shell.inject_rc_integration(ShellType::Fish);

    assert!(result.is_ok());
    assert!(result.unwrap());

    // Verify config.fish was created (with parent dirs)
    let fish_config_path = PathBuf::from("/home/testuser/.config/fish/config.fish");
    let content = fs.read_file_content(&fish_config_path).unwrap();

    assert!(content.contains("# >>> managed shell integration"));
    assert!(content.contains("source /mnt/data/scripts/nails_prompt.fish"));
    assert!(content.contains("source /mnt/data/scripts/nails_alias.fish"));
}
#[test]
#[serial]
fn test_inject_rc_integration_idempotent() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    env.set("SUDO_USER", "testuser");

    let shell = ShellInstrumentation::new(fs.clone(), config.clone());

    // Call twice
    let result1 = shell.inject_rc_integration(ShellType::Bash);
    let result2 = shell.inject_rc_integration(ShellType::Bash);

    assert!(result1.is_ok());
    assert!(result2.is_ok());

    // Verify only ONE integration block exists
    let bashrc_path = PathBuf::from("/home/testuser/.bashrc");
    let content = fs.read_file_content(&bashrc_path).unwrap();

    let marker_count = content.matches("# >>> managed shell integration").count();
    assert_eq!(marker_count, 1, "Should only have one integration block");
}
#[test]
#[serial]
fn test_inject_rc_integration_appends_to_existing_bashrc() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    // Create existing .bashrc
    let bashrc_path = PathBuf::from("/home/testuser/.bashrc");
    fs.mock_set_path_exists(&bashrc_path.to_string_lossy(), true);
    fs.mock_set_file_content(
        &bashrc_path.to_string_lossy(),
        "# Existing config\nexport PATH=/usr/bin:$PATH\n",
    );

    env.set("SUDO_USER", "testuser");

    let shell = ShellInstrumentation::new(fs.clone(), config.clone());
    let result = shell.inject_rc_integration(ShellType::Bash);

    assert!(result.is_ok());

    let content = fs.read_file_content(&bashrc_path).unwrap();

    // Should preserve existing content
    assert!(content.contains("# Existing config"));
    assert!(content.contains("export PATH=/usr/bin:$PATH"));

    // Should append NAILS integration
    assert!(content.contains("# >>> managed shell integration"));
}
#[test]
#[serial]
fn test_inject_rc_integration_uses_color_scheme_config() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config {
        color_scheme: crate::config::ColorSchemeConfig {
            hidden: crate::config::ColorProfile {
                background: "#123456".to_string(),
                foreground: "#abcdef".to_string(),
            },
            ..Default::default()
        },
        ..Default::default()
    };

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    env.set("SUDO_USER", "testuser");

    let shell = ShellInstrumentation::new(fs.clone(), config.clone());
    let result = shell.inject_rc_integration(ShellType::Bash);

    assert!(result.is_ok());

    let bashrc_path = PathBuf::from("/home/testuser/.bashrc");
    let content = fs.read_file_content(&bashrc_path).unwrap();

    // Should use configured colors, not hardcoded
    assert!(content.contains("#123456"));
    assert!(content.contains("#abcdef"));
}
#[test]
#[serial]
fn test_inject_rc_integration_falls_back_to_user_env() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/fallbackuser", true);

    // No SUDO_USER, should fall back to USER
    env.remove("SUDO_USER").set("USER", "fallbackuser");

    let shell = ShellInstrumentation::new(fs.clone(), config.clone());
    let result = shell.inject_rc_integration(ShellType::Bash);

    assert!(result.is_ok());

    // Should use USER env var
    let bashrc_path = PathBuf::from("/home/fallbackuser/.bashrc");
    assert!(fs.read_file_content(&bashrc_path).is_ok());
}
#[test]
#[serial]
fn test_inject_rc_integration_returns_false_on_failure() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    // Make bashrc write fail
    fs.mock_set_write_should_fail("/home/testuser/.bashrc", true);

    env.set("SUDO_USER", "testuser");

    let shell = ShellInstrumentation::new(fs.clone(), config.clone());
    let result = shell.inject_rc_integration(ShellType::Bash);

    // Should return Ok(false) on best-effort failure
    assert!(result.is_ok());
    assert!(!result.unwrap());
}
#[test]
#[serial]
fn test_inject_rc_integration_uses_home_env_without_hardcoded_home_prefix() {
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
    let result = shell.inject_rc_integration(ShellType::Bash);

    assert!(result.is_ok());
    let bashrc_path = PathBuf::from(format!("{home}/.bashrc"));
    assert!(fs.read_file_content(&bashrc_path).is_ok());
}
