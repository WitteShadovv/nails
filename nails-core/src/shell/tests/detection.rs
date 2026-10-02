use super::*;

#[test]
#[serial]
fn test_detect_bash_shell() {
    let mut env = EnvGuard::lock();
    env.set("SHELL", "/bin/bash");
    let shell = create_test_shell();
    let result = shell.detect_current_shell();
    assert_eq!(result, Some(ShellType::Bash));
}
#[test]
#[serial]
fn test_detect_zsh_shell() {
    let mut env = EnvGuard::lock();
    env.set("SHELL", "/usr/bin/zsh");
    let shell = create_test_shell();
    let result = shell.detect_current_shell();
    assert_eq!(result, Some(ShellType::Zsh));
}
#[test]
#[serial]
fn test_detect_fish_shell() {
    let mut env = EnvGuard::lock();
    env.set("SHELL", "/usr/local/bin/fish");
    let shell = create_test_shell();
    let result = shell.detect_current_shell();
    assert_eq!(result, Some(ShellType::Fish));
}
#[test]
#[serial]
fn test_detect_unsupported_shell() {
    let mut env = EnvGuard::lock();
    env.set("SHELL", "/bin/tcsh");
    let shell = create_test_shell();
    let result = shell.detect_current_shell();
    assert_eq!(result, None);
}
#[test]
#[serial]
fn test_detect_shell_falls_back_to_home_dir_without_hardcoded_home_prefix() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config::default();
    let home = "/srv/users/amnesia";
    set_mock_home(&fs, home);
    fs.mock_set_path_exists(&format!("{home}/.zshrc"), true);

    env.remove("SHELL")
        .remove("SUDO_USER")
        .remove("NAILS_TARGET_USER")
        .set("USER", "amnesia")
        .set("HOME", home);

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.detect_current_shell();

    assert_eq!(result, Some(ShellType::Zsh));
}
#[test]
#[serial]
fn test_detect_shell_falls_back_to_fish_config_when_shell_env_is_unset() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config::default();
    let home = "/home/amnesia";
    set_mock_home(&fs, home);
    fs.mock_set_path_exists(&format!("{home}/.config/fish/config.fish"), true);

    env.remove("SHELL")
        .remove("SUDO_USER")
        .remove("NAILS_TARGET_USER")
        .set("USER", "amnesia")
        .set("HOME", home);

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.detect_current_shell();

    assert_eq!(result, Some(ShellType::Fish));
}
#[test]
#[serial]
fn test_detect_shell_returns_none_when_no_shell_env_or_rc_files_exist() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config::default();
    let home = "/home/amnesia";
    set_mock_home(&fs, home);

    env.remove("SHELL")
        .remove("SUDO_USER")
        .remove("NAILS_TARGET_USER")
        .set("USER", "amnesia")
        .set("HOME", home);

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.detect_current_shell();

    assert_eq!(result, None);
}
#[test]
#[serial]
fn test_resolve_target_username_prefers_sudo_user() {
    let mut env = EnvGuard::lock();
    let shell = create_test_shell();

    env.set("SUDO_USER", "sudo-user")
        .set("NAILS_TARGET_USER", "target-user")
        .set("USER", "plain-user");

    let result = shell.resolve_target_username().unwrap();

    assert_eq!(result, "sudo-user");
}
#[test]
#[serial]
fn test_resolve_target_username_uses_target_user_fallback() {
    let mut env = EnvGuard::lock();
    let shell = create_test_shell();

    env.remove("SUDO_USER")
        .set("NAILS_TARGET_USER", "target-user")
        .set("USER", "plain-user");

    let result = shell.resolve_target_username().unwrap();

    assert_eq!(result, "target-user");
}
#[test]
#[serial]
fn test_resolve_target_username_uses_user_fallback() {
    let mut env = EnvGuard::lock();
    let shell = create_test_shell();

    env.remove("SUDO_USER")
        .remove("NAILS_TARGET_USER")
        .set("USER", "plain-user");

    let result = shell.resolve_target_username().unwrap();

    assert_eq!(result, "plain-user");
}
#[test]
#[serial]
fn test_resolve_target_username_errors_without_any_user_env() {
    let mut env = EnvGuard::lock();
    let shell = create_test_shell();

    env.remove("SUDO_USER")
        .remove("NAILS_TARGET_USER")
        .remove("USER");

    let err = shell.resolve_target_username().unwrap_err();

    assert!(err.to_string().contains("Could not determine username"));
}
#[test]
#[serial]
fn test_has_explicit_target_user_context_detects_target_user_env() {
    let mut env = EnvGuard::lock();
    env.remove("SUDO_USER").remove("NAILS_TARGET_USER");
    assert!(!ShellInstrumentation::<MockFilesystem>::has_explicit_target_user_context());

    env.set("NAILS_TARGET_USER", "amnesia");
    assert!(ShellInstrumentation::<MockFilesystem>::has_explicit_target_user_context());
}
#[test]
#[serial]
fn test_resolve_home_from_current_environment_uses_matching_home() {
    let mut env = EnvGuard::lock();
    env.remove("SUDO_USER")
        .remove("NAILS_TARGET_USER")
        .set("HOME", "/srv/users/amnesia");

    let result = ShellInstrumentation::<MockFilesystem>::resolve_home_from_current_environment(
        Some("amnesia"),
    );

    assert_eq!(result, Some(PathBuf::from("/srv/users/amnesia")));
}
#[test]
#[serial]
fn test_resolve_home_from_current_environment_rejects_mismatched_home() {
    let mut env = EnvGuard::lock();
    env.remove("SUDO_USER")
        .remove("NAILS_TARGET_USER")
        .set("HOME", "/srv/users/other");

    let result = ShellInstrumentation::<MockFilesystem>::resolve_home_from_current_environment(
        Some("amnesia"),
    );

    assert_eq!(result, None);
}
#[test]
#[serial]
fn test_resolve_home_from_current_environment_ignores_home_for_explicit_target_context() {
    let mut env = EnvGuard::lock();
    env.set("NAILS_TARGET_USER", "amnesia")
        .set("HOME", "/srv/users/amnesia");

    let result = ShellInstrumentation::<MockFilesystem>::resolve_home_from_current_environment(
        Some("amnesia"),
    );

    assert_eq!(result, None);
}
#[test]
#[serial]
fn test_resolve_target_home_dir_prefers_matching_home_env() {
    let mut env = EnvGuard::lock();
    let shell = create_test_shell();

    env.remove("SUDO_USER")
        .remove("NAILS_TARGET_USER")
        .set("USER", "amnesia")
        .set("HOME", "/srv/users/amnesia");

    let result = shell.resolve_target_home_dir().unwrap();

    assert_eq!(result, PathBuf::from("/srv/users/amnesia"));
}
#[test]
#[serial]
fn test_resolve_target_home_dir_falls_back_to_home_username_path_when_home_mismatched() {
    let mut env = EnvGuard::lock();
    let shell = create_test_shell();

    env.remove("SUDO_USER")
        .remove("NAILS_TARGET_USER")
        .set("USER", "amnesia")
        .set("HOME", "/tmp/not-amnesia");

    let result = shell.resolve_target_home_dir().unwrap();

    assert_eq!(result, PathBuf::from("/home/amnesia"));
}
#[test]
#[serial]
fn test_resolve_target_home_dir_ignores_home_env_when_explicit_target_user_is_set() {
    let mut env = EnvGuard::lock();
    let shell = create_test_shell();

    env.remove("SUDO_USER")
        .set("NAILS_TARGET_USER", "amnesia")
        .remove("USER")
        .set("HOME", "/srv/users/amnesia");

    let result = shell.resolve_target_home_dir().unwrap();

    assert_eq!(result, PathBuf::from("/home/amnesia"));
}
#[test]
#[serial]
fn test_resolve_target_home_dir_errors_without_any_user_context() {
    let mut env = EnvGuard::lock();
    let shell = create_test_shell();

    env.remove("SUDO_USER")
        .remove("NAILS_TARGET_USER")
        .remove("USER")
        .remove("HOME");

    let err = shell.resolve_target_home_dir().unwrap_err();

    assert!(err.to_string().contains("Could not determine username"));
}
#[test]
#[serial]
fn test_detect_shell_ignores_mismatched_home_and_falls_back_to_user_home_rc_files() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config::default();
    set_mock_home(&fs, "/home/amnesia");
    fs.mock_set_path_exists("/home/amnesia/.zshrc", true);
    fs.mock_set_path_exists("/tmp/not-amnesia", true);

    env.remove("SHELL")
        .remove("SUDO_USER")
        .remove("NAILS_TARGET_USER")
        .set("USER", "amnesia")
        .set("HOME", "/tmp/not-amnesia");

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.detect_current_shell();

    assert_eq!(result, Some(ShellType::Zsh));
}
#[test]
#[serial]
fn test_detect_shell_defaults_to_bash_for_explicit_target_user_without_rc_files() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config::default();
    set_mock_home(&fs, "/home/amnesia");

    env.remove("SHELL")
        .remove("SUDO_USER")
        .remove("USER")
        .set("NAILS_TARGET_USER", "amnesia");

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.detect_current_shell();

    assert_eq!(result, Some(ShellType::Bash));
}
