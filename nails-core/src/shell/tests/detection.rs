// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

/// A shell instrumentation whose `SHELL` is injected from the startup snapshot,
/// with no attached operator.
fn shell_with_shell_env(shell: &str) -> ShellInstrumentation<MockFilesystem> {
    create_test_shell().with_shell_env(Some(shell.to_string()))
}

/// A shell instrumentation acting for a fixed operator, with `SHELL` unset so
/// detection falls back to probing that operator's rc files.
fn shell_for_user(
    fs: MockFilesystem,
    name: &str,
    home: &str,
) -> ShellInstrumentation<MockFilesystem> {
    let user = TargetUser::for_test(1000, 1000, name, home, "/bin/bash");
    ShellInstrumentation::new(fs, Config::default()).with_target_user(user)
}

#[test]
fn test_detect_bash_shell() {
    let shell = shell_with_shell_env("/bin/bash");
    assert_eq!(shell.detect_current_shell(), Some(ShellType::Bash));
}

#[test]
fn test_detect_zsh_shell() {
    let shell = shell_with_shell_env("/usr/bin/zsh");
    assert_eq!(shell.detect_current_shell(), Some(ShellType::Zsh));
}

#[test]
fn test_detect_fish_shell() {
    let shell = shell_with_shell_env("/usr/local/bin/fish");
    assert_eq!(shell.detect_current_shell(), Some(ShellType::Fish));
}

#[test]
fn test_detect_unsupported_shell() {
    let shell = shell_with_shell_env("/bin/tcsh");
    assert_eq!(shell.detect_current_shell(), None);
}

#[test]
fn test_detect_shell_falls_back_to_zshrc_without_hardcoded_home_prefix() {
    // No SHELL injected: detection resolves the operator's home and probes its
    // rc files. The home need not live under /home.
    let fs = MockFilesystem::new();
    let home = "/srv/users/amnesia";
    set_mock_home(&fs, home);
    fs.mock_set_path_exists(&format!("{home}/.zshrc"), true);

    let shell = shell_for_user(fs, "amnesia", home);

    assert_eq!(shell.detect_current_shell(), Some(ShellType::Zsh));
}

#[test]
fn test_detect_shell_falls_back_to_fish_config_when_shell_env_is_unset() {
    let fs = MockFilesystem::new();
    let home = "/home/amnesia";
    set_mock_home(&fs, home);
    fs.mock_set_path_exists(&format!("{home}/.config/fish/config.fish"), true);

    let shell = shell_for_user(fs, "amnesia", home);

    assert_eq!(shell.detect_current_shell(), Some(ShellType::Fish));
}

#[test]
fn test_detect_shell_returns_none_without_shell_env_operator_or_rc_files() {
    // No SHELL and no attached operator: the home cannot be resolved, so
    // detection reports nothing rather than guessing.
    let shell = create_test_shell();
    assert_eq!(shell.detect_current_shell(), None);
}

#[test]
fn test_detect_shell_probes_the_operators_home_rc_files() {
    // The operator's home carries a .zshrc; detection uses that home, not any
    // ambient value.
    let fs = MockFilesystem::new();
    set_mock_home(&fs, "/home/amnesia");
    fs.mock_set_path_exists("/home/amnesia/.zshrc", true);

    let shell = shell_for_user(fs, "amnesia", "/home/amnesia");

    assert_eq!(shell.detect_current_shell(), Some(ShellType::Zsh));
}

#[test]
fn test_detect_shell_defaults_to_bash_for_known_operator_without_rc_files() {
    let fs = MockFilesystem::new();
    set_mock_home(&fs, "/home/amnesia");

    let shell = shell_for_user(fs, "amnesia", "/home/amnesia");

    assert_eq!(shell.detect_current_shell(), Some(ShellType::Bash));
}

#[test]
fn test_resolve_target_home_dir_uses_the_attached_operator_home() {
    let shell = shell_for_user(MockFilesystem::new(), "amnesia", "/srv/users/amnesia");

    let result = shell.resolve_target_home_dir().unwrap();

    assert_eq!(result, PathBuf::from("/srv/users/amnesia"));
}

#[test]
fn test_resolve_target_home_dir_errors_without_an_attached_operator() {
    let shell = create_test_shell();

    let err = shell.resolve_target_home_dir().unwrap_err();

    assert!(
        err.to_string()
            .contains("Could not determine the target home directory")
    );
}
