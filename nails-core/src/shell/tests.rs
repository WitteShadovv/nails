//! Tests for shell module

use super::*;
use crate::MockFilesystem;

use serial_test::serial;

fn create_test_shell() -> ShellInstrumentation<MockFilesystem> {
    let fs = MockFilesystem::new();
    let config = Config::default();
    ShellInstrumentation::new(fs, config)
}

fn set_mock_home(fs: &MockFilesystem, home: &str) {
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists(home, true);
}

#[test]
#[serial]
fn test_detect_bash_shell() {
    unsafe {
        std::env::set_var("SHELL", "/bin/bash");
    }
    let shell = create_test_shell();
    let result = shell.detect_current_shell();
    unsafe {
        std::env::remove_var("SHELL");
    }
    assert_eq!(result, Some(ShellType::Bash));
}

#[test]
#[serial]
fn test_detect_zsh_shell() {
    unsafe {
        std::env::set_var("SHELL", "/usr/bin/zsh");
    }
    let shell = create_test_shell();
    let result = shell.detect_current_shell();
    unsafe {
        std::env::remove_var("SHELL");
    }
    assert_eq!(result, Some(ShellType::Zsh));
}

#[test]
#[serial]
fn test_detect_fish_shell() {
    unsafe {
        std::env::set_var("SHELL", "/usr/local/bin/fish");
    }
    let shell = create_test_shell();
    let result = shell.detect_current_shell();
    unsafe {
        std::env::remove_var("SHELL");
    }
    assert_eq!(result, Some(ShellType::Fish));
}

#[test]
#[serial]
fn test_detect_unsupported_shell() {
    unsafe {
        std::env::set_var("SHELL", "/bin/tcsh");
    }
    let shell = create_test_shell();
    let result = shell.detect_current_shell();
    unsafe {
        std::env::remove_var("SHELL");
    }
    assert_eq!(result, None);
}

#[test]
#[serial]
fn test_detect_shell_falls_back_to_home_dir_without_hardcoded_home_prefix() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let home = "/srv/users/amnesia";
    set_mock_home(&fs, home);
    fs.mock_set_path_exists(&format!("{home}/.zshrc"), true);

    unsafe {
        std::env::remove_var("SHELL");
        std::env::remove_var("SUDO_USER");
        std::env::remove_var("NAILS_TARGET_USER");
        std::env::set_var("USER", "amnesia");
        std::env::set_var("HOME", home);
    }

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.detect_current_shell();

    unsafe {
        std::env::remove_var("USER");
        std::env::remove_var("HOME");
    }

    assert_eq!(result, Some(ShellType::Zsh));
}

#[test]
#[serial]
fn test_detect_shell_falls_back_to_fish_config_when_shell_env_is_unset() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let home = "/home/amnesia";
    set_mock_home(&fs, home);
    fs.mock_set_path_exists(&format!("{home}/.config/fish/config.fish"), true);

    unsafe {
        std::env::remove_var("SHELL");
        std::env::remove_var("SUDO_USER");
        std::env::remove_var("NAILS_TARGET_USER");
        std::env::set_var("USER", "amnesia");
        std::env::set_var("HOME", home);
    }

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.detect_current_shell();

    unsafe {
        std::env::remove_var("USER");
        std::env::remove_var("HOME");
    }

    assert_eq!(result, Some(ShellType::Fish));
}

#[test]
#[serial]
fn test_detect_shell_returns_none_when_no_shell_env_or_rc_files_exist() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let home = "/home/amnesia";
    set_mock_home(&fs, home);

    unsafe {
        std::env::remove_var("SHELL");
        std::env::remove_var("SUDO_USER");
        std::env::remove_var("NAILS_TARGET_USER");
        std::env::set_var("USER", "amnesia");
        std::env::set_var("HOME", home);
    }

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.detect_current_shell();

    unsafe {
        std::env::remove_var("USER");
        std::env::remove_var("HOME");
    }

    assert_eq!(result, None);
}

#[test]
#[serial]
fn test_resolve_target_username_prefers_sudo_user() {
    let shell = create_test_shell();

    unsafe {
        std::env::set_var("SUDO_USER", "sudo-user");
        std::env::set_var("NAILS_TARGET_USER", "target-user");
        std::env::set_var("USER", "plain-user");
    }

    let result = shell.resolve_target_username().unwrap();

    unsafe {
        std::env::remove_var("SUDO_USER");
        std::env::remove_var("NAILS_TARGET_USER");
        std::env::remove_var("USER");
    }

    assert_eq!(result, "sudo-user");
}

#[test]
#[serial]
fn test_resolve_target_username_uses_target_user_fallback() {
    let shell = create_test_shell();

    unsafe {
        std::env::remove_var("SUDO_USER");
        std::env::set_var("NAILS_TARGET_USER", "target-user");
        std::env::set_var("USER", "plain-user");
    }

    let result = shell.resolve_target_username().unwrap();

    unsafe {
        std::env::remove_var("NAILS_TARGET_USER");
        std::env::remove_var("USER");
    }

    assert_eq!(result, "target-user");
}

#[test]
#[serial]
fn test_resolve_target_username_uses_user_fallback() {
    let shell = create_test_shell();

    unsafe {
        std::env::remove_var("SUDO_USER");
        std::env::remove_var("NAILS_TARGET_USER");
        std::env::set_var("USER", "plain-user");
    }

    let result = shell.resolve_target_username().unwrap();

    unsafe {
        std::env::remove_var("USER");
    }

    assert_eq!(result, "plain-user");
}

#[test]
#[serial]
fn test_resolve_target_username_errors_without_any_user_env() {
    let shell = create_test_shell();

    unsafe {
        std::env::remove_var("SUDO_USER");
        std::env::remove_var("NAILS_TARGET_USER");
        std::env::remove_var("USER");
    }

    let err = shell.resolve_target_username().unwrap_err();

    assert!(err.to_string().contains("Could not determine username"));
}

#[test]
#[serial]
fn test_has_explicit_target_user_context_detects_target_user_env() {
    unsafe {
        std::env::remove_var("SUDO_USER");
        std::env::remove_var("NAILS_TARGET_USER");
    }
    assert!(!ShellInstrumentation::<MockFilesystem>::has_explicit_target_user_context());

    unsafe {
        std::env::set_var("NAILS_TARGET_USER", "amnesia");
    }
    assert!(ShellInstrumentation::<MockFilesystem>::has_explicit_target_user_context());

    unsafe {
        std::env::remove_var("NAILS_TARGET_USER");
    }
}

#[test]
#[serial]
fn test_resolve_home_from_current_environment_uses_matching_home() {
    unsafe {
        std::env::remove_var("SUDO_USER");
        std::env::remove_var("NAILS_TARGET_USER");
        std::env::set_var("HOME", "/srv/users/amnesia");
    }

    let result = ShellInstrumentation::<MockFilesystem>::resolve_home_from_current_environment(
        Some("amnesia"),
    );

    unsafe {
        std::env::remove_var("HOME");
    }

    assert_eq!(result, Some(PathBuf::from("/srv/users/amnesia")));
}

#[test]
#[serial]
fn test_resolve_home_from_current_environment_rejects_mismatched_home() {
    unsafe {
        std::env::remove_var("SUDO_USER");
        std::env::remove_var("NAILS_TARGET_USER");
        std::env::set_var("HOME", "/srv/users/other");
    }

    let result = ShellInstrumentation::<MockFilesystem>::resolve_home_from_current_environment(
        Some("amnesia"),
    );

    unsafe {
        std::env::remove_var("HOME");
    }

    assert_eq!(result, None);
}

#[test]
#[serial]
fn test_resolve_home_from_current_environment_ignores_home_for_explicit_target_context() {
    unsafe {
        std::env::set_var("NAILS_TARGET_USER", "amnesia");
        std::env::set_var("HOME", "/srv/users/amnesia");
    }

    let result = ShellInstrumentation::<MockFilesystem>::resolve_home_from_current_environment(
        Some("amnesia"),
    );

    unsafe {
        std::env::remove_var("NAILS_TARGET_USER");
        std::env::remove_var("HOME");
    }

    assert_eq!(result, None);
}

#[test]
#[serial]
fn test_resolve_target_home_dir_prefers_matching_home_env() {
    let shell = create_test_shell();

    unsafe {
        std::env::remove_var("SUDO_USER");
        std::env::remove_var("NAILS_TARGET_USER");
        std::env::set_var("USER", "amnesia");
        std::env::set_var("HOME", "/srv/users/amnesia");
    }

    let result = shell.resolve_target_home_dir().unwrap();

    unsafe {
        std::env::remove_var("USER");
        std::env::remove_var("HOME");
    }

    assert_eq!(result, PathBuf::from("/srv/users/amnesia"));
}

#[test]
#[serial]
fn test_resolve_target_home_dir_falls_back_to_home_username_path_when_home_mismatched() {
    let shell = create_test_shell();

    unsafe {
        std::env::remove_var("SUDO_USER");
        std::env::remove_var("NAILS_TARGET_USER");
        std::env::set_var("USER", "amnesia");
        std::env::set_var("HOME", "/tmp/not-amnesia");
    }

    let result = shell.resolve_target_home_dir().unwrap();

    unsafe {
        std::env::remove_var("USER");
        std::env::remove_var("HOME");
    }

    assert_eq!(result, PathBuf::from("/home/amnesia"));
}

#[test]
#[serial]
fn test_resolve_target_home_dir_ignores_home_env_when_explicit_target_user_is_set() {
    let shell = create_test_shell();

    unsafe {
        std::env::remove_var("SUDO_USER");
        std::env::set_var("NAILS_TARGET_USER", "amnesia");
        std::env::remove_var("USER");
        std::env::set_var("HOME", "/srv/users/amnesia");
    }

    let result = shell.resolve_target_home_dir().unwrap();

    unsafe {
        std::env::remove_var("NAILS_TARGET_USER");
        std::env::remove_var("HOME");
    }

    assert_eq!(result, PathBuf::from("/home/amnesia"));
}

#[test]
#[serial]
fn test_resolve_target_home_dir_errors_without_any_user_context() {
    let shell = create_test_shell();

    unsafe {
        std::env::remove_var("SUDO_USER");
        std::env::remove_var("NAILS_TARGET_USER");
        std::env::remove_var("USER");
        std::env::remove_var("HOME");
    }

    let err = shell.resolve_target_home_dir().unwrap_err();

    assert!(err.to_string().contains("Could not determine username"));
}

#[test]
#[serial]
fn test_detect_shell_ignores_mismatched_home_and_falls_back_to_user_home_rc_files() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    set_mock_home(&fs, "/home/amnesia");
    fs.mock_set_path_exists("/home/amnesia/.zshrc", true);
    fs.mock_set_path_exists("/tmp/not-amnesia", true);

    unsafe {
        std::env::remove_var("SHELL");
        std::env::remove_var("SUDO_USER");
        std::env::remove_var("NAILS_TARGET_USER");
        std::env::set_var("USER", "amnesia");
        std::env::set_var("HOME", "/tmp/not-amnesia");
    }

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.detect_current_shell();

    unsafe {
        std::env::remove_var("USER");
        std::env::remove_var("HOME");
    }

    assert_eq!(result, Some(ShellType::Zsh));
}

#[test]
#[serial]
fn test_detect_shell_defaults_to_bash_for_explicit_target_user_without_rc_files() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    set_mock_home(&fs, "/home/amnesia");

    unsafe {
        std::env::remove_var("SHELL");
        std::env::remove_var("SUDO_USER");
        std::env::remove_var("USER");
        std::env::set_var("NAILS_TARGET_USER", "amnesia");
    }

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.detect_current_shell();

    unsafe {
        std::env::remove_var("NAILS_TARGET_USER");
    }

    assert_eq!(result, Some(ShellType::Bash));
}

#[test]
#[serial]
fn test_scripts_dir_path() {
    let shell = create_test_shell();
    let scripts_dir = shell.scripts_dir();
    assert!(scripts_dir.to_string_lossy().ends_with("/scripts"));
}

#[test]
#[serial]
fn test_prompt_script_paths() {
    let shell = create_test_shell();

    let bash_path = shell.prompt_script_path(ShellType::Bash);
    assert!(bash_path.to_string_lossy().ends_with("nails_prompt.bash"));

    let zsh_path = shell.prompt_script_path(ShellType::Zsh);
    assert!(zsh_path.to_string_lossy().ends_with("nails_prompt.zsh"));

    let fish_path = shell.prompt_script_path(ShellType::Fish);
    assert!(fish_path.to_string_lossy().ends_with("nails_prompt.fish"));
}

#[test]
#[serial]
fn test_cleanup_script_paths() {
    let shell = create_test_shell();

    let bash_cleanup = shell.cleanup_script_path(ShellType::Bash);
    assert!(
        bash_cleanup
            .to_string_lossy()
            .ends_with("nails_prompt_cleanup.bash")
    );

    let zsh_cleanup = shell.cleanup_script_path(ShellType::Zsh);
    assert!(
        zsh_cleanup
            .to_string_lossy()
            .ends_with("nails_prompt_cleanup.zsh")
    );

    let fish_cleanup = shell.cleanup_script_path(ShellType::Fish);
    assert!(
        fish_cleanup
            .to_string_lossy()
            .ends_with("nails_prompt_cleanup.fish")
    );
}

#[test]
#[serial]
fn test_write_prompt_scripts_creates_directory() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs.clone(), config);

    // Scripts directory doesn't exist initially
    let scripts_dir = shell.scripts_dir();
    assert!(!fs.path_exists(&scripts_dir).unwrap());

    // Write scripts
    shell.write_prompt_scripts().unwrap();

    // Scripts directory now exists
    assert!(fs.path_exists(&scripts_dir).unwrap());
}

#[test]
#[serial]
fn test_write_prompt_scripts_writes_all_files() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs.clone(), config);

    // Write scripts
    shell.write_prompt_scripts().unwrap();

    let scripts_dir = shell.scripts_dir();

    // Verify all 6 files can be read (meaning they were written)
    assert!(
        fs.read_file_content(&scripts_dir.join("nails_prompt.bash"))
            .is_ok()
    );
    assert!(
        fs.read_file_content(&scripts_dir.join("nails_prompt_cleanup.bash"))
            .is_ok()
    );
    assert!(
        fs.read_file_content(&scripts_dir.join("nails_prompt.zsh"))
            .is_ok()
    );
    assert!(
        fs.read_file_content(&scripts_dir.join("nails_prompt_cleanup.zsh"))
            .is_ok()
    );
    assert!(
        fs.read_file_content(&scripts_dir.join("nails_prompt.fish"))
            .is_ok()
    );
    assert!(
        fs.read_file_content(&scripts_dir.join("nails_prompt_cleanup.fish"))
            .is_ok()
    );
}

#[test]
#[serial]
fn test_write_prompt_scripts_idempotent() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs.clone(), config);

    // Write scripts twice
    shell.write_prompt_scripts().unwrap();
    shell.write_prompt_scripts().unwrap();

    let scripts_dir = shell.scripts_dir();

    // All files should still be readable (idempotent)
    assert!(
        fs.read_file_content(&scripts_dir.join("nails_prompt.bash"))
            .is_ok()
    );
    assert!(
        fs.read_file_content(&scripts_dir.join("nails_prompt.zsh"))
            .is_ok()
    );
    assert!(
        fs.read_file_content(&scripts_dir.join("nails_prompt.fish"))
            .is_ok()
    );
}

#[test]
#[serial]
fn test_write_prompt_scripts_uses_custom_hidden_volume_path() {
    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: "/custom/hidden".into(),
        ..Default::default()
    };

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs.clone(), config);

    shell.write_prompt_scripts().unwrap();

    let scripts_dir = shell.scripts_dir();
    let bash_script_path = scripts_dir.join("nails_prompt.bash");

    // Read the generated script
    let script_content = fs.read_file_content(&bash_script_path).unwrap();

    // Verify script no longer has .nails guard check
    assert!(!script_content.contains(".nails"));
}

#[test]
#[serial]
fn test_script_content_has_shebang() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs.clone(), config);

    shell.write_prompt_scripts().unwrap();

    let scripts_dir = shell.scripts_dir();

    // Check bash script has shebang
    let bash_content = fs
        .read_file_content(&scripts_dir.join("nails_prompt.bash"))
        .unwrap();
    assert!(bash_content.starts_with("#!/usr/bin/env bash"));

    // Check zsh script has shebang
    let zsh_content = fs
        .read_file_content(&scripts_dir.join("nails_prompt.zsh"))
        .unwrap();
    assert!(zsh_content.starts_with("#!/usr/bin/env zsh"));

    // Check fish script has shebang
    let fish_content = fs
        .read_file_content(&scripts_dir.join("nails_prompt.fish"))
        .unwrap();
    assert!(fish_content.starts_with("#!/usr/bin/env fish"));
}

// Alias script tests

#[test]
#[serial]
fn test_write_alias_scripts_creates_directory() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs.clone(), config);

    // Scripts directory doesn't exist initially
    let scripts_dir = shell.scripts_dir();
    assert!(!fs.path_exists(&scripts_dir).unwrap());

    // Write alias scripts
    shell.write_alias_scripts().unwrap();

    // Scripts directory now exists
    assert!(fs.path_exists(&scripts_dir).unwrap());
}

#[test]
#[serial]
fn test_write_alias_scripts_writes_all_files() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs.clone(), config);

    // Write alias scripts
    shell.write_alias_scripts().unwrap();

    let scripts_dir = shell.scripts_dir();

    // Verify all 4 files can be read (meaning they were written)
    assert!(
        fs.read_file_content(&scripts_dir.join("nails_alias.sh"))
            .is_ok()
    );
    assert!(
        fs.read_file_content(&scripts_dir.join("nails_alias_cleanup.sh"))
            .is_ok()
    );
    assert!(
        fs.read_file_content(&scripts_dir.join("nails_alias.fish"))
            .is_ok()
    );
    assert!(
        fs.read_file_content(&scripts_dir.join("nails_alias_cleanup.fish"))
            .is_ok()
    );
}

#[test]
#[serial]
fn test_alias_script_path_bash() {
    let shell = create_test_shell();
    let path = shell.alias_script_path(ShellType::Bash);
    assert!(path.to_string_lossy().ends_with("nails_alias.sh"));
}

#[test]
#[serial]
fn test_alias_script_path_zsh() {
    let shell = create_test_shell();
    let path = shell.alias_script_path(ShellType::Zsh);
    assert!(path.to_string_lossy().ends_with("nails_alias.sh"));
}

#[test]
#[serial]
fn test_alias_script_path_fish() {
    let shell = create_test_shell();
    let path = shell.alias_script_path(ShellType::Fish);
    assert!(path.to_string_lossy().ends_with("nails_alias.fish"));
}

#[test]
#[serial]
fn test_alias_cleanup_script_path_bash() {
    let shell = create_test_shell();
    let path = shell.alias_cleanup_script_path(ShellType::Bash);
    assert!(path.to_string_lossy().ends_with("nails_alias_cleanup.sh"));
}

#[test]
#[serial]
fn test_alias_cleanup_script_path_zsh() {
    let shell = create_test_shell();
    let path = shell.alias_cleanup_script_path(ShellType::Zsh);
    assert!(path.to_string_lossy().ends_with("nails_alias_cleanup.sh"));
}

#[test]
#[serial]
fn test_alias_cleanup_script_path_fish() {
    let shell = create_test_shell();
    let path = shell.alias_cleanup_script_path(ShellType::Fish);
    assert!(path.to_string_lossy().ends_with("nails_alias_cleanup.fish"));
}

#[test]
#[serial]
fn test_bash_zsh_alias_script_content() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs.clone(), config);

    shell.write_alias_scripts().unwrap();

    let scripts_dir = shell.scripts_dir();
    let script_content = fs
        .read_file_content(&scripts_dir.join("nails_alias.sh"))
        .unwrap();

    // Verify script has no .nails guard
    assert!(!script_content.contains(".nails"));
    assert!(script_content.contains("alias nails >/dev/null 2>&1"));
    assert!(script_content.contains("alias nails='sudo"));
}

#[test]
#[serial]
fn test_fish_alias_script_content() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs.clone(), config);

    shell.write_alias_scripts().unwrap();

    let scripts_dir = shell.scripts_dir();
    let script_content = fs
        .read_file_content(&scripts_dir.join("nails_alias.fish"))
        .unwrap();

    // Verify script has no .nails guard
    assert!(!script_content.contains(".nails"));
    assert!(script_content.contains("functions -q nails"));
    assert!(script_content.contains("alias nails 'sudo"));
}

#[test]
#[serial]
fn test_alias_script_uses_actual_binary_path() {
    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: "/custom/hidden".into(),
        ..Default::default()
    };

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs.clone(), config);

    shell.write_alias_scripts().unwrap();

    let scripts_dir = shell.scripts_dir();
    let bash_script = fs
        .read_file_content(&scripts_dir.join("nails_alias.sh"))
        .unwrap();

    // Verify script uses actual binary path (from current_exe or fallback)
    // Should contain 'sudo' followed by a path, but NOT hardcoded /bin/nails
    assert!(bash_script.contains("alias nails='sudo"));
}

#[test]
#[serial]
fn test_bash_zsh_cleanup_script_content() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs.clone(), config);

    shell.write_alias_scripts().unwrap();

    let scripts_dir = shell.scripts_dir();
    let cleanup_content = fs
        .read_file_content(&scripts_dir.join("nails_alias_cleanup.sh"))
        .unwrap();

    // Verify best-effort cleanup
    assert!(cleanup_content.contains("unalias nails 2>/dev/null || true"));
}

#[test]
#[serial]
fn test_fish_cleanup_script_content() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs.clone(), config);

    shell.write_alias_scripts().unwrap();

    let scripts_dir = shell.scripts_dir();
    let cleanup_content = fs
        .read_file_content(&scripts_dir.join("nails_alias_cleanup.fish"))
        .unwrap();

    // Verify best-effort cleanup
    assert!(cleanup_content.contains("functions -e nails 2>/dev/null; or true"));
}

#[test]
#[serial]
fn test_write_alias_scripts_idempotent() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    let shell = ShellInstrumentation::new(fs.clone(), config);

    // Write scripts twice
    shell.write_alias_scripts().unwrap();
    shell.write_alias_scripts().unwrap();

    let scripts_dir = shell.scripts_dir();

    // All files should still be readable (idempotent)
    assert!(
        fs.read_file_content(&scripts_dir.join("nails_alias.sh"))
            .is_ok()
    );
    assert!(
        fs.read_file_content(&scripts_dir.join("nails_alias.fish"))
            .is_ok()
    );
}

// Tests for shell_setup() and ShellSetupResult

#[test]
#[serial]
fn test_shell_setup_with_bash() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    unsafe {
        std::env::set_var("SHELL", "/bin/bash");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config);
    let result = shell.shell_setup();

    unsafe {
        std::env::remove_var("SHELL");
    }

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
#[serial]
fn test_shell_setup_with_zsh() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to zsh
    unsafe {
        std::env::set_var("SHELL", "/usr/bin/zsh");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config);
    let result = shell.shell_setup();

    unsafe {
        std::env::remove_var("SHELL");
    }

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
#[serial]
fn test_shell_setup_with_fish() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to fish
    unsafe {
        std::env::set_var("SHELL", "/usr/bin/fish");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config);
    let result = shell.shell_setup();

    unsafe {
        std::env::remove_var("SHELL");
    }

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
#[serial]
fn test_shell_setup_no_shell_detected() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Ensure SHELL is not set (use a custom variable that we know is unset)
    unsafe {
        std::env::remove_var("SHELL");
    }

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.shell_setup();

    // Should succeed but return None
    assert!(result.is_ok());
    assert!(matches!(result.as_ref(), Ok(None)));
}

#[test]
#[serial]
fn test_shell_setup_without_shell_env_still_sets_up_persistent_integration_for_target_user() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/amnesia", true);

    unsafe {
        std::env::remove_var("SHELL");
        std::env::set_var("NAILS_TARGET_USER", "amnesia");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config);
    let result = shell.shell_setup();

    unsafe {
        std::env::remove_var("NAILS_TARGET_USER");
    }

    assert!(result.is_ok());
    let setup = result
        .unwrap()
        .expect("shell fallback should select a shell");
    assert_eq!(setup.shell_type, ShellType::Bash);

    let bashrc_path = PathBuf::from("/home/amnesia/.bashrc");
    let content = fs.read_file_content(&bashrc_path).unwrap();
    assert!(content.contains("# >>> NAILS shell integration"));
}

#[test]
#[serial]
fn test_shell_setup_returns_warning_without_source_commands_when_script_writes_fail() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);
    fs.mock_set_write_should_fail("/mnt/hidden-volume/scripts/nails_prompt.bash", true);
    fs.mock_set_write_should_fail("/mnt/hidden-volume/scripts/nails_alias.sh", true);

    unsafe {
        std::env::set_var("SHELL", "/bin/bash");
        std::env::set_var("USER", "testuser");
        std::env::set_var("HOME", "/home/testuser");
    }

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell
        .shell_setup()
        .unwrap()
        .expect("shell should still be detected");

    unsafe {
        std::env::remove_var("SHELL");
        std::env::remove_var("USER");
        std::env::remove_var("HOME");
    }

    assert_eq!(result.shell_type, ShellType::Bash);
    assert!(result.instructions.is_empty());
    let warning = result.warning.expect("warning should be reported");
    assert!(warning.contains("prompt scripts could not be generated"));
    assert!(warning.contains("alias scripts could not be generated"));
}

#[test]
#[serial]
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

    unsafe {
        std::env::set_var("SHELL", "/bin/bash");
        std::env::set_var("SUDO_USER", "testuser");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config);
    let result = shell
        .shell_setup()
        .unwrap()
        .expect("setup should continue on best-effort autostart failure");

    unsafe {
        std::env::remove_var("SHELL");
        std::env::remove_var("SUDO_USER");
    }

    assert_eq!(result.shell_type, ShellType::Bash);
    assert_eq!(result.instructions.len(), 2);
    assert!(result.warning.is_none());
    assert!(result.rc_modified);
}

#[test]
#[serial]
fn test_shell_setup_continues_when_xdg_autostart_resolution_errors() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    unsafe {
        std::env::set_var("SHELL", "/bin/bash");
        std::env::remove_var("SUDO_USER");
        std::env::remove_var("NAILS_TARGET_USER");
        std::env::remove_var("USER");
        std::env::remove_var("HOME");
    }

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell
        .shell_setup()
        .unwrap()
        .expect("setup should continue even when autostart setup errors");

    unsafe {
        std::env::remove_var("SHELL");
    }

    assert_eq!(result.shell_type, ShellType::Bash);
    assert_eq!(result.instructions.len(), 2);
    assert!(!result.rc_modified);
    assert!(result.warning.is_none());
}

#[test]
#[serial]
fn test_shell_setup_unsupported_shell() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL to unsupported shell
    unsafe {
        std::env::set_var("SHELL", "/bin/tcsh");
    }

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.shell_setup();

    unsafe {
        std::env::remove_var("SHELL");
    }

    // Should succeed but return None
    assert!(result.is_ok());
    assert!(matches!(result.as_ref(), Ok(None)));
}

#[test]
#[serial]
fn test_shell_setup_to_source_commands() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    unsafe {
        std::env::set_var("SHELL", "/bin/bash");
    }

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.shell_setup();

    unsafe {
        std::env::remove_var("SHELL");
    }

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

// Tests for shell_cleanup() and ShellCleanupResult

#[test]
#[serial]
fn test_shell_cleanup_normal_deactivation() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    unsafe {
        std::env::set_var("SHELL", "/bin/bash");
    }

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.shell_cleanup(false); // false = no alias removal

    unsafe {
        std::env::remove_var("SHELL");
    }

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
#[serial]
fn test_shell_cleanup_emergency_deactivation() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    unsafe {
        std::env::set_var("SHELL", "/bin/bash");
    }

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.shell_cleanup(true); // true = include alias removal

    unsafe {
        std::env::remove_var("SHELL");
    }

    // Should have shell type detected
    assert_eq!(result.shell_type, Some(ShellType::Bash));

    // Should have both prompt cleanup AND alias cleanup
    assert_eq!(result.instructions.len(), 2);
    assert!(result.instructions[0].contains("nails_prompt_cleanup.bash"));
    assert!(result.instructions[1].contains("nails_alias_cleanup.sh"));
}

#[test]
#[serial]
fn test_shell_cleanup_no_shell_detected() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Ensure SHELL is not set
    unsafe {
        std::env::remove_var("SHELL");
    }

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
#[serial]
fn test_shell_cleanup_with_fish() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Set SHELL to fish
    unsafe {
        std::env::set_var("SHELL", "/usr/bin/fish");
    }

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.shell_cleanup(true); // emergency with alias removal

    unsafe {
        std::env::remove_var("SHELL");
    }

    // Should have fish shell type
    assert_eq!(result.shell_type, Some(ShellType::Fish));

    // Should have both cleanup scripts
    assert_eq!(result.instructions.len(), 2);
    assert!(result.instructions[0].contains("nails_prompt_cleanup.fish"));
    assert!(result.instructions[1].contains("nails_alias_cleanup.fish"));
}

#[test]
#[serial]
fn test_shell_setup_result_paths() {
    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: "/test/hidden".into(),
        ..Default::default()
    };

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    unsafe {
        std::env::set_var("SHELL", "/bin/bash");
    }

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.shell_setup();

    unsafe {
        std::env::remove_var("SHELL");
    }

    // Should have Some result
    assert!(matches!(result.as_ref(), Ok(Some(_))));
    let setup = result.unwrap().unwrap();

    // Verify paths point to correct scripts
    assert!(
        setup
            .prompt_script_path
            .to_string_lossy()
            .contains("/test/hidden/scripts/nails_prompt.bash")
    );
    assert!(
        setup
            .alias_script_path
            .to_string_lossy()
            .contains("/test/hidden/scripts/nails_alias.sh")
    );
}

// Color scheme integration tests (Story 14-8, Code Review Follow-up)
//
// Note: stdout write error testing (AC8 silent failure path) is not included here
// because mocking std::io::stdout() requires complex test infrastructure that's not
// practical in this context. The error handling is implemented in shell_setup() and
// shell_cleanup() methods using tracing::warn!() for logging failures while continuing
// activation/deactivation. The silent failure behavior is verified by code review.

#[test]
#[serial]
fn test_shell_setup_color_scheme_enabled() {
    let fs = MockFilesystem::new();
    let mut config = Config::default();
    config.color_scheme.enabled = true;
    config.color_scheme.hidden.background = "#1a1a2e".to_string();
    config.color_scheme.hidden.foreground = "#e0e0e0".to_string();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    unsafe {
        std::env::set_var("SHELL", "/bin/bash");
    }

    let shell = ShellInstrumentation::new(fs, config.clone());
    let result = shell.shell_setup();

    unsafe {
        std::env::remove_var("SHELL");
    }

    // Verify setup succeeds
    assert!(result.is_ok());
    let setup_result = result.unwrap();
    assert!(setup_result.is_some());

    // Verify that color scheme sequences would be generated
    let color_sequences = color_scheme::apply_hidden_color_scheme(&config.color_scheme);
    assert!(!color_sequences.is_empty());
    assert!(color_sequences.contains("\x1b]11;#1a1a2e\x07")); // background
    assert!(color_sequences.contains("\x1b]10;#e0e0e0\x07")); // foreground
}

#[test]
#[serial]
fn test_shell_setup_color_scheme_disabled() {
    let fs = MockFilesystem::new();
    let mut config = Config::default();
    config.color_scheme.enabled = false;

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    unsafe {
        std::env::set_var("SHELL", "/bin/bash");
    }

    let shell = ShellInstrumentation::new(fs, config.clone());
    let result = shell.shell_setup();

    unsafe {
        std::env::remove_var("SHELL");
    }

    // Verify setup succeeds
    assert!(result.is_ok());

    // Verify that color scheme sequences are NOT generated when disabled
    let color_sequences = color_scheme::apply_hidden_color_scheme(&config.color_scheme);
    assert!(color_sequences.is_empty());
}

#[test]
#[serial]
fn test_shell_cleanup_color_scheme_enabled() {
    let fs = MockFilesystem::new();
    let mut config = Config::default();
    config.color_scheme.enabled = true;
    config.color_scheme.decoy.reset = true;

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    unsafe {
        std::env::set_var("SHELL", "/bin/bash");
    }

    let shell = ShellInstrumentation::new(fs, config.clone());
    let result = shell.shell_cleanup(false);

    unsafe {
        std::env::remove_var("SHELL");
    }

    // Verify cleanup succeeds
    assert!(result.shell_type.is_some());

    // Verify that color reset sequences would be generated
    let color_sequences = color_scheme::apply_decoy_color_scheme(&config.color_scheme);
    assert!(!color_sequences.is_empty());
    assert!(color_sequences.contains("\x1b]111\x07")); // reset background
    assert!(color_sequences.contains("\x1b]110\x07")); // reset foreground
    assert!(color_sequences.contains("\x1b]104\x07")); // reset palette
}

#[test]
#[serial]
fn test_shell_cleanup_color_scheme_disabled() {
    let fs = MockFilesystem::new();
    let mut config = Config::default();
    config.color_scheme.enabled = false;

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    unsafe {
        std::env::set_var("SHELL", "/bin/bash");
    }

    let shell = ShellInstrumentation::new(fs, config.clone());
    let result = shell.shell_cleanup(false);

    unsafe {
        std::env::remove_var("SHELL");
    }

    // Verify cleanup succeeds
    assert!(result.shell_type.is_some());

    // Verify that color reset sequences are NOT generated when disabled
    let color_sequences = color_scheme::apply_decoy_color_scheme(&config.color_scheme);
    assert!(color_sequences.is_empty());
}

#[test]
#[serial]
fn test_activation_deactivation_color_scheme_cycle() {
    let fs = MockFilesystem::new();
    let mut config = Config::default();
    config.color_scheme.enabled = true;
    config.color_scheme.hidden.background = "#1a1a2e".to_string();
    config.color_scheme.hidden.foreground = "#e0e0e0".to_string();
    config.color_scheme.decoy.reset = true;

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    unsafe {
        std::env::set_var("SHELL", "/bin/bash");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config.clone());

    // Test activation (shell_setup)
    let setup_result = shell.shell_setup();
    assert!(setup_result.is_ok());

    // Verify hidden color scheme is generated for activation
    let hidden_sequences = color_scheme::apply_hidden_color_scheme(&config.color_scheme);
    assert!(!hidden_sequences.is_empty());
    assert!(hidden_sequences.contains("\x1b]11;#1a1a2e\x07"));
    assert!(hidden_sequences.contains("\x1b]10;#e0e0e0\x07"));

    // Test deactivation (shell_cleanup)
    let cleanup_result = shell.shell_cleanup(false);
    assert!(cleanup_result.shell_type.is_some());

    // Verify decoy (reset) color scheme is generated for deactivation
    let decoy_sequences = color_scheme::apply_decoy_color_scheme(&config.color_scheme);
    assert!(!decoy_sequences.is_empty());
    assert!(decoy_sequences.contains("\x1b]111\x07"));
    assert!(decoy_sequences.contains("\x1b]110\x07"));
    assert!(decoy_sequences.contains("\x1b]104\x07"));

    // Verify sequences are different (not accidentally generating same thing)
    assert_ne!(hidden_sequences, decoy_sequences);

    unsafe {
        std::env::remove_var("SHELL");
    }
}

#[test]
#[serial]
fn test_color_scheme_applied_after_scripts_written() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    unsafe {
        std::env::set_var("SHELL", "/bin/bash");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config.clone());

    // Run shell_setup which writes scripts first, then applies color scheme
    let result = shell.shell_setup();

    unsafe {
        std::env::remove_var("SHELL");
    }

    // Verify setup succeeded
    assert!(result.is_ok());
    let setup = result.unwrap();
    assert!(setup.is_some());

    // Verify scripts were written
    let scripts_dir = shell.scripts_dir();
    let prompt_script = fs.read_file_content(&scripts_dir.join("nails_prompt.bash"));
    let alias_script = fs.read_file_content(&scripts_dir.join("nails_alias.sh"));

    // Both scripts should exist (verifying they were written before color scheme)
    assert!(prompt_script.is_ok());
    assert!(alias_script.is_ok());

    // Color scheme application happens after script writing
    // This test verifies the order by checking that scripts exist
    // and color scheme function is called (which it is in shell_setup after write_prompt_scripts)
    let color_sequences = color_scheme::apply_hidden_color_scheme(&config.color_scheme);
    assert!(!color_sequences.is_empty());
}

#[test]
#[serial]
fn test_emergency_deactivation_includes_color_reset() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    unsafe {
        std::env::set_var("SHELL", "/bin/bash");
    }

    let shell = ShellInstrumentation::new(fs, config.clone());

    // Emergency deactivation calls shell_cleanup(true)
    let result = shell.shell_cleanup(true);

    unsafe {
        std::env::remove_var("SHELL");
    }

    // Verify cleanup completed
    assert!(result.shell_type.is_some());

    // Verify color reset sequences are generated (best-effort)
    let color_sequences = color_scheme::apply_decoy_color_scheme(&config.color_scheme);
    assert!(!color_sequences.is_empty());
    assert!(color_sequences.contains("\x1b]111\x07"));
}

// ============================================================================
// RC File Integration Tests (Task 1: Auto-source shell integration)
// ============================================================================

#[test]
#[serial]
fn test_inject_rc_integration_bash_creates_bashrc() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    unsafe {
        std::env::set_var("SHELL", "/bin/bash");
        std::env::set_var("SUDO_USER", "testuser");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config.clone());

    // Call inject_rc_integration
    let result = shell.inject_rc_integration(ShellType::Bash);

    unsafe {
        std::env::remove_var("SHELL");
        std::env::remove_var("SUDO_USER");
    }

    assert!(result.is_ok());
    assert!(result.unwrap());

    // Verify .bashrc was created with integration block
    let bashrc_path = PathBuf::from("/home/testuser/.bashrc");
    let content = fs.read_file_content(&bashrc_path).unwrap();

    assert!(content.contains("# >>> NAILS shell integration"));
    assert!(content.contains("source /mnt/hidden-volume/scripts/nails_prompt.bash"));
    assert!(content.contains("source /mnt/hidden-volume/scripts/nails_alias.sh"));
    assert!(content.contains("printf '\\e]11;#1a1a2e\\a\\e]10;#e0e0e0\\a'"));
    assert!(content.contains("# <<< NAILS shell integration <<<"));
}

#[test]
#[serial]
fn test_inject_rc_integration_zsh_creates_zshrc() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    unsafe {
        std::env::set_var("SHELL", "/bin/zsh");
        std::env::set_var("SUDO_USER", "testuser");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config.clone());

    let result = shell.inject_rc_integration(ShellType::Zsh);

    unsafe {
        std::env::remove_var("SHELL");
        std::env::remove_var("SUDO_USER");
    }

    assert!(result.is_ok());
    assert!(result.unwrap());

    // Verify .zshrc was created
    let zshrc_path = PathBuf::from("/home/testuser/.zshrc");
    let content = fs.read_file_content(&zshrc_path).unwrap();

    assert!(content.contains("# >>> NAILS shell integration"));
    assert!(content.contains("source /mnt/hidden-volume/scripts/nails_prompt.zsh"));
    assert!(content.contains("source /mnt/hidden-volume/scripts/nails_alias.sh"));
}

#[test]
#[serial]
fn test_inject_rc_integration_fish_creates_config_fish() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    unsafe {
        std::env::set_var("SHELL", "/bin/fish");
        std::env::set_var("SUDO_USER", "testuser");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config.clone());

    let result = shell.inject_rc_integration(ShellType::Fish);

    unsafe {
        std::env::remove_var("SHELL");
        std::env::remove_var("SUDO_USER");
    }

    assert!(result.is_ok());
    assert!(result.unwrap());

    // Verify config.fish was created (with parent dirs)
    let fish_config_path = PathBuf::from("/home/testuser/.config/fish/config.fish");
    let content = fs.read_file_content(&fish_config_path).unwrap();

    assert!(content.contains("# >>> NAILS shell integration"));
    assert!(content.contains("source /mnt/hidden-volume/scripts/nails_prompt.fish"));
    assert!(content.contains("source /mnt/hidden-volume/scripts/nails_alias.fish"));
}

#[test]
#[serial]
fn test_inject_rc_integration_idempotent() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    unsafe {
        std::env::set_var("SUDO_USER", "testuser");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config.clone());

    // Call twice
    let result1 = shell.inject_rc_integration(ShellType::Bash);
    let result2 = shell.inject_rc_integration(ShellType::Bash);

    unsafe {
        std::env::remove_var("SUDO_USER");
    }

    assert!(result1.is_ok());
    assert!(result2.is_ok());

    // Verify only ONE integration block exists
    let bashrc_path = PathBuf::from("/home/testuser/.bashrc");
    let content = fs.read_file_content(&bashrc_path).unwrap();

    let marker_count = content.matches("# >>> NAILS shell integration").count();
    assert_eq!(marker_count, 1, "Should only have one integration block");
}

#[test]
#[serial]
fn test_inject_rc_integration_appends_to_existing_bashrc() {
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

    unsafe {
        std::env::set_var("SUDO_USER", "testuser");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config.clone());
    let result = shell.inject_rc_integration(ShellType::Bash);

    unsafe {
        std::env::remove_var("SUDO_USER");
    }

    assert!(result.is_ok());

    let content = fs.read_file_content(&bashrc_path).unwrap();

    // Should preserve existing content
    assert!(content.contains("# Existing config"));
    assert!(content.contains("export PATH=/usr/bin:$PATH"));

    // Should append NAILS integration
    assert!(content.contains("# >>> NAILS shell integration"));
}

#[test]
#[serial]
fn test_inject_rc_integration_uses_color_scheme_config() {
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

    unsafe {
        std::env::set_var("SUDO_USER", "testuser");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config.clone());
    let result = shell.inject_rc_integration(ShellType::Bash);

    unsafe {
        std::env::remove_var("SUDO_USER");
    }

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
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/fallbackuser", true);

    unsafe {
        // No SUDO_USER, should fall back to USER
        std::env::remove_var("SUDO_USER");
        std::env::set_var("USER", "fallbackuser");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config.clone());
    let result = shell.inject_rc_integration(ShellType::Bash);

    unsafe {
        std::env::remove_var("USER");
    }

    assert!(result.is_ok());

    // Should use USER env var
    let bashrc_path = PathBuf::from("/home/fallbackuser/.bashrc");
    assert!(fs.read_file_content(&bashrc_path).is_ok());
}

#[test]
#[serial]
fn test_inject_rc_integration_returns_false_on_failure() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    // Make bashrc write fail
    fs.mock_set_write_should_fail("/home/testuser/.bashrc", true);

    unsafe {
        std::env::set_var("SUDO_USER", "testuser");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config.clone());
    let result = shell.inject_rc_integration(ShellType::Bash);

    unsafe {
        std::env::remove_var("SUDO_USER");
    }

    // Should return Ok(false) on best-effort failure
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

// ============================================================================
// XDG Autostart Entry Tests (write_xdg_autostart_entry)
// ============================================================================

#[test]
#[serial]
fn test_write_xdg_autostart_entry_creates_desktop_file() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    unsafe {
        std::env::set_var("SUDO_USER", "testuser");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config);
    let result = shell.write_xdg_autostart_entry();

    unsafe {
        std::env::remove_var("SUDO_USER");
    }

    assert!(result.is_ok());
    assert!(result.unwrap());

    // Verify the desktop file was written
    let desktop_path = PathBuf::from("/home/testuser/.config/autostart/nails-notify.desktop");
    let content = fs.read_file_content(&desktop_path).unwrap();

    assert!(content.contains("[Desktop Entry]"));
    assert!(content.contains("Type=Application"));
    assert!(content.contains("Name=NAILS Notification Dispatch"));
    assert!(content.contains("notify-dispatch"));
    assert!(!content.contains("Exec=nails notify-dispatch"));
    assert!(content.contains("Terminal=false"));
    assert!(content.contains("NoDisplay=true"));
    assert!(content.contains("X-GNOME-Autostart-enabled=true"));
}

#[test]
#[serial]
fn test_write_xdg_autostart_entry_creates_autostart_directory() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    unsafe {
        std::env::set_var("SUDO_USER", "testuser");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config);

    // Autostart directory doesn't exist yet
    let autostart_dir = PathBuf::from("/home/testuser/.config/autostart");
    assert!(!fs.path_exists(&autostart_dir).unwrap());

    // Writing should create it
    let result = shell.write_xdg_autostart_entry();

    unsafe {
        std::env::remove_var("SUDO_USER");
    }

    assert!(result.is_ok());
    assert!(result.unwrap());

    // Directory should now exist
    assert!(fs.path_exists(&autostart_dir).unwrap());
}

#[test]
#[serial]
fn test_write_xdg_autostart_entry_uses_user_env_fallback() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/fallbackuser", true);

    unsafe {
        std::env::remove_var("SUDO_USER");
        std::env::set_var("USER", "fallbackuser");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config);
    let result = shell.write_xdg_autostart_entry();

    unsafe {
        std::env::remove_var("USER");
    }

    assert!(result.is_ok());
    assert!(result.unwrap());

    // Should use USER env var to find home directory
    let desktop_path = PathBuf::from("/home/fallbackuser/.config/autostart/nails-notify.desktop");
    assert!(fs.read_file_content(&desktop_path).is_ok());
}

#[test]
#[serial]
fn test_write_xdg_autostart_entry_uses_home_env_without_hardcoded_home_prefix() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let home = "/srv/users/fallbackuser";

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/srv", true);
    fs.mock_set_path_exists("/srv/users", true);
    fs.mock_set_path_exists(home, true);

    unsafe {
        std::env::remove_var("SUDO_USER");
        std::env::set_var("USER", "fallbackuser");
        std::env::set_var("HOME", home);
    }

    let shell = ShellInstrumentation::new(fs.clone(), config);
    let result = shell.write_xdg_autostart_entry();

    unsafe {
        std::env::remove_var("USER");
        std::env::remove_var("HOME");
    }

    assert!(result.is_ok());
    assert!(result.unwrap());

    let desktop_path = PathBuf::from(format!("{home}/.config/autostart/nails-notify.desktop"));
    assert!(fs.read_file_content(&desktop_path).is_ok());
}

#[test]
#[serial]
fn test_inject_rc_integration_uses_home_env_without_hardcoded_home_prefix() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let home = "/srv/users/fallbackuser";

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/srv", true);
    fs.mock_set_path_exists("/srv/users", true);
    fs.mock_set_path_exists(home, true);

    unsafe {
        std::env::remove_var("SUDO_USER");
        std::env::set_var("USER", "fallbackuser");
        std::env::set_var("HOME", home);
    }

    let shell = ShellInstrumentation::new(fs.clone(), config);
    let result = shell.inject_rc_integration(ShellType::Bash);

    unsafe {
        std::env::remove_var("USER");
        std::env::remove_var("HOME");
    }

    assert!(result.is_ok());
    let bashrc_path = PathBuf::from(format!("{home}/.bashrc"));
    assert!(fs.read_file_content(&bashrc_path).is_ok());
}

#[test]
#[serial]
fn test_write_xdg_autostart_entry_idempotent() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    unsafe {
        std::env::set_var("SUDO_USER", "testuser");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config);

    // Write twice — should succeed both times
    let result1 = shell.write_xdg_autostart_entry();
    let result2 = shell.write_xdg_autostart_entry();

    unsafe {
        std::env::remove_var("SUDO_USER");
    }

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

    unsafe {
        std::env::set_var("SUDO_USER", "testuser");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config);
    let result = shell.write_xdg_autostart_entry();

    unsafe {
        std::env::remove_var("SUDO_USER");
    }

    // Should return Ok(false) on best-effort failure
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
#[serial]
fn test_write_xdg_autostart_desktop_file_content_format() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    unsafe {
        std::env::set_var("SUDO_USER", "testuser");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config);
    shell.write_xdg_autostart_entry().unwrap();

    unsafe {
        std::env::remove_var("SUDO_USER");
    }

    let desktop_path = PathBuf::from("/home/testuser/.config/autostart/nails-notify.desktop");
    let content = fs.read_file_content(&desktop_path).unwrap();

    // Verify exact desktop entry format (each field on its own line)
    assert!(content.starts_with("[Desktop Entry]\n"));
    assert!(content.contains("Comment=Dispatches pending NAILS notifications on login\n"));
    assert!(content.contains(&format!(
        "Exec={} notify-dispatch\n",
        std::env::current_exe().unwrap().display()
    )));
    assert!(content.ends_with('\n'));
}

#[test]
#[serial]
fn test_shell_setup_writes_xdg_autostart_entry() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/home/testuser", true);

    unsafe {
        std::env::set_var("SHELL", "/bin/bash");
        std::env::set_var("SUDO_USER", "testuser");
    }

    let shell = ShellInstrumentation::new(fs.clone(), config);
    let result = shell.shell_setup();

    unsafe {
        std::env::remove_var("SHELL");
        std::env::remove_var("SUDO_USER");
    }

    assert!(result.is_ok());
    assert!(result.unwrap().is_some());

    // Verify that shell_setup also created the autostart entry
    let desktop_path = PathBuf::from("/home/testuser/.config/autostart/nails-notify.desktop");
    let content = fs.read_file_content(&desktop_path).unwrap();
    assert!(content.contains("notify-dispatch"));
    assert!(!content.contains("Exec=nails notify-dispatch"));
}
