// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
fn test_scripts_dir_path() {
    let shell = create_test_shell();
    let scripts_dir = shell.scripts_dir();
    assert!(scripts_dir.to_string_lossy().ends_with("/scripts"));
}
#[test]
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
fn test_write_prompt_scripts_uses_custom_hidden_volume_root() {
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
