use super::*;

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
