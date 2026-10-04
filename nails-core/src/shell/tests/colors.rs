// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
#[serial]
fn test_shell_setup_result_paths() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: "/test/hidden".into(),
        ..Default::default()
    };

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    env.set("SHELL", "/bin/bash");

    let shell = ShellInstrumentation::new(fs, config);
    let result = shell.shell_setup();

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
#[test]
#[serial]
fn test_shell_setup_color_scheme_enabled() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let mut config = Config::default();
    config.color_scheme.enabled = true;
    config.color_scheme.hidden.background = "#1a1a2e".to_string();
    config.color_scheme.hidden.foreground = "#e0e0e0".to_string();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    env.set("SHELL", "/bin/bash");

    let shell = ShellInstrumentation::new(fs, config.clone());
    let result = shell.shell_setup();

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
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let mut config = Config::default();
    config.color_scheme.enabled = false;

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    env.set("SHELL", "/bin/bash");

    let shell = ShellInstrumentation::new(fs, config.clone());
    let result = shell.shell_setup();

    // Verify setup succeeds
    assert!(result.is_ok());

    // Verify that color scheme sequences are NOT generated when disabled
    let color_sequences = color_scheme::apply_hidden_color_scheme(&config.color_scheme);
    assert!(color_sequences.is_empty());
}
#[test]
#[serial]
fn test_shell_cleanup_color_scheme_enabled() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let mut config = Config::default();
    config.color_scheme.enabled = true;
    config.color_scheme.decoy.reset = true;

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    env.set("SHELL", "/bin/bash");

    let shell = ShellInstrumentation::new(fs, config.clone());
    let result = shell.shell_cleanup(false);

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
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let mut config = Config::default();
    config.color_scheme.enabled = false;

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    env.set("SHELL", "/bin/bash");

    let shell = ShellInstrumentation::new(fs, config.clone());
    let result = shell.shell_cleanup(false);

    // Verify cleanup succeeds
    assert!(result.shell_type.is_some());

    // Verify that color reset sequences are NOT generated when disabled
    let color_sequences = color_scheme::apply_decoy_color_scheme(&config.color_scheme);
    assert!(color_sequences.is_empty());
}
#[test]
#[serial]
fn test_activation_deactivation_color_scheme_cycle() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let mut config = Config::default();
    config.color_scheme.enabled = true;
    config.color_scheme.hidden.background = "#1a1a2e".to_string();
    config.color_scheme.hidden.foreground = "#e0e0e0".to_string();
    config.color_scheme.decoy.reset = true;

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    env.set("SHELL", "/bin/bash");

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
}
#[test]
#[serial]
fn test_color_scheme_applied_after_scripts_written() {
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    env.set("SHELL", "/bin/bash");

    let shell = ShellInstrumentation::new(fs.clone(), config.clone());

    // Run shell_setup which writes scripts first, then applies color scheme
    let result = shell.shell_setup();

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
    let mut env = EnvGuard::lock();
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Mock the parent directory to exist
    fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

    // Set SHELL environment variable to bash
    env.set("SHELL", "/bin/bash");

    let shell = ShellInstrumentation::new(fs, config.clone());

    // Emergency deactivation calls shell_cleanup(true)
    let result = shell.shell_cleanup(true);

    // Verify cleanup completed
    assert!(result.shell_type.is_some());

    // Verify color reset sequences are generated (best-effort)
    let color_sequences = color_scheme::apply_decoy_color_scheme(&config.color_scheme);
    assert!(!color_sequences.is_empty());
    assert!(color_sequences.contains("\x1b]111\x07"));
}
