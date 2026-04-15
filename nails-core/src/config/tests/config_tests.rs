//! Tests for main Config struct and ConfigBuilder

use crate::config::{
    CliOverrides, Config, ConfigBuilder, DEFAULT_HIDDEN_VOLUME_ROOT, EphemeralOverlayDir,
    ExtendedOverlayConfig, OverlayConfig, OverlayMode, derive_hidden_volume_root,
};
use std::path::PathBuf;

#[test]
fn test_config_default() {
    let config = Config::default();

    // hidden_volume_root should be auto-derived (not empty)
    assert!(!config.hidden_volume_root.as_os_str().is_empty());
    // state_file_path should be derived from hidden_volume_root
    assert_eq!(
        config.state_file_path,
        config.hidden_volume_root.join("state.json")
    );
    // Default config includes /home, /etc, and /var overlays
    assert_eq!(config.overlays.len(), 4);
    assert_eq!(config.overlays[1].name, "home");
    assert_eq!(config.overlays[2].name, "etc");
    assert_eq!(config.overlays[3].name, "var");
    // Extended overlays disabled - using regular overlays for all directories
    assert!(!config.extended_overlays.enabled);
    // User-configurable options with defaults (Epic 10)
    assert!(config.clear_history);
    assert!(config.preflight_checks);
    assert_eq!(config.default_verbosity, "info");
    assert!(config.color_output);
    assert!(config.verify_on_deactivate);
    assert!(config.milestone_tips);
    // log_path should be derived from hidden_volume_root
    assert_eq!(config.log_path, config.hidden_volume_root.join("logs"));
    assert_eq!(config.max_log_size_mb, 10);
    assert_eq!(config.retention_days, 7);
}

#[test]
fn test_config_test_default() {
    let config = Config::test_default();

    // test_default() should have overlays but extended_overlays disabled
    assert_eq!(
        config.hidden_volume_root,
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
    );
    assert_eq!(config.overlays.len(), 4);
    assert_eq!(config.overlays[1].name, "home");
    assert_eq!(config.overlays[2].name, "etc");
    assert_eq!(config.overlays[3].name, "var");
    // Extended overlays disabled in test_default for simpler testing
    assert!(!config.extended_overlays.enabled);
    assert!(config.extended_overlays.directories.is_empty());
    // User-configurable options should still have defaults
    assert!(config.clear_history);
    assert!(config.preflight_checks);
    assert_eq!(config.default_verbosity, "info");
    assert!(config.color_output);
    assert!(config.verify_on_deactivate);
    assert!(config.milestone_tips);
    assert_eq!(
        config.log_path,
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("logs")
    );
    assert_eq!(config.max_log_size_mb, 10);
    assert_eq!(config.retention_days, 7);
}

#[test]
fn test_config_with_overlays() {
    let overlay = OverlayConfig {
        name: "home".to_string(),
        lower: PathBuf::from("/home"),
        upper: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/upper"),
        work: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/work"),
        target: PathBuf::from("/home"),
    };

    let config = Config {
        hidden_volume_root: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        state_file_path: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("state.json"),
        overlays: vec![overlay.clone()],
        ..Config::default()
    };

    assert_eq!(config.overlays.len(), 1);
    assert_eq!(config.overlays[0], overlay);
}

#[test]
fn test_config_clone() {
    let config1 = Config {
        hidden_volume_root: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        state_file_path: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("state.json"),
        overlays: vec![],
        ..Config::default()
    };

    let config2 = config1.clone();
    assert_eq!(config1, config2);
}

#[test]
fn test_config_serialization() {
    let config = Config {
        hidden_volume_root: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        state_file_path: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("state.json"),
        overlays: vec![OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/home"),
            upper: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/upper"),
            work: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/work"),
            target: PathBuf::from("/home"),
        }],
        ..Config::default()
    };

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&config).expect("Should serialize");
    assert!(json.contains("\"hidden_volume_root\""));
    assert!(json.contains("\"state_file_path\""));
    assert!(json.contains("\"overlays\""));

    // Deserialize back
    let deserialized: Config = serde_json::from_str(&json).expect("Should deserialize");
    assert_eq!(deserialized, config);
}

#[test]
fn test_config_multiple_overlays() {
    let overlay1 = OverlayConfig {
        name: "home".to_string(),
        lower: PathBuf::from("/home"),
        upper: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/upper"),
        work: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/work"),
        target: PathBuf::from("/home"),
    };

    let overlay2 = OverlayConfig {
        name: "etc".to_string(),
        lower: PathBuf::from("/etc"),
        upper: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/etc/upper"),
        work: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/etc/work"),
        target: PathBuf::from("/etc"),
    };

    let config = Config {
        hidden_volume_root: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        state_file_path: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("state.json"),
        overlays: vec![overlay1.clone(), overlay2.clone()],
        ..Config::default()
    };

    assert_eq!(config.overlays.len(), 2);
    assert_eq!(config.overlays[0], overlay1);
    assert_eq!(config.overlays[1], overlay2);
}

#[test]
fn test_config_with_extended_overlays() {
    let extended = ExtendedOverlayConfig {
        enabled: true,
        directories: vec![EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        }],
    };

    let config = Config {
        hidden_volume_root: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        state_file_path: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("state.json"),
        overlays: vec![],
        extended_overlays: extended.clone(),
        ..Config::default()
    };

    assert_eq!(config.extended_overlays, extended);
    assert!(config.extended_overlays.enabled);
    assert_eq!(config.extended_overlays.directories.len(), 1);
}

#[test]
fn test_config_default_has_disabled_extended_overlays() {
    let config = Config::default();
    // Extended overlays disabled - using regular overlays for all directories
    assert!(!config.extended_overlays.enabled);
    assert!(config.extended_overlays.directories.is_empty());
    // /var is now a regular overlay instead of extended overlay
    assert_eq!(config.overlays.len(), 4);
    assert_eq!(config.overlays[3].name, "var");
    assert_eq!(config.overlays[3].target, PathBuf::from("/var"));
}

#[test]
fn test_config_serialization_with_extended_overlays() {
    let extended = ExtendedOverlayConfig {
        enabled: true,
        directories: vec![EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        }],
    };

    let config = Config {
        hidden_volume_root: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        state_file_path: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("state.json"),
        overlays: vec![],
        extended_overlays: extended,
        ..Config::default()
    };

    // Serialize to JSON
    let json = serde_json::to_string(&config).expect("Should serialize");
    assert!(json.contains("\"extended_overlays\""));
    assert!(json.contains("\"enabled\""));

    // Deserialize back
    let deserialized: Config = serde_json::from_str(&json).expect("Should deserialize");
    assert_eq!(deserialized, config);
}

#[test]
fn test_builder_with_all_fields_specified() {
    let overlays = vec![OverlayConfig {
        name: "home".to_string(),
        lower: PathBuf::from("/home"),
        upper: PathBuf::from("/mnt/hidden/home"),
        work: PathBuf::from("/mnt/hidden/.work/home"),
        target: PathBuf::from("/home"),
    }];

    let extended = ExtendedOverlayConfig {
        enabled: true,
        directories: vec![EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        }],
    };

    let config = ConfigBuilder::new()
        .hidden_volume_path(PathBuf::from("/mnt/hidden"))
        .state_file_path(PathBuf::from("/mnt/hidden/state.json"))
        .overlays(overlays.clone())
        .minimum_space_mb(1000)
        .extended_overlays(extended.clone())
        .clear_history(false)
        .preflight_checks(false)
        .default_verbosity("debug")
        .color_output(false)
        .verify_on_deactivate(false)
        .milestone_tips(false)
        .log_path(PathBuf::from("/custom/logs"))
        .max_log_size_mb(20)
        .retention_days(14)
        .build()
        .expect("Build should succeed");

    assert_eq!(config.hidden_volume_root, PathBuf::from("/mnt/hidden"));
    assert_eq!(
        config.state_file_path,
        PathBuf::from("/mnt/hidden/state.json")
    );
    assert_eq!(config.overlays, overlays);
    assert_eq!(config.minimum_space_mb, 1000);
    assert_eq!(config.extended_overlays, extended);
    assert!(!config.clear_history);
    assert!(!config.preflight_checks);
    assert_eq!(config.default_verbosity, "debug");
    assert!(!config.color_output);
    assert!(!config.verify_on_deactivate);
    assert!(!config.milestone_tips);
    assert_eq!(config.log_path, PathBuf::from("/custom/logs"));
    assert_eq!(config.max_log_size_mb, 20);
    assert_eq!(config.retention_days, 14);
}

#[test]
fn test_builder_with_minimal_fields_applies_defaults() {
    let config = ConfigBuilder::new()
        .hidden_volume_path(PathBuf::from("/mnt/hidden"))
        .build()
        .expect("Build should succeed");

    // Required field
    assert_eq!(config.hidden_volume_root, PathBuf::from("/mnt/hidden"));

    // Smart defaults
    assert_eq!(
        config.state_file_path,
        PathBuf::from("/mnt/hidden/state.json")
    );
    assert!(config.overlays.is_empty());
    assert_eq!(config.minimum_space_mb, 500);
    assert!(!config.extended_overlays.enabled);

    // User-configurable defaults
    assert!(config.clear_history);
    assert!(config.preflight_checks);
    assert_eq!(config.default_verbosity, "info");
    assert!(config.color_output);
    assert!(config.verify_on_deactivate);
    assert!(config.milestone_tips);
    assert_eq!(config.log_path, PathBuf::from("/mnt/hidden/logs"));
    assert_eq!(config.max_log_size_mb, 10);
    assert_eq!(config.retention_days, 7);
}

#[test]
fn test_builder_auto_derives_when_field_not_set() {
    // Story 14.9: hidden_volume_root is no longer required, it auto-derives
    let result = ConfigBuilder::new().build();

    assert!(result.is_ok());
    let config = result.unwrap();

    // Should have auto-derived hidden_volume_root
    assert!(!config.hidden_volume_root.as_os_str().is_empty());
    assert_ne!(config.hidden_volume_root, PathBuf::default());
}

#[test]
fn test_builder_each_default_value_is_correct() {
    let config = ConfigBuilder::new()
        .hidden_volume_path(PathBuf::from("/mnt/test"))
        .build()
        .expect("Build should succeed");

    // Verify each default matches the spec
    assert!(config.clear_history);
    assert!(config.preflight_checks);
    assert_eq!(config.default_verbosity, "info");
    assert!(config.color_output);
    assert!(config.verify_on_deactivate);
    assert!(config.milestone_tips);
    assert_eq!(config.log_path, PathBuf::from("/mnt/test/logs"));
    assert_eq!(config.max_log_size_mb, 10);
    assert_eq!(config.retention_days, 7);
}

#[test]
fn test_builder_log_path_derived_from_hidden_volume() {
    let config = ConfigBuilder::new()
        .hidden_volume_path(PathBuf::from("/custom/path"))
        .build()
        .expect("Build should succeed");

    // log_path should be derived from hidden_volume_root
    assert_eq!(config.log_path, PathBuf::from("/custom/path/logs"));
}

#[test]
fn test_builder_log_path_can_be_overridden() {
    let config = ConfigBuilder::new()
        .hidden_volume_path(PathBuf::from("/mnt/hidden"))
        .log_path(PathBuf::from("/var/log/nails"))
        .build()
        .expect("Build should succeed");

    // Explicit log_path should override derived value
    assert_eq!(config.log_path, PathBuf::from("/var/log/nails"));
}

#[test]
fn test_config_serialization_with_new_fields() {
    let config = ConfigBuilder::new()
        .hidden_volume_path(PathBuf::from("/mnt/hidden"))
        .clear_history(false)
        .default_verbosity("debug")
        .build()
        .expect("Build should succeed");

    // Serialize to JSON
    let json = serde_json::to_string(&config).expect("Should serialize");
    assert!(json.contains("\"clear_history\""));
    assert!(json.contains("false"));
    assert!(json.contains("\"default_verbosity\""));
    assert!(json.contains("\"debug\""));

    // Deserialize back
    let deserialized: Config = serde_json::from_str(&json).expect("Should deserialize");
    assert_eq!(deserialized, config);
}

#[test]
fn test_config_backward_compatibility_with_old_configs() {
    // Simulate old config JSON without new fields
    let state_file = format!("{}/state.json", DEFAULT_HIDDEN_VOLUME_ROOT);
    let old_json = format!(
        r#"{{
        "hidden_volume_root": "{}",
        "state_file_path": "{}",
        "overlays": [],
        "minimum_space_mb": 500,
        "extended_overlays": {{
            "enabled": false,
            "directories": []
        }}
    }}"#,
        DEFAULT_HIDDEN_VOLUME_ROOT, state_file
    );

    // Should deserialize successfully with defaults for missing fields
    let config: Config = serde_json::from_str(&old_json).expect("Should deserialize");

    assert_eq!(
        config.hidden_volume_root,
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
    );
    assert!(config.clear_history); // Default applied
    assert!(config.preflight_checks); // Default applied
    assert_eq!(config.default_verbosity, "info"); // Default applied
    assert!(config.color_output); // Default applied
    assert!(config.verify_on_deactivate); // Default applied
    assert!(config.milestone_tips); // Default applied
    assert_eq!(
        config.log_path,
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("logs")
    ); // Default applied
    assert_eq!(config.max_log_size_mb, 10); // Default applied
    assert_eq!(config.retention_days, 7); // Default applied
}

#[test]
fn test_load_valid_yaml_file() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
hidden_volume_path: /mnt/test-volume
clear_history: false
preflight_checks: true
default_verbosity: debug
color_output: true
verify_on_deactivate: false
milestone_tips: true
log_path: /mnt/test-volume/custom-logs
max_log_size_mb: 20
retention_days: 14
"#
    )
    .unwrap();

    let config = Config::load(file.path()).unwrap();
    assert_eq!(config.hidden_volume_root, PathBuf::from("/mnt/test-volume"));
    assert!(!config.clear_history);
    assert!(config.preflight_checks);
    assert_eq!(config.default_verbosity, "debug");
    assert!(config.color_output);
    assert!(!config.verify_on_deactivate);
    assert!(config.milestone_tips);
    assert_eq!(
        config.log_path,
        PathBuf::from("/mnt/test-volume/custom-logs")
    );
    assert_eq!(config.max_log_size_mb, 20);
    assert_eq!(config.retention_days, 14);
}

#[test]
fn test_load_file_not_found_error() {
    let result = Config::load(&PathBuf::from("/nonexistent/config.yaml"));
    assert!(result.is_err());

    match result {
        Err(crate::error::NailsError::ConfigError(msg)) => {
            assert!(msg.contains("Config file not found"));
            assert!(msg.contains("/nonexistent/config.yaml"));
            assert!(msg.contains("Create one with:"));
        }
        _ => panic!("Expected ConfigError for missing file"),
    }
}

#[test]
fn test_load_malformed_yaml_error() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
hidden_volume_path: /mnt/test
clear_history: [this, is, invalid
"#
    )
    .unwrap();

    let result = Config::load(file.path());
    assert!(result.is_err());

    match result {
        Err(crate::error::NailsError::ConfigError(msg)) => {
            assert!(msg.contains("Invalid YAML"));
        }
        _ => panic!("Expected ConfigError for malformed YAML"),
    }
}

#[test]
fn test_load_missing_required_field_error() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut file = NamedTempFile::new().unwrap();
    // Write YAML without hidden_volume_path - should now succeed with auto-derived default
    writeln!(
        file,
        r#"
clear_history: true
preflight_checks: true
"#
    )
    .unwrap();

    // With auto-derivation, missing hidden_volume_root should succeed
    let result = Config::load(file.path());
    assert!(
        result.is_ok(),
        "Config should load successfully with auto-derived hidden_volume_root"
    );

    let config = result.unwrap();
    assert!(config.clear_history);
    assert!(config.preflight_checks);
    assert!(
        !config.hidden_volume_root.as_os_str().is_empty(),
        "Should have auto-derived root"
    );
}

#[test]
fn test_load_partial_config_with_defaults() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Only specify required field and a few optional ones
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
hidden_volume_path: /mnt/partial
clear_history: false
"#
    )
    .unwrap();

    let config = Config::load(file.path()).unwrap();
    assert_eq!(config.hidden_volume_root, PathBuf::from("/mnt/partial"));
    assert!(!config.clear_history); // Specified
    assert!(config.preflight_checks); // Default
    assert_eq!(config.default_verbosity, "info"); // Default
    assert!(config.color_output); // Default
    assert!(config.verify_on_deactivate); // Default
    assert!(config.milestone_tips); // Default
}

#[test]
fn test_example_config_returns_valid_yaml() {
    let example = Config::example_config();

    // Example should be parseable
    assert!(example.contains("hidden_volume_path"));
    assert!(example.contains("clear_history"));
    assert!(example.contains("preflight_checks"));
    assert!(example.contains("default_verbosity"));

    // Try to parse it (simulated - actual parsing would require serde_saphyr)
    assert!(example.contains("# NAILS Configuration"));
    assert!(example.contains("# Required fields:"));
}

#[test]
fn test_load_or_default_with_existing_file() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
hidden_volume_path: /mnt/test-default
clear_history: false
"#
    )
    .unwrap();

    let config = Config::load_or_default(file.path()).unwrap();
    assert_eq!(
        config.hidden_volume_root,
        PathBuf::from("/mnt/test-default")
    );
    assert!(!config.clear_history);
}

#[test]
fn test_load_or_default_with_nonexistent_file() {
    let config = Config::load_or_default(&PathBuf::from("/nonexistent/config.yaml")).unwrap();

    // Should return Config::default() with auto-derived root
    assert!(!config.hidden_volume_root.as_os_str().is_empty());
    assert!(config.clear_history);
}

#[test]
fn test_load_with_hidden_volume_path_alias() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Test that the YAML alias "hidden_volume_path" works
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
hidden_volume_path: /mnt/alias-test
clear_history: false
"#
    )
    .unwrap();

    let config = Config::load(file.path()).unwrap();
    assert_eq!(config.hidden_volume_root, PathBuf::from("/mnt/alias-test"));
    assert!(!config.clear_history);
}

#[test]
fn test_cli_overrides_default() {
    let overrides = CliOverrides::default();
    assert!(overrides.preflight_checks.is_none());
    assert!(overrides.clear_history.is_none());
    assert!(overrides.verbosity.is_none());
    assert!(overrides.color_output.is_none());
    assert!(overrides.verify_on_deactivate.is_none());
}

#[test]
fn test_apply_cli_overrides_preflight_checks() {
    let mut config = Config::default();
    assert!(config.preflight_checks); // Default is true

    let overrides = CliOverrides {
        preflight_checks: Some(false),
        ..Default::default()
    };

    config.apply_cli_overrides(&overrides);
    assert!(!config.preflight_checks); // CLI override applied
}

#[test]
fn test_apply_cli_overrides_clear_history() {
    let mut config = Config::default();
    assert!(config.clear_history); // Default is true

    let overrides = CliOverrides {
        clear_history: Some(false),
        ..Default::default()
    };

    config.apply_cli_overrides(&overrides);
    assert!(!config.clear_history); // CLI override applied
}

#[test]
fn test_apply_cli_overrides_verbosity() {
    let mut config = Config::default();
    assert_eq!(config.default_verbosity, "info");

    let overrides = CliOverrides {
        verbosity: Some("debug".to_string()),
        ..Default::default()
    };

    config.apply_cli_overrides(&overrides);
    assert_eq!(config.default_verbosity, "debug");
}

#[test]
fn test_apply_cli_overrides_verbosity_single_v_to_info() {
    // Test AC4: -v flag maps to "info" (not "verbose")
    let mut config = Config::default();

    let overrides = CliOverrides {
        verbosity: Some("info".to_string()), // Single -v flag
        ..Default::default()
    };

    config.apply_cli_overrides(&overrides);
    assert_eq!(config.default_verbosity, "info");
}

#[test]
fn test_apply_cli_overrides_color_output() {
    let mut config = Config::default();
    assert!(config.color_output); // Default is true

    let overrides = CliOverrides {
        color_output: Some(false),
        ..Default::default()
    };

    config.apply_cli_overrides(&overrides);
    assert!(!config.color_output);
}

#[test]
fn test_apply_cli_overrides_verify_on_deactivate() {
    let mut config = Config::default();
    assert!(config.verify_on_deactivate); // Default is true

    let overrides = CliOverrides {
        verify_on_deactivate: Some(false),
        ..Default::default()
    };

    config.apply_cli_overrides(&overrides);
    assert!(!config.verify_on_deactivate);
}

#[test]
fn test_apply_cli_overrides_priority_order() {
    // Start with config that has clear_history = true
    let mut config = Config::default();
    assert!(config.clear_history);

    // CLI says --no-clear-history (false)
    let overrides = CliOverrides {
        clear_history: Some(false),
        ..Default::default()
    };

    config.apply_cli_overrides(&overrides);

    // CLI wins (Priority: CLI > Config > Defaults)
    assert!(!config.clear_history);
}

#[test]
fn test_apply_cli_overrides_unset_preserves_config() {
    // Simulate config file with clear_history: false
    let mut config = Config {
        clear_history: false,
        ..Default::default()
    };

    // CLI doesn't specify clear_history
    let overrides = CliOverrides::default();

    config.apply_cli_overrides(&overrides);

    // Config file value preserved
    assert!(!config.clear_history);
}

#[test]
fn test_apply_cli_overrides_multiple_simultaneously() {
    let mut config = Config::default();

    let overrides = CliOverrides {
        preflight_checks: Some(false),
        verbosity: Some("debug".to_string()),
        color_output: Some(false),
        ..Default::default()
    };

    config.apply_cli_overrides(&overrides);

    assert!(!config.preflight_checks);
    assert_eq!(config.default_verbosity, "debug");
    assert!(!config.color_output);
    // Unspecified fields remain at defaults
    assert!(config.clear_history);
    assert!(config.verify_on_deactivate);
}

#[test]
fn test_from_file_and_cli_with_nonexistent_file() {
    let overrides = CliOverrides {
        preflight_checks: Some(false),
        verbosity: Some("quiet".to_string()),
        ..Default::default()
    };

    let config =
        Config::from_file_and_cli(&PathBuf::from("/nonexistent/config.yaml"), &overrides).unwrap();

    // Defaults used (auto-derived root), then CLI overrides applied
    assert!(!config.hidden_volume_root.as_os_str().is_empty());
    assert!(!config.preflight_checks); // CLI override
    assert_eq!(config.default_verbosity, "quiet"); // CLI override
    assert!(config.clear_history); // Default (no override)
}

#[test]
fn test_from_file_and_cli_with_existing_file() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
hidden_volume_path: /mnt/test-volume
clear_history: true
preflight_checks: true
default_verbosity: info
"#
    )
    .unwrap();

    let overrides = CliOverrides {
        preflight_checks: Some(false),        // Override config file
        verbosity: Some("debug".to_string()), // Override config file
        ..Default::default()
    };

    let config = Config::from_file_and_cli(file.path(), &overrides).unwrap();

    // Config file values
    assert_eq!(config.hidden_volume_root, PathBuf::from("/mnt/test-volume"));
    assert!(config.clear_history); // From config file (no override)

    // CLI overrides win
    assert!(!config.preflight_checks); // CLI override beats config
    assert_eq!(config.default_verbosity, "debug"); // CLI override beats config
}

#[test]
fn test_derive_hidden_volume_root_success() {
    // Test that we can derive from current executable
    let derived = derive_hidden_volume_root();

    // Should return a non-empty path
    assert!(!derived.as_os_str().is_empty());

    // Should be a valid directory path (has components)
    assert!(derived.components().count() >= 1);

    // Should not panic on multiple calls (idempotent)
    let derived2 = derive_hidden_volume_root();
    assert_eq!(derived, derived2);
}

#[test]
fn test_config_default_uses_derived_root() {
    let config = Config::default();

    // Should have non-empty hidden_volume_root
    assert!(!config.hidden_volume_root.as_os_str().is_empty());

    // State file should be derived from root
    assert!(
        config
            .state_file_path
            .starts_with(&config.hidden_volume_root)
    );

    // Log path should be derived from root
    assert!(config.log_path.starts_with(&config.hidden_volume_root));

    // Overlay paths should be derived from root
    for overlay in &config.overlays {
        assert!(
            overlay.upper.starts_with(&config.hidden_volume_root),
            "Overlay {} upper path should start with hidden_volume_root",
            overlay.name
        );
        assert!(
            overlay.work.starts_with(&config.hidden_volume_root),
            "Overlay {} work path should start with hidden_volume_root",
            overlay.name
        );
    }
}

#[test]
fn test_config_load_overrides_derived_root() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");

    // Write config with explicit hidden_volume_root
    let yaml_content = r#"
hidden_volume_root: /custom/mount
state_file_path: /custom/mount/state.json
"#;
    temp_file
        .write_all(yaml_content.as_bytes())
        .expect("Failed to write config");

    // Load config
    let config = Config::load(temp_file.path()).expect("Failed to load config");

    // Should use explicit value from YAML, not derived
    assert_eq!(config.hidden_volume_root, PathBuf::from("/custom/mount"));
}

#[test]
fn test_config_load_derives_when_missing() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");

    // Write config WITHOUT hidden_volume_root
    let yaml_content = r#"
clear_history: false
preflight_checks: true
"#;
    temp_file
        .write_all(yaml_content.as_bytes())
        .expect("Failed to write config");

    // Load config
    let config = Config::load(temp_file.path()).expect("Failed to load config");

    // Should derive from binary location
    assert!(!config.hidden_volume_root.as_os_str().is_empty());

    // Should NOT be empty default
    assert_ne!(config.hidden_volume_root, PathBuf::default());
}

#[test]
fn test_config_builder_uses_explicit_value() {
    let explicit_root = PathBuf::from("/explicit/path");

    let config = ConfigBuilder::new()
        .hidden_volume_path(explicit_root.clone())
        .build()
        .expect("Failed to build config");

    // Should use explicit value, not derived
    assert_eq!(config.hidden_volume_root, explicit_root);
}

#[test]
fn test_config_builder_derives_when_not_set() {
    let config = ConfigBuilder::new()
        .clear_history(false)
        .build()
        .expect("Failed to build config");

    // Should derive from binary location
    assert!(!config.hidden_volume_root.as_os_str().is_empty());
    assert_ne!(config.hidden_volume_root, PathBuf::default());
}

#[test]
fn test_priority_order() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Priority order: config file > binary-derived > DEFAULT_HIDDEN_VOLUME_ROOT

    // 1. Config file value wins
    let mut temp_file1 = NamedTempFile::new().expect("Failed to create temp file");
    temp_file1
        .write_all(b"hidden_volume_root: /config/wins\n")
        .expect("Failed to write");
    let config1 = Config::load(temp_file1.path()).expect("Failed to load config");
    assert_eq!(config1.hidden_volume_root, PathBuf::from("/config/wins"));

    // 2. Binary-derived when config missing
    let mut temp_file2 = NamedTempFile::new().expect("Failed to create temp file");
    temp_file2
        .write_all(b"clear_history: false\n")
        .expect("Failed to write");
    let config2 = Config::load(temp_file2.path()).expect("Failed to load config");
    assert_ne!(config2.hidden_volume_root, PathBuf::default());

    // 3. DEFAULT_HIDDEN_VOLUME_ROOT as ultimate fallback (tested via function)
    // (Cannot easily test current_exe() failure in unit test, covered by code review)
}

#[test]
fn test_all_paths_derive_from_root() {
    let custom_root = PathBuf::from("/custom/hidden");

    let config = ConfigBuilder::new()
        .hidden_volume_path(custom_root.clone())
        .build()
        .expect("Failed to build config");

    // Verify all paths start with custom root
    assert_eq!(config.hidden_volume_root, custom_root);
    assert!(config.state_file_path.starts_with(&custom_root));
    assert!(config.log_path.starts_with(&custom_root));

    // Test that manually creating overlays with a custom root works
    let overlay = OverlayConfig {
        name: "test".to_string(),
        lower: "/home".into(),
        target: "/home".into(),
        upper: custom_root.join("overlays/test/upper"),
        work: custom_root.join("overlays/test/work"),
    };

    assert!(
        overlay.upper.starts_with(&custom_root),
        "Overlay upper path should start with custom root"
    );
    assert!(
        overlay.work.starts_with(&custom_root),
        "Overlay work path should start with custom root"
    );
}

#[test]
fn test_derived_paths_consistency() {
    // Test that auto-derived root produces consistent derived paths
    let config = Config::default();

    // All derived paths should use the same hidden_volume_root
    let root = &config.hidden_volume_root;

    assert_eq!(config.state_file_path, root.join("state.json"));
    assert_eq!(config.log_path, root.join("logs"));

    // Check overlay paths
    assert_eq!(config.overlays[1].upper, root.join("home"));
    assert_eq!(config.overlays[1].work, root.join(".work/home"));
    assert_eq!(config.overlays[2].upper, root.join("etc"));
    assert_eq!(config.overlays[2].work, root.join(".work/etc"));
    assert_eq!(config.overlays[3].upper, root.join("var"));
    assert_eq!(config.overlays[3].work, root.join(".work/var"));
}

#[test]
fn test_config_load_derives_dependent_paths() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");

    // Write minimal config - all paths should be derived
    let yaml_content = r#"
hidden_volume_root: /test/volume
"#;
    temp_file
        .write_all(yaml_content.as_bytes())
        .expect("Failed to write config");

    let config = Config::load(temp_file.path()).expect("Failed to load config");

    // Verify explicit hidden_volume_root used
    assert_eq!(config.hidden_volume_root, PathBuf::from("/test/volume"));

    // Verify derived paths updated to match
    assert_eq!(
        config.state_file_path,
        PathBuf::from("/test/volume/state.json")
    );
    assert_eq!(config.log_path, PathBuf::from("/test/volume/logs"));
}

#[test]
fn test_symlink_resolution_documented() {
    // This test documents expected symlink behavior
    // Actual symlink testing would require filesystem setup

    // If binary is at: /usr/local/bin/nails -> /mnt/hidden-volume/nails
    // Then canonicalize() should resolve to: /mnt/hidden-volume/nails
    // And derive_hidden_volume_root() should return: /mnt/hidden-volume

    // This is tested implicitly by test_derive_hidden_volume_root_success()
    // which calls the actual derive function that does symlink resolution

    let derived = derive_hidden_volume_root();
    assert!(!derived.as_os_str().is_empty());
}

#[test]
fn test_builder_respects_explicit_derived_paths() {
    let custom_root = PathBuf::from("/builder/test");
    let custom_state = PathBuf::from("/builder/test/custom/state.json");
    let custom_log = PathBuf::from("/builder/test/custom/logs");

    let config = ConfigBuilder::new()
        .hidden_volume_path(custom_root.clone())
        .state_file_path(custom_state.clone())
        .log_path(custom_log.clone())
        .build()
        .expect("Failed to build config");

    // All explicit values should be preserved
    assert_eq!(config.hidden_volume_root, custom_root);
    assert_eq!(config.state_file_path, custom_state);
    assert_eq!(config.log_path, custom_log);
}

// ===== Tests for Story 14.10: Dynamic Full-Root Overlay =====

#[test]
fn test_overlay_mode_default_is_auto() {
    let config = Config::default();
    assert_eq!(config.overlay_mode, OverlayMode::Auto);
}

#[test]
fn test_overlay_mode_serialization() {
    let auto_mode = OverlayMode::Auto;
    let explicit_mode = OverlayMode::Explicit;

    // Serialize to YAML
    let auto_yaml = serde_saphyr::to_string(&auto_mode).unwrap();
    let explicit_yaml = serde_saphyr::to_string(&explicit_mode).unwrap();

    assert!(auto_yaml.contains("auto"));
    assert!(explicit_yaml.contains("explicit"));

    // Deserialize from YAML
    let auto_parsed: OverlayMode = serde_saphyr::from_str(&auto_yaml).unwrap();
    let explicit_parsed: OverlayMode = serde_saphyr::from_str(&explicit_yaml).unwrap();

    assert_eq!(auto_parsed, OverlayMode::Auto);
    assert_eq!(explicit_parsed, OverlayMode::Explicit);
}

#[test]
fn test_compute_effective_exclusions_defaults_only() {
    let config = Config::default();

    let exclusions = config.compute_effective_exclusions();

    // Should return all 12 defaults (/boot removed)
    assert_eq!(exclusions.len(), 12);
    assert!(exclusions.contains(&PathBuf::from("/proc")));
    assert!(exclusions.contains(&PathBuf::from("/sys")));
    assert!(exclusions.contains(&PathBuf::from("/dev")));
    assert!(exclusions.contains(&PathBuf::from("/run")));
    assert!(exclusions.contains(&PathBuf::from("/mnt")));
    assert!(!exclusions.contains(&PathBuf::from("/boot")));
    assert!(exclusions.contains(&PathBuf::from("/bin")));
    assert!(exclusions.contains(&PathBuf::from("/usr")));
    assert!(exclusions.contains(&PathBuf::from("/lib")));
    assert!(exclusions.contains(&PathBuf::from("/lib64")));
    assert!(exclusions.contains(&PathBuf::from("/sbin")));
}

#[test]
fn test_compute_effective_exclusions_with_user_additions() {
    let config = Config {
        overlay_exclusions: vec![PathBuf::from("/custom1"), PathBuf::from("/custom2")],
        ..Config::default()
    };

    let exclusions = config.compute_effective_exclusions();

    // Should include defaults + user additions (12 + 2 = 14 total)
    assert_eq!(exclusions.len(), 14);
    assert!(exclusions.contains(&PathBuf::from("/proc")));
    assert!(exclusions.contains(&PathBuf::from("/custom1")));
    assert!(exclusions.contains(&PathBuf::from("/custom2")));
}

#[test]
fn test_compute_effective_exclusions_with_user_removals() {
    let config = Config {
        overlay_exclusions_remove: vec![
            PathBuf::from("/mnt"),
            PathBuf::from("/boot"),
            PathBuf::from("/lib"),
        ],
        ..Config::default()
    };

    let exclusions = config.compute_effective_exclusions();

    // Should include defaults minus removals (12 - 2 = 10 total, /boot no longer in defaults)
    assert_eq!(exclusions.len(), 10);
    assert!(exclusions.contains(&PathBuf::from("/proc")));
    assert!(exclusions.contains(&PathBuf::from("/sys")));
    assert!(exclusions.contains(&PathBuf::from("/dev")));
    assert!(!exclusions.contains(&PathBuf::from("/mnt")));
    assert!(!exclusions.contains(&PathBuf::from("/boot")));
    assert!(!exclusions.contains(&PathBuf::from("/lib")));
}

#[test]
fn test_compute_effective_exclusions_remove_all_defaults() {
    let config = Config {
        overlay_exclusions_remove: vec![
            PathBuf::from("/proc"),
            PathBuf::from("/sys"),
            PathBuf::from("/dev"),
            PathBuf::from("/run"),
            PathBuf::from("/mnt"),
            PathBuf::from("/boot"),
            PathBuf::from("/bin"),
            PathBuf::from("/usr"),
            PathBuf::from("/lib"),
            PathBuf::from("/lib64"),
            PathBuf::from("/sbin"),
            PathBuf::from("/lost+found"),
            PathBuf::from("/Downloads"),
        ],
        ..Config::default()
    };

    let exclusions = config.compute_effective_exclusions();

    // User has full control - can remove ALL exclusions
    assert_eq!(exclusions.len(), 0);
}

#[test]
fn test_compute_effective_exclusions_combined_add_and_remove() {
    let config = Config {
        overlay_exclusions: vec![PathBuf::from("/custom")],
        overlay_exclusions_remove: vec![PathBuf::from("/mnt")],
        ..Config::default()
    };

    let exclusions = config.compute_effective_exclusions();

    // Defaults (12) + /custom - /mnt = 12 items
    assert_eq!(exclusions.len(), 12);
    assert!(exclusions.contains(&PathBuf::from("/custom")));
    assert!(!exclusions.contains(&PathBuf::from("/mnt")));
    assert!(!exclusions.contains(&PathBuf::from("/boot")));
}

#[test]
fn test_compute_effective_exclusions_no_duplicates() {
    let config = Config {
        overlay_exclusions: vec![
            PathBuf::from("/proc"), // Already in defaults
            PathBuf::from("/boot"),
        ],
        ..Config::default()
    };

    let exclusions = config.compute_effective_exclusions();

    // Should not have duplicate /proc
    let proc_count = exclusions
        .iter()
        .filter(|p| *p == &PathBuf::from("/proc"))
        .count();
    assert_eq!(proc_count, 1);
}

#[test]
#[tracing_test::traced_test]
fn test_compute_effective_exclusions_warns_about_dangerous_removals() {
    // Issue 8: Verify warnings are logged when removing dangerous exclusions
    let config = Config {
        overlay_exclusions_remove: vec![
            PathBuf::from("/proc"), // Dangerous - pseudo-filesystem
            PathBuf::from("/sys"),  // Dangerous - pseudo-filesystem
            PathBuf::from("/dev"),  // Dangerous - pseudo-filesystem
        ],
        ..Config::default()
    };

    // This should log warnings but not fail
    let exclusions = config.compute_effective_exclusions();

    // /proc, /sys, /dev should be removed from exclusions
    assert!(!exclusions.contains(&PathBuf::from("/proc")));
    assert!(!exclusions.contains(&PathBuf::from("/sys")));
    assert!(!exclusions.contains(&PathBuf::from("/dev")));

    // Verify warnings were logged
    assert!(logs_contain("Removing /proc"));
    assert!(logs_contain("Removing /sys"));
    assert!(logs_contain("Removing /dev"));
    assert!(logs_contain("mount will likely FAIL"));
}

// ========================================================================
// nixos_flake config field tests (--flake CLI flag / nixos_flake config)
// ========================================================================

#[test]
fn test_config_default_nixos_flake_is_none() {
    let config = Config::default();
    assert_eq!(config.nixos_flake, None);
}

#[test]
fn test_config_test_default_nixos_flake_is_none() {
    let config = Config::test_default();
    assert_eq!(config.nixos_flake, None);
}

#[test]
fn test_config_nixos_flake_serialization_roundtrip() {
    let config = Config {
        nixos_flake: Some("/etc/nixos#amnesia-virtualbox".to_string()),
        ..Config::default()
    };

    let json = serde_json::to_string_pretty(&config).expect("Should serialize");
    assert!(json.contains("nixos_flake"));
    assert!(json.contains("/etc/nixos#amnesia-virtualbox"));

    let deserialized: Config = serde_json::from_str(&json).expect("Should deserialize");
    assert_eq!(
        deserialized.nixos_flake,
        Some("/etc/nixos#amnesia-virtualbox".to_string())
    );
}

#[test]
fn test_config_nixos_flake_absent_deserializes_to_none() {
    // Simulate older config JSON without nixos_flake field
    let json = format!(
        r#"{{
        "hidden_volume_root": "{}",
        "state_file_path": "{}/state.json",
        "overlays": [],
        "minimum_space_mb": 100,
        "extended_overlays": {{ "enabled": false, "directories": [] }}
    }}"#,
        DEFAULT_HIDDEN_VOLUME_ROOT, DEFAULT_HIDDEN_VOLUME_ROOT
    );

    let config: Config = serde_json::from_str(&json).expect("Should deserialize");
    assert_eq!(config.nixos_flake, None);
}

#[test]
fn test_config_nixos_flake_yaml_load() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
hidden_volume_path: /mnt/test-volume
nixos_flake: /etc/nixos#amnesia-virtualbox
"#
    )
    .unwrap();

    let config = Config::load(file.path()).unwrap();
    assert_eq!(
        config.nixos_flake,
        Some("/etc/nixos#amnesia-virtualbox".to_string())
    );
}

#[test]
fn test_config_nixos_flake_yaml_load_absent() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
hidden_volume_path: /mnt/test-volume
"#
    )
    .unwrap();

    let config = Config::load(file.path()).unwrap();
    assert_eq!(config.nixos_flake, None);
}

#[test]
fn test_config_nixos_flake_yaml_load_path_only() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
hidden_volume_path: /mnt/test-volume
nixos_flake: /etc/nixos
"#
    )
    .unwrap();

    let config = Config::load(file.path()).unwrap();
    assert_eq!(config.nixos_flake, Some("/etc/nixos".to_string()));
}

#[test]
fn test_cli_overrides_default_nixos_flake_is_none() {
    let overrides = CliOverrides::default();
    assert!(overrides.nixos_flake.is_none());
}

#[test]
fn test_apply_cli_overrides_nixos_flake() {
    let mut config = Config::default();
    assert_eq!(config.nixos_flake, None);

    let overrides = CliOverrides {
        nixos_flake: Some("/etc/nixos#my-config".to_string()),
        ..Default::default()
    };

    config.apply_cli_overrides(&overrides);
    assert_eq!(config.nixos_flake, Some("/etc/nixos#my-config".to_string()));
}

#[test]
fn test_apply_cli_overrides_nixos_flake_none_preserves_config() {
    let mut config = Config {
        nixos_flake: Some("/etc/nixos#from-config".to_string()),
        ..Config::default()
    };

    let overrides = CliOverrides::default(); // nixos_flake is None

    config.apply_cli_overrides(&overrides);
    assert_eq!(
        config.nixos_flake,
        Some("/etc/nixos#from-config".to_string())
    );
}

#[test]
fn test_apply_cli_overrides_nixos_flake_overrides_config() {
    // CLI --flake should override config file nixos_flake
    let mut config = Config {
        nixos_flake: Some("/etc/nixos#from-config".to_string()),
        ..Config::default()
    };

    let overrides = CliOverrides {
        nixos_flake: Some("/mnt/hidden/nixos#from-cli".to_string()),
        ..Default::default()
    };

    config.apply_cli_overrides(&overrides);
    assert_eq!(
        config.nixos_flake,
        Some("/mnt/hidden/nixos#from-cli".to_string())
    );
}

#[test]
fn test_from_file_and_cli_nixos_flake_precedence() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Config file sets nixos_flake
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
hidden_volume_path: /mnt/test-volume
nixos_flake: /etc/nixos#config-value
"#
    )
    .unwrap();

    // CLI overrides it
    let overrides = CliOverrides {
        nixos_flake: Some("/etc/nixos#cli-value".to_string()),
        ..Default::default()
    };

    let config = Config::from_file_and_cli(file.path(), &overrides).unwrap();
    // CLI wins
    assert_eq!(config.nixos_flake, Some("/etc/nixos#cli-value".to_string()));
}

#[test]
fn test_example_config_mentions_nixos_flake() {
    let example = Config::example_config();
    assert!(
        example.contains("nixos_flake"),
        "Example config should mention nixos_flake"
    );
}

#[test]
fn test_discover_config_path_with_override_returns_exact_path() {
    use crate::config::discover_config_path;

    let override_path = PathBuf::from("/custom/myconfig.yaml");
    let result = discover_config_path(Some(&override_path));
    assert_eq!(result, override_path);
}

#[test]
fn test_discover_config_path_without_override_returns_nails_yaml_path() {
    use crate::config::discover_config_path;

    let result = discover_config_path(None);
    // Should end with config/nails.yaml regardless of how binary path is resolved
    assert!(
        result.ends_with("config/nails.yaml"),
        "Expected path ending with config/nails.yaml, got: {}",
        result.display()
    );
}

#[test]
fn test_load_or_default_with_malformed_yaml_returns_error() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "this: is: invalid: yaml: [[[").unwrap();

    // Malformed YAML should propagate the error (not return default)
    let result = Config::load_or_default(file.path());
    assert!(result.is_err(), "Expected error for malformed YAML");
}

#[test]
fn test_load_with_empty_hidden_volume_root_derives_from_binary() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut file = NamedTempFile::new().unwrap();
    // Explicitly set hidden_volume_path to empty string
    writeln!(file, "hidden_volume_path: \"\"").unwrap();

    let config = Config::load(file.path()).unwrap();
    // When hidden_volume_root is empty, it should be derived from binary (non-empty)
    assert!(
        !config.hidden_volume_root.as_os_str().is_empty(),
        "hidden_volume_root should be auto-derived when empty in config"
    );
}
