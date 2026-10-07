// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for main Config struct and ConfigBuilder

use crate::config::{
    CliOverrides, Config, ConfigBuilder, DEFAULT_HIDDEN_VOLUME_ROOT, derive_hidden_volume_root,
};
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

/// Write `contents` to a temporary TOML file that is removed on drop.
fn write_config(contents: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    file
}

#[test]
fn test_persona_mode_defaults_to_shared_home() {
    use crate::config::PersonaMode;

    let config = Config::load_or_default(Path::new("/nonexistent/nails.toml")).unwrap();
    assert_eq!(config.persona.mode, PersonaMode::SharedHome);
}

#[test]
fn test_persona_mode_fresh_home_parses_from_file() {
    use crate::config::PersonaMode;

    let file =
        write_config("hidden_volume_root = \"/mnt/data\"\n[persona]\nmode = \"fresh-home\"\n");
    let config = Config::load(file.path()).unwrap();
    assert_eq!(config.persona.mode, PersonaMode::FreshHome);
}

#[test]
fn test_persona_mode_shared_home_parses_from_file() {
    use crate::config::PersonaMode;

    let file =
        write_config("hidden_volume_root = \"/mnt/data\"\n[persona]\nmode = \"shared-home\"\n");
    let config = Config::load(file.path()).unwrap();
    assert_eq!(config.persona.mode, PersonaMode::SharedHome);
}

#[test]
fn test_persona_mode_rejects_unknown_value() {
    let file = write_config("hidden_volume_root = \"/mnt/data\"\n[persona]\nmode = \"bogus\"\n");
    assert!(Config::load(file.path()).is_err());
}

#[test]
fn test_persona_table_rejects_unknown_key() {
    let file = write_config(
        "hidden_volume_root = \"/mnt/data\"\n[persona]\nmode = \"fresh-home\"\nextra = 1\n",
    );
    assert!(Config::load(file.path()).is_err());
}

#[test]
fn test_persona_round_trips_through_toml() {
    use crate::config::PersonaMode;

    let config = Config {
        persona: crate::config::PersonaConfig {
            mode: PersonaMode::FreshHome,
            ..Default::default()
        },
        ..Config::test_default()
    };
    let toml_text = toml::to_string(&config).expect("serialize");
    let parsed: Config = toml::from_str(&toml_text).expect("parse back");
    assert_eq!(parsed.persona.mode, PersonaMode::FreshHome);
    assert_eq!(parsed, config);
}

#[test]
fn test_builder_auto_derives_when_field_not_set() {
    let config = ConfigBuilder::new().build().expect("Build should succeed");

    assert!(!config.hidden_volume_root.as_os_str().is_empty());
    assert_ne!(config.hidden_volume_root, PathBuf::default());
}

#[test]
fn test_builder_log_path_derived_from_hidden_volume() {
    let config = ConfigBuilder::new()
        .hidden_volume_root(PathBuf::from("/custom/path"))
        .build()
        .expect("Build should succeed");

    assert_eq!(config.log_path, PathBuf::from("/custom/path/logs"));
}

#[test]
fn test_builder_log_path_can_be_overridden() {
    let config = ConfigBuilder::new()
        .hidden_volume_root(PathBuf::from("/mnt/hidden"))
        .log_path(PathBuf::from("/mnt/hidden/var/log"))
        .build()
        .expect("Build should succeed");

    assert_eq!(config.log_path, PathBuf::from("/mnt/hidden/var/log"));
}

#[test]
fn test_builder_respects_explicit_derived_paths() {
    let custom_root = PathBuf::from("/builder/test");
    let custom_state = PathBuf::from("/builder/test/custom/state.json");
    let custom_log = PathBuf::from("/builder/test/custom/logs");

    let config = ConfigBuilder::new()
        .hidden_volume_root(custom_root.clone())
        .state_file_path(custom_state.clone())
        .log_path(custom_log.clone())
        .build()
        .expect("Failed to build config");

    assert_eq!(config.hidden_volume_root, custom_root);
    assert_eq!(config.state_file_path, custom_state);
    assert_eq!(config.log_path, custom_log);
}

#[test]
fn test_load_file_not_found_error() {
    let result = Config::load(&PathBuf::from("/nonexistent/config.toml"));

    match result {
        Err(crate::error::NailsError::ConfigNotFound { path }) => {
            assert_eq!(path, PathBuf::from("/nonexistent/config.toml"));
        }
        other => panic!("Expected ConfigNotFound for missing file, got {other:?}"),
    }
}

#[test]
fn test_load_derives_dependent_paths_from_configured_root() {
    let file = write_config("hidden_volume_root = \"/test/volume\"\n");

    let config = Config::load(file.path()).expect("Failed to load config");
    assert_eq!(config.hidden_volume_root, PathBuf::from("/test/volume"));
    assert_eq!(
        config.state_file_path,
        PathBuf::from("/test/volume/state.json")
    );
    assert_eq!(config.log_path, PathBuf::from("/test/volume/logs"));
}

#[test]
fn test_load_keeps_explicit_state_path_equal_to_the_builtin_default() {
    // An explicit value must win even when it happens to equal the constant
    // fallback path. The state file must lie inside the root, so the root is
    // the parent of the default root.
    let state = format!("{DEFAULT_HIDDEN_VOLUME_ROOT}/state.json");
    let root = Path::new(DEFAULT_HIDDEN_VOLUME_ROOT).parent().unwrap();
    let file = write_config(&format!(
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{state}\"\n",
        root.display()
    ));

    let config = Config::load(file.path()).unwrap();
    assert_eq!(config.state_file_path, PathBuf::from(state));
    assert_eq!(config.log_path, root.join("logs"));
}

#[test]
fn test_load_rejects_empty_root() {
    let file = write_config("hidden_volume_root = \"\"\n");

    let err = Config::load(file.path()).unwrap_err().to_string();
    assert!(err.contains("hidden_volume_root is empty"), "{err}");
}

#[test]
fn test_load_or_default_with_invalid_file_returns_error() {
    let file = write_config("this is = = not toml [[[\n");

    let result = Config::load_or_default(file.path());
    assert!(
        result.is_err(),
        "invalid TOML must not fall back to defaults"
    );
}

#[test]
fn test_apply_cli_overrides_nixos_flake_overrides_config() {
    let mut config = Config {
        nixos_flake: Some("/etc/nixos#from-config".to_string()),
        ..Config::default()
    };

    config.apply_cli_overrides(&CliOverrides {
        nixos_flake: Some("/mnt/hidden/nixos#from-cli".to_string()),
    });
    assert_eq!(
        config.nixos_flake.as_deref(),
        Some("/mnt/hidden/nixos#from-cli")
    );
}

#[test]
fn test_derive_hidden_volume_root_success() {
    let derived = derive_hidden_volume_root();

    assert!(!derived.as_os_str().is_empty());
    assert!(derived.components().count() >= 1);
    // Idempotent
    assert_eq!(derived, derive_hidden_volume_root());
}

#[test]
fn test_config_nixos_flake_defaults_to_none() {
    assert_eq!(Config::default().nixos_flake, None);
    assert_eq!(Config::test_default().nixos_flake, None);
}

#[test]
fn test_config_nixos_flake_toml_load() {
    let with_attr = write_config("nixos_flake = \"/mnt/hv/nixos#host\"\n");
    let path_only = write_config("nixos_flake = \"/mnt/hv/nixos\"\n");
    let absent = write_config("minimum_space_mb = 500\n");

    assert_eq!(
        Config::load(with_attr.path())
            .unwrap()
            .nixos_flake
            .as_deref(),
        Some("/mnt/hv/nixos#host")
    );
    assert_eq!(
        Config::load(path_only.path())
            .unwrap()
            .nixos_flake
            .as_deref(),
        Some("/mnt/hv/nixos")
    );
    assert_eq!(Config::load(absent.path()).unwrap().nixos_flake, None);
}

#[test]
fn test_discover_config_path_with_override_returns_exact_path() {
    use crate::config::discover_config_path;

    let override_path = PathBuf::from("/custom/myconfig.toml");
    assert_eq!(discover_config_path(Some(&override_path)), override_path);
}

#[test]
fn test_discover_config_path_without_override_is_binary_relative_toml() {
    use crate::config::discover_config_path;

    let result = discover_config_path(None);
    assert!(
        result.ends_with("config/nails.toml"),
        "Expected path ending with config/nails.toml, got: {}",
        result.display()
    );

    let exe_dir = std::env::current_exe()
        .unwrap()
        .canonicalize()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    assert_eq!(result, exe_dir.join("config").join("nails.toml"));
}

#[test]
fn retired_live_overlay_keys_are_rejected() {
    for key in [
        "overlays = []",
        "overlay_mode = \"auto\"",
        "clear_history = true",
        "risky_services = \"restart\"",
        "nixos_switch_required = true",
    ] {
        assert!(toml::from_str::<Config>(key).is_err(), "{key}");
    }
}

#[test]
fn test_config_default() {
    let config = Config::default();
    assert!(!config.hidden_volume_root.as_os_str().is_empty());
    assert_eq!(
        config.state_file_path,
        config.hidden_volume_root.join("state.json")
    );
    assert!(config.show_opsec_reminders);
    assert_eq!(config.minimum_space_mb, 500);
    assert_eq!(config.log_path, config.hidden_volume_root.join("logs"));
}

#[test]
fn test_config_test_default() {
    let config = Config::test_default();
    assert_eq!(
        config.hidden_volume_root,
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
    );
    assert_eq!(
        config.log_path,
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("logs")
    );
}

#[test]
fn test_config_toml_serialization_round_trip() {
    let config = Config {
        hidden_volume_root: PathBuf::from("/mnt/round-trip"),
        state_file_path: PathBuf::from("/mnt/round-trip/state.json"),
        log_path: PathBuf::from("/mnt/round-trip/logs"),
        nixos_flake: Some("/mnt/round-trip/nixos#host".to_string()),
        ..Config::test_default()
    };
    let toml_text = toml::to_string(&config).expect("Should serialize to TOML");
    let parsed: Config = toml::from_str(&toml_text).expect("Should parse back strictly");
    assert_eq!(parsed, config);
}

#[test]
fn test_config_keys_match_serialized_fields() {
    let config = Config {
        nixos_flake: Some("/flake#host".to_string()),
        ..Config::test_default()
    };
    let table = toml::Table::try_from(&config).unwrap();
    let mut serialized: Vec<&str> = table.keys().map(String::as_str).collect();
    let mut documented: Vec<&str> = crate::config::CONFIG_KEYS.to_vec();
    serialized.sort_unstable();
    documented.sort_unstable();
    assert_eq!(serialized, documented);
}

#[test]
fn test_builder_with_all_fields_specified() {
    let config = ConfigBuilder::new()
        .hidden_volume_root(PathBuf::from("/mnt/hidden"))
        .state_file_path(PathBuf::from("/mnt/hidden/state.json"))
        .minimum_space_mb(1000)
        .show_opsec_reminders(false)
        .log_path(PathBuf::from("/mnt/hidden/custom-logs"))
        .build()
        .expect("Build should succeed");
    assert_eq!(config.hidden_volume_root, PathBuf::from("/mnt/hidden"));
    assert_eq!(config.minimum_space_mb, 1000);
    assert!(!config.show_opsec_reminders);
    assert_eq!(config.log_path, PathBuf::from("/mnt/hidden/custom-logs"));
}

#[test]
fn test_load_valid_toml_file() {
    let file = write_config(
        r##"
hidden_volume_root = "/mnt/test-volume"
show_opsec_reminders = false
log_path = "/mnt/test-volume/custom-logs"
minimum_space_mb = 750
nixos_flake = "/mnt/test-volume/nixos#host"
"##,
    );
    let config = Config::load(file.path()).unwrap();
    assert_eq!(config.hidden_volume_root, PathBuf::from("/mnt/test-volume"));
    assert!(!config.show_opsec_reminders);
    assert_eq!(config.minimum_space_mb, 750);
    assert_eq!(
        config.nixos_flake.as_deref(),
        Some("/mnt/test-volume/nixos#host")
    );
    assert_eq!(config.loaded_config_path.as_deref(), Some(file.path()));
}

#[test]
fn accept_persistent_decoy_defaults_to_false() {
    let unset: Config = toml::from_str("").unwrap();
    assert!(!unset.accept_persistent_decoy);

    let set: Config = toml::from_str("accept_persistent_decoy = true").unwrap();
    assert!(set.accept_persistent_decoy);
}

#[test]
fn strict_loader_rejects_misspelled_accept_persistent_decoy() {
    // deny_unknown_fields: a typo'd key must be refused, not silently ignored.
    assert!(toml::from_str::<Config>("accept_persistent_decoyy = true").is_err());
    assert!(toml::from_str::<Config>("accept_persistant_decoy = true").is_err());
}
