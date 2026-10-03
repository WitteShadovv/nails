//! Tests for main Config struct and ConfigBuilder

use crate::RiskyServicePolicy;
use crate::config::{
    CliOverrides, Config, ConfigBuilder, DEFAULT_HIDDEN_VOLUME_ROOT, OverlayConfig, OverlayMode,
    derive_hidden_volume_root,
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
fn test_config_default() {
    let config = Config::default();

    // hidden_volume_root should be auto-derived (not empty)
    assert!(!config.hidden_volume_root.as_os_str().is_empty());
    // state_file_path should be derived from hidden_volume_root
    assert_eq!(
        config.state_file_path,
        config.hidden_volume_root.join("state.json")
    );
    // Default config includes /boot, /home, /etc and /var overlays
    assert_eq!(config.overlays.len(), 4);
    assert_eq!(config.overlays[1].name, "home");
    assert_eq!(config.overlays[2].name, "etc");
    assert_eq!(config.overlays[3].name, "var");
    assert!(config.clear_history);
    assert!(config.show_opsec_reminders);
    assert_eq!(config.minimum_space_mb, 500);
    // log_path should be derived from hidden_volume_root
    assert_eq!(config.log_path, config.hidden_volume_root.join("logs"));
}

#[test]
fn test_config_test_default() {
    let config = Config::test_default();

    assert_eq!(
        config.hidden_volume_root,
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
    );
    assert_eq!(config.overlays.len(), 4);
    assert_eq!(config.overlays[1].name, "home");
    assert_eq!(config.overlays[2].name, "etc");
    assert_eq!(config.overlays[3].name, "var");
    assert!(config.clear_history);
    assert_eq!(
        config.log_path,
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("logs")
    );
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
fn test_config_json_serialization_round_trip() {
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

    let json = serde_json::to_string_pretty(&config).expect("Should serialize");
    assert!(json.contains("\"hidden_volume_root\""));
    assert!(json.contains("\"state_file_path\""));
    assert!(json.contains("\"overlays\""));

    let deserialized: Config = serde_json::from_str(&json).expect("Should deserialize");
    assert_eq!(deserialized, config);
}

#[test]
fn test_config_toml_serialization_round_trip() {
    let config = Config {
        hidden_volume_root: PathBuf::from("/mnt/round-trip"),
        state_file_path: PathBuf::from("/mnt/round-trip/state.json"),
        log_path: PathBuf::from("/mnt/round-trip/logs"),
        overlay_mode: OverlayMode::Explicit,
        nixos_flake: Some("/mnt/round-trip/nixos#host".to_string()),
        prompt_label: "ctx".to_string(),
        ..Config::test_default()
    };

    let toml_text = toml::to_string(&config).expect("Should serialize to TOML");
    let parsed: Config = toml::from_str(&toml_text).expect("Should parse back strictly");
    assert_eq!(parsed, config);
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
fn test_config_keys_match_serialized_fields() {
    let config = Config {
        nixos_flake: Some("/flake#host".to_string()),
        risky_services: Some(RiskyServicePolicy::Restart),
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
    let overlays = vec![OverlayConfig {
        name: "home".to_string(),
        lower: PathBuf::from("/home"),
        upper: PathBuf::from("/mnt/hidden/home"),
        work: PathBuf::from("/mnt/hidden/.work/home"),
        target: PathBuf::from("/home"),
    }];

    let config = ConfigBuilder::new()
        .hidden_volume_root(PathBuf::from("/mnt/hidden"))
        .state_file_path(PathBuf::from("/mnt/hidden/state.json"))
        .overlays(overlays.clone())
        .overlay_mode(OverlayMode::Explicit)
        .overlay_exclusions(vec![PathBuf::from("/srv")])
        .overlay_exclusions_remove(vec![PathBuf::from("/mnt")])
        .allow_leaky_exclusions(vec![PathBuf::from("/srv")])
        .minimum_space_mb(1000)
        .clear_history(false)
        .show_opsec_reminders(false)
        .log_path(PathBuf::from("/mnt/hidden/custom-logs"))
        .build()
        .expect("Build should succeed");

    assert_eq!(config.hidden_volume_root, PathBuf::from("/mnt/hidden"));
    assert_eq!(
        config.state_file_path,
        PathBuf::from("/mnt/hidden/state.json")
    );
    assert_eq!(config.overlays, overlays);
    assert_eq!(config.overlay_mode, OverlayMode::Explicit);
    assert_eq!(config.overlay_exclusions, vec![PathBuf::from("/srv")]);
    assert_eq!(
        config.overlay_exclusions_remove,
        vec![PathBuf::from("/mnt")]
    );
    assert_eq!(config.allow_leaky_exclusions, vec![PathBuf::from("/srv")]);
    assert_eq!(config.minimum_space_mb, 1000);
    assert!(!config.clear_history);
    assert!(!config.show_opsec_reminders);
    assert_eq!(config.log_path, PathBuf::from("/mnt/hidden/custom-logs"));
}

#[test]
fn test_builder_with_minimal_fields_applies_defaults() {
    let config = ConfigBuilder::new()
        .hidden_volume_root(PathBuf::from("/mnt/hidden"))
        .build()
        .expect("Build should succeed");

    assert_eq!(config.hidden_volume_root, PathBuf::from("/mnt/hidden"));
    assert_eq!(
        config.state_file_path,
        PathBuf::from("/mnt/hidden/state.json")
    );
    assert!(config.overlays.is_empty());
    assert_eq!(config.overlay_mode, OverlayMode::Auto);
    assert_eq!(config.minimum_space_mb, 500);
    assert!(config.clear_history);
    assert_eq!(config.log_path, PathBuf::from("/mnt/hidden/logs"));
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
fn test_load_valid_toml_file() {
    let file = write_config(
        r##"
hidden_volume_root = "/mnt/test-volume"
clear_history = false
show_opsec_reminders = false
log_path = "/mnt/test-volume/custom-logs"
minimum_space_mb = 750
prompt_label = "ctx"
nixos_flake = "/mnt/test-volume/nixos#host"
overlay_mode = "auto"
overlay_exclusions = ["/srv"]
overlay_exclusions_remove = ["/mnt"]
allow_leaky_exclusions = ["/srv"]

[color_scheme]
enabled = false

[color_scheme.hidden]
background = "#000000"

[color_scheme.decoy]
reset = false
"##,
    );

    let config = Config::load(file.path()).unwrap();
    assert_eq!(config.hidden_volume_root, PathBuf::from("/mnt/test-volume"));
    assert!(!config.clear_history);
    assert!(!config.show_opsec_reminders);
    assert_eq!(
        config.log_path,
        PathBuf::from("/mnt/test-volume/custom-logs")
    );
    assert_eq!(config.minimum_space_mb, 750);
    assert_eq!(config.prompt_label, "ctx");
    assert_eq!(
        config.nixos_flake.as_deref(),
        Some("/mnt/test-volume/nixos#host")
    );
    assert_eq!(config.overlay_exclusions, vec![PathBuf::from("/srv")]);
    assert_eq!(
        config.overlay_exclusions_remove,
        vec![PathBuf::from("/mnt")]
    );
    assert_eq!(config.allow_leaky_exclusions, vec![PathBuf::from("/srv")]);
    assert!(!config.color_scheme.enabled);
    assert_eq!(config.color_scheme.hidden.background, "#000000");
    // Unset nested keys keep their defaults
    assert_eq!(config.color_scheme.hidden.foreground, "#e0e0e0");
    assert!(!config.color_scheme.decoy.reset);
    assert_eq!(config.loaded_config_path.as_deref(), Some(file.path()));
}

#[test]
fn test_load_explicit_overlays() {
    let file = write_config(
        r#"
hidden_volume_root = "/mnt/hv"
overlay_mode = "explicit"

[[overlays]]
name = "home"
lower = "/home"
upper = "/mnt/hv/home"
work = "/mnt/hv/.work/home"
target = "/home"

[[overlays]]
name = "etc"
lower = "/etc"
upper = "/mnt/hv/etc"
work = "/mnt/hv/.work/etc"
target = "/etc"
"#,
    );

    let config = Config::load(file.path()).unwrap();
    assert_eq!(config.overlay_mode, OverlayMode::Explicit);
    assert_eq!(config.overlays.len(), 2);
    assert_eq!(config.overlays[0].name, "home");
    assert_eq!(config.overlays[1].upper, PathBuf::from("/mnt/hv/etc"));
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
fn test_load_without_root_derives_it() {
    let file = write_config("clear_history = true\nshow_opsec_reminders = true\n");

    let config = Config::load(file.path()).expect("root is optional");
    assert!(config.clear_history);
    assert!(config.show_opsec_reminders);
    assert_eq!(config.hidden_volume_root, derive_hidden_volume_root());
    assert_eq!(
        config.state_file_path,
        config.hidden_volume_root.join("state.json")
    );
    assert_eq!(config.log_path, config.hidden_volume_root.join("logs"));
}

#[test]
fn test_load_partial_config_with_defaults() {
    let file = write_config("hidden_volume_root = \"/mnt/partial\"\nclear_history = false\n");

    let config = Config::load(file.path()).unwrap();
    assert_eq!(config.hidden_volume_root, PathBuf::from("/mnt/partial"));
    assert!(!config.clear_history);
    assert!(config.show_opsec_reminders);
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
fn test_load_or_default_with_existing_file() {
    let file = write_config("hidden_volume_root = \"/mnt/test-default\"\nclear_history = false\n");

    let config = Config::load_or_default(file.path()).unwrap();
    assert_eq!(
        config.hidden_volume_root,
        PathBuf::from("/mnt/test-default")
    );
    assert!(!config.clear_history);
}

#[test]
fn test_load_or_default_with_nonexistent_file() {
    let config = Config::load_or_default(&PathBuf::from("/nonexistent/config.toml")).unwrap();

    assert!(!config.hidden_volume_root.as_os_str().is_empty());
    assert!(config.clear_history);
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
fn test_cli_overrides_default() {
    let overrides = CliOverrides::default();
    assert!(overrides.clear_history.is_none());
    assert!(overrides.nixos_flake.is_none());
}

#[test]
fn test_apply_cli_overrides_clear_history() {
    let mut config = Config::default();
    assert!(config.clear_history);

    config.apply_cli_overrides(&CliOverrides {
        clear_history: Some(false),
        ..Default::default()
    });
    assert!(!config.clear_history);
}

#[test]
fn test_apply_cli_overrides_unset_preserves_config() {
    let mut config = Config {
        clear_history: false,
        nixos_flake: Some("/etc/nixos#from-config".to_string()),
        ..Default::default()
    };

    config.apply_cli_overrides(&CliOverrides::default());

    assert!(!config.clear_history);
    assert_eq!(
        config.nixos_flake.as_deref(),
        Some("/etc/nixos#from-config")
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
        ..Default::default()
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
fn test_config_default_uses_derived_root() {
    let config = Config::default();

    assert!(!config.hidden_volume_root.as_os_str().is_empty());
    assert!(
        config
            .state_file_path
            .starts_with(&config.hidden_volume_root)
    );
    assert!(config.log_path.starts_with(&config.hidden_volume_root));
    for overlay in &config.overlays {
        assert!(overlay.upper.starts_with(&config.hidden_volume_root));
        assert!(overlay.work.starts_with(&config.hidden_volume_root));
    }
}

#[test]
fn test_derived_paths_consistency() {
    let config = Config::default();
    let root = &config.hidden_volume_root;

    assert_eq!(config.state_file_path, root.join("state.json"));
    assert_eq!(config.log_path, root.join("logs"));
    assert_eq!(config.overlays[1].upper, root.join("home"));
    assert_eq!(config.overlays[1].work, root.join(".work/home"));
    assert_eq!(config.overlays[2].upper, root.join("etc"));
    assert_eq!(config.overlays[2].work, root.join(".work/etc"));
    assert_eq!(config.overlays[3].upper, root.join("var"));
    assert_eq!(config.overlays[3].work, root.join(".work/var"));
}

#[test]
fn test_overlay_mode_default_is_auto() {
    let config = Config::default();
    assert_eq!(config.overlay_mode, OverlayMode::Auto);
}

#[test]
fn test_overlay_mode_toml_values() {
    let auto = write_config("overlay_mode = \"auto\"\n");
    let explicit = write_config("overlay_mode = \"explicit\"\n");

    assert_eq!(
        Config::load(auto.path()).unwrap().overlay_mode,
        OverlayMode::Auto
    );
    assert_eq!(
        Config::load(explicit.path()).unwrap().overlay_mode,
        OverlayMode::Explicit
    );
}

#[test]
fn test_compute_effective_exclusions_defaults_only() {
    let config = Config::default();

    let exclusions = config.compute_effective_exclusions();

    // Only the host-independent defaults; the base-OS core roots now live in the
    // platform policy, not the config defaults.
    assert_eq!(exclusions.len(), 6);
    assert!(exclusions.contains(&PathBuf::from("/proc")));
    assert!(exclusions.contains(&PathBuf::from("/sys")));
    assert!(exclusions.contains(&PathBuf::from("/dev")));
    assert!(exclusions.contains(&PathBuf::from("/run")));
    assert!(exclusions.contains(&PathBuf::from("/mnt")));
    assert!(!exclusions.contains(&PathBuf::from("/boot")));
    assert!(!exclusions.contains(&PathBuf::from("/bin")));
    assert!(!exclusions.contains(&PathBuf::from("/usr")));
    assert!(!exclusions.contains(&PathBuf::from("/lib")));
    assert!(!exclusions.contains(&PathBuf::from("/lib64")));
    assert!(!exclusions.contains(&PathBuf::from("/sbin")));
    assert!(exclusions.contains(&PathBuf::from("/lost+found")));
}

#[test]
fn test_compute_effective_exclusions_with_user_additions() {
    let config = Config {
        overlay_exclusions: vec![PathBuf::from("/custom1"), PathBuf::from("/custom2")],
        ..Config::default()
    };

    let exclusions = config.compute_effective_exclusions();

    assert_eq!(exclusions.len(), 8);
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

    // /boot and /lib are not defaults any more, so only /mnt is actually removed.
    assert_eq!(exclusions.len(), 5);
    assert!(exclusions.contains(&PathBuf::from("/proc")));
    assert!(!exclusions.contains(&PathBuf::from("/mnt")));
    assert!(!exclusions.contains(&PathBuf::from("/boot")));
    assert!(!exclusions.contains(&PathBuf::from("/lib")));
}

#[test]
fn test_compute_effective_exclusions_remove_all_defaults() {
    let config = Config {
        overlay_exclusions_remove: crate::config::DEFAULT_OVERLAY_EXCLUSIONS
            .iter()
            .map(PathBuf::from)
            .collect(),
        ..Config::default()
    };

    assert!(config.compute_effective_exclusions().is_empty());
}

#[test]
fn test_compute_effective_exclusions_combined_add_and_remove() {
    let config = Config {
        overlay_exclusions: vec![PathBuf::from("/custom")],
        overlay_exclusions_remove: vec![PathBuf::from("/mnt")],
        ..Config::default()
    };

    let exclusions = config.compute_effective_exclusions();

    // 6 defaults + /custom - /mnt.
    assert_eq!(exclusions.len(), 6);
    assert!(exclusions.contains(&PathBuf::from("/custom")));
    assert!(!exclusions.contains(&PathBuf::from("/mnt")));
}

#[test]
fn test_compute_effective_exclusions_no_duplicates() {
    let config = Config {
        overlay_exclusions: vec![PathBuf::from("/proc"), PathBuf::from("/boot")],
        ..Config::default()
    };

    let exclusions = config.compute_effective_exclusions();

    let proc_count = exclusions
        .iter()
        .filter(|p| *p == &PathBuf::from("/proc"))
        .count();
    assert_eq!(proc_count, 1);
}

#[test]
#[tracing_test::traced_test]
fn test_compute_effective_exclusions_warns_about_dangerous_removals() {
    let config = Config {
        overlay_exclusions_remove: vec![
            PathBuf::from("/proc"),
            PathBuf::from("/sys"),
            PathBuf::from("/dev"),
        ],
        ..Config::default()
    };

    let exclusions = config.compute_effective_exclusions();

    assert!(!exclusions.contains(&PathBuf::from("/proc")));
    assert!(!exclusions.contains(&PathBuf::from("/sys")));
    assert!(!exclusions.contains(&PathBuf::from("/dev")));
    assert!(logs_contain("Removing /proc"));
    assert!(logs_contain("Removing /sys"));
    assert!(logs_contain("Removing /dev"));
    assert!(logs_contain("mount will likely FAIL"));
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
    let absent = write_config("clear_history = true\n");

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
fn test_config_prompt_label_defaults_empty() {
    assert!(Config::default().prompt_label.is_empty());
}

#[test]
fn test_config_prompt_label_toml_load() {
    let with_label = write_config("prompt_label = \"ctx\"\n");
    let without = write_config("clear_history = true\n");

    assert_eq!(Config::load(with_label.path()).unwrap().prompt_label, "ctx");
    assert!(
        Config::load(without.path())
            .unwrap()
            .prompt_label
            .is_empty()
    );
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
fn risky_services_parses_restart_and_skip() {
    let restart: Config = toml::from_str("risky_services = \"restart\"").unwrap();
    assert_eq!(restart.risky_services, Some(RiskyServicePolicy::Restart));

    let skip: Config = toml::from_str("risky_services = \"skip\"").unwrap();
    assert_eq!(skip.risky_services, Some(RiskyServicePolicy::Skip));

    let unset: Config = toml::from_str("").unwrap();
    assert_eq!(unset.risky_services, None);
}

#[test]
fn risky_services_rejects_unknown_value() {
    assert!(toml::from_str::<Config>("risky_services = \"ignore\"").is_err());
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
