//! Tests for strict TOML parsing, error messages and value sources

use crate::config::{CliOverrides, Config, LoadedConfig, OverlayMode, ValueSource};
use crate::error::NailsError;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

fn write_config(contents: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    file
}

/// Load `contents` strictly and return the one-line error message.
fn load_error(contents: &str) -> String {
    let file = write_config(contents);
    match Config::load(file.path()) {
        Err(NailsError::ConfigError(message)) => message,
        other => panic!("expected ConfigError, got {other:?}"),
    }
}

#[test]
fn unknown_top_level_key_is_rejected_with_hint() {
    let message = load_error("hidden_volume_root = \"/mnt/hv\"\nnixos_flak = \"/x#y\"\n");

    assert!(message.contains("line 2, column 1"), "{message}");
    assert!(
        message.contains("unknown key `nixos_flak` (did you mean `nixos_flake`?)"),
        "{message}"
    );
    assert!(
        !message.contains('\n'),
        "message must be one line: {message}"
    );
}

#[test]
fn misspelt_root_key_is_rejected_instead_of_falling_back() {
    let message = load_error("hiden_volume_root = \"/mnt/hv\"\n");

    assert!(
        message.contains("did you mean `hidden_volume_root`?"),
        "{message}"
    );
}

#[test]
fn unknown_key_without_close_match_lists_valid_keys() {
    let message = load_error("[color_scheme]\nzzz = true\n");

    assert!(message.contains("line 2"), "{message}");
    assert!(message.contains("unknown key `zzz`"), "{message}");
    assert!(
        message.contains("expected one of: enabled, hidden, decoy"),
        "{message}"
    );
}

#[test]
fn unknown_nested_key_in_color_scheme_is_rejected() {
    let message = load_error("[color_scheme]\nenable = false\n");

    assert!(
        message.contains("unknown key `enable` (did you mean `enabled`?)"),
        "{message}"
    );
}

#[test]
fn unknown_nested_key_in_color_profile_is_rejected() {
    let message = load_error("[color_scheme.hidden]\nbackgroud = \"#000000\"\n");

    assert!(message.contains("did you mean `background`?"), "{message}");
}

#[test]
fn unknown_key_in_overlay_table_is_rejected() {
    let message = load_error(
        r#"
[[overlays]]
name = "home"
lower = "/home"
upper = "/mnt/hv/home"
work = "/mnt/hv/.work/home"
targt = "/home"
"#,
    );

    assert!(message.contains("did you mean `target`?"), "{message}");
}

#[test]
fn keys_without_an_effect_are_rejected() {
    // Nothing ever read these: preflight checks are skipped only by
    // `activate --no-preflight`, and log rotation is not wired up.
    for key in [
        "preflight_checks = false",
        "max_log_size_mb = 20",
        "retention_days = 3",
    ] {
        let message = load_error(&format!("{key}\n"));
        let name = key.split(' ').next().unwrap();

        assert!(
            message.contains(&format!("unknown key `{name}`")),
            "{message}"
        );
    }
}

#[test]
fn unknown_overlay_mode_value_is_rejected_with_hint() {
    let message = load_error("overlay_mode = \"explict\"\n");

    assert!(
        message.contains("unknown value `explict` (did you mean `explicit`?)"),
        "{message}"
    );
}

#[test]
fn wrong_type_is_rejected_with_location() {
    let message = load_error("clear_history = true\nminimum_space_mb = \"500\"\n");

    assert!(message.contains("line 2"), "{message}");
    assert!(message.contains("invalid type"), "{message}");
}

#[test]
fn syntax_error_is_rejected_with_location() {
    let message = load_error("clear_history = true\n\nlog_path = \n");

    assert!(message.starts_with("invalid config "), "{message}");
    assert!(message.contains("line 3"), "{message}");
}

#[test]
fn yaml_syntax_is_not_accepted() {
    let message = load_error("hidden_volume_root: /mnt/hidden-volume\n");

    assert!(message.contains("line 1"), "{message}");
}

#[test]
fn runtime_only_field_cannot_be_set_from_the_file() {
    let message = load_error("loaded_config_path = \"/elsewhere\"\n");

    assert!(
        message.contains("unknown key `loaded_config_path`"),
        "{message}"
    );
}

#[test]
fn error_names_the_file() {
    let file = write_config("bogus = 1\n");
    let message = Config::load(file.path()).unwrap_err().to_string();

    assert!(
        message.contains(&file.path().display().to_string()),
        "{message}"
    );
}

#[test]
fn line_and_column_count_characters_not_bytes() {
    let message = load_error("prompt_label = \"é\"\nzzz = 1\n");
    assert!(message.contains("line 2, column 1"), "{message}");

    let message = load_error("prompt_label = \"é\" zzz\n");
    assert!(message.contains("line 1"), "{message}");
}

/// Uncomment every `# key = value` and `# [table]` line of a template.
fn uncomment_assignments(template: &str) -> String {
    template
        .lines()
        .map(|line| {
            let body = line.strip_prefix("# ").unwrap_or("");
            let first = body.split_whitespace().next().unwrap_or("");
            let is_assignment = body.contains(" = ")
                && !first.is_empty()
                && first.chars().all(|c| c.is_ascii_lowercase() || c == '_');
            if is_assignment || body.starts_with('[') {
                body
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn example_config_is_valid_as_is_and_fully_uncommented() {
    let example = Config::example_config();
    let as_is = write_config(&example);
    Config::load(as_is.path()).expect("commented example parses");

    let uncommented = uncomment_assignments(&example);
    let file = write_config(&uncommented);
    let config = Config::load(file.path()).expect("every example key is a real key");

    assert_eq!(config.overlay_mode, OverlayMode::Auto);
    assert_eq!(config.overlays.len(), 1);
    assert_eq!(
        config.nixos_flake.as_deref(),
        Some("/mnt/hidden-volume/nixos#my-host")
    );
}

#[test]
fn example_config_mentions_every_key() {
    let example = Config::example_config();
    for key in crate::config::CONFIG_KEYS {
        assert!(example.contains(key), "example misses {key}");
    }
}

#[test]
fn init_template_derives_root_and_uses_given_paths() {
    let template = Config::init_template(Path::new("/media/hv"));

    assert!(template.contains("# hidden_volume_root = \"/media/hv\""));
    assert!(
        !template
            .lines()
            .any(|line| line.starts_with("hidden_volume_root")),
        "root must stay commented out so it is derived from the binary"
    );

    let as_is = write_config(&template);
    let config = Config::load(as_is.path()).unwrap();
    assert_eq!(
        config.hidden_volume_root,
        crate::config::derive_hidden_volume_root()
    );

    let uncommented = write_config(&uncomment_assignments(&template));
    let config = Config::load(uncommented.path()).unwrap();
    assert_eq!(config.hidden_volume_root, PathBuf::from("/media/hv"));
    assert_eq!(config.overlays[0].upper, PathBuf::from("/media/hv/home"));
}

#[test]
fn init_template_escapes_unusual_paths() {
    let template = Config::init_template(Path::new("/media/my \"hv\""));
    let file = write_config(&uncomment_assignments(&template));

    let config = Config::load(file.path()).unwrap();
    assert_eq!(config.hidden_volume_root, PathBuf::from("/media/my \"hv\""));
}

#[test]
fn sources_distinguish_file_default_derived_and_cli() {
    let file = write_config("minimum_space_mb = 750\nnixos_flake = \"/a#b\"\n");
    let mut loaded = LoadedConfig::load(file.path()).unwrap();

    assert!(loaded.file_found);
    assert_eq!(loaded.source("minimum_space_mb"), ValueSource::File);
    assert_eq!(loaded.source("nixos_flake"), ValueSource::File);
    assert_eq!(loaded.source("hidden_volume_root"), ValueSource::Derived);
    assert_eq!(loaded.source("state_file_path"), ValueSource::Derived);
    assert_eq!(loaded.source("clear_history"), ValueSource::Default);

    loaded.apply_cli_overrides(&CliOverrides {
        nixos_flake: Some("/c#d".to_string()),
        clear_history: Some(false),
    });

    assert_eq!(loaded.source("nixos_flake"), ValueSource::Cli);
    assert_eq!(loaded.source("clear_history"), ValueSource::Cli);
    assert_eq!(loaded.source("minimum_space_mb"), ValueSource::File);
    assert_eq!(loaded.config.nixos_flake.as_deref(), Some("/c#d"));
    assert!(!loaded.config.clear_history);
}

#[test]
fn explicit_root_is_a_file_source() {
    let file = write_config("hidden_volume_root = \"/mnt/hv\"\n");
    let loaded = LoadedConfig::load(file.path()).unwrap();

    assert_eq!(loaded.source("hidden_volume_root"), ValueSource::File);
    assert_eq!(loaded.source("log_path"), ValueSource::Derived);
}

#[test]
fn load_or_default_reports_missing_file() {
    let loaded = LoadedConfig::load_or_default(Path::new("/nonexistent/nails.toml")).unwrap();

    assert!(!loaded.file_found);
    assert_eq!(loaded.path, PathBuf::from("/nonexistent/nails.toml"));
    assert!(
        loaded
            .sources()
            .iter()
            .all(|(_, source)| matches!(source, ValueSource::Default | ValueSource::Derived))
    );
}

#[test]
fn strict_load_reports_missing_file() {
    let result = LoadedConfig::load(Path::new("/nonexistent/nails.toml"));
    assert!(matches!(result, Err(NailsError::ConfigNotFound { .. })));
}

#[test]
fn annotated_toml_marks_sources_and_parses_back() {
    let file = write_config(
        r#"
hidden_volume_root = "/mnt/hv"
overlay_mode = "explicit"
nixos_flake = "/mnt/hv/nixos#host"

[[overlays]]
name = "home"
lower = "/home"
upper = "/mnt/hv/home"
work = "/mnt/hv/.work/home"
target = "/home"
"#,
    );
    let mut loaded = LoadedConfig::load(file.path()).unwrap();
    loaded.apply_cli_overrides(&CliOverrides {
        clear_history: Some(false),
        ..Default::default()
    });

    let rendered = loaded.to_annotated_toml().unwrap();

    assert!(
        rendered.contains("hidden_volume_root = \"/mnt/hv\"  # file"),
        "{rendered}"
    );
    assert!(
        rendered.contains("state_file_path = \"/mnt/hv/state.json\"  # derived"),
        "{rendered}"
    );
    assert!(
        rendered.contains("clear_history = false  # cli"),
        "{rendered}"
    );
    assert!(
        rendered.contains("minimum_space_mb = 500  # default"),
        "{rendered}"
    );
    assert!(
        rendered.contains("# overlays: file\n[[overlays]]"),
        "{rendered}"
    );
    assert!(
        rendered.contains("# color_scheme: default\n[color_scheme]"),
        "{rendered}"
    );

    let reparsed = write_config(&rendered);
    let config = Config::load(reparsed.path()).expect("annotated output is valid config");
    let mut expected = loaded.config.clone();
    expected.loaded_config_path = config.loaded_config_path.clone();
    assert_eq!(config, expected);
}

#[test]
fn annotated_toml_notes_unset_optional_keys_and_missing_file() {
    let loaded = LoadedConfig::defaults(Path::new("/nonexistent/nails.toml"));

    let rendered = loaded.to_annotated_toml().unwrap();
    assert!(
        rendered.contains("/nonexistent/nails.toml (not found, using defaults)"),
        "{rendered}"
    );
    assert!(
        rendered.contains("# nixos_flake is not set  # default"),
        "{rendered}"
    );
}

#[test]
fn json_rendering_carries_path_existence_config_and_sources() {
    let file = write_config("minimum_space_mb = 750\n");
    let loaded = LoadedConfig::load(file.path()).unwrap();

    let json = loaded.to_json().unwrap();
    assert_eq!(json["path"], file.path().display().to_string());
    assert_eq!(json["exists"], true);
    assert_eq!(json["config"]["minimum_space_mb"], 750);
    assert_eq!(json["sources"]["minimum_space_mb"], "file");
    assert_eq!(json["sources"]["hidden_volume_root"], "derived");
    assert_eq!(json["sources"]["clear_history"], "default");
    assert!(json["config"].get("loaded_config_path").is_none());
}
