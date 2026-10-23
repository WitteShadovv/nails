// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the facade's shared configuration resolution.

use super::{ConfigSource, config_error_line, load_config_for_teardown, pick_teardown_config};
use crate::{Config, NailsError};
use std::io::Write;
use std::path::PathBuf;

#[test]
fn config_source_describe_names_each_source() {
    // The phrase is shown to the operator so they know whether a teardown
    // acted on the real file, the RAM-backed copy, or built-in defaults.
    // Each variant has an exact, distinct contract string.
    assert_eq!(ConfigSource::File.describe(), "configuration file");
    assert_eq!(
        ConfigSource::RuntimeCopy.describe(),
        "RAM-backed runtime copy"
    );
    assert_eq!(ConfigSource::Defaults.describe(), "built-in defaults");
}

#[test]
fn teardown_with_explicit_config_treats_the_file_as_authoritative() {
    // `--config` pointing at a readable file must be used as the
    // authoritative source: the guard's `config_override.is_some()` arm
    // makes it `File` without consulting the runtime copy or defaults.
    let mut file = tempfile::NamedTempFile::new().unwrap();
    writeln!(file, "hidden_volume_root = \"/mnt/explicit-root\"").unwrap();

    let (config, source) = load_config_for_teardown(Some(file.path()));

    assert_eq!(source, ConfigSource::File);
    assert_eq!(
        config.hidden_volume_root,
        PathBuf::from("/mnt/explicit-root")
    );
}

#[test]
fn teardown_without_config_never_claims_an_authoritative_file() {
    // With no `--config` and no binary-relative file present (the test
    // environment has neither), the config is not authoritative: teardown
    // must fall back to the runtime copy or built-in defaults and say so,
    // never report `File`.
    let (_config, source) = load_config_for_teardown(None);

    assert_ne!(
        source,
        ConfigSource::File,
        "a teardown with no --config and no on-disk file must not claim a File source"
    );
}

#[test]
fn an_unreadable_config_names_the_file() {
    let error = NailsError::io(
        "/mnt/data/config/nails.toml",
        std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    );
    assert!(
        config_error_line(&error).starts_with("cannot read config /mnt/data/config/nails.toml: "),
        "{}",
        config_error_line(&error)
    );
}

fn config_rooted_at(root: &str) -> Config {
    Config {
        hidden_volume_root: PathBuf::from(root),
        ..Config::test_default()
    }
}

#[test]
fn teardown_config_prefers_an_authoritative_file() {
    let file = config_rooted_at("/mnt/data/file");
    let copy = config_rooted_at("/mnt/data/copy");
    let (config, source) = pick_teardown_config(Some(file), Some(copy), || {
        panic!("defaults must not be evaluated when a file is present")
    });
    assert_eq!(source, ConfigSource::File);
    assert_eq!(config.hidden_volume_root, PathBuf::from("/mnt/data/file"));
}

#[test]
fn teardown_config_prefers_the_runtime_copy_over_defaults() {
    // The regression: a missing binary-relative config yields built-in
    // defaults, whose hidden root is derived from the running binary. When
    // emergency runs from the RAM-backed copy that root points into /run, so
    // the mirrored copy — which records the real hidden root — must win.
    let copy = config_rooted_at("/mnt/data/real-hidden-root");
    let (config, source) = pick_teardown_config(None, Some(copy), || {
        panic!("defaults must not be evaluated when a runtime copy is present")
    });
    assert_eq!(source, ConfigSource::RuntimeCopy);
    assert_eq!(
        config.hidden_volume_root,
        PathBuf::from("/mnt/data/real-hidden-root")
    );
}

#[test]
fn teardown_config_falls_back_to_defaults_when_nothing_else_is_available() {
    let defaults = config_rooted_at("/derived/from/binary");
    let (config, source) = pick_teardown_config(None, None, || defaults.clone());
    assert_eq!(source, ConfigSource::Defaults);
    assert_eq!(
        config.hidden_volume_root,
        PathBuf::from("/derived/from/binary")
    );
}
