// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared configuration resolution for the facade.
//!
//! One place turns the optional `--config` path into a [`LoadedConfig`], so no
//! operation and no front end can disagree on where the configuration came from
//! or treat a broken file as if it were the built-in defaults. A teardown
//! (emergency or recover) must never be blocked by a failed hidden volume, so it
//! has its own fall-back resolution that always yields a usable configuration.

use std::path::{Path, PathBuf};

use crate::{Config, LoadedConfig, NailsError};

/// Resolve and load the configuration strictly.
///
/// * `config_override` is `Some` (`--config`): the file must exist.
/// * `config_override` is `None`: the binary-relative file is optional and
///   built-in defaults apply when it is missing.
///
/// Either way an unreadable or invalid file is an error. `loaded_config_path`
/// is set to the consulted path so cleanup preserves it.
pub fn resolve_config(config_override: Option<&Path>) -> Result<LoadedConfig, NailsError> {
    let path = crate::config::discover_config_path(config_override);
    let mut loaded = if config_override.is_some() {
        LoadedConfig::load(&path)?
    } else {
        LoadedConfig::load_or_default(&path)?
    };
    loaded.config.loaded_config_path = Some(path);
    Ok(loaded)
}

/// One-line description of a configuration load failure.
pub fn config_error_line(error: &NailsError) -> String {
    match error {
        NailsError::ConfigNotFound { path } => format!(
            "config file not found: {} (run `nails init <root>` or pass --config)",
            path.display()
        ),
        NailsError::ConfigError(message) => message.clone(),
        NailsError::IoError { path, source } => {
            format!("cannot read config {}: {source}", path.display())
        }
        other => other.to_string(),
    }
}

/// Resolve the configuration, or fall back to the built-in defaults derived from
/// the binary location.
///
/// For a command that must never refuse: on any problem this logs a single
/// warning and continues with built-in defaults, whose hidden volume root is
/// derived from the binary location.
pub fn load_config_or_defaults(config_override: Option<&Path>) -> LoadedConfig {
    resolve_config(config_override).unwrap_or_else(|error| {
        let path: PathBuf = crate::config::discover_config_path(config_override);
        tracing::warn!(
            "{}; continuing with defaults derived from the binary location",
            config_error_line(&error)
        );
        let mut loaded = LoadedConfig::defaults(&path);
        loaded.config.loaded_config_path = Some(path);
        loaded
    })
}

/// Where a teardown's configuration was ultimately loaded from.
///
/// Reported to the operator so a teardown that had to fall back off the failed
/// hidden volume says so, rather than silently acting on the wrong data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    /// The real configuration file (on the hidden volume or binary-relative).
    File,
    /// The RAM-backed copy under `/run`, used because the file was unreadable.
    RuntimeCopy,
    /// Built-in defaults, used because neither the file nor a copy was available.
    Defaults,
}

impl ConfigSource {
    /// A short phrase naming the source, for human-facing output.
    pub fn describe(self) -> &'static str {
        match self {
            ConfigSource::File => "configuration file",
            ConfigSource::RuntimeCopy => "RAM-backed runtime copy",
            ConfigSource::Defaults => "built-in defaults",
        }
    }
}

/// Load the configuration for a teardown (emergency or recover) that must never
/// be blocked by a failed hidden volume.
///
/// The real config file lives on the hidden volume, so when that volume is the
/// thing that failed the file is unreadable. This tries, in order: the config
/// file, the mirrored copy in the RAM-backed runtime directory under `/run`
/// (written at activation precisely for this case), and finally the built-in
/// defaults. The source is returned so the caller can tell the operator which one
/// was used; in every case the teardown only acts on what the live mount table
/// shows NAILS created.
pub fn load_config_for_teardown(config_override: Option<&Path>) -> (Config, ConfigSource) {
    // An authoritative config file wins: either an explicit `--config` (which
    // errors rather than defaulting when absent) or a binary-relative file that
    // was actually present. A *missing* binary-relative file is not authoritative:
    // `resolve_config` returns built-in defaults for it, whose hidden volume root
    // is derived from the running binary's own location. When emergency runs from
    // the RAM-backed copy under `/run` that root points into `/run`, not at the
    // real overlays, so those defaults must not be preferred over the mirrored
    // config the copy carries.
    let file_config = match resolve_config(config_override) {
        Ok(loaded) if config_override.is_some() || loaded.file_found => Some(loaded.into_config()),
        _ => None,
    };

    // The RAM-backed runtime copy under `/run` records the real hidden root and
    // state path from activation, written precisely so teardown still works when
    // the hidden volume (and the real config and state files on it) are gone. It
    // is strictly better than binary-relative defaults, so it is consulted whenever
    // no authoritative file was found — not only when the file was unreadable.
    let runtime_copy_config = if file_config.is_some() {
        None
    } else {
        match crate::runtime_copy::read_config_copy(&crate::RealFilesystem) {
            Ok(copy) => copy,
            Err(e) => {
                tracing::warn!(error = %e, "could not read the runtime config copy; using defaults");
                None
            }
        }
    };

    let defaults = || load_config_or_defaults(config_override).into_config();
    pick_teardown_config(file_config, runtime_copy_config, defaults)
}

/// Choose the teardown configuration and record where it came from.
///
/// Precedence: an authoritative config file, then the RAM-backed runtime copy
/// under `/run`, then built-in defaults. The runtime copy must outrank defaults
/// so an emergency launched from the copy (when the hidden volume is gone) tears
/// down the real overlays instead of a set derived from the copied binary's own
/// location. `defaults` is only evaluated when neither of the first two is present.
fn pick_teardown_config(
    file_config: Option<Config>,
    runtime_copy_config: Option<Config>,
    defaults: impl FnOnce() -> Config,
) -> (Config, ConfigSource) {
    if let Some(config) = file_config {
        return (config, ConfigSource::File);
    }
    if let Some(config) = runtime_copy_config {
        tracing::warn!("config file not found; using the RAM-backed runtime copy under /run");
        return (config, ConfigSource::RuntimeCopy);
    }
    (defaults(), ConfigSource::Defaults)
}

#[cfg(test)]
mod tests {
    use super::{ConfigSource, config_error_line, pick_teardown_config};
    use crate::{Config, NailsError};
    use std::path::PathBuf;

    #[test]
    fn an_unreadable_config_names_the_file() {
        let error = NailsError::io(
            "/mnt/data/config/nails.toml",
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        assert!(
            config_error_line(&error)
                .starts_with("cannot read config /mnt/data/config/nails.toml: "),
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
}
