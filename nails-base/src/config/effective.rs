// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The effective configuration and where each value came from
//!
//! `nails config show` prints every key with its source, so an operator can
//! tell a value they wrote from a default or a path derived from the binary
//! location. Activation uses the same type, so what `config show` reports is
//! what `activate` runs with.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::loading::parse_config_file;
use super::types::{CONFIG_KEYS, CliOverrides, Config};
use crate::error::{NailsError, Result};

/// Where an effective configuration value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueSource {
    /// Built-in default.
    Default,
    /// Set in the configuration file.
    File,
    /// Set by a command-line flag.
    Cli,
    /// Computed: the hidden volume root from the binary location, or a path
    /// placed under the hidden volume root.
    Derived,
}

impl fmt::Display for ValueSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Default => "default",
            Self::File => "file",
            Self::Cli => "cli",
            Self::Derived => "derived",
        })
    }
}

/// Keys whose built-in value is computed rather than fixed.
const DERIVED_KEYS: &[&str] = &["hidden_volume_root", "state_file_path", "log_path"];

/// A configuration together with the file it came from and the source of
/// every value.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    /// The effective configuration.
    pub config: Config,
    /// The configuration file path that was consulted.
    pub path: PathBuf,
    /// Whether that file existed (and was therefore parsed).
    pub file_found: bool,
    file_keys: BTreeSet<String>,
    cli_keys: BTreeSet<&'static str>,
}

impl LoadedConfig {
    /// Load `path` strictly; a missing file is an error.
    ///
    /// # Errors
    ///
    /// `NailsError::ConfigNotFound` when the file does not exist,
    /// `NailsError::IoError` when it cannot be read (with the error's kind, so
    /// a caller can tell a permission problem from the others), otherwise
    /// `NailsError::ConfigError` as described on [`Config::load`].
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NailsError::ConfigNotFound {
                    path: path.to_path_buf(),
                }
            } else {
                NailsError::io(path, e)
            }
        })?;
        Self::parse(path, &contents)
    }

    /// Check `contents` as the file at `path`, strictly: what [`load`](Self::load)
    /// does once it has read the file, which `config validate` reports and the
    /// settings writer runs on the text it is about to write.
    ///
    /// # Errors
    ///
    /// `NailsError::ConfigError` or `NailsError::UnsafeConfigPath`, as
    /// described on [`Config::load`].
    pub fn parse(path: &Path, contents: &str) -> Result<Self> {
        let parsed = parse_config_file(path, contents)?;

        Ok(Self {
            config: parsed.config,
            path: path.to_path_buf(),
            file_found: true,
            file_keys: parsed.keys,
            cli_keys: BTreeSet::new(),
        })
    }

    /// Load `path` strictly, using defaults when the file does not exist.
    ///
    /// A missing file is reported through [`LoadedConfig::file_found`]: each
    /// command says so in its own output (`check`, `status --details` and
    /// `config show` name the source, `activate` prints a notice before it
    /// asks for confirmation), so the log records it at debug level only.
    ///
    /// # Errors
    ///
    /// Every error of [`LoadedConfig::load`] except `ConfigNotFound`.
    pub fn load_or_default(path: &Path) -> Result<Self> {
        match Self::load(path) {
            Err(NailsError::ConfigNotFound { .. }) => {
                tracing::debug!("No config file found at {}, using defaults", path.display());
                Ok(Self::defaults(path))
            }
            other => other,
        }
    }

    /// Built-in defaults, with the hidden volume root derived from the binary.
    pub fn defaults(path: &Path) -> Self {
        Self {
            config: Config::default(),
            path: path.to_path_buf(),
            file_found: false,
            file_keys: BTreeSet::new(),
            cli_keys: BTreeSet::new(),
        }
    }

    /// Apply command-line overrides and record them as the source of the
    /// values they replace.
    pub fn apply_cli_overrides(&mut self, overrides: &CliOverrides) {
        self.config.apply_cli_overrides(overrides);
        self.cli_keys.extend(overrides.overridden_keys());
    }

    /// Where the value of top-level `key` came from.
    pub fn source(&self, key: &str) -> ValueSource {
        if self.cli_keys.contains(key) {
            ValueSource::Cli
        } else if self.file_keys.contains(key) {
            ValueSource::File
        } else if DERIVED_KEYS.contains(&key) {
            ValueSource::Derived
        } else {
            ValueSource::Default
        }
    }

    /// The source of every top-level key, in display order.
    pub fn sources(&self) -> Vec<(&'static str, ValueSource)> {
        CONFIG_KEYS
            .iter()
            .map(|key| (*key, self.source(key)))
            .collect()
    }

    /// The effective configuration.
    pub fn into_config(self) -> Config {
        self.config
    }

    /// Render the effective configuration as TOML, annotating each key with
    /// its source.
    ///
    /// Plain keys come first and tables after them, because in TOML a bare
    /// key that follows a table header belongs to that table. The output
    /// parses back to the same configuration.
    ///
    /// # Errors
    ///
    /// `NailsError::ConfigError` if a value cannot be represented in TOML
    /// (for example a path that is not valid UTF-8).
    pub fn to_annotated_toml(&self) -> Result<String> {
        let table = toml::Table::try_from(&self.config).map_err(render_error)?;
        let status = if self.file_found {
            "found"
        } else {
            "not found, using defaults"
        };

        let mut values = format!(
            "# Effective configuration\n# Config file: {} ({status})\n\n",
            self.path.display()
        );
        let mut tables = String::new();

        for key in CONFIG_KEYS {
            let source = self.source(key);
            let Some(value) = table.get(*key) else {
                values.push_str(&format!("# {key} is not set  # {source}\n"));
                continue;
            };

            let mut single = toml::Table::new();
            single.insert((*key).to_string(), value.clone());
            let rendered = toml::to_string(&single).map_err(render_error)?;

            if is_table_like(value) {
                tables.push_str(&format!("\n# {key}: {source}\n{rendered}"));
            } else {
                values.push_str(&format!("{}  # {source}\n", rendered.trim_end()));
            }
        }

        values.push_str(&tables);
        Ok(values)
    }

    /// The effective configuration, its file and the source of every key, as
    /// JSON.
    ///
    /// # Errors
    ///
    /// `NailsError::ConfigError` if the configuration cannot be serialized.
    pub fn to_json(&self) -> Result<serde_json::Value> {
        let config = serde_json::to_value(&self.config)
            .map_err(|e| NailsError::ConfigError(format!("cannot render config: {e}")))?;
        let sources: serde_json::Map<String, serde_json::Value> = self
            .sources()
            .into_iter()
            .map(|(key, source)| (key.to_string(), serde_json::json!(source)))
            .collect();

        Ok(serde_json::json!({
            "path": self.path.display().to_string(),
            "exists": self.file_found,
            "config": config,
            "sources": sources,
        }))
    }
}

fn is_table_like(value: &toml::Value) -> bool {
    match value {
        toml::Value::Table(_) => true,
        toml::Value::Array(items) => !items.is_empty() && items.iter().all(toml::Value::is_table),
        _ => false,
    }
}

fn render_error(error: impl fmt::Display) -> NailsError {
    NailsError::ConfigError(format!("cannot render config as TOML: {error}"))
}
