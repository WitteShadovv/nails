// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Configuration loading and discovery

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::effective::LoadedConfig;
use super::types::{Config, DEFAULT_HIDDEN_VOLUME_ROOT};
use crate::error::{NailsError, Result};

// The configuration directory and file names live in the artifact registry, the
// single source of what NAILS writes. Re-exported here so existing callers keep
// using `config::CONFIG_FILE_NAME` without the literal being repeated.
pub use crate::artifacts::{CONFIG_DIR_NAME, CONFIG_FILE_NAME};

/// Discover the configuration file path
///
/// Resolution order:
/// 1. `--config <PATH>` (any TOML file; highest priority)
/// 2. `{binary_dir}/config/nails.toml`, where `binary_dir` is the directory
///    of the running executable after symlinks are resolved
/// 3. `{current_dir}/config/nails.toml`, only when the executable path cannot
///    be determined
///
/// Resolving symlinks first means a `/usr/local/bin/nails` link to
/// `/mnt/hidden-volume/nails` reads `/mnt/hidden-volume/config/nails.toml`:
/// the configuration always travels with the binary on the hidden volume.
///
/// This function only computes the path; it never checks that the file
/// exists. A missing file at the discovered location means "use defaults",
/// while a missing file named by `--config` is an error (see the CLI).
///
/// # Example
///
/// ```rust
/// use nails_base::config::discover_config_path;
/// use std::path::PathBuf;
///
/// // With CLI override
/// let path = discover_config_path(Some(&PathBuf::from("/custom/config.toml")));
/// assert_eq!(path, PathBuf::from("/custom/config.toml"));
///
/// // Binary-relative (most common case)
/// let path = discover_config_path(None);
/// assert!(path.ends_with("config/nails.toml"));
/// ```
pub fn discover_config_path(config_override: Option<&Path>) -> PathBuf {
    if let Some(override_path) = config_override {
        return override_path.to_path_buf();
    }

    let relative = Path::new(CONFIG_DIR_NAME).join(CONFIG_FILE_NAME);

    if let Ok(exe_path) = std::env::current_exe()
        && let Ok(resolved_path) = exe_path.canonicalize()
        && let Some(exe_dir) = resolved_path.parent()
    {
        return exe_dir.join(relative);
    }

    tracing::warn!(
        "Failed to determine binary location for config discovery, trying current working directory"
    );

    match std::env::current_dir() {
        Ok(dir) => dir.join(relative),
        Err(e) => {
            tracing::error!(
                "Failed to determine current directory for config discovery: {}. Using fallback ./{}",
                e,
                relative.display()
            );
            Path::new(".").join(relative)
        }
    }
}

/// A strictly parsed config file: the resolved config and the top-level keys
/// the file set explicitly.
pub(super) struct ParsedFile {
    pub(super) config: Config,
    pub(super) keys: BTreeSet<String>,
}

/// Parse `contents` (read from `path`) strictly.
///
/// Unknown keys at any level, wrong types and TOML syntax errors are all
/// rejected with a one-line message that names the file, the line and column,
/// and for a misspelt key the closest valid key. Paths the file leaves unset
/// (`state_file_path`, `log_path`) are derived from `hidden_volume_root`, and
/// then every path is checked by [`Config::validate_paths`].
pub(super) fn parse_config_file(path: &Path, contents: &str) -> Result<ParsedFile> {
    let mut config: Config =
        toml::from_str(contents).map_err(|e| invalid_config(path, contents, &e))?;
    let table: toml::Table =
        toml::from_str(contents).map_err(|e| invalid_config(path, contents, &e))?;
    let keys: BTreeSet<String> = table.keys().cloned().collect();

    if config.hidden_volume_root.as_os_str().is_empty() {
        return Err(NailsError::ConfigError(format!(
            "invalid config {}: hidden_volume_root is empty (remove the key to derive it from the binary location)",
            path.display()
        )));
    }

    if !keys.contains("state_file_path") {
        config.state_file_path = config.hidden_volume_root.join("state.json");
    }
    if !keys.contains("log_path") {
        config.log_path = config.hidden_volume_root.join("logs");
    }
    config.loaded_config_path = Some(path.to_path_buf());
    config.validate_paths()?;

    Ok(ParsedFile { config, keys })
}

fn invalid_config(path: &Path, contents: &str, error: &toml::de::Error) -> NailsError {
    let detail = super::suggest::describe(error.message());
    let message = match error.span() {
        Some(span) => {
            let (line, column) = line_and_column(contents, span.start);
            format!(
                "invalid config {}: line {line}, column {column}: {detail}",
                path.display()
            )
        }
        None => format!("invalid config {}: {detail}", path.display()),
    };
    NailsError::ConfigError(message)
}

/// 1-based line and column of byte `offset` in `text`.
fn line_and_column(text: &str, offset: usize) -> (usize, usize) {
    let before = &text[..floor_char_boundary(text, offset)];
    let line = before.matches('\n').count() + 1;
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    let column = before[line_start..].chars().count() + 1;
    (line, column)
}

fn floor_char_boundary(text: &str, offset: usize) -> usize {
    let mut offset = offset.min(text.len());
    while !text.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

impl Config {
    /// Load configuration from a TOML file, strictly
    ///
    /// # Errors
    ///
    /// - `NailsError::ConfigNotFound` if the file does not exist.
    /// - `NailsError::IoError` if the file cannot be read (permission denied,
    ///   a directory, an I/O error), carrying the error's kind.
    /// - `NailsError::ConfigError` if the file is not valid TOML, contains an
    ///   unknown key at any level, or has a value of the wrong type. The
    ///   message is one line and names the line and column; for a misspelt
    ///   key it suggests the closest valid key.
    /// - `NailsError::UnsafeConfigPath` if a path breaks a rule of
    ///   [`Config::validate_paths`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_base::config::Config;
    ///
    /// # use std::io::Write;
    /// # use tempfile::NamedTempFile;
    /// # let mut file = NamedTempFile::new().unwrap();
    /// # writeln!(file, "hidden_volume_root = \"/mnt/data\"").unwrap();
    /// let config = Config::load(file.path()).expect("Failed to load config");
    /// assert_eq!(config.state_file_path.to_str(), Some("/mnt/data/state.json"));
    /// ```
    pub fn load(path: &Path) -> Result<Self> {
        LoadedConfig::load(path).map(LoadedConfig::into_config)
    }

    /// Load configuration from file, or return defaults if the file doesn't exist
    ///
    /// Any other error (unreadable file, invalid TOML, unknown key) is still
    /// returned.
    pub fn load_or_default(path: &Path) -> Result<Self> {
        LoadedConfig::load_or_default(path).map(LoadedConfig::into_config)
    }

    /// Commented example configuration listing every key
    ///
    /// Every assignment is commented out, so the example is also a valid
    /// (empty) configuration. Printed by `nails config show --example`.
    pub fn example_config() -> String {
        render_template(
            Path::new(DEFAULT_HIDDEN_VOLUME_ROOT),
            "# Example nails configuration (nails.toml).",
        )
    }

    /// Starter configuration written by `nails init`
    ///
    /// Same content as [`Config::example_config`], with example paths under
    /// `hidden_root`. `hidden_volume_root` stays commented out so the root is
    /// derived from the binary location and survives the volume being mounted
    /// somewhere else.
    pub fn init_template(hidden_root: &Path) -> String {
        render_template(
            hidden_root,
            "# nails configuration, generated by `nails init`.",
        )
    }
}

/// Render the commented configuration template with example paths under `root`.
fn render_template(root: &Path, title: &str) -> String {
    let quote = |path: PathBuf| toml::Value::String(path.to_string_lossy().into_owned());
    let root_value = quote(root.to_path_buf());
    let state_value = quote(root.join("state.json"));
    let log_value = quote(root.join("logs"));
    let flake_value = quote(root.join("nixos#my-host"));

    format!(
        r##"{title}
#
# Every key is optional and unknown keys are rejected. Paths must be absolute,
# without `.`, `..` or symlinks. Check this file with `nails config validate`;
# show the effective values with `nails config show`. docs/configuration.md in
# the nails source describes every key and every path rule.

# Root of the hidden volume. Unset: derived from the location of the nails
# binary, which keeps working when the volume is mounted somewhere else.
# hidden_volume_root = {root_value}

# State file and log directory, inside hidden_volume_root. Unset: placed
# directly under it.
# state_file_path = {state_value}
# log_path = {log_value}

# Show OpSec reminders based on session uptime.
# show_opsec_reminders = true

# Minimum free space on the hidden volume for activation, in MB. The pre-flight
# check fails below this floor (no warn band).
# minimum_space_mb = 500

# Free space required when a hidden NixOS system is built (NixOS), in MB.
# rebuild_space_mb = 4096

# NixOS flake reference for the hidden environment; the flake must import the
# hidden module. Unset: a flake in <hidden_volume_root>/nixos; else, when
# /etc/nixos is the decoy's own flake, activation refuses; otherwise the legacy
# hidden configuration. Write and lock a hidden flake inside a hidden session,
# never on the decoy.
# nixos_flake = {flake_value}

# How the hidden session relates to the decoy account.
#   "shared-home" (default): the hidden session starts from the decoy home (the
#     root overlay's lower). The decoy's accounts, keys and app profiles are live
#     in the hidden session; `nails check` says so on a line of its own.
#   "fresh-home": the operator's home starts empty in the hidden session (an
#     opaque directory in the root upper), so the decoy home is not visible.
# (A separate fixed-UID hidden account, "separate-user", is planned for a later
#  release and is not an accepted value yet.)
# [persona]
# mode = "shared-home"

# In-session watcher over the hidden backend.
#   The hidden volume can fail mid-session (an automount is torn down when its
#   device is pulled, the device drops off the bus, or the filesystem goes
#   read-only). The watcher polls the backend every few seconds and alerts you the
#   moment it fails. It is ALERT-ONLY by default: a transient stall never tears the
#   session down on its own.
# [backend_watch]
# enabled = true           # run the watcher in the hidden session
# auto_emergency = false   # opt-in: tear the session down automatically on a
#                          # failure that outlasts the debounce window
# poll_interval_secs = 5   # seconds between probes
# debounce_secs = 15       # seconds a failure must persist before auto_emergency

# Disks mounted during the hidden session (a USB drive udisks automounts, a
# manual mount of a decoy partition). They are real disks: a read-write mount
# takes hidden writes.
#   alert: the session watcher alerts you about every read-write mount of a disk
#     outside the hidden volume (the watcher runs for this even when
#     [backend_watch] is disabled).
#   read_only: opt-in: every disk the session does not use, and every disk
#     attached during it, is read-only for the session (mounts come up read-only,
#     writes fail); the way back makes them writable again. A root user can still
#     set a disk writable on purpose.
# [session_mounts]
# alert = true
# read_only = false

# What to do about system sleep (suspend/hibernate) while the hidden environment
# is active. Suspending an active session leaves it resident in RAM behind the
# hidden session's own lock screen, so whoever unlocks it on resume is in the
# still-live session.
#   "warn" (default): pre-flight warns when the host would suspend an active
#     session (lid switch, idle auto-suspend); nothing runs at runtime.
#   "block": hold sleep and idle block inhibitors for the whole session so the
#     host cannot suspend while active, and take the lid switch from logind when
#     a closed lid would sleep (the lid then does nothing, not even lock the
#     screen); released at deactivation. A laptop kept running with the lid shut
#     can overheat.
#   "teardown": hold a sleep *delay* inhibitor and power off when the host is
#     about to sleep, within logind's InhibitDelayMaxSec.
# Also set the logind lid switch to "lock" on the decoy; see
# docs/decoy-requirements.md.
# [sleep_policy]
# mode = "warn"
"##
    )
}
