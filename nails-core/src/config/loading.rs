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
/// use nails_core::config::discover_config_path;
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
    /// - `NailsError::ConfigError` if the file cannot be read, is not valid
    ///   TOML, contains an unknown key at any level, or has a value of the
    ///   wrong type. The message is one line and names the line and column;
    ///   for a misspelt key it suggests the closest valid key.
    /// - `NailsError::UnsafeConfigPath` if a path breaks a rule of
    ///   [`Config::validate_paths`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::config::Config;
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
    let upper_value = quote(root.join("home"));
    let work_value = quote(root.join(".work/home"));

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

# Clear shell history on deactivation.
# clear_history = true

# Show OpSec reminders based on session uptime.
# show_opsec_reminders = true

# Minimum free space on the hidden volume for activation, in MB.
# minimum_space_mb = 500

# Shell prompt indicator while the hidden environment is active. Empty shows
# nothing; any text is visible on screen and in screenshots.
# prompt_label = ""

# NixOS flake reference for the hidden environment. Unset: auto-detected.
# nixos_flake = {flake_value}

# Fail activation (rolling the overlays back and restoring the decoy session)
# when the hidden NixOS build or switch fails, instead of only warning. The
# switch runs before the session restart, so the default fails closed.
# nixos_switch_required = true

# What to do with risky services (NetworkManager, dbus, the audio server) that
# still reference a target at activation: "restart" them or "skip" (leave them
# running as reported survivors). Unset: restart when the session is killed,
# prompt on a terminal otherwise. Overridden by --risky-services.
# risky_services = "restart"

# Overlay target selection. "auto" overlays every top-level directory except
# the exclusions; "explicit" overlays only the [[overlays]] tables below.
# overlay_mode = "auto"

# Auto mode: extra exclusions, and default exclusions to overlay anyway. The
# default list and the reason for each entry are in docs/configuration.md.
# Writes under an excluded directory reach the decoy disk.
# overlay_exclusions = ["/media"]
# overlay_exclusions_remove = ["/mnt"]

# Auto mode: directories the session writes to (/home, /root, /etc, /var,
# /nix, /srv, /opt, and /tmp unless it is a tmpfs) are refused in
# overlay_exclusions unless they are listed here to accept the leak.
# allow_leaky_exclusions = []

# Explicit mode: one table per overlay. upper and work must lie inside
# hidden_volume_root, and no target may contain it.
# [[overlays]]
# name = "home"
# lower = "/home"
# upper = {upper_value}
# work = {work_value}
# target = "/home"

# How the hidden session relates to the decoy account.
#   "shared-home" (default): run in the decoy home, merged read-write through the
#     /home overlay. The decoy's accounts, keys and app profiles are live in the
#     hidden session; activation warns while this mode is in effect.
#   "fresh-home": bind-mount a clean, empty home from the hidden volume over the
#     operator's home, so the decoy home contents are not visible.
# (A separate fixed-UID hidden account, "separate-user", is planned for a later
#  release and is not an accepted value yet.)
# [persona]
# mode = "shared-home"

# Terminal colors while the hidden environment is active.
# [color_scheme]
# enabled = true
#
# [color_scheme.hidden]
# background = "#1a1a2e"
# foreground = "#e0e0e0"
#
# [color_scheme.decoy]
# reset = true
"##
    )
}
