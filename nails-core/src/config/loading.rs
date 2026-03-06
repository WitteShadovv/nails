//! Configuration loading and discovery

use std::path::PathBuf;

use super::defaults::derive_hidden_volume_root;
use super::types::{Config, DEFAULT_HIDDEN_VOLUME_ROOT};

/// Discover configuration file path using binary-relative resolution
///
/// Priority order (Story 14.1):
/// 1. --config CLI flag override (highest priority)
/// 2. Binary-relative path: `{binary_dir}/config/nails.yaml` (symlinks resolved)
/// 3. CWD fallback: `{current_dir}/config/nails.yaml` (if current_exe() fails)
///
/// # Symlink Handling
///
/// This function uses `canonicalize()` on the binary path to resolve symlinks.
/// For example, if `/usr/local/bin/nails` is a symlink to `/mnt/hidden-volume/bin/nails`,
/// the config will be resolved to `/mnt/hidden-volume/config/nails.yaml`.
///
/// # Fallback Behavior
///
/// If `current_exe()` fails (rare cases like proc not mounted on Linux),
/// a warning is logged via `tracing::warn!` and the current working directory
/// is used as fallback. If CWD also cannot be determined, `./config/nails.yaml` is returned.
///
/// # Arguments
///
/// * `config_override` - Optional path from `--config` CLI flag
///
/// # Returns
///
/// Resolved config path (always returns a path, never fails)
///
/// # Example
///
/// ```rust
/// use nails_core::config::discover_config_path;
/// use std::path::PathBuf;
///
/// // With CLI override
/// let path = discover_config_path(Some(&PathBuf::from("/custom/config.yaml")));
/// assert_eq!(path, PathBuf::from("/custom/config.yaml"));
///
/// // Binary-relative (most common case)
/// let path = discover_config_path(None);
/// // Returns {binary_dir}/config/nails.yaml
/// ```
pub fn discover_config_path(config_override: Option<&std::path::Path>) -> PathBuf {
    // Priority 1: Explicit --config override
    if let Some(override_path) = config_override {
        return override_path.to_path_buf();
    }

    // Priority 2: Binary-relative path (preferred)
    // Use canonicalize() to resolve symlinks before getting parent directory
    // This handles the case where /usr/local/bin/nails is a symlink to
    // /mnt/hidden-volume/bin/nails - we want config at the actual binary location
    if let Ok(exe_path) = std::env::current_exe()
        && let Ok(resolved_path) = exe_path.canonicalize()
        && let Some(exe_dir) = resolved_path.parent()
    {
        return exe_dir.join("config/nails.yaml");
    }

    // Priority 3: CWD fallback (when current_exe() or canonicalize() fails)
    tracing::warn!(
        "Failed to determine binary location for config discovery, trying current working directory"
    );

    let cwd = std::env::current_dir();
    match cwd {
        Ok(dir) => dir.join("config/nails.yaml"),
        Err(e) => {
            // Both current_exe() and current_dir() failed - this is very unusual
            // Log error and return relative path as last resort
            tracing::error!(
                "Failed to determine current directory for config discovery: {}. Using fallback ./config/nails.yaml",
                e
            );
            PathBuf::from("./config/nails.yaml")
        }
    }
}

impl Config {
    /// Load configuration from YAML file
    ///
    /// Reads and parses configuration from the specified path. Returns descriptive
    /// errors for missing files, malformed YAML, or missing required fields.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to YAML configuration file (typically `~/.nails/config.yaml`)
    ///
    /// # Errors
    ///
    /// Returns `NailsError::ConfigError` if:
    /// - File does not exist (includes example config in error)
    /// - YAML syntax is invalid (includes line number)
    /// - Required field `hidden_volume_path` is missing
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::config::Config;
    /// use std::path::PathBuf;
    ///
    /// # use std::io::Write;
    /// # use tempfile::NamedTempFile;
    /// # let mut file = NamedTempFile::new().unwrap();
    /// # writeln!(file, "hidden_volume_path: /mnt/hidden-volume").unwrap();
    /// let config = Config::load(file.path()).expect("Failed to load config");
    /// ```
    pub fn load(path: &std::path::Path) -> crate::error::Result<Self> {
        use crate::error::NailsError;

        // Read file contents with descriptive error
        let contents = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NailsError::ConfigError(format!(
                    "Config file not found: {}\n\nCreate one with:\n{}",
                    path.display(),
                    Self::example_config()
                ))
            } else {
                NailsError::ConfigError(format!("Failed to read config: {}", e))
            }
        })?;

        // Parse YAML with line number in errors
        let mut config: Config = serde_yaml::from_str(&contents).map_err(|e| {
            let line_info = if let Some(location) = e.location() {
                format!(" at line {}", location.line())
            } else {
                String::new()
            };

            NailsError::ConfigError(format!(
                "Invalid YAML{}: {}\n\nExample config:\n{}",
                line_info,
                e,
                Self::example_config()
            ))
        })?;

        // If hidden_volume_root not specified in YAML, derive from binary (Story 14.9)
        // Priority order: config file value > binary-derived > DEFAULT_HIDDEN_VOLUME_ROOT
        if config.hidden_volume_root.as_os_str().is_empty() {
            tracing::info!("Config file missing hidden_volume_root, deriving from binary location");
            config.hidden_volume_root = derive_hidden_volume_root();
        }

        // Derive state_file_path from hidden_volume_root if it's still the default
        let default_state_path = PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("state.json");
        if config.state_file_path == default_state_path {
            config.state_file_path = config.hidden_volume_root.join("state.json");
        }

        // Derive log_path from hidden_volume_root if it's still the default
        // When hidden_volume_root is auto-derived, log_path still gets the constant default
        // via serde default function. This ensures log_path matches the derived root.
        let default_log_path = PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("logs");
        if config.log_path == default_log_path {
            config.log_path = config.hidden_volume_root.join("logs");
        }

        Ok(config)
    }

    /// Returns example YAML configuration with all fields documented
    ///
    /// Provides a complete example config showing required and optional fields
    /// with their default values. Useful for error messages and documentation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::config::Config;
    ///
    /// let example = Config::example_config();
    /// println!("{}", example);
    /// ```
    pub fn example_config() -> &'static str {
        r##"# NAILS Configuration
# Required fields:
hidden_volume_path: /mnt/hidden-volume

# Optional fields (defaults shown):
clear_history: true
preflight_checks: true
default_verbosity: info  # quiet, info, debug
color_output: true
verify_on_deactivate: true
milestone_tips: true

# Logging configuration:
log_path: /mnt/hidden-volume/logs
max_log_size_mb: 10
retention_days: 7

# Terminal color scheme configuration:
color_scheme:
  enabled: true
  hidden:
    background: "#1a1a2e"
    foreground: "#e0e0e0"
  decoy:
    reset: true

# Overlay mode configuration (Story 14.10):
# overlay_mode: auto  # auto (default) or explicit
#
# Auto mode (recommended): Dynamically overlay ALL directories under /
# except those in the exclusion list. Provides maximum forensic protection.
#
# Explicit mode: Only overlay directories listed in 'overlays' section below.
# Use this for fine-grained control over what gets overlaid.

# Overlay exclusion configuration (Auto mode only):
# overlay_exclusions:
#   - /boot        # Add custom exclusions (merged with defaults)
#   - /nix
#
# overlay_exclusions_remove:
#   - /mnt         # Remove from default exclusions if needed
#
# Default exclusions: /proc, /sys, /dev, /run, /mnt
# (pseudo-filesystems that cannot/should not be overlaid)

# Overlay configuration (Explicit mode only):
# overlays:
#   - name: home
#     lower: /home
#     upper: /mnt/hidden-volume/home
#     work: /mnt/hidden-volume/.work/home
#     target: /home

# Extended overlay configuration (ephemeral tmpfs-backed overlays):
# extended_overlays:
#   enabled: false
#   directories:
#     - path: /var
#       tmpfs_upper_size: 512M
#       tmpfs_work_size: 128M

# NixOS flake reference (optional, auto-detected if not set):
# nixos_flake: /etc/nixos#amnesia-virtualbox
"##
    }

    /// Load configuration from file, or return default if file doesn't exist
    ///
    /// Convenience method that attempts to load config from file, but falls back
    /// to `Config::default()` if the file doesn't exist. Other errors (malformed
    /// YAML, missing required fields) are still returned.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to YAML configuration file
    ///
    /// # Errors
    ///
    /// Returns `NailsError::ConfigError` for parsing errors, but NOT for missing files.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::config::Config;
    /// use std::path::PathBuf;
    ///
    /// let config = Config::load_or_default(&PathBuf::from("~/.nails/config.yaml"))
    ///     .expect("Failed to load config");
    /// ```
    pub fn load_or_default(path: &std::path::Path) -> crate::error::Result<Self> {
        match Self::load(path) {
            Ok(config) => Ok(config),
            Err(crate::error::NailsError::ConfigError(msg))
                if msg.contains("Config file not found") =>
            {
                tracing::info!("No config file found at {}, using defaults", path.display());
                Ok(Self::default())
            }
            Err(e) => Err(e),
        }
    }
}
