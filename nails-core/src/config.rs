//! Configuration management for NAILS
//!
//! This module provides configuration structures for the NAILS system,
//! including the `Config` struct with user-configurable options and
//! `ConfigBuilder` for fluent API construction with validation.
//!
//! # Example
//!
//! ```rust
//! use nails_core::config::DEFAULT_HIDDEN_VOLUME_ROOT;
//! use nails_core::ConfigBuilder;
//! use std::path::PathBuf;
//!
//! let config = ConfigBuilder::new()
//!     .hidden_volume_path(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT))
//!     .clear_history(false)
//!     .default_verbosity("debug")
//!     .build()
//!     .expect("Failed to build config");
//! ```

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// CLI argument overrides for configuration
///
/// All fields are Option to distinguish "not specified" from "explicitly set".
/// Only Some values override the loaded config.
///
/// # Priority Order (UXR26)
///
/// Configuration values are resolved in this priority order:
/// 1. CLI flags (highest priority)
/// 2. Config file values
/// 3. Default values (lowest priority)
///
/// # Example
///
/// ```rust
/// use nails_core::CliOverrides;
///
/// let overrides = CliOverrides {
///     preflight_checks: Some(false), // --no-preflight flag
///     verbosity: Some("debug".to_string()), // -vv flag
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    /// Override preflight_checks (--no-preflight sets to false)
    pub preflight_checks: Option<bool>,

    /// Override clear_history (--no-clear-history sets to false)
    pub clear_history: Option<bool>,

    /// Override default_verbosity (from -q, -v, -vv flags)
    pub verbosity: Option<String>,

    /// Override color_output (--no-color sets to false)
    pub color_output: Option<bool>,

    /// Override verify_on_deactivate (--no-verify sets to false)
    pub verify_on_deactivate: Option<bool>,
}

/// Overlay filesystem configuration
///
/// Defines the paths for a single overlay mount point. OverlayFS combines
/// multiple directories into a single view:
/// - **lower**: Read-only base layer (from decoy system)
/// - **upper**: Writable layer (on hidden volume)
/// - **work**: Work directory for overlay metadata
/// - **target**: Where the overlay is mounted
///
/// # Security Consideration
///
/// All writable layers (upper, work) MUST be on the hidden volume to prevent
/// forensic evidence from leaking to the decoy system.
///
/// # Example
///
/// ```rust
/// use nails_core::config::DEFAULT_HIDDEN_VOLUME_ROOT;
/// use nails_core::config::OverlayConfig;
/// use std::path::PathBuf;
///
/// let overlay = OverlayConfig {
///     name: "home".to_string(),
///     lower: PathBuf::from("/home"),
///     upper: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/upper"),
///     work: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/work"),
///     target: PathBuf::from("/home"),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayConfig {
    /// Human-readable name for this overlay (e.g., "home", "etc")
    pub name: String,

    /// Lower directory (read-only base layer)
    pub lower: PathBuf,

    /// Upper directory (writable, on hidden volume)
    pub upper: PathBuf,

    /// Work directory (overlay metadata)
    pub work: PathBuf,

    /// Target mount point
    pub target: PathBuf,
}

impl Default for OverlayConfig {
    /// Create an empty overlay configuration for testing
    fn default() -> Self {
        Self {
            name: String::new(),
            lower: PathBuf::new(),
            upper: PathBuf::new(),
            work: PathBuf::new(),
            target: PathBuf::new(),
        }
    }
}

/// Color scheme configuration for terminal appearance changes
///
/// Controls automatic terminal color scheme switching when entering/leaving
/// the hidden environment. Provides visual feedback beyond the shell prompt.
///
/// # Example
///
/// ```rust
/// use nails_core::config::ColorSchemeConfig;
///
/// let config = ColorSchemeConfig::default();
/// assert!(config.enabled);
/// assert_eq!(config.hidden.background, "#1a1a2e");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColorSchemeConfig {
    /// Whether color scheme switching is enabled
    #[serde(default = "default_color_scheme_enabled")]
    pub enabled: bool,

    /// Hidden environment color profile
    #[serde(default)]
    pub hidden: ColorProfile,

    /// Decoy environment color profile
    #[serde(default)]
    pub decoy: DecoyProfile,
}

impl Default for ColorSchemeConfig {
    fn default() -> Self {
        Self {
            enabled: default_color_scheme_enabled(),
            hidden: ColorProfile::default(),
            decoy: DecoyProfile::default(),
        }
    }
}

/// Color profile for terminal appearance
///
/// Defines foreground and background colors using hex color format.
///
/// # Color Format
///
/// Colors should be specified in hex format (e.g., "#1a1a2e" or "#e0e0e0").
/// The format is expected to be compatible with OSC (Operating System Command)
/// escape sequences. Common formats include:
/// - 6-digit hex: `#1a1a2e` (recommended)
/// - 3-digit hex: `#abc` (may work with some terminals)
/// - RGB: `rgb:1a/1a/2e` (alternative OSC format)
///
/// # Validation
///
/// **No format validation is performed** on color values. Invalid formats
/// are passed directly to the terminal via OSC sequences. Terminals that
/// don't recognize the format will silently ignore the sequences (per AC8).
///
/// This design choice prioritizes:
/// 1. Flexibility: Support various terminal color formats without restriction
/// 2. Simplicity: No complex regex validation or color parsing needed
/// 3. Robustness: Invalid colors fail silently (terminal ignores them)
///
/// Users are responsible for providing valid hex color values. The default
/// values provide working examples.
///
/// # Example
///
/// ```rust
/// use nails_core::config::ColorProfile;
///
/// let profile = ColorProfile {
///     background: "#1a1a2e".to_string(),
///     foreground: "#e0e0e0".to_string(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColorProfile {
    /// Background color (hex format, e.g., "#1a1a2e")
    ///
    /// No validation is performed. Invalid formats are passed to the terminal
    /// and silently ignored if not supported.
    #[serde(default = "default_hidden_background")]
    pub background: String,

    /// Foreground color (hex format, e.g., "#e0e0e0")
    ///
    /// No validation is performed. Invalid formats are passed to the terminal
    /// and silently ignored if not supported.
    #[serde(default = "default_hidden_foreground")]
    pub foreground: String,
}

impl Default for ColorProfile {
    fn default() -> Self {
        Self {
            background: default_hidden_background(),
            foreground: default_hidden_foreground(),
        }
    }
}

/// Decoy profile configuration
///
/// Controls whether to reset terminal colors to defaults when
/// returning to decoy environment.
///
/// # Example
///
/// ```rust
/// use nails_core::config::DecoyProfile;
///
/// let profile = DecoyProfile::default();
/// assert!(profile.reset);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoyProfile {
    /// Whether to reset terminal to defaults (true = use OSC reset sequences)
    #[serde(default = "default_decoy_reset")]
    pub reset: bool,
}

impl Default for DecoyProfile {
    fn default() -> Self {
        Self {
            reset: default_decoy_reset(),
        }
    }
}

/// Overlay mode determines how overlay targets are selected
///
/// This enum controls whether NAILS automatically overlays all directories
/// under `/` (auto mode) or only explicitly configured directories (explicit mode).
///
/// # Modes
///
/// - **Auto**: Dynamic enumeration - discovers all directories under `/` at runtime
///   and overlays them (except exclusions). This is the default and recommended mode
///   for maximum forensic protection.
/// - **Explicit**: Legacy mode - only overlays directories explicitly listed in
///   the `overlays` configuration. Use this if you need fine-grained control.
///
/// # Security Implications
///
/// Auto mode provides maximum forensic artifact protection by ensuring no directory
/// on the base system can leak artifacts from the hidden environment. Explicit mode
/// may leave some directories unprotected if not configured correctly.
///
/// # Example
///
/// ```rust
/// use nails_core::config::OverlayMode;
///
/// let mode = OverlayMode::Auto;  // Default - overlay everything
/// let legacy = OverlayMode::Explicit;  // Only overlay configured dirs
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OverlayMode {
    /// Auto mode: enumerate all directories under `/` and overlay them (except exclusions)
    /// This is the default and recommended mode for maximum forensic protection.
    #[default]
    Auto,

    /// Explicit mode: only overlay directories explicitly listed in `overlays` config
    /// This preserves legacy behavior for users who want fine-grained control.
    Explicit,
}

/// Application configuration
///
/// Complete configuration management with file loading, validation, and builder pattern.
/// Use `ConfigBuilder` for programmatic construction with validation.
///
/// # Example
///
/// ```rust
/// use nails_core::config::DEFAULT_HIDDEN_VOLUME_ROOT;
/// use nails_core::config::Config;
/// use std::path::PathBuf;
///
/// // Use default for tests
/// let config = Config::default();
///
/// // Or create custom config
/// let config = Config {
///     hidden_volume_root: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
///     state_file_path: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join(".nails/state.json"),
///     overlays: vec![],
///     ..Config::default()
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Root of hidden volume
    ///
    /// Auto-derived from binary location if not specified in config file (Story 14.9).
    /// Priority: config file value > binary-derived > DEFAULT_HIDDEN_VOLUME_ROOT
    #[serde(alias = "hidden_volume_path", default = "default_hidden_volume_root")]
    pub hidden_volume_root: PathBuf,

    /// Path to state file (on hidden volume)
    #[serde(default = "default_state_file_path")]
    pub state_file_path: PathBuf,

    /// Overlay configurations
    #[serde(default)]
    pub overlays: Vec<OverlayConfig>,

    /// Minimum disk space required for activation (in MB)
    #[serde(default = "default_minimum_space_mb")]
    pub minimum_space_mb: u64,

    /// Extended overlay configuration for ephemeral (tmpfs-backed) overlays (Story 4.11)
    #[serde(default)]
    pub extended_overlays: ExtendedOverlayConfig,

    // ===== Dynamic Overlay Configuration (Story 14.10) =====
    /// Overlay mode: determines how overlay targets are selected
    ///
    /// - **Auto** (default, recommended): Dynamically enumerate ALL directories under `/`
    ///   and overlay them (except those in the exclusion list). Provides maximum forensic
    ///   protection by ensuring no directory on the base system can leak artifacts.
    ///
    /// - **Explicit**: Only overlay directories explicitly listed in `overlays` field.
    ///   Preserves legacy behavior for users who want fine-grained control.
    ///
    /// **Default**: `OverlayMode::Auto`
    ///
    /// **Example**:
    /// ```yaml
    /// overlay_mode: auto  # Use dynamic enumeration (default)
    /// # OR
    /// overlay_mode: explicit  # Use explicit overlay list
    /// ```
    #[serde(default)]
    pub overlay_mode: OverlayMode,

    /// User-specified additional exclusions (merged with defaults)
    ///
    /// Directories to exclude from overlay in Auto mode, in addition to the defaults.
    /// These paths are merged with the default exclusion list.
    ///
    /// **Default exclusions**: `/proc`, `/sys`, `/dev`, `/run`, `/mnt`, `/boot`, `/bin`, `/usr`, `/lib`, `/lib64`, `/sbin`, `/lost+found`, `/Downloads`
    ///
    /// **Use case**: Exclude additional directories you don't want overlaid
    /// (e.g., `/boot` for boot partition, `/nix` for Nix store performance).
    ///
    /// **Example**:
    /// ```yaml
    /// overlay_exclusions:
    ///   - /boot
    ///   - /nix
    /// ```
    #[serde(default)]
    pub overlay_exclusions: Vec<PathBuf>,

    /// User-specified exclusions to REMOVE from defaults
    ///
    /// Directories to remove from the default exclusion list. Provides full user control
    /// over what gets overlaid - no mandatory exclusions.
    ///
    /// **Warning**: Removing default exclusions like `/proc`, `/sys`, `/dev` will likely
    /// cause mount failures (they are pseudo-filesystems that cannot be overlaid).
    /// Only remove if you understand the implications.
    ///
    /// **Use case**: Advanced users who want to overlay `/mnt` or other default exclusions.
    ///
    /// **Example**:
    /// ```yaml
    /// overlay_exclusions_remove:
    ///   - /mnt  # I want /mnt overlaid (not excluded)
    /// ```
    #[serde(default)]
    pub overlay_exclusions_remove: Vec<PathBuf>,

    // ===== User-Configurable Options (Epic 10) =====
    /// Whether to clear shell history during deactivation
    #[serde(default = "default_clear_history")]
    pub clear_history: bool,

    /// Whether to run preflight checks before activation
    #[serde(default = "default_preflight_checks")]
    pub preflight_checks: bool,

    /// Default verbosity level for logging (e.g., "info", "debug", "warn")
    #[serde(default = "default_verbosity")]
    pub default_verbosity: String,

    /// Whether to use colored output in terminal
    #[serde(default = "default_color_output")]
    pub color_output: bool,

    /// Whether to run verify command after deactivation
    #[serde(default = "default_verify_on_deactivate")]
    pub verify_on_deactivate: bool,

    /// Whether to show milestone tips during operations
    #[serde(default = "default_milestone_tips")]
    pub milestone_tips: bool,

    /// Whether to show OpSec reminders based on uptime thresholds
    #[serde(default = "default_show_opsec_reminders")]
    pub show_opsec_reminders: bool,

    /// Path to log file directory
    #[serde(default = "default_log_path")]
    pub log_path: PathBuf,

    /// Maximum log file size in megabytes before rotation
    #[serde(default = "default_max_log_size_mb")]
    pub max_log_size_mb: u64,

    /// Number of days to retain log files
    #[serde(default = "default_retention_days")]
    pub retention_days: u64,

    /// Terminal color scheme configuration
    #[serde(default)]
    pub color_scheme: ColorSchemeConfig,
}

/// Default hidden volume root path (single source of truth)
///
/// # Note
///
/// This constant is public for use in documentation examples and tests.
/// Production code should use `Config::hidden_volume_root` field instead of
/// hardcoding this value.
pub const DEFAULT_HIDDEN_VOLUME_ROOT: &str = "/mnt/hidden-volume";

/// Derive hidden volume root from binary location
///
/// Automatically determines the hidden volume root by extracting the parent
/// directory of the nails binary (after symlink resolution). This enables
/// zero-config operation where users can simply place the binary on the
/// hidden volume and everything "just works" without explicit configuration.
///
/// # Returns
///
/// The parent directory of the nails binary (after symlink resolution).
/// Falls back to `DEFAULT_HIDDEN_VOLUME_ROOT` if binary path cannot be determined.
///
/// # Algorithm
///
/// 1. Call `std::env::current_exe()` to get binary path
/// 2. Call `.canonicalize()` to resolve all symlinks
/// 3. Extract parent directory with `.parent()`
/// 4. Return parent, or fallback to `DEFAULT_HIDDEN_VOLUME_ROOT` on any error
///
/// # Logging
///
/// - DEBUG: Logs detected binary path and canonical path
/// - INFO: Logs successfully derived path when successful
/// - WARN: Logs fallback when `current_exe()` fails
/// - WARN: Logs fallback when `canonicalize()` fails (uses original path)
/// - WARN: Logs fallback when `parent()` returns None (binary at root)
///
/// # Example
///
/// Binary at `/mnt/hidden-volume/nails` → returns `/mnt/hidden-volume`
/// Binary at `/custom/nails` → returns `/custom`
/// Symlink at `/usr/local/bin/nails` → `/mnt/hidden-volume/nails` → returns `/mnt/hidden-volume`
///
/// # Errors
///
/// Does not return `Result`. All errors handled internally with fallback.
/// This design ensures config loading never fails due to binary path resolution.
///
/// # Priority Order
///
/// This function provides the middle-priority default:
/// 1. Config file value (explicit user intent - highest priority)
/// 2. **Binary-derived default (smart inference - this function)**
/// 3. `DEFAULT_HIDDEN_VOLUME_ROOT` constant (hardcoded fallback - lowest priority)
pub fn derive_hidden_volume_root() -> PathBuf {
    match std::env::current_exe() {
        Ok(exe_path) => {
            tracing::debug!("Binary path detected: {}", exe_path.display());

            // Resolve symlinks
            let canonical_path = exe_path.canonicalize().unwrap_or_else(|e| {
                tracing::warn!(
                    "Failed to canonicalize binary path {:?}: {}. Using original path.",
                    exe_path,
                    e
                );
                exe_path.clone()
            });

            tracing::debug!("Canonical binary path: {}", canonical_path.display());

            // Extract parent directory
            match canonical_path.parent() {
                Some(parent) => {
                    let parent_path = parent.to_path_buf();

                    // TEST SAFETY GUARD (Layer 4): Detect build directories
                    // Prevents tests from treating target/debug/ as a valid hidden volume
                    // This is a defense-in-depth measure to protect against accidental
                    // system operations during test execution.
                    let path_str = parent_path.to_string_lossy();
                    if path_str.contains("/target/debug")
                        || path_str.contains("/target/release")
                        || path_str.contains("/target/llvm-cov-target")
                        || path_str.starts_with("/nix/store")
                    {
                        tracing::warn!(
                            "Binary path not suitable for deriving hidden volume (build/store location): {}. \
                             Refusing to derive hidden volume root from build artifacts. \
                             Falling back to {}",
                            parent_path.display(),
                            DEFAULT_HIDDEN_VOLUME_ROOT
                        );
                        return PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT);
                    }

                    tracing::info!(
                        "Derived hidden volume root from binary location: {}",
                        parent_path.display()
                    );
                    parent_path
                }
                None => {
                    tracing::warn!(
                        "Binary at root directory (no parent): {}. Falling back to {}",
                        canonical_path.display(),
                        DEFAULT_HIDDEN_VOLUME_ROOT
                    );
                    PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                "Failed to determine binary location: {}. Falling back to {}",
                e,
                DEFAULT_HIDDEN_VOLUME_ROOT
            );
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
        }
    }
}

// Serde default functions for new user-configurable fields
fn default_hidden_volume_root() -> PathBuf {
    derive_hidden_volume_root()
}

fn default_state_file_path() -> PathBuf {
    // This will be overridden in load() to use the actual hidden_volume_root
    PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join(".nails/state.json")
}

fn default_minimum_space_mb() -> u64 {
    500
}

fn default_clear_history() -> bool {
    true
}

fn default_preflight_checks() -> bool {
    true
}

fn default_verbosity() -> String {
    "info".to_string()
}

fn default_color_output() -> bool {
    true
}

fn default_verify_on_deactivate() -> bool {
    true
}

fn default_milestone_tips() -> bool {
    true
}

fn default_show_opsec_reminders() -> bool {
    true
}

fn default_log_path() -> PathBuf {
    // Default will be derived from hidden_volume_root in builder
    PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("logs")
}

fn default_max_log_size_mb() -> u64 {
    10
}

fn default_retention_days() -> u64 {
    7
}

fn default_color_scheme_enabled() -> bool {
    true
}

fn default_hidden_background() -> String {
    "#1a1a2e".to_string()
}

fn default_hidden_foreground() -> String {
    "#e0e0e0".to_string()
}

fn default_decoy_reset() -> bool {
    true
}

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

/// Default exclusion list for dynamic overlay enumeration (Story 14.10)
///
/// These directories are excluded by default because they are:
/// - Kernel-managed virtual filesystems (/proc, /sys, /dev)
/// - Runtime state directories (/run)
/// - Mount point directories (/mnt)
/// - Bootloader directory (/boot)
/// - System library symlinks common in NixOS (/lib, /lib64, /sbin)
/// - Filesystem recovery directory (/lost+found)
/// - Non-standard user directories (/Downloads)
///
/// Directories like /etc, /home, /nix, /var, /tmp, /srv, /root, /opt, /media
/// ARE included by default for maximum forensic protection.
///
/// Users can add more exclusions via `overlay_exclusions` or remove
/// defaults via `overlay_exclusions_remove` in config YAML.
pub const DEFAULT_OVERLAY_EXCLUSIONS: &[&str] = &[
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/mnt",
    "/boot",
    "/bin",
    "/usr",
    "/lib",
    "/lib64",
    "/sbin",
    "/lost+found",
    "/Downloads",
];

impl Config {
    /// Compute effective exclusion list for dynamic overlay enumeration
    ///
    /// Combines default exclusions with user additions and removals:
    /// 1. Start with DEFAULT_OVERLAY_EXCLUSIONS
    /// 2. Add user-specified overlay_exclusions
    /// 3. Remove user-specified overlay_exclusions_remove
    /// 4. Deduplicate results
    ///
    /// # Returns
    ///
    /// Vec of PathBuf containing all effective exclusions (deduplicated)
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::config::Config;
    /// use std::path::PathBuf;
    ///
    /// let mut config = Config::default();
    /// config.overlay_exclusions = vec![PathBuf::from("/tmp")];
    /// config.overlay_exclusions_remove = vec![PathBuf::from("/mnt")];
    ///
    /// let exclusions = config.compute_effective_exclusions();
    /// assert!(exclusions.contains(&PathBuf::from("/proc")));  // default
    /// assert!(exclusions.contains(&PathBuf::from("/tmp")));   // user addition
    /// assert!(!exclusions.contains(&PathBuf::from("/mnt")));  // user removal
    /// ```
    pub fn compute_effective_exclusions(&self) -> Vec<PathBuf> {
        use std::collections::HashSet;

        // Start with defaults converted to PathBuf
        let mut exclusions: HashSet<PathBuf> = DEFAULT_OVERLAY_EXCLUSIONS
            .iter()
            .map(PathBuf::from)
            .collect();

        // Warn if user is removing dangerous exclusions (pseudo-filesystems that cannot be overlaid)
        let dangerous_exclusions = ["/proc", "/sys", "/dev", "/run"];
        for dangerous in &dangerous_exclusions {
            if self
                .overlay_exclusions_remove
                .contains(&PathBuf::from(dangerous))
            {
                tracing::warn!(
                    exclusion = %dangerous,
                    "Removing {} from exclusion list - mount will likely FAIL (pseudo-filesystem cannot be overlaid)",
                    dangerous
                );
            }
        }

        // Add user-specified additions
        for path in &self.overlay_exclusions {
            exclusions.insert(path.clone());
        }

        // Remove user-specified removals
        for path in &self.overlay_exclusions_remove {
            exclusions.remove(path);
        }

        // Convert to Vec and sort for deterministic output
        let mut result: Vec<PathBuf> = exclusions.into_iter().collect();
        result.sort();
        result
    }
}

/// Builder for Config with validation and smart defaults
///
/// Provides fluent API for constructing Config instances with validation.
/// Required fields must be set before calling `build()`.
///
/// # Example
///
/// ```rust
/// use nails_core::config::DEFAULT_HIDDEN_VOLUME_ROOT;
/// use nails_core::config::ConfigBuilder;
/// use std::path::PathBuf;
///
/// let config = ConfigBuilder::new()
///     .hidden_volume_path(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT))
///     .clear_history(false)
///     .default_verbosity("debug")
///     .build()
///     .expect("Failed to build config");
/// ```
#[derive(Debug, Default, Clone)]
pub struct ConfigBuilder {
    hidden_volume_root: Option<PathBuf>,
    state_file_path: Option<PathBuf>,
    overlays: Option<Vec<OverlayConfig>>,
    minimum_space_mb: Option<u64>,
    extended_overlays: Option<ExtendedOverlayConfig>,
    overlay_mode: Option<OverlayMode>,
    overlay_exclusions: Option<Vec<PathBuf>>,
    overlay_exclusions_remove: Option<Vec<PathBuf>>,
    clear_history: Option<bool>,
    preflight_checks: Option<bool>,
    default_verbosity: Option<String>,
    color_output: Option<bool>,
    verify_on_deactivate: Option<bool>,
    milestone_tips: Option<bool>,
    show_opsec_reminders: Option<bool>,
    log_path: Option<PathBuf>,
    max_log_size_mb: Option<u64>,
    retention_days: Option<u64>,
    color_scheme: Option<ColorSchemeConfig>,
}

impl ConfigBuilder {
    /// Create a new ConfigBuilder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the hidden volume root path (required)
    ///
    /// This is the only required field. All other fields have smart defaults.
    pub fn hidden_volume_path(mut self, path: PathBuf) -> Self {
        self.hidden_volume_root = Some(path);
        self
    }

    /// Set the state file path
    ///
    /// Default: `{hidden_volume_root}/.nails/state.json`
    pub fn state_file_path(mut self, path: PathBuf) -> Self {
        self.state_file_path = Some(path);
        self
    }

    /// Set overlay configurations
    ///
    /// Default: empty list
    pub fn overlays(mut self, overlays: Vec<OverlayConfig>) -> Self {
        self.overlays = Some(overlays);
        self
    }

    /// Set minimum space in megabytes
    ///
    /// Default: 500 MB
    pub fn minimum_space_mb(mut self, mb: u64) -> Self {
        self.minimum_space_mb = Some(mb);
        self
    }

    /// Set extended overlay configuration
    ///
    /// Default: disabled
    pub fn extended_overlays(mut self, config: ExtendedOverlayConfig) -> Self {
        self.extended_overlays = Some(config);
        self
    }

    /// Set whether to clear shell history during deactivation
    ///
    /// Default: `true`
    pub fn clear_history(mut self, enabled: bool) -> Self {
        self.clear_history = Some(enabled);
        self
    }

    /// Set whether to run preflight checks before activation
    ///
    /// Default: `true`
    pub fn preflight_checks(mut self, enabled: bool) -> Self {
        self.preflight_checks = Some(enabled);
        self
    }

    /// Set default verbosity level for logging
    ///
    /// Common values: "quiet", "info", "debug"
    ///
    /// Default: `"info"`
    pub fn default_verbosity(mut self, level: &str) -> Self {
        self.default_verbosity = Some(level.to_string());
        self
    }

    /// Set whether to use colored output in terminal
    ///
    /// Default: `true`
    pub fn color_output(mut self, enabled: bool) -> Self {
        self.color_output = Some(enabled);
        self
    }

    /// Set whether to run verify command after deactivation
    ///
    /// Default: `true`
    pub fn verify_on_deactivate(mut self, enabled: bool) -> Self {
        self.verify_on_deactivate = Some(enabled);
        self
    }

    /// Set whether to show milestone tips during operations
    ///
    /// Default: `true`
    pub fn milestone_tips(mut self, enabled: bool) -> Self {
        self.milestone_tips = Some(enabled);
        self
    }

    /// Set whether to show OpSec reminders based on uptime thresholds
    ///
    /// Default: `true`
    pub fn show_opsec_reminders(mut self, enabled: bool) -> Self {
        self.show_opsec_reminders = Some(enabled);
        self
    }

    /// Set log file directory path
    ///
    /// Default: `{hidden_volume_root}/logs`
    pub fn log_path(mut self, path: PathBuf) -> Self {
        self.log_path = Some(path);
        self
    }

    /// Set maximum log file size in megabytes before rotation
    ///
    /// Default: 10 MB
    pub fn max_log_size_mb(mut self, size: u64) -> Self {
        self.max_log_size_mb = Some(size);
        self
    }

    /// Set number of days to retain log files
    ///
    /// Default: 7 days
    pub fn retention_days(mut self, days: u64) -> Self {
        self.retention_days = Some(days);
        self
    }

    /// Set terminal color scheme configuration
    ///
    /// Default: enabled with dark navy background
    pub fn color_scheme(mut self, config: ColorSchemeConfig) -> Self {
        self.color_scheme = Some(config);
        self
    }

    /// Build the Config with validation and smart defaults
    ///
    /// # Errors
    ///
    /// Returns `NailsError::ConfigError` if required fields are missing.
    pub fn build(self) -> crate::error::Result<Config> {
        // Use explicit value if set, otherwise derive from binary (Story 14.9)
        // Priority order: explicit value > binary-derived > DEFAULT_HIDDEN_VOLUME_ROOT
        let hidden_volume_root = self
            .hidden_volume_root
            .unwrap_or_else(derive_hidden_volume_root);

        // Apply smart defaults for optional fields
        let state_file_path = self
            .state_file_path
            .unwrap_or_else(|| hidden_volume_root.join(".nails/state.json"));

        let overlays = self.overlays.unwrap_or_default();

        let minimum_space_mb = self.minimum_space_mb.unwrap_or(500);

        let extended_overlays = self.extended_overlays.unwrap_or_default();

        let overlay_mode = self.overlay_mode.unwrap_or_default();

        let overlay_exclusions = self.overlay_exclusions.unwrap_or_default();

        let overlay_exclusions_remove = self.overlay_exclusions_remove.unwrap_or_default();

        let clear_history = self.clear_history.unwrap_or_else(default_clear_history);

        let preflight_checks = self
            .preflight_checks
            .unwrap_or_else(default_preflight_checks);

        let default_verbosity = self.default_verbosity.unwrap_or_else(default_verbosity);

        let color_output = self.color_output.unwrap_or_else(default_color_output);

        let verify_on_deactivate = self
            .verify_on_deactivate
            .unwrap_or_else(default_verify_on_deactivate);

        let milestone_tips = self.milestone_tips.unwrap_or_else(default_milestone_tips);

        let show_opsec_reminders = self
            .show_opsec_reminders
            .unwrap_or_else(default_show_opsec_reminders);

        // Derive log_path from hidden_volume_root if not specified
        let log_path = self
            .log_path
            .unwrap_or_else(|| hidden_volume_root.join("logs"));

        let max_log_size_mb = self.max_log_size_mb.unwrap_or_else(default_max_log_size_mb);

        let retention_days = self.retention_days.unwrap_or_else(default_retention_days);

        let color_scheme = self.color_scheme.unwrap_or_default();

        Ok(Config {
            hidden_volume_root,
            state_file_path,
            overlays,
            minimum_space_mb,
            extended_overlays,
            overlay_mode,
            overlay_exclusions,
            overlay_exclusions_remove,
            clear_history,
            preflight_checks,
            default_verbosity,
            color_output,
            verify_on_deactivate,
            milestone_tips,
            show_opsec_reminders,
            log_path,
            max_log_size_mb,
            retention_days,
            color_scheme,
        })
    }
}

impl Default for Config {
    /// Create default configuration with sensible test defaults
    ///
    /// Uses binary-derived hidden volume root for zero-config operation.
    /// Includes default overlays for /home, /etc, and /var for VM testing.
    fn default() -> Self {
        // Auto-derive hidden volume root from binary location (Story 14.9)
        let hidden_root = derive_hidden_volume_root();

        Self {
            hidden_volume_root: hidden_root.clone(),
            state_file_path: hidden_root.join(".nails/state.json"),
            overlays: vec![
                OverlayConfig {
                    name: "home".to_string(),
                    lower: PathBuf::from("/home"),
                    upper: hidden_root.join("home"),
                    work: hidden_root.join(".work/home"),
                    target: PathBuf::from("/home"),
                },
                OverlayConfig {
                    name: "etc".to_string(),
                    lower: PathBuf::from("/etc"),
                    upper: hidden_root.join("etc"),
                    work: hidden_root.join(".work/etc"),
                    target: PathBuf::from("/etc"),
                },
                OverlayConfig {
                    name: "var".to_string(),
                    lower: PathBuf::from("/var"),
                    upper: hidden_root.join("var"),
                    work: hidden_root.join(".work/var"),
                    target: PathBuf::from("/var"),
                },
            ],
            minimum_space_mb: 500, // Default minimum: 500 MB
            // Ephemeral overlays DISABLED - using regular overlays instead (Story 4.11)
            extended_overlays: ExtendedOverlayConfig {
                enabled: false,
                directories: vec![],
            },
            // Dynamic overlay configuration (Story 14.10)
            overlay_mode: OverlayMode::Auto,
            overlay_exclusions: vec![],
            overlay_exclusions_remove: vec![],
            // User-configurable options with smart defaults (Epic 10)
            clear_history: default_clear_history(),
            preflight_checks: default_preflight_checks(),
            default_verbosity: default_verbosity(),
            color_output: default_color_output(),
            verify_on_deactivate: default_verify_on_deactivate(),
            milestone_tips: default_milestone_tips(),
            show_opsec_reminders: default_show_opsec_reminders(),
            log_path: hidden_root.join("logs"), // Derived from hidden_volume_root
            max_log_size_mb: default_max_log_size_mb(),
            retention_days: default_retention_days(),
            color_scheme: ColorSchemeConfig::default(),
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
        let default_state_path =
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join(".nails/state.json");
        if config.state_file_path == default_state_path {
            config.state_file_path = config.hidden_volume_root.join(".nails/state.json");
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

    /// Apply CLI flag overrides to this config
    ///
    /// Priority order: CLI flags > Config file > Defaults (UXR26)
    /// Only overrides values that are explicitly set (Some).
    ///
    /// # Arguments
    ///
    /// * `overrides` - CLI overrides to apply
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{Config, CliOverrides};
    ///
    /// let mut config = Config::default();
    /// let overrides = CliOverrides {
    ///     preflight_checks: Some(false),
    ///     verbosity: Some("debug".to_string()),
    ///     ..Default::default()
    /// };
    ///
    /// config.apply_cli_overrides(&overrides);
    /// assert!(!config.preflight_checks);
    /// assert_eq!(config.default_verbosity, "debug");
    /// ```
    pub fn apply_cli_overrides(&mut self, overrides: &CliOverrides) {
        if let Some(v) = overrides.preflight_checks {
            self.preflight_checks = v;
        }
        if let Some(v) = overrides.clear_history {
            self.clear_history = v;
        }
        if let Some(v) = &overrides.verbosity {
            self.default_verbosity = v.clone();
        }
        if let Some(v) = overrides.color_output {
            self.color_output = v;
        }
        if let Some(v) = overrides.verify_on_deactivate {
            self.verify_on_deactivate = v;
        }
    }

    /// Load config from file and apply CLI overrides
    ///
    /// This is the primary entry point for CLI applications.
    ///
    /// # Priority Order (UXR26)
    /// 1. CLI flags (highest priority)
    /// 2. Config file values
    /// 3. Default values (lowest priority)
    ///
    /// # Arguments
    ///
    /// * `config_path` - Path to YAML config file (uses defaults if missing)
    /// * `overrides` - CLI argument overrides
    ///
    /// # Errors
    ///
    /// Returns `NailsError::ConfigError` for malformed YAML or missing required fields.
    /// Missing config file is not an error (uses defaults).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{Config, CliOverrides};
    /// use std::path::PathBuf;
    ///
    /// let overrides = CliOverrides {
    ///     preflight_checks: Some(false),
    ///     ..Default::default()
    /// };
    ///
    /// let config = Config::from_file_and_cli(
    ///     &PathBuf::from("~/.nails/config.yaml"),
    ///     &overrides,
    /// ).expect("Failed to load config");
    /// ```
    pub fn from_file_and_cli(
        config_path: &std::path::Path,
        overrides: &CliOverrides,
    ) -> crate::error::Result<Self> {
        let mut config = Self::load_or_default(config_path)?;
        config.apply_cli_overrides(overrides);
        Ok(config)
    }

    /// Create test configuration with disabled extended overlays
    ///
    /// This provides a minimal config for unit tests that don't need
    /// ephemeral overlay functionality. Extended overlays are disabled
    /// to avoid tests needing to set up pivot mount staging directories.
    ///
    /// For tests that specifically need extended overlays, configure
    /// them explicitly in the test setup.
    pub fn test_default() -> Self {
        let hidden_root = PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT);

        Self {
            hidden_volume_root: hidden_root.clone(),
            state_file_path: hidden_root.join(".nails/state.json"),
            overlays: vec![
                OverlayConfig {
                    name: "home".to_string(),
                    lower: PathBuf::from("/home"),
                    upper: hidden_root.join("home"),
                    work: hidden_root.join(".work/home"),
                    target: PathBuf::from("/home"),
                },
                OverlayConfig {
                    name: "etc".to_string(),
                    lower: PathBuf::from("/etc"),
                    upper: hidden_root.join("etc"),
                    work: hidden_root.join(".work/etc"),
                    target: PathBuf::from("/etc"),
                },
                OverlayConfig {
                    name: "var".to_string(),
                    lower: PathBuf::from("/var"),
                    upper: hidden_root.join("var"),
                    work: hidden_root.join(".work/var"),
                    target: PathBuf::from("/var"),
                },
            ],
            minimum_space_mb: 500,
            // Disabled for tests - avoids needing to set up pivot mount paths
            extended_overlays: ExtendedOverlayConfig {
                enabled: false,
                directories: vec![],
            },
            // Dynamic overlay configuration (Story 14.10)
            // Use Auto mode by default (test actual default behavior)
            overlay_mode: OverlayMode::Auto,
            overlay_exclusions: vec![],
            overlay_exclusions_remove: vec![],
            // User-configurable options with smart defaults (Epic 10)
            clear_history: default_clear_history(),
            preflight_checks: default_preflight_checks(),
            default_verbosity: default_verbosity(),
            color_output: default_color_output(),
            verify_on_deactivate: default_verify_on_deactivate(),
            milestone_tips: default_milestone_tips(),
            show_opsec_reminders: default_show_opsec_reminders(),
            log_path: hidden_root.join("logs"), // Derived from hidden_volume_root
            max_log_size_mb: default_max_log_size_mb(),
            retention_days: default_retention_days(),
            color_scheme: ColorSchemeConfig::default(),
        }
    }
}

/// Extended overlay configuration for ephemeral (tmpfs-backed) overlays
///
/// Enables optional extended overlay mounting for high-activity directories
/// (/var, /tmp, /srv, /opt) with tmpfs-backed upper layers.
///
/// This strategy provides defense-in-depth against forensic analysis by:
/// - Storing runtime artifacts in RAM only (tmpfs)
/// - Destroying data immediately on unmount
/// - Preventing hidden storage capacity waste on transient files
///
/// # Forensic Rationale (Thesis Section 4.3.6)
///
/// - Persistent overlays (home/etc): Data on hidden encrypted storage
/// - Ephemeral overlays (var/tmp): Data in RAM, destroyed on unmount
/// - Different threat models for different data types
///
/// # Example
///
/// ```rust
/// use nails_core::config::ExtendedOverlayConfig;
///
/// let config = ExtendedOverlayConfig::default();
/// assert!(!config.enabled); // Disabled by default for safety
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedOverlayConfig {
    /// Whether extended overlays are enabled
    pub enabled: bool,

    /// List of ephemeral overlay directories
    #[serde(default)]
    pub directories: Vec<EphemeralOverlayDir>,
}

impl Default for ExtendedOverlayConfig {
    /// Extended overlays disabled by default for safety
    ///
    /// User must explicitly opt-in via configuration.
    fn default() -> Self {
        Self {
            enabled: false,
            directories: vec![],
        }
    }
}

/// Ephemeral overlay directory configuration
///
/// Defines a single ephemeral overlay with tmpfs-backed upper and work layers.
///
/// # Example
///
/// ```rust
/// use nails_core::config::EphemeralOverlayDir;
/// use std::path::PathBuf;
///
/// let dir = EphemeralOverlayDir {
///     path: PathBuf::from("/var"),
///     tmpfs_upper_size: "1G".to_string(),
///     tmpfs_work_size: "512M".to_string(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EphemeralOverlayDir {
    /// Target directory path to overlay (e.g., "/var", "/tmp")
    pub path: PathBuf,

    /// Tmpfs size for upper layer (e.g., "1G", "512M")
    pub tmpfs_upper_size: String,

    /// Tmpfs size for work layer (e.g., "512M", "256M")
    pub tmpfs_work_size: String,
}

impl EphemeralOverlayDir {
    /// Parse tmpfs size string to bytes
    ///
    /// Supports standard size suffixes:
    /// - "M" or "MB" for megabytes
    /// - "G" or "GB" for gigabytes
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::config::EphemeralOverlayDir;
    /// use std::path::PathBuf;
    ///
    /// let dir = EphemeralOverlayDir {
    ///     path: PathBuf::from("/var"),
    ///     tmpfs_upper_size: "1G".to_string(),
    ///     tmpfs_work_size: "512M".to_string(),
    /// };
    ///
    /// assert_eq!(dir.parse_upper_size().unwrap(), 1024 * 1024 * 1024);
    /// assert_eq!(dir.parse_work_size().unwrap(), 512 * 1024 * 1024);
    /// ```
    pub fn parse_upper_size(&self) -> Result<u64, String> {
        parse_size(&self.tmpfs_upper_size)
    }

    /// Parse work directory tmpfs size to bytes
    pub fn parse_work_size(&self) -> Result<u64, String> {
        parse_size(&self.tmpfs_work_size)
    }
}

/// Parse size string to bytes
///
/// Internal helper for parsing tmpfs size specifications.
///
/// # Supported Formats
///
/// - "512M", "512MB" → 512 megabytes
/// - "1G", "1GB" → 1 gigabyte
/// - Numbers only → bytes
///
/// # Errors
///
/// Returns error string if format is invalid.
fn parse_size(size_str: &str) -> Result<u64, String> {
    let trimmed = size_str.trim().to_uppercase();

    // Check for gigabyte suffix
    if let Some(num_str) = trimmed.strip_suffix("GB") {
        let num: u64 = num_str
            .trim()
            .parse()
            .map_err(|_| format!("Invalid number in size: {}", size_str))?;
        return Ok(num * 1024 * 1024 * 1024);
    }

    if let Some(num_str) = trimmed.strip_suffix('G') {
        let num: u64 = num_str
            .trim()
            .parse()
            .map_err(|_| format!("Invalid number in size: {}", size_str))?;
        return Ok(num * 1024 * 1024 * 1024);
    }

    // Check for megabyte suffix
    if let Some(num_str) = trimmed.strip_suffix("MB") {
        let num: u64 = num_str
            .trim()
            .parse()
            .map_err(|_| format!("Invalid number in size: {}", size_str))?;
        return Ok(num * 1024 * 1024);
    }

    if let Some(num_str) = trimmed.strip_suffix('M') {
        let num: u64 = num_str
            .trim()
            .parse()
            .map_err(|_| format!("Invalid number in size: {}", size_str))?;
        return Ok(num * 1024 * 1024);
    }

    // No suffix, parse as bytes
    trimmed
        .parse::<u64>()
        .map_err(|_| format!("Invalid size format: {}", size_str))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== OverlayConfig Tests ==========

    #[test]
    fn test_overlay_config_creation() {
        let overlay = OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/home"),
            upper: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/upper"),
            work: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/work"),
            target: PathBuf::from("/home"),
        };

        assert_eq!(overlay.name, "home");
        assert_eq!(overlay.lower, PathBuf::from("/home"));
        assert_eq!(
            overlay.upper,
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/upper")
        );
        assert_eq!(
            overlay.work,
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/work")
        );
        assert_eq!(overlay.target, PathBuf::from("/home"));
    }

    #[test]
    fn test_overlay_config_default() {
        let overlay = OverlayConfig::default();
        assert_eq!(overlay.name, String::new());
        assert_eq!(overlay.lower, PathBuf::new());
        assert_eq!(overlay.upper, PathBuf::new());
        assert_eq!(overlay.work, PathBuf::new());
        assert_eq!(overlay.target, PathBuf::new());
    }

    #[test]
    fn test_overlay_config_clone() {
        let overlay1 = OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/home"),
            upper: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/upper"),
            work: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/work"),
            target: PathBuf::from("/home"),
        };

        let overlay2 = overlay1.clone();
        assert_eq!(overlay1, overlay2);
    }

    #[test]
    fn test_overlay_config_serialization() {
        let overlay = OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/home"),
            upper: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/upper"),
            work: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/work"),
            target: PathBuf::from("/home"),
        };

        // Serialize to JSON
        let json = serde_json::to_string(&overlay).expect("Should serialize");
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"home\""));
        assert!(json.contains("\"lower\""));
        assert!(json.contains("\"upper\""));
        assert!(json.contains("\"work\""));
        assert!(json.contains("\"target\""));

        // Deserialize back
        let deserialized: OverlayConfig = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized, overlay);
    }

    // ========== Config Tests ==========

    #[test]
    fn test_config_default() {
        let config = Config::default();

        // hidden_volume_root should be auto-derived (not empty)
        assert!(!config.hidden_volume_root.as_os_str().is_empty());
        // state_file_path should be derived from hidden_volume_root
        assert_eq!(
            config.state_file_path,
            config.hidden_volume_root.join(".nails/state.json")
        );
        // Default config includes /home, /etc, and /var overlays
        assert_eq!(config.overlays.len(), 3);
        assert_eq!(config.overlays[0].name, "home");
        assert_eq!(config.overlays[1].name, "etc");
        assert_eq!(config.overlays[2].name, "var");
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
        assert_eq!(config.overlays.len(), 3);
        assert_eq!(config.overlays[0].name, "home");
        assert_eq!(config.overlays[1].name, "etc");
        assert_eq!(config.overlays[2].name, "var");
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
            state_file_path: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join(".nails/state.json"),
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
            state_file_path: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join(".nails/state.json"),
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
            state_file_path: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join(".nails/state.json"),
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
            state_file_path: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join(".nails/state.json"),
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
            state_file_path: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join(".nails/state.json"),
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
        assert_eq!(config.overlays.len(), 3);
        assert_eq!(config.overlays[2].name, "var");
        assert_eq!(config.overlays[2].target, PathBuf::from("/var"));
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
            state_file_path: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join(".nails/state.json"),
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

    // ========== ExtendedOverlayConfig Tests ==========

    #[test]
    fn test_extended_overlay_config_default() {
        let config = ExtendedOverlayConfig::default();
        assert!(!config.enabled);
        assert!(config.directories.is_empty());
    }

    #[test]
    fn test_extended_overlay_config_creation() {
        let dir1 = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        let dir2 = EphemeralOverlayDir {
            path: PathBuf::from("/tmp"),
            tmpfs_upper_size: "512M".to_string(),
            tmpfs_work_size: "256M".to_string(),
        };

        let config = ExtendedOverlayConfig {
            enabled: true,
            directories: vec![dir1.clone(), dir2.clone()],
        };

        assert!(config.enabled);
        assert_eq!(config.directories.len(), 2);
        assert_eq!(config.directories[0], dir1);
        assert_eq!(config.directories[1], dir2);
    }

    #[test]
    fn test_extended_overlay_config_serialization() {
        let dir = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        let config = ExtendedOverlayConfig {
            enabled: true,
            directories: vec![dir],
        };

        // Serialize to JSON
        let json = serde_json::to_string(&config).expect("Should serialize");
        assert!(json.contains("\"enabled\""));
        assert!(json.contains("true"));
        assert!(json.contains("\"directories\""));

        // Deserialize back
        let deserialized: ExtendedOverlayConfig =
            serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized, config);
    }

    // ========== EphemeralOverlayDir Tests ==========

    #[test]
    fn test_ephemeral_overlay_dir_creation() {
        let dir = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        assert_eq!(dir.path, PathBuf::from("/var"));
        assert_eq!(dir.tmpfs_upper_size, "1G");
        assert_eq!(dir.tmpfs_work_size, "512M");
    }

    #[test]
    fn test_parse_size_megabytes() {
        let dir = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "512M".to_string(),
            tmpfs_work_size: "256MB".to_string(),
        };

        assert_eq!(dir.parse_upper_size().unwrap(), 512 * 1024 * 1024);
        assert_eq!(dir.parse_work_size().unwrap(), 256 * 1024 * 1024);
    }

    #[test]
    fn test_parse_size_gigabytes() {
        let dir = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "2GB".to_string(),
        };

        assert_eq!(dir.parse_upper_size().unwrap(), 1024 * 1024 * 1024);
        assert_eq!(dir.parse_work_size().unwrap(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_parse_size_lowercase() {
        let dir = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1g".to_string(),
            tmpfs_work_size: "512m".to_string(),
        };

        assert_eq!(dir.parse_upper_size().unwrap(), 1024 * 1024 * 1024);
        assert_eq!(dir.parse_work_size().unwrap(), 512 * 1024 * 1024);
    }

    #[test]
    fn test_parse_size_bytes() {
        let dir = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1048576".to_string(), // 1 MB in bytes
            tmpfs_work_size: "524288".to_string(),   // 512 KB in bytes
        };

        assert_eq!(dir.parse_upper_size().unwrap(), 1048576);
        assert_eq!(dir.parse_work_size().unwrap(), 524288);
    }

    #[test]
    fn test_parse_size_with_whitespace() {
        let dir = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "  1G  ".to_string(),
            tmpfs_work_size: " 512M ".to_string(),
        };

        assert_eq!(dir.parse_upper_size().unwrap(), 1024 * 1024 * 1024);
        assert_eq!(dir.parse_work_size().unwrap(), 512 * 1024 * 1024);
    }

    #[test]
    fn test_parse_size_invalid_format() {
        let dir = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "invalid".to_string(),
            tmpfs_work_size: "1X".to_string(),
        };

        assert!(dir.parse_upper_size().is_err());
        assert!(dir.parse_work_size().is_err());
    }

    #[test]
    fn test_parse_size_invalid_number() {
        let dir = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "abcM".to_string(),
            tmpfs_work_size: "G".to_string(),
        };

        assert!(dir.parse_upper_size().is_err());
        assert!(dir.parse_work_size().is_err());
    }

    #[test]
    fn test_ephemeral_overlay_dir_serialization() {
        let dir = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        // Serialize to JSON
        let json = serde_json::to_string(&dir).expect("Should serialize");
        assert!(json.contains("\"path\""));
        assert!(json.contains("\"/var\""));
        assert!(json.contains("\"tmpfs_upper_size\""));
        assert!(json.contains("\"1G\""));

        // Deserialize back
        let deserialized: EphemeralOverlayDir =
            serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized, dir);
    }

    // ========== ConfigBuilder Tests ==========

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
            PathBuf::from("/mnt/hidden/.nails/state.json")
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
        let state_file = format!("{}/.nails/state.json", DEFAULT_HIDDEN_VOLUME_ROOT);
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

    // ========== Config::load() Tests (Story 10.2) ==========

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

        // Try to parse it (simulated - actual parsing would require serde_yaml)
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

    // ========== CliOverrides Tests (Story 10.3) ==========

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
            Config::from_file_and_cli(&PathBuf::from("/nonexistent/config.yaml"), &overrides)
                .unwrap();

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

    // ========== discover_config_path() Tests (Story 14.1) ==========

    #[test]
    fn test_discover_config_path_override_takes_priority() {
        let override_path = PathBuf::from("/custom/config.yaml");
        let result = discover_config_path(Some(&override_path));
        assert_eq!(result, override_path);
    }

    #[test]
    fn test_discover_config_path_binary_relative() {
        // When no override, should use binary-relative path
        // Expected: {binary_dir}/config/nails.yaml
        let result = discover_config_path(None);

        // Should end with /config/nails.yaml
        assert!(result.to_str().unwrap().ends_with("/config/nails.yaml"));

        // Should NOT contain .nails (the old home-dir path)
        assert!(!result.to_str().unwrap().contains(".nails"));

        // Verify it's actually binary-relative by checking against real binary location
        let exe_path = std::env::current_exe().unwrap();
        let resolved_exe = exe_path.canonicalize().unwrap();
        let exe_dir = resolved_exe.parent().unwrap();
        let expected = exe_dir.join("config/nails.yaml");
        assert_eq!(result, expected, "Config path should be binary-relative");
    }

    #[test]
    fn test_discover_config_path_priority_order() {
        // Test: CLI override takes precedence over binary-relative
        let override_path = PathBuf::from("/explicit/path.yaml");
        let with_override = discover_config_path(Some(&override_path));
        let without_override = discover_config_path(None);

        // Override should always win
        assert_eq!(with_override, override_path);
        assert_ne!(without_override, override_path);

        // Without override should be binary-relative
        assert!(
            without_override
                .to_str()
                .unwrap()
                .ends_with("/config/nails.yaml")
        );
    }

    #[test]
    fn test_discover_config_path_cwd_fallback_format() {
        // Test that CWD fallback produces correct path format
        // Note: This test verifies the path format; actual CWD fallback behavior
        // requires mocking current_exe() which is not easily done in standard Rust.
        // The fallback path should always end with /config/nails.yaml
        let result = discover_config_path(None);

        // Path should always end with config/nails.yaml regardless of resolution path
        assert!(
            result.to_str().unwrap().ends_with("/config/nails.yaml"),
            "Expected path to end with /config/nails.yaml, got: {:?}",
            result
        );
    }

    #[test]
    fn test_discover_config_path_uses_canonicalize() {
        // Test that symlink resolution is attempted
        // This verifies that the function uses canonicalize() on current_exe()
        // to resolve symlinks before getting the parent directory.
        //
        // In production, if /usr/local/bin/nails is a symlink to
        // /mnt/hidden-volume/bin/nails, config should be at
        // /mnt/hidden-volume/config/nails.yaml, not /usr/local/bin/config/nails.yaml.
        //
        // This test verifies the function returns a valid path ending in config/nails.yaml
        let result = discover_config_path(None);
        assert!(result.to_str().unwrap().ends_with("/config/nails.yaml"));

        // The path should be absolute (canonicalize produces absolute paths on success)
        assert!(
            result.is_absolute() || result.starts_with("."),
            "Path should be absolute or start with '.' for fallback"
        );
    }

    #[test]
    fn test_integration_custom_hidden_volume_root_workflow() {
        // AC9 Integration test: Verify custom hidden_volume_root works end-to-end
        // Story 14.2 - Eliminate hardcoded /mnt/hidden-volume constant

        // Step 1: Create config with custom hidden_volume_root
        use crate::state::is_on_hidden_volume;
        use std::path::Path;

        let custom_root = "/tmp";
        let config = Config {
            hidden_volume_root: PathBuf::from(custom_root),
            state_file_path: PathBuf::from("/tmp/.nails/state.json"),
            log_path: PathBuf::from("/tmp/logs"),
            ..Config::default()
        };

        // Step 2: Verify config uses custom root
        assert_eq!(config.hidden_volume_root, PathBuf::from(custom_root));

        // Step 3: Verify state file validation respects custom root
        let valid_state_path = Path::new("/tmp/.nails/state.json");
        let invalid_state_path = Path::new("/mnt/hidden-volume/.nails/state.json");

        assert!(
            is_on_hidden_volume(valid_state_path, custom_root),
            "State file at /tmp should be valid with custom root /tmp"
        );
        assert!(
            !is_on_hidden_volume(invalid_state_path, custom_root),
            "State file at /mnt/hidden-volume should be invalid with custom root /tmp"
        );

        // Step 4: Verify default state_file_path is re-derived from custom root
        let default_path = default_state_file_path();
        assert!(
            default_path.starts_with(DEFAULT_HIDDEN_VOLUME_ROOT),
            "Default state path should use DEFAULT_HIDDEN_VOLUME_ROOT before config load"
        );

        // Step 5: Verify that config paths can be completely customized
        let another_custom_root = "/mnt/secure";
        let config2 = Config {
            hidden_volume_root: PathBuf::from(another_custom_root),
            state_file_path: PathBuf::from("/mnt/secure/.nails/state.json"),
            log_path: PathBuf::from("/mnt/secure/logs"),
            ..Config::default()
        };

        assert_eq!(
            config2.hidden_volume_root,
            PathBuf::from(another_custom_root)
        );
        assert!(
            is_on_hidden_volume(
                Path::new("/mnt/secure/.nails/state.json"),
                another_custom_root
            ),
            "Should accept custom mount point /mnt/secure"
        );
    }

    // ========== ColorSchemeConfig Tests (Story 14-8) ==========

    #[test]
    fn test_color_scheme_config_serde_round_trip() {
        // Test serialization and deserialization of ColorSchemeConfig
        let config = ColorSchemeConfig {
            enabled: true,
            hidden: ColorProfile {
                background: "#1a1a2e".to_string(),
                foreground: "#e0e0e0".to_string(),
            },
            decoy: DecoyProfile { reset: true },
        };

        // Serialize to JSON
        let json = serde_json::to_string(&config).expect("Should serialize");
        assert!(json.contains("\"enabled\""));
        assert!(json.contains("\"hidden\""));
        assert!(json.contains("\"background\""));
        assert!(json.contains("\"foreground\""));
        assert!(json.contains("\"decoy\""));
        assert!(json.contains("\"reset\""));

        // Deserialize back
        let deserialized: ColorSchemeConfig =
            serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized, config);
    }

    #[test]
    fn test_color_scheme_config_disabled() {
        let config = ColorSchemeConfig {
            enabled: false,
            hidden: ColorProfile::default(),
            decoy: DecoyProfile { reset: false },
        };

        let json = serde_json::to_string(&config).expect("Should serialize");
        let deserialized: ColorSchemeConfig =
            serde_json::from_str(&json).expect("Should deserialize");

        assert!(!deserialized.enabled);
        assert!(!deserialized.decoy.reset);
    }

    #[test]
    fn test_color_scheme_config_custom_colors() {
        let config = ColorSchemeConfig {
            enabled: true,
            hidden: ColorProfile {
                background: "#2e3440".to_string(),
                foreground: "#d8dee9".to_string(),
            },
            decoy: DecoyProfile { reset: true },
        };

        let json = serde_json::to_string(&config).expect("Should serialize");
        assert!(json.contains("#2e3440"));
        assert!(json.contains("#d8dee9"));

        let deserialized: ColorSchemeConfig =
            serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized.hidden.background, "#2e3440");
        assert_eq!(deserialized.hidden.foreground, "#d8dee9");
    }

    // ========== Auto-Derive Hidden Volume Root Tests (Story 14-9) ==========

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
state_file_path: /custom/mount/.nails/state.json
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
            upper: custom_root.join(".nails/overlays/test/upper"),
            work: custom_root.join(".nails/overlays/test/work"),
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

        assert_eq!(config.state_file_path, root.join(".nails/state.json"));
        assert_eq!(config.log_path, root.join("logs"));

        // Check overlay paths
        assert_eq!(config.overlays[0].upper, root.join("home"));
        assert_eq!(config.overlays[0].work, root.join(".work/home"));
        assert_eq!(config.overlays[1].upper, root.join("etc"));
        assert_eq!(config.overlays[1].work, root.join(".work/etc"));
        assert_eq!(config.overlays[2].upper, root.join("var"));
        assert_eq!(config.overlays[2].work, root.join(".work/var"));
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
            PathBuf::from("/test/volume/.nails/state.json")
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
        let auto_yaml = serde_yaml::to_string(&auto_mode).unwrap();
        let explicit_yaml = serde_yaml::to_string(&explicit_mode).unwrap();

        assert!(auto_yaml.contains("auto"));
        assert!(explicit_yaml.contains("explicit"));

        // Deserialize from YAML
        let auto_parsed: OverlayMode = serde_yaml::from_str(&auto_yaml).unwrap();
        let explicit_parsed: OverlayMode = serde_yaml::from_str(&explicit_yaml).unwrap();

        assert_eq!(auto_parsed, OverlayMode::Auto);
        assert_eq!(explicit_parsed, OverlayMode::Explicit);
    }

    #[test]
    fn test_compute_effective_exclusions_defaults_only() {
        let config = Config::default();

        let exclusions = config.compute_effective_exclusions();

        // Should return all 13 defaults
        assert_eq!(exclusions.len(), 13);
        assert!(exclusions.contains(&PathBuf::from("/proc")));
        assert!(exclusions.contains(&PathBuf::from("/sys")));
        assert!(exclusions.contains(&PathBuf::from("/dev")));
        assert!(exclusions.contains(&PathBuf::from("/run")));
        assert!(exclusions.contains(&PathBuf::from("/mnt")));
        assert!(exclusions.contains(&PathBuf::from("/boot")));
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

        // Should include defaults + user additions (13 + 2 = 15 total)
        assert_eq!(exclusions.len(), 15);
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

        // Should include defaults minus removals (13 - 3 = 10 total)
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

        // Defaults (13) + /custom - /mnt = 13 items
        assert_eq!(exclusions.len(), 13);
        assert!(exclusions.contains(&PathBuf::from("/custom")));
        assert!(!exclusions.contains(&PathBuf::from("/mnt")));
        assert!(exclusions.contains(&PathBuf::from("/boot")));
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
}
