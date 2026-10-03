//! Shared test fixtures for configuration and manager construction.
//!
//! This module is compiled for this crate's own tests and, through the
//! `test-support` feature, for downstream test code in `nails-cli` and this
//! crate's integration tests. None of it reaches the release binary.

use std::path::PathBuf;

use tempfile::TempDir;

use super::colors::ColorSchemeConfig;
use super::defaults::{default_clear_history, default_show_opsec_reminders};
use super::overlay::{OverlayConfig, OverlayMode};
use super::types::{Config, DEFAULT_HIDDEN_VOLUME_ROOT};
use crate::filesystem::{MockFilesystem, PathKind};
use crate::manager::NailsManager;
use crate::nixos::NixOSBuilder;
use crate::state::{StateFile, SystemState};

impl Config {
    /// Create a deterministic test configuration
    ///
    /// Unlike `Config::default()`, the hidden volume root is the fixed
    /// `DEFAULT_HIDDEN_VOLUME_ROOT` rather than derived from the test binary.
    pub fn test_default() -> Self {
        let hidden_root = PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT);

        Self {
            hidden_volume_root: hidden_root.clone(),
            state_file_path: hidden_root.join("state.json"),
            overlays: vec![
                OverlayConfig {
                    name: "boot".to_string(),
                    lower: PathBuf::from("/boot"),
                    upper: hidden_root.join("boot"),
                    work: hidden_root.join(".work/boot"),
                    target: PathBuf::from("/boot"),
                },
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
            rebuild_space_mb: 4096,
            // Use Auto mode by default (test actual default behavior)
            overlay_mode: OverlayMode::Auto,
            overlay_exclusions: vec![],
            overlay_exclusions_remove: vec![],
            allow_leaky_exclusions: vec![],
            clear_history: default_clear_history(),
            show_opsec_reminders: default_show_opsec_reminders(),
            log_path: hidden_root.join("logs"), // Derived from hidden_volume_root
            loaded_config_path: None,
            color_scheme: ColorSchemeConfig::default(),
            persona: super::persona::PersonaConfig::default(),
            backend_watch: super::backend_watch::BackendWatchConfig::default(),
            prompt_label: String::new(),
            nixos_flake: None,
            nixos_switch_required: true,
            risky_services: None,
            accept_persistent_decoy: false,
            sleep_policy: super::types::SleepPolicyConfig::default(),
            emergency: super::types::EmergencyConfig::default(),
        }
    }
}

/// Builder that assembles a [`MockFilesystem`], a [`Config`] and a
/// [`NailsManager`] for a test, replacing the ad-hoc `make_manager` helpers that
/// had been copied across the test suites.
///
/// Staged files, directories and symlinks are applied to the mock when
/// [`manager`](TestWorld::manager) is called. Unless a [`Config`] is supplied
/// with [`with_config`](TestWorld::with_config), the manager's hidden volume
/// root is a fresh temporary directory, so state paths resolve somewhere real
/// and unique per test.
///
/// ```ignore
/// use nails_core::TestWorld;
///
/// let (manager, _tmp) = TestWorld::new()
///     .with_dir("/etc/nixos")
///     .with_file("/etc/nixos/configuration.nix", "{ }")
///     .manager();
/// assert!(manager.config().hidden_volume_root.exists());
/// ```
pub struct TestWorld {
    fs: MockFilesystem,
    config: Option<Config>,
    root: Option<PathBuf>,
    nixos: Option<NixOSBuilder>,
    state: Option<StateFile>,
    files: Vec<(String, String)>,
    dirs: Vec<String>,
    symlinks: Vec<String>,
}

impl TestWorld {
    /// Start a new builder with an empty mock filesystem.
    pub fn new() -> Self {
        Self {
            fs: MockFilesystem::new(),
            config: None,
            root: None,
            nixos: None,
            state: None,
            files: Vec::new(),
            dirs: Vec::new(),
            symlinks: Vec::new(),
        }
    }

    /// Use a pre-built [`MockFilesystem`] instead of the empty one, for tests
    /// that configure the mock before the manager exists.
    pub fn with_filesystem(mut self, fs: MockFilesystem) -> Self {
        self.fs = fs;
        self
    }

    /// Root the default [`Config`] at a caller-owned directory instead of a
    /// fresh temporary one. Ignored when [`with_config`](TestWorld::with_config)
    /// supplies a full config.
    pub fn with_hidden_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.root = Some(root.into());
        self
    }

    /// Build the manager with a [`NixOSBuilder`] attached
    /// (`NailsManager::with_nixos`) rather than the plain constructor.
    pub fn with_nixos(mut self, builder: NixOSBuilder) -> Self {
        self.nixos = Some(builder);
        self
    }

    /// Seed the manager's cached state so a method under test sees a known
    /// state without a state file being staged on disk.
    pub fn with_state(mut self, state: StateFile) -> Self {
        self.state = Some(state);
        self
    }

    /// Seed the cached state as [`SystemState::Inactive`], the common starting
    /// point for tests that drive a single transition.
    pub fn inactive(self) -> Self {
        self.with_state(StateFile {
            state: SystemState::Inactive,
            ..StateFile::default()
        })
    }

    /// Stage a readable file with the given contents.
    pub fn with_file(mut self, path: impl Into<String>, content: impl Into<String>) -> Self {
        self.files.push((path.into(), content.into()));
        self
    }

    /// Stage a directory.
    pub fn with_dir(mut self, path: impl Into<String>) -> Self {
        self.dirs.push(path.into());
        self
    }

    /// Stage a symbolic link.
    pub fn with_symlink(mut self, path: impl Into<String>) -> Self {
        self.symlinks.push(path.into());
        self
    }

    /// Stage the decoy's base `hardware-configuration.nix`, which the NixOS
    /// preflight and build checks read.
    pub fn with_hardware_config(self, content: impl Into<String>) -> Self {
        self.with_file("/etc/nixos/hardware-configuration.nix", content)
    }

    /// Use a specific [`Config`] instead of the temp-dir-backed default.
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Borrow the mock filesystem to apply setters `TestWorld` does not wrap.
    pub fn filesystem(&self) -> &MockFilesystem {
        &self.fs
    }

    /// Build the manager, returning it together with the temporary directory
    /// that backs its hidden volume root. The caller keeps the [`TempDir`]
    /// alive for the lifetime of the test.
    pub fn manager(self) -> (NailsManager<MockFilesystem>, TempDir) {
        let tempdir = tempfile::tempdir().expect("create tempdir for TestWorld");

        let config = self.config.unwrap_or_else(|| {
            let hidden_root = self
                .root
                .clone()
                .unwrap_or_else(|| tempdir.path().to_path_buf());
            Config {
                hidden_volume_root: hidden_root.clone(),
                state_file_path: hidden_root.join("state.json"),
                log_path: hidden_root.join("logs"),
                overlays: Vec::new(),
                ..Config::test_default()
            }
        });

        for dir in &self.dirs {
            self.fs.mock_set_path_type(dir, PathKind::Dir);
        }
        for (path, content) in &self.files {
            self.fs.mock_add_file(path, content);
        }
        for link in &self.symlinks {
            self.fs.mock_set_path_type(link, PathKind::Symlink);
        }

        let state_path = config.state_file_path.clone();
        let manager = match self.nixos {
            Some(builder) => NailsManager::with_nixos(self.fs, config, state_path, builder),
            None => NailsManager::new(self.fs, config, state_path),
        };
        if let Some(state) = self.state {
            manager.seed_cached_state(state);
        }
        (manager, tempdir)
    }
}

impl Default for TestWorld {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::Filesystem;
    use std::path::Path;

    #[test]
    fn with_hidden_root_roots_the_config_at_a_caller_owned_dir() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, _tmp) = TestWorld::new().with_hidden_root(dir.path()).manager();
        assert_eq!(manager.config().hidden_volume_root, dir.path());
        assert_eq!(
            manager.config().state_file_path,
            dir.path().join("state.json")
        );
    }

    #[test]
    fn with_filesystem_keeps_a_prebuilt_mock() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/srv/staged", PathKind::Dir);
        let (manager, _tmp) = TestWorld::new().with_filesystem(fs).manager();
        assert!(
            manager
                .filesystem()
                .is_directory(Path::new("/srv/staged"))
                .unwrap()
        );
    }

    #[test]
    fn with_nixos_attaches_a_builder() {
        let builder = NixOSBuilder::new(
            PathBuf::from("/mnt/hidden/config"),
            PathBuf::from("/mnt/hidden/nails-system"),
        );
        let (manager, _tmp) = TestWorld::new().with_nixos(builder).manager();
        // The Debug output names the builder field only when one is attached.
        assert!(format!("{manager:?}").contains("nixos_builder"));
    }

    #[test]
    fn inactive_seeds_the_cached_state_without_a_state_file() {
        let (manager, tmp) = TestWorld::new().inactive().manager();
        // No state file was staged, yet the cached state reads back as Inactive.
        assert!(!tmp.path().join("state.json").exists());
        assert_eq!(manager.current_state().unwrap(), SystemState::Inactive);
    }
}
