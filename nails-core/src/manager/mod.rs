// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # NailsManager
//!
//! The orchestrator behind the CLI commands: it holds the configuration, the
//! state file cache, the detected host and the hidden NixOS builder, and drives
//! the whole-root session ([`session_flow`]) and the pre-flight registry
//! ([`preflight_runner`]).

use crate::{Config, Filesystem, Result};
use std::cell::RefCell;
use std::path::PathBuf;

pub mod preflight_runner;
pub mod session_flow;
pub mod state_management;

pub use preflight_runner::{PreflightOptions, RegistryInputs, build_registry};
pub use session_flow::{EnterOptions, EnterOutcome, SessionRecovery};
pub use state_management::ResetUpperPlan;

/// Central orchestrator for all NAILS operations.
///
/// Generic over the [`Filesystem`] so the state and pre-flight logic can be
/// tested without root. `cached_state` uses `RefCell` so the lazy load can
/// populate the cache through a shared reference; NAILS orchestration is
/// single-threaded.
pub struct NailsManager<F: Filesystem> {
    /// Filesystem implementation (real or mock)
    filesystem: F,
    /// Application configuration
    config: Config,
    /// Path to state file (on hidden volume)
    state_file_path: PathBuf,
    /// Cached state file (lazy loaded)
    cached_state: RefCell<Option<crate::StateFile>>,
    /// The hidden NixOS configuration to build, if any.
    nixos_builder: Option<crate::nixos::NixOSBuilder>,
    /// Host facts from the platform seam, detected once (or injected by a test).
    host_profile: Option<crate::platform::HostProfile>,
    /// A backend injected by a test, answering instead of the derived one.
    platform_override: Option<std::sync::Arc<dyn crate::platform::Platform<F> + Send + Sync>>,
    /// Verbosity level for progress output
    verbosity: crate::verbosity::Verbosity,
    /// The startup environment snapshot.
    runtime_env: crate::RuntimeEnv,
    /// The attach-gate refusals this activation's own writes accept (set from
    /// [`EnterOptions::allow_decoy_storage`]).
    allow: crate::hidden_root::Allow,
}

impl<F: Filesystem> std::fmt::Debug for NailsManager<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NailsManager")
            .field("config", &self.config)
            .field("state_file_path", &self.state_file_path)
            .field(
                "nixos_builder",
                &self.nixos_builder.as_ref().map(|_| "<NixOSBuilder>"),
            )
            .field(
                "host_profile",
                &self.host_profile.as_ref().map(|profile| profile.kind),
            )
            .field("verbosity", &self.verbosity)
            .finish()
    }
}

impl<F: Filesystem> NailsManager<F> {
    /// A manager over `filesystem` with `config`, the state file at
    /// `state_file_path`.
    pub fn new(filesystem: F, config: Config, state_file_path: PathBuf) -> Self {
        Self {
            filesystem,
            config,
            state_file_path,
            cached_state: RefCell::new(None),
            nixos_builder: None,
            host_profile: None,
            platform_override: None,
            verbosity: crate::verbosity::Verbosity::default(),
            runtime_env: (*crate::runtime_env::current()).clone(),
            allow: crate::hidden_root::Allow::Nothing,
        }
    }

    /// [`NailsManager::new`] with a hidden NixOS builder.
    pub fn with_nixos(
        filesystem: F,
        config: Config,
        state_file_path: PathBuf,
        nixos_builder: crate::nixos::NixOSBuilder,
    ) -> Self {
        let mut manager = Self::new(filesystem, config, state_file_path);
        manager.nixos_builder = Some(nixos_builder);
        manager
    }

    /// Seed the state cache (tests).
    #[cfg(any(test, feature = "test-support"))]
    pub fn seed_cached_state(&self, state: crate::StateFile) {
        *self.cached_state.borrow_mut() = Some(state);
    }

    /// Set the verbosity.
    pub fn set_verbosity(&mut self, verbosity: crate::verbosity::Verbosity) {
        self.verbosity = verbosity;
    }

    /// Detect the host and keep its profile.
    pub fn initialize_platform(&mut self) -> Result<()> {
        self.host_profile = Some(crate::platform::detect(&self.filesystem)?);
        self.platform_override = None;
        Ok(())
    }

    /// Inject a host profile.
    pub fn set_host_profile(&mut self, profile: crate::platform::HostProfile) {
        self.host_profile = Some(profile);
        self.platform_override = None;
    }

    /// Inject a fake platform (tests).
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_fake_platform(&mut self, fake: crate::platform::FakePlatform) {
        self.host_profile = Some(fake.host_profile());
        self.platform_override = Some(std::sync::Arc::new(fake));
    }

    /// Set the hidden NixOS builder.
    pub fn set_nixos_builder(&mut self, builder: crate::nixos::NixOSBuilder) {
        self.nixos_builder = Some(builder);
    }

    /// Whether a hidden NixOS configuration is configured.
    pub fn hidden_switch_configured(&self) -> bool {
        self.nixos_builder.is_some()
    }

    /// The build target this host's platform discovers.
    pub fn discover_host_target(&self, overlay_only: bool) -> Result<crate::platform::HostTarget> {
        let hidden_root = &self.config.hidden_volume_root;
        let explicit = self.config.nixos_flake.as_deref();
        match self.platform_override.as_deref() {
            Some(platform) => crate::platform::discover_with_platform(
                platform,
                &self.filesystem,
                hidden_root,
                explicit,
                overlay_only,
            ),
            None => crate::platform::discover_host_target(
                &self.filesystem,
                self.host_profile.as_ref(),
                hidden_root,
                explicit,
                overlay_only,
            ),
        }
    }

    /// The detected host profile.
    pub fn host_profile(&self) -> Option<&crate::platform::HostProfile> {
        self.host_profile.as_ref()
    }

    /// The platform backend for the detected host.
    pub fn platform(
        &self,
    ) -> Option<std::sync::Arc<dyn crate::platform::Platform<F> + Send + Sync>> {
        if let Some(platform) = self.platform_override.as_ref() {
            return Some(std::sync::Arc::clone(platform));
        }
        self.host_profile
            .as_ref()
            .map(|profile| std::sync::Arc::from(crate::platform::platform_for::<F>(profile)))
    }

    pub(crate) fn config_layer(&self) -> Option<Box<dyn crate::platform::ConfigLayer<F>>> {
        use crate::platform::Platform;
        match self.platform() {
            Some(platform) => platform.config_layer(),
            None => crate::platform::NixOsPlatform.config_layer(),
        }
    }

    /// Stage the hidden configuration through the host's config layer (NixOS
    /// only; `overlay_only` stages nothing).
    pub fn stage_hidden_config(&self, overlay_only: bool) -> Result<()> {
        if let Some(layer) = self.config_layer().filter(|_| !overlay_only) {
            layer.stage(
                &self.filesystem,
                &self.config.hidden_volume_root,
                false,
                self.allow,
            )?;
        }
        Ok(())
    }

    /// The filesystem.
    pub fn filesystem(&self) -> &F {
        &self.filesystem
    }

    /// The configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Attach the startup environment snapshot.
    #[must_use]
    pub fn with_runtime_env(mut self, runtime_env: crate::RuntimeEnv) -> Self {
        self.runtime_env = runtime_env;
        self
    }

    /// The startup environment snapshot.
    pub fn runtime_env(&self) -> &crate::RuntimeEnv {
        &self.runtime_env
    }
}

#[cfg(test)]
mod platform_wiring_tests {
    use crate::filesystem::MockFilesystem;
    use crate::platform::PlatformKind;
    use crate::{Config, NailsManager, NixOSBuilder};
    use std::path::PathBuf;

    /// A mock host with a readable os-release and systemd PID 1, so detection
    /// needs no real /etc files.
    fn fhs_host() -> MockFilesystem {
        let fs = MockFilesystem::new();
        fs.mock_add_file("/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n");
        fs.mock_add_file("/proc/1/comm", "systemd");
        fs
    }

    fn manager(fs: MockFilesystem) -> NailsManager<MockFilesystem> {
        NailsManager::new(fs, Config::default(), PathBuf::from("/tmp/state.json"))
    }

    #[test]
    fn platform_is_none_until_initialised() {
        let m = manager(fhs_host());
        assert!(m.host_profile().is_none());
        assert!(m.platform().is_none());
    }

    #[test]
    fn initialize_platform_detects_and_derives_backend() {
        let mut m = manager(fhs_host());
        m.initialize_platform().unwrap();

        assert_eq!(m.host_profile().unwrap().kind, PlatformKind::Fhs);
        let backend = m.platform().expect("platform derived from profile");
        assert_eq!(backend.kind(), PlatformKind::Fhs);
    }

    #[test]
    fn set_host_profile_injects_without_fixtures() {
        // No /etc/nixos (or any fixture): inject a NixOS profile directly.
        let fs = MockFilesystem::new();
        fs.mock_add_file("/etc/os-release", "ID=nixos\n");
        fs.mock_add_file("/proc/1/comm", "systemd");
        let profile = crate::platform::detect(&fs).unwrap();

        let mut m = manager(MockFilesystem::new());
        m.set_host_profile(profile);
        assert_eq!(m.platform().unwrap().kind(), PlatformKind::NixOs);
    }

    #[test]
    fn platform_seam_coexists_with_nixos_builder() {
        // The seam is additive: a NixOS-builder manager still assembles and the
        // host profile threads through alongside it.
        let fs = fhs_host();
        let builder = NixOSBuilder::new(PathBuf::from("/mnt/hidden/nixos"));
        let mut m = NailsManager::with_nixos(
            fs,
            Config::default(),
            PathBuf::from("/tmp/state.json"),
            builder,
        );
        m.initialize_platform().unwrap();
        assert_eq!(m.host_profile().unwrap().kind, PlatformKind::Fhs);
    }

    #[test]
    fn fake_platform_drives_profile_backend_and_discovery() {
        use crate::platform::{FakePlatform, HostTarget};
        let mut m = NailsManager::new(
            MockFilesystem::new(),
            Config::default(),
            PathBuf::from("/tmp/state.json"),
        );
        m.set_fake_platform(
            FakePlatform::nixos().with_build_target(HostTarget::Flake(PathBuf::from("/cfg"))),
        );

        assert_eq!(m.host_profile().unwrap().kind, PlatformKind::NixOs);
        assert_eq!(m.platform().unwrap().kind(), PlatformKind::NixOs);
        assert!(m.config_layer().is_some());
        assert_eq!(
            m.discover_host_target(false).unwrap(),
            HostTarget::Flake(PathBuf::from("/cfg"))
        );
        assert_eq!(
            m.discover_host_target(true).unwrap(),
            HostTarget::OverlayOnly
        );
    }

    #[test]
    fn detection_replaces_an_injected_fake() {
        use crate::platform::{FakePlatform, HostTarget};
        let mut m = NailsManager::new(fhs_host(), Config::default(), PathBuf::from("/tmp/s.json"));
        m.set_fake_platform(
            FakePlatform::nixos().with_build_target(HostTarget::Flake(PathBuf::from("/cfg"))),
        );
        m.initialize_platform().unwrap();

        assert_eq!(m.platform().unwrap().kind(), PlatformKind::Fhs);
        assert_eq!(m.discover_host_target(false).unwrap(), HostTarget::None);
    }

    #[test]
    fn set_nixos_builder_wires_a_builder_after_construction() {
        let mut m = NailsManager::new(
            MockFilesystem::new(),
            Config::default(),
            PathBuf::from("/tmp/state.json"),
        );
        assert!(!m.hidden_switch_configured());
        m.set_nixos_builder(NixOSBuilder::new_legacy(PathBuf::from(
            "/cfg/configuration.nix",
        )));
        assert!(m.hidden_switch_configured());
    }
}
