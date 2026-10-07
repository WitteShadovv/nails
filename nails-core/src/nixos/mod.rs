// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The hidden NixOS configuration.
//!
//! - [`config`]: staging the hidden configuration in the root upper's
//!   `/etc/nixos` and the hidden module, and checking the decoy's own
//!   configuration is clean;
//! - [`NixOSBuilder`]: which configuration to build (a flake attribute or a
//!   legacy `configuration.nix`). The build itself runs into the next root's
//!   store, see [`crate::session::nixos`].

use std::path::{Path, PathBuf};

pub mod config;
mod flake_ref;

pub use config::{
    NixOSConfigInfo, NixParser, RealNixParser, contains_nails_import,
    ensure_hidden_configuration_module, ensure_hidden_hardware_configuration, inject_import_block,
    parse_check_composed_config, prepare_nixos_config_overlay, stage_hidden_config_symlink,
    stage_hidden_nixos_config, verify_base_config_clean,
};

pub(crate) use flake_ref::{
    resolve_local_flake_dir, selected_nixos_configuration_fragment, split_flake_ref,
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum NixOSBuildMode {
    Flake,
    Legacy { config_path: PathBuf },
}

/// Which hidden NixOS configuration to build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NixOSBuilder {
    config_path: PathBuf,
    build_mode: NixOSBuildMode,
    flake_ref: Option<String>,
}

impl NixOSBuilder {
    /// A flake in the directory `config_path`.
    pub fn new(config_path: PathBuf) -> Self {
        Self {
            config_path,
            build_mode: NixOSBuildMode::Flake,
            flake_ref: None,
        }
    }

    /// A legacy build of `config_path` (a `configuration.nix`).
    pub fn new_legacy(config_path: PathBuf) -> Self {
        let config_dir = config_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/etc/nixos"));
        Self {
            config_path: config_dir,
            build_mode: NixOSBuildMode::Legacy { config_path },
            flake_ref: None,
        }
    }

    /// An explicit flake reference `<path>#<name>` (or without a fragment).
    pub fn new_with_flake_ref(flake_ref: String) -> Self {
        match flake_ref.find('#') {
            Some(hash) => Self {
                config_path: PathBuf::from(&flake_ref[..hash]),
                build_mode: NixOSBuildMode::Flake,
                flake_ref: Some(flake_ref),
            },
            None => Self::new(PathBuf::from(&flake_ref)),
        }
    }

    /// Whether this is a flake build.
    pub fn is_flake(&self) -> bool {
        matches!(self.build_mode, NixOSBuildMode::Flake)
    }

    /// The `configuration.nix` of a legacy (channel) build, `None` for a flake.
    pub fn legacy_config(&self) -> Option<&Path> {
        match &self.build_mode {
            NixOSBuildMode::Legacy { config_path } => Some(config_path),
            NixOSBuildMode::Flake => None,
        }
    }

    /// The flake reference passed to `nix` (or the legacy config directory).
    pub fn effective_flake_arg(&self) -> String {
        match &self.flake_ref {
            Some(flake_ref) => flake_ref.clone(),
            None => self.config_path.to_string_lossy().into_owned(),
        }
    }

    /// The flake directory, for a flake build.
    pub(crate) fn flake_dir(&self) -> Option<&Path> {
        self.is_flake().then_some(self.config_path.as_path())
    }

    /// The `nix build` installable of the hidden toplevel (flake builds).
    pub(crate) fn toplevel_installable(&self) -> crate::Result<String> {
        if !self.is_flake() {
            return Err(crate::NailsError::NixOSError(
                "an explicit toplevel build is only supported for flake configurations".into(),
            ));
        }
        let flake_arg = self.effective_flake_arg();
        let (base_ref, explicit_fragment) = split_flake_ref(&flake_arg);
        let (name, _) = selected_nixos_configuration_fragment(explicit_fragment)?;
        Ok(format!(
            "{base_ref}#nixosConfigurations.{name}.config.system.build.toplevel"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flake_builder_names_the_toplevel_installable() {
        let builder = NixOSBuilder::new_with_flake_ref("/mnt/data/nixos#hidden".into());
        assert!(builder.is_flake());
        assert_eq!(builder.flake_dir(), Some(Path::new("/mnt/data/nixos")));
        assert_eq!(
            builder.toplevel_installable().unwrap(),
            "/mnt/data/nixos#nixosConfigurations.hidden.config.system.build.toplevel"
        );
        assert_eq!(builder.legacy_config(), None);
    }

    #[test]
    fn a_legacy_builder_has_a_configuration_and_no_installable() {
        let builder = NixOSBuilder::new_legacy(PathBuf::from("/etc/nixos/configuration.nix"));
        assert!(!builder.is_flake());
        assert_eq!(
            builder.legacy_config(),
            Some(Path::new("/etc/nixos/configuration.nix"))
        );
        assert_eq!(builder.flake_dir(), None);
        assert!(builder.toplevel_installable().is_err());
        assert_eq!(builder.effective_flake_arg(), "/etc/nixos");
        let root = NixOSBuilder::new_legacy(PathBuf::from("/"));
        assert_eq!(root.effective_flake_arg(), "/etc/nixos");
    }

    #[test]
    fn a_plain_flake_directory_is_its_own_reference() {
        let builder = NixOSBuilder::new(PathBuf::from("/cfg"));
        assert_eq!(builder.effective_flake_arg(), "/cfg");
        let no_fragment = NixOSBuilder::new_with_flake_ref("/cfg".into());
        assert_eq!(no_fragment, builder);
    }
}
