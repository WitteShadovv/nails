// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Readers of the RAM-backed runtime directory an entry writes under `/run`.
//!
//! The entry ([`crate::session::entry`]) copies the running executable, the
//! effective configuration and the session plan into a private directory with
//! a neutral name on the decoy's `/run` tmpfs, so the hidden session's own
//! units and the panic path keep working when the hidden volume fails. This
//! module reads them back: the configuration for `emergency`, `recover` and
//! the sleep guard, and the hidden root the backend watcher probes.

use std::path::PathBuf;

use crate::config::Config;
use crate::filesystem::Filesystem;
use crate::session::entry::CONFIG_COPY_NAME;
use crate::{NailsError, Result};
use nails_teardown::whole_root::plan::{BINARY_NAME, PLAN_NAME, RUNTIME_DIR};

/// The runtime directory on the decoy's `/run` tmpfs. Neutral.
pub const RUNTIME_COPY_DIR: &str = RUNTIME_DIR;

/// Path of the mirrored executable.
pub fn binary_copy_path() -> PathBuf {
    PathBuf::from(RUNTIME_DIR).join(BINARY_NAME)
}

/// Path of the mirrored configuration.
pub fn config_copy_path() -> PathBuf {
    PathBuf::from(RUNTIME_DIR).join(CONFIG_COPY_NAME)
}

/// Path of the session plan.
pub fn plan_path() -> PathBuf {
    PathBuf::from(RUNTIME_DIR).join(PLAN_NAME)
}

/// What the backend watcher needs to know when the hidden volume and its
/// `state.json` can no longer be read: the hidden root and the overlay targets,
/// read from the session plan in the runtime directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeManifest {
    /// The configured hidden volume root at activation.
    pub hidden_root: PathBuf,
    /// The overlay targets that were mounted, in activation order.
    pub overlay_targets: Vec<PathBuf>,
}

impl RuntimeManifest {
    /// The watcher's view of a session plan: the hidden root. The whole-root
    /// session has no per-target overlays to probe; the hidden volume is the
    /// one thing that can fail.
    pub fn from_plan(plan: &nails_teardown::whole_root::plan::Plan) -> Self {
        Self {
            hidden_root: plan.hidden_root.clone(),
            overlay_targets: Vec::new(),
        }
    }
}

/// Read the watcher's manifest from the session plan in the runtime copy, if
/// one is present.
///
/// `Ok(None)` when no plan exists (no activation wrote one, or it was already
/// torn down); an error only on a present-but-unusable plan.
pub fn read_manifest<F: Filesystem>(filesystem: &F) -> Result<Option<RuntimeManifest>> {
    let path = plan_path();
    if !filesystem.path_exists(&path)? {
        return Ok(None);
    }
    let content = filesystem.read_file_content(&path)?;
    let plan = nails_teardown::whole_root::plan::Plan::from_json(&content)
        .map_err(|e| NailsError::io(&path, std::io::Error::other(e.to_string())))?;
    Ok(Some(RuntimeManifest::from_plan(&plan)))
}

/// Load the mirrored configuration from the runtime copy, if one is present.
///
/// Used as a fallback by `emergency`/`recover` when the hidden volume (and so the
/// real config file) can no longer be read. `Ok(None)` when no copy exists.
pub fn read_config_copy<F: Filesystem>(filesystem: &F) -> Result<Option<Config>> {
    let path = config_copy_path();
    if !filesystem.path_exists(&path)? {
        return Ok(None);
    }
    let content = filesystem.read_file_content(&path)?;
    let config: Config = toml::from_str(&content).map_err(|e| {
        NailsError::ConfigError(format!(
            "runtime config copy at {} is unparseable: {e}",
            path.display()
        ))
    })?;
    Ok(Some(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;

    #[test]
    fn neutral_names_contain_no_product_name() {
        for name in [RUNTIME_COPY_DIR, BINARY_NAME, CONFIG_COPY_NAME, PLAN_NAME] {
            assert!(
                !name.to_ascii_lowercase().contains("nails"),
                "runtime name {name:?} must be neutral"
            );
        }
    }

    #[test]
    fn the_manifest_is_read_from_the_session_plan() {
        let fs = MockFilesystem::new();
        let config = Config::test_default();
        let side = nails_teardown::whole_root::plan::RootSide {
            init: PathBuf::from("/usr/lib/systemd/systemd"),
            system: None,
        };
        let plan = nails_teardown::whole_root::plan::Plan {
            version: nails_teardown::whole_root::plan::PLAN_VERSION,
            hidden_root: config.hidden_volume_root.clone(),
            upper: config.hidden_volume_root.join("root/upper"),
            work: config.hidden_volume_root.join("root/work"),
            owner: None,
            decoy_root: nails_teardown::whole_root::plan::DecoyRoot {
                source: PathBuf::from("/dev/vda2"),
                fstype: "ext4".to_string(),
                data: None,
            },
            decoy: side.clone(),
            hidden: side,
            policy_mounts: Vec::new(),
            masks: Vec::new(),
            session_units: Vec::new(),
            backend: Vec::new(),
            tools: nails_teardown::whole_root::plan::Tools::default(),
            armed: None,
            entered_at: Some(1),
            run_noexec: false,
        };
        fs.mock_set_path_exists(plan_path().to_str().unwrap(), true);
        fs.mock_set_file_content(plan_path().to_str().unwrap(), &plan.to_json());

        let manifest = read_manifest(&fs).unwrap().expect("plan present");
        assert_eq!(manifest.hidden_root, config.hidden_volume_root);
        assert!(manifest.overlay_targets.is_empty());
    }

    #[test]
    fn config_copy_round_trips() {
        let fs = MockFilesystem::new();
        let config = Config::test_default();
        let path = config_copy_path();
        fs.mock_set_path_exists(path.to_str().unwrap(), true);
        fs.mock_set_file_content(path.to_str().unwrap(), &toml::to_string(&config).unwrap());

        let loaded = read_config_copy(&fs).unwrap().expect("config copy present");
        assert_eq!(loaded.hidden_volume_root, config.hidden_volume_root);
        assert_eq!(loaded.state_file_path, config.state_file_path);
    }

    #[test]
    fn read_manifest_is_none_without_a_copy() {
        let fs = MockFilesystem::new();
        assert!(read_manifest(&fs).unwrap().is_none());
        assert!(read_config_copy(&fs).unwrap().is_none());
    }
}
