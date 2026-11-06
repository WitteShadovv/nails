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

use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::filesystem::Filesystem;
use crate::session::entry::CONFIG_COPY_NAME;
use crate::{NailsError, Result};
use nails_teardown::whole_root::plan::{BINARY_NAME, PLAN_NAME, RUNTIME_DIR};

/// The runtime directory on the decoy's `/run` tmpfs. Neutral. The artifact
/// registry names the same directory (`runtime-copy-dir`).
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
    /// The device of the hidden volume's mount at entry (see
    /// [`Plan::hidden_dev`](nails_teardown::whole_root::plan::Plan::hidden_dev)).
    pub hidden_dev: Option<String>,
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
            hidden_dev: plan.hidden_dev.clone(),
            overlay_targets: Vec::new(),
        }
    }
}

/// The text of the file at `path`, read at once: `None` when there is no
/// such file (nothing at the path, or a file on the way to it), an error
/// naming the path when it is there but cannot be read.
fn read_if_there<F: Filesystem>(filesystem: &F, path: &Path) -> Result<Option<String>> {
    match filesystem.read_file_content(path) {
        Ok(content) => Ok(Some(content)),
        Err(e)
            if matches!(
                e.io_kind(),
                Some(std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory)
            ) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Read the watcher's manifest from the session plan in the runtime copy, if
/// one is present.
///
/// `Ok(None)` when no plan exists (no activation wrote one, or it was already
/// torn down); an error naming the plan when it is there but cannot be read
/// or does not parse.
pub fn read_manifest<F: Filesystem>(filesystem: &F) -> Result<Option<RuntimeManifest>> {
    let path = plan_path();
    let Some(content) = read_if_there(filesystem, &path)? else {
        return Ok(None);
    };
    let plan = nails_teardown::whole_root::plan::Plan::from_json(&content)
        .map_err(|e| NailsError::io(&path, std::io::Error::other(e.to_string())))?;
    Ok(Some(RuntimeManifest::from_plan(&plan)))
}

/// Load the mirrored configuration from the runtime copy, if one is present.
///
/// Used as a fallback by `emergency`/`recover` when the hidden volume (and so the
/// real config file) can no longer be read. `Ok(None)` when no copy exists; an
/// error naming the copy when it is there but cannot be read or does not
/// parse.
pub fn read_config_copy<F: Filesystem>(filesystem: &F) -> Result<Option<Config>> {
    let path = config_copy_path();
    let Some(content) = read_if_there(filesystem, &path)? else {
        return Ok(None);
    };
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
            hidden_dev: Some("253:0".to_string()),
            accepted_decoy_storage: None,
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
            boot_masks: Vec::new(),
            generator_masks: Vec::new(),
            skips: Vec::new(),
            required_masks: Vec::new(),
            session_units: Vec::new(),
            backend: Vec::new(),
            tools: nails_teardown::whole_root::plan::Tools::default(),
            armed: None,
            entered_at: Some(1),
            run_noexec: false,
            carried: Vec::new(),
            decoy_mounts: Vec::new(),
            read_only_disks: false,
            failed_at_entry: Vec::new(),
            kernel_settings: Vec::new(),
            pids: Default::default(),
        };
        fs.mock_set_path_exists(plan_path().to_str().unwrap(), true);
        fs.mock_set_file_content(plan_path().to_str().unwrap(), &plan.to_json());

        let manifest = read_manifest(&fs).unwrap().expect("plan present");
        assert_eq!(manifest.hidden_root, config.hidden_volume_root);
        assert_eq!(manifest.hidden_dev.as_deref(), Some("253:0"));
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

    /// A copy is read at once, with no lookup before it: one that is not
    /// there is none, also where a file stands on the way to it.
    #[test]
    fn a_copy_that_is_not_there_is_none() {
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::NotADirectory,
        ] {
            let fs = MockFilesystem::new();
            fs.mock_set_lookup_error(RUNTIME_COPY_DIR, kind);
            assert!(read_manifest(&fs).unwrap().is_none(), "{kind:?}");
            assert!(read_config_copy(&fs).unwrap().is_none(), "{kind:?}");
        }
    }

    /// A copy that is there but cannot be read is an error that names it,
    /// never taken for no copy.
    #[test]
    fn a_copy_that_cannot_be_read_is_an_error_naming_it() {
        let fs = MockFilesystem::new();
        let plan = plan_path();
        let copy = config_copy_path();
        for path in [&plan, &copy] {
            fs.mock_set_file_content(path.to_str().unwrap(), "unused");
            fs.mock_set_lookup_error(path.to_str().unwrap(), std::io::ErrorKind::Other);
        }
        for error in [
            read_manifest(&fs).unwrap_err(),
            read_config_copy(&fs).unwrap_err(),
        ] {
            let NailsError::IoError { path, source } = &error else {
                panic!("not an I/O error: {error:?}");
            };
            assert!(*path == plan || *path == copy, "{error}");
            assert_eq!(source.kind(), std::io::ErrorKind::Other, "{error}");
            assert!(error.to_string().contains(&path.display().to_string()));
        }
    }

    /// A copy that does not parse is an error that names it too.
    #[test]
    fn a_copy_that_does_not_parse_is_an_error_naming_it() {
        let fs = MockFilesystem::new();
        fs.mock_set_file_content(plan_path().to_str().unwrap(), "{ not a plan");
        fs.mock_set_file_content(config_copy_path().to_str().unwrap(), "= not toml");
        let plan = read_manifest(&fs).unwrap_err().to_string();
        assert!(plan.contains(&plan_path().display().to_string()), "{plan}");
        let config = read_config_copy(&fs).unwrap_err().to_string();
        assert!(
            config.contains(&config_copy_path().display().to_string()),
            "{config}"
        );
    }
}
