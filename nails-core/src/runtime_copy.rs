// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A RAM-backed copy of the tool, its config and a mount manifest under `/run`.
//!
//! The executable and the configuration both live on the hidden volume, so once
//! that volume fails or is pulled the panic button may no longer be runnable and
//! the configuration that records where the overlays are can no longer be read —
//! exactly when they are needed most. At activation NAILS therefore mirrors three
//! things into a private directory on the decoy's tmpfs-backed `/run`:
//!
//! - the running executable, so `emergency` can still be launched by full path
//!   when the hidden root is gone;
//! - the effective configuration, so teardown knows the hidden root and state
//!   file without re-reading them from the failed volume;
//! - the teardown plan ([`nails_teardown::plan`]), written there by activation
//!   step by step, which records what was mounted and how to undo it, and from
//!   which the watcher reads the hidden root and the targets it probes.
//!
//! The directory and every file in it carry a **neutral, non-product name**: a
//! forensic examiner enumerating `/run` must not find the tool's name, and the
//! in-session watcher ([`crate::watcher`]) that runs from this copy is registered
//! with systemd under the same neutral name. The whole directory is `0700` and is
//! removed on both deactivation and emergency teardown; a leftover is a teardown
//! failure, the same contract as the per-activation runtime scaffolding root.

use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::filesystem::Filesystem;
use crate::{NailsError, Result};

/// Neutral runtime-copy directory on the decoy's `/run` tmpfs.
///
/// The name reveals nothing about the tool: `/run` is full of short runtime
/// state directories, and overlay-backed runtimes (containers, snaps) are
/// commonplace, so this reads as ordinary system state rather than a tell. It is
/// deliberately *not* the per-activation runtime scaffolding root (see
/// [`crate::runtime_root`]): that root holds the pivot staging and store bind and
/// is torn down with the overlays, whereas this copy and the watcher outlive the
/// unmount, so they live at their own neutral path and both leave no product name
/// anywhere under `/run`.
pub const RUNTIME_COPY_DIR: &str = "/run/overlay-runtime";

/// File name of the mirrored executable inside [`RUNTIME_COPY_DIR`]. Neutral.
pub const BINARY_NAME: &str = "control";

/// File name of the mirrored configuration inside [`RUNTIME_COPY_DIR`]. Neutral.
pub const CONFIG_NAME: &str = "settings.toml";

/// File name of the teardown plan inside [`RUNTIME_COPY_DIR`]. Neutral.
pub const PLAN_NAME: &str = nails_teardown::plan::PLAN_NAME;

/// Transient systemd unit name for the in-session watcher started from this copy.
///
/// Passed to `systemd-run --unit`, so it appears in `systemctl` listings and in
/// the journal: it must contain no product name for the same reason the directory
/// must not.
pub const WATCH_UNIT_NAME: &str = "overlay-runtime-monitor";

/// Private mode for the runtime-copy directory and the mirrored executable.
const PRIVATE_MODE: u32 = 0o700;

/// The runtime-copy directory as a path.
pub fn runtime_copy_dir() -> PathBuf {
    PathBuf::from(RUNTIME_COPY_DIR)
}

/// Path of the mirrored executable.
pub fn binary_copy_path() -> PathBuf {
    runtime_copy_dir().join(BINARY_NAME)
}

/// Path of the mirrored configuration.
pub fn config_copy_path() -> PathBuf {
    runtime_copy_dir().join(CONFIG_NAME)
}

/// Path of the teardown plan.
pub fn plan_path() -> PathBuf {
    runtime_copy_dir().join(PLAN_NAME)
}

/// What the backend watcher needs to know when the hidden volume and its
/// `state.json` can no longer be read: the hidden root and the overlay targets,
/// read from the teardown plan activation keeps in the runtime copy.
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

/// Write the runtime copy: the executable and the effective config, into the
/// private (`0700`) directory under `/run` that already holds this activation's
/// teardown plan.
///
/// `binary_src` is the path of the running executable (the caller passes
/// [`std::env::current_exe`]).
/// A binary or config left by a crashed prior session is replaced, so it
/// cannot shadow the current one; the plan the running activation wrote is kept.
pub fn write_runtime_copy<F: Filesystem>(
    filesystem: &F,
    config: &Config,
    binary_src: &Path,
) -> Result<()> {
    let dir = runtime_copy_dir();

    if filesystem.path_exists(&dir)? {
        for stale in [binary_copy_path(), config_copy_path()] {
            if filesystem.path_exists(&stale)? {
                filesystem.remove_file(&stale)?;
            }
        }
    } else {
        filesystem.create_directory(&dir)?;
    }
    filesystem.set_permissions(&dir, PRIVATE_MODE)?;

    // The executable: raw bytes, then locked to 0700 so only root can read or run
    // the mirrored binary.
    let binary_dst = binary_copy_path();
    filesystem.copy_file(binary_src, &binary_dst)?;
    filesystem.set_permissions(&binary_dst, PRIVATE_MODE)?;

    // The effective configuration, as strict TOML, so teardown resolves the
    // hidden root and state file without touching the failed volume.
    let config_toml = toml::to_string(config).map_err(|e| {
        NailsError::ConfigError(format!(
            "failed to serialize config for the runtime copy: {e}"
        ))
    })?;
    filesystem.write_file_content(&config_copy_path(), &config_toml)?;

    tracing::info!(
        dir = %dir.display(),
        "Wrote the RAM-backed runtime copy (binary, config) next to the teardown plan"
    );
    Ok(())
}

/// Remove the runtime copy directory and everything in it.
///
/// Best-effort by contract at the call sites (teardown must continue even if this
/// fails), but the error is returned so a caller can log it. A directory that is
/// already gone is a success.
pub fn remove_runtime_copy<F: Filesystem>(filesystem: &F) -> Result<()> {
    let dir = runtime_copy_dir();
    if filesystem.path_exists(&dir)? {
        filesystem.remove_dir_all(&dir)?;
        tracing::info!(dir = %dir.display(), "Removed the RAM-backed runtime copy");
    }
    Ok(())
}

/// Read the watcher's manifest from the teardown plan in the runtime copy, if
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

/// Start the in-session backend watcher as a transient systemd unit.
///
/// The watcher is launched from the mirrored executable and registered under the
/// neutral [`WATCH_UNIT_NAME`], with `--collect` so systemd reaps the unit once
/// it exits. Best-effort: a failure to start only means the session runs without
/// the extra safety net, never that activation fails. Callers must gate this on a
/// non-test runtime; it performs a real host operation.
pub fn start_watch_unit() {
    use crate::process::{ProcessCommand, ProcessRunner, RealProcessRunner};

    let binary = binary_copy_path();
    let command = ProcessCommand::tool("systemd-run")
        .arg("--unit")
        .arg(WATCH_UNIT_NAME)
        .arg("--collect")
        .arg("--quiet")
        // A crash of the watcher must not dump core onto the decoy.
        .arg("--property=LimitCORE=0")
        .arg(&binary)
        .arg("watch")
        // A wedged PID 1 must not hold activation up; the watcher is optional.
        .deadline(crate::process::run::SYSTEMCTL_ACTION_BUDGET);

    match RealProcessRunner.run(&command) {
        Ok(output) if output.status.success() => {
            tracing::info!(
                unit = WATCH_UNIT_NAME,
                "Started the in-session backend watcher"
            );
        }
        Ok(output) => {
            // systemd-run's own message is the diagnosis (a refused executable,
            // an unreachable PID 1), so it is carried into the warning.
            tracing::warn!(
                unit = WATCH_UNIT_NAME,
                status = %output.status,
                stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                "Could not start the in-session backend watcher; the session runs without it"
            );
        }
        Err(e) => {
            tracing::warn!(
                unit = WATCH_UNIT_NAME,
                error = %e,
                "Could not start the in-session backend watcher; the session runs without it"
            );
        }
    }
}

/// Stop the in-session backend watcher's transient unit, best-effort.
///
/// Called by deactivation and emergency teardown. A watcher that was never
/// started (disabled, or failed to start) makes `systemctl stop` a harmless
/// no-op. Callers must gate this on a non-test runtime; it performs a real host
/// operation.
pub fn stop_watch_unit() {
    use crate::process::{ProcessCommand, ProcessRunner, RealProcessRunner};

    let own_unit = crate::process::cgroup_unit::own_service_unit();
    if !crate::process::cgroup_unit::may_stop_unit(own_unit.as_deref(), WATCH_UNIT_NAME) {
        // The teardown runs inside this very unit (the watcher's auto-emergency):
        // stopping it would SIGTERM the teardown. The unit ends on its own when
        // the process returns.
        tracing::info!(
            unit = WATCH_UNIT_NAME,
            "Not stopping the unit this teardown runs in"
        );
        return;
    }
    let command = ProcessCommand::tool("systemctl")
        .arg("stop")
        .arg(WATCH_UNIT_NAME)
        .deadline(crate::process::run::UNIT_STOP_BUDGET);
    let _ = RealProcessRunner.run(&command);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::filesystem::MockFilesystem;

    fn test_config() -> Config {
        Config::test_default()
    }

    #[test]
    fn neutral_names_contain_no_product_name() {
        for name in [
            RUNTIME_COPY_DIR,
            BINARY_NAME,
            CONFIG_NAME,
            PLAN_NAME,
            WATCH_UNIT_NAME,
        ] {
            assert!(
                !name.to_ascii_lowercase().contains("nails"),
                "runtime-copy name {name:?} must be neutral"
            );
        }
    }

    #[test]
    fn write_creates_private_dir_with_binary_and_config() {
        let fs = MockFilesystem::new();
        // The parent /run must exist for the writes to land, as on a real host.
        fs.mock_set_directory_creatable("/run/overlay-runtime", true);

        let config = test_config();
        let binary = PathBuf::from("/mnt/data/bin/control");

        write_runtime_copy(&fs, &config, &binary).unwrap();

        assert!(fs.path_exists(&runtime_copy_dir()).unwrap());
        assert!(fs.path_exists(&binary_copy_path()).unwrap());
        assert!(fs.path_exists(&config_copy_path()).unwrap());

        // The directory and the mirrored binary are private (0700).
        assert_eq!(
            fs.mock_get_permissions(&runtime_copy_dir()),
            Some(PRIVATE_MODE)
        );
        assert_eq!(
            fs.mock_get_permissions(&binary_copy_path()),
            Some(PRIVATE_MODE)
        );
    }

    #[test]
    fn the_manifest_is_read_from_the_session_plan() {
        let fs = MockFilesystem::new();
        fs.mock_set_directory_creatable("/run/overlay-runtime", true);
        let config = test_config();
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
        };
        fs.create_directory(&runtime_copy_dir()).unwrap();
        fs.write_file_content(&plan_path(), &plan.to_json())
            .unwrap();
        write_runtime_copy(&fs, &config, Path::new("/bin/control")).unwrap();

        let manifest = read_manifest(&fs).unwrap().expect("plan present");
        assert_eq!(manifest.hidden_root, config.hidden_volume_root);
        assert!(manifest.overlay_targets.is_empty());
    }

    #[test]
    fn config_copy_round_trips() {
        let fs = MockFilesystem::new();
        fs.mock_set_directory_creatable("/run/overlay-runtime", true);

        let config = test_config();
        write_runtime_copy(&fs, &config, Path::new("/bin/control")).unwrap();

        let loaded = read_config_copy(&fs).unwrap().expect("config copy present");
        assert_eq!(loaded.hidden_volume_root, config.hidden_volume_root);
        assert_eq!(loaded.state_file_path, config.state_file_path);
    }

    #[test]
    fn remove_clears_the_directory() {
        let fs = MockFilesystem::new();
        fs.mock_set_directory_creatable("/run/overlay-runtime", true);

        let config = test_config();
        write_runtime_copy(&fs, &config, Path::new("/bin/control")).unwrap();
        assert!(fs.path_exists(&runtime_copy_dir()).unwrap());

        remove_runtime_copy(&fs).unwrap();
        assert!(!fs.path_exists(&runtime_copy_dir()).unwrap());
    }

    #[test]
    fn read_manifest_is_none_without_a_copy() {
        let fs = MockFilesystem::new();
        assert!(read_manifest(&fs).unwrap().is_none());
        assert!(read_config_copy(&fs).unwrap().is_none());
    }

    #[test]
    fn remove_is_a_noop_when_absent() {
        let fs = MockFilesystem::new();
        remove_runtime_copy(&fs).unwrap();
    }
}
