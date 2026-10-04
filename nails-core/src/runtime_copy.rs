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
//! - a manifest of the overlay targets that were mounted, so a teardown that
//!   cannot consult the live mount table still has a record of what to look for.
//!
//! The directory and every file in it carry a **neutral, non-product name**: a
//! forensic examiner enumerating `/run` must not find the tool's name, and the
//! in-session watcher ([`crate::watcher`]) that runs from this copy is registered
//! with systemd under the same neutral name. The whole directory is `0700` and is
//! removed on both deactivation and emergency teardown; a leftover is a teardown
//! failure, the same contract as [`crate::artifacts::RUNTIME_DIR`].

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::filesystem::Filesystem;
use crate::{NailsError, Result};

/// Neutral runtime-copy directory on the decoy's `/run` tmpfs.
///
/// The name reveals nothing about the tool: `/run` is full of short runtime
/// state directories, and overlay-backed runtimes (containers, snaps) are
/// commonplace, so this reads as ordinary system state rather than a tell. It is
/// deliberately *not* [`crate::artifacts::RUNTIME_DIR`] (`/run/nails`): that path
/// is product-named and holds the ephemeral overlay uppers, whereas this copy and
/// the watcher must leave no product name anywhere under `/run`.
pub const RUNTIME_COPY_DIR: &str = "/run/overlay-runtime";

/// File name of the mirrored executable inside [`RUNTIME_COPY_DIR`]. Neutral.
pub const BINARY_NAME: &str = "control";

/// File name of the mirrored configuration inside [`RUNTIME_COPY_DIR`]. Neutral.
pub const CONFIG_NAME: &str = "settings.toml";

/// File name of the mount manifest inside [`RUNTIME_COPY_DIR`]. Neutral.
pub const MANIFEST_NAME: &str = "mounts.json";

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

/// Path of the mount manifest.
pub fn manifest_path() -> PathBuf {
    runtime_copy_dir().join(MANIFEST_NAME)
}

/// What teardown needs to know when the hidden volume and its `state.json` can no
/// longer be read.
///
/// Recorded at activation into [`manifest_path`] so `emergency`/`recover` have a
/// durable, RAM-backed record of the hidden root and the overlay targets that
/// were brought up, independent of the volume that may now be gone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeManifest {
    /// The configured hidden volume root at activation.
    pub hidden_root: PathBuf,
    /// The state file path at activation.
    pub state_file: PathBuf,
    /// The overlay targets that were mounted, in activation order.
    pub overlay_targets: Vec<PathBuf>,
}

/// Write the runtime copy: the executable, the effective config and the mount
/// manifest, into a fresh `0700` directory under `/run`.
///
/// `binary_src` is the path of the running executable (the caller passes
/// [`std::env::current_exe`]). Any pre-existing copy is removed first so a stale
/// directory from a crashed prior session cannot leave a mismatched binary or
/// manifest behind.
pub fn write_runtime_copy<F: Filesystem>(
    filesystem: &F,
    config: &Config,
    binary_src: &Path,
    overlay_targets: &[PathBuf],
) -> Result<()> {
    let dir = runtime_copy_dir();

    // Start from a clean directory: a leftover from a crashed session would
    // otherwise shadow the current binary or manifest.
    if filesystem.path_exists(&dir)? {
        filesystem.remove_dir_all(&dir)?;
    }
    filesystem.create_directory(&dir)?;
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

    // The mount manifest.
    let manifest = RuntimeManifest {
        hidden_root: config.hidden_volume_root.clone(),
        state_file: config.state_file_path.clone(),
        overlay_targets: overlay_targets.to_vec(),
    };
    let manifest_json = serde_json::to_string_pretty(&manifest).map_err(|e| {
        NailsError::IoError(std::io::Error::other(format!(
            "failed to serialize the runtime manifest: {e}"
        )))
    })?;
    filesystem.write_file_content(&manifest_path(), &manifest_json)?;

    tracing::info!(
        dir = %dir.display(),
        targets = overlay_targets.len(),
        "Wrote the RAM-backed runtime copy (binary, config, mount manifest)"
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

/// Read the mount manifest back from the runtime copy, if one is present.
///
/// `Ok(None)` when no runtime copy exists (no activation wrote one, or it was
/// already torn down); an error only on a present-but-unparseable manifest.
pub fn read_manifest<F: Filesystem>(filesystem: &F) -> Result<Option<RuntimeManifest>> {
    let path = manifest_path();
    if !filesystem.path_exists(&path)? {
        return Ok(None);
    }
    let content = filesystem.read_file_content(&path)?;
    let manifest: RuntimeManifest = serde_json::from_str(&content).map_err(|e| {
        NailsError::IoError(std::io::Error::other(format!(
            "runtime manifest at {} is unparseable: {e}",
            path.display()
        )))
    })?;
    Ok(Some(manifest))
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
        .arg(&binary)
        .arg("watch");

    match RealProcessRunner.run(&command) {
        Ok(output) if output.status.success() => {
            tracing::info!(
                unit = WATCH_UNIT_NAME,
                "Started the in-session backend watcher"
            );
        }
        Ok(output) => {
            tracing::warn!(
                unit = WATCH_UNIT_NAME,
                status = %output.status,
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

    let command = ProcessCommand::tool("systemctl")
        .arg("stop")
        .arg(WATCH_UNIT_NAME);
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
            MANIFEST_NAME,
            WATCH_UNIT_NAME,
        ] {
            assert!(
                !name.to_ascii_lowercase().contains("nails"),
                "runtime-copy name {name:?} must be neutral"
            );
        }
    }

    #[test]
    fn write_creates_private_dir_with_binary_config_and_manifest() {
        let fs = MockFilesystem::new();
        // The parent /run must exist for the writes to land, as on a real host.
        fs.mock_set_directory_creatable("/run/overlay-runtime", true);

        let config = test_config();
        let targets = vec![PathBuf::from("/home"), PathBuf::from("/etc")];
        let binary = PathBuf::from("/mnt/data/bin/control");

        write_runtime_copy(&fs, &config, &binary, &targets).unwrap();

        assert!(fs.path_exists(&runtime_copy_dir()).unwrap());
        assert!(fs.path_exists(&binary_copy_path()).unwrap());
        assert!(fs.path_exists(&config_copy_path()).unwrap());
        assert!(fs.path_exists(&manifest_path()).unwrap());

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
    fn manifest_round_trips_the_hidden_root_and_targets() {
        let fs = MockFilesystem::new();
        fs.mock_set_directory_creatable("/run/overlay-runtime", true);

        let config = test_config();
        let targets = vec![PathBuf::from("/home"), PathBuf::from("/var")];
        write_runtime_copy(&fs, &config, Path::new("/bin/control"), &targets).unwrap();

        let manifest = read_manifest(&fs).unwrap().expect("manifest present");
        assert_eq!(manifest.hidden_root, config.hidden_volume_root);
        assert_eq!(manifest.state_file, config.state_file_path);
        assert_eq!(manifest.overlay_targets, targets);
    }

    #[test]
    fn config_copy_round_trips() {
        let fs = MockFilesystem::new();
        fs.mock_set_directory_creatable("/run/overlay-runtime", true);

        let config = test_config();
        write_runtime_copy(&fs, &config, Path::new("/bin/control"), &[]).unwrap();

        let loaded = read_config_copy(&fs).unwrap().expect("config copy present");
        assert_eq!(loaded.hidden_volume_root, config.hidden_volume_root);
        assert_eq!(loaded.state_file_path, config.state_file_path);
    }

    #[test]
    fn remove_clears_the_directory() {
        let fs = MockFilesystem::new();
        fs.mock_set_directory_creatable("/run/overlay-runtime", true);

        let config = test_config();
        write_runtime_copy(&fs, &config, Path::new("/bin/control"), &[]).unwrap();
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
