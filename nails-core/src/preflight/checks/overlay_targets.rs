// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Overlay target safety floor
//!
//! Two configurations pass every per-path rule and still break the hidden
//! session:
//!
//! - An overlay target that covers the hidden volume, the state file, the log
//!   directory or the running binary. overlayfs does not carry submounts into
//!   its merged view, so a hidden volume mounted at VeraCrypt's
//!   `/media/veracrypt1` disappears under an overlay of `/media`; the upper
//!   layers and the state file then resolve into the overlay itself.
//! - An Auto-mode exclusion of a directory the session writes to, which sends
//!   those writes to the decoy disk (see [`Config::leaky_exclusions`]).
//!
//! [`OverlayTargetsCheck`] reports both before anything changes, and
//! activation runs it again before any side effect even with
//! `--no-preflight`. [`ensure_targets_clear`] repeats the coverage test on the
//! exact target list right before mounting.

use std::ffi::OsStr;
use std::fmt;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::super::{CheckResult, PreFlightCheck};
use crate::config::{Config, OverlayMode, TMP_DIRECTORY};
use crate::{Filesystem, NailsError, Result};

/// A path nails depends on for the whole session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtectedKind {
    HiddenRoot,
    StateFile,
    LogDirectory,
    Binary,
}

impl ProtectedKind {
    fn label(self) -> &'static str {
        match self {
            Self::HiddenRoot => "hidden root",
            Self::StateFile => "state file",
            Self::LogDirectory => "log directory",
            Self::Binary => "nails binary",
        }
    }

    fn remedy(self) -> &'static str {
        match self {
            Self::HiddenRoot => "mount it under /mnt or /run/media",
            Self::StateFile => "set state_file_path outside it",
            Self::LogDirectory => "set log_path outside it",
            Self::Binary => "run nails from the hidden volume",
        }
    }
}

/// A configured path together with the path it resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Resolved {
    configured: PathBuf,
    real: PathBuf,
}

impl Resolved {
    fn new<F: Filesystem>(fs: &F, path: &Path) -> Result<Self> {
        Ok(Self {
            configured: path.to_path_buf(),
            real: resolve_path(fs, path)?,
        })
    }
}

impl fmt::Display for Resolved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.configured.display())?;
        if self.real != self.configured {
            write!(f, " (resolves to {})", self.real.display())?;
        }
        Ok(())
    }
}

/// A protected path that an overlay target would cover.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CoveredPath {
    kind: ProtectedKind,
    path: Resolved,
    target: Resolved,
    mode: OverlayMode,
}

impl fmt::Display for CoveredPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let target = self.target.configured.display();
        write!(
            f,
            "{} {} is under overlay target {}; {}, or ",
            self.kind.label(),
            self.path,
            self.target,
            self.kind.remedy()
        )?;
        match self.mode {
            OverlayMode::Auto => write!(f, "add {target} to overlay_exclusions"),
            OverlayMode::Explicit => write!(f, "remove the {target} overlay"),
        }
    }
}

/// The paths no overlay target may cover, with symlinks resolved.
#[derive(Debug)]
struct ProtectedPaths {
    entries: Vec<(ProtectedKind, Resolved)>,
}

impl ProtectedPaths {
    fn resolve<F: Filesystem>(fs: &F, config: &Config, binary: Option<&Path>) -> Result<Self> {
        let mut entries = vec![
            (
                ProtectedKind::HiddenRoot,
                Resolved::new(fs, &config.hidden_volume_root)?,
            ),
            (
                ProtectedKind::StateFile,
                Resolved::new(fs, &config.state_file_path)?,
            ),
            (
                ProtectedKind::LogDirectory,
                Resolved::new(fs, &config.log_path)?,
            ),
        ];
        if let Some(binary) = binary {
            entries.push((ProtectedKind::Binary, Resolved::new(fs, binary)?));
        }
        Ok(Self { entries })
    }

    /// The first protected path one of `targets` would cover, hidden root
    /// first, since a covered root explains every path below it.
    fn first_covered<F: Filesystem>(
        &self,
        fs: &F,
        mode: OverlayMode,
        targets: &[PathBuf],
    ) -> Result<Option<CoveredPath>> {
        let targets = targets
            .iter()
            .map(|target| Resolved::new(fs, target))
            .collect::<Result<Vec<_>>>()?;
        for (kind, path) in &self.entries {
            for target in &targets {
                if !path.real.starts_with(&target.real) {
                    continue;
                }
                // A binary on the target's own filesystem stays visible
                // through the overlay's lower layer, which is the normal case
                // for a store-installed nails under an overlaid /nix. Only a
                // binary on another filesystem mounted below the target
                // disappears from the merged view.
                if *kind == ProtectedKind::Binary
                    && fs.device_id(&path.real)? == fs.device_id(&target.real)?
                {
                    continue;
                }
                return Ok(Some(CoveredPath {
                    kind: *kind,
                    path: path.clone(),
                    target: target.clone(),
                    mode,
                }));
            }
        }
        Ok(None)
    }
}

/// Resolve the symlinks in `path`, including a path whose tail does not
/// exist yet, such as a state file or log directory nails creates later: the
/// deepest existing ancestor is resolved and the missing components appended.
///
/// Any error other than a missing component is returned, so a path that
/// cannot be inspected is refused rather than compared as written.
fn resolve_path<F: Filesystem>(fs: &F, path: &Path) -> Result<PathBuf> {
    let mut existing = path;
    let mut missing: Vec<&OsStr> = Vec::new();
    loop {
        match fs.canonicalize(existing) {
            Ok(mut resolved) => {
                resolved.extend(missing.iter().rev());
                return Ok(resolved);
            }
            Err(NailsError::IoError(e))
                if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) =>
            {
                match (existing.parent(), existing.file_name()) {
                    (Some(parent), Some(name)) => {
                        missing.push(name);
                        existing = parent;
                    }
                    _ => return Ok(path.to_path_buf()),
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// The running nails binary, or `None` inside the test harness.
///
/// A test binary lives in a cargo build tree, often below `/home`; treating it
/// as the deployed binary would refuse every test configuration that overlays
/// `/home`.
fn running_binary() -> Option<PathBuf> {
    if crate::runtime_safety::should_skip_host_interaction() {
        return None;
    }
    std::env::current_exe().ok()
}

/// Refuse to mount `targets` when one of them covers the hidden root, the
/// state file, the log directory or the running binary.
///
/// Called with the exact list about to be mounted, so the floor also holds
/// for a top-level directory created after the pre-flight checks ran.
///
/// # Errors
///
/// [`NailsError::ConfigError`] naming the covered path, the target and the
/// fix; any error from resolving the paths.
pub(crate) fn ensure_targets_clear<F: Filesystem>(
    fs: &F,
    config: &Config,
    targets: &[PathBuf],
) -> Result<()> {
    let protected = ProtectedPaths::resolve(fs, config, running_binary().as_deref())?;
    match protected.first_covered(fs, config.overlay_mode, targets)? {
        Some(covered) => Err(NailsError::ConfigError(covered.to_string())),
        None => Ok(()),
    }
}

/// Pre-flight check for the overlay target safety floor.
///
/// Fails when an overlay target is equal to or above the hidden root, the
/// state file, the log directory or the running binary (all with symlinks
/// resolved), and when an Auto-mode exclusion leaves a load-bearing directory
/// on the decoy disk without `allow_leaky_exclusions` accepting it. `/tmp`
/// counts as load-bearing unless it is a tmpfs. Warns when an accepted leak is
/// in effect.
///
/// # Example
///
/// ```rust
/// use nails_core::config::Config;
/// use nails_core::filesystem::MockFilesystem;
/// use nails_core::preflight::{OverlayTargetsCheck, PreFlightCheck};
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// fs.mock_set_root_directories(vec![PathBuf::from("/home"), PathBuf::from("/media")]);
///
/// let mut config = Config::default();
/// config.hidden_volume_root = PathBuf::from("/media/veracrypt1");
/// config.state_file_path = config.hidden_volume_root.join("state.json");
/// config.log_path = config.hidden_volume_root.join("logs");
///
/// let result = OverlayTargetsCheck::new(config).run(&fs).unwrap();
/// assert!(result.is_fail());
/// ```
#[derive(Debug, Clone)]
pub struct OverlayTargetsCheck {
    config: Config,
    binary: Option<PathBuf>,
}

impl OverlayTargetsCheck {
    /// Create the check for `config` and the running binary.
    pub fn new(config: Config) -> Self {
        Self::with_binary(config, running_binary())
    }

    fn with_binary(config: Config, binary: Option<PathBuf>) -> Self {
        Self { config, binary }
    }

    fn targets<F: Filesystem>(&self, fs: &F) -> Result<Vec<PathBuf>> {
        match self.config.overlay_mode {
            OverlayMode::Auto => crate::build_overlay_targets(fs, &self.config),
            OverlayMode::Explicit => Ok(self
                .config
                .overlays
                .iter()
                .map(|overlay| overlay.target.clone())
                .collect()),
        }
    }
}

/// `/tmp` is only safe to exclude when its writes stay in RAM.
fn tmp_is_tmpfs<F: Filesystem>(fs: &F) -> Result<bool> {
    Ok(fs.get_filesystem_type(Path::new(TMP_DIRECTORY))?.as_deref() == Some("tmpfs"))
}

fn describe_exclusions(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| {
            if path == Path::new(TMP_DIRECTORY) {
                format!("{} (not a tmpfs)", path.display())
            } else {
                path.display().to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

impl<F: Filesystem> PreFlightCheck<F> for OverlayTargetsCheck {
    fn name(&self) -> &'static str {
        "overlay-targets"
    }

    fn description(&self) -> &'static str {
        "Validates no overlay target hides the hidden volume and no exclusion leaks to the decoy disk"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let targets = self.targets(fs)?;
        let mut problems = Vec::new();

        let protected = ProtectedPaths::resolve(fs, &self.config, self.binary.as_deref())?;
        if let Some(covered) = protected.first_covered(fs, self.config.overlay_mode, &targets)? {
            problems.push(covered.to_string());
        }

        let tmp_is_tmpfs = tmp_is_tmpfs(fs)?;
        let leaky = self.config.leaky_exclusions(tmp_is_tmpfs);
        if !leaky.is_empty() {
            problems.push(format!(
                "overlay_exclusions leaves {} on the decoy disk, so the hidden session's writes \
                 there are not hidden; remove them from overlay_exclusions, or list them in \
                 allow_leaky_exclusions to accept the leak",
                describe_exclusions(&leaky)
            ));
        }

        if !problems.is_empty() {
            return Ok(CheckResult::fail(problems.join("; ")));
        }

        let accepted = self.config.accepted_leaky_exclusions(tmp_is_tmpfs);
        if !accepted.is_empty() {
            return Ok(CheckResult::Warn(format!(
                "allow_leaky_exclusions keeps {} on the decoy disk: the hidden session's writes \
                 there are not hidden",
                describe_exclusions(&accepted)
            )));
        }

        Ok(CheckResult::Pass(format!(
            "{} overlay target(s) leave the hidden volume visible; no exclusion leaks to the decoy disk",
            targets.len()
        )))
    }
}

#[cfg(test)]
mod tests;
