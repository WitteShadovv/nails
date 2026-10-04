// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Validation of every path a configuration names
//!
//! A configured path decides where hidden data is written and what is passed
//! to the kernel as overlay mount options, so a path that is relative, takes
//! a detour through `..` or a symlink, or carries an option separator could
//! put hidden data on the decoy disk or corrupt a mount. Each rule has its own
//! [`PathProblem`], and every configuration is checked before it is returned,
//! whether it was loaded from `nails.toml` or built with `ConfigBuilder`.

use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use super::types::Config;
use crate::error::{NailsError, Result};

/// Why a configured path was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathProblem {
    /// The path is relative, so its meaning would depend on the working
    /// directory of whoever runs nails.
    #[error("must be an absolute path")]
    NotAbsolute,

    /// The path has a `.` or `..` segment. Checks that compare paths as text
    /// would treat `/mnt/hidden/../etc` as inside `/mnt/hidden`.
    #[error("must not contain `.` or `..` segments")]
    NotNormalized,

    /// The path contains a character that would be misread: `,` and `:`
    /// separate overlay mount options and lower layers, and a newline cannot
    /// be represented in a mount option or a mount table line.
    #[error("must not contain {}", describe_char(*.0))]
    ForbiddenCharacter(char),

    /// The hidden volume root is `/`, which is the decoy filesystem itself.
    #[error("must not be the filesystem root")]
    FilesystemRoot,

    /// An existing component of the path is a symlink, which could redirect
    /// hidden data anywhere, including onto the decoy disk.
    #[error("must not pass through a symlink ({} is one)", .0.display())]
    Symlink(PathBuf),

    /// The path lies inside an overlay target, so mounting the overlay would
    /// hide the hidden volume, or the file nails keeps on it, behind it.
    #[error("must not lie inside the overlay target {}", .0.display())]
    InsideOverlayTarget(PathBuf),

    /// An Auto-mode exclusion names a directory a normal session writes to,
    /// so the hidden session's writes there would reach the decoy disk.
    #[error(
        "excludes a directory the session writes to, so those writes would reach the decoy disk; \
         remove it, or list it in allow_leaky_exclusions to accept the leak"
    )]
    LeakyExclusion,

    /// A path that holds hidden data is not strictly inside the hidden
    /// volume root.
    #[error("must lie inside the hidden volume root {}", .0.display())]
    OutsideHiddenRoot(PathBuf),

    /// A component could not be inspected, so the symlink rule cannot be
    /// confirmed. Refused rather than assumed safe.
    #[error("cannot be inspected: {0}")]
    Uninspectable(String),
}

fn describe_char(c: char) -> String {
    match c {
        '\n' => "a newline".to_string(),
        other => format!("'{other}'"),
    }
}

/// Characters overlayfs reads as separators inside a mount option value.
const MOUNT_OPTION_SEPARATORS: [char; 2] = [',', ':'];

/// How a path is used, which decides the rules it must follow.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Use {
    /// The hidden volume root: hidden upper and work directories are derived
    /// from it, so it ends up in overlay mount options.
    Root,
    /// Compared or matched only (exclusions).
    Plain,
    /// Ends up in an overlay mount option: a lower layer, or an overlay
    /// target, whose name also names the pivot snapshot used as a lower layer.
    MountOption,
    /// Holds hidden data: must stay inside the hidden volume root.
    Hidden,
    /// Holds hidden data and ends up in an overlay mount option.
    HiddenMountOption,
}

impl Use {
    fn in_mount_option(self) -> bool {
        matches!(
            self,
            Self::Root | Self::MountOption | Self::HiddenMountOption
        )
    }

    fn holds_hidden_data(self) -> bool {
        matches!(self, Self::Hidden | Self::HiddenMountOption)
    }
}

impl Config {
    /// Check every configured path against the path rules.
    ///
    /// - Every path is absolute, has no `.` or `..` segment and no newline.
    /// - The hidden volume root, overlay lower, upper and work directories
    ///   and overlay targets contain no `,` or `:`.
    /// - The hidden volume root is not `/`, and neither it, the state file nor
    ///   the log directory lies inside an overlay target.
    /// - In Auto mode, no exclusion names a load-bearing directory (see
    ///   [`Config::leaky_exclusions`]) that `allow_leaky_exclusions` does not
    ///   list. `/tmp` is left to the `overlay-targets` pre-flight check, which
    ///   can see whether it is a tmpfs.
    /// - The state file, the log directory and the overlay upper and work
    ///   directories lie strictly inside the hidden volume root.
    /// - No existing component of the hidden volume root, or of a path inside
    ///   it, is a symlink. Components that do not exist yet are fine.
    ///
    /// Loading a file and `ConfigBuilder::build` both run this check, so a
    /// [`Config`] only needs it again after its fields were changed directly.
    ///
    /// # Errors
    ///
    /// [`NailsError::UnsafeConfigPath`] for the first path that breaks a
    /// rule, naming the setting and the [`PathProblem`].
    pub fn validate_paths(&self) -> Result<()> {
        let root = &self.hidden_volume_root;
        let reject = |key: &str, path: &Path, problem: PathProblem| NailsError::UnsafeConfigPath {
            file: self.loaded_config_path.clone(),
            key: key.to_string(),
            path: path.to_path_buf(),
            problem,
        };

        if let Some(problem) = lexical_problem(root, Use::Root, root) {
            return Err(reject("hidden_volume_root", root, problem));
        }
        if root.parent().is_none() {
            return Err(reject(
                "hidden_volume_root",
                root,
                PathProblem::FilesystemRoot,
            ));
        }

        let paths = self.configured_paths();
        for (key, path, usage) in &paths {
            if let Some(problem) = lexical_problem(path, *usage, root) {
                return Err(reject(key, path, problem));
            }
        }

        let held_on_root = [
            ("hidden_volume_root", root.as_path()),
            ("state_file_path", self.state_file_path.as_path()),
            ("log_path", self.log_path.as_path()),
        ];
        for (key, path) in held_on_root {
            if let Some(overlay) = self.overlays.iter().find(|o| path.starts_with(&o.target)) {
                return Err(reject(
                    key,
                    path,
                    PathProblem::InsideOverlayTarget(overlay.target.clone()),
                ));
            }
        }

        // Report the first offending entry in the order the user wrote them.
        let leaky = self.leaky_exclusions(true);
        if let Some((i, path)) = self
            .overlay_exclusions
            .iter()
            .enumerate()
            .find(|(_, path)| leaky.contains(path))
        {
            return Err(reject(
                &format!("overlay_exclusions[{i}]"),
                path,
                PathProblem::LeakyExclusion,
            ));
        }
        // Only reachable if a default exclusion were load-bearing, which the
        // platform layer must never introduce silently.
        if let Some(path) = leaky.first() {
            return Err(reject(
                "overlay_exclusions",
                path,
                PathProblem::LeakyExclusion,
            ));
        }

        // Touch the filesystem only once every path is known to be absolute
        // and normalized, so each prefix inspected below is meaningful.
        let root_entry = ("hidden_volume_root".to_string(), root.as_path(), Use::Root);
        let hidden = paths
            .iter()
            .filter(|(_, _, usage)| usage.holds_hidden_data());
        for (key, path, _) in std::iter::once(&root_entry).chain(hidden) {
            if let Some(problem) = symlink_problem(path) {
                return Err(reject(key, path, problem));
            }
        }
        Ok(())
    }

    /// Every configured path other than the hidden volume root, with the
    /// setting it comes from and how it is used.
    fn configured_paths(&self) -> Vec<(String, &Path, Use)> {
        let mut paths = vec![
            (
                "state_file_path".to_string(),
                self.state_file_path.as_path(),
                Use::Hidden,
            ),
            ("log_path".to_string(), self.log_path.as_path(), Use::Hidden),
        ];
        for (i, overlay) in self.overlays.iter().enumerate() {
            let key = |field: &str| format!("overlays[{i}].{field}");
            paths.push((key("lower"), overlay.lower.as_path(), Use::MountOption));
            paths.push((
                key("upper"),
                overlay.upper.as_path(),
                Use::HiddenMountOption,
            ));
            paths.push((key("work"), overlay.work.as_path(), Use::HiddenMountOption));
            paths.push((key("target"), overlay.target.as_path(), Use::MountOption));
        }
        for (i, path) in self.overlay_exclusions.iter().enumerate() {
            paths.push((
                format!("overlay_exclusions[{i}]"),
                path.as_path(),
                Use::Plain,
            ));
        }
        for (i, path) in self.overlay_exclusions_remove.iter().enumerate() {
            paths.push((
                format!("overlay_exclusions_remove[{i}]"),
                path.as_path(),
                Use::Plain,
            ));
        }
        for (i, path) in self.allow_leaky_exclusions.iter().enumerate() {
            paths.push((
                format!("allow_leaky_exclusions[{i}]"),
                path.as_path(),
                Use::Plain,
            ));
        }
        paths
    }
}

/// The first rule `path` breaks without looking at the filesystem.
fn lexical_problem(path: &Path, usage: Use, root: &Path) -> Option<PathProblem> {
    if !path.is_absolute() {
        return Some(PathProblem::NotAbsolute);
    }
    // `Path::components` silently drops interior `.` segments, so the raw
    // bytes are inspected instead.
    let has_dot_segment = path
        .as_os_str()
        .as_bytes()
        .split(|byte| *byte == b'/')
        .any(|segment| segment == b"." || segment == b"..");
    if has_dot_segment {
        return Some(PathProblem::NotNormalized);
    }
    let text = path.to_string_lossy();
    if text.contains('\n') {
        return Some(PathProblem::ForbiddenCharacter('\n'));
    }
    if usage.in_mount_option()
        && let Some(c) = text.chars().find(|c| MOUNT_OPTION_SEPARATORS.contains(c))
    {
        return Some(PathProblem::ForbiddenCharacter(c));
    }
    if usage.holds_hidden_data() && (path == root || !path.starts_with(root)) {
        return Some(PathProblem::OutsideHiddenRoot(root.to_path_buf()));
    }
    None
}

/// Report the first existing component of `path` that is a symlink.
///
/// Walks from `/` downwards with `lstat`. The walk stops at the first
/// component that does not exist, since nothing below it can exist either.
fn symlink_problem(path: &Path) -> Option<PathProblem> {
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        if matches!(component, Component::RootDir) {
            continue;
        }
        match std::fs::symlink_metadata(&prefix) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Some(PathProblem::Symlink(prefix));
            }
            Ok(_) => {}
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
                return None;
            }
            Err(e) => {
                return Some(PathProblem::Uninspectable(format!(
                    "{}: {e}",
                    prefix.display()
                )));
            }
        }
    }
    None
}
