// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where a whole-root session keeps its layers on the hidden volume, and the
//! system paths it works under.
//!
//! ```text
//! <hidden>/root/upper              the root overlay's upper: the hidden system
//! <hidden>/root/work               its work directory
//! <hidden>/root/mounts/<unit>/…    upper/work of each other overlaid decoy
//!                                  filesystem (a separate /home), named by its
//!                                  systemd path escape
//! <hidden>/root/cache              nix's evaluation cache during the build
//! <hidden>/config/nixos/           the hidden NixOS module (NixOS)
//! ```
//!
//! The hidden NixOS hardware configuration lives in the upper's
//! `/etc/nixos/`, so inside the hidden session `/etc/nixos` is simply the
//! hidden configuration.

use super::fstab::escape_path;
use nails_teardown::whole_root::nextroot::NEXTROOT;
use nails_teardown::whole_root::plan::{BINARY_NAME, PLAN_NAME, RUNTIME_DIR};
use std::path::{Path, PathBuf};

/// The layers of one hidden volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    hidden_root: PathBuf,
}

impl Layout {
    /// The layout under `hidden_root`.
    pub fn new(hidden_root: &Path) -> Self {
        Self {
            hidden_root: hidden_root.to_path_buf(),
        }
    }

    /// The hidden volume root.
    pub fn hidden_root(&self) -> &Path {
        &self.hidden_root
    }

    /// The root overlay's upper.
    pub fn upper(&self) -> PathBuf {
        self.hidden_root.join("root/upper")
    }

    /// The root overlay's work directory.
    pub fn work(&self) -> PathBuf {
        self.hidden_root.join("root/work")
    }

    /// Upper and work of the overlay over the decoy filesystem at `target`.
    pub fn mount_layers(&self, target: &Path) -> (PathBuf, PathBuf) {
        let base = self
            .hidden_root
            .join("root/mounts")
            .join(escape_path(target));
        (base.join("upper"), base.join("work"))
    }

    /// The upper of `path` in the hidden root (where a hidden file at `path`
    /// lives), ignoring the per-filesystem overlays.
    pub fn in_upper(&self, path: &Path) -> PathBuf {
        self.upper().join(path.strip_prefix("/").unwrap_or(path))
    }

    /// nix's cache directory during the hidden build.
    pub fn cache(&self) -> PathBuf {
        self.hidden_root.join("root/cache")
    }

    /// The hidden NixOS configuration directory as the hidden root sees it.
    pub fn etc_nixos(&self) -> PathBuf {
        self.in_upper(Path::new("/etc/nixos"))
    }
}

/// The system paths a session works under. Production uses [`Paths::system`];
/// tests point both at scratch trees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// The decoy root (`/`).
    pub root: PathBuf,
    /// The `/run` tmpfs.
    pub run: PathBuf,
}

impl Paths {
    /// `/` and `/run`.
    pub fn system() -> Self {
        Self {
            root: PathBuf::from("/"),
            run: PathBuf::from("/run"),
        }
    }

    /// Whether these are the real system paths.
    pub fn is_system(&self) -> bool {
        *self == Self::system()
    }

    /// `/run/nextroot`.
    pub fn nextroot(&self) -> PathBuf {
        if self.is_system() {
            PathBuf::from(NEXTROOT)
        } else {
            self.run.join("nextroot")
        }
    }

    /// The runtime directory.
    pub fn runtime(&self) -> PathBuf {
        if self.is_system() {
            PathBuf::from(RUNTIME_DIR)
        } else {
            self.run.join("overlay-runtime")
        }
    }

    /// The session plan.
    pub fn plan(&self) -> PathBuf {
        self.runtime().join(PLAN_NAME)
    }

    /// The RAM copy of the binary.
    pub fn binary_copy(&self) -> PathBuf {
        self.runtime().join(BINARY_NAME)
    }

    /// `path` (absolute, as the decoy sees it) under the decoy root.
    pub fn decoy(&self, path: &Path) -> PathBuf {
        self.root.join(path.strip_prefix("/").unwrap_or(path))
    }

    /// `path` (absolute, as the hidden root sees it) under the next root.
    pub fn in_nextroot(&self, path: &Path) -> PathBuf {
        self.nextroot().join(path.strip_prefix("/").unwrap_or(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_layers_sit_under_root_on_the_hidden_volume() {
        let layout = Layout::new(Path::new("/mnt/data"));
        assert_eq!(layout.upper(), Path::new("/mnt/data/root/upper"));
        assert_eq!(layout.work(), Path::new("/mnt/data/root/work"));
        assert_eq!(
            layout.mount_layers(Path::new("/home")),
            (
                PathBuf::from("/mnt/data/root/mounts/home/upper"),
                PathBuf::from("/mnt/data/root/mounts/home/work")
            )
        );
        assert_eq!(
            layout.etc_nixos(),
            Path::new("/mnt/data/root/upper/etc/nixos")
        );
    }

    #[test]
    fn system_paths_use_the_real_runtime_names_and_test_paths_their_own_tree() {
        let system = Paths::system();
        assert_eq!(system.nextroot(), Path::new("/run/nextroot"));
        assert_eq!(system.plan(), Path::new("/run/overlay-runtime/plan.json"));
        assert_eq!(
            system.in_nextroot(Path::new("/boot")),
            Path::new("/run/nextroot/boot")
        );
        let test = Paths {
            root: PathBuf::from("/tmp/r"),
            run: PathBuf::from("/tmp/run"),
        };
        assert_eq!(test.nextroot(), Path::new("/tmp/run/nextroot"));
        assert_eq!(test.decoy(Path::new("/home")), Path::new("/tmp/r/home"));
    }
}
