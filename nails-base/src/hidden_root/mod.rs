// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Hidden-root attach gate.
//!
//! NAILS must write nothing — not a log line, not a staged `configuration.nix`,
//! not a cleaned history file — unless the hidden root is positively *attached*:
//! a volume of its own mounted at that path, that holds the hidden environment.
//! The binary's own directory is only a hint at where that volume lives; a hint
//! is not a mount. Treating a path that merely *exists* as the hidden volume is
//! what let `verify`, `status` and friends drop identifying logs into a download
//! directory or the decoy, and what let `activate` stage files onto an unmounted
//! mount point on a persistent disk.
//!
//! [`HiddenRoot::assess`] is the single gate every write path consults, most of
//! them through [`HiddenRoot::verify_attached`]. It answers one question — is
//! this path a mounted hidden volume we may write to? — and returns a
//! [`Refusal`] when the answer is no, so the caller can degrade to stderr-only
//! logging or refuse the operation with a message the operator can act on.

#[cfg(test)]
mod tests;

use crate::filesystem::mountinfo::{MountEntry, root_is_hidden_overlay, top_mount_at};
use crate::{Filesystem, Result};
use std::path::{Path, PathBuf};

// The marker names come from the artifact registry, the single source of what
// NAILS writes, so the attach gate and the registry can never disagree about the
// names that identify an initialised hidden root.

/// State-file marker that marks a directory as an initialised NAILS hidden root.
pub const MARKER_STATE_FILE: &str = crate::artifacts::STATE_FILE_NAME;

/// Config directory (holding `nails.toml`) relative to the hidden root.
pub const MARKER_CONFIG_DIR: &str = crate::artifacts::CONFIG_DIR_NAME;
/// Config-file name inside [`MARKER_CONFIG_DIR`].
pub const MARKER_CONFIG_FILE: &str = crate::artifacts::CONFIG_FILE_NAME;

/// Whether a candidate hidden root is a mounted hidden volume we may write to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachState {
    /// The path is a volume of its own (and, when required, carries a NAILS
    /// marker). Writing to it is safe.
    Attached,
    /// The path is not usable as the hidden root. The string explains why, for
    /// an operator-facing message or a degradation log line.
    Unattached(String),
}

impl AttachState {
    /// `true` only for [`AttachState::Attached`].
    pub fn is_attached(&self) -> bool {
        matches!(self, AttachState::Attached)
    }

    /// The reason a path was judged unattached, if it was.
    pub fn reason(&self) -> Option<&str> {
        match self {
            AttachState::Attached => None,
            AttachState::Unattached(reason) => Some(reason.as_str()),
        }
    }
}

/// Why [`HiddenRoot::assess`] refused a hidden root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalKind {
    /// No hidden root is configured.
    NotConfigured,
    /// The path does not exist.
    Missing,
    /// The mount table could not be read, so nothing shows what is mounted.
    MountTableUnreadable,
    /// Nothing is mounted at the root: it is a folder on the filesystem
    /// mounted at `mount_point`.
    NotAMountPoint {
        /// Where the filesystem holding the folder is mounted.
        mount_point: PathBuf,
    },
    /// Two filesystems are mounted at the root: `below`, then `above` over it.
    /// A write reaches `above`.
    Covered {
        /// The source of the lower mount.
        below: PathBuf,
        /// The source of the mount on top, which a lookup reaches.
        above: PathBuf,
    },
    /// In the hidden session, the filesystem at the root is not the volume the
    /// session entered with.
    NotTheSessionVolume {
        /// The source of the mount a lookup reaches.
        source: PathBuf,
    },
    /// The root reports the same device as `/`.
    SameDeviceAsRoot,
}

/// A refused hidden root: the kind, and a sentence for the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// What is wrong.
    pub kind: RefusalKind,
    /// Why, naming the paths involved.
    pub reason: String,
}

/// The gate's answer for a hidden root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assessment {
    /// A volume of its own is mounted at the root; writing to it is safe.
    Attached,
    /// Nothing may be written to the root.
    Refused(Refusal),
}

impl Assessment {
    /// `true` only for [`Assessment::Attached`].
    pub fn is_attached(&self) -> bool {
        matches!(self, Assessment::Attached)
    }
}

fn refuse(kind: RefusalKind, reason: String) -> Result<Assessment> {
    Ok(Assessment::Refused(Refusal { kind, reason }))
}

/// The attach gate.
pub struct HiddenRoot;

impl HiddenRoot {
    /// Decide whether a volume of its own is mounted at `root`.
    ///
    /// The checks, in order; the first that fails decides:
    ///
    /// 1. **Present** — a root is configured and the path exists.
    /// 2. **A mount point** — the mount table is readable, and a lookup of the
    ///    resolved path ends in a mount whose mount point is that path. A folder
    ///    on a filesystem mounted elsewhere (`/`, a separate `/home`) fails,
    ///    whatever device that filesystem is on, and so does a root covered by a
    ///    later mount on one of its parents.
    /// 3. **One filesystem** — every mount stacked at the root shares one
    ///    device. A second disk mounted over the hidden volume would receive
    ///    every write, so it fails, naming both sources.
    /// 4. **The session's volume** — in the hidden session (`/` is an overlay
    ///    whose upper lies under the root), the mount at the root must be the
    ///    device the entry recorded in the session plan (`hidden_dev`). For a
    ///    plan without it, or none that can be read, `<root>/root/upper` must
    ///    sit on the same device as the root.
    /// 5. **Not `/`'s device** — a backstop for a bind of `/`'s own filesystem
    ///    at the root.
    ///
    /// No subprocess, no write, no cache: it reads the mount table and, in the
    /// session, the plan through `fs`.
    pub fn assess<F: Filesystem>(fs: &F, root: &Path) -> Result<Assessment> {
        if root.as_os_str().is_empty() {
            return refuse(
                RefusalKind::NotConfigured,
                "no hidden root is configured".to_string(),
            );
        }
        if !fs.path_exists(root)? {
            return refuse(
                RefusalKind::Missing,
                format!(
                    "hidden root {} does not exist (mount the hidden volume there first)",
                    root.display()
                ),
            );
        }
        let table = match fs.mount_table() {
            Ok(table) => table,
            Err(error) => {
                return refuse(
                    RefusalKind::MountTableUnreadable,
                    format!(
                        "the mount table cannot be read ({error}), so nothing shows that a \
                         volume is mounted at {}",
                        root.display()
                    ),
                );
            }
        };
        let canonical = fs.canonicalize(root).unwrap_or_else(|_| root.to_path_buf());

        let Some(visible) = top_mount_at(&table, &canonical) else {
            let holder = mount_holding(&table, &canonical)
                .map_or_else(|| PathBuf::from("/"), |m| m.mount_point.clone());
            return refuse(
                RefusalKind::NotAMountPoint {
                    mount_point: holder.clone(),
                },
                format!(
                    "hidden root {} is not a mount point: it is a folder on the filesystem \
                     mounted at {} (unlock and mount the hidden volume there before continuing)",
                    root.display(),
                    holder.display()
                ),
            );
        };

        if let Some(below) = covered_mount(&table, visible) {
            return refuse(
                RefusalKind::Covered {
                    below: below.source.clone(),
                    above: visible.source.clone(),
                },
                format!(
                    "two filesystems are mounted at {}: {}, then {} over it (unmount the one \
                     that is not the hidden volume)",
                    root.display(),
                    below.source.display(),
                    visible.source.display()
                ),
            );
        }

        if root_is_hidden_overlay(&table, &canonical).is_some()
            && !holds_the_session_volume(
                fs,
                &canonical,
                visible,
                recorded_hidden_dev(fs).as_deref(),
            )
        {
            return refuse(
                RefusalKind::NotTheSessionVolume {
                    source: visible.source.clone(),
                },
                format!(
                    "the filesystem at {} ({}) is not the volume this session started from \
                     (unmount what was mounted over it)",
                    root.display(),
                    visible.source.display()
                ),
            );
        }

        if fs.device_id(root)? == fs.device_id(Path::new("/"))? {
            return refuse(
                RefusalKind::SameDeviceAsRoot,
                format!(
                    "hidden root {} shares a device with /, so nothing is mounted there \
                     (unlock and mount the hidden volume before continuing)",
                    root.display()
                ),
            );
        }

        Ok(Assessment::Attached)
    }

    /// Decide whether `root` is a mounted hidden volume NAILS may write to:
    /// [`assess`](Self::assess), then, when `require_marker` is set, a NAILS
    /// marker (`state.json` or `config/nails.toml`) on it. The marker keeps a
    /// write command from treating some *other* mounted volume that happens to
    /// sit at the configured path as the hidden environment. `init` creates the
    /// marker, so it calls with `require_marker` cleared.
    ///
    /// Returns [`AttachState::Attached`] only when every applicable check passes;
    /// otherwise [`AttachState::Unattached`] carrying the first failing reason.
    pub fn verify_attached<F: Filesystem>(
        fs: &F,
        root: &Path,
        require_marker: bool,
    ) -> Result<AttachState> {
        if let Assessment::Refused(refusal) = Self::assess(fs, root)? {
            return Ok(AttachState::Unattached(refusal.reason));
        }

        if require_marker && !Self::has_marker(fs, root)? {
            return Ok(AttachState::Unattached(format!(
                "hidden root {} is mounted but holds no NAILS marker \
                 ({MARKER_STATE_FILE} or {MARKER_CONFIG_DIR}/{MARKER_CONFIG_FILE}); \
                 run `nails init` on the hidden volume first",
                root.display()
            )));
        }

        Ok(AttachState::Attached)
    }

    /// Whether `root` carries a NAILS marker: the state file or the config file.
    fn has_marker<F: Filesystem>(fs: &F, root: &Path) -> Result<bool> {
        if fs.path_exists(&root.join(MARKER_STATE_FILE))? {
            return Ok(true);
        }
        fs.path_exists(&root.join(MARKER_CONFIG_DIR).join(MARKER_CONFIG_FILE))
    }
}

/// The mount a lookup of `path` ends in: the visible mount at the deepest
/// prefix of `path` that is a mount point.
pub fn mount_holding<'a>(table: &'a [MountEntry], path: &Path) -> Option<&'a MountEntry> {
    path.ancestors()
        .find_map(|prefix| top_mount_at(table, prefix))
}

/// Whether another filesystem is stacked under `top` at its mount point: the
/// source of the nearest such mount.
pub fn covered_mount<'a>(table: &'a [MountEntry], top: &'a MountEntry) -> Option<&'a MountEntry> {
    stack_below(table, top).find(|m| m.dev != top.dev)
}

/// The mounts stacked under `top` at its own mount point, nearest first.
fn stack_below<'a>(
    table: &'a [MountEntry],
    top: &'a MountEntry,
) -> impl Iterator<Item = &'a MountEntry> {
    std::iter::successors(Some(top), |above| {
        table.iter().find(|m| {
            m.mount_id == above.parent_id
                && m.mount_id != above.mount_id
                && m.mount_point == top.mount_point
        })
    })
    .skip(1)
}

/// In the hidden session: whether the mount `visible` at `root` is the volume
/// the session entered with.
///
/// The entry records the device (`major:minor`) of the hidden volume's mount in
/// the session plan as `hidden_dev`; `recorded` is that value. A plan written
/// before that field existed, or none that can be read, leaves one test: the
/// root overlay's upper, at `<root>/root/upper`, must sit on the device the
/// root reports, which fails when another disk covers the root.
pub fn holds_the_session_volume<F: Filesystem>(
    fs: &F,
    root: &Path,
    visible: &MountEntry,
    recorded: Option<&str>,
) -> bool {
    if let Some(recorded) = recorded {
        return visible.dev == recorded;
    }
    let upper = root.join("root").join("upper");
    matches!(
        (fs.device_id(&upper), fs.device_id(root)),
        (Ok(upper_dev), Ok(root_dev)) if upper_dev == root_dev
    )
}

/// The hidden volume's device as the session plan in `/run` records it.
pub fn recorded_hidden_dev<F: Filesystem>(fs: &F) -> Option<String> {
    let path = nails_teardown::whole_root::plan::default_plan_path();
    let text = fs.read_file_content(&path).ok()?;
    nails_teardown::whole_root::plan::Plan::from_json(&text)
        .ok()?
        .hidden_dev
}

/// Refuse a state write (the state file or its `.lock`) unless `dir` lies on the
/// hidden volume mounted at `root`.
///
/// Every manager state write and every command's state lock goes through it.
/// Only `init --allow-unmounted`, which the operator points at a directory on
/// purpose, writes its first state file without it.
///
/// The state directory is the hidden root (or a directory inside it). When the
/// hidden volume is not mounted the configured path is a bare mount-point
/// directory on the decoy, and creating `state.json` or `.lock` there would
/// leave a NAILS artifact on the decoy disk. The same attach gate every other
/// write path consults decides it: `root` must pass [`HiddenRoot::assess`], and
/// `dir` must lie under it on the root's own mount, not on another filesystem
/// mounted inside it. No marker is required, since `state.json` is itself the
/// marker.
pub fn ensure_state_dir_attached<F: Filesystem>(fs: &F, root: &Path, dir: &Path) -> Result<()> {
    #[cfg(any(test, feature = "test-hooks"))]
    if crate::runtime_safety::in_unit_tests() && !state_attach_probe::enforced() {
        return Ok(());
    }
    let refused = |reason: String| {
        Err(crate::NailsError::InvalidState(format!(
            "refusing to write state outside the mounted hidden volume: {reason}"
        )))
    };
    if let Assessment::Refused(refusal) = HiddenRoot::assess(fs, root)? {
        return refused(refusal.reason);
    }
    let root = fs.canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let dir = fs.canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    if !dir.starts_with(&root) {
        return refused(format!(
            "{} is not inside the hidden root {}",
            dir.display(),
            root.display()
        ));
    }
    let table = fs.mount_table()?;
    let root_mount = top_mount_at(&table, &root).map(|m| m.mount_id);
    match mount_holding(&table, &dir) {
        Some(mount) if Some(mount.mount_id) == root_mount => Ok(()),
        holder => refused(format!(
            "{} is on another filesystem ({}) mounted inside the hidden root {}",
            dir.display(),
            holder.map_or(Path::new("/"), |m| &m.mount_point).display(),
            root.display()
        )),
    }
}

/// Test seam for [`ensure_state_dir_attached`], compiled only for tests.
///
/// The library crates' unit tests ([`in_unit_tests`](crate::runtime_safety::in_unit_tests))
/// write state into temp directories that share `/`'s device on many hosts, so
/// the state gate is off for them unless a test arms it on its own thread to
/// exercise the refusal against a real directory.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub mod state_attach_probe {
    use std::cell::Cell;

    thread_local! {
        static ENFORCED: Cell<bool> = const { Cell::new(false) };
    }

    /// Enforce the state attach gate on this thread until the guard drops.
    pub fn enforce() -> Guard {
        ENFORCED.with(|cell| cell.set(true));
        Guard
    }

    pub fn enforced() -> bool {
        ENFORCED.with(Cell::get)
    }

    pub struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            ENFORCED.with(|cell| cell.set(false));
        }
    }
}
