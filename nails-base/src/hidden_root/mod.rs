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
//! logging or refuse the operation with a message the operator can act on
//! (see [`refusal`] for its text and codes).

pub mod refusal;
pub mod separation;
#[cfg(test)]
mod tests;

use crate::filesystem::mountinfo::{MountEntry, root_is_hidden_overlay, top_mount_at};
use crate::{Filesystem, Result};
use nails_teardown::whole_root::nextroot::NEXTROOT;
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
    MountTableUnreadable {
        /// Why it could not be read.
        error: String,
    },
    /// Nothing is mounted at the root: it is a folder on the filesystem
    /// mounted at `mount_point`.
    NotAMountPoint {
        /// Where the filesystem holding the folder is mounted.
        mount_point: PathBuf,
    },
    /// Two filesystems are mounted at the root: `below`, then `above` over it.
    /// A write reaches `above`. Each is shown by its type only: a source or a
    /// device-mapper name can name the tool that opened the volume.
    Covered {
        /// The type of the lower filesystem.
        below: String,
        /// The type of the filesystem on top, which a lookup reaches.
        above: String,
    },
    /// In the hidden session, the filesystem at the root is not the volume the
    /// session entered with.
    NotTheSessionVolume {
        /// The type of the filesystem a lookup reaches.
        fstype: String,
    },
    /// The root lives on storage the decoy uses, or on a disk that a program
    /// serves, which can keep it there (see [`separation`]).
    DecoyStorage {
        /// Where it lives.
        verdict: separation::Verdict,
    },
    /// Where the root lives cannot be told: these inputs exist but could not
    /// be read.
    StorageUnjudged {
        /// The inputs that could not be read.
        unreadable: Vec<PathBuf>,
    },
    /// Nothing shows on which disk the root's storage lies (see
    /// [`separation::Verdict::UntracedStorage`],
    /// [`separation::Verdict::DiskNotFound`],
    /// [`separation::Verdict::UnplacedImageFile`],
    /// [`separation::Verdict::UntracedDevice`] and
    /// [`separation::Verdict::ClaimedDeviceNotFound`]).
    StorageUntraced {
        /// Why it cannot be followed.
        verdict: separation::Verdict,
    },
    /// The root reports the same device as `/`.
    SameDeviceAsRoot,
}

/// A refused hidden root: the kind, and a sentence for the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// What is wrong.
    pub kind: RefusalKind,
    /// Why, naming the paths involved (see [`refusal`]).
    pub reason: String,
    /// The root that was refused, as the caller named it.
    pub root: PathBuf,
}

/// The gate's answer for a hidden root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assessment {
    /// A volume of its own is mounted at the root; writing to it is safe.
    Attached,
    /// The root may be written to, but it lives on the decoy's storage in a
    /// way that only warns (see [`separation::Severity::Warn`]); the refusal
    /// says what to tell the operator.
    Warned(Refusal),
    /// Nothing may be written to the root.
    Refused(Refusal),
}

impl Assessment {
    /// `true` for [`Assessment::Attached`] and [`Assessment::Warned`].
    pub fn is_attached(&self) -> bool {
        !matches!(self, Assessment::Refused(_))
    }
}

/// The refusals the operator overrode (`--allow-decoy-storage`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Allow {
    /// Every refusal stands.
    #[default]
    Nothing,
    /// A root the [`separation`] judge places on the decoy's storage attaches
    /// with a warning: a bind of a folder of `/` too, which the judge places
    /// there before the gate's own test of `/`'s device, and a root on a disk
    /// that a program serves (a network or userspace block device), for an
    /// operator who knows the program keeps the data elsewhere. Everything
    /// else still refuses: a missing root, a folder that is no mount point, a
    /// covered one, storage that cannot be judged or followed, and a root on
    /// `/`'s own device the judge does not place. A root whose data reaches a
    /// ZFS volume, or anything else the judge cannot follow to its disks, is
    /// refused so even when it is one of the decoy's own filesystems.
    DecoyStorage,
}

impl Allow {
    /// Whether this override turns a refusal of `kind` into a warning.
    pub fn covers(self, kind: &RefusalKind) -> bool {
        self == Allow::DecoyStorage && matches!(kind, RefusalKind::DecoyStorage { .. })
    }
}

fn refuse(kind: RefusalKind, root: &Path) -> Result<Assessment> {
    Ok(Assessment::Refused(Refusal::new(kind, root)))
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
    /// 5. **Not the decoy's storage** — outside the session, the
    ///    [`separation`] judge: not a subvolume, bind or image file on a
    ///    filesystem the decoy uses, no device shared with it, a block device
    ///    the judge can follow to its disks, none that a program serves, and
    ///    every input it needs readable (a tmpfs or ramfs root needs none). A
    ///    verdict that only warns attaches with [`Assessment::Warned`].
    /// 6. **Not `/`'s device** — a backstop for a bind of `/`'s own filesystem
    ///    at the root.
    ///
    /// No subprocess, no write, no cache: it reads the mount table, `fstab`,
    /// `crypttab`, sysfs, `/proc/devices` and the ext3 and ext4 journals jbd2
    /// lists in `/proc` on the decoy, and the plan in the session, through
    /// `fs`.
    pub fn assess<F: Filesystem>(fs: &F, root: &Path) -> Result<Assessment> {
        if root.as_os_str().is_empty() {
            return refuse(RefusalKind::NotConfigured, root);
        }
        if !fs.path_exists(root)? {
            return refuse(RefusalKind::Missing, root);
        }
        let table = match fs.mount_table() {
            Ok(table) => table,
            Err(error) => {
                return refuse(
                    RefusalKind::MountTableUnreadable {
                        error: error.to_string(),
                    },
                    root,
                );
            }
        };
        let canonical = fs.canonicalize(root).unwrap_or_else(|_| root.to_path_buf());

        let Some(visible) = top_mount_at(&table, &canonical) else {
            let holder = mount_holding(&table, &canonical)
                .map_or_else(|| PathBuf::from("/"), |m| m.mount_point.clone());
            return refuse(
                RefusalKind::NotAMountPoint {
                    mount_point: holder,
                },
                root,
            );
        };

        if let Some(below) = covered_mount(&table, visible) {
            return refuse(
                RefusalKind::Covered {
                    below: separation::shown_fstype(&below.fstype),
                    above: separation::shown_fstype(&visible.fstype),
                },
                root,
            );
        }

        let in_session = root_is_hidden_overlay(&table, &canonical).is_some();
        if in_session
            && !holds_the_session_volume(
                fs,
                &canonical,
                visible,
                recorded_hidden_dev(fs).as_deref(),
            )
        {
            return refuse(
                RefusalKind::NotTheSessionVolume {
                    fstype: separation::shown_fstype(&visible.fstype),
                },
                root,
            );
        }

        let mut warning = None;
        if !in_session {
            let verdict = separation::judge_storage(fs, &table, visible, Path::new("/")).verdict;
            match (verdict.severity(), verdict) {
                (_, separation::Verdict::CouldNotJudge { unreadable }) => {
                    return refuse(RefusalKind::StorageUnjudged { unreadable }, root);
                }
                (
                    _,
                    verdict @ (separation::Verdict::UntracedStorage { .. }
                    | separation::Verdict::DiskNotFound
                    | separation::Verdict::UnplacedImageFile { .. }
                    | separation::Verdict::UntracedDevice { .. }
                    | separation::Verdict::ClaimedDeviceNotFound),
                ) => {
                    return refuse(RefusalKind::StorageUntraced { verdict }, root);
                }
                (separation::Severity::Pass, _) => {}
                (severity, verdict) => {
                    let refusal = Refusal::new(RefusalKind::DecoyStorage { verdict }, root);
                    if severity == separation::Severity::Refuse {
                        return Ok(Assessment::Refused(refusal));
                    }
                    warning = Some(refusal);
                }
            }
        }

        if fs.device_id(root)? == fs.device_id(Path::new("/"))? {
            return refuse(RefusalKind::SameDeviceAsRoot, root);
        }

        Ok(warning.map_or(Assessment::Attached, Assessment::Warned))
    }

    /// [`assess`](Self::assess), with the refusals `allow` covers turned into
    /// [`Assessment::Warned`].
    pub fn assess_allowing<F: Filesystem>(fs: &F, root: &Path, allow: Allow) -> Result<Assessment> {
        Ok(match Self::assess(fs, root)? {
            Assessment::Refused(refusal) if allow.covers(&refusal.kind) => {
                Assessment::Warned(refusal)
            }
            other => other,
        })
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
                 run `{}` on the hidden volume first",
                root.display(),
                crate::next_step::sudo_line(crate::next_step::NextStep::Init)
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

    /// Where else the filesystem at `root` is mounted on the decoy: its
    /// [`second_mounts`] in this process's mount table, in the order the table
    /// lists them, with what the mount at `root` shows of it. `None` when it is
    /// mounted nowhere else, when nothing is mounted at `root`, which
    /// [`assess`] refuses by itself, and in the hidden session, which enters
    /// with the volume bound at its own path and where the decoy's desktop does
    /// not run. Reads the mount table through `fs`.
    ///
    /// [`assess`]: Self::assess
    pub fn mounted_elsewhere<F: Filesystem>(
        fs: &F,
        root: &Path,
    ) -> Result<Option<MountedElsewhere>> {
        found_elsewhere(fs, root, false)
    }

    /// [`mounted_elsewhere`](Self::mounted_elsewhere) for a root that
    /// [`assess`](Self::assess) placed on a filesystem the decoy uses
    /// ([`separation::Verdict::OnDecoyFilesystem`]), which the operator
    /// accepted with `--allow-decoy-storage`. Two kinds of other mounts of
    /// that filesystem do not count. One is the decoy's own mounts of it,
    /// which the gate's warning is about: the one at `/`, and one that a line
    /// of the decoy's fstab makes ([`separation::decoys_own_mount`]). The
    /// other is a mount that shows none of the root's folder, neither that
    /// folder nor one above or inside it: NixOS's read-only bind of
    /// `/nix/store` beside a bind of a folder of `/`, say, or another
    /// subvolume of a btrfs filesystem. Every other mount counts, as for a
    /// volume of its own: a separate drive mounted at `/srv` by hand as well,
    /// which made the gate place the root on the decoy's storage, a copy that
    /// mount propagation made of the root's mount at a bind line's mount
    /// point, and a mount the decoy makes with no fstab line, such as the
    /// `/home` or `/srv` partition that systemd-gpt-auto-generator mounts, or
    /// ostree's `/sysroot`.
    ///
    /// It reads the judge's inputs again through `fs`, as the gate does
    /// ([`separation::collect`]), and fails when one that exists cannot be
    /// read now.
    pub fn mounted_elsewhere_on_a_decoy_filesystem<F: Filesystem>(
        fs: &F,
        root: &Path,
    ) -> Result<Option<MountedElsewhere>> {
        found_elsewhere(fs, root, true)
    }
}

/// [`HiddenRoot::mounted_elsewhere`], and with `decoy_filesystem`
/// [`HiddenRoot::mounted_elsewhere_on_a_decoy_filesystem`].
fn found_elsewhere<F: Filesystem>(
    fs: &F,
    root: &Path,
    decoy_filesystem: bool,
) -> Result<Option<MountedElsewhere>> {
    let table = fs.mount_table()?;
    let canonical = fs.canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    if root_is_hidden_overlay(&table, &canonical).is_some() {
        return Ok(None);
    }
    let Some(visible) = top_mount_at(&table, &canonical) else {
        return Ok(None);
    };
    let mut second = second_mounts(&table, visible);
    if decoy_filesystem {
        let collected = separation::collect(fs, &table, Path::new("/"));
        if !collected.unreadable.is_empty() {
            let unreadable: Vec<String> = collected
                .unreadable
                .iter()
                .map(|path| path.display().to_string())
                .collect();
            return Err(crate::NailsError::InvalidState(format!(
                "{} could not be read, so where this computer mounts the filesystem at {} \
                 cannot be told",
                unreadable.join(", "),
                root.display()
            )));
        }
        let scene = collected.scene(&table);
        second.retain(|mount| {
            shows_some_of(mount, visible) && !separation::decoys_own_mount(&scene, mount, visible)
        });
    }
    let mounts: Vec<SecondMount> = second
        .into_iter()
        .map(|mount| SecondMount {
            mount_point: mount.mount_point.clone(),
            hidden_under: hidden_under(&table, mount),
        })
        .collect();
    Ok((!mounts.is_empty()).then(|| MountedElsewhere {
        mounts,
        root_shows: separation::sharing(visible),
        root_folder: visible.root.clone(),
    }))
}

/// Whether `mount`, a mount of the filesystem that `visible` shows at a
/// hidden root, shows some of the folder of it that `visible` shows: that
/// folder, a folder above it, or one inside it. A bind of a folder beside it,
/// or another btrfs subvolume, shows none of it: its files cannot be reached
/// there.
fn shows_some_of(mount: &MountEntry, visible: &MountEntry) -> bool {
    visible.root.starts_with(&mount.root) || mount.root.starts_with(&visible.root)
}

/// The volume at a hidden root, mounted at other places too (see
/// [`HiddenRoot::mounted_elsewhere`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountedElsewhere {
    /// The other mounts, in the order the mount table lists them; never empty.
    pub mounts: Vec<SecondMount>,
    /// What of the filesystem the mount at the root shows: all of it, a
    /// folder of it bound there, or a btrfs subvolume of it.
    pub root_shows: separation::Sharing,
    /// The folder or subvolume of the filesystem that the mount at the root
    /// shows, as the mount table names it: `/` for all of it.
    pub root_folder: PathBuf,
}

/// Another mount of the volume at a hidden root (see [`second_mounts`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecondMount {
    /// Where it is mounted.
    pub mount_point: PathBuf,
    /// Where the mount that hides it is mounted, when a lookup of
    /// `mount_point` ends in another mount: one stacked on it at the same
    /// place, or one on a folder above it, the root's own mount included.
    /// `umount` given `mount_point` then reaches that mount, or none.
    pub hidden_under: Option<PathBuf>,
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

/// The mount stacked on the hidden volume at `root`: the mount a lookup of
/// `root` reaches, when it is not the volume.
///
/// `recorded` is the volume's device as the session plan records it
/// (`hidden_dev`); a mount with another device is not the volume, while a
/// second bind of the volume itself is. Without a record, the visible mount
/// counts when another filesystem lies below it at `root`.
///
/// A mount on a parent of `root` hides the volume as well (`mount /dev/sdc1
/// /mnt` over a root at `/mnt/data`): when the volume is still in the table at
/// `root` but a lookup ends in a mount on one of its parents, that mount is the
/// cover. `None` when the volume is not mounted at `root` at all, which is no
/// cover but a volume that is gone. `root` is the resolved path.
pub fn shadowing_mount<'a>(
    table: &'a [MountEntry],
    root: &Path,
    recorded: Option<&str>,
) -> Option<&'a MountEntry> {
    let Some(visible) = top_mount_at(table, root) else {
        return covering_parent(table, root, recorded);
    };
    let covered = match recorded {
        Some(dev) => visible.dev != dev,
        None => covered_mount(table, visible).is_some(),
    };
    covered.then_some(visible)
}

/// The mount on a parent of `root` that a lookup of `root` ends in, when it
/// hides the volume still mounted at `root` (the recorded device, if there is
/// a record).
fn covering_parent<'a>(
    table: &'a [MountEntry],
    root: &Path,
    recorded: Option<&str>,
) -> Option<&'a MountEntry> {
    let volume = table
        .iter()
        .find(|m| m.mount_point == root && recorded.is_none_or(|dev| m.dev == dev))?;
    mount_holding(table, root).filter(|holder| holder.dev != volume.dev)
}

/// The other mounts of the filesystem mounted at `visible`, the visible mount
/// at the hidden root: the same superblock (`major:minor`) mounted at another
/// place in `table` as well, in the order the table lists them.
///
/// A desktop that mounts a drive by itself (gnome-shell through gvfs and
/// udisks2, KDE Plasma's Device Auto-Mount, udiskie) can mount the filesystem
/// of a volume unlocked from a terminal a second time, under `/media/<user>` or
/// `/run/media/<user>`, where the decoy's desktop reaches its files. Every
/// mount of the superblock in the table counts, wherever it lies and whether a
/// later mount hides it or not: a bind of a folder of it, and on btrfs another
/// subvolume of it, which the table shows with the same device. A mount in
/// another mount namespace, which this table does not list, is not seen. Two
/// kinds do not count: a mount at the root's own mount point, so a bind of the
/// volume stacked at the root is the root, and one in the tree of the next
/// root while one is mounted at [`NEXTROOT`], where an entry binds the volume
/// at its own path (the session-state check refuses that tree by itself). For
/// a root on a filesystem the decoy uses, which the operator accepted,
/// [`HiddenRoot::mounted_elsewhere_on_a_decoy_filesystem`] leaves out the
/// decoy's own mounts of it and those that show none of the root's folder.
pub fn second_mounts<'a>(table: &'a [MountEntry], visible: &MountEntry) -> Vec<&'a MountEntry> {
    let nextroot = Path::new(NEXTROOT);
    let next_root_mounted = table.iter().any(|m| m.mount_point == nextroot);
    table
        .iter()
        .filter(|m| m.dev == visible.dev && m.mount_point != visible.mount_point)
        .filter(|m| !(next_root_mounted && m.mount_point.starts_with(nextroot)))
        .collect()
}

/// Where the mount that hides `mount` is mounted, when a lookup of its mount
/// point ends in another mount (see [`SecondMount::hidden_under`]).
fn hidden_under(table: &[MountEntry], mount: &MountEntry) -> Option<PathBuf> {
    mount_holding(table, &mount.mount_point)
        .filter(|reached| reached.mount_id != mount.mount_id)
        .map(|reached| reached.mount_point.clone())
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
    recorded_plan(fs)?.hidden_dev
}

/// Why the session's hidden root is not a volume of its own, when its
/// activation accepted that with `--allow-decoy-storage` (the plan in `/run`).
pub fn recorded_acceptance<F: Filesystem>(fs: &F) -> Option<String> {
    recorded_plan(fs)?.accepted_decoy_storage
}

/// The session plan in `/run`, if one can be read.
fn recorded_plan<F: Filesystem>(fs: &F) -> Option<nails_teardown::whole_root::plan::Plan> {
    let path = nails_teardown::whole_root::plan::default_plan_path();
    let text = fs.read_file_content(&path).ok()?;
    nails_teardown::whole_root::plan::Plan::from_json(&text).ok()
}

/// Refuse a state write (the state file or its `.lock`) unless `dir` lies on the
/// hidden volume mounted at `root`.
///
/// Every manager state write and every command's state lock goes through it.
/// Only `init` writes its first state file without it, once the attach gate
/// (with `--allow-decoy-storage`, if the operator gave it) has passed the
/// target.
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
    ensure_state_dir_attached_allowing(fs, root, dir, Allow::Nothing)
}

/// [`ensure_state_dir_attached`] with the refusals `allow` covers accepted: an
/// activation the operator ran with `--allow-decoy-storage` keeps its state on
/// the root it accepted. `dir` must still lie under the root, on the root's own
/// mount.
pub fn ensure_state_dir_attached_allowing<F: Filesystem>(
    fs: &F,
    root: &Path,
    dir: &Path,
    allow: Allow,
) -> Result<()> {
    #[cfg(any(test, feature = "test-hooks"))]
    if crate::runtime_safety::in_unit_tests() && !state_attach_probe::enforced() {
        return Ok(());
    }
    let refused = |reason: String| {
        Err(crate::NailsError::InvalidState(format!(
            "refusing to write state outside the mounted hidden volume: {reason}"
        )))
    };
    if let Assessment::Refused(refusal) = HiddenRoot::assess_allowing(fs, root, allow)? {
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
    let root_mount = mount_holding(&table, &root).map(|m| m.mount_id);
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
