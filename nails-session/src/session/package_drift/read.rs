// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reading the decoy's package databases and what the upper holds of them,
//! for the judges.
//!
//! A path is looked up one component at a time, each seen not to be a
//! symbolic link before the next is looked up below it, so no lookup follows
//! a link on the decoy. In the upper, a whiteout or a link on the way is a
//! deletion or a replacement by a hidden session. A directory a hidden
//! session deleted and made again (an opaque one) counts as merged with the
//! decoy's: no package manager does that to its database.

use super::{Database, Doubt, Verdict, judge_dpkg, judge_pacman, judge_rpm};
use crate::filesystem::Filesystem;
use crate::session::layout::Layout;
use nails_base::NailsError;
use nails_base::packages::{dpkg, pacman, rpm};
use nails_teardown::mountinfo::MountEntry;
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

/// Each package database's verdict, with its path as hidden sessions see it,
/// in the order of [`Database::ALL`]: the decoy root `root`, read through
/// `fs`, against hidden sessions' copies in `layout`. `mounts` is the mount
/// table, from which the decoy's filesystems below `root` are taken: a
/// database on one of its own is judged against that filesystem's upper.
/// `None` says the mount table could not be read: then no verdict that needs
/// hidden sessions' copy is reached, since where that copy lies is not known.
/// `privileged` says whether this process reads the decoy's database without
/// changing its access time; when it does not, a verdict that needs the
/// database read is [`Doubt::NeedsRoot`].
pub fn verdicts<F: Filesystem>(
    fs: &F,
    root: &Path,
    layout: &Layout,
    mounts: Option<&[MountEntry]>,
    privileged: bool,
) -> Vec<(Database, String, Verdict)> {
    let reader = Reader {
        fs,
        root,
        layout,
        mounts: mounts
            .unwrap_or_default()
            .iter()
            .filter_map(|mount| {
                let below = mount.mount_point.strip_prefix(root).ok()?;
                Some(Path::new("/").join(below))
            })
            .collect(),
        privileged,
    };
    let (rpm_at, rpm) = reader.rpm();
    let verdicts = vec![
        (Database::Dpkg, format!("/{}", dpkg::STATUS), reader.dpkg()),
        (
            Database::Pacman,
            format!("/{}", pacman::LOCAL),
            reader.pacman(),
        ),
        (Database::Rpm, rpm_at, rpm),
    ];
    if mounts.is_some() {
        return verdicts;
    }
    verdicts
        .into_iter()
        .map(|(database, at, verdict)| {
            let verdict = match verdict {
                Verdict::Absent | Verdict::Unknown(_) => verdict,
                _ => Verdict::Unknown(Doubt::Other(
                    "the mount table cannot be read, so where hidden sessions keep their copy \
                     is not known"
                        .to_string(),
                )),
            };
            (database, at, verdict)
        })
        .collect()
}

/// What the decoy has at a path.
enum OnDecoy {
    /// Nothing of the kind asked for.
    Missing,
    /// A symbolic link on the way, at the path given.
    Linked(String),
    /// What was asked for.
    Present,
}

/// What the upper holds at a path.
enum InUpper {
    /// Nothing: the decoy's shows through.
    Nothing,
    /// A deletion (`deleted`) or a replacement of the path, or of a
    /// directory on its way, at `path` as hidden sessions see it.
    Gone {
        /// The path hidden sessions changed.
        path: String,
        /// Whether they deleted it rather than replaced it.
        deleted: bool,
    },
    /// What was asked for, at this path in the upper.
    Here(PathBuf),
    /// The entry cannot be read, for the reason given.
    Unreadable(String),
    /// The entry cannot be read without root.
    NeedsRoot,
}

/// The reads of one judgement.
struct Reader<'a, F: Filesystem> {
    fs: &'a F,
    root: &'a Path,
    layout: &'a Layout,
    /// The decoy's mount points below its root, as the decoy sees them.
    mounts: Vec<PathBuf>,
    privileged: bool,
}

impl<F: Filesystem> Reader<'_, F> {
    /// Look up `rel` below the decoy root: a file, or a directory when `dir`.
    fn on_decoy(&self, rel: &str, dir: bool) -> OnDecoy {
        let mut path = self.root.to_path_buf();
        let mut shown = PathBuf::from("/");
        for component in Path::new(rel).components() {
            path.push(component);
            shown.push(component);
            if self.fs.is_symlink(&path).unwrap_or(false) {
                return OnDecoy::Linked(shown.display().to_string());
            }
        }
        let present = self.fs.path_exists(&path).unwrap_or(false)
            && self.fs.is_directory(&path).unwrap_or(false) == dir;
        if present {
            OnDecoy::Present
        } else {
            OnDecoy::Missing
        }
    }

    /// The upper that holds hidden sessions' changes to `rel` (below the
    /// decoy root), the path of `rel` below it, and the mount point of the
    /// filesystem it is on: the root overlay's upper, or the upper of the
    /// decoy filesystem mounted at the longest mount point above `rel`.
    fn upper_of(&self, rel: &str) -> (PathBuf, PathBuf, PathBuf) {
        let path = Path::new("/").join(rel);
        let mount = self
            .mounts
            .iter()
            .filter(|mount| mount.as_path() != Path::new("/"))
            .filter(|mount| path.starts_with(mount) && path != **mount)
            .max_by_key(|mount| mount.components().count());
        match mount {
            Some(mount) => {
                let below = path.strip_prefix(mount).unwrap_or(&path).to_path_buf();
                (self.layout.mount_layers(mount).0, below, mount.clone())
            }
            None => (self.layout.upper(), PathBuf::from(rel), PathBuf::from("/")),
        }
    }

    /// What the upper `base` holds at `rel`, the path of the filesystem
    /// mounted at `mount`: a file, or a directory when `dir`.
    fn in_upper(&self, base: &Path, rel: &Path, mount: &Path, dir: bool) -> InUpper {
        let mut path = base.to_path_buf();
        let mut shown = mount.to_path_buf();
        let components: Vec<Component<'_>> = rel.components().collect();
        for (i, component) in components.iter().enumerate() {
            path.push(component);
            shown.push(component);
            let last = i + 1 == components.len();
            match self.held(&path, &shown, dir || !last, last) {
                Ok(Some(found)) => return found,
                Ok(None) => {}
                Err(e) if !self.privileged && denied(&e) => return InUpper::NeedsRoot,
                Err(e) => {
                    return InUpper::Unreadable(format!(
                        "what hidden sessions keep at {} cannot be read ({e})",
                        shown.display()
                    ));
                }
            }
        }
        InUpper::Nothing
    }

    /// What the upper holds at `path`, the path `shown` as hidden sessions
    /// see it: a directory when `dir`, else a file; `last` when it is the
    /// path asked for rather than one on its way. `None` for a directory on
    /// the way, or one the upper lacks, where the walk goes on.
    fn held(
        &self,
        path: &Path,
        shown: &Path,
        dir: bool,
        last: bool,
    ) -> crate::error::Result<Option<InUpper>> {
        let fs = self.fs;
        let gone = |deleted| InUpper::Gone {
            path: shown.display().to_string(),
            deleted,
        };
        if fs.is_overlay_whiteout(path)? {
            return Ok(Some(gone(true)));
        }
        if fs.is_symlink(path)? {
            return Ok(Some(gone(false)));
        }
        if !fs.path_exists(path)? {
            // A lookup that fails says the entry is missing, so the
            // directory's listing tells a missing entry from one that cannot
            // be looked up.
            self.not_listed(path)?;
            // Nothing below an entry the upper lacks.
            return Ok(last.then_some(InUpper::Nothing));
        }
        if fs.is_directory(path)? != dir {
            return Ok(Some(gone(false)));
        }
        Ok(last.then(|| InUpper::Here(path.to_path_buf())))
    }

    /// Ok when the upper's directory of `path` does not list it, or does not
    /// exist; an error when that directory cannot be listed, or lists `path`
    /// although looking it up failed.
    fn not_listed(&self, path: &Path) -> crate::error::Result<()> {
        let Some(parent) = path.parent() else {
            return Ok(());
        };
        match self.fs.list_directory(parent) {
            Ok(entries) if entries.iter().any(|entry| entry == path) => Err(NailsError::io(
                path,
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "listed, but it cannot be looked up",
                ),
            )),
            Ok(_) => Ok(()),
            Err(e) if missing(&e) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// What the upper holds of the database at `rel`, as [`Self::in_upper`]
    /// reads it with the upper [`Self::upper_of`] gives, and that upper and
    /// the path below it.
    fn copy_of(&self, rel: &str, dir: bool) -> (InUpper, PathBuf, PathBuf) {
        let (base, below, mount) = self.upper_of(rel);
        (self.in_upper(&base, &below, &mount, dir), base, below)
    }

    /// dpkg's record.
    fn dpkg(&self) -> Verdict {
        if let Some(verdict) = decoy_verdict(self.on_decoy(dpkg::STATUS, false)) {
            return verdict;
        }
        let (copy, base, below) = self.copy_of(dpkg::STATUS, false);
        let copy = match upper_verdict(copy) {
            Ok(path) => path,
            Err(verdict) => return verdict,
        };
        if !self.privileged {
            return Verdict::Unknown(Doubt::NeedsRoot);
        }
        let decoy = match dpkg::read_status(self.fs, self.root) {
            Ok(Some(packages)) if packages.is_empty() => {
                return no_package(&format!("/{} on the decoy", dpkg::STATUS));
            }
            Ok(Some(packages)) => packages,
            Ok(None) => return Verdict::Absent,
            Err(e) => return unreadable(&format!("/{} on the decoy", dpkg::STATUS), &e),
        };
        let hidden = match dpkg::read_status_file(self.fs, &copy) {
            Ok(Some(packages)) if packages.is_empty() => {
                return no_package(&format!("hidden sessions' copy of /{}", dpkg::STATUS));
            }
            Ok(Some(packages)) => packages,
            Ok(None) => return Verdict::Shared,
            Err(e) => {
                return unreadable(&format!("hidden sessions' copy of /{}", dpkg::STATUS), &e);
            }
        };
        let info = base.join(below.parent().unwrap_or(&below)).join("info");
        let changed = match self.fs.list_directory(&info) {
            Ok(entries) => owners(&entries),
            Err(e) if missing(&e) => BTreeSet::new(),
            Err(e) => return unreadable(&format!("hidden sessions' copy of /{}", dpkg::INFO), &e),
        };
        judge_dpkg(&decoy, &hidden, &changed)
    }

    /// pacman's database.
    fn pacman(&self) -> Verdict {
        if let Some(verdict) = decoy_verdict(self.on_decoy(pacman::LOCAL, true)) {
            return verdict;
        }
        let (copy, _, _) = self.copy_of(pacman::LOCAL, true);
        let dir = match upper_verdict(copy) {
            Ok(path) => path,
            Err(verdict) => return verdict,
        };
        let entries = match self.fs.list_directory(&dir) {
            Ok(entries) => entries,
            Err(e) => {
                return unreadable(&format!("hidden sessions' copy of /{}", pacman::LOCAL), &e);
            }
        };
        let mut kept = Vec::new();
        let mut removed = Vec::new();
        for entry in &entries {
            let Some(package) = entry
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(pacman::parse_entry)
            else {
                continue;
            };
            if self.fs.is_overlay_whiteout(entry).unwrap_or(false) {
                removed.push(package);
            } else {
                kept.push(package);
            }
        }
        if kept.is_empty() && removed.is_empty() {
            return Verdict::Shared;
        }
        if !self.privileged {
            return Verdict::Unknown(Doubt::NeedsRoot);
        }
        let decoy = match pacman::read_local(self.fs, self.root) {
            Ok(Some(packages)) => packages,
            Ok(None) => return Verdict::Absent,
            Err(e) => return unreadable(&format!("/{} on the decoy", pacman::LOCAL), &e),
        };
        judge_pacman(&decoy, &kept, &removed)
    }

    /// rpm's database, with its path as hidden sessions see it.
    fn rpm(&self) -> (String, Verdict) {
        let (rel, decoy) = match rpm::locate(self.fs, self.root) {
            Ok(Some(located)) => located,
            Ok(None) => return (format!("/{}", rpm::DATABASES[0]), Verdict::Absent),
            Err(e) => {
                let at = format!("/{}", rpm::DATABASES[0]);
                let verdict = unreadable(&format!("{at} on the decoy"), &e);
                return (at, verdict);
            }
        };
        let at = format!("/{rel}");
        let (copy, _, _) = self.copy_of(rel, false);
        let copy = match upper_verdict(copy) {
            Ok(path) => path,
            Err(verdict) => return (at, verdict),
        };
        let verdict = match rpm::stamp(self.fs, &copy) {
            Ok(Some(hidden)) => judge_rpm(decoy, hidden),
            Ok(None) => Verdict::Shared,
            Err(e) => unreadable(&format!("hidden sessions' copy of {at}"), &e),
        };
        (at, verdict)
    }
}

/// The verdict the decoy's side gives on its own: `None` when the decoy has
/// the database and the upper decides.
fn decoy_verdict(on_decoy: OnDecoy) -> Option<Verdict> {
    match on_decoy {
        OnDecoy::Present => None,
        OnDecoy::Missing => Some(Verdict::Absent),
        OnDecoy::Linked(at) => Some(Verdict::Unknown(Doubt::Other(format!(
            "{at} on the decoy is a symbolic link"
        )))),
    }
}

/// The path of hidden sessions' copy, or the verdict the upper gives
/// without one.
fn upper_verdict(in_upper: InUpper) -> std::result::Result<PathBuf, Verdict> {
    match in_upper {
        InUpper::Here(path) => Ok(path),
        InUpper::Nothing => Err(Verdict::Shared),
        InUpper::Gone { path, deleted } => Err(Verdict::Gone { path, deleted }),
        InUpper::Unreadable(reason) => Err(Verdict::Unknown(Doubt::Other(reason))),
        InUpper::NeedsRoot => Err(Verdict::Unknown(Doubt::NeedsRoot)),
    }
}

/// The verdict for the dpkg record `what` that holds no package NAILS reads:
/// no system dpkg runs on has none, so its format is one NAILS does not know.
fn no_package(what: &str) -> Verdict {
    Verdict::Unknown(Doubt::Other(format!(
        "{what} records no package NAILS can read"
    )))
}

/// The verdict for `what` that cannot be read.
fn unreadable(what: &str, error: &NailsError) -> Verdict {
    Verdict::Unknown(Doubt::Other(format!("{what} cannot be read ({error})")))
}

/// Whether `error` says a path, or a directory on its way, does not exist.
fn missing(error: &NailsError) -> bool {
    matches!(
        error.io_kind(),
        Some(std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory)
    )
}

/// Whether `error` says this process may not look at a path.
fn denied(error: &NailsError) -> bool {
    error.io_kind() == Some(std::io::ErrorKind::PermissionDenied)
}

/// The packages the entries of dpkg's `info` directory belong to.
fn owners(entries: &[PathBuf]) -> BTreeSet<(String, Option<String>)> {
    entries
        .iter()
        .filter_map(|entry| entry.file_name()?.to_str())
        .filter_map(dpkg::info_owner)
        .map(|(name, arch)| (name.to_string(), arch.map(str::to_string)))
        .collect()
}
