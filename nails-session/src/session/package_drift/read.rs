// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reading the decoy's package databases and what the upper holds of them,
//! for the judges.
//!
//! A path is looked up one component at a time, each seen not to be a
//! symbolic link before the next is looked up below it, so no lookup follows
//! a link on the decoy; a package's file rpm records through a link is looked
//! up where the link leads by rpm's own records ([`rpm::Links`]), never by
//! the link on the disk. In the upper, a whiteout or a link on the way is a
//! deletion or a replacement by a hidden session. A directory a hidden
//! session deleted and made again (an opaque one) counts as merged with the
//! decoy's: no package manager does that to its database.
//!
//! Where the mount table cannot be read, the decoy's filesystems are told
//! from the kernel's own word on each directory above a database or a
//! package's file: `statx` says whether a path is the root of a mount
//! ([`Filesystem::mount_root`]). It is asked from the top down, and a link,
//! an automount point and a directory the decoy lacks end the walk: the
//! lookup of anything below the first follows it, of anything below the
//! second mounts it, and below the third is no mount point of the decoy's.

use super::{Database, Doubt, RpmKey, Verdict, judge_dpkg, judge_pacman, judge_rpm, rpm_differing};
use crate::filesystem::{Filesystem, MountRoot};
use crate::session::layout::Layout;
use nails_base::NailsError;
use nails_base::packages::{self, dpkg, pacman, rpm};
use nails_teardown::mountinfo::MountEntry;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// Each package database's verdict, with its path as hidden sessions see it,
/// in the order of [`Database::ALL`]: the decoy root `root`, read through
/// `fs`, against hidden sessions' copies in `layout`. `mounts` is the mount
/// table, from which the decoy's filesystems below `root` are taken: a
/// database on one of its own is judged against that filesystem's upper.
/// `None` says the mount table could not be read: then the kernel says of
/// each directory above a database whether it is a mount point, and where it
/// does not say, no verdict that needs hidden sessions' copy is reached.
/// `privileged` says whether this process reads the decoy's database without
/// changing its access time; when it does not, a verdict that needs the
/// database read is [`Doubt::NeedsRoot`], unless the mount table says the
/// filesystem the database is on is mounted `noatime`, where no read changes
/// an access time.
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
        mounts: mounts.map(|mounts| {
            mounts
                .iter()
                .filter_map(|mount| {
                    let below = mount.mount_point.strip_prefix(root).ok()?;
                    Some(Path::new("/").join(below))
                })
                .collect()
        }),
        table: mounts,
        probed: RefCell::default(),
        listed: RefCell::default(),
        resolved: RefCell::default(),
        privileged,
    };
    let (rpm_at, rpm) = reader.rpm();
    vec![
        (Database::Dpkg, format!("/{}", dpkg::STATUS), reader.dpkg()),
        (
            Database::Pacman,
            format!("/{}", pacman::LOCAL),
            reader.pacman(),
        ),
        (Database::Rpm, rpm_at, rpm),
    ]
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

/// What the kernel said of a directory of the decoy, without the mount
/// table.
#[derive(Debug, Clone, Copy)]
enum Probed {
    /// The root of a mount.
    Mount,
    /// No mount's root.
    Plain,
    /// A symbolic link, or nothing the decoy has: nothing below it is asked
    /// about.
    End,
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
    /// The decoy's mount points below its root, as the decoy sees them:
    /// `None` when the mount table cannot be read.
    mounts: Option<Vec<PathBuf>>,
    /// The mount table, for the options of the decoy's filesystems.
    table: Option<&'a [MountEntry]>,
    /// Without the mount table: what the kernel said of a directory, as the
    /// decoy sees it.
    probed: RefCell<BTreeMap<PathBuf, Probed>>,
    /// The names of the entries of each directory of an upper listed for
    /// rpm's files: `None` for one that does not exist.
    listed: RefCell<BTreeMap<PathBuf, Option<BTreeSet<OsString>>>>,
    /// Each directory of rpm's files as recorded, and where it lies once the
    /// links rpm's records give on its way are followed: each path exactly
    /// as long as its bytes, which is what the budget is charged for.
    resolved: RefCell<BTreeMap<Box<str>, Box<str>>>,
    privileged: bool,
}

impl<F: Filesystem> Reader<'_, F> {
    /// Whether this process may read `rel` below the decoy root: as root,
    /// which reads with `O_NOATIME`, or where the filesystem `rel` is on is
    /// mounted `noatime` (the topmost of the deepest mounts above it, as the
    /// mount table lists them), where the kernel changes no access time on
    /// any read.
    fn may_read(&self, rel: &str) -> bool {
        if self.privileged {
            return true;
        }
        let path = self.root.join(rel);
        self.table
            .and_then(|table| {
                table
                    .iter()
                    .filter(|mount| path.starts_with(&mount.mount_point))
                    .max_by_key(|mount| mount.mount_point.components().count())
            })
            .is_some_and(|mount| {
                mount
                    .mount_opts
                    .split(',')
                    .any(|option| option == "noatime")
            })
    }

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
    /// decoy filesystem mounted at the longest mount point above `rel`. A
    /// verdict when that mount point cannot be told.
    fn upper_of(&self, rel: &str) -> std::result::Result<(PathBuf, PathBuf, PathBuf), Verdict> {
        let path = Path::new("/").join(rel);
        let mount = match &self.mounts {
            Some(mounts) => mounts
                .iter()
                .filter(|mount| mount.as_path() != Path::new("/"))
                .filter(|mount| path.starts_with(mount) && path != **mount)
                .max_by_key(|mount| mount.components().count())
                .cloned(),
            None => self.probe(&path)?,
        };
        Ok(match mount {
            Some(mount) => {
                let below = path.strip_prefix(&mount).unwrap_or(&path).to_path_buf();
                (self.layout.mount_layers(&mount).0, below, mount)
            }
            None => (self.layout.upper(), PathBuf::from(rel), PathBuf::from("/")),
        })
    }

    /// Without the mount table: the deepest directory above `path` (as the
    /// decoy sees it), other than `/`, that the kernel says is a mount point.
    /// The directories are asked about from the top down, and the walk ends
    /// at a link and at a directory the decoy lacks ([`Self::probe_dir`]).
    fn probe(&self, path: &Path) -> std::result::Result<Option<PathBuf>, Verdict> {
        let dirs: Vec<&Path> = path
            .ancestors()
            .skip(1)
            .filter(|dir| *dir != Path::new("/"))
            .collect();
        let mut deepest = None;
        for dir in dirs.into_iter().rev() {
            match self.probe_dir(dir)? {
                Probed::Mount => deepest = Some(dir.to_path_buf()),
                Probed::Plain => {}
                Probed::End => break,
            }
        }
        Ok(deepest)
    }

    /// What the kernel says of `dir` (as the decoy sees it), all of whose
    /// directories above were seen to be neither links nor automount points:
    /// one `statx` that follows no link and mounts nothing there
    /// ([`Filesystem::mount_root`]). Below a link nothing is asked about, since
    /// the lookup of anything there would follow it and change its access
    /// time, nor below an automount point, which the lookup would mount, and a
    /// path the decoy lacks is no mount point.
    fn probe_dir(&self, dir: &Path) -> std::result::Result<Probed, Verdict> {
        if let Some(&probed) = self.probed.borrow().get(dir) {
            return Ok(probed);
        }
        let on_decoy = self.root.join(dir.strip_prefix("/").unwrap_or(dir));
        // One `statx` that follows no link and mounts no automount point.
        let probed = match self.fs.mount_root(&on_decoy) {
            Ok(MountRoot::Link | MountRoot::Automount) => Probed::End,
            Ok(MountRoot::Entry(Some(true))) => Probed::Mount,
            Ok(MountRoot::Entry(Some(false))) => Probed::Plain,
            Ok(MountRoot::Entry(None)) => {
                return Err(Verdict::Unknown(Doubt::Other(format!(
                    "the mount table cannot be read, and the kernel does not say whether {} is \
                     a mount point",
                    dir.display()
                ))));
            }
            Err(e) if missing(&e) => Probed::End,
            Err(e) => {
                return Err(Verdict::Unknown(Doubt::Other(format!(
                    "the mount table cannot be read, nor whether {} is a mount point ({e})",
                    dir.display()
                ))));
            }
        };
        self.probed.borrow_mut().insert(dir.to_path_buf(), probed);
        Ok(probed)
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
    fn copy_of(
        &self,
        rel: &str,
        dir: bool,
    ) -> std::result::Result<(InUpper, PathBuf, PathBuf), Verdict> {
        let (base, below, mount) = self.upper_of(rel)?;
        Ok((self.in_upper(&base, &below, &mount, dir), base, below))
    }

    /// dpkg's record.
    fn dpkg(&self) -> Verdict {
        if let Some(verdict) = decoy_verdict(self.on_decoy(dpkg::STATUS, false)) {
            return verdict;
        }
        let (copy, base, below) = match self.copy_of(dpkg::STATUS, false) {
            Ok(copy) => copy,
            Err(verdict) => return verdict,
        };
        let copy = match upper_verdict(copy) {
            Ok(path) => path,
            Err(verdict) => return verdict,
        };
        if !self.may_read(dpkg::STATUS) {
            return Verdict::Unknown(Doubt::NeedsRoot);
        }
        let on_decoy = format!("/{} on the decoy", dpkg::STATUS);
        let in_hidden = format!("hidden sessions' copy of /{}", dpkg::STATUS);
        let decoy = match packages::read_bounded(self.fs, &self.root.join(dpkg::STATUS)) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Verdict::Absent,
            Err(e) => return unreadable(&on_decoy, &e),
        };
        let hidden = match packages::read_bounded(self.fs, &copy) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Verdict::Shared,
            Err(e) => return unreadable(&in_hidden, &e),
        };
        // A copy that holds what the decoy's record holds follows it, whatever
        // the format.
        if decoy == hidden {
            return Verdict::Follows { own: 0 };
        }
        let parse = |bytes: &[u8]| dpkg::parse_status(&String::from_utf8_lossy(bytes));
        let (decoy, hidden) = (parse(&decoy), parse(&hidden));
        if decoy.is_empty() {
            return no_package(&on_decoy);
        }
        if hidden.is_empty() {
            return no_package(&in_hidden);
        }
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
        let (copy, _, _) = match self.copy_of(pacman::LOCAL, true) {
            Ok(copy) => copy,
            Err(verdict) => return verdict,
        };
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
        if !self.may_read(pacman::LOCAL) {
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
        let rel = match rpm::locate(self.fs, self.root) {
            Ok(Some((rel, _))) => rel,
            Ok(None) => return (format!("/{}", rpm::DATABASES[0]), Verdict::Absent),
            Err(e) => {
                let at = format!("/{}", rpm::DATABASES[0]);
                let verdict = unreadable(&format!("{at} on the decoy"), &e);
                return (at, verdict);
            }
        };
        let at = format!("/{rel}");
        let verdict = self.rpm_at(rel, &at).unwrap_or_else(|verdict| verdict);
        (at, verdict)
    }

    /// rpm's database at `rel` below the decoy root, at `at` as hidden
    /// sessions see it.
    fn rpm_at(&self, rel: &str, at: &str) -> std::result::Result<Verdict, Verdict> {
        let on_decoy = self.root.join(rel);
        let beside = |suffix: &str| format!("{rel}{suffix}");
        for suffix in [rpm::WAL, rpm::JOURNAL] {
            let path = self.root.join(beside(suffix));
            if self.fs.is_symlink(&path).unwrap_or(false) {
                return Err(Verdict::Unknown(Doubt::Other(format!(
                    "{at}{suffix} on the decoy is a symbolic link"
                ))));
            }
        }
        let decoy = rpm::Files::beside(self.fs, &on_decoy)
            .map_err(|e| unreadable(&format!("{at} on the decoy"), &e))?;
        // What hidden sessions see of each of the three files: their own copy
        // in the upper, the decoy's, or none where they deleted it.
        let mut held = false;
        let mut view = |suffix: &str,
                        decoy: Option<&PathBuf>|
         -> std::result::Result<Option<PathBuf>, Verdict> {
            let (copy, _, _) = self.copy_of(&beside(suffix), false)?;
            match copy {
                InUpper::Here(path) => {
                    held = true;
                    Ok(Some(path))
                }
                InUpper::Nothing => Ok(decoy.cloned()),
                InUpper::Gone { path, deleted } if suffix.is_empty() => {
                    Err(Verdict::Gone { path, deleted })
                }
                InUpper::Gone { .. } => {
                    held = true;
                    Ok(None)
                }
                InUpper::Unreadable(reason) => Err(Verdict::Unknown(Doubt::Other(reason))),
                InUpper::NeedsRoot => Err(Verdict::Unknown(Doubt::NeedsRoot)),
            }
        };
        let database = view("", Some(&decoy.database))?;
        let wal = view(rpm::WAL, decoy.wal.as_ref())?;
        let journal = view(rpm::JOURNAL, decoy.journal.as_ref())?;
        if !held {
            return Ok(Verdict::Shared);
        }
        if !self.may_read(rel) {
            return Err(Verdict::Unknown(Doubt::NeedsRoot));
        }
        let hidden = rpm::Files {
            database: database.unwrap_or_else(|| decoy.database.clone()),
            wal,
            journal,
        };
        // The packages of both databases share one budget of memory.
        let mut budget = rpm::Budget::default();
        let decoy = rpm::read_packages(self.fs, &decoy, &mut budget)
            .map_err(|e| unreadable(&format!("{at} on the decoy"), &e))?;
        let hidden = rpm::read_packages(self.fs, &hidden, &mut budget)
            .map_err(|e| unreadable(&format!("hidden sessions' copy of {at}"), &e))?;
        // The links they record, and the paths resolved through them, from
        // the same budget.
        let links = rpm::Links::of(decoy.iter().chain(&hidden), &mut budget)
            .map_err(|e| too_much(at, &e))?;
        let mut changed: BTreeSet<RpmKey> = BTreeSet::new();
        for (key, packages) in rpm_differing(&decoy, &hidden) {
            if self.changed_files(&packages, &links, at, &mut budget)? {
                changed.insert(key);
            }
        }
        Ok(judge_rpm(&decoy, &hidden, &changed))
    }

    /// Whether the upper holds, or deleted, one of the own files
    /// ([`rpm::File::is_own`]) of `packages`, each where rpm installed it
    /// ([`Self::installed_at`], through `links`, with what it keeps taken from
    /// `budget`): whether a hidden session installed, updated or removed one
    /// of them. `at` is the database's path as hidden sessions see it.
    fn changed_files(
        &self,
        packages: &[&rpm::Package],
        links: &rpm::Links,
        at: &str,
        budget: &mut rpm::Budget,
    ) -> std::result::Result<bool, Verdict> {
        for package in packages {
            for file in package.files.iter().filter(|file| file.is_own()) {
                let path = self.installed_at(package, file, links, at, budget)?;
                let rel = path.trim_start_matches('/');
                if rel.is_empty() {
                    continue;
                }
                let (base, below, _) = self.upper_of(rel)?;
                if self.touched(&base, &below)? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Where `file` of `package` lies: its directory with the links on its
    /// way that `links`, rpm's own records, give followed, and its name. rpm
    /// installs a file through such a link, so the upper holds the kernel's
    /// modules Fedora records below `/lib`, a link to `usr/lib`, below
    /// `/usr/lib`. Each directory is resolved once and kept, with what it
    /// keeps taken from `budget`. A verdict when its links make a loop or
    /// lead to a path too long for any system ([`rpm::Unresolved`]), or when
    /// the budget runs out.
    fn installed_at(
        &self,
        package: &rpm::Package,
        file: &rpm::File,
        links: &rpm::Links,
        at: &str,
        budget: &mut rpm::Budget,
    ) -> std::result::Result<String, Verdict> {
        let dir = package.dirs.get(file.dir as usize).map_or("", |dir| dir);
        if let Some(resolved) = self.resolved.borrow().get(dir) {
            return Ok(format!("{resolved}{}", file.name));
        }
        let mut resolved = links.resolve(dir).map_err(|why| {
            Verdict::Unknown(Doubt::Other(format!(
                "rpm's records give links on the way to {dir} that NAILS cannot follow: {why}"
            )))
        })?;
        if !resolved.ends_with('/') {
            resolved.push('/');
        }
        budget
            .take(
                RESOLVED
                    + rpm::Budget::allocation(dir.len())
                    + rpm::Budget::allocation(resolved.len()),
            )
            .map_err(|e| too_much(at, &e))?;
        let path = format!("{resolved}{}", file.name);
        // Kept without the room to spare the `/` may have grown it by.
        self.resolved
            .borrow_mut()
            .insert(dir.into(), resolved.into_boxed_str());
        Ok(path)
    }

    /// Whether the upper `base` holds an entry at `rel`, or deleted or
    /// replaced a directory on its way. Each directory of the upper is
    /// listed once.
    fn touched(&self, base: &Path, rel: &Path) -> std::result::Result<bool, Verdict> {
        let names: Option<Vec<&std::ffi::OsStr>> = rel
            .components()
            .map(|component| match component {
                Component::Normal(name) => Some(name),
                _ => None,
            })
            .collect();
        let Some((file, dirs)) = names.as_deref().and_then(<[_]>::split_last) else {
            return Ok(false);
        };
        let fs = self.fs;
        let mut dir = base.to_path_buf();
        for name in dirs {
            if !self.lists(&dir, name)? {
                return Ok(false);
            }
            dir.push(name);
            // A directory deleted (a whiteout, which is no directory) or
            // replaced on the way.
            let replaced = fs
                .is_symlink(&dir)
                .and_then(|link| Ok(link || !fs.is_directory(&dir)?));
            match replaced {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(e) => return Err(unreadable("an entry of hidden sessions' upper", &e)),
            }
        }
        self.lists(&dir, file)
    }

    /// Whether the upper's directory `dir` lists `name`.
    fn lists(&self, dir: &Path, name: &std::ffi::OsStr) -> std::result::Result<bool, Verdict> {
        if let Some(names) = self.listed.borrow().get(dir) {
            return Ok(names.as_ref().is_some_and(|names| names.contains(name)));
        }
        let names = match self.fs.list_directory(dir) {
            Ok(entries) => Some(
                entries
                    .iter()
                    .filter_map(|entry| entry.file_name().map(std::ffi::OsStr::to_os_string))
                    .collect::<BTreeSet<_>>(),
            ),
            Err(e) if missing(&e) => None,
            Err(e) => {
                return Err(unreadable(
                    &format!("what hidden sessions keep at {}", dir.display()),
                    &e,
                ));
            }
        };
        let found = names.as_ref().is_some_and(|names| names.contains(name));
        self.listed.borrow_mut().insert(dir.to_path_buf(), names);
        Ok(found)
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

/// About what the cache of resolved directories holds for one besides the
/// bytes of the two paths: its entry, twice over for the room a map keeps
/// spare.
const RESOLVED: usize = 2 * size_of::<(Box<str>, Box<str>)>();

/// The verdict for rpm's databases at `at`, and what they record, that need
/// more memory than the reader keeps for them (`reason`).
fn too_much(at: &str, reason: &str) -> Verdict {
    Verdict::Unknown(Doubt::Other(format!(
        "{at} on the decoy and hidden sessions' copy of it cannot be read together ({reason})"
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
