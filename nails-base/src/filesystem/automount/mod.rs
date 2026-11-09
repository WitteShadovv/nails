// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The automount guard: a check makes no lookup that would mount an
//! automount point.
//!
//! A lookup that passes an automount point that nothing is mounted on yet
//! mounts it: a direct or offset one (systemd's for `x-systemd.automount`, or
//! an automounter's direct or offset map) as the lookup goes into it, a name
//! in the directory of an indirect map as the lookup looks that name up. A
//! check leaves no mount behind, so it asks before each lookup, without
//! making it: [`on_the_way`] reads the links on the way one by one, never
//! following them and never mounting what it reads, and asks the mount table
//! of the running system, as read when the check starts ([`Snapshot`]),
//! about each place the lookup would pass.
//!
//! [`Guarded`] is a [`Filesystem`] that asks so before every call that takes
//! a path. A lookup it does not make fails with
//! [`NailsError::NotLookedUp`] from the same call, as a path that cannot be
//! read fails, so each reader words it where it words an unreadable path. It
//! also keeps every such lookup in a ledger, which [`settle`] reads when the
//! check ends: no reader that takes an error for "nothing there" can let a
//! check pass over a path it did not look up.
//!
//! The table is the one read when the check starts. At the root of each
//! mount on the way the kernel is asked what is on top there
//! ([`Filesystem::mount_root`]), so a direct or offset automount point the
//! table missed, one whose mount expired while the check ran or one set up
//! after the table was read, is not looked up either. A name of an indirect
//! map that expires so can be mounted by the guard's own reading of it: the
//! kernel asks the automounter for a name it holds nothing for, even for a
//! lookup that asks it not to mount.

use crate::error::Skip;
use crate::filesystem::mountinfo::MountEntry;
use crate::filesystem::{Filesystem, MountRoot};
use crate::hidden_root::mount_holding;
use crate::next_step::{NextStep, shell_word, sudo_line};
use crate::preflight::CheckResult;
use crate::{NailsError, Result};
use nails_api::Allowable;
use std::ffi::OsString;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

mod guarded;

pub use guarded::Guarded;

/// The filesystem type of an automount point.
const AUTOMOUNT_FS: &str = "autofs";

/// The option of an automount point that is the directory of an indirect
/// map: a lookup of a name in it mounts that name, while the directory
/// itself is no automount point. A direct or offset automount point is one
/// itself.
const INDIRECT_MAP: &str = "indirect";

/// The kernel's limit on the links one lookup follows (`MAXSYMLINKS`).
const MAX_LINKS: usize = 40;

/// The mount table a check judges its lookups by, read once when it starts.
///
/// Each check reads its own, and so does each part of the report that reads
/// the decoy, rather than one table for the whole run of `check`: a lookup
/// is judged by a table read just before the check that makes it, which
/// leaves an automount the least time to change under it. Each read is one
/// read of `/proc/self/mountinfo`.
#[derive(Debug)]
pub struct Snapshot {
    table: Table,
}

/// What a [`Snapshot`] holds.
#[derive(Debug)]
enum Table {
    /// The running system's mount table.
    Running(Vec<MountEntry>),
    /// The tree read is not the running system's (a test's tree, an image):
    /// no automount point of this system lies in it, and nothing is guarded.
    Elsewhere,
    /// The running system's table cannot be read, for this reason: nothing
    /// shows where a lookup would mount an automount point, so none is made.
    Unreadable(String),
}

impl Snapshot {
    /// The table for a check that reads the tree at `root`: `/` gives the
    /// running system's table through `fs`, or why it cannot be read; any
    /// other root gives one that guards nothing.
    pub fn read<F: Filesystem>(fs: &F, root: &Path) -> Arc<Snapshot> {
        let table = if root != Path::new("/") {
            Table::Elsewhere
        } else {
            match fs.mount_table() {
                Ok(table) => Table::Running(table),
                Err(error) => Table::Unreadable(error.to_string()),
            }
        };
        Arc::new(Snapshot { table })
    }

    /// A snapshot of `table`, whatever the root: for the tests of a reader
    /// that does not read through a [`Filesystem`], over a tree whose
    /// automount points lie below a temporary directory.
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_table(table: Vec<MountEntry>) -> Arc<Snapshot> {
        Arc::new(Snapshot {
            table: Table::Running(table),
        })
    }

    /// Why the running system's table cannot be read, when it cannot: then
    /// no lookup is made.
    pub fn unreadable(&self) -> Option<&str> {
        match &self.table {
            Table::Unreadable(error) => Some(error),
            Table::Running(_) | Table::Elsewhere => None,
        }
    }

    /// The running system's table, when the tree read is the running
    /// system's and its table can be read.
    pub fn table(&self) -> Option<&[MountEntry]> {
        match &self.table {
            Table::Running(table) => Some(table),
            Table::Elsewhere | Table::Unreadable(_) => None,
        }
    }

    /// Whether a lookup of `path` as `lookup` makes it may be made, for a
    /// reader that makes its lookups itself, not through a [`Filesystem`]:
    /// `Ok(None)` when it may, `Ok(Some(point))` when a lookup that only
    /// resolves `path` ends at the direct automount point `point`, which the
    /// reader answers without looking it up (an automount point is a
    /// directory, never a link). `fs` reads the links on the way.
    ///
    /// # Errors
    ///
    /// [`NailsError::NotLookedUp`] where the lookup would mount an automount
    /// point, or where the table cannot be read; the error of a lookup on
    /// the way that fails, naming `path`, as the lookup itself would fail.
    pub fn check<F: Filesystem>(
        &self,
        fs: &F,
        path: &Path,
        lookup: Lookup,
    ) -> Result<Option<PathBuf>> {
        match &self.table {
            Table::Elsewhere => Ok(None),
            Table::Unreadable(error) => Err(NailsError::NotLookedUp {
                path: path.to_path_buf(),
                reason: Skip::NoMountTable {
                    error: error.clone(),
                },
            }),
            Table::Running(table) => match on_the_way(fs, table, path, lookup) {
                Way::Clear => Ok(None),
                Way::AtPoint(point) => Ok(Some(point)),
                Way::Mounts(point) => Err(NailsError::NotLookedUp {
                    path: path.to_path_buf(),
                    reason: Skip::Automount { point },
                }),
                Way::Failed(error) => Err(NailsError::io(path, error)),
            },
        }
    }
}

/// How a lookup treats the last component of its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    /// It reads what is there: a `statx` that may mount, as `stat` and
    /// `lstat` of the standard library make it, or an open that reads or
    /// lists it. A direct automount point at its end is mounted. `follow`:
    /// a link at its end is followed.
    Enters {
        /// Whether a link at the end is followed.
        follow: bool,
    },
    /// It only resolves the path: `realpath`, `readlink`, a `statx` with
    /// `AT_NO_AUTOMOUNT`. A direct automount point at its end mounts nothing
    /// and is answered from the table without a lookup
    /// ([`Way::AtPoint`]); a name in the directory of an indirect map is
    /// mounted as it is looked up, so that lookup is not made. `follow`: a
    /// link at its end is followed.
    Resolves {
        /// Whether a link at the end is followed.
        follow: bool,
    },
}

impl Lookup {
    /// Whether the lookup follows a link at its end.
    fn follows(self) -> bool {
        match self {
            Lookup::Enters { follow } | Lookup::Resolves { follow } => follow,
        }
    }

    /// Whether the lookup only resolves its path.
    fn resolves(self) -> bool {
        matches!(self, Lookup::Resolves { .. })
    }
}

/// Whether a lookup would pass an automount point, as [`on_the_way`] tells.
#[derive(Debug)]
pub enum Way {
    /// It passes no automount point that nothing is mounted on, or fails
    /// with "not there" before it would: it may be made.
    Clear,
    /// It would mount this automount point: it is not made.
    Mounts(PathBuf),
    /// It only resolves its path, which ends at this direct automount point
    /// that nothing is mounted on: the point is a directory, its resolved
    /// path is this one, and it is not looked up.
    AtPoint(PathBuf),
    /// A lookup on the way fails with this error, as the lookup itself
    /// would: it is not made.
    Failed(std::io::Error),
}

/// One step of a lookup, as [`on_the_way`] takes them.
enum Step {
    /// Into the entry of this name.
    Into(OsString),
    /// Up to the parent, for `..`.
    Up,
}

/// Put the steps of `path` on `steps`, its first step last, so that they
/// are taken from the end in order.
fn push_steps(steps: &mut Vec<Step>, path: &Path) {
    for component in path.components().rev() {
        match component {
            Component::Normal(name) => steps.push(Step::Into(name.to_os_string())),
            Component::ParentDir => steps.push(Step::Up),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
}

/// Whether `mount` is the directory of an indirect map.
fn is_indirect(mount: &MountEntry) -> bool {
    mount
        .super_opts
        .split(',')
        .any(|option| option == INDIRECT_MAP)
}

/// Whether `mount` is the directory of an indirect map at `path` itself.
fn is_map_directory(mount: &MountEntry, path: &Path) -> bool {
    mount.fstype == AUTOMOUNT_FS && mount.mount_point == path && is_indirect(mount)
}

/// Whether a lookup that reaches `path` makes `mount`, the mount that holds
/// it, mount something: when it is an automount, unless it is the directory
/// of an indirect map at `path` itself, whose names the next step looks up.
/// An automount whose options say no kind is taken for a direct one.
fn mounts(mount: &MountEntry, path: &Path) -> bool {
    mount.fstype == AUTOMOUNT_FS && !is_map_directory(mount, path)
}

/// Whether the lookup of `path` enters its last component whatever it is
/// asked to do with it: a path that ends in `/` or `/.` names a directory,
/// which the kernel looks into, and mounts there, also for a lookup that
/// would only resolve the path or not follow a link at its end.
fn enters_its_end(path: &Path) -> bool {
    let bytes = path.as_os_str().as_bytes();
    bytes.len() > 1 && (bytes.ends_with(b"/") || bytes.ends_with(b"/."))
}

/// Whether `error` says nothing is there: no entry on the way, or a
/// component on the way that is no directory.
fn nothing_there(error: &NailsError) -> bool {
    matches!(
        error.io_kind(),
        Some(ErrorKind::NotFound | ErrorKind::NotADirectory)
    )
}

/// The I/O error of `error`, for a [`Way::Failed`].
fn into_io(error: NailsError) -> std::io::Error {
    match error {
        NailsError::IoError { source, .. } => source,
        other => std::io::Error::other(other.to_string()),
    }
}

/// Whether a lookup of `path` as `lookup` would mount an automount point
/// that `table`, the running system's mount table, shows nothing mounted on
/// yet, without making the lookup.
///
/// The path is walked as the kernel walks it: from `/`, or for a relative
/// path from the working directory, one component at a time, each link on
/// the way read with [`Filesystem::read_link`] and followed where it leads,
/// a relative one from the directory that holds it, and `..` taken from the
/// directory reached, so after a link the parent of where it led. Each place
/// is asked of the table before the lookup passes it, so the first that
/// would mount is the automount point itself: a direct or offset one, or a
/// name in the directory of an indirect map. A place the table does not
/// flag is read with [`Filesystem::mount_root`], which neither follows a
/// link nor mounts there, and tells a link and an automount point the table
/// missed: the kernel's attribute for one, and at the root of a mount an
/// autofs on top. An autofs on top of the directory of an indirect map the
/// table shows is that directory, whose names the next step asks about. The
/// last place is read only where the lookup would read it. A place that is
/// not there ends the walk: the lookup fails there. More links than the
/// kernel follows in one lookup fail it with `ELOOP`.
pub fn on_the_way<F: Filesystem>(fs: &F, table: &[MountEntry], path: &Path, lookup: Lookup) -> Way {
    let lookup = if enters_its_end(path) {
        Lookup::Enters { follow: true }
    } else {
        lookup
    };
    let mut at = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        match std::env::current_dir() {
            Ok(dir) => dir,
            Err(error) => return Way::Failed(error),
        }
    };
    let mut steps = Vec::new();
    push_steps(&mut steps, path);
    // Only a place at or below an automount point can be held by one, so the
    // table is asked which mount holds a place only then: that reads the whole
    // table for each prefix of the place, and most tables hold no automount
    // point, or none on the way.
    let points: Vec<&Path> = table
        .iter()
        .filter(|mount| mount.fstype == AUTOMOUNT_FS)
        .map(|mount| mount.mount_point.as_path())
        .collect();
    let mut links = 0;
    while let Some(step) = steps.pop() {
        let name = match step {
            Step::Into(name) => name,
            Step::Up => {
                at.pop();
                continue;
            }
        };
        let next = at.join(name);
        let last = steps.is_empty();
        let holder = if points.iter().any(|point| next.starts_with(point)) {
            mount_holding(table, &next)
        } else {
            None
        };
        if let Some(mount) = holder
            && mounts(mount, &next)
        {
            // A direct point at the end of a lookup that only resolves
            // it mounts nothing: its path is its answer.
            return if last && lookup.resolves() && mount.mount_point == next {
                Way::AtPoint(next)
            } else {
                Way::Mounts(next)
            };
        }
        // A lookup that only resolves its path, and does not follow a link
        // at its end, reads nothing there that could mount it.
        if last && lookup.resolves() && !lookup.follows() {
            return Way::Clear;
        }
        match fs.mount_root(&next) {
            Ok(MountRoot::Entry(_)) => at = next,
            // The directory of an indirect map is an autofs on top, as an
            // automount point is: the names in it are its points.
            Ok(MountRoot::Automount)
                if holder.is_some_and(|mount| is_map_directory(mount, &next)) =>
            {
                at = next;
            }
            Ok(MountRoot::Automount) => {
                return if last && lookup.resolves() {
                    Way::AtPoint(next)
                } else {
                    Way::Mounts(next)
                };
            }
            Ok(MountRoot::Link) if last && !lookup.follows() => return Way::Clear,
            Ok(MountRoot::Link) => {
                links += 1;
                if links > MAX_LINKS {
                    return Way::Failed(std::io::Error::from_raw_os_error(nix::libc::ELOOP));
                }
                let target = match fs.read_link(&next) {
                    // A link to nothing by name: the lookup fails there.
                    Ok(target) if target.as_os_str().is_empty() => return Way::Clear,
                    Ok(target) => target,
                    Err(error) if nothing_there(&error) => return Way::Clear,
                    Err(error) => return Way::Failed(into_io(error)),
                };
                if target.is_absolute() {
                    at = PathBuf::from("/");
                }
                push_steps(&mut steps, &target);
            }
            Err(error) if nothing_there(&error) => return Way::Clear,
            Err(error) => return Way::Failed(into_io(error)),
        }
    }
    Way::Clear
}

/// A lookup [`Guarded`] did not make, as its ledger keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The path the lookup would have looked up.
    pub path: PathBuf,
    /// Why it was not made.
    pub reason: Skip,
}

/// What a check does about a lookup it did not make, once it has read the
/// rest ([`settle`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnSkip {
    /// It warns: a warn-only check, or a part of one that warns.
    Warn,
    /// It refuses, with the override that lifts the refusal, if one does.
    Refuse(Option<Allowable>),
}

/// `items` as a list in a sentence: `a`, `a and b`, `a, b and c`.
fn listing(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// What the operator does to let a check look behind the automount points
/// `points`: mount them, and run the check again. Ends with a full stop.
pub fn mount_fix(points: &[&Path]) -> String {
    let named: Vec<String> = points
        .iter()
        .map(|point| point.display().to_string())
        .collect();
    let words: Vec<String> = points
        .iter()
        .map(|point| shell_word(point.as_os_str()))
        .collect();
    format!(
        "Mount {} (for example `ls {}`) and run `{}` again.",
        listing(&named),
        words.join(" "),
        sudo_line(NextStep::Check)
    )
}

/// What a check says of a path it did not look up or could not, as
/// [`describe`] words it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unseen {
    /// Why the check cannot tell what is at the path, without a full stop.
    pub sentence: String,
    /// What to do so that it can, where something can be done that the
    /// sentence does not say.
    pub fix: Option<String>,
    /// The automount point the lookup would have mounted, where that is
    /// why it was not made.
    pub automount_point: Option<PathBuf>,
}

/// What a check says of the path it names `shown`, whose lookup failed with
/// `error` or was not made: a lookup NAILS may not make asks for sudo, one
/// the guard did not make gives the guard's reason and says to mount the
/// automount point, and any other names its error.
pub fn describe(shown: &str, error: &NailsError) -> Unseen {
    if let Some((_, reason)) = error.not_looked_up() {
        let point = reason.point().map(Path::to_path_buf);
        return Unseen {
            sentence: reason.sentence_for(&shown),
            fix: point.as_deref().map(|point| mount_fix(&[point])),
            automount_point: point,
        };
    }
    let sentence = if error.io_kind() == Some(ErrorKind::PermissionDenied) {
        format!("NAILS cannot look up {shown}; run the command again with sudo")
    } else {
        format!("NAILS cannot look up {shown} ({error})")
    };
    Unseen {
        sentence,
        fix: None,
        automount_point: None,
    }
}

/// Whether `message` names the automount point `point` as such: the guard's
/// words, followed by no more of a path.
fn names_point(message: &str, point: &Path) -> bool {
    let needle = format!("automount point {}", point.display());
    message.match_indices(&needle).any(|(at, _)| {
        let mut rest = message[at + needle.len()..].chars();
        match rest.next() {
            None => true,
            Some('.') => rest.next().is_none_or(char::is_whitespace),
            Some(c) => c.is_whitespace() || matches!(c, ',' | ';' | ':' | ')'),
        }
    })
}

/// The result of a check that read through [`Guarded`], once `skipped`, the
/// lookups its ledger kept, are accounted for: each automount point the
/// result does not name yet is named with the first path it kept the check
/// from looking up, the mount table once where it could not be read, and
/// the fix that mounts the points is given once. A pass becomes a warning,
/// or a refusal with `on_skip`'s override, since the check did not look
/// everywhere; a refusing part turns a warning into a refusal too. A result
/// with nothing in the ledger, and a skipped check, stay as they are.
pub fn settle(result: CheckResult, skipped: &[Skipped], on_skip: OnSkip) -> CheckResult {
    if skipped.is_empty() || result.is_skipped() {
        return result;
    }
    let message = result.message();
    let (points, reasons) = ledger(message, skipped);
    // The fix once: a point whose fix the result gives already, as a check
    // that words a lookup it did not make itself gives it, is left out.
    let given = |point: &&Path| {
        let fix = mount_fix(&[*point]);
        message.contains(&fix) || result.remediation().is_some_and(|text| text.contains(&fix))
    };
    let unfixed: Vec<&Path> = points
        .iter()
        .copied()
        .filter(|point| !given(point))
        .collect();
    let fix = (!unfixed.is_empty()).then(|| mount_fix(&unfixed));
    let unnamed: Vec<&str> = reasons
        .iter()
        .filter(|(_, named)| !named)
        .map(|(reason, _)| reason.as_str())
        .collect();
    match result {
        // A pass names none of it: what the check could not look at comes
        // first, then what it found where it could.
        CheckResult::Pass(seen) => {
            let all: Vec<&str> = reasons.iter().map(|(reason, _)| reason.as_str()).collect();
            let message = format!("{}\nWhere it could look: {seen}", untold(&all));
            match on_skip {
                OnSkip::Warn => CheckResult::Warn(with_fix(message, fix.as_deref())),
                OnSkip::Refuse(allowable) => CheckResult::Fail {
                    message,
                    remediation: fix,
                    allowable,
                },
            }
        }
        CheckResult::Warn(warning) => {
            let message = told(warning, &unnamed);
            match on_skip {
                OnSkip::Warn => CheckResult::Warn(with_fix(message, fix.as_deref())),
                OnSkip::Refuse(allowable) => CheckResult::Fail {
                    message,
                    remediation: fix,
                    allowable,
                },
            }
        }
        CheckResult::Fail {
            message,
            remediation,
            allowable,
        } => {
            // An override lifts the refusal only where it lifts every part
            // of it.
            let allowable = match on_skip {
                OnSkip::Refuse(lifts) if lifts == allowable => allowable,
                OnSkip::Refuse(_) => None,
                OnSkip::Warn => allowable,
            };
            let remediation = match (remediation, fix) {
                (Some(remediation), Some(fix)) => Some(format!("{remediation}\n{fix}")),
                (remediation, fix) => remediation.or(fix),
            };
            CheckResult::Fail {
                message: told(message, &unnamed),
                remediation,
                allowable,
            }
        }
        skipped @ CheckResult::Skipped(_) => skipped,
    }
}

/// The lookups of `skipped`, as the result whose message is `message`
/// accounts for them: each automount point once, by the first path it kept
/// the check from looking up, and the mount table once, each reason with
/// whether `message` names it already; and the automount points.
fn ledger<'a>(message: &str, skipped: &'a [Skipped]) -> (Vec<&'a Path>, Vec<(String, bool)>) {
    let mut points: Vec<&Path> = Vec::new();
    let mut reasons: Vec<(String, bool)> = Vec::new();
    let mut table = false;
    for skip in skipped {
        let named = match &skip.reason {
            Skip::Automount { point } if points.contains(&point.as_path()) => continue,
            Skip::Automount { point } => {
                points.push(point);
                names_point(message, point)
            }
            Skip::NoMountTable { .. } if table => continue,
            Skip::NoMountTable { .. } => {
                table = true;
                message.contains("cannot read the mount table")
            }
        };
        reasons.push((skip.reason.sentence(&skip.path), named));
    }
    (points, reasons)
}

/// The reasons of the lookups `skipped` that `text` does not name yet, as
/// [`settle`] adds them to a result: each automount point once, by the
/// first path it kept the check from looking up, and the mount table once.
/// For a probe that tells what it found rather than a check's result, whose
/// caller counts each as a place it cannot tell about.
pub fn unnamed(text: &str, skipped: &[Skipped]) -> Vec<String> {
    ledger(text, skipped)
        .1
        .into_iter()
        .filter(|(_, named)| !named)
        .map(|(reason, _)| reason)
        .collect()
}

/// What a check that keeps its result, as one that only informs does, says
/// of the lookups `skipped` its view did not make: the sentence [`settle`]
/// puts before a pass, then on a line of its own the fix that mounts the
/// automount points, if any. `None` when the view made every lookup.
pub fn note(skipped: &[Skipped]) -> Option<String> {
    if skipped.is_empty() {
        return None;
    }
    let (points, reasons) = ledger("", skipped);
    let all: Vec<&str> = reasons.iter().map(|(reason, _)| reason.as_str()).collect();
    let fix = (!points.is_empty()).then(|| mount_fix(&points));
    Some(with_fix(untold(&all), fix.as_deref()))
}

/// The sentence that says the check cannot tell, for `reasons`.
fn untold(reasons: &[&str]) -> String {
    format!(
        "NAILS cannot tell about everything it checks: {}.",
        reasons.join("; ")
    )
}

/// `message`, with a line for `unnamed`, the lookups the check did not make
/// that it does not name yet, if any.
fn told(message: String, unnamed: &[&str]) -> String {
    if unnamed.is_empty() {
        message
    } else {
        format!("{message}\n{}", untold(unnamed))
    }
}

/// `text`, with `fix` on a line of its own after it, if there is one.
fn with_fix(text: String, fix: Option<&str>) -> String {
    match fix {
        Some(fix) => format!("{text}\n{fix}"),
        None => text,
    }
}

#[cfg(test)]
mod tests;
