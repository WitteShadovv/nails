// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What of the files a zsh that runs now read as it started may have
//! changed since. zsh keeps what it read then: a shell started before an
//! edit, a removal or a NixOS rebuild runs with the options of the files as
//! they were, while the check reads them as they are now. So where a path
//! the check reads or looks for (a startup file, what it sources, a
//! function's file, the compiled form zsh looks for beside each) changed
//! after the shell started, by its status change time, the check cannot
//! tell what zsh read there: a doubt.
//!
//! For each path that counts: each link met on the way to it, which a
//! rebuild or an `ln -sf` replaces, the file it leads to, which an edit or a
//! rename into place changes, and the directory zsh looks in for it and its
//! compiled form, or, for a path that leads to nothing now, the deepest
//! directory on the way that is there, whose entries change as a file in it
//! is made, removed or renamed; and each directory above those, up to the
//! root, as one renamed into place keeps the change times of what is in it
//! (`mv ~/.zsh/plugins.new ~/.zsh/plugins`). The Nix store and what is below
//! it are left out: nothing in a store path changes once it is there, and a
//! new one is reached only through a link that changed. On NixOS the link to
//! the system it runs (`/run/current-system`), which each switch replaces,
//! counts too, so a switch shows whatever `/etc` is made of: links into the
//! store, or a mount of an image whose files may keep the image's change
//! times.
//!
//! A directory changes as any file in it is made or removed, and zsh makes
//! and removes a lock file beside its history file as it reads that file as
//! it starts, unless `HIST_FCNTL_LOCK` is on: so a zsh whose history file is
//! in a directory that counts (the home, `ZDOTDIR`) without that option
//! changes it as it starts, however new it is, and the fix the warning gives
//! then says so.
//!
//! A change up to three seconds before the shell started counts too: the
//! boot time its start is read from is cut to the second, the times are
//! compared by the second, and the second before the one it started in
//! counts, as a filesystem may keep change times to the second or behind the
//! clock by a tick. A change of the system clock after the
//! shell started can move the time the shell started is read as, so a step
//! forward hides a change made before it by no more than the step.

use super::Reader;
use crate::Filesystem;
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The most links a lookup follows, as Linux does (`MAXSYMLINKS`).
const LINKS: usize = 40;

/// Where nothing changes once it is there.
const STORE: &str = "/nix/store";

/// How many of the paths that changed a doubt names.
const NAMED: usize = 3;

/// What NixOS marks itself with, and the link to the system it runs, which
/// each switch replaces.
const NIXOS: &str = "/etc/NIXOS";
const SYSTEM: &str = "/run/current-system";

/// How each doubt of what changed after the shell started starts.
const STALE: &str = "it cannot tell what the shell read as it started";

/// What a doubt of what changed after the shell started says past what
/// changed, which a zsh started after the change fixes; and what it says
/// where a directory changed.
const CHANGED: &str = "changed after it started (a shell started now reads what is there now";
const DIRECTORY: &str = ", and zsh changes the directory that holds its history file as it \
                         starts unless HIST_FCNTL_LOCK is on";

/// The fix for a zsh that may have read other startup files as it started
/// than those there now, and that the check finds nothing else in; and the
/// one where a directory changed, which may be the one the history file is
/// in.
const RESTART_FIX: &str = "Type the decoy commands in a zsh you start after the change, the way \
                           you started this one: it reads the startup files as they are then.";
const DIRECTORY_FIX: &str = "Type the decoy commands in a zsh you start after the change, the \
                             way you started this one: it reads the startup files as they are \
                             then. Where the history file is in a directory named here, first \
                             turn HIST_FCNTL_LOCK on in the startup files or keep the history \
                             file in a directory of its own, or the new zsh changes that \
                             directory again as it starts.";

/// The fix for a zsh whose files gave `doubts` and no write, where each of
/// them is that what it read changed after it started, which a zsh started
/// after the change fixes; `None` where another doubt is among them, one the
/// check cannot read when the shell or a path changed among them.
pub(in super::super) fn restart_fix(doubts: &[String]) -> Option<&'static str> {
    let restarts = |doubt: &String| doubt.starts_with(STALE) && doubt.contains(CHANGED);
    if doubts.is_empty() || !doubts.iter().all(restarts) {
        return None;
    }
    Some(if doubts.iter().any(|doubt| doubt.contains(DIRECTORY)) {
        DIRECTORY_FIX
    } else {
        RESTART_FIX
    })
}

/// Whether a path whose status changed at `changed` may have changed after
/// a shell that started at `started` read it: a change in the second
/// before the one it started in, or later, counts.
pub(super) fn changed_since(changed: SystemTime, started: SystemTime) -> bool {
    let seconds = |time: SystemTime| {
        time.duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs())
    };
    seconds(changed) + 1 >= seconds(started)
}

impl<F: Filesystem> Reader<'_, F> {
    /// Note a doubt where a path the files read or looked for changed after
    /// the shell that runs now started (see [the module](self)), or where the
    /// check cannot tell when it started or when a path changed. Nothing for
    /// a shell that may not run yet.
    pub(super) fn since_start(&mut self) {
        let started = match self.install.started.clone() {
            None => return,
            Some(Ok(started)) => started,
            Some(Err(why)) => {
                self.doubt(format!(
                    "{STALE}, as it cannot tell when it started ({why})"
                ));
                return;
            }
        };
        let mut paths: Vec<PathBuf> = self
            .read_files
            .iter()
            .chain(&self.missing)
            .map(|(path, _)| path.clone())
            .chain(self.looked.iter().cloned())
            .collect();
        paths.sort();
        paths.dedup();
        let mut compared: HashSet<PathBuf> = HashSet::new();
        let mut changed: Vec<String> = Vec::new();
        let mut doubts = Vec::new();
        // On NixOS each switch replaces the link to the system it starts,
        // whatever /etc is made of (links into the store, or a mount of an
        // image whose files may keep the image's change times).
        if !matches!(self.fs.inode(Path::new(NIXOS)), Ok(None)) {
            compared.insert(PathBuf::from(SYSTEM));
            match self.fs.change_time(Path::new(SYSTEM)) {
                Ok(time) if changed_since(time, started) => changed.push(SYSTEM.to_string()),
                Ok(_) => {}
                Err(error) => doubts.push(format!(
                    "{STALE}, as when {SYSTEM} changed cannot be read ({})",
                    error
                        .io_kind()
                        .map_or_else(|| error.to_string(), |kind| kind.to_string())
                )),
            }
        }
        for path in paths {
            let counted = match self.counted(&path) {
                Ok(counted) => counted,
                Err(why) => {
                    doubts.push(format!("{STALE} in {}, as {why}", path.display()));
                    continue;
                }
            };
            for counted in counted {
                if !compared.insert(counted.clone()) {
                    continue;
                }
                match self.fs.change_time(&counted) {
                    Ok(time) if changed_since(time, started) => {
                        changed.push(counted.display().to_string());
                    }
                    Ok(_) => {}
                    Err(error) => doubts.push(format!(
                        "{STALE}, as when {} changed cannot be read ({})",
                        counted.display(),
                        error
                            .io_kind()
                            .map_or_else(|| error.to_string(), |kind| kind.to_string())
                    )),
                }
            }
        }
        changed.sort();
        // A directory, which a link may lead to but which is none.
        let directory = changed.iter().any(|path| {
            let path = Path::new(path);
            matches!(self.fs.is_symlink(path), Ok(false))
                && matches!(self.fs.is_directory(path), Ok(true))
        });
        if !changed.is_empty() {
            let shown = match changed.len() {
                1 => changed[0].clone(),
                count if count <= NAMED => {
                    format!(
                        "{} and {}",
                        changed[..count - 1].join(", "),
                        changed[count - 1]
                    )
                }
                count => format!("{} and {} more", changed[..NAMED].join(", "), count - NAMED),
            };
            let directory = if directory { DIRECTORY } else { "" };
            doubts.insert(0, format!("{STALE}, as {shown} {CHANGED}{directory})"));
        }
        for doubt in doubts {
            self.doubt(doubt);
        }
    }

    /// The paths whose change times tell whether a lookup of `path` finds
    /// what it found as the shell started (see [the module](self)), each
    /// directory above them among them, but those in the Nix store; `Err`
    /// with why when the check cannot follow the links on the way.
    fn counted(&self, path: &Path) -> Result<Vec<PathBuf>, String> {
        let mut counted = Vec::new();
        let holder = match path.parent() {
            Some(parent) => self.followed(parent, &mut counted)?,
            None => PathBuf::from("/"),
        };
        let target = self.followed(path, &mut counted)?;
        if self.there(&target)? {
            counted.push(target);
            counted.push(holder);
        } else {
            let mut deepest = PathBuf::from("/");
            for dir in target.ancestors().skip(1) {
                if self.there(dir)? {
                    deepest = dir.to_path_buf();
                    break;
                }
            }
            counted.push(deepest);
            if self.there(&holder)? {
                counted.push(holder);
            }
        }
        let above: Vec<PathBuf> = counted
            .iter()
            .flat_map(|path| path.ancestors().skip(1))
            .map(Path::to_path_buf)
            .collect();
        counted.extend(above);
        counted.retain(|path| !path.starts_with(STORE));
        Ok(counted)
    }

    /// Whether something is at `path`, its links followed.
    fn there(&self, path: &Path) -> Result<bool, String> {
        self.fs
            .inode(path)
            .map(|inode| inode.is_some())
            .map_err(|error| {
                format!(
                    "{} cannot be looked up ({})",
                    path.display(),
                    error
                        .io_kind()
                        .map_or_else(|| error.to_string(), |kind| kind.to_string())
                )
            })
    }

    /// The path a lookup of `path`, an absolute one, reaches, each link on
    /// the way read and followed as the kernel follows it, the links noted in
    /// `links`; a part that is not there is taken as written.
    fn followed(&self, path: &Path, links: &mut Vec<PathBuf>) -> Result<PathBuf, String> {
        let mut reached = PathBuf::from("/");
        // The parts left to look up, the next one last.
        let mut parts: Vec<OsString> = Vec::new();
        push_parts(&mut parts, path);
        let mut followed = 0;
        while let Some(part) = parts.pop() {
            if part == ".." {
                reached.pop();
                continue;
            }
            let next = reached.join(&part);
            let link = self
                .fs
                .is_symlink(&next)
                .map_err(|error| format!("{} cannot be looked up ({error})", next.display()))?;
            if !link {
                reached = next;
                continue;
            }
            followed += 1;
            if followed > LINKS {
                return Err(format!(
                    "{} leads through more than {LINKS} links",
                    path.display()
                ));
            }
            let target = self
                .fs
                .read_link(&next)
                .map_err(|error| format!("the link {} cannot be read ({error})", next.display()))?;
            links.push(next);
            if target.is_absolute() {
                reached = PathBuf::from("/");
            }
            push_parts(&mut parts, &target);
        }
        Ok(reached)
    }
}

/// Push the parts of `path` onto `parts`, a stack whose next part is its
/// last, so that the first part of `path` comes next; `.` is none, and the
/// root is where an absolute path starts from, which the caller sets.
fn push_parts(parts: &mut Vec<OsString>, path: &Path) {
    for component in path.components().rev() {
        match component {
            Component::Normal(name) => parts.push(name.to_os_string()),
            Component::ParentDir => parts.push(OsString::from("..")),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }
}
