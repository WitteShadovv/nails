// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pre-flight check that flags what a Nix install leaves on a decoy that is
//! not NixOS.
//!
//! On every distribution but NixOS, Nix belongs inside the hidden session:
//! everything a session writes, the Nix store and the installer's changes to
//! `/etc` among it, lands on the hidden volume. A Nix installed on the decoy
//! writes to the decoy disk instead, and so does everything it installs or
//! builds there, each store path named after its package and recorded in the
//! store's database. The check looks under the decoy root for what the
//! upstream installer, or a distribution's Nix package, leaves behind:
//!
//! - `/nix`, whatever it is: a directory, empty or not, a file or a link,
//!   even one to nothing;
//! - `nix-daemon.service` and `nix-daemon.socket` in the unit directories
//!   systemd loads system units from on the disk (`/etc/systemd/system`,
//!   `/usr/local/lib/systemd/system`, `/usr/lib/systemd/system` and
//!   `/lib/systemd/system`), a link to one in a dependency directory
//!   (`.wants`, `.requires`, `.upholds`) of `/etc/systemd/system`, the
//!   drop-in directory of one there, and `/etc/tmpfiles.d/nix-daemon.conf`;
//! - `/etc/nix`, and a `nix` command in `/usr/bin` or `/usr/local/bin`;
//! - the `nixbld` group of `/etc/group`, and the build users of
//!   `/etc/passwd`: `nixbld<N>`, `_nixbld<N>`, and any whose group is
//!   `nixbld`;
//! - the shell hooks: `/etc/profile.d/nix.sh` and `nix-daemon.sh`,
//!   `/etc/fish/conf.d/nix.fish`, a line naming `/nix/var/nix/profiles/` in
//!   `/etc/bashrc`, `/etc/bash.bashrc`, `/etc/zshrc` or `/etc/zsh/zshrc`, and
//!   the `.backup-before-nix` copy the installer keeps of each of these files
//!   and of `/etc/profile.d/nix.sh`;
//! - `.nix-profile`, `.nix-defexpr`, `.nix-channels`, `.local/state/nix`,
//!   `.cache/nix` and `.config/nix` in `/root` and in each home `/etc/passwd`
//!   names, but one on the hidden volume.
//!
//! Each one found is named in a warning; the check never refuses, as a
//! decoy may need its own Nix. What it cannot look up or read it names in
//! the warning too, so it never passes a decoy it could not see. On NixOS,
//! whose package manager Nix is, it passes. Inside a hidden session `/`
//! shows the session's own files over the decoy's, so it is skipped there.
//!
//! Nothing is written. A path is looked up without following its last link,
//! and a file is read as the locate-database check reads one
//! ([`DecoyFiles`]): opened with `O_NOATIME`, so that run as root its access
//! time stays, and never where a link leads onto the hidden volume. A link a
//! lookup follows on the way still gets its access time.

use super::super::{CheckResult, PreFlightCheck};
use super::locate_database::files::{DecoyFile, DecoyFiles};
use super::locate_database::hidden_locations;
use crate::filesystem::mountinfo::root_is_hidden_overlay;
use crate::{Filesystem, Result};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// Where the docs explain the check.
const DOC: &str = "docs/decoy-requirements.md#nix-on-the-decoy";

/// The store and state of Nix, relative to the root.
const STORE: &str = "nix";

/// The other paths of a Nix install that are a trace whatever they hold:
/// its settings and its command where a package puts it.
const INSTALL_PATHS: &[&str] = &["etc/nix", "usr/bin/nix", "usr/local/bin/nix"];

/// The unit directories on the disk systemd loads system units from, the
/// administrator's first.
const UNIT_DIRS: &[&str] = &[
    "etc/systemd/system",
    "usr/local/lib/systemd/system",
    "usr/lib/systemd/system",
    "lib/systemd/system",
];

/// The administrator's unit directory, which holds the links that enable a
/// unit and the drop-in directories.
const ADMIN_UNIT_DIR: &str = "etc/systemd/system";

/// The units of the Nix daemon.
const DAEMON_UNITS: &[&str] = &["nix-daemon.service", "nix-daemon.socket"];

/// The suffixes of the dependency directories `systemctl enable` links a
/// unit into.
const DEPENDENCY_DIR_SUFFIXES: &[&str] = &[".wants", ".requires", ".upholds"];

/// The installer's tmpfiles rule for the daemon.
const TMPFILES_RULE: &str = "etc/tmpfiles.d/nix-daemon.conf";

/// The shell hooks Nix installs as files of their own.
const HOOK_FILES: &[&str] = &[
    "etc/profile.d/nix.sh",
    "etc/profile.d/nix-daemon.sh",
    "etc/fish/conf.d/nix.fish",
];

/// The shell startup files the installer adds its hook to.
const HOOKED_FILES: &[&str] = &[
    "etc/bashrc",
    "etc/bash.bashrc",
    "etc/zshrc",
    "etc/zsh/zshrc",
];

/// What every hook names: a script of the default profile.
const HOOK_MARK: &[u8] = b"/nix/var/nix/profiles/";

/// The suffix of the copy the installer keeps of each file it changes.
const BACKUP_SUFFIX: &str = ".backup-before-nix";

/// The files the installer backs up before it changes them.
const BACKED_UP_FILES: &[&str] = &[
    "etc/bashrc",
    "etc/profile.d/nix.sh",
    "etc/zshrc",
    "etc/bash.bashrc",
    "etc/zsh/zshrc",
];

/// What Nix keeps in a home: the profile and channel links of `nix-env`,
/// the newer profiles, and Nix's caches and settings.
const HOME_PATHS: &[&str] = &[
    ".nix-profile",
    ".nix-defexpr",
    ".nix-channels",
    ".local/state/nix",
    ".cache/nix",
    ".config/nix",
];

/// The group of the build users.
const BUILD_GROUP: &str = "nixbld";

/// Pre-flight check that warns when a decoy that is not NixOS holds what a
/// Nix install leaves behind.
#[derive(Debug)]
pub struct DecoyNixTraceCheck {
    /// The hidden root as configured.
    hidden_root: PathBuf,
    /// Whether the host carries a NixOS config layer, whose own Nix is no
    /// trace.
    is_nixos: bool,
    /// Root of the system tree that is read; `/` outside tests.
    root: PathBuf,
}

impl DecoyNixTraceCheck {
    /// The check for the hidden root at `hidden_root`; `is_nixos` passes a
    /// NixOS decoy.
    pub fn new(hidden_root: PathBuf, is_nixos: bool) -> Self {
        Self {
            hidden_root,
            is_nixos,
            root: PathBuf::from("/"),
        }
    }

    /// Read the system tree rooted at `root` instead of `/` (tests).
    #[cfg(test)]
    fn with_root(mut self, root: &Path) -> Self {
        self.root = root.to_path_buf();
        self
    }

    /// Whether `/` is the overlay of a hidden session. Only the running
    /// system's mount table can say, so a tree read under another root never
    /// is.
    fn in_hidden_session<F: Filesystem>(&self, fs: &F) -> bool {
        self.root == Path::new("/")
            && fs
                .mount_table()
                .is_ok_and(|table| root_is_hidden_overlay(&table, &self.hidden_root).is_some())
    }
}

/// Whether a path is there, as `lstat(2)` sees it.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    /// Something is there: a file, a directory, a device or a link, even one
    /// to nothing.
    Present,
    /// Nothing is there.
    Absent,
    /// NAILS cannot tell, for this reason.
    Unknown(String),
}

/// What the check found under the root.
struct Traces<'a, F: Filesystem> {
    fs: &'a F,
    files: DecoyFiles<'a, F>,
    root: &'a Path,
    /// The hidden volume's locations, resolved: what lies there is not the
    /// decoy's.
    hidden: &'a [PathBuf],
    /// Each trace, as the warning names it.
    found: Vec<String>,
    /// Why NAILS cannot tell about the rest.
    unread: Vec<String>,
}

impl<'a, F: Filesystem> Traces<'a, F> {
    /// The traces under `root`; `hidden` are the hidden volume's locations.
    fn read(fs: &'a F, root: &'a Path, hidden: &'a [PathBuf]) -> Self {
        let mut traces = Self {
            fs,
            files: DecoyFiles::new(fs, root, hidden),
            root,
            hidden,
            found: Vec::new(),
            unread: Vec::new(),
        };
        traces.note(&root.join(STORE));
        traces.units();
        traces.note_all(INSTALL_PATHS);
        let homes = traces.accounts();
        traces.note_all(HOOK_FILES);
        traces.hooks();
        for file in BACKED_UP_FILES {
            traces.note(&root.join(format!("{file}{BACKUP_SUFFIX}")));
        }
        traces.homes(&homes);
        traces
    }

    /// `path`, a path under the root, as the decoy names it.
    fn shown(&self, path: &Path) -> String {
        self.files.shown(path)
    }

    /// Whether `path` is there. A link is not followed, so a link to nothing
    /// is there as well.
    fn seen(&self, path: &Path) -> Seen {
        if self.fs.is_symlink(path).unwrap_or(false) || self.fs.path_exists(path).unwrap_or(false) {
            return Seen::Present;
        }
        // Neither lookup saw it: it is missing, or one of them failed, which
        // only the error of resolving it tells.
        match self.fs.canonicalize(path) {
            Err(e) => match e.io_kind() {
                Some(ErrorKind::NotFound | ErrorKind::NotADirectory) => Seen::Absent,
                Some(ErrorKind::PermissionDenied) => Seen::Unknown(format!(
                    "NAILS cannot look up {}; run the command again with sudo",
                    self.shown(path)
                )),
                _ => Seen::Unknown(format!("NAILS cannot look up {} ({e})", self.shown(path))),
            },
            // Resolved after both lookups missed it: it appeared just now.
            Ok(_) => Seen::Absent,
        }
    }

    /// Record `path` as a trace when it is there, or why NAILS cannot tell.
    /// Whether NAILS could tell.
    fn note(&mut self, path: &Path) -> bool {
        match self.seen(path) {
            Seen::Present => self.found.push(self.shown(path)),
            Seen::Absent => {}
            Seen::Unknown(why) => {
                self.unread.push(why);
                return false;
            }
        }
        true
    }

    /// [`note`](Self::note) each of `paths`, relative to the root.
    fn note_all(&mut self, paths: &[&str]) {
        for path in paths {
            self.note(&self.root.join(path));
        }
    }

    /// The daemon's units, the links that enable one, its drop-in
    /// directories and its tmpfiles rule.
    fn units(&mut self) {
        // A directory another one resolves to is read once: on a merged
        // `/usr`, `/lib` is `/usr/lib`.
        let mut read: Vec<PathBuf> = Vec::new();
        for dir in UNIT_DIRS {
            let dir = self.root.join(dir);
            if let Ok(real) = self.fs.canonicalize(&dir) {
                if read.contains(&real) {
                    continue;
                }
                read.push(real);
            }
            for unit in DAEMON_UNITS {
                self.note(&dir.join(unit));
            }
        }
        let admin = self.root.join(ADMIN_UNIT_DIR);
        for unit in DAEMON_UNITS {
            self.note(&admin.join(format!("{unit}.d")));
        }
        match self.files.list(&admin) {
            Ok(mut entries) => {
                // In a fixed order: a directory lists its entries in none.
                entries.sort();
                for entry in entries {
                    let is_dependency_dir = entry.file_name().is_some_and(|name| {
                        let name = name.to_string_lossy();
                        DEPENDENCY_DIR_SUFFIXES
                            .iter()
                            .any(|suffix| name.ends_with(suffix))
                    });
                    if is_dependency_dir {
                        for unit in DAEMON_UNITS {
                            self.note(&entry.join(unit));
                        }
                    }
                }
            }
            Err(why) => self.unread.push(why),
        }
        self.note(&self.root.join(TMPFILES_RULE));
    }

    /// The text of `rel`, a file under the root, or `None` when it is not
    /// there; why NAILS cannot read it goes to the reasons.
    fn text(&mut self, rel: &str) -> Option<Vec<u8>> {
        match self.files.read(&self.root.join(rel)) {
            DecoyFile::Text(text) => Some(text),
            DecoyFile::Absent | DecoyFile::Null => None,
            DecoyFile::Unread(why) => {
                self.unread.push(why);
                None
            }
        }
    }

    /// The build group and users, and the homes of `/root` and of
    /// `/etc/passwd`.
    fn accounts(&mut self) -> Vec<String> {
        let mut group_ids: Vec<String> = Vec::new();
        if let Some(text) = self.text("etc/group") {
            for line in String::from_utf8_lossy(&text).lines() {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.first() == Some(&BUILD_GROUP) {
                    group_ids.push(fields.get(2).copied().unwrap_or_default().to_string());
                }
            }
            if !group_ids.is_empty() {
                self.found
                    .push(format!("the {BUILD_GROUP} group in /etc/group"));
            }
        }
        let mut homes = vec!["/root".to_string()];
        let mut builders: Vec<String> = Vec::new();
        if let Some(text) = self.text("etc/passwd") {
            for line in String::from_utf8_lossy(&text).lines() {
                let fields: Vec<&str> = line.split(':').collect();
                let name = fields.first().copied().unwrap_or_default();
                let gid = fields.get(3).copied().unwrap_or_default();
                if is_build_user(name) || (!gid.is_empty() && group_ids.iter().any(|id| id == gid))
                {
                    builders.push(name.to_string());
                }
                if let Some(home) = fields.get(5)
                    && home.starts_with('/')
                    && *home != "/"
                    && !homes.iter().any(|known| known == home)
                {
                    homes.push((*home).to_string());
                }
            }
        }
        if !builders.is_empty() {
            self.found.push(build_users(&builders));
        }
        homes
    }

    /// The shell startup files whose hook names a script of the default
    /// profile.
    fn hooks(&mut self) {
        for file in HOOKED_FILES {
            if let Some(text) = self.text(file)
                && text
                    .windows(HOOK_MARK.len())
                    .any(|window| window == HOOK_MARK)
            {
                self.found.push(format!("the Nix lines in /{file}"));
            }
        }
    }

    /// What Nix keeps in each of `homes`, but in one on the hidden volume.
    /// Once NAILS cannot look into a home, the rest of it is not looked up.
    fn homes(&mut self, homes: &[String]) {
        for home in homes {
            let home = self.root.join(home.trim_start_matches('/'));
            if self.hidden.iter().any(|hidden| home.starts_with(hidden)) {
                continue;
            }
            for path in HOME_PATHS {
                if !self.note(&home.join(path)) {
                    break;
                }
            }
        }
    }
}

/// Whether `name` is the name the installer gives a build user:
/// `nixbld<N>`, or `_nixbld<N>` as on macOS.
fn is_build_user(name: &str) -> bool {
    name.strip_prefix('_')
        .unwrap_or(name)
        .strip_prefix(BUILD_GROUP)
        .is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
}

/// The build users of `/etc/passwd`, as the warning names them: up to
/// three by name, more by the first two and a count.
fn build_users(names: &[String]) -> String {
    let shown = match names {
        [] => return String::new(),
        [one] => return format!("the Nix build user {one} in /etc/passwd"),
        [_, _] | [_, _, _] => listing(names),
        [first, second, rest @ ..] => format!("{first}, {second} and {} more", rest.len()),
    };
    format!("{} Nix build users in /etc/passwd ({shown})", names.len())
}

/// `items` as a list in a sentence: `a`, `a and b`, `a, b and c`.
fn listing(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// The check's result for what it found and what it could not read.
fn verdict(found: &[String], unread: &[String]) -> CheckResult {
    let unread = unread.join("; ");
    if found.is_empty() {
        if unread.is_empty() {
            return CheckResult::Pass("no trace of a Nix install on the decoy".to_string());
        }
        return CheckResult::warn_with(
            format!("NAILS cannot tell whether a Nix install left traces on the decoy: {unread}."),
            format!("See {DOC}."),
        );
    }
    let mut message = format!(
        "Nix is installed on the decoy, or was: it holds {}.",
        listing(found)
    );
    if !unread.is_empty() {
        message.push_str(&format!(" NAILS cannot tell about the rest: {unread}."));
    }
    CheckResult::warn_with(
        message,
        format!(
            "What Nix installs or builds on the decoy is written to its disk under the name of \
             each package. Install the hidden session's software inside a hidden session, where \
             everything Nix writes lands on the hidden volume, and if the decoy does not need \
             Nix, remove it and these traces long before the next session. See {DOC}."
        ),
    )
}

impl<F: Filesystem> PreFlightCheck<F> for DecoyNixTraceCheck {
    fn name(&self) -> &'static str {
        "decoy-nix-trace"
    }

    fn description(&self) -> &'static str {
        "Warns when a decoy that is not NixOS holds what a Nix install leaves behind"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        if self.is_nixos {
            return Ok(CheckResult::Pass(
                "the decoy is NixOS, whose own package manager Nix is".to_string(),
            ));
        }
        if self.in_hidden_session(fs) {
            return Ok(CheckResult::skipped(
                "a hidden session is running, and `/` shows its files over the decoy's: run the \
                 check on the decoy",
            ));
        }
        let hidden: Vec<PathBuf> = hidden_locations(fs, &self.hidden_root)
            .into_iter()
            .map(|location| location.path)
            .collect();
        let traces = Traces::read(fs, &self.root, &hidden);
        Ok(verdict(&traces.found, &traces.unread))
    }
}

#[cfg(test)]
#[path = "decoy_nix_trace_tests.rs"]
mod tests;
