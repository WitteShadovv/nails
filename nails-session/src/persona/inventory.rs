// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Collector for the decoy persona state the hidden session inherits.
//!
//! When NAILS runs the hidden session in the decoy home (the default
//! [`SharedHome`](crate::config::PersonaMode::SharedHome) model), every autostart
//! entry, enabled user service and display-manager autologin the decoy account
//! carries over runs under the decoy identity in the hidden session. Sync, cloud,
//! messaging and account clients can then reach remote servers and the operator's
//! other devices while the hidden environment is active. System-wide autostart
//! entries and user units carry over in every persona mode.
//!
//! This module is a platform-neutral, read-only inventory of that inherited
//! state. It is a pure function of what it reads (a [`PersonaSource`]: any
//! [`Filesystem`], or the next root at entry), so the same collector backs
//! the Warn-only `inherited-autostart` pre-flight check (in `nails-core`),
//! the full listing in `nails check`, and the activation-time masking of
//! inherited entries. It never writes and never fails: an unreadable or missing
//! source contributes nothing rather than aborting the inventory.
//!
//! # Scope and honesty
//!
//! Each entry carries two name-only judgements from [`super::classify`]: whether
//! the name is a known trace writer ("remote-linked": a client that carries data
//! off the machine) and whether a system-wide entry is a component the desktop
//! or distribution ships. Neither makes a claim about signed-in state or about
//! what an entry actually does. System services are never classified.

use std::path::Path;

use super::classify::{is_desktop_component, is_trace_writer};
use super::{autologin, autostart};
use crate::Filesystem;

/// What the inventory reads. Every [`Filesystem`] is one; activation reads the
/// operator's home through the next root instead, resolved as the hidden root
/// will resolve it.
pub trait PersonaSource {
    /// The entries of `dir`, as paths below it; empty when it cannot be listed.
    fn entries(&self, dir: &Path) -> Vec<std::path::PathBuf>;
    /// The text of the file at `path`, `None` when it cannot be read.
    fn text(&self, path: &Path) -> Option<String>;
    /// Whether `path` exists.
    fn exists(&self, path: &Path) -> bool;
}

impl<F: Filesystem> PersonaSource for F {
    fn entries(&self, dir: &Path) -> Vec<std::path::PathBuf> {
        self.list_directory(dir).unwrap_or_default()
    }

    fn text(&self, path: &Path) -> Option<String> {
        self.read_file_content(path).ok()
    }

    fn exists(&self, path: &Path) -> bool {
        self.path_exists(path).unwrap_or(false)
    }
}

/// Where an inherited entry comes from.
///
/// The source determines both how the entry is reported and whether it can be
/// masked for the hidden session: autostart entries and user units can be
/// shadowed from the operator's home, while lingering and autologin are
/// system-level facts that are reported but not masked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InheritedSource {
    /// A `.desktop` autostart entry in the operator's home: `~/.config/autostart`,
    /// or on NixOS the autostart directory of the user's own Nix profile.
    UserAutostart,
    /// A system-wide `.desktop` autostart entry shared by every account:
    /// `/etc/xdg/autostart`, or on NixOS the system and per-user profiles.
    GlobalAutostart,
    /// A user service or timer enabled in `~/.config/systemd/user/*.wants`.
    UserUnit,
    /// A user service or timer enabled in `/etc/systemd/user/*.wants`.
    GlobalUnit,
    /// Lingering is enabled for the operator (`/var/lib/systemd/linger/<user>`),
    /// so their user manager and enabled services run without an active login.
    Linger,
    /// A display manager is configured to log the operator in automatically.
    Autologin,
}

impl InheritedSource {
    /// Stable identifier used in JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            InheritedSource::UserAutostart => "user-autostart",
            InheritedSource::GlobalAutostart => "global-autostart",
            InheritedSource::UserUnit => "user-unit",
            InheritedSource::GlobalUnit => "global-unit",
            InheritedSource::Linger => "linger",
            InheritedSource::Autologin => "autologin",
        }
    }

    /// Whether the source is tied to the operator's home (as opposed to a
    /// system-level fact). Fresh-home mode replaces the home, so user-level
    /// sources are not inherited and are left out of the inventory.
    pub fn is_user_level(self) -> bool {
        matches!(
            self,
            InheritedSource::UserAutostart | InheritedSource::UserUnit
        )
    }

    /// Whether an entry from this source can be masked for the hidden session.
    ///
    /// Autostart entries (user or global) are masked with a `Hidden=true`
    /// override in the operator's home, and user units (user or global) with a
    /// `/dev/null` symlink mask; both shadow the lower-layer decoy entry only in
    /// the hidden overlay. Lingering and autologin cannot be masked this way.
    pub fn is_maskable(self) -> bool {
        self.is_autostart() || self.is_unit()
    }

    /// Whether this source is a desktop autostart entry.
    pub fn is_autostart(self) -> bool {
        matches!(
            self,
            InheritedSource::UserAutostart | InheritedSource::GlobalAutostart
        )
    }

    /// Whether this source is a systemd user unit.
    pub fn is_unit(self) -> bool {
        matches!(
            self,
            InheritedSource::UserUnit | InheritedSource::GlobalUnit
        )
    }
}

/// One inherited persona entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonaEntry {
    /// The entry's name: the `.desktop` stem for autostart entries, the full unit
    /// name (with suffix) for units, and the operator's login name for lingering
    /// and autologin.
    pub name: String,
    /// Where the entry comes from.
    pub source: InheritedSource,
    /// The name is on the list of known trace writers: a sync, cloud, backup,
    /// messaging, mail, account or phone-link client (name-only heuristic).
    pub remote_linked: bool,
    /// A system-wide entry whose name is a component the installed desktop or
    /// distribution ships (name-only heuristic). Always false for entries in
    /// the operator's home, lingering and autologin: those were added by the
    /// user or by third-party software.
    pub desktop: bool,
}

impl PersonaEntry {
    /// An entry of `source` named `name`, classified by its name.
    pub fn new(name: impl Into<String>, source: InheritedSource) -> Self {
        let name = name.into();
        let remote_linked = is_trace_writer(&name);
        let desktop = matches!(
            source,
            InheritedSource::GlobalAutostart | InheritedSource::GlobalUnit
        ) && is_desktop_component(&name);
        Self {
            name,
            source,
            remote_linked,
            desktop,
        }
    }
}

/// The full inventory of inherited persona state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersonaInventory {
    /// The inherited entries, grouped by source in a stable order and sorted by
    /// name within each group.
    pub entries: Vec<PersonaEntry>,
}

impl PersonaInventory {
    /// Whether nothing is inherited.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many entries were found.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// The names tagged as remote-linked, in inventory order.
    pub fn remote_linked_names(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| entry.remote_linked)
            .map(|entry| entry.name.clone())
            .collect()
    }

    /// The entries that can be masked for the hidden session.
    pub fn maskable(&self) -> impl Iterator<Item = &PersonaEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.source.is_maskable())
    }
}

/// Collect the decoy persona state the hidden session would inherit for `user`
/// in `home`.
///
/// `fresh_home` selects the fresh-home persona model: because the operator's home
/// is replaced by a clean hidden home, user-level sources (user autostart and
/// user units) are not inherited and are omitted. Global autostart, global units,
/// lingering and autologin are system-level and are always reported.
///
/// Autostart entries follow the XDG autostart rules over the directories the
/// desktop reads (see [`autostart`]): for a name found in several, the most
/// important directory wins, and `Hidden=true` there hides the name everywhere.
///
/// This is read-only and infallible: a missing or unreadable source simply
/// contributes nothing.
pub fn collect_inherited_persona<F: PersonaSource>(
    fs: &F,
    home: &Path,
    user: &str,
    fresh_home: bool,
) -> PersonaInventory {
    let mut entries = Vec::new();

    let started = autostart::collect(fs, home, user, fresh_home);
    for source in [
        InheritedSource::UserAutostart,
        InheritedSource::GlobalAutostart,
    ] {
        let names = started
            .iter()
            .filter(|(_, from)| *from == source)
            .map(|(name, _)| name.clone())
            .collect();
        push_sorted(&mut entries, names, source);
    }

    if !fresh_home {
        collect_wants(
            fs,
            &home.join(".config/systemd/user"),
            InheritedSource::UserUnit,
            &mut entries,
        );
    }
    collect_wants(
        fs,
        Path::new("/etc/systemd/user"),
        InheritedSource::GlobalUnit,
        &mut entries,
    );

    if !user.is_empty() && fs.exists(&Path::new("/var/lib/systemd/linger").join(user)) {
        entries.push(PersonaEntry::new(user, InheritedSource::Linger));
    }

    collect_autologin(fs, user, &mut entries);

    PersonaInventory { entries }
}

/// The final path component as an owned string, lossily decoded. A directory
/// listing always yields a final component, so this never needs to branch on a
/// missing name.
pub(super) fn file_name_of(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// List the enabled units under a systemd unit directory.
///
/// Enabled units appear as symlinks inside `*.wants` sub-directories (for
/// example `default.target.wants/syncthing.service`). Unit names are reported
/// with their suffix, sorted and de-duplicated across the `.wants` directories.
fn collect_wants<F: PersonaSource>(
    fs: &F,
    dir: &Path,
    source: InheritedSource,
    entries: &mut Vec<PersonaEntry>,
) {
    let mut names: Vec<String> = Vec::new();

    for wants_dir in list_dir(fs, dir) {
        if !file_name_of(&wants_dir).ends_with(".wants") {
            continue;
        }

        for unit in list_dir(fs, &wants_dir) {
            names.push(file_name_of(&unit));
        }
    }

    push_sorted(entries, names, source);
}

/// The display-manager autologin the decoy carries: the accounts GDM, SDDM and
/// LightDM log in on their own, read as each of them reads its files
/// ([`autologin`]).
fn collect_autologin<F: PersonaSource>(fs: &F, user: &str, entries: &mut Vec<PersonaEntry>) {
    push_sorted(
        entries,
        autologin::accounts(fs, user),
        InheritedSource::Autologin,
    );
}

/// List a directory, treating any error (missing, unreadable) as empty so the
/// inventory stays best-effort.
pub(super) fn list_dir<F: PersonaSource>(fs: &F, dir: &Path) -> Vec<std::path::PathBuf> {
    fs.entries(dir)
}

/// Sort and de-duplicate names, then append them as entries of one source.
fn push_sorted(entries: &mut Vec<PersonaEntry>, mut names: Vec<String>, source: InheritedSource) {
    names.sort();
    names.dedup();
    for name in names {
        entries.push(PersonaEntry::new(name, source));
    }
}

#[cfg(test)]
mod tests;
