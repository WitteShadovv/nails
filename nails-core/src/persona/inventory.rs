// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Collector for the decoy persona state the hidden session inherits.
//!
//! When NAILS runs the hidden session in the decoy home (the default
//! [`SharedHome`](crate::config::PersonaMode::SharedHome) model), every autostart
//! entry, enabled user service and display-manager autologin the decoy account
//! carries over runs under the decoy identity in the hidden session. Sync, cloud,
//! messaging and account clients can then reach remote servers and the operator's
//! other devices while the hidden environment is active.
//!
//! This module is a platform-neutral, read-only inventory of that inherited
//! state. It is a pure function of a [`Filesystem`], so the same collector backs
//! the Warn-only [`inherited-autostart`](crate::preflight::checks) pre-flight
//! check, the full listing in `nails check`, and the activation-time masking of
//! inherited entries. It never writes and never fails: an unreadable or missing
//! source contributes nothing rather than aborting the inventory.
//!
//! # Scope and honesty
//!
//! The "remote-linked" tag is a name-only heuristic against a fixed list of
//! common sync and account clients. It makes **no** claim about signed-in state
//! or about what an entry actually does; it only flags that an inherited name
//! looks like a client that talks to remote servers, so the operator can decide
//! whether to mask it. System services are never classified heuristically.

use std::path::Path;

use crate::Filesystem;

/// Where an inherited entry comes from.
///
/// The source determines both how the entry is reported and whether it can be
/// masked for the hidden session: autostart entries and user units can be
/// shadowed from the operator's home, while lingering and autologin are
/// system-level facts that are reported but not masked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InheritedSource {
    /// A `~/.config/autostart/*.desktop` entry in the operator's home.
    UserAutostart,
    /// A `/etc/xdg/autostart/*.desktop` entry shared by every account.
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
    /// The name matches a common sync or account client (name-only heuristic).
    pub remote_linked: bool,
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

/// Fixed list of common sync, cloud, messaging and account client name
/// fragments. A match is a case-insensitive substring of the entry name; it
/// flags the name as remote-linked and makes no claim about signed-in state.
const REMOTE_CLIENTS: &[&str] = &[
    "dropbox",
    "nextcloud",
    "owncloud",
    "syncthing",
    "megasync",
    "insync",
    "onedrive",
    "rclone",
    "telegram",
    "signal",
    "slack",
    "discord",
    "element",
    "keybase",
    "thunderbird",
    "evolution",
    "gnome-online-accounts",
    "goa-daemon",
    "kaccounts",
    "zoom",
    "teams",
];

/// Whether an entry name looks like a remote-linked client.
fn is_remote_linked(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    REMOTE_CLIENTS.iter().any(|client| lower.contains(client))
}

/// Collect the decoy persona state the hidden session would inherit for `user`
/// in `home`.
///
/// `fresh_home` selects the fresh-home persona model: because the operator's home
/// is replaced by a clean hidden home, user-level sources (user autostart and
/// user units) are not inherited and are omitted. Global autostart, global units,
/// lingering and autologin are system-level and are always reported.
///
/// This is read-only and infallible: a missing or unreadable source simply
/// contributes nothing.
pub fn collect_inherited_persona<F: Filesystem>(
    fs: &F,
    home: &Path,
    user: &str,
    fresh_home: bool,
) -> PersonaInventory {
    let mut entries = Vec::new();

    if !fresh_home {
        collect_autostart(
            fs,
            &home.join(".config/autostart"),
            InheritedSource::UserAutostart,
            &mut entries,
        );
    }
    collect_autostart(
        fs,
        Path::new("/etc/xdg/autostart"),
        InheritedSource::GlobalAutostart,
        &mut entries,
    );

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

    if !user.is_empty()
        && fs
            .path_exists(&Path::new("/var/lib/systemd/linger").join(user))
            .unwrap_or(false)
    {
        push_entry(&mut entries, user.to_string(), InheritedSource::Linger);
    }

    collect_autologin(fs, user, &mut entries);

    PersonaInventory { entries }
}

/// Add an entry, tagging it as remote-linked by the name-only heuristic.
fn push_entry(entries: &mut Vec<PersonaEntry>, name: String, source: InheritedSource) {
    let remote_linked = is_remote_linked(&name);
    entries.push(PersonaEntry {
        name,
        source,
        remote_linked,
    });
}

/// List and classify the `*.desktop` entries in an autostart directory.
///
/// Entries that are hidden (`Hidden=true`) are skipped, as is NAILS' own
/// notification autostart entry. Names are reported as the `.desktop` stem,
/// sorted and de-duplicated.
fn collect_autostart<F: Filesystem>(
    fs: &F,
    dir: &Path,
    source: InheritedSource,
    entries: &mut Vec<PersonaEntry>,
) {
    let mut names: Vec<String> = Vec::new();

    for path in list_dir(fs, dir) {
        let file_name = file_name_of(&path);
        if !file_name.ends_with(".desktop") || file_name == crate::shell::NOTIFY_AUTOSTART_FILE {
            continue;
        }

        let content = fs.read_file_content(&path).unwrap_or_default();
        if desktop_entry_hidden(&content) {
            continue;
        }

        names.push(file_name.trim_end_matches(".desktop").to_string());
    }

    push_sorted(entries, names, source);
}

/// The final path component as an owned string, lossily decoded. A directory
/// listing always yields a final component, so this never needs to branch on a
/// missing name.
fn file_name_of(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// Whether a `.desktop` file is hidden (`Hidden=true` in its `[Desktop Entry]`).
fn desktop_entry_hidden(content: &str) -> bool {
    content.lines().any(|line| {
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        key.trim() == "Hidden" && value.trim().eq_ignore_ascii_case("true")
    })
}

/// List the enabled units under a systemd unit directory.
///
/// Enabled units appear as symlinks inside `*.wants` sub-directories (for
/// example `default.target.wants/syncthing.service`). Unit names are reported
/// with their suffix, sorted and de-duplicated across the `.wants` directories.
fn collect_wants<F: Filesystem>(
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

/// Parse the display-manager autologin configuration and report the autologin
/// user, if any, for each of GDM, SDDM and LightDM.
fn collect_autologin<F: Filesystem>(fs: &F, user: &str, entries: &mut Vec<PersonaEntry>) {
    let mut names: Vec<String> = Vec::new();

    if let Some(login) = gdm_autologin_user(fs) {
        names.push(login);
    }
    if let Some(login) = sddm_autologin_user(fs) {
        names.push(login);
    }
    if let Some(login) = lightdm_autologin_user(fs) {
        names.push(login);
    }

    // A display manager may name the autologin user explicitly, or only enable
    // autologin without naming an account in the file we can read; in the latter
    // case fall back to the resolved operator so the entry still carries a name.
    let names: Vec<String> = names
        .into_iter()
        .map(|name| {
            if name.is_empty() {
                user.to_string()
            } else {
                name
            }
        })
        .filter(|name| !name.is_empty())
        .collect();

    push_sorted(entries, names, InheritedSource::Autologin);
}

/// GDM autologin from `/etc/gdm/custom.conf` or `/etc/gdm3/custom.conf`.
fn gdm_autologin_user<F: Filesystem>(fs: &F) -> Option<String> {
    for path in ["/etc/gdm/custom.conf", "/etc/gdm3/custom.conf"] {
        let Ok(content) = fs.read_file_content(Path::new(path)) else {
            continue;
        };
        let enabled = ini_value(&content, "AutomaticLoginEnable")
            .map(|value| value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if !enabled {
            continue;
        }
        return Some(ini_value(&content, "AutomaticLogin").unwrap_or_default());
    }
    None
}

/// SDDM autologin from `/etc/sddm.conf` or any `/etc/sddm.conf.d/*.conf`.
fn sddm_autologin_user<F: Filesystem>(fs: &F) -> Option<String> {
    let mut files = vec![std::path::PathBuf::from("/etc/sddm.conf")];
    files.extend(conf_d_files(fs, Path::new("/etc/sddm.conf.d")));

    for path in files {
        let Ok(content) = fs.read_file_content(&path) else {
            continue;
        };
        if let Some(login) = ini_value(&content, "User")
            && !login.is_empty()
        {
            return Some(login);
        }
    }
    None
}

/// LightDM autologin from `/etc/lightdm/lightdm.conf` or any
/// `/etc/lightdm/lightdm.conf.d/*.conf`.
fn lightdm_autologin_user<F: Filesystem>(fs: &F) -> Option<String> {
    let mut files = vec![std::path::PathBuf::from("/etc/lightdm/lightdm.conf")];
    files.extend(conf_d_files(fs, Path::new("/etc/lightdm/lightdm.conf.d")));

    for path in files {
        let Ok(content) = fs.read_file_content(&path) else {
            continue;
        };
        if let Some(login) = ini_value(&content, "autologin-user")
            && !login.is_empty()
        {
            return Some(login);
        }
    }
    None
}

/// The `*.conf` files in a `conf.d` directory, sorted for a stable read order.
fn conf_d_files<F: Filesystem>(fs: &F, dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files: Vec<std::path::PathBuf> = list_dir(fs, dir)
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.ends_with(".conf"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    files
}

/// Read the first value of an INI-style `key = value` line, ignoring sections.
fn ini_value(content: &str, key: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let (candidate, value) = line.split_once('=')?;
        if candidate.trim() == key {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}

/// List a directory, treating any error (missing, unreadable) as empty so the
/// inventory stays best-effort.
fn list_dir<F: Filesystem>(fs: &F, dir: &Path) -> Vec<std::path::PathBuf> {
    fs.list_directory(dir).unwrap_or_default()
}

/// Sort and de-duplicate names, then append them as entries of one source.
fn push_sorted(entries: &mut Vec<PersonaEntry>, mut names: Vec<String>, source: InheritedSource) {
    names.sort();
    names.dedup();
    for name in names {
        push_entry(entries, name, source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use std::path::PathBuf;

    const USER: &str = "alice";
    const HOME: &str = "/home/alice";

    fn collect(fs: &MockFilesystem, fresh_home: bool) -> PersonaInventory {
        collect_inherited_persona(fs, Path::new(HOME), USER, fresh_home)
    }

    fn names_for(inventory: &PersonaInventory, source: InheritedSource) -> Vec<String> {
        inventory
            .entries
            .iter()
            .filter(|entry| entry.source == source)
            .map(|entry| entry.name.clone())
            .collect()
    }

    #[test]
    fn empty_system_yields_empty_inventory() {
        let fs = MockFilesystem::new();
        assert!(collect(&fs, false).is_empty());
        assert_eq!(collect(&fs, false).len(), 0);
    }

    #[test]
    fn lists_user_autostart_and_skips_hidden_and_own_entry() {
        let fs = MockFilesystem::new();
        let dir = PathBuf::from("/home/alice/.config/autostart");
        let dropbox = dir.join("dropbox.desktop");
        let hidden = dir.join("telegram.desktop");
        let own = dir.join("nails-notify.desktop");
        let editor = dir.join("editor.desktop");
        // A non-.desktop file in the directory must be ignored.
        let readme = dir.join("README");
        fs.mock_set_directory_contents(
            &dir,
            vec![
                dropbox.clone(),
                hidden.clone(),
                own.clone(),
                editor.clone(),
                readme.clone(),
            ],
        );
        fs.mock_set_file_content(dropbox.to_str().unwrap(), "[Desktop Entry]\nName=Dropbox\n");
        fs.mock_set_file_content(
            hidden.to_str().unwrap(),
            "[Desktop Entry]\nName=Telegram\nHidden=true\n",
        );
        fs.mock_set_file_content(own.to_str().unwrap(), "[Desktop Entry]\nName=Notify\n");
        fs.mock_set_file_content(editor.to_str().unwrap(), "[Desktop Entry]\nName=Editor\n");
        fs.mock_set_file_content(readme.to_str().unwrap(), "not a desktop entry\n");

        let inventory = collect(&fs, false);
        assert_eq!(
            names_for(&inventory, InheritedSource::UserAutostart),
            vec!["dropbox".to_string(), "editor".to_string()]
        );
        // Telegram (remote-linked) is hidden and skipped; the own notify entry is
        // skipped too, so only the visible Dropbox entry is tagged remote-linked.
        assert_eq!(inventory.remote_linked_names(), vec!["dropbox".to_string()]);
    }

    #[test]
    fn remote_client_names_are_tagged() {
        let fs = MockFilesystem::new();
        let dir = PathBuf::from("/home/alice/.config/autostart");
        let sync = dir.join("nextcloud.desktop");
        let plain = dir.join("screenshot-tool.desktop");
        fs.mock_set_directory_contents(&dir, vec![sync.clone(), plain.clone()]);
        fs.mock_set_file_content(sync.to_str().unwrap(), "[Desktop Entry]\n");
        fs.mock_set_file_content(plain.to_str().unwrap(), "[Desktop Entry]\n");

        let inventory = collect(&fs, false);
        assert_eq!(
            inventory.remote_linked_names(),
            vec!["nextcloud".to_string()]
        );
        let plain_entry = inventory
            .entries
            .iter()
            .find(|entry| entry.name == "screenshot-tool")
            .unwrap();
        assert!(!plain_entry.remote_linked);
    }

    #[test]
    fn lists_global_autostart() {
        let fs = MockFilesystem::new();
        let dir = PathBuf::from("/etc/xdg/autostart");
        let entry = dir.join("syncthing.desktop");
        fs.mock_set_directory_contents(&dir, vec![entry.clone()]);
        fs.mock_set_file_content(entry.to_str().unwrap(), "[Desktop Entry]\n");

        let inventory = collect(&fs, false);
        assert_eq!(
            names_for(&inventory, InheritedSource::GlobalAutostart),
            vec!["syncthing".to_string()]
        );
        assert_eq!(
            inventory.remote_linked_names(),
            vec!["syncthing".to_string()]
        );
    }

    #[test]
    fn lists_user_and_global_wants_units() {
        let fs = MockFilesystem::new();
        let user_dir = PathBuf::from("/home/alice/.config/systemd/user");
        let user_wants = user_dir.join("default.target.wants");
        fs.mock_set_directory_contents(&user_dir, vec![user_wants.clone()]);
        fs.mock_set_directory_contents(&user_wants, vec![user_wants.join("syncthing.service")]);

        let global_dir = PathBuf::from("/etc/systemd/user");
        let global_wants = global_dir.join("timers.target.wants");
        fs.mock_set_directory_contents(&global_dir, vec![global_wants.clone()]);
        fs.mock_set_directory_contents(&global_wants, vec![global_wants.join("backup.timer")]);

        let inventory = collect(&fs, false);
        assert_eq!(
            names_for(&inventory, InheritedSource::UserUnit),
            vec!["syncthing.service".to_string()]
        );
        assert_eq!(
            names_for(&inventory, InheritedSource::GlobalUnit),
            vec!["backup.timer".to_string()]
        );
    }

    #[test]
    fn ignores_non_wants_directories_in_systemd_user() {
        let fs = MockFilesystem::new();
        let user_dir = PathBuf::from("/home/alice/.config/systemd/user");
        // A plain unit file dropped in the directory is not an enabled unit.
        fs.mock_set_directory_contents(&user_dir, vec![user_dir.join("custom.service")]);

        let inventory = collect(&fs, false);
        assert!(names_for(&inventory, InheritedSource::UserUnit).is_empty());
    }

    #[test]
    fn reports_linger_when_present() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/var/lib/systemd/linger/alice", true);

        let inventory = collect(&fs, false);
        assert_eq!(
            names_for(&inventory, InheritedSource::Linger),
            vec!["alice".to_string()]
        );
    }

    #[test]
    fn no_linger_entry_when_absent() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/var/lib/systemd/linger/alice", false);

        let inventory = collect(&fs, false);
        assert!(names_for(&inventory, InheritedSource::Linger).is_empty());
    }

    #[test]
    fn reports_gdm_autologin() {
        let fs = MockFilesystem::new();
        fs.mock_set_file_content(
            "/etc/gdm3/custom.conf",
            "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=bob\n",
        );

        let inventory = collect(&fs, false);
        assert_eq!(
            names_for(&inventory, InheritedSource::Autologin),
            vec!["bob".to_string()]
        );
    }

    #[test]
    fn ignores_gdm_when_autologin_disabled() {
        let fs = MockFilesystem::new();
        fs.mock_set_file_content(
            "/etc/gdm/custom.conf",
            "[daemon]\nAutomaticLoginEnable=false\nAutomaticLogin=bob\n",
        );

        let inventory = collect(&fs, false);
        assert!(names_for(&inventory, InheritedSource::Autologin).is_empty());
    }

    #[test]
    fn gdm_autologin_enabled_without_named_user_falls_back_to_operator() {
        let fs = MockFilesystem::new();
        fs.mock_set_file_content(
            "/etc/gdm/custom.conf",
            "[daemon]\nAutomaticLoginEnable=true\n",
        );

        let inventory = collect(&fs, false);
        assert_eq!(
            names_for(&inventory, InheritedSource::Autologin),
            vec!["alice".to_string()]
        );
    }

    #[test]
    fn reports_sddm_autologin_from_conf_d() {
        let fs = MockFilesystem::new();
        // The main file has an empty autologin user, so the collector must fall
        // through to the drop-in. A non-.conf file in the drop-in dir is ignored.
        fs.mock_set_file_content("/etc/sddm.conf", "[Autologin]\nUser=\n");
        let dir = PathBuf::from("/etc/sddm.conf.d");
        let drop_in = dir.join("10-autologin.conf");
        let note = dir.join("notes.txt");
        fs.mock_set_directory_contents(&dir, vec![drop_in.clone(), note.clone()]);
        fs.mock_set_file_content(drop_in.to_str().unwrap(), "[Autologin]\nUser=carol\n");
        fs.mock_set_file_content(note.to_str().unwrap(), "ignore me\n");

        let inventory = collect(&fs, false);
        assert_eq!(
            names_for(&inventory, InheritedSource::Autologin),
            vec!["carol".to_string()]
        );
    }

    #[test]
    fn sddm_without_autologin_user_reports_nothing() {
        let fs = MockFilesystem::new();
        fs.mock_set_file_content("/etc/sddm.conf", "[General]\nNumlock=on\n");

        let inventory = collect(&fs, false);
        assert!(names_for(&inventory, InheritedSource::Autologin).is_empty());
    }

    #[test]
    fn reports_lightdm_autologin() {
        let fs = MockFilesystem::new();
        fs.mock_set_file_content(
            "/etc/lightdm/lightdm.conf",
            "[Seat:*]\nautologin-user=dave\n",
        );

        let inventory = collect(&fs, false);
        assert_eq!(
            names_for(&inventory, InheritedSource::Autologin),
            vec!["dave".to_string()]
        );
    }

    #[test]
    fn reports_lightdm_autologin_from_conf_d_when_main_is_empty() {
        let fs = MockFilesystem::new();
        fs.mock_set_file_content("/etc/lightdm/lightdm.conf", "[Seat:*]\nautologin-user=\n");
        let dir = PathBuf::from("/etc/lightdm/lightdm.conf.d");
        let drop_in = dir.join("50-autologin.conf");
        fs.mock_set_directory_contents(&dir, vec![drop_in.clone()]);
        fs.mock_set_file_content(drop_in.to_str().unwrap(), "[Seat:*]\nautologin-user=erin\n");

        let inventory = collect(&fs, false);
        assert_eq!(
            names_for(&inventory, InheritedSource::Autologin),
            vec!["erin".to_string()]
        );
    }

    #[test]
    fn fresh_home_drops_user_level_sources_only() {
        let fs = MockFilesystem::new();

        // User-level sources that fresh-home must drop.
        let user_autostart = PathBuf::from("/home/alice/.config/autostart");
        let user_entry = user_autostart.join("dropbox.desktop");
        fs.mock_set_directory_contents(&user_autostart, vec![user_entry.clone()]);
        fs.mock_set_file_content(user_entry.to_str().unwrap(), "[Desktop Entry]\n");

        let user_units = PathBuf::from("/home/alice/.config/systemd/user");
        let user_wants = user_units.join("default.target.wants");
        fs.mock_set_directory_contents(&user_units, vec![user_wants.clone()]);
        fs.mock_set_directory_contents(&user_wants, vec![user_wants.join("syncthing.service")]);

        // System-level sources that must survive.
        let global_autostart = PathBuf::from("/etc/xdg/autostart");
        let global_entry = global_autostart.join("evolution.desktop");
        fs.mock_set_directory_contents(&global_autostart, vec![global_entry.clone()]);
        fs.mock_set_file_content(global_entry.to_str().unwrap(), "[Desktop Entry]\n");
        fs.mock_set_path_exists("/var/lib/systemd/linger/alice", true);

        let inventory = collect(&fs, true);
        assert!(names_for(&inventory, InheritedSource::UserAutostart).is_empty());
        assert!(names_for(&inventory, InheritedSource::UserUnit).is_empty());
        assert_eq!(
            names_for(&inventory, InheritedSource::GlobalAutostart),
            vec!["evolution".to_string()]
        );
        assert_eq!(
            names_for(&inventory, InheritedSource::Linger),
            vec!["alice".to_string()]
        );
    }

    #[test]
    fn maskable_covers_autostart_and_units_only() {
        let fs = MockFilesystem::new();
        let autostart = PathBuf::from("/home/alice/.config/autostart");
        let entry = autostart.join("dropbox.desktop");
        fs.mock_set_directory_contents(&autostart, vec![entry.clone()]);
        fs.mock_set_file_content(entry.to_str().unwrap(), "[Desktop Entry]\n");
        fs.mock_set_path_exists("/var/lib/systemd/linger/alice", true);

        let inventory = collect(&fs, false);
        let maskable: Vec<&str> = inventory
            .maskable()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(maskable, vec!["dropbox"]);
    }

    #[test]
    fn source_metadata_is_stable() {
        assert_eq!(InheritedSource::UserAutostart.as_str(), "user-autostart");
        assert_eq!(
            InheritedSource::GlobalAutostart.as_str(),
            "global-autostart"
        );
        assert_eq!(InheritedSource::UserUnit.as_str(), "user-unit");
        assert_eq!(InheritedSource::GlobalUnit.as_str(), "global-unit");
        assert_eq!(InheritedSource::Linger.as_str(), "linger");
        assert_eq!(InheritedSource::Autologin.as_str(), "autologin");

        assert!(InheritedSource::UserAutostart.is_user_level());
        assert!(InheritedSource::UserUnit.is_user_level());
        assert!(!InheritedSource::GlobalAutostart.is_user_level());
        assert!(!InheritedSource::Linger.is_user_level());

        assert!(InheritedSource::GlobalAutostart.is_autostart());
        assert!(InheritedSource::GlobalUnit.is_unit());
        assert!(!InheritedSource::Linger.is_maskable());
        assert!(!InheritedSource::Autologin.is_maskable());
    }

    #[test]
    fn empty_user_skips_linger_lookup() {
        let fs = MockFilesystem::new();
        // With no resolved operator the linger file cannot be named, so no
        // lookup is attempted and nothing is reported.
        let inventory = collect_inherited_persona(&fs, Path::new(HOME), "", false);
        assert!(names_for(&inventory, InheritedSource::Linger).is_empty());
    }
}
