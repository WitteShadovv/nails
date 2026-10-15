// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The XDG autostart entries a desktop session starts for the operator.
//!
//! A session reads `autostart/` below `$XDG_CONFIG_HOME` (the home's
//! `~/.config`) and then below each directory of `$XDG_CONFIG_DIRS`, most
//! important first. Neither variable is set under `sudo`, so the directories
//! are those the platform's sessions use:
//!
//! - everywhere: `~/.config/autostart`, then `/etc/xdg/autostart`;
//! - on NixOS (a live `/run/current-system`), after `/etc/xdg/autostart`, the
//!   `etc/xdg/autostart` of each profile NixOS puts in `XDG_CONFIG_DIRS`: the
//!   user's own Nix profiles in the home (`~/.nix-profile`,
//!   `~/.local/state/nix/profile`), the per-user packages
//!   (`/etc/profiles/per-user/<user>`), the default profile
//!   (`/nix/var/nix/profiles/default`) and the system's packages
//!   (`/run/current-system/sw`), where the desktop's own entries live.
//!
//! The autostart specification decides between files of the same name: only
//! the one in the most important directory is used, and when that one says
//! `Hidden=true` the name is not started at all.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::inventory::{InheritedSource, PersonaSource, file_name_of, list_dir};

/// The live system link that marks a NixOS host.
const NIXOS_CURRENT_SYSTEM: &str = "/run/current-system";

/// One directory of the search path and whether it lives in the home.
struct AutostartDir {
    path: PathBuf,
    in_home: bool,
}

impl AutostartDir {
    fn home(home: &Path, rel: &str) -> Self {
        Self {
            path: home.join(rel),
            in_home: true,
        }
    }

    fn system(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            in_home: false,
        }
    }
}

/// The autostart directories for `user` in `home`, most important first.
fn search_path<F: PersonaSource>(fs: &F, home: &Path, user: &str) -> Vec<AutostartDir> {
    let mut dirs = vec![
        AutostartDir::home(home, ".config/autostart"),
        AutostartDir::system("/etc/xdg/autostart"),
    ];
    if fs.exists(Path::new(NIXOS_CURRENT_SYSTEM)) {
        dirs.push(AutostartDir::home(home, ".nix-profile/etc/xdg/autostart"));
        dirs.push(AutostartDir::home(
            home,
            ".local/state/nix/profile/etc/xdg/autostart",
        ));
        if !user.is_empty() && !user.contains('/') {
            dirs.push(AutostartDir::system(format!(
                "/etc/profiles/per-user/{user}/etc/xdg/autostart"
            )));
        }
        dirs.push(AutostartDir::system(
            "/nix/var/nix/profiles/default/etc/xdg/autostart",
        ));
        dirs.push(AutostartDir::system(
            "/run/current-system/sw/etc/xdg/autostart",
        ));
    }
    dirs
}

/// The autostart entries a session of `user` would start, as `.desktop` stems
/// with the source of the file that wins for each.
///
/// In fresh-home mode the directories in the home are skipped: the hidden home
/// does not carry them, so neither their entries nor their `Hidden=true`
/// overrides apply. NAILS' own legacy notification entry is never listed.
pub(super) fn collect<F: PersonaSource>(
    fs: &F,
    home: &Path,
    user: &str,
    fresh_home: bool,
) -> Vec<(String, InheritedSource)> {
    // For each name, the source of the winning file, or None when the winning
    // file hides the name.
    let mut winners: BTreeMap<String, Option<InheritedSource>> = BTreeMap::new();

    for dir in search_path(fs, home, user) {
        if fresh_home && dir.in_home {
            continue;
        }
        let source = if dir.in_home {
            InheritedSource::UserAutostart
        } else {
            InheritedSource::GlobalAutostart
        };
        for path in list_dir(fs, &dir.path) {
            let file_name = file_name_of(&path);
            let Some(stem) = file_name.strip_suffix(".desktop") else {
                continue;
            };
            if file_name == crate::artifacts::LEGACY_NOTIFY_AUTOSTART_FILE
                || winners.contains_key(stem)
            {
                continue;
            }
            let hidden = desktop_entry_hidden(&fs.text(&path).unwrap_or_default());
            winners.insert(stem.to_string(), (!hidden).then_some(source));
        }
    }

    winners
        .into_iter()
        .filter_map(|(name, source)| source.map(|source| (name, source)))
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Filesystem;
    use crate::filesystem::MockFilesystem;

    const HOME: &str = "/home/alice";

    fn entry(fs: &MockFilesystem, dir: &str, name: &str, content: &str) {
        let path = PathBuf::from(dir).join(name);
        let mut listing = fs.list_directory(Path::new(dir)).unwrap_or_default();
        listing.push(path.clone());
        fs.mock_set_directory_contents(Path::new(dir), listing);
        fs.mock_set_file_content(path.to_str().unwrap(), content);
    }

    fn started(fs: &MockFilesystem, fresh_home: bool) -> Vec<(String, InheritedSource)> {
        collect(fs, Path::new(HOME), "alice", fresh_home)
    }

    #[test]
    fn nixos_profiles_are_read_only_on_nixos() {
        let fs = MockFilesystem::new();
        let sw = "/run/current-system/sw/etc/xdg/autostart";
        entry(
            &fs,
            sw,
            "gnome-keyring-secrets.desktop",
            "[Desktop Entry]\n",
        );
        assert!(started(&fs, false).is_empty(), "not NixOS: not searched");

        fs.mock_set_path_exists(NIXOS_CURRENT_SYSTEM, true);
        assert_eq!(
            started(&fs, false),
            vec![(
                "gnome-keyring-secrets".to_string(),
                InheritedSource::GlobalAutostart
            )]
        );
    }

    #[test]
    fn every_nixos_profile_directory_is_searched() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(NIXOS_CURRENT_SYSTEM, true);
        entry(
            &fs,
            "/home/alice/.nix-profile/etc/xdg/autostart",
            "a.desktop",
            "",
        );
        entry(
            &fs,
            "/home/alice/.local/state/nix/profile/etc/xdg/autostart",
            "b.desktop",
            "",
        );
        entry(
            &fs,
            "/etc/profiles/per-user/alice/etc/xdg/autostart",
            "c.desktop",
            "",
        );
        entry(
            &fs,
            "/nix/var/nix/profiles/default/etc/xdg/autostart",
            "d.desktop",
            "",
        );
        assert_eq!(
            started(&fs, false),
            vec![
                ("a".to_string(), InheritedSource::UserAutostart),
                ("b".to_string(), InheritedSource::UserAutostart),
                ("c".to_string(), InheritedSource::GlobalAutostart),
                ("d".to_string(), InheritedSource::GlobalAutostart),
            ]
        );
        // Fresh-home drops the profiles that live in the home.
        assert_eq!(
            started(&fs, true),
            vec![
                ("c".to_string(), InheritedSource::GlobalAutostart),
                ("d".to_string(), InheritedSource::GlobalAutostart),
            ]
        );
    }

    #[test]
    fn the_most_important_directory_wins_and_hidden_hides_the_name() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(NIXOS_CURRENT_SYSTEM, true);
        let sw = "/run/current-system/sw/etc/xdg/autostart";
        entry(&fs, sw, "tracker.desktop", "[Desktop Entry]\n");
        entry(&fs, sw, "geoclue-demo-agent.desktop", "[Desktop Entry]\n");
        entry(&fs, sw, "sync.desktop", "[Desktop Entry]\nHidden=true\n");
        // The home hides one system entry and replaces another.
        entry(
            &fs,
            "/home/alice/.config/autostart",
            "tracker.desktop",
            "[Desktop Entry]\nHidden=true\n",
        );
        entry(
            &fs,
            "/home/alice/.config/autostart",
            "geoclue-demo-agent.desktop",
            "[Desktop Entry]\nExec=other\n",
        );
        // /etc/xdg outranks the system profile, so this copy decides.
        entry(
            &fs,
            "/etc/xdg/autostart",
            "sync.desktop",
            "[Desktop Entry]\n",
        );

        assert_eq!(
            started(&fs, false),
            vec![
                (
                    "geoclue-demo-agent".to_string(),
                    InheritedSource::UserAutostart
                ),
                ("sync".to_string(), InheritedSource::GlobalAutostart),
            ]
        );
        // In fresh-home the home's overrides do not apply.
        assert_eq!(
            started(&fs, true),
            vec![
                (
                    "geoclue-demo-agent".to_string(),
                    InheritedSource::GlobalAutostart
                ),
                ("sync".to_string(), InheritedSource::GlobalAutostart),
                ("tracker".to_string(), InheritedSource::GlobalAutostart),
            ]
        );
    }

    #[test]
    fn a_user_name_with_a_slash_names_no_profile() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(NIXOS_CURRENT_SYSTEM, true);
        let dirs = search_path(&fs, Path::new(HOME), "../alice");
        assert!(
            dirs.iter()
                .all(|dir| !dir.path.starts_with("/etc/profiles")),
            "no per-user profile for an odd name"
        );
    }
}
