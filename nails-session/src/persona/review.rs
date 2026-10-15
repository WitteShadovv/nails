// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What becomes of each inherited entry under a persona configuration.
//!
//! The `inherited-autostart` check, the `nails check` listing and its JSON
//! report all judge an entry the same way:
//!
//! - an entry `[persona] mask_inherited` names (or covers with `"*"`) is
//!   masked at entry, so it is handled;
//! - a system-wide component the desktop or distribution ships is ignored,
//!   unless its name is on the list of known trace writers;
//! - everything else needs the operator's review: entries in the home and
//!   other entries added by the user or by third-party software, known trace
//!   writers, lingering and autologin.
//!
//! It also decides which masks activation writes: one for every maskable entry
//! the configuration names, and one for every name it lists that the inventory
//! does not, so a directory the collector does not read never drops a mask the
//! operator asked for.

use super::inventory::{PersonaEntry, PersonaInventory};
use crate::config::PersonaConfig;
use crate::config::persona::is_entry_name;

/// The suffixes of systemd unit names. A `mask_inherited` name the inventory
/// does not list is masked as a user unit when it ends in one of them, and as
/// an autostart entry otherwise.
const UNIT_SUFFIXES: &[&str] = &[
    ".service",
    ".socket",
    ".timer",
    ".path",
    ".target",
    ".mount",
    ".automount",
    ".swap",
    ".slice",
    ".scope",
    ".device",
];

/// The kind of mask activation writes for an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskKind {
    /// A `Hidden=true` override at `~/.config/autostart/<name>.desktop`.
    Autostart,
    /// A `/dev/null` symlink at `~/.config/systemd/user/<name>`.
    Unit,
}

impl MaskKind {
    /// The kind of mask for a name the inventory does not list.
    pub fn for_name(name: &str) -> Self {
        if UNIT_SUFFIXES.iter().any(|suffix| name.ends_with(suffix)) {
            MaskKind::Unit
        } else {
            MaskKind::Autostart
        }
    }
}

/// One mask activation writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskTarget {
    /// The entry name: an autostart stem or a full unit name.
    pub name: String,
    /// Where the mask goes.
    pub kind: MaskKind,
}

/// What becomes of one inherited entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryStatus {
    /// A component the installed desktop or distribution ships, not a known
    /// trace writer: not reported.
    Ignored,
    /// Named in `[persona] mask_inherited`: masked for the hidden session.
    Masked,
    /// Reported for the operator's review.
    Review,
}

impl EntryStatus {
    /// Stable identifier used in JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            EntryStatus::Ignored => "ignored",
            EntryStatus::Masked => "masked",
            EntryStatus::Review => "review",
        }
    }
}

impl PersonaEntry {
    /// What becomes of this entry under `persona`.
    pub fn status(&self, persona: &PersonaConfig) -> EntryStatus {
        if self.source.is_maskable() && persona.masks_inherited(&self.name) {
            EntryStatus::Masked
        } else if self.desktop && !self.remote_linked {
            EntryStatus::Ignored
        } else {
            EntryStatus::Review
        }
    }
}

impl PersonaInventory {
    /// The masks `persona` asks activation to write: every maskable entry it
    /// names (all of them with `"*"`), then every name it lists that matches no
    /// maskable entry ([`Self::unmatched_masks`]), judged by its suffix (see
    /// [`MaskKind::for_name`]). A name that is not a single file name is never
    /// a target, and no target appears twice.
    pub fn mask_targets(&self, persona: &PersonaConfig) -> Vec<MaskTarget> {
        let mut targets = Vec::new();
        for entry in self
            .maskable()
            .filter(|entry| persona.masks_inherited(&entry.name))
        {
            let kind = if entry.source.is_autostart() {
                MaskKind::Autostart
            } else {
                MaskKind::Unit
            };
            push_target(&mut targets, &entry.name, kind);
        }
        for name in self.unmatched_masks(persona) {
            let kind = MaskKind::for_name(&name);
            push_target(&mut targets, &name, kind);
        }
        targets
    }

    /// The names `[persona] mask_inherited` lists that match no maskable
    /// inherited entry, in configuration order. Activation masks them anyway;
    /// `nails check` names them, since a typo lands here too.
    pub fn unmatched_masks(&self, persona: &PersonaConfig) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for name in &persona.mask_inherited {
            if name == "*" || !is_entry_name(name) || out.contains(name) {
                continue;
            }
            if !self.maskable().any(|entry| &entry.name == name) {
                out.push(name.clone());
            }
        }
        out
    }

    /// The entries with `status` under `persona`, in inventory order.
    pub fn with_status<'a>(
        &'a self,
        persona: &'a PersonaConfig,
        status: EntryStatus,
    ) -> impl Iterator<Item = &'a PersonaEntry> + 'a {
        self.entries
            .iter()
            .filter(move |entry| entry.status(persona) == status)
    }
}

/// Add a mask target unless it is not a file name or already listed.
fn push_target(targets: &mut Vec<MaskTarget>, name: &str, kind: MaskKind) {
    if is_entry_name(name)
        && !targets
            .iter()
            .any(|target| target.name == name && target.kind == kind)
    {
        targets.push(MaskTarget {
            name: name.to_string(),
            kind,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persona::InheritedSource;

    fn masking(names: &[&str]) -> PersonaConfig {
        PersonaConfig {
            mask_inherited: names.iter().map(|name| name.to_string()).collect(),
            ..PersonaConfig::default()
        }
    }

    #[test]
    fn desktop_components_are_ignored_unless_they_carry_data_off_the_machine() {
        let persona = PersonaConfig::default();
        let settings = PersonaEntry::new(
            "org.gnome.SettingsDaemon.Power",
            InheritedSource::GlobalAutostart,
        );
        assert_eq!(settings.status(&persona), EntryStatus::Ignored);
        let alarms = PersonaEntry::new(
            "org.gnome.Evolution-alarm-notify",
            InheritedSource::GlobalAutostart,
        );
        assert!(alarms.desktop && alarms.remote_linked);
        assert_eq!(alarms.status(&persona), EntryStatus::Review);
    }

    #[test]
    fn entries_in_the_home_and_unknown_system_entries_need_review() {
        let persona = PersonaConfig::default();
        // A desktop component's name in the home is the user's own copy.
        for entry in [
            PersonaEntry::new("pipewire.service", InheritedSource::UserUnit),
            PersonaEntry::new("my-backup", InheritedSource::UserAutostart),
            PersonaEntry::new("portmaster", InheritedSource::GlobalAutostart),
            PersonaEntry::new("alice", InheritedSource::Linger),
            PersonaEntry::new("alice", InheritedSource::Autologin),
        ] {
            assert!(!entry.desktop, "{entry:?}");
            assert_eq!(entry.status(&persona), EntryStatus::Review, "{entry:?}");
        }
    }

    #[test]
    fn masked_entries_are_handled_and_lingering_cannot_be_masked() {
        let dropbox = PersonaEntry::new("dropbox", InheritedSource::UserAutostart);
        let keyring = PersonaEntry::new("gnome-keyring-ssh", InheritedSource::GlobalAutostart);
        let linger = PersonaEntry::new("alice", InheritedSource::Linger);

        let named = masking(&["dropbox", "alice"]);
        assert_eq!(dropbox.status(&named), EntryStatus::Masked);
        assert_eq!(keyring.status(&named), EntryStatus::Ignored);
        assert_eq!(linger.status(&named), EntryStatus::Review);

        let all = masking(&["*"]);
        assert_eq!(dropbox.status(&all), EntryStatus::Masked);
        assert_eq!(keyring.status(&all), EntryStatus::Masked);
        assert_eq!(linger.status(&all), EntryStatus::Review);
    }

    fn target(name: &str, kind: MaskKind) -> MaskTarget {
        MaskTarget {
            name: name.to_string(),
            kind,
        }
    }

    #[test]
    fn named_masks_the_inventory_misses_are_still_written() {
        let inventory = PersonaInventory {
            entries: vec![
                PersonaEntry::new("dropbox", InheritedSource::UserAutostart),
                PersonaEntry::new("syncthing.service", InheritedSource::GlobalUnit),
                PersonaEntry::new("alice", InheritedSource::Linger),
            ],
        };
        let persona = masking(&[
            "syncthing.service",
            "kdeconnect-indicator",
            "ghost.timer",
            "alice",
            "ghost.timer",
        ]);
        assert_eq!(
            inventory.unmatched_masks(&persona),
            vec!["kdeconnect-indicator", "ghost.timer", "alice"],
            "lingering cannot be masked, so its name matches nothing maskable"
        );
        assert_eq!(
            inventory.mask_targets(&persona),
            vec![
                target("syncthing.service", MaskKind::Unit),
                target("kdeconnect-indicator", MaskKind::Autostart),
                target("ghost.timer", MaskKind::Unit),
                target("alice", MaskKind::Autostart),
            ]
        );
    }

    #[test]
    fn a_star_masks_every_maskable_entry_and_names_still_add_theirs() {
        let inventory = PersonaInventory {
            entries: vec![
                PersonaEntry::new("dropbox", InheritedSource::UserAutostart),
                PersonaEntry::new("pipewire.socket", InheritedSource::GlobalUnit),
                PersonaEntry::new("alice", InheritedSource::Autologin),
            ],
        };
        let persona = masking(&["*", "dropbox", "extra"]);
        assert_eq!(inventory.unmatched_masks(&persona), vec!["extra"]);
        assert_eq!(
            inventory.mask_targets(&persona),
            vec![
                target("dropbox", MaskKind::Autostart),
                target("pipewire.socket", MaskKind::Unit),
                target("extra", MaskKind::Autostart),
            ]
        );
    }

    #[test]
    fn names_that_are_not_file_names_are_never_targets() {
        let persona = masking(&["../../.bashrc", "a/b", "", ".", "..", "ok"]);
        let inventory = PersonaInventory::default();
        assert_eq!(inventory.unmatched_masks(&persona), vec!["ok"]);
        assert_eq!(
            inventory.mask_targets(&persona),
            vec![target("ok", MaskKind::Autostart)]
        );
    }

    #[test]
    fn a_unit_suffix_makes_an_unknown_name_a_unit() {
        for unit in ["a.service", "b.socket", "c.timer", "d.path", "e.target"] {
            assert_eq!(MaskKind::for_name(unit), MaskKind::Unit, "{unit}");
        }
        for entry in ["dropbox", "org.gnome.Evolution-alarm-notify", "service"] {
            assert_eq!(MaskKind::for_name(entry), MaskKind::Autostart, "{entry}");
        }
    }

    #[test]
    fn with_status_filters_in_inventory_order() {
        let inventory = PersonaInventory {
            entries: vec![
                PersonaEntry::new("dropbox", InheritedSource::UserAutostart),
                PersonaEntry::new("xdg-user-dirs", InheritedSource::GlobalAutostart),
                PersonaEntry::new("syncthing.service", InheritedSource::UserUnit),
            ],
        };
        let persona = masking(&["syncthing.service"]);
        let names = |status| {
            inventory
                .with_status(&persona, status)
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(EntryStatus::Review), vec!["dropbox"]);
        assert_eq!(names(EntryStatus::Ignored), vec!["xdg-user-dirs"]);
        assert_eq!(names(EntryStatus::Masked), vec!["syncthing.service"]);
        assert_eq!(EntryStatus::Review.as_str(), "review");
        assert_eq!(EntryStatus::Ignored.as_str(), "ignored");
        assert_eq!(EntryStatus::Masked.as_str(), "masked");
    }
}
