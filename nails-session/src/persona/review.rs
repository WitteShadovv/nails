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

use super::inventory::{PersonaEntry, PersonaInventory};
use crate::config::PersonaConfig;

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
