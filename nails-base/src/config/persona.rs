// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Persona mode: how the hidden session relates to the decoy account.
//!
//! By default NAILS runs the hidden session as the decoy user, in the decoy
//! home: the root overlay merges the decoy home read-write, so every account,
//! credential store and application profile configured there is live in the
//! hidden session. That shared-account model is the default
//! [`PersonaMode::SharedHome`], kept because deployments that rely on the
//! decoy's existing login still need it; `nails check` says on a line of its
//! own when it is in effect.
//!
//! [`PersonaMode::FreshHome`] is the opt-in separation: at the first entry the
//! operator's home becomes an opaque directory in the upper on the hidden
//! volume (see `nails_session::session::persona`), so the hidden session starts from
//! a clean home and the decoy home contents are not visible. It stays the
//! hidden home at every later entry.
//!
//! A third model, a separate fixed-UID hidden account, is reserved as
//! `separate-user` for a later phase: it needs the hidden NixOS generation
//! switched before login, so it is not an activation-time decision and is not an
//! accepted value here yet.

use serde::{Deserialize, Deserializer, Serialize};

/// How the hidden session relates to the decoy account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PersonaMode {
    /// Shared-account model: the hidden session runs in the decoy home, merged
    /// read-write through the root overlay. The default; `nails check` names it
    /// on a line of its own, because the decoy's accounts and secrets are live.
    #[default]
    SharedHome,

    /// Opt-in separation: the operator's home is an opaque directory in the
    /// upper on the hidden volume, so the decoy home contents are not visible in
    /// the hidden session.
    FreshHome,
}

impl PersonaMode {
    /// The `nails.toml` / JSON spelling of the mode.
    pub fn as_str(self) -> &'static str {
        match self {
            PersonaMode::SharedHome => "shared-home",
            PersonaMode::FreshHome => "fresh-home",
        }
    }
}

/// `[persona]` configuration table.
///
/// Mirrors the other nested config tables: every key is optional and unknown keys
/// are rejected, so a typo fails loudly instead of silently selecting a default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PersonaConfig {
    /// How the hidden session relates to the decoy account. Defaults to
    /// [`PersonaMode::SharedHome`] so the long-standing behaviour is unchanged
    /// unless the operator opts into `fresh-home`.
    #[serde(default)]
    pub mode: PersonaMode,

    /// Inherited decoy autostart entries and user units to mask for the hidden
    /// session.
    ///
    /// Each value is an entry name as the persona inventory reports it: the
    /// `.desktop` stem for an autostart entry, or the full unit name (with its
    /// suffix) for a user unit. The single element `"*"` masks every maskable
    /// inherited entry. Masking happens at entry, before the soft-reboot: a
    /// `Hidden=true` autostart override or a `/dev/null` user-unit mask is
    /// written through the next root's home, so it lands only in the upper on
    /// the hidden volume and never on the decoy. A name the inventory does not
    /// list is masked too: as a user unit when it ends in a unit suffix, as an
    /// autostart entry otherwise. Lingering and autologin are reported but
    /// cannot be masked this way. Empty by default; every value must be a file
    /// name ([`is_entry_name`]) or `"*"`.
    #[serde(default, deserialize_with = "entry_names")]
    pub mask_inherited: Vec<String>,
}

/// Whether `name` can name an inherited entry: one non-empty file name, so a
/// mask written for it stays in the directory it belongs to.
pub fn is_entry_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0'])
}

/// Deserialize `mask_inherited`, refusing a value that is neither `"*"` nor an
/// entry name.
fn entry_names<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    let names = Vec::<String>::deserialize(deserializer)?;
    if let Some(bad) = names
        .iter()
        .find(|name| name.as_str() != "*" && !is_entry_name(name))
    {
        return Err(serde::de::Error::custom(format!(
            "{bad:?} is not an entry name: use a name as `nails check` lists it, without `/`"
        )));
    }
    Ok(names)
}

impl PersonaConfig {
    /// Whether the mask list requests masking every maskable inherited entry.
    pub fn masks_all_inherited(&self) -> bool {
        self.mask_inherited.iter().any(|name| name == "*")
    }

    /// Whether an inherited entry named `name` should be masked.
    pub fn masks_inherited(&self, name: &str) -> bool {
        self.masks_all_inherited() || self.mask_inherited.iter().any(|entry| entry == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mode_is_shared_home() {
        assert_eq!(PersonaConfig::default().mode, PersonaMode::SharedHome);
    }

    #[test]
    fn mode_spellings_are_kebab_case() {
        assert_eq!(PersonaMode::SharedHome.as_str(), "shared-home");
        assert_eq!(PersonaMode::FreshHome.as_str(), "fresh-home");
    }

    #[test]
    fn parses_both_modes_and_rejects_unknown() {
        let fresh: PersonaConfig = toml::from_str("mode = \"fresh-home\"").unwrap();
        assert_eq!(fresh.mode, PersonaMode::FreshHome);

        let shared: PersonaConfig = toml::from_str("mode = \"shared-home\"").unwrap();
        assert_eq!(shared.mode, PersonaMode::SharedHome);

        assert!(toml::from_str::<PersonaConfig>("mode = \"bogus\"").is_err());
        assert!(toml::from_str::<PersonaConfig>("other = 1").is_err());
    }

    #[test]
    fn mask_inherited_defaults_to_empty() {
        assert!(PersonaConfig::default().mask_inherited.is_empty());
        assert!(!PersonaConfig::default().masks_all_inherited());
    }

    #[test]
    fn parses_mask_inherited_list() {
        let config: PersonaConfig =
            toml::from_str("mask_inherited = [\"dropbox\", \"syncthing.service\"]").unwrap();
        assert_eq!(
            config.mask_inherited,
            vec!["dropbox".to_string(), "syncthing.service".to_string()]
        );
        assert!(!config.masks_all_inherited());
        assert!(config.masks_inherited("dropbox"));
        assert!(config.masks_inherited("syncthing.service"));
        assert!(!config.masks_inherited("telegram"));
    }

    #[test]
    fn mask_all_sentinel_matches_everything() {
        let config: PersonaConfig = toml::from_str("mask_inherited = [\"*\"]").unwrap();
        assert!(config.masks_all_inherited());
        assert!(config.masks_inherited("anything"));
    }

    #[test]
    fn mask_inherited_roundtrips_with_mode() {
        let config = PersonaConfig {
            mode: PersonaMode::FreshHome,
            mask_inherited: vec!["dropbox".to_string()],
        };
        let serialized = toml::to_string(&config).unwrap();
        let parsed: PersonaConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(parsed, config);
    }

    #[test]
    fn a_mask_name_that_is_not_a_file_name_is_refused() {
        for bad in ["../x", "a/b", "", ".", ".."] {
            let text = format!("mask_inherited = [\"dropbox\", {bad:?}]");
            let error = toml::from_str::<PersonaConfig>(&text).unwrap_err();
            assert!(
                error.to_string().contains("not an entry name"),
                "{bad:?}: {error}"
            );
        }
        assert!(is_entry_name("org.gnome.Evolution-alarm-notify"));
        assert!(is_entry_name("syncthing.service"));
        assert!(!is_entry_name("*/x"));
    }

    #[test]
    fn unknown_key_is_still_rejected_alongside_mask_inherited() {
        assert!(toml::from_str::<PersonaConfig>("mask_inherited = [\"x\"]\nbogus = 1").is_err());
    }
}
