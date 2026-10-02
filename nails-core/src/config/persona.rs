//! Persona mode: how the hidden session relates to the decoy account.
//!
//! By default NAILS runs the hidden session as the decoy user, in the decoy
//! home: the `/home` overlay merges the decoy home read-write, so every account,
//! credential store and application profile configured there is live in the
//! hidden session. That shared-account model is the legacy behaviour; it is kept
//! as the explicit, opt-in [`PersonaMode::SharedHome`] because deployments that
//! rely on the decoy's existing login still need it, and activation warns when it
//! is in effect.
//!
//! [`PersonaMode::FreshHome`] is the opt-in separation: once the `/home` overlay
//! is mounted, a fresh, empty directory on the hidden volume is bind-mounted over
//! the operator's home, so the hidden session starts from a clean home and the
//! decoy home contents are not visible. The bind source lives at
//! [`persona_home_source`] under the hidden volume root, so it is torn down with
//! the rest of the hidden mounts on deactivation.
//!
//! A third model, a separate fixed-UID hidden account, is reserved as
//! `separate-user` for a later phase: it needs the hidden NixOS generation
//! switched before login, so it is not an activation-time decision and is not an
//! accepted value here yet.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Directory under the hidden volume root that holds the fresh persona home.
///
/// Kept as two components so the mount-table classifier
/// ([`crate::filesystem::NailsMounts`]) can recognise the bind by the tail of its
/// in-filesystem root path without knowing where the hidden volume is mounted.
pub const PERSONA_DIR: &str = "persona";

/// The home directory inside [`PERSONA_DIR`] that becomes the operator's home in
/// fresh-home mode.
pub const PERSONA_HOME_DIR: &str = "home";

/// The on-disk source of the fresh persona home, `{hidden_root}/persona/home`.
///
/// This is the directory bind-mounted over the operator's home in
/// [`PersonaMode::FreshHome`]. It stays inside the hidden volume root so it is
/// created, torn down and (when the volume is detached) hidden with everything
/// else NAILS owns.
pub fn persona_home_source(hidden_volume_root: &Path) -> PathBuf {
    hidden_volume_root.join(PERSONA_DIR).join(PERSONA_HOME_DIR)
}

/// Whether a mount-table `root` path (the in-filesystem subtree a bind exposes)
/// is the persona home bind.
///
/// A bind of `{hidden_root}/persona/home` appears in `/proc/self/mountinfo` with
/// its `root` field ending in `persona/home`, regardless of where the hidden
/// volume is mounted, so matching that tail identifies the bind without the
/// classifier needing the configured hidden root.
pub fn is_persona_home_root(mount_root: &Path) -> bool {
    let mut components = mount_root.components().rev();
    let last = components.next();
    let penultimate = components.next();
    matches!(
        (penultimate, last),
        (Some(p), Some(l))
            if p.as_os_str() == PERSONA_DIR && l.as_os_str() == PERSONA_HOME_DIR
    )
}

/// How the hidden session relates to the decoy account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PersonaMode {
    /// Legacy shared-account model: the hidden session runs in the decoy home,
    /// merged read-write through the `/home` overlay. Opt-in, and warned about at
    /// activation, because the decoy's accounts and secrets are live.
    #[default]
    SharedHome,

    /// Opt-in separation: a fresh, empty home on the hidden volume is bind-mounted
    /// over the operator's home, so the decoy home contents are not visible in the
    /// hidden session.
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
    fn persona_home_source_is_under_hidden_root() {
        let source = persona_home_source(Path::new("/mnt/data"));
        assert_eq!(source, PathBuf::from("/mnt/data/persona/home"));
    }

    #[test]
    fn recognises_persona_home_root_regardless_of_volume_mount() {
        // Hidden volume mounted at its own root: bind root is /persona/home.
        assert!(is_persona_home_root(Path::new("/persona/home")));
        // Hidden volume mounted higher up: bind root keeps the persona tail.
        assert!(is_persona_home_root(Path::new("/data/persona/home")));
        // Unrelated binds are not matched.
        assert!(!is_persona_home_root(Path::new("/persist/etc/nixos")));
        assert!(!is_persona_home_root(Path::new("/home")));
        assert!(!is_persona_home_root(Path::new("/persona")));
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
}
