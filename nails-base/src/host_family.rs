// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The Filesystem-Hierarchy-Standard family a host belongs to.
//!
//! This is the small, shared vocabulary for "which FHS family is this?", used by
//! the platform detection that fills it in, by the recorded state that remembers
//! it, and by the residue catalogue that scopes a row to a family. It lives in
//! the base crate so none of those has to depend on the platform crate to name a
//! family.
//!
//! NixOS is deliberately not a member: it has its own first-class backend and is
//! classified before the family table is consulted. A host NAILS cannot place in
//! one of these families carries no family at all.

use serde::{Deserialize, Serialize};

/// A family of systemd hosts laid out on the Filesystem Hierarchy Standard.
///
/// The serialised form is the family's lowercase identifier (`debian`, `fedora`,
/// `arch`), so a recorded family reads back the way os-release spells a family
/// `ID`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    /// Debian and its relatives (Debian, Ubuntu, and `ID_LIKE=debian`
    /// derivatives such as Linux Mint or Pop!\_OS).
    Debian,
    /// Fedora and its relatives (Nobara, Ultramarine).
    Fedora,
    /// Arch and its relatives (EndeavourOS, CachyOS, Manjaro).
    Arch,
}

impl Family {
    /// The family's lowercase identifier: `debian`, `fedora` or `arch`.
    ///
    /// This is the value the state file records and the one an os-release family
    /// `ID` carries, so detection, recording and the catalogue all agree on it.
    pub fn as_str(self) -> &'static str {
        match self {
            Family::Debian => "debian",
            Family::Fedora => "fedora",
            Family::Arch => "arch",
        }
    }

    /// The family's name as a message writes it: `Debian`, `Fedora` or `Arch`.
    pub fn label(self) -> &'static str {
        match self {
            Family::Debian => "Debian",
            Family::Fedora => "Fedora",
            Family::Arch => "Arch",
        }
    }
}

impl std::fmt::Display for Family {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_is_the_lowercase_family_name() {
        assert_eq!(Family::Debian.as_str(), "debian");
        assert_eq!(Family::Fedora.as_str(), "fedora");
        assert_eq!(Family::Arch.as_str(), "arch");
    }

    #[test]
    fn label_is_the_name_a_message_writes() {
        assert_eq!(Family::Debian.label(), "Debian");
        assert_eq!(Family::Fedora.label(), "Fedora");
        assert_eq!(Family::Arch.label(), "Arch");
    }

    #[test]
    fn display_matches_the_identifier() {
        assert_eq!(Family::Arch.to_string(), "arch");
    }

    #[test]
    fn serialises_as_the_lowercase_identifier() {
        assert_eq!(
            serde_json::to_string(&Family::Fedora).unwrap(),
            "\"fedora\""
        );
        assert_eq!(
            serde_json::from_str::<Family>("\"arch\"").unwrap(),
            Family::Arch
        );
    }
}
