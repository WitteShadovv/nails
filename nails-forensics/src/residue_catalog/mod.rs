// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The residue catalog: every class of trace a hidden session, or the setup
//! around it, can leave where an examiner looks.
//!
//! Each row names one class once: where it lands, which platforms it applies
//! to, the pre-flight probe that warns about it before activation, the verify
//! probe that detects it afterwards, the mitigation, the section of the docs
//! that explains it and the end-to-end test that asserts it. The catalog is
//! plain data ([`rows`]); the consumers read it instead of keeping their own
//! lists:
//!
//! - the `residue-catalog` pre-flight check runs every [`Probe::Paths`]
//!   pre-flight probe;
//! - `verify` runs every [`Probe::Paths`] verify probe and builds its "areas
//!   not checked" list from the rows it could not cover in that run;
//! - `verify --offline --examiner` groups its findings by the rows'
//!   [`ResidueClass::conclusion`];
//! - the tables in `docs/decoy-requirements.md` and `docs/threat-model.md`
//!   are generated from it ([`docs`]), and a unit test fails when they drift.
//!
//! The artifact registry ([`crate::artifacts`]) stays the list of the exact
//! paths and markers NAILS itself writes; one catalog row stands for all of
//! them.
//!
//! A row may have no detector or no VM test only by saying why
//! ([`Probe::None`], [`E2e::None`]): the reason is then shown to the operator
//! (verify's areas not checked) and in the docs, so a gap is never silent.

pub mod docs;
mod rows;

#[cfg(test)]
mod tests;

pub use crate::artifacts::ArtifactSeverity as ProbeSeverity;
pub use rows::CATALOG;

/// Whether a class is residue of the hidden session itself or a trace of the
/// setup an examiner would use to argue that a hidden volume exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidueKind {
    /// Something the hidden session writes or causes to be written.
    Session,
    /// Evidence of the encrypted backend or its tooling, which `verify
    /// --offline --examiner` reports.
    Setup,
}

/// The host families a residue class applies to, as a small bitset.
///
/// A class scopes to any combination of families. [`NIXOS`](Self::NIXOS) is
/// NAILS's first-class backend; [`DEBIAN`](Self::DEBIAN), [`FEDORA`](Self::FEDORA)
/// and [`ARCH`](Self::ARCH) are the FHS families; [`FHS`](Self::FHS) is the three
/// of them together, and [`ALL`](Self::ALL) is every supported host. Combine them
/// with `|` (`Platforms::NIXOS | Platforms::DEBIAN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Platforms(u8);

impl Platforms {
    /// NixOS hosts.
    pub const NIXOS: Platforms = Platforms(0b0001);
    /// The Debian family (Debian, Ubuntu and their derivatives).
    pub const DEBIAN: Platforms = Platforms(0b0010);
    /// The Fedora family (Fedora and its derivatives).
    pub const FEDORA: Platforms = Platforms(0b0100);
    /// The Arch family (Arch and its derivatives).
    pub const ARCH: Platforms = Platforms(0b1000);
    /// Every FHS family: Debian, Fedora and Arch together.
    pub const FHS: Platforms = Platforms(Self::DEBIAN.0 | Self::FEDORA.0 | Self::ARCH.0);
    /// Every supported host: NixOS and every FHS family.
    pub const ALL: Platforms = Platforms(Self::NIXOS.0 | Self::FHS.0);

    /// The family a detected host belongs to, or `None` when detection could not
    /// place it: an offline image, a failed probe, or a refused host with no
    /// resolved family. A `None` host is given every class ([`applies_to`]), so a
    /// gap in detection never silently drops a residue class.
    ///
    /// A refused Fedora or Arch host still carries its family, so its family's
    /// rows apply to it in a `verify` or `check` run even though activation
    /// refuses it.
    ///
    /// [`applies_to`]: Self::applies_to
    pub fn for_host(profile: &crate::platform::HostProfile) -> Option<Platforms> {
        use crate::platform::PlatformKind;
        if profile.kind == PlatformKind::NixOs {
            return Some(Platforms::NIXOS);
        }
        match profile.family {
            Some(nails_base::Family::Debian) => Some(Platforms::DEBIAN),
            Some(nails_base::Family::Fedora) => Some(Platforms::FEDORA),
            Some(nails_base::Family::Arch) => Some(Platforms::ARCH),
            // An FHS host whose family could not be named still belongs to the
            // FHS group; a refused host with no family reads as undetected.
            None => (profile.kind == PlatformKind::Fhs).then_some(Platforms::FHS),
        }
    }

    /// Whether the class applies to a host whose family bits are `host`.
    ///
    /// `None` — an offline image, or a host detection could not place — is given
    /// every class. Otherwise a class applies when its families overlap the
    /// host's.
    pub fn applies_to(self, host: Option<Platforms>) -> bool {
        match host {
            None => true,
            Some(host) => self.0 & host.0 != 0,
        }
    }

    /// The families as the docs name them: `all`, or a comma-separated list such
    /// as `NixOS` or `Debian, Fedora, Arch`.
    pub fn label(self) -> String {
        if self == Platforms::ALL {
            return "all".to_string();
        }
        [
            (Platforms::NIXOS, "NixOS"),
            (Platforms::DEBIAN, "Debian"),
            (Platforms::FEDORA, "Fedora"),
            (Platforms::ARCH, "Arch"),
        ]
        .into_iter()
        .filter(|(bit, _)| self.0 & bit.0 != 0)
        .map(|(_, name)| name)
        .collect::<Vec<_>>()
        .join(", ")
    }
}

impl std::ops::BitOr for Platforms {
    type Output = Platforms;

    fn bitor(self, rhs: Platforms) -> Platforms {
        Platforms(self.0 | rhs.0)
    }
}

/// Where a class lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// Paths on the decoy root. A leading `~/` means "in every user's home".
    Paths(&'static [&'static str]),
    /// A mechanism that is not a fixed path (firmware, a device region, a
    /// window in time).
    Mechanism(&'static str),
}

/// How one probe point (pre-flight or verify) covers a class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// A named check covers it: a pre-flight check name, or a verify check id
    /// from [`crate::verify::VERIFY_CHECK_IDS`].
    Check(&'static str),
    /// Data-driven: report each listed path that exists on the inspected root.
    /// A directory is reported only when it has entries. The finding carries the
    /// row's mitigation and doc link.
    Paths {
        /// Absolute paths on the decoy root.
        paths: &'static [&'static str],
        /// How loudly a hit is reported.
        severity: ProbeSeverity,
    },
    /// Nothing at this probe point checks the class; the reason says why, and
    /// is shown wherever the class goes unchecked.
    None(&'static str),
}

impl Probe {
    /// Whether this probe detects anything at all.
    pub fn detects(&self) -> bool {
        !matches!(self, Probe::None(_))
    }
}

/// The end-to-end test that asserts a class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E2e {
    /// The `name` of a NixOS VM test under `nix/e2e-tests/tests`.
    Test(&'static str),
    /// Several VM tests by `name`, each asserting a part of the mitigation.
    Tests(&'static [&'static str]),
    /// No VM test can assert it; the reason says why.
    None(&'static str),
}

/// One class of residue.
#[derive(Debug, Clone, Copy)]
pub struct ResidueClass {
    /// Stable identifier, used in reports, findings and tests.
    pub id: &'static str,
    /// Short human name.
    pub title: &'static str,
    /// Session residue or a setup trace.
    pub kind: ResidueKind,
    /// Where it lands.
    pub channel: Channel,
    /// The hosts it applies to.
    pub platforms: Platforms,
    /// Why an examiner cares.
    pub risk: &'static str,
    /// What warns about it before activation.
    pub preflight: Probe,
    /// Whether that pre-flight probe refuses activation (fail closed) rather
    /// than warning.
    pub preflight_blocks: bool,
    /// What detects it afterwards.
    pub verify: Probe,
    /// What the operator does about it.
    pub mitigation: &'static str,
    /// The doc section that explains it, as `<file under docs/>#<anchor>`.
    pub doc_anchor: &'static str,
    /// The VM test that asserts it.
    pub e2e: E2e,
    /// Whether the overlay cannot cover it at all (a residual channel the threat
    /// model lists).
    pub residual: bool,
    /// For a setup trace: what an examiner concludes from it.
    pub conclusion: Option<&'static str>,
}

impl ResidueClass {
    /// One-line pointer to the docs, for finding guidance.
    pub fn see_also(&self) -> String {
        format!("see docs/{}", self.doc_anchor)
    }
}

/// The whole catalog.
pub fn catalog() -> &'static [ResidueClass] {
    CATALOG
}

/// The row with the given id.
pub fn class(id: &str) -> Option<&'static ResidueClass> {
    CATALOG.iter().find(|row| row.id == id)
}

/// The rows whose verify probe is the named check.
pub fn covered_by_verify_check(check: &str) -> impl Iterator<Item = &'static ResidueClass> + '_ {
    CATALOG
        .iter()
        .filter(move |row| matches!(row.verify, Probe::Check(id) if id == check))
}

/// Whether a path probe hit should be reported: a regular file or link that
/// exists, or a directory that has at least one entry.
///
/// Reads with the filesystem abstraction only (existence and a directory
/// listing), so the probe never opens a decoy file for content.
pub fn path_probe_hit<F: crate::Filesystem>(fs: &F, path: &std::path::Path) -> bool {
    if !fs.path_exists(path).unwrap_or(false) {
        return false;
    }
    if fs.is_directory(path).unwrap_or(false) {
        return fs
            .list_directory(path)
            .map(|entries| !entries.is_empty())
            .unwrap_or(false);
    }
    true
}
