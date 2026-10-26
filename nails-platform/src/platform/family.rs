// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The family table: which systemd hosts NAILS admits, warns about or refuses.
//!
//! NAILS validates the overlay-only backend per family. The generic
//! [`FhsPlatform`](super::FhsPlatform) is the executor for every admitted FHS
//! host; this module is the *policy* that decides, from `/etc/os-release`, which
//! hosts are admitted today and which are refused until their own gate passes.
//!
//! Keeping the policy as one data table means admitting another family is a data
//! change here plus its gate run — it does not fork the backend.
//! [`detect`](super::detect) consults [`classify`] for every non-NixOS systemd
//! host and turns the result into a [`PlatformKind`].
//!
//! Each row carries its family, its version gate, whether it is a base
//! distribution or a derivative, whether NAILS admits it, and how its hosts
//! upgrade to a newer systemd. Fedora and Arch are in the table but not
//! admitted, so they are refused as product data until their support has been
//! verified, not hidden behind a test flag.
//!
//! A distribution that ships editions (Fedora's Cloud, Workstation, KDE Plasma
//! Desktop) also lists them in its row, as os-release `VARIANT_ID` names them:
//! a host runs clean only on a release and an edition NAILS is tested on.
//!
//! [`PlatformKind`]: super::PlatformKind

use nails_base::Family;

mod gate;
mod hints;

use gate::admitted_verdict;
pub use hints::{Package, install_hint, upgrade_hint};

/// A distribution version reduced to `(major, minor)`.
///
/// `VERSION_ID` is a dotted release string (`"12"`, `"13"`, `"24.04"`). Only the
/// first two components order releases for our purposes, so a missing minor
/// reads as `0` and any trailing components are ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DistroVersion {
    major: u32,
    minor: u32,
}

impl DistroVersion {
    const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }

    /// Parse a `VERSION_ID` value into `(major, minor)`.
    ///
    /// Returns `None` when the major component is not a number, so a rolling or
    /// malformed `VERSION_ID` is treated as "cannot confirm the minimum" rather
    /// than silently passing.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        let mut parts = value.trim().split('.');
        let major = parts.next()?.parse::<u32>().ok()?;
        let minor = parts
            .next()
            .and_then(|part| part.parse::<u32>().ok())
            .unwrap_or(0);
        Some(Self::new(major, minor))
    }
}

impl std::fmt::Display for DistroVersion {
    /// The release as the distribution writes it: the major alone when there is
    /// no minor (`13`), otherwise with a two-digit minor (`24.04`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.minor == 0 {
            write!(f, "{}", self.major)
        } else {
            write!(f, "{}.{:02}", self.major, self.minor)
        }
    }
}

/// How a family's releases are gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gate {
    /// A versioned distribution: admitted from `min` upward, tested on the
    /// `validated` releases, warning for any other release at or above `min`. A
    /// `validated` release that also appears in `caveats` stays tested — it is
    /// still listed in the tested-release sentence — but carries that specific
    /// warning, for a known issue that affects an otherwise supported release.
    /// A derivative lists neither: NAILS tests no release of one, so from `min`
    /// upward it runs as an untested derivative.
    Versioned {
        min: DistroVersion,
        validated: &'static [DistroVersion],
        caveats: &'static [(DistroVersion, &'static str)],
    },
    /// A rolling distribution with no release to gate on.
    Rolling,
}

/// Whether a row is a base distribution or a derivative of one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A base distribution (Debian, Ubuntu, Fedora, Arch).
    Base,
    /// A derivative of a base distribution, carrying its base [`Family`].
    Derivative,
}

/// How a distribution's hosts reach a release whose systemd supports
/// soft-reboot, as the distribution's own documentation describes it.
/// [`upgrade_hint`] turns it into the sentence `systemd-version` prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Upgrade {
    /// An upgrade to a newer release, done the way the text says (for Ubuntu,
    /// "with `do-release-upgrade`, then reboot"). The hint names the row's
    /// tested releases or, for a derivative, a release built on those of its
    /// base family.
    Release(&'static str),
    /// An update of the whole rolling system, done the way the text says.
    Rolling(&'static str),
}

/// How Arch and the Arch derivatives in the table bring a host up to date: a
/// full upgrade, as each of them documents. A partial upgrade is unsupported
/// there, so the hint never names `pacman -S systemd` alone.
const PACMAN_FULL_UPGRADE: Upgrade = Upgrade::Rolling("with `pacman -Syu`, then reboot");

/// An edition of a distribution, as os-release `VARIANT_ID` names it.
pub(crate) struct Edition {
    /// The `VARIANT_ID`, lowercased.
    id: &'static str,
    /// Human-facing name used in messages.
    label: &'static str,
    /// Whether NAILS is tested on this edition. An edition NAILS knows by
    /// name but has not been tested on is listed so its warning can name it.
    validated: bool,
}

/// Fedora's minimum release. Nobara and Ultramarine number their releases
/// after the Fedora release each is built on, so it is their minimum too.
const FEDORA_MIN: DistroVersion = DistroVersion::new(44, 0);

/// The gate of a Fedora derivative: refused below Fedora's minimum release,
/// and from there run as an untested derivative.
const FEDORA_DERIVATIVE: Gate = Gate::Versioned {
    min: FEDORA_MIN,
    validated: &[],
    caveats: &[],
};

/// One row of the family table.
pub(crate) struct FamilyRow {
    /// The `/etc/os-release` `ID`, lowercased.
    id: &'static str,
    /// Human-facing name used in messages.
    label: &'static str,
    /// The family this row belongs to (its base family, for a derivative).
    family: Family,
    /// How the row's releases are gated.
    gate: Gate,
    /// Base distribution or derivative.
    kind: Kind,
    /// Whether NAILS admits this family. A base row that is not admitted is
    /// refused; a derivative is refused until its base family is admitted.
    admitted: bool,
    /// How the row's hosts upgrade to a systemd new enough for the session.
    upgrade: Upgrade,
    /// The distribution's editions, for a base row that gates on them; empty
    /// for one that does not. A host of a row that lists editions runs clean
    /// only on a validated one: any other edition, listed or not, and a host
    /// that names none, run with a warning.
    editions: &'static [Edition],
}

/// The warning the Ubuntu 26.04 row carries. 26.04 is a tested release, but a
/// known upstream issue affects it: after the switch into the hidden session,
/// AppArmor keeps chrony and CUPS from reaching systemd and the journal, and on
/// the way back the decoy reports chrony failed until a full reboot. The fault
/// is upstream, so 26.04 stays validated and NAILS warns rather than refuses.
const UBUNTU_2604_CAVEAT: &str = "Ubuntu 26.04 is tested, but a known upstream issue affects it: after the \
     switch into the hidden session, AppArmor blocks chrony (time sync) and CUPS \
     (printing) from reaching systemd and the journal, so the clock does not sync \
     and printing times out. After the way back the decoy lists chrony as failed \
     until its next full reboot, which hints a soft-reboot happened; reboot the \
     decoy fully after a session to clear it. The fault is upstream, not in NAILS, \
     and remains until Ubuntu fixes it.";

/// The family table. Admitting a family is a data change here (its `admitted`
/// flag) plus its gate run — the backend ([`FhsPlatform`](super::FhsPlatform))
/// is already generic.
///
/// Fedora and Arch sit here with `admitted: false`: recognised, named in their
/// refusal, and ready to flip to admitted once their support has been verified.
const TABLE: &[FamilyRow] = &[
    FamilyRow {
        id: "debian",
        label: "Debian",
        family: Family::Debian,
        gate: Gate::Versioned {
            min: DistroVersion::new(13, 0),
            validated: &[DistroVersion::new(13, 0)],
            caveats: &[],
        },
        kind: Kind::Base,
        admitted: true,
        upgrade: Upgrade::Release("as its release notes describe, then reboot"),
        editions: &[],
    },
    FamilyRow {
        id: "ubuntu",
        label: "Ubuntu",
        family: Family::Debian,
        gate: Gate::Versioned {
            min: DistroVersion::new(24, 4),
            // A release is listed once a run of NAILS on it has passed. 26.10 is
            // not yet: its distro-test image is staged, but no run has passed on
            // it, so it warns as untested.
            validated: &[DistroVersion::new(24, 4), DistroVersion::new(26, 4)],
            caveats: &[(DistroVersion::new(26, 4), UBUNTU_2604_CAVEAT)],
        },
        kind: Kind::Base,
        admitted: true,
        upgrade: Upgrade::Release("with `do-release-upgrade`, then reboot"),
        editions: &[],
    },
    FamilyRow {
        id: "fedora",
        label: "Fedora",
        family: Family::Fedora,
        gate: Gate::Versioned {
            min: FEDORA_MIN,
            validated: &[DistroVersion::new(44, 0)],
            caveats: &[],
        },
        kind: Kind::Base,
        admitted: false,
        // The upgrade reboots by itself; Fedora supports it across at most two
        // releases.
        upgrade: Upgrade::Release("with `dnf system-upgrade`, at most two releases at a time"),
        // Cloud is the edition of the image the Fedora distribution tests
        // boot, so it is the one admission validates. Workstation and KDE
        // Plasma Desktop warn until a run of NAILS on each has passed, as any
        // other edition does.
        editions: &[
            Edition {
                id: "cloud",
                label: "Cloud",
                validated: true,
            },
            Edition {
                id: "workstation",
                label: "Workstation",
                validated: false,
            },
            Edition {
                id: "kde",
                label: "KDE Plasma Desktop",
                validated: false,
            },
        ],
    },
    FamilyRow {
        id: "arch",
        label: "Arch",
        family: Family::Arch,
        gate: Gate::Rolling,
        kind: Kind::Base,
        admitted: false,
        upgrade: PACMAN_FULL_UPGRADE,
        editions: &[],
    },
    // Arch derivatives: refused while Arch is, named so the refusal is precise
    // and flips to a warning the day Arch is admitted.
    FamilyRow {
        id: "endeavouros",
        label: "EndeavourOS",
        family: Family::Arch,
        gate: Gate::Rolling,
        kind: Kind::Derivative,
        admitted: false,
        upgrade: PACMAN_FULL_UPGRADE,
        editions: &[],
    },
    FamilyRow {
        id: "cachyos",
        label: "CachyOS",
        family: Family::Arch,
        gate: Gate::Rolling,
        kind: Kind::Derivative,
        admitted: false,
        upgrade: PACMAN_FULL_UPGRADE,
        editions: &[],
    },
    FamilyRow {
        id: "manjaro",
        label: "Manjaro",
        family: Family::Arch,
        gate: Gate::Rolling,
        kind: Kind::Derivative,
        admitted: false,
        upgrade: PACMAN_FULL_UPGRADE,
        editions: &[],
    },
    // Fedora derivatives, gated on the Fedora release each is built on.
    FamilyRow {
        id: "nobara",
        label: "Nobara",
        family: Family::Fedora,
        gate: FEDORA_DERIVATIVE,
        kind: Kind::Derivative,
        admitted: false,
        // Nobara upgrades through its own updater and warns against
        // `dnf system-upgrade`.
        upgrade: Upgrade::Release("as Nobara's upgrade guide describes, then reboot"),
        editions: &[],
    },
    FamilyRow {
        id: "ultramarine",
        label: "Ultramarine",
        family: Family::Fedora,
        gate: FEDORA_DERIVATIVE,
        kind: Kind::Derivative,
        admitted: false,
        upgrade: Upgrade::Release("with `dnf system-upgrade`"),
        editions: &[],
    },
];

/// A host refused by name: a distribution NAILS recognises and declines
/// explicitly, rather than letting it fall through to the generic refusal.
struct NamedRefusal {
    /// The `/etc/os-release` `ID`, lowercased.
    id: &'static str,
    /// Human-facing name used in messages.
    label: &'static str,
    /// Why, as a sentence fragment: "NAILS does not target …".
    note: &'static str,
}

/// Distributions refused by name. Enterprise Linux rebuilds and SteamOS are
/// recognised but out of scope, so they get a precise refusal rather than the
/// generic "not a supported platform".
const NAMED_REFUSALS: &[NamedRefusal] = &[
    NamedRefusal {
        id: "rhel",
        label: "Red Hat Enterprise Linux",
        note: "NAILS does not target enterprise Linux distributions",
    },
    NamedRefusal {
        id: "centos",
        label: "CentOS",
        note: "NAILS does not target enterprise Linux distributions",
    },
    NamedRefusal {
        id: "almalinux",
        label: "AlmaLinux",
        note: "NAILS does not target enterprise Linux distributions",
    },
    NamedRefusal {
        id: "rocky",
        label: "Rocky Linux",
        note: "NAILS does not target enterprise Linux distributions",
    },
    NamedRefusal {
        id: "ol",
        label: "Oracle Linux",
        note: "NAILS does not target enterprise Linux distributions",
    },
    NamedRefusal {
        id: "steamos",
        label: "SteamOS",
        note: "NAILS does not target immutable, gaming-oriented systems",
    },
];

/// The outcome of consulting the table for a non-NixOS systemd host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FamilySupport {
    /// An admitted family on a tested release: runs clean.
    Supported,
    /// An admitted family on a tested release that still carries a specific,
    /// documented warning: a release NAILS validates, but on which a known
    /// issue affects the session. It stays a tested release — it is named in
    /// the tested-release sentence — and the string is the warning NAILS emits.
    SupportedWithCaveat(String),
    /// An admitted family NAILS has not tested on this release or this
    /// edition, or a derivative of an admitted family. It runs; the string is
    /// the warning that says so.
    Untested(String),
    /// A family NAILS does not admit, a derivative of one, or a host refused by
    /// name or as unknown. Carries the documented refusal reason.
    Refused(String),
}

/// What [`classify`] decides: the family NAILS resolved (if any) and its verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Classification {
    /// The family the host resolved to, where one could be determined. `None`
    /// for an unidentifiable host or one refused by name.
    pub(crate) family: Option<Family>,
    /// Whether NAILS runs on the host, runs with a warning, or refuses it.
    pub(crate) support: FamilySupport,
}

/// The name a message uses for a table or named-refusal `ID` (`Ubuntu` for
/// `ubuntu`, `Fedora` for `fedora`), or `None` for an `ID` neither lists.
pub(crate) fn label(id: &str) -> Option<&'static str> {
    TABLE
        .iter()
        .find(|row| row.id == id)
        .map(|row| row.label)
        .or_else(|| {
            NAMED_REFUSALS
                .iter()
                .find(|row| row.id == id)
                .map(|row| row.label)
        })
}

/// The name a message uses for a host's edition (`Cloud` for a Fedora host
/// whose `VARIANT_ID` is `cloud`), or `None` when the host's row lists no such
/// edition.
pub(crate) fn edition_label(id: &str, variant_id: &str) -> Option<&'static str> {
    TABLE
        .iter()
        .find(|row| row.id == id)?
        .editions
        .iter()
        .find(|edition| edition.id == variant_id)
        .map(|edition| edition.label)
}

/// Classify a non-NixOS systemd host against the family table.
///
/// - A named refusal (Enterprise Linux, SteamOS) is declined by name first.
/// - A table `ID` is resolved by its row, whatever `ID_LIKE` says: an admitted
///   base is gated on its release and, where the row lists editions, on its
///   `VARIANT_ID`; a non-admitted base is refused as product data; and a
///   derivative follows its base family (a warning once the base is admitted,
///   from the row's minimum release, and a refusal until then).
/// - A non-table `ID` whose `ID_LIKE` names `fedora`, `rhel`, `centos` or `arch`
///   anywhere is refused, naming the first such family in the list's
///   closest-first order. This holds whatever else `ID_LIKE` names: a host that
///   declares kinship with a family NAILS has not validated is refused rather
///   than run as a Debian derivative, even when `debian` comes first.
/// - Otherwise, a non-table `ID` whose `ID_LIKE` names `debian` or `ubuntu` is
///   accepted provisionally, with a warning that NAILS has not tested the
///   derivative.
/// - Anything else — an unknown or missing `ID` — is refused.
pub(crate) fn classify(
    id: Option<&str>,
    id_like: &[String],
    version_id: Option<&str>,
    variant_id: Option<&str>,
) -> Classification {
    if let Some(id) = id {
        if let Some(named) = NAMED_REFUSALS.iter().find(|row| row.id == id) {
            return Classification {
                family: None,
                support: FamilySupport::Refused(named_refusal(named)),
            };
        }
        if let Some(row) = TABLE.iter().find(|row| row.id == id) {
            return classify_row(row, version_id, variant_id);
        }
    }

    // An unvalidated family wins over a Debian-family token, wherever each
    // stands in `ID_LIKE`: the host is refused rather than admitted.
    if let Some(family) = family_from_id_like(id_like) {
        return Classification {
            family: Some(family),
            support: FamilySupport::Refused(unvalidated_like_reason(id, family)),
        };
    }

    if id_like
        .iter()
        .any(|token| token == "debian" || token == "ubuntu")
    {
        return Classification {
            family: Some(Family::Debian),
            support: FamilySupport::Untested(derivative_warning(Family::Debian)),
        };
    }

    Classification {
        family: None,
        support: FamilySupport::Refused(unknown_reason(id)),
    }
}

/// Resolve a matched table row to a verdict.
fn classify_row(
    row: &FamilyRow,
    version_id: Option<&str>,
    variant_id: Option<&str>,
) -> Classification {
    let family = Some(row.family);
    let support = match row.kind {
        Kind::Derivative if !base_admitted(row.family) => {
            FamilySupport::Refused(derivative_refusal(row))
        }
        Kind::Base if !row.admitted => FamilySupport::Refused(not_validated_refusal(row)),
        Kind::Base | Kind::Derivative => admitted_verdict(row, version_id, variant_id),
    };
    Classification { family, support }
}

/// Whether the family's base distribution is admitted.
fn base_admitted(family: Family) -> bool {
    TABLE
        .iter()
        .any(|row| row.kind == Kind::Base && row.family == family && row.admitted)
}

/// The first family NAILS has not validated that an `ID_LIKE` token names, in
/// the list's closest-first order, for an `ID` the table does not list.
/// `debian` and `ubuntu` are not among them: they admit a derivative only when
/// no token names an unvalidated family.
fn family_from_id_like(id_like: &[String]) -> Option<Family> {
    for token in id_like {
        match token.as_str() {
            "fedora" | "rhel" | "centos" => return Some(Family::Fedora),
            "arch" => return Some(Family::Arch),
            _ => {}
        }
    }
    None
}

/// The warning for a derivative of an admitted family.
fn derivative_warning(family: Family) -> String {
    format!(
        "this system is a derivative of the {} family, which NAILS has not tested. It runs, \
         but a change the derivative makes can break the session or leave a trace NAILS does \
         not know about. Use a tested release, or run `{}` on this computer before you rely \
         on it.",
        family.label(),
        rehearse_line(),
    )
}

/// The `rehearse` line an untested host is pointed at, with the real binary
/// path.
fn rehearse_line() -> String {
    nails_base::next_step::sudo_line(nails_base::next_step::NextStep::Rehearse)
}

/// The refusal for a derivative whose base family NAILS has not admitted.
fn derivative_refusal(row: &FamilyRow) -> String {
    format!(
        "{} is based on {}, which NAILS has not yet validated. NAILS refuses it until {} \
         support has been verified. NAILS supports NixOS and the Debian family ({}).",
        row.label,
        row.family.label(),
        row.family.label(),
        supported_platforms(),
    )
}

/// The refusal for a base family that is in the table but not admitted.
fn not_validated_refusal(row: &FamilyRow) -> String {
    format!(
        "{} is not yet a validated platform. NAILS refuses it until its support has been \
         verified. NAILS supports NixOS and the Debian family ({}).",
        row.label,
        supported_platforms(),
    )
}

/// The refusal for a host whose `ID_LIKE` names an unvalidated family.
fn unvalidated_like_reason(id: Option<&str>, family: Family) -> String {
    let who = match id {
        Some(id) => format!("host '{id}'"),
        None => "this host".to_string(),
    };
    format!(
        "{who} declares itself part of the {} family, which NAILS has not yet validated. \
         NAILS supports NixOS and the Debian family ({}); other distributions are not yet \
         validated.",
        family.label(),
        supported_platforms(),
    )
}

/// The refusal for a named distribution NAILS declines explicitly.
fn named_refusal(row: &NamedRefusal) -> String {
    format!(
        "{} is not a supported platform; {}. NAILS supports NixOS and the Debian family ({}).",
        row.label,
        row.note,
        supported_platforms(),
    )
}

/// The refusal for a host NAILS has no backend for.
fn unknown_reason(id: Option<&str>) -> String {
    match id {
        Some(id) => format!(
            "host '{id}' is not a supported platform. NAILS supports NixOS and the Debian \
             family ({}); other distributions are not yet validated.",
            supported_platforms(),
        ),
        None => format!(
            "this host declares no os-release ID; NAILS supports NixOS and the Debian family \
             ({}) and refuses hosts it cannot identify.",
            supported_platforms(),
        ),
    }
}

/// The admitted platforms as one sentence fragment, generated from the table:
/// `Debian 13, Ubuntu 24.04 and 26.04`.
fn supported_platforms() -> String {
    let parts: Vec<String> = TABLE
        .iter()
        .filter(|row| row.kind == Kind::Base && row.admitted)
        .map(|row| match row.gate {
            Gate::Versioned { validated, .. } => format!("{} {}", row.label, releases(validated)),
            Gate::Rolling => row.label.to_string(),
        })
        .collect();
    parts.join(", ")
}

/// `versions` as a list for a sentence: `13`, `24.04 and 26.04`, or
/// `22.04, 24.04 and 26.04`.
fn releases(versions: &[DistroVersion]) -> String {
    joined(versions, "and")
}

/// `versions` as alternatives for a sentence: `13`, `24.04 or 26.04`, or
/// `22.04, 24.04 or 26.04`.
fn either(versions: &[DistroVersion]) -> String {
    joined(versions, "or")
}

/// `items` in a sentence, the last two joined by `conjunction`: `a`,
/// `a and b`, or `a, b and c`.
fn joined<T: ToString>(items: &[T], conjunction: &str) -> String {
    let names: Vec<String> = items.iter().map(ToString::to_string).collect();
    match names.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} {conjunction} {last}", rest.join(", ")),
    }
}

/// The documented refusal for a Debian-family host that is not usr-merged.
///
/// NAILS is tested only on the merged layout, where `/bin`, `/sbin` and `/lib`
/// are symlinks into `/usr`; every supported release ships it. A split layout
/// is refused rather than run untested.
pub(crate) const USR_MERGE_REFUSAL: &str = "this Debian-family host is not usr-merged (/bin, /sbin or /lib is a real \
     directory rather than a symlink into /usr). NAILS is tested only on the merged \
     layout, which every supported release ships. Convert the host with usrmerge, \
     or use Debian 13, Ubuntu 24.04 or Ubuntu 26.04.";

#[cfg(test)]
#[path = "family_tests.rs"]
mod tests;
