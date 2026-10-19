// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Debian-family support data for host detection.
//!
//! NAILS validates the overlay-only backend on Debian and Ubuntu first. The
//! generic [`FhsPlatform`](super::FhsPlatform) is the executor for every
//! supported FHS host; this module is the *policy* that decides which FHS hosts
//! are supported today and which are refused until their own backend lands.
//!
//! Keeping the policy as a small data table means bringing another distribution
//! online is a single entry here plus a contract-suite run — it does not fork
//! the backend. [`detect`](super::detect) consults [`classify_family`] for every
//! non-NixOS systemd host and turns the result into a [`PlatformKind`].
//!
//! Each entry also lists the releases NAILS has been tested on. A release at or
//! above the minimum that is not on that list (a newer Ubuntu than the tests
//! cover) is admitted with a warning that says so, never refused.
//!
//! [`PlatformKind`]: super::PlatformKind

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
    /// The release as the Debian family writes it: the major alone when there is
    /// no minor (`13`), otherwise with a two-digit minor (`24.04`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.minor == 0 {
            write!(f, "{}", self.major)
        } else {
            write!(f, "{}.{:02}", self.major, self.minor)
        }
    }
}

/// One supported Debian-family distribution: the floor it is admitted from and
/// the releases it was tested on.
struct SupportedDistro {
    /// The `/etc/os-release` `ID`, lowercased.
    id: &'static str,
    /// Human-facing name used in refusal messages.
    label: &'static str,
    /// The oldest release NAILS supports on this distribution.
    minimum: DistroVersion,
    /// The releases NAILS has been tested on. Any other release at or above
    /// [`minimum`](Self::minimum) is admitted with a warning that it is
    /// untested.
    validated: &'static [DistroVersion],
}

/// The support table. Adding a distribution NAILS has validated is one entry
/// here — the backend ([`FhsPlatform`](super::FhsPlatform)) is already generic —
/// and a release the tests cover is one more `validated` version.
const SUPPORTED: &[SupportedDistro] = &[
    SupportedDistro {
        id: "debian",
        label: "Debian",
        minimum: DistroVersion::new(13, 0),
        validated: &[DistroVersion::new(13, 0)],
    },
    SupportedDistro {
        id: "ubuntu",
        label: "Ubuntu",
        minimum: DistroVersion::new(24, 4),
        validated: &[DistroVersion::new(24, 4), DistroVersion::new(26, 4)],
    },
];

/// The name of a table distribution (`Ubuntu` for `ubuntu`), or `None` for an
/// `ID` the table does not list.
pub(crate) fn label(id: &str) -> Option<&'static str> {
    SUPPORTED
        .iter()
        .find(|entry| entry.id == id)
        .map(|entry| entry.label)
}

/// The outcome of consulting the support table for a non-NixOS systemd host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FamilySupport {
    /// A Debian-family host on a release NAILS has been tested on, or a
    /// derivative accepted provisionally.
    Supported,
    /// A table distribution at or above its minimum, on a release NAILS has not
    /// been tested on. It is admitted; the string is the warning that says so.
    UntestedRelease(String),
    /// A Debian-family host below the version NAILS supports, or whose version
    /// could not be confirmed. Carries the documented refusal reason.
    Refused(String),
}

/// Classify a non-NixOS systemd host against the Debian-family support table.
///
/// - A table `ID` (debian, ubuntu) is version-gated against its minimum, and a
///   release at or above it that the table does not list as tested is admitted
///   with a warning ([`FamilySupport::UntestedRelease`]).
/// - A non-table `ID` whose `ID_LIKE` names a table family (e.g. a derivative
///   declaring `ID_LIKE=debian`) is accepted provisionally: its own release
///   scheme cannot be mapped to a base version reliably, and the read-only
///   `/usr` guard protects the decoy regardless.
/// - Anything else — Fedora, Arch, an unknown `ID`, or a missing `ID` — is
///   refused with a documented message, because no validated backend covers it.
pub(crate) fn classify_family(
    id: Option<&str>,
    id_like: &[String],
    version_id: Option<&str>,
) -> FamilySupport {
    if let Some(id) = id
        && let Some(entry) = SUPPORTED.iter().find(|entry| entry.id == id)
    {
        return gate_version(entry, version_id);
    }

    // No direct table match: accept a declared derivative of a supported family,
    // otherwise refuse.
    if id_like
        .iter()
        .any(|token| SUPPORTED.iter().any(|entry| entry.id == token))
    {
        return FamilySupport::Supported;
    }

    FamilySupport::Refused(unknown_reason(id))
}

/// Version-gate a matched table entry.
fn gate_version(entry: &SupportedDistro, version_id: Option<&str>) -> FamilySupport {
    let Some(raw) = version_id else {
        return FamilySupport::Refused(format!(
            "{} host declares no VERSION_ID, so NAILS cannot confirm it is at \
             least {} (the minimum supported release).",
            entry.label, entry.minimum,
        ));
    };

    let Some(version) = DistroVersion::parse(raw) else {
        return FamilySupport::Refused(format!(
            "{} host has an unparseable VERSION_ID ('{raw}'); NAILS requires at \
             least {}.",
            entry.label, entry.minimum,
        ));
    };

    if version < entry.minimum {
        return FamilySupport::Refused(format!(
            "{} {raw} is older than the minimum supported release ({} {}). \
             Upgrade the host or run NAILS on a supported release.",
            entry.label, entry.label, entry.minimum,
        ));
    }

    if !entry.validated.contains(&version) {
        return FamilySupport::UntestedRelease(format!(
            "{} {raw} is not a release NAILS has been tested on (tested: {} {}). NAILS runs \
             on it, but a change in this release can break the session or leave a trace \
             NAILS does not know about. Use a tested release, or run `nails rehearse` on this \
             machine before you rely on it.",
            entry.label,
            entry.label,
            releases(entry.validated),
        ));
    }

    FamilySupport::Supported
}

/// `versions` as a list for a sentence: `13`, `24.04 and 26.04`, or
/// `22.04, 24.04 and 26.04`.
fn releases(versions: &[DistroVersion]) -> String {
    let names: Vec<String> = versions.iter().map(ToString::to_string).collect();
    match names.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
    }
}

/// The documented refusal for a host NAILS has no backend for.
fn unknown_reason(id: Option<&str>) -> String {
    match id {
        Some(id) => format!(
            "host '{id}' is not a supported platform. NAILS supports NixOS and \
             the Debian family (Debian 13, Ubuntu 24.04 and 26.04); other \
             distributions are not yet validated."
        ),
        None => "this host declares no os-release ID; NAILS supports NixOS and \
             the Debian family (Debian 13, Ubuntu 24.04 and 26.04) and refuses \
             hosts it cannot identify."
            .to_string(),
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
mod tests {
    use super::*;

    #[test]
    fn version_parses_major_and_minor() {
        assert_eq!(DistroVersion::parse("12"), Some(DistroVersion::new(12, 0)));
        assert_eq!(
            DistroVersion::parse("24.04"),
            Some(DistroVersion::new(24, 4))
        );
        assert_eq!(
            DistroVersion::parse(" 13 "),
            Some(DistroVersion::new(13, 0))
        );
    }

    #[test]
    fn version_rejects_malformed() {
        assert_eq!(DistroVersion::parse("rolling"), None);
        assert_eq!(DistroVersion::parse(""), None);
        // A non-numeric minor degrades to zero rather than failing the parse.
        assert_eq!(
            DistroVersion::parse("24.lts"),
            Some(DistroVersion::new(24, 0))
        );
    }

    #[test]
    fn version_orders_releases() {
        assert!(DistroVersion::new(12, 0) < DistroVersion::new(13, 0));
        assert!(DistroVersion::new(24, 4) > DistroVersion::new(22, 4));
        assert!(DistroVersion::new(24, 4) == DistroVersion::new(24, 4));
        assert!(DistroVersion::new(24, 10) > DistroVersion::new(24, 4));
    }

    #[test]
    fn version_is_written_as_the_distribution_writes_it() {
        assert_eq!(DistroVersion::new(13, 0).to_string(), "13");
        assert_eq!(DistroVersion::new(24, 4).to_string(), "24.04");
        assert_eq!(DistroVersion::new(26, 10).to_string(), "26.10");
    }

    #[test]
    fn releases_are_listed_as_in_a_sentence() {
        let v = DistroVersion::new;
        assert_eq!(releases(&[]), "");
        assert_eq!(releases(&[v(13, 0)]), "13");
        assert_eq!(releases(&[v(24, 4), v(26, 4)]), "24.04 and 26.04");
        assert_eq!(
            releases(&[v(22, 4), v(24, 4), v(26, 4)]),
            "22.04, 24.04 and 26.04"
        );
    }

    #[test]
    fn debian_at_and_above_minimum_is_supported() {
        assert!(matches!(
            classify_family(Some("debian"), &[], Some("12")),
            FamilySupport::Refused(_)
        ));
        assert_eq!(
            classify_family(Some("debian"), &[], Some("13")),
            FamilySupport::Supported
        );
    }

    #[test]
    fn ubuntu_tested_releases_are_supported() {
        for release in ["24.04", "26.04"] {
            assert_eq!(
                classify_family(Some("ubuntu"), &["debian".to_string()], Some(release)),
                FamilySupport::Supported,
                "{release}"
            );
        }
    }

    #[test]
    fn an_untested_ubuntu_release_is_admitted_with_a_warning() {
        // Newer than every tested release (26.10 came out on 2026-10-15), or
        // between two of them: admitted, never refused, and the warning says so.
        for release in ["26.10", "28.04", "24.10", "25.04", "25.10"] {
            match classify_family(Some("ubuntu"), &["debian".to_string()], Some(release)) {
                FamilySupport::UntestedRelease(warning) => {
                    assert!(
                        warning.starts_with(&format!(
                            "Ubuntu {release} is not a release NAILS has been tested on \
                             (tested: Ubuntu 24.04 and 26.04)."
                        )),
                        "{warning}"
                    );
                    assert!(warning.contains("nails rehearse"), "{warning}");
                }
                other => panic!("{release}: expected an untested release, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_debian_release_after_the_tested_one_is_admitted_with_a_warning() {
        match classify_family(Some("debian"), &[], Some("14")) {
            FamilySupport::UntestedRelease(warning) => assert!(
                warning.starts_with(
                    "Debian 14 is not a release NAILS has been tested on (tested: Debian 13)."
                ),
                "{warning}"
            ),
            other => panic!("expected an untested release, got {other:?}"),
        }
    }

    #[test]
    fn debian_below_minimum_is_refused() {
        let outcome = classify_family(Some("debian"), &[], Some("11"));
        match outcome {
            FamilySupport::Refused(reason) => {
                assert!(reason.contains("11"));
                assert!(reason.contains("minimum"));
                assert!(reason.contains("(Debian 13)"), "{reason}");
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn ubuntu_below_minimum_is_refused() {
        let outcome = classify_family(Some("ubuntu"), &["debian".to_string()], Some("22.04"));
        match outcome {
            FamilySupport::Refused(reason) => {
                assert!(reason.contains("(Ubuntu 24.04)"), "{reason}")
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn every_tested_release_is_one_the_table_admits() {
        for entry in SUPPORTED {
            assert!(!entry.validated.is_empty(), "{} lists no release", entry.id);
            for version in entry.validated {
                assert!(*version >= entry.minimum, "{} {version}", entry.id);
                assert_eq!(
                    classify_family(Some(entry.id), &[], Some(&version.to_string())),
                    FamilySupport::Supported,
                    "{} {version}",
                    entry.id
                );
            }
        }
    }

    #[test]
    fn labels_name_the_table_distributions_only() {
        assert_eq!(label("ubuntu"), Some("Ubuntu"));
        assert_eq!(label("debian"), Some("Debian"));
        assert_eq!(label("linuxmint"), None);
    }

    #[test]
    fn debian_without_version_is_refused() {
        let outcome = classify_family(Some("debian"), &[], None);
        match outcome {
            FamilySupport::Refused(reason) => assert!(reason.contains("VERSION_ID")),
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn fedora_is_refused() {
        let outcome = classify_family(Some("fedora"), &[], Some("40"));
        match outcome {
            FamilySupport::Refused(reason) => assert!(reason.contains("fedora")),
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn arch_is_refused() {
        assert!(matches!(
            classify_family(Some("arch"), &[], None),
            FamilySupport::Refused(_)
        ));
    }

    #[test]
    fn missing_id_is_refused() {
        let outcome = classify_family(None, &[], None);
        match outcome {
            FamilySupport::Refused(reason) => assert!(reason.contains("no os-release ID")),
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn debian_like_derivative_is_accepted() {
        // A derivative declaring ID_LIKE=debian with an unknown ID is accepted
        // provisionally; its own VERSION_ID is not gated.
        assert_eq!(
            classify_family(
                Some("linuxmint"),
                &["ubuntu".to_string(), "debian".to_string()],
                Some("22")
            ),
            FamilySupport::Supported
        );
    }
}
