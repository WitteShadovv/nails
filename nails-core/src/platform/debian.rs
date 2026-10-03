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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// One supported Debian-family distribution and the floor it is validated at.
struct SupportedDistro {
    /// The `/etc/os-release` `ID`, lowercased.
    id: &'static str,
    /// Human-facing name used in refusal messages.
    label: &'static str,
    /// The oldest release NAILS supports on this distribution.
    minimum: DistroVersion,
}

/// The support table. Adding a distribution NAILS has validated is one entry
/// here — the backend ([`FhsPlatform`](super::FhsPlatform)) is already generic.
const SUPPORTED: &[SupportedDistro] = &[
    SupportedDistro {
        id: "debian",
        label: "Debian",
        minimum: DistroVersion::new(12, 0),
    },
    SupportedDistro {
        id: "ubuntu",
        label: "Ubuntu",
        minimum: DistroVersion::new(24, 4),
    },
];

/// The outcome of consulting the support table for a non-NixOS systemd host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FamilySupport {
    /// A supported Debian-family host at or above its minimum version.
    Supported,
    /// A Debian-family host below the version NAILS supports, or whose version
    /// could not be confirmed. Carries the documented refusal reason.
    Refused(String),
}

/// Classify a non-NixOS systemd host against the Debian-family support table.
///
/// - A table `ID` (debian, ubuntu) is version-gated against its minimum.
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

    FamilySupport::Supported
}

/// The documented refusal for a host NAILS has no backend for.
fn unknown_reason(id: Option<&str>) -> String {
    match id {
        Some(id) => format!(
            "host '{id}' is not a supported platform. NAILS supports NixOS and \
             the Debian family (Debian 12+, Ubuntu 24.04+); other distributions \
             are not yet validated."
        ),
        None => "this host declares no os-release ID; NAILS supports NixOS and \
             the Debian family (Debian 12+, Ubuntu 24.04+) and refuses hosts it \
             cannot identify."
            .to_string(),
    }
}

/// The documented refusal for a Debian-family host that is not usr-merged.
///
/// A merged layout keeps `/bin`, `/sbin` and `/lib` as symlinks into `/usr`, so
/// the read-only `/usr` guard is the single invariant that keeps package writes
/// off the decoy disk. On a split (non-merged) layout those are real directories
/// outside `/usr`, which the guard would not cover, so NAILS refuses rather than
/// risk leaking payloads to the decoy.
pub(crate) const USR_MERGE_REFUSAL: &str = "this Debian-family host is not usr-merged (/bin, /sbin or /lib is a real \
     directory rather than a symlink into /usr). NAILS keeps /usr read-only as \
     its leak guard, which only holds on a merged layout. Convert the host with \
     usrmerge, or use a release that ships the merged layout (Debian 12+, \
     Ubuntu 24.04+).";

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
    fn debian_at_and_above_minimum_is_supported() {
        assert_eq!(
            classify_family(Some("debian"), &[], Some("12")),
            FamilySupport::Supported
        );
        assert_eq!(
            classify_family(Some("debian"), &[], Some("13")),
            FamilySupport::Supported
        );
    }

    #[test]
    fn ubuntu_at_and_above_minimum_is_supported() {
        assert_eq!(
            classify_family(Some("ubuntu"), &["debian".to_string()], Some("24.04")),
            FamilySupport::Supported
        );
        assert_eq!(
            classify_family(Some("ubuntu"), &["debian".to_string()], Some("25.04")),
            FamilySupport::Supported
        );
    }

    #[test]
    fn debian_below_minimum_is_refused() {
        let outcome = classify_family(Some("debian"), &[], Some("11"));
        match outcome {
            FamilySupport::Refused(reason) => {
                assert!(reason.contains("11"));
                assert!(reason.contains("minimum"));
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn ubuntu_below_minimum_is_refused() {
        let outcome = classify_family(Some("ubuntu"), &["debian".to_string()], Some("22.04"));
        assert!(matches!(outcome, FamilySupport::Refused(_)));
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
