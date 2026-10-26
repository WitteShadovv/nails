// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The gate a host of an admitted row of the family table is held to.
//!
//! [`admitted_verdict`] decides what a host gets once NAILS admits its row (for
//! a derivative, the row of its base family): its release is held to the row's
//! minimum and refused below it, then compared with the releases NAILS is
//! tested on, and where the row lists editions, its edition (os-release
//! `VARIANT_ID`) is compared with the tested ones. A release or an edition NAILS
//! has not been tested on runs, with one warning that names each; only the
//! minimum refuses.

use super::{
    DistroVersion, FamilyRow, FamilySupport, Gate, Kind, derivative_warning, joined, rehearse_line,
    releases,
};

/// The verdict on a host of `row` once NAILS admits the row (for a
/// derivative, its base family).
///
/// A host below the row's minimum release, or whose release cannot be read
/// where the row gates on one, is refused. A derivative otherwise runs as an
/// untested derivative. A base runs clean on a tested release and, where the
/// row lists editions, a tested edition; any other release or edition runs
/// with a warning that names it, and a tested release can carry a caveat.
pub(super) fn admitted_verdict(
    row: &FamilyRow,
    version_id: Option<&str>,
    variant_id: Option<&str>,
) -> FamilySupport {
    let release = match release_standing(row, version_id) {
        Ok(release) => release,
        Err(reason) => return FamilySupport::Refused(reason),
    };
    if row.kind == Kind::Derivative {
        return FamilySupport::Untested(derivative_warning(row.family));
    }
    let edition = untested_edition(row, variant_id);
    match (release, edition) {
        (Release::Tested, None) => FamilySupport::Supported,
        (Release::Caveat(caveat), None) => FamilySupport::SupportedWithCaveat(caveat.to_string()),
        (Release::Tested, Some(edition)) => {
            FamilySupport::Untested(untested_warning(row, version_id, None, Some(edition)))
        }
        // The caveat of a tested release holds on an untested edition too.
        (Release::Caveat(caveat), Some(edition)) => FamilySupport::Untested(format!(
            "{} {caveat}",
            untested_warning(row, version_id, None, Some(edition))
        )),
        (Release::Untested(tested), edition) => {
            FamilySupport::Untested(untested_warning(row, version_id, Some(tested), edition))
        }
    }
}

/// Where a host's release stands among those its row is tested on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Release {
    /// A tested release, or any release of a rolling row, which has none to
    /// gate on.
    Tested,
    /// A tested release with a known issue: the caveat NAILS adds.
    Caveat(&'static str),
    /// A release NAILS has not been tested on: the releases it has.
    Untested(&'static [DistroVersion]),
}

/// Gate a host's release on `row`: where it stands, or the refusal when the
/// row's minimum cannot be confirmed or the release is below it.
fn release_standing(row: &FamilyRow, version_id: Option<&str>) -> Result<Release, String> {
    let Gate::Versioned {
        min,
        validated,
        caveats,
    } = row.gate
    else {
        // A rolling family has no release to gate on.
        return Ok(Release::Tested);
    };

    let Some(raw) = version_id else {
        return Err(format!(
            "{} host declares no VERSION_ID, so NAILS cannot confirm it is at \
             least {min} (the minimum supported release).",
            row.label,
        ));
    };

    let Some(version) = DistroVersion::parse(raw) else {
        return Err(format!(
            "{} host has an unparseable VERSION_ID ('{raw}'); NAILS requires at \
             least {min}.",
            row.label,
        ));
    };

    if version < min {
        return Err(format!(
            "{} {raw} is older than the minimum supported release ({} {min}). \
             Upgrade the host or run NAILS on a supported release.",
            row.label, row.label,
        ));
    }

    if !validated.contains(&version) {
        return Ok(Release::Untested(validated));
    }

    // A tested release can still carry a specific, documented caveat.
    Ok(caveats
        .iter()
        .copied()
        .find(|(caveated, _)| *caveated == version)
        .map_or(Release::Tested, |(_, caveat)| Release::Caveat(caveat)))
}

/// What os-release says of a host's edition when it is not one NAILS is tested
/// on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UntestedEdition<'a> {
    /// An edition the row lists but NAILS has not been tested on, by its label.
    Listed(&'static str),
    /// A `VARIANT_ID` the row does not list.
    Unlisted(&'a str),
    /// No `VARIANT_ID`, or an empty one: the host names no edition.
    Unnamed,
}

/// Gate a host's edition on `row`: `None` when the row lists no editions or
/// `variant_id` names a tested one, and otherwise what the host runs instead.
fn untested_edition<'a>(
    row: &FamilyRow,
    variant_id: Option<&'a str>,
) -> Option<UntestedEdition<'a>> {
    if row.editions.is_empty() {
        return None;
    }
    let Some(variant) = variant_id.filter(|variant| !variant.is_empty()) else {
        return Some(UntestedEdition::Unnamed);
    };
    match row.editions.iter().find(|edition| edition.id == variant) {
        Some(edition) if edition.validated => None,
        Some(edition) => Some(UntestedEdition::Listed(edition.label)),
        None => Some(UntestedEdition::Unlisted(variant)),
    }
}

/// The warning for a host of an admitted base row on a release or an edition
/// NAILS has not been tested on, or both. `tested_releases` is set when the
/// release is untested and lists the releases the row is tested on.
fn untested_warning(
    row: &FamilyRow,
    version_id: Option<&str>,
    tested_releases: Option<&[DistroVersion]>,
    edition: Option<UntestedEdition<'_>>,
) -> String {
    let host = match version_id {
        Some(raw) => format!("{} {raw}", row.label),
        None => row.label.to_string(),
    };
    let mut facts = Vec::new();
    if let Some(tested) = tested_releases {
        facts.push(format!(
            "{host} is not a release NAILS has been tested on (tested: {} {})",
            row.label,
            releases(tested),
        ));
    }
    if let Some(edition) = edition {
        let tested = tested_editions(row);
        facts.push(match edition {
            UntestedEdition::Listed(label) => format!(
                "{host} {label} is not an edition NAILS has been tested on (tested: {tested})"
            ),
            UntestedEdition::Unlisted(variant) => format!(
                "{host} with VARIANT_ID '{variant}' is not an edition NAILS has been tested on \
                 (tested: {tested})"
            ),
            UntestedEdition::Unnamed => format!(
                "{host} declares no edition (its os-release has no VARIANT_ID, or an empty \
                 one), so NAILS cannot tell whether it is a tested one (tested: {tested})"
            ),
        });
    }
    let (change, use_tested) = match (tested_releases.is_some(), edition.is_some()) {
        (true, true) => ("release or edition", "release and edition"),
        (true, false) => ("release", "release"),
        (false, _) => ("edition", "edition"),
    };
    format!(
        "{}. NAILS runs on it, but a change in this {change} can break the session or leave a \
         trace NAILS does not know about. Use a tested {use_tested}, or run `{}` on this \
         computer before you rely on it.",
        facts.join(". "),
        rehearse_line(),
    )
}

/// The editions `row` is tested on, as a sentence names them: `Fedora Cloud`,
/// or `Fedora Cloud and Server`.
pub(super) fn tested_editions(row: &FamilyRow) -> String {
    let labels: Vec<&str> = row
        .editions
        .iter()
        .filter(|edition| edition.validated)
        .map(|edition| edition.label)
        .collect();
    format!("{} {}", row.label, joined(&labels, "and"))
}
