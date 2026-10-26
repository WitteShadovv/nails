// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The verdict engine: the component that decides "oracle clean".
//!
//! Given the three normalized scans and the policy, it:
//!
//! 1. validates the allowlist — every entry cites exactly one residual catalog
//!    row, or a threat-model anchor a residual row points at, and names one
//!    exact location, never a wholesale `/var`, `/nix` or `/home` tree; an
//!    entry vouches for that exact leaf alone, never what lies beneath it; a
//!    broken allowlist never yields a clean verdict;
//! 2. computes the noise-subtracted residue (see [`crate::residue`]): what is
//!    new in `after`, changed in it or gone from it, unless the clean control
//!    cycle shows the same change, which makes it scan noise rather than a
//!    trace of the hidden session;
//! 3. partitions that residue into the planted self-checks, the cited-and-
//!    explained, and the unexplained (each unexplained finding is a leak);
//! 4. checks the scan is not blind — every positive control names a concrete
//!    planted artifact (an exact path and value, never a directory) and is
//!    detected in `after` while `before` and the control cycle lack it, and
//!    there is at least one to check;
//! 5. checks the coverage canary, validated the same way, is detected; and
//! 6. for a real scan, checks every required analysis channel
//!    ([`Tool::REQUIRED`]: restore, bulk_extractor and plaso) reported at
//!    least one finding on every image: a tool that did not run, failed or
//!    read nothing sees no residue, and no channel stands in for another. The
//!    nix_db channel is not required, since only a Nix decoy has a store
//!    database: the scan holds its rows to the database instead (see
//!    [`crate::scan`]).
//!
//! The run is [`Status::Clean`] only when all six hold. [`verdict`] decides the
//! first five over the findings alone, so a test world needs only the findings
//! its rule weighs; [`scan_verdict`] adds the sixth and is the decision the CLI
//! renders. Every verdict also names the classes of change it cannot see (see
//! [`crate::unseen`]), and a clean summary line ends with them, so a clean
//! verdict never claims more than its keys tell apart. Everything here is a
//! pure function of its inputs, so the whole engine is unit-tested in
//! `crate::tests` over synthetic findings.

use crate::catalog::Catalog;
use crate::model::{
    AllowEntry, Canary, Change, Controls, Finding, ImageLabel, OraclePolicy, PositiveControl,
    Scans, Tool,
};
use crate::residue::compute_residue;
use crate::unseen::{self, Unseen};
use serde::Serialize;
use std::collections::BTreeSet;

/// The overall outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Every difference is noise or cited, the scan is not blind, the canary
    /// was seen.
    Clean,
    /// At least one failure below; never emitted on anything but a clean run.
    Fail,
}

/// One reason a run is not clean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Failure {
    /// A genuine `after`-vs-`before` difference, absent from the control cycle
    /// and covered by no cited allowlist entry — a leak.
    UnexplainedResidue {
        /// Whether the finding is new in `after`, changed in it or gone from it.
        change: Change,
        /// The tool that surfaced the leak.
        tool: Tool,
        /// Where it was seen.
        path: String,
        /// What was seen there: for a removal, what `after` lost.
        field: String,
    },
    /// A planted positive control was not detected in `after`: the scan is
    /// blind, so no "no residue" claim can be trusted.
    PositiveControlMissing {
        /// The control's name.
        name: String,
    },
    /// A positive control's value is already on `before` or the control
    /// cycle, so seeing it in `after` proves nothing about the planted record:
    /// the scan has not shown it sees one, and the run is blind.
    PositiveControlInBaseline {
        /// The control's name.
        name: String,
        /// The first baseline image that carries it: `before` or `control`.
        image: String,
    },
    /// No positive control was configured, so the run cannot prove it is able
    /// to see residue at all.
    NoPositiveControl,
    /// The coverage canary was not detected: the scan did not read the image.
    CanaryMissing {
        /// Where the canary should have appeared.
        path: String,
    },
    /// An allowlist entry was rejected. A clean verdict is impossible until the
    /// allowlist is fixed.
    InvalidAllowlistEntry {
        /// The entry's locus.
        path: String,
        /// The entry's citation.
        cite: String,
        /// Why it was rejected.
        reason: String,
    },
    /// A positive-control locus was rejected: too broad, or not a concrete
    /// planted artifact (an exact path and value). A misconfigured self-check
    /// must never silently widen into a blanket residue exemption, so the run
    /// fails until it is fixed.
    InvalidPositiveControl {
        /// The control's name.
        name: String,
        /// The control's locus.
        path: String,
        /// Why it was rejected.
        reason: String,
    },
    /// The coverage-canary locus was rejected, for the same reasons: it must
    /// name a concrete planted marker, not a whole directory.
    InvalidCanary {
        /// The canary's locus.
        path: String,
        /// Why it was rejected.
        reason: String,
    },
    /// A required analysis channel ([`Tool::REQUIRED`]) reported no finding at
    /// all for one image: the tool did not run, failed, or read nothing. No
    /// other channel stands in for it (the restore channel leaves the rotating
    /// journal files to plaso, and every shipped self-check is a bulk_extractor
    /// finding), so a scan missing a channel could not look and is never clean.
    ChannelMissing {
        /// The silent channel.
        tool: Tool,
        /// The image it reported nothing for: `before`, `control` or `after`.
        image: String,
    },
}

/// A residue finding that a cited allowlist entry explains, with the cited
/// row's own words for why it is expected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Explained {
    /// Whether the finding is new in `after`, changed in it or gone from it.
    pub change: Change,
    /// The tool that surfaced it.
    pub tool: Tool,
    /// Where it was seen.
    pub path: String,
    /// What was seen there.
    pub field: String,
    /// The citation that covers it.
    pub cite: String,
    /// The cited row's `risk`, or empty for a doc-anchor citation.
    pub risk: String,
    /// The cited row's `mitigation`, or empty for a doc-anchor citation.
    pub mitigation: String,
}

/// Whether a named positive control was detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControlResult {
    /// The control's name.
    pub name: String,
    /// Whether `after` carried it while `before` and the control cycle did not.
    pub detected: bool,
}

/// The reconciling counts. `candidate == noise_subtracted + residue` and
/// `residue == self_checks + explained + unexplained`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Counts {
    /// Changes from `before` to `after`: a finding new in `after` or gone from
    /// it, or a restore path whose entry `after` holds differently.
    pub candidate: usize,
    /// Of those, the ones the control cycle shows too (scan noise): the same
    /// finding gained or lost, or a restore path it changed as well.
    pub noise_subtracted: usize,
    /// The noise-subtracted residue.
    pub residue: usize,
    /// Residue findings that are planted self-checks (controls or the canary).
    pub self_checks: usize,
    /// Residue findings a cited allowlist entry explains.
    pub explained: usize,
    /// Residue findings nothing explains — the leaks.
    pub unexplained: usize,
}

/// The full verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verdict {
    /// Clean or fail.
    pub status: Status,
    /// Whether the scan was blind: a positive control was missing or already
    /// in the baseline or, in [`scan_verdict`], a required analysis channel
    /// reported nothing for an image. Set independently of `status` so a blind
    /// run reads unmistakably.
    pub blind: bool,
    /// A one-line human summary.
    pub summary: String,
    /// The reconciling counts.
    pub counts: Counts,
    /// Every reason the run is not clean, if any.
    pub failures: Vec<Failure>,
    /// The cited-and-explained residue findings.
    pub explained: Vec<Explained>,
    /// Per positive control, whether it was detected.
    pub positive_controls: Vec<ControlResult>,
    /// Whether the coverage canary was detected.
    pub canary_detected: bool,
    /// The classes of change this verdict cannot see, the files of this run a
    /// plain reboot rewrites among them: what a clean verdict does not cover.
    pub unseen: Vec<Unseen>,
}

impl Verdict {
    /// Whether the run is clean.
    pub fn is_clean(&self) -> bool {
        self.status == Status::Clean
    }

    /// The process exit code: `0` clean, `1` fail.
    pub fn exit_code(&self) -> u8 {
        if self.is_clean() { 0 } else { 1 }
    }
}

/// System and user-data subtrees too broad to exempt even with a valid
/// citation: the places the catalog enumerates residue *selectively*, so a
/// wholesale exemption would blind the oracle to the very directories it exists
/// to watch. A space-separated list so the first path segment can be matched
/// without a wholesale `/var`, `/nix` or `/home` exemption slipping through at
/// depth two. `home`, `root`, `mnt` and `media` hold user data and mounts: a
/// two-segment `/home/user` names a whole account, never a specific residue.
const SYSTEM_ROOTS: &str =
    "var nix run usr etc lib lib64 opt srv boot sys proc dev tmp home root mnt media";

/// Whether path `pat` covers path `p`: equal, or `pat` is an ancestor
/// directory of `p`. Component-aware, so `/var/lib/nix` never spuriously
/// covers `/var/lib/nixos`. It places an allowlist entry inside the channel of
/// the row it cites. Crate-visible for its own tests.
pub(crate) fn path_covers(pat: &str, p: &str) -> bool {
    if pat == p {
        return true;
    }
    if !pat.starts_with('/') || !p.starts_with('/') {
        return false;
    }
    let pat = pat.trim_end_matches('/');
    p.len() > pat.len() && p.as_bytes()[pat.len()] == b'/' && p.starts_with(pat)
}

/// Whether a finding is the one a `(tool, path, field)` locator names: the
/// tool when one is pinned, the exact path and the value when one is named.
fn locator_matches(tool: Option<Tool>, path: &str, field: Option<&str>, f: &Finding) -> bool {
    if let Some(t) = tool
        && t != f.tool
    {
        return false;
    }
    if path != f.path {
        return false;
    }
    match field {
        Some(expected) => expected == f.field,
        None => true,
    }
}

/// Why `path` is too broad to allowlist, or `None` when it is specific enough.
/// Crate-visible for its own tests.
pub(crate) fn breadth_reason(path: &str) -> Option<String> {
    if path.is_empty() {
        return Some("empty path".to_string());
    }
    if path
        .chars()
        .any(|c| matches!(c, '*' | '?' | '[' | ']' | '{' | '}'))
    {
        return Some("glob wildcards are not allowed; name a concrete path".to_string());
    }
    // A bare word is a bulk_extractor feature type or another locus that is
    // not a path; its breadth is enforced by requiring a specific `field` in
    // `entry_reject_reason`, not here.
    if !path.starts_with('/') {
        return None;
    }
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segs.len() < 2 {
        return Some("names a whole top-level directory; allowlist a path within it".to_string());
    }
    if segs.len() < 3 && SYSTEM_ROOTS.split(' ').any(|r| r == segs[0]) {
        return Some(format!(
            "names the whole /{} subtree; allowlist a path within it",
            segs[..2].join("/")
        ));
    }
    None
}

/// Validate one allowlist entry against the catalog, returning the reason it
/// is rejected, or `None` when it may explain the exact finding it names.
///
/// Only a residual row explains a difference: every other row describes a
/// trace the overlay must prevent, so that trace in `after` is a leak, and
/// citing the row would print the leak's own description as its excuse. A doc
/// anchor is held to the same rule through the rows that point at it.
fn entry_reject_reason(entry: &AllowEntry, catalog: &Catalog) -> Option<String> {
    let cite = entry.cite.trim();
    if cite.is_empty() {
        return Some("empty citation".to_string());
    }
    let is_locus_word = !entry.path.starts_with('/');
    if is_locus_word && entry.field.as_deref().unwrap_or("").is_empty() {
        return Some(
            "a feature or record allowlist must name a specific value in `field`".to_string(),
        );
    }
    if let Some(reason) = breadth_reason(&entry.path) {
        return Some(reason);
    }
    if cite.contains('#') {
        return match catalog.anchor(cite) {
            None => Some(format!("`{cite}` is not a known residue doc section")),
            Some(false) => Some(format!(
                "`{cite}` explains only rows the overlay must prevent, never a residual trace"
            )),
            Some(true) => None,
        };
    }
    let Some(row) = catalog.row(cite) else {
        return Some(format!("`{cite}` is not a residue-catalog id"));
    };
    if !row.residual {
        return Some(format!(
            "`{cite}` is not a residual row: it names a trace the overlay must prevent, which is a leak when it shows"
        ));
    }
    // A path-channel row vouches only within its own channel; citing it for a
    // path outside that channel is rejected. A feature or record locus and a
    // mechanism row are not pinned to a path, so there is nothing to compare.
    if is_locus_word || row.channel_paths.is_empty() {
        return None;
    }
    let within = row
        .channel_paths
        .iter()
        .any(|c| path_covers(c, &entry.path));
    if within {
        return None;
    }
    Some(format!(
        "path is outside the channel of `{cite}` ({})",
        row.channel_paths.join(", ")
    ))
}

/// Split the allowlist into the entries that pass validation and a failure per
/// entry that does not.
fn validate_allowlist<'a>(
    entries: &'a [AllowEntry],
    catalog: &Catalog,
) -> (Vec<&'a AllowEntry>, Vec<Failure>) {
    let mut valid = Vec::new();
    let mut failures = Vec::new();
    for entry in entries {
        match entry_reject_reason(entry, catalog) {
            None => valid.push(entry),
            Some(reason) => failures.push(Failure::InvalidAllowlistEntry {
                path: entry.path.clone(),
                cite: entry.cite.clone(),
                reason,
            }),
        }
    }
    (valid, failures)
}

/// Whether any finding in `set` matches the `(tool, path, field)` locator. Used
/// to detect positive controls and the canary, which are concrete leaves, so
/// the path must match exactly.
fn any_match(set: &BTreeSet<Finding>, tool: Option<Tool>, path: &str, field: Option<&str>) -> bool {
    set.iter().any(|f| locator_matches(tool, path, field, f))
}

/// The self-checks whose loci passed validation: the positive controls and the
/// canary that may both prove the scan is not blind and exempt their own
/// planted residue. An invalid locus is dropped here and fails the run
/// separately, so it can never act as a blanket residue exemption.
struct ValidSelfChecks<'a> {
    positive_controls: Vec<&'a PositiveControl>,
    canary: Option<&'a Canary>,
}

/// Why a self-check locus is not a concrete planted artifact, or `None` when it
/// names one. Held to the SAME breadth guard as the allowlist, and required to
/// pin an exact value: a directory or value-less locus would silently exempt
/// everything beneath it.
fn self_check_reject_reason(path: &str, field: Option<&str>) -> Option<String> {
    if let Some(reason) = breadth_reason(path) {
        return Some(reason);
    }
    if field.unwrap_or("").is_empty() {
        return Some("must name an exact value in `field`, not a whole location".to_string());
    }
    None
}

/// Validate every positive control and the canary, returning the ones that may
/// act as self-checks and a failure per rejected locus.
fn validate_self_checks(controls: &Controls) -> (ValidSelfChecks<'_>, Vec<Failure>) {
    let mut failures = Vec::new();
    let mut positive_controls = Vec::new();
    for c in &controls.positive_controls {
        match self_check_reject_reason(&c.path, c.field.as_deref()) {
            None => positive_controls.push(c),
            Some(reason) => failures.push(Failure::InvalidPositiveControl {
                name: c.name.clone(),
                path: c.path.clone(),
                reason,
            }),
        }
    }
    let canary =
        match self_check_reject_reason(&controls.canary.path, controls.canary.field.as_deref()) {
            None => Some(&controls.canary),
            Some(reason) => {
                failures.push(Failure::InvalidCanary {
                    path: controls.canary.path.clone(),
                    reason,
                });
                None
            }
        };
    (
        ValidSelfChecks {
            positive_controls,
            canary,
        },
        failures,
    )
}

/// Whether a finding is one of the scan's own planted self-checks (a validated
/// positive control or the validated canary), which are expected residue, never
/// leaks. Self-checks are concrete leaves, so the path must match exactly.
fn is_self_check(f: &Finding, checks: &ValidSelfChecks) -> bool {
    if let Some(canary) = checks.canary
        && locator_matches(canary.tool, &canary.path, canary.field.as_deref(), f)
    {
        return true;
    }
    checks
        .positive_controls
        .iter()
        .any(|c| locator_matches(c.tool, &c.path, c.field.as_deref(), f))
}

/// Whether a validated allowlist entry covers a residue finding: the exact path
/// and, when named, the exact value; with no value named, only the restore
/// channel's entry at that path. An entry covers a removal only when it says
/// so, and a removal entry nothing else.
fn entry_covers(e: &AllowEntry, f: &Finding, change: Change) -> bool {
    if e.removed != (change == Change::Removed) || e.path != f.path {
        return false;
    }
    match &e.field {
        Some(field) => *field == f.field,
        None => f.tool.one_entry_per_path(),
    }
}

/// Partition the residue into self-checks, explained and unexplained. A
/// removal is never a self-check: every check is planted on `after`.
fn partition_residue(
    residue: &[(&Finding, Change)],
    valid: &[&AllowEntry],
    checks: &ValidSelfChecks,
    catalog: &Catalog,
) -> (Vec<Explained>, Vec<Failure>, usize) {
    let mut explained = Vec::new();
    let mut unexplained = Vec::new();
    let mut self_checks = 0;
    for &(f, change) in residue {
        if change != Change::Removed && is_self_check(f, checks) {
            self_checks += 1;
            continue;
        }
        match valid.iter().find(|e| entry_covers(e, f, change)) {
            Some(e) => explained.push(explain(f, change, &e.cite, catalog)),
            None => unexplained.push(Failure::UnexplainedResidue {
                change,
                tool: f.tool,
                path: f.path.clone(),
                field: f.field.clone(),
            }),
        }
    }
    (explained, unexplained, self_checks)
}

/// Build the explanation for a finding a cited entry covers.
fn explain(f: &Finding, change: Change, cite: &str, catalog: &Catalog) -> Explained {
    let (risk, mitigation) = match catalog.row(cite) {
        Some(row) => (row.risk.clone(), row.mitigation.clone()),
        None => (String::new(), String::new()),
    };
    Explained {
        change,
        tool: f.tool,
        path: f.path.clone(),
        field: f.field.clone(),
        cite: cite.to_string(),
        risk,
        mitigation,
    }
}

/// Check every validated positive control is detected: present in `after` and
/// absent from `before` and the control cycle, so that it is the planted record
/// the scan saw and not one the baseline already carried. Returns the
/// per-control results, a failure per control not detected, and whether the
/// scan is blind. The "at least one control" rule is enforced in [`verdict`]
/// over the configured list, so a rejected control is not miscounted as none
/// configured.
fn check_controls(
    scans: &Scans,
    controls: &[&PositiveControl],
) -> (Vec<ControlResult>, Vec<Failure>, bool) {
    let mut results = Vec::new();
    let mut failures = Vec::new();
    for c in controls {
        let seen =
            |label: ImageLabel| any_match(scans.image(label), c.tool, &c.path, c.field.as_deref());
        let baseline = [ImageLabel::Before, ImageLabel::Control]
            .into_iter()
            .find(|&label| seen(label));
        let failure = match baseline {
            Some(label) => Some(Failure::PositiveControlInBaseline {
                name: c.name.clone(),
                image: label.dir_name().to_string(),
            }),
            None if !seen(ImageLabel::After) => Some(Failure::PositiveControlMissing {
                name: c.name.clone(),
            }),
            None => None,
        };
        results.push(ControlResult {
            name: c.name.clone(),
            detected: failure.is_none(),
        });
        failures.extend(failure);
    }
    let blind = !failures.is_empty();
    (results, failures, blind)
}

/// Check the coverage canary is detected in `after`.
fn check_canary(after: &BTreeSet<Finding>, canary: &Canary) -> (bool, Option<Failure>) {
    let detected = any_match(after, canary.tool, &canary.path, canary.field.as_deref());
    if detected {
        return (true, None);
    }
    let failure = Failure::CanaryMissing {
        path: canary.path.clone(),
    };
    (false, Some(failure))
}

/// Render the one-line human summary. A clean line ends with what the verdict
/// cannot see.
fn summarize(
    status: Status,
    blind: bool,
    counts: &Counts,
    failures: usize,
    unseen: &[Unseen],
) -> String {
    if status == Status::Clean {
        return format!(
            "CLEAN: {} residue ({} noise subtracted, {} cited, {} self-check){}",
            counts.residue,
            counts.noise_subtracted,
            counts.explained,
            counts.self_checks,
            unseen::summary_suffix(unseen)
        );
    }
    let marker = if blind { " (BLIND)" } else { "" };
    format!(
        "FAIL{marker}: {failures} failure(s), {} of {} residue unexplained",
        counts.unexplained, counts.residue
    )
}

/// Decide the verdict over the normalized findings: the first five rules of the
/// module docs. It does not check that the required channels reported, so a
/// real run is decided with [`scan_verdict`]. Pure: the whole decision is a
/// function of the scans, the policy and the catalog.
pub fn verdict(scans: &Scans, policy: &OraclePolicy, catalog: &Catalog) -> Verdict {
    let (valid, mut failures) = validate_allowlist(&policy.allowlist.entries, catalog);
    let (checks, self_check_failures) = validate_self_checks(&policy.controls);
    failures.extend(self_check_failures);

    let residue = compute_residue(scans);
    let unseen = unseen::classes(scans, &residue.rewritten);
    let (explained, unexplained, self_checks) =
        partition_residue(&residue.items, &valid, &checks, catalog);
    let (control_results, control_failures, blind) =
        check_controls(scans, &checks.positive_controls);
    let (canary_detected, canary_failure) = match checks.canary {
        Some(canary) => check_canary(&scans.after, canary),
        None => (false, None),
    };

    let unexplained_count = unexplained.len();
    failures.extend(unexplained);
    if policy.controls.positive_controls.is_empty() {
        failures.push(Failure::NoPositiveControl);
    }
    failures.extend(control_failures);
    failures.extend(canary_failure);

    let status = if failures.is_empty() {
        Status::Clean
    } else {
        Status::Fail
    };
    let counts = Counts {
        candidate: residue.candidate,
        noise_subtracted: residue.noise_subtracted,
        residue: residue.items.len(),
        self_checks,
        explained: explained.len(),
        unexplained: unexplained_count,
    };
    let summary = summarize(status, blind, &counts, failures.len(), &unseen);
    Verdict {
        status,
        blind,
        summary,
        counts,
        failures,
        explained,
        positive_controls: control_results,
        canary_detected,
        unseen,
    }
}

/// One failure per required analysis channel that reported no finding for an
/// image, image by image in [`ImageLabel::ALL`] order, then channel by
/// channel.
fn missing_channels(scans: &Scans) -> Vec<Failure> {
    let mut failures = Vec::new();
    for label in ImageLabel::ALL {
        let findings = scans.image(label);
        for tool in Tool::REQUIRED {
            if !findings.iter().any(|f| f.tool == tool) {
                failures.push(Failure::ChannelMissing {
                    tool,
                    image: label.dir_name().to_string(),
                });
            }
        }
    }
    failures
}

/// Decide the verdict for a real scan: [`verdict`], and the run also fails,
/// blind, for every required analysis channel ([`Tool::REQUIRED`]) that
/// reported nothing for an image. Every such channel finds something on a real
/// image (the restore channel the tree, plaso a file's timestamps,
/// bulk_extractor the canary), so a silent one did not run, failed, or read
/// nothing, and the scan could not look. The Nix store database's rows are
/// held to their database instead: the scan stops when the restore carve holds
/// it and they are missing. A channel that reports did not necessarily read
/// the image, though: plaso still dates an image whose file system it cannot
/// open, as one opaque file at the same path on every image. So
/// `ci/oracle/run-scan.sh` keeps a plaso timeline only when it has an event
/// for the canary's file, and drops the channel otherwise, which this rule
/// then fails. This is the decision the CLI renders.
pub fn scan_verdict(scans: &Scans, policy: &OraclePolicy, catalog: &Catalog) -> Verdict {
    let mut decided = verdict(scans, policy, catalog);
    let missing = missing_channels(scans);
    if !missing.is_empty() {
        decided.blind = true;
        decided.failures.extend(missing);
        decided.status = Status::Fail;
        decided.summary = summarize(
            decided.status,
            decided.blind,
            &decided.counts,
            decided.failures.len(),
            &decided.unseen,
        );
    }
    decided
}
