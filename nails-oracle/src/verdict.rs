// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The verdict engine: the component that decides "oracle clean".
//!
//! Given the three normalized scans and the policy, it:
//!
//! 1. validates the allowlist — every entry cites exactly one real catalog row
//!    or threat-model anchor and names a specific location, never a wholesale
//!    `/var`, `/nix` or `/home` tree; only a path-channel citation may exempt a
//!    whole subtree, a mechanism or anchor citation only its exact leaf; a
//!    broken allowlist never yields a clean verdict;
//! 2. computes the noise-subtracted residue `after − before − control`: a
//!    difference that also shows up in the clean control cycle is scan noise,
//!    not a trace of the hidden session;
//! 3. partitions that residue into the planted self-checks, the cited-and-
//!    explained, and the unexplained (each unexplained finding is a leak);
//! 4. checks the scan is not blind — every positive control names a concrete
//!    planted artifact (an exact path and value, never a directory) and is
//!    detected in `after`, and there is at least one to check; and
//! 5. checks the coverage canary, validated the same way, is detected.
//!
//! The run is [`Status::Clean`] only when all five hold. Everything here is a
//! pure function of its inputs, so the whole engine is unit-tested in
//! [`crate::tests`] over synthetic findings.

use crate::catalog::Catalog;
use crate::model::{
    AllowEntry, Canary, Controls, Finding, OraclePolicy, PositiveControl, Scans, Tool,
};
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
        /// The tool that surfaced the leak.
        tool: Tool,
        /// Where it was seen.
        path: String,
        /// What was seen there.
        field: String,
    },
    /// A planted positive control was not detected in `after`: the scan is
    /// blind, so no "no residue" claim can be trusted.
    PositiveControlMissing {
        /// The control's name.
        name: String,
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
}

/// A residue finding that a cited allowlist entry explains, with the cited
/// row's own words for why it is expected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Explained {
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
    /// Whether `after` carried it.
    pub detected: bool,
}

/// The reconciling counts. `residue == self_checks + explained + unexplained`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Counts {
    /// Findings new in `after` versus `before`.
    pub candidate: usize,
    /// Of those, the ones also present in the control cycle (scan noise).
    pub noise_subtracted: usize,
    /// The noise-subtracted residue: `after − before − control`.
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
    /// Whether a positive control was missing (a blind scan). Set independently
    /// of `status` so a blind run reads unmistakably.
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

/// Whether allowlist/locator path `pat` covers finding path `p`: equal, or
/// `pat` is an ancestor directory of `p`. Component-aware, so `/var/lib/nix`
/// never spuriously covers `/var/lib/nixos`. Crate-visible for its own tests.
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

/// Whether a finding matches a `(tool, path, field)` locator. `subtree` chooses
/// how `path` matches: `true` covers the locus and everything beneath it (a
/// path-channel allowlist entry), `false` demands the exact path (a concrete
/// leaf: a mechanism/anchor allowlist entry, or a positive control or canary).
fn locator_matches(
    tool: Option<Tool>,
    path: &str,
    field: Option<&str>,
    f: &Finding,
    subtree: bool,
) -> bool {
    if let Some(t) = tool
        && t != f.tool
    {
        return false;
    }
    let path_ok = if subtree {
        path_covers(path, &f.path)
    } else {
        path == f.path
    };
    if !path_ok {
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
    // A bare word is a bulk_extractor feature type; its breadth is enforced by
    // requiring a specific `field` in `entry_reject_reason`, not here.
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

/// How a validated allowlist entry matches findings: whether its citation lets
/// it vouch for a whole subtree or only for the exact leaf it names.
#[derive(Clone, Copy)]
enum Coverage {
    /// Backed by a path-channel row whose channel covers the locus: the entry
    /// covers that locus and everything beneath it.
    Subtree,
    /// Backed by a mechanism row, a doc anchor, or a feature type: the entry
    /// vouches only for the exact concrete leaf it names, never a subtree, so a
    /// path-less citation can never wholesale-exempt a directory.
    Leaf,
}

/// Validate one allowlist entry against the catalog, returning how it is allowed
/// to match on success, or the reason it is rejected.
fn entry_reject_reason(entry: &AllowEntry, catalog: &Catalog) -> Result<Coverage, String> {
    let cite = entry.cite.trim();
    if cite.is_empty() {
        return Err("empty citation".to_string());
    }
    let is_feature = !entry.path.starts_with('/');
    if is_feature && entry.field.as_deref().unwrap_or("").is_empty() {
        return Err("a feature allowlist must name a specific value in `field`".to_string());
    }
    if let Some(reason) = breadth_reason(&entry.path) {
        return Err(reason);
    }
    if cite.contains('#') {
        if !catalog.anchor_exists(cite) {
            return Err(format!("`{cite}` is not a known residue doc section"));
        }
        // A doc anchor names no channel, so it vouches only for the exact locus.
        return Ok(Coverage::Leaf);
    }
    let Some(row) = catalog.row(cite) else {
        return Err(format!("`{cite}` is not a residue-catalog id"));
    };
    // A feature type is matched exactly by type and value, and a mechanism row
    // (no channel paths) is not pinned to any path: neither may vouch for more
    // than the exact concrete leaf cited, closing the wholesale-subtree hole.
    if is_feature || row.channel_paths.is_empty() {
        return Ok(Coverage::Leaf);
    }
    // A path-channel row vouches only within its own channel; citing it for a
    // path outside that channel is rejected. Inside the channel it may cover the
    // cited locus and everything beneath it.
    let within = row
        .channel_paths
        .iter()
        .any(|c| path_covers(c, &entry.path));
    if !within {
        return Err(format!(
            "path is outside the channel of `{cite}` ({})",
            row.channel_paths.join(", ")
        ));
    }
    Ok(Coverage::Subtree)
}

/// A validated allowlist entry together with how it is allowed to match.
struct ValidEntry<'a> {
    entry: &'a AllowEntry,
    coverage: Coverage,
}

/// Split the allowlist into the entries that pass validation (each with its
/// coverage) and a failure per entry that does not.
fn validate_allowlist<'a>(
    entries: &'a [AllowEntry],
    catalog: &Catalog,
) -> (Vec<ValidEntry<'a>>, Vec<Failure>) {
    let mut valid = Vec::new();
    let mut failures = Vec::new();
    for entry in entries {
        match entry_reject_reason(entry, catalog) {
            Ok(coverage) => valid.push(ValidEntry { entry, coverage }),
            Err(reason) => failures.push(Failure::InvalidAllowlistEntry {
                path: entry.path.clone(),
                cite: entry.cite.clone(),
                reason,
            }),
        }
    }
    (valid, failures)
}

/// The noise-subtracted residue (`after − before − control`), with the
/// candidate (`after − before`) and the noise counts.
fn compute_residue(scans: &Scans) -> (Vec<&Finding>, usize, usize) {
    let mut residue = Vec::new();
    let mut candidate = 0;
    for f in &scans.after {
        if scans.before.contains(f) {
            continue;
        }
        candidate += 1;
        if !scans.control.contains(f) {
            residue.push(f);
        }
    }
    let noise_subtracted = candidate - residue.len();
    (residue, candidate, noise_subtracted)
}

/// Whether any finding in `set` matches the `(tool, path, field)` locator. Used
/// to detect positive controls and the canary, which are concrete leaves, so
/// the path must match exactly.
fn any_match(set: &BTreeSet<Finding>, tool: Option<Tool>, path: &str, field: Option<&str>) -> bool {
    set.iter()
        .any(|f| locator_matches(tool, path, field, f, false))
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
        && locator_matches(canary.tool, &canary.path, canary.field.as_deref(), f, false)
    {
        return true;
    }
    for c in &checks.positive_controls {
        if locator_matches(c.tool, &c.path, c.field.as_deref(), f, false) {
            return true;
        }
    }
    false
}

/// Whether a validated allowlist entry covers a finding, matching a subtree or
/// an exact leaf according to its coverage.
fn entry_covers(e: &ValidEntry, f: &Finding) -> bool {
    let subtree = matches!(e.coverage, Coverage::Subtree);
    locator_matches(None, &e.entry.path, e.entry.field.as_deref(), f, subtree)
}

/// Partition the residue into self-checks, explained and unexplained.
fn partition_residue(
    residue: &[&Finding],
    valid: &[ValidEntry],
    checks: &ValidSelfChecks,
    catalog: &Catalog,
) -> (Vec<Explained>, Vec<Failure>, usize) {
    let mut explained = Vec::new();
    let mut unexplained = Vec::new();
    let mut self_checks = 0;
    for &f in residue {
        if is_self_check(f, checks) {
            self_checks += 1;
            continue;
        }
        match valid.iter().find(|e| entry_covers(e, f)) {
            Some(e) => explained.push(explain(f, &e.entry.cite, catalog)),
            None => unexplained.push(Failure::UnexplainedResidue {
                tool: f.tool,
                path: f.path.clone(),
                field: f.field.clone(),
            }),
        }
    }
    (explained, unexplained, self_checks)
}

/// Build the explanation for a finding a cited entry covers.
fn explain(f: &Finding, cite: &str, catalog: &Catalog) -> Explained {
    let (risk, mitigation) = match catalog.row(cite) {
        Some(row) => (row.risk.clone(), row.mitigation.clone()),
        None => (String::new(), String::new()),
    };
    Explained {
        tool: f.tool,
        path: f.path.clone(),
        field: f.field.clone(),
        cite: cite.to_string(),
        risk,
        mitigation,
    }
}

/// Check every validated positive control is detected in `after`. Returns the
/// per-control results, a failure per missing control, and whether the scan is
/// blind. The "at least one control" rule is enforced in [`verdict`] over the
/// configured list, so a rejected control is not miscounted as none configured.
fn check_controls(
    after: &BTreeSet<Finding>,
    controls: &[&PositiveControl],
) -> (Vec<ControlResult>, Vec<Failure>, bool) {
    let mut results = Vec::new();
    let mut failures = Vec::new();
    let mut blind = false;
    for c in controls {
        let detected = any_match(after, c.tool, &c.path, c.field.as_deref());
        if !detected {
            failures.push(Failure::PositiveControlMissing {
                name: c.name.clone(),
            });
            blind = true;
        }
        results.push(ControlResult {
            name: c.name.clone(),
            detected,
        });
    }
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

/// Render the one-line human summary.
fn summarize(status: Status, blind: bool, counts: &Counts, failures: usize) -> String {
    if status == Status::Clean {
        return format!(
            "CLEAN: {} residue ({} noise subtracted, {} cited, {} self-check)",
            counts.residue, counts.noise_subtracted, counts.explained, counts.self_checks
        );
    }
    let marker = if blind { " (BLIND)" } else { "" };
    format!(
        "FAIL{marker}: {failures} failure(s), {} of {} residue unexplained",
        counts.unexplained, counts.residue
    )
}

/// Decide the verdict for one oracle run. Pure: the whole decision is a
/// function of the scans, the policy and the catalog.
pub fn verdict(scans: &Scans, policy: &OraclePolicy, catalog: &Catalog) -> Verdict {
    let (valid, mut failures) = validate_allowlist(&policy.allowlist.entries, catalog);
    let (checks, self_check_failures) = validate_self_checks(&policy.controls);
    failures.extend(self_check_failures);

    let (residue, candidate, noise_subtracted) = compute_residue(scans);
    let (explained, unexplained, self_checks) =
        partition_residue(&residue, &valid, &checks, catalog);
    let (control_results, control_failures, blind) =
        check_controls(&scans.after, &checks.positive_controls);
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
        candidate,
        noise_subtracted,
        residue: residue.len(),
        self_checks,
        explained: explained.len(),
        unexplained: unexplained_count,
    };
    let summary = summarize(status, blind, &counts, failures.len());
    Verdict {
        status,
        blind,
        summary,
        counts,
        failures,
        explained,
        positive_controls: control_results,
        canary_detected,
    }
}
