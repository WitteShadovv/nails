// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Property tests of the verdict engine against expectations the test works
//! out itself.
//!
//! The hand-written suite in [`crate::tests`] pins specific outcomes of
//! [`crate::verdict::verdict`]. This suite drives it over bounded random scans
//! and policies and compares every answer with one computed here, never with
//! another of the engine's own outputs: the test takes the set differences of
//! the images itself, every pool entry below carries a hand-written label
//! saying whether validation must accept it and how far it reaches, and
//! findings are matched with [`locates`], written apart from the engine's
//! locator.
//!
//! - (a) the candidate count is `after − before`, the residue count
//!   `after − before − control`, and the noise subtracted is the candidates
//!   the control cycle also saw;
//! - (b) the residue splits, finding by finding, into the planted self-checks,
//!   the findings a valid entry reaches (each under the citation that reaches
//!   it) and the rest, which are the leaks;
//! - (c) the run reports exactly the expected failures (each rejected entry
//!   and self-check, each leak, no positive control at all, a control or the
//!   canary not detected) and is clean exactly when there are none; and
//! - (d) a world built to be clean comes out clean, and the same world with
//!   one uncoverable finding new in `after` fails with exactly that leak.
//!
//! A random policy nearly always fails on something, so (d) is the property
//! that exercises a clean verdict and the rule that a single leak fails it.

use crate::catalog::{Catalog, CatalogRow};
use crate::model::{
    AllowEntry, Allowlist, Canary, Controls, Finding, OraclePolicy, PositiveControl, Scans, Tool,
};
use crate::verdict::{self, ControlResult, Counts, Failure, Status, Verdict};
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

/// Cases per property: enough to mix the pools while staying fast.
const CASES: u32 = 64;

/// The same small synthetic catalog the unit tests pin down: two path-channel
/// rows, a mechanism row with no channel, and two resolvable doc anchors.
/// [`valid_entries`] cites every row and the first anchor; [`rejected_entries`]
/// cites an id and an anchor the catalog does not have.
fn catalog() -> Catalog {
    Catalog::from_rows(
        [
            CatalogRow {
                id: "var-lib-nixos".into(),
                risk: "rewritten on every boot".into(),
                mitigation: "compare against a control run".into(),
                channel_paths: vec!["/var/lib/nixos".into()],
            },
            CatalogRow {
                id: "timesync-clock".into(),
                risk: "touched at every sync".into(),
                mitigation: "expected info-level residual".into(),
                channel_paths: vec!["/var/lib/systemd/timesync/clock".into()],
            },
            CatalogRow {
                id: "login-boot-records".into(),
                risk: "the way back is recorded".into(),
                mitigation: "power off after the session".into(),
                channel_paths: vec![], // a mechanism row, no channel paths
            },
        ],
        [
            "threat-model.md#residual-channels".into(),
            "threat-model.md#known-residual-changes".into(),
        ],
    )
}

/// The engine's verdict, against [`catalog`].
fn decide(scans: &Scans, policy: &OraclePolicy) -> Verdict {
    verdict::verdict(scans, policy, &catalog())
}

// --- labelled pools ---------------------------------------------------------

/// A file `btrfs restore` recovered at `path`.
fn restore(path: &str) -> Finding {
    Finding::new(Tool::BtrfsRestore, path, "")
}

/// An e-mail address `bulk_extractor` carved.
fn email(address: &str) -> Finding {
    Finding::new(Tool::BulkExtractor, "email", address)
}

/// How far a valid allowlist entry reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// The cited path and everything below it: a path-channel row cited inside
    /// its own channel.
    Subtree,
    /// The exact path only: a mechanism row, a doc anchor or a feature value.
    Leaf,
}

fn entry(path: &str, field: Option<&str>, cite: &str) -> AllowEntry {
    AllowEntry {
        path: path.into(),
        field: field.map(Into::into),
        cite: cite.into(),
        note: None,
    }
}

/// Allowlist entries validation must accept, each labelled with its reach.
fn valid_entries() -> Vec<(AllowEntry, Reach)> {
    vec![
        (
            entry("/var/lib/nixos", None, "var-lib-nixos"),
            Reach::Subtree,
        ),
        (
            entry("/var/lib/systemd/timesync/clock", None, "timesync-clock"),
            Reach::Subtree,
        ),
        (
            entry("/var/log/wtmp.db", None, "login-boot-records"),
            Reach::Leaf,
        ),
        (
            entry("/var/lib/boot-records", None, "login-boot-records"),
            Reach::Leaf,
        ),
        (
            entry(
                "/sys/firmware/efi/efivars/trace",
                None,
                "threat-model.md#residual-channels",
            ),
            Reach::Leaf,
        ),
        (
            entry("email", Some("leak@evil.example"), "login-boot-records"),
            Reach::Leaf,
        ),
    ]
}

/// Allowlist entries validation must reject, one for each rule. Most name a
/// locus over pool findings, so one wrongly accepted would explain what must
/// stay a leak.
fn rejected_entries() -> Vec<AllowEntry> {
    vec![
        // A whole top-level directory.
        entry("/var", None, "var-lib-nixos"),
        // A whole system subtree.
        entry("/var/lib", None, "var-lib-nixos"),
        // Glob wildcards.
        entry("/nix/store/**", None, "var-lib-nixos"),
        // Not a catalog id.
        entry("/var/lib/nixos", None, "no-such-row"),
        // Not a known doc anchor.
        entry("/var/lib/nixos", None, "threat-model.md#invented-section"),
        // Outside the cited row's channel.
        entry("/var/log/lastlog", None, "var-lib-nixos"),
        // An empty citation.
        entry("/var/lib/nixos", None, "  "),
        // A feature type with no value.
        entry("email", None, "login-boot-records"),
    ]
}

fn control(name: &str, tool: Option<Tool>, path: &str, field: Option<&str>) -> PositiveControl {
    PositiveControl {
        name: name.into(),
        tool,
        path: path.into(),
        field: field.map(Into::into),
        note: None,
    }
}

/// Positive controls validation must accept, each with the finding its planted
/// record leaves in `after`.
fn valid_controls() -> Vec<(PositiveControl, Finding)> {
    vec![
        (
            control(
                "wtmpdb-boot",
                Some(Tool::Plaso),
                "/var/log/wtmp.db",
                Some("linux:wtmp:event"),
            ),
            Finding::new(Tool::Plaso, "/var/log/wtmp.db", "linux:wtmp:event"),
        ),
        (
            control(
                "lastlog2",
                Some(Tool::BulkExtractor),
                "email",
                Some("lastlog2@oracle.example"),
            ),
            email("lastlog2@oracle.example"),
        ),
    ]
}

/// Positive controls validation must reject: a whole directory, and an exact
/// path with no value, which would exempt anything seen there.
fn rejected_controls() -> Vec<PositiveControl> {
    vec![
        control("too-broad", None, "/var/log", None),
        control("wtmpdb-loose", Some(Tool::Plaso), "/var/log/wtmp.db", None),
    ]
}

/// The planted coverage canary.
fn canary_finding() -> Finding {
    email("canary@oracle.example")
}

/// The valid canary: the planted marker, pinned to the channel that carves it.
fn valid_canary() -> Canary {
    Canary {
        tool: Some(Tool::BulkExtractor),
        path: "email".into(),
        field: Some("canary@oracle.example".into()),
    }
}

/// Canaries validation must reject: a whole directory, and a feature type with
/// no value.
fn rejected_canaries() -> Vec<Canary> {
    vec![
        Canary {
            tool: None,
            path: "/var/log".into(),
            field: None,
        },
        Canary {
            tool: Some(Tool::BulkExtractor),
            path: "email".into(),
            field: None,
        },
    ]
}

/// Findings no valid entry reaches and no valid self-check matches. Each sits
/// next to something that is covered, so a guard that let one through shows.
fn leak_pool() -> Vec<Finding> {
    vec![
        // Under no entry at all.
        restore("/home/user/secret.txt"),
        // Below a leaf entry rather than at it.
        restore("/var/lib/boot-records/leak.txt"),
        // A string prefix of a channel, not a path below it.
        restore("/var/lib/nixos-old/uid-map"),
        // The cited feature type with another value.
        email("other@evil.example"),
        // The canary's value, carved by a channel the canary does not pin.
        Finding::new(Tool::Plaso, "email", "canary@oracle.example"),
    ]
}

/// The findings the random images draw from: a baseline file, a noise file, a
/// finding each valid entry reaches, the planted self-checks and the leaks.
/// Small, so three images drawn from it overlap and carried baselines,
/// subtracted noise and surviving residue all occur.
fn finding_pool() -> Vec<Finding> {
    let mut pool = vec![
        restore("/etc/hostname"),
        restore("/var/log/lastlog"),
        restore("/var/lib/nixos/declarative-users"),
        restore("/var/lib/systemd/timesync/clock"),
        restore("/var/lib/boot-records"),
        restore("/sys/firmware/efi/efivars/trace"),
        email("leak@evil.example"),
        canary_finding(),
    ];
    pool.extend(valid_controls().into_iter().map(|(_, planted)| planted));
    pool.extend(leak_pool());
    pool
}

// --- the expected verdict ---------------------------------------------------

/// The reach the labels give entry `e`, or `None` when validation must reject
/// it.
fn reach_of(e: &AllowEntry) -> Option<Reach> {
    valid_entries()
        .into_iter()
        .find(|(valid, _)| valid == e)
        .map(|(_, reach)| reach)
}

/// Whether the labels say validation must accept positive control `c`.
fn is_valid_control(c: &PositiveControl) -> bool {
    valid_controls().iter().any(|(valid, _)| valid == c)
}

/// The test's own locator: the tool when one is pinned, the exact path (or,
/// for a subtree, any path below it by whole components), and the value when
/// one is named.
fn locates(tool: Option<Tool>, path: &str, field: Option<&str>, reach: Reach, f: &Finding) -> bool {
    let below = reach == Reach::Subtree
        && f.path
            .strip_prefix(path)
            .is_some_and(|rest| rest.starts_with('/'));
    tool.is_none_or(|t| t == f.tool)
        && (f.path == path || below)
        && field.is_none_or(|value| value == f.field)
}

/// Whether a valid entry with reach `reach` covers `f`; an entry pins no tool.
fn reaches(e: &AllowEntry, reach: Reach, f: &Finding) -> bool {
    locates(None, &e.path, e.field.as_deref(), reach, f)
}

/// The verdict one run must get.
struct Expected {
    /// The reconciling counts.
    counts: Counts,
    /// Each explained finding, with the citation that explains it.
    explained: BTreeMap<Finding, String>,
    /// The residue nothing explains: the leaks.
    leaks: BTreeSet<Finding>,
    /// Every failure, with rejection reasons left empty.
    failures: Vec<Failure>,
    /// Per valid positive control, whether `after` carries it.
    control_results: Vec<ControlResult>,
    /// Whether a valid positive control is missing from `after`.
    blind: bool,
    /// Whether the canary is valid and `after` carries it.
    canary_detected: bool,
}

/// Work out the verdict on `scans` under `policy`: the set differences from the
/// images, validity and reach from the labels, every match from [`locates`].
fn expect(scans: &Scans, policy: &OraclePolicy) -> Expected {
    let candidate: BTreeSet<Finding> = scans.after.difference(&scans.before).cloned().collect();
    let residue: BTreeSet<Finding> = candidate.difference(&scans.control).cloned().collect();
    let controls: Vec<&PositiveControl> = policy
        .controls
        .positive_controls
        .iter()
        .filter(|c| is_valid_control(c))
        .collect();
    let canary = Some(&policy.controls.canary).filter(|c| **c == valid_canary());
    let entries: Vec<(&AllowEntry, Reach)> = policy
        .allowlist
        .entries
        .iter()
        .filter_map(|e| reach_of(e).map(|reach| (e, reach)))
        .collect();

    // A planted self-check comes first; otherwise the first valid entry that
    // reaches a finding explains it, and a finding nothing reaches is a leak.
    let planted = |f: &Finding| {
        controls
            .iter()
            .any(|c| locates(c.tool, &c.path, c.field.as_deref(), Reach::Leaf, f))
            || canary.is_some_and(|c| locates(c.tool, &c.path, c.field.as_deref(), Reach::Leaf, f))
    };
    let mut self_checks = 0;
    let mut explained = BTreeMap::new();
    let mut leaks = BTreeSet::new();
    for f in &residue {
        if planted(f) {
            self_checks += 1;
        } else if let Some((e, _)) = entries.iter().find(|(e, reach)| reaches(e, *reach, f)) {
            explained.insert(f.clone(), e.cite.clone());
        } else {
            leaks.insert(f.clone());
        }
    }

    let in_after = |tool: Option<Tool>, path: &str, field: Option<&str>| {
        scans
            .after
            .iter()
            .any(|f| locates(tool, path, field, Reach::Leaf, f))
    };
    let control_results: Vec<ControlResult> = controls
        .iter()
        .map(|c| ControlResult {
            name: c.name.clone(),
            detected: in_after(c.tool, &c.path, c.field.as_deref()),
        })
        .collect();
    let blind = control_results.iter().any(|r| !r.detected);
    let canary_detected = canary.is_some_and(|c| in_after(c.tool, &c.path, c.field.as_deref()));
    let failures = expected_failures(policy, &leaks, &control_results, canary_detected);
    Expected {
        counts: Counts {
            candidate: candidate.len(),
            noise_subtracted: candidate.intersection(&scans.control).count(),
            residue: residue.len(),
            self_checks,
            explained: explained.len(),
            unexplained: leaks.len(),
        },
        explained,
        leaks,
        failures,
        control_results,
        blind,
        canary_detected,
    }
}

/// Every failure the run must report, with rejection reasons left empty: each
/// rejected entry and self-check, each leak, no positive control at all, each
/// valid control `after` lacks, and a valid canary `after` lacks.
fn expected_failures(
    policy: &OraclePolicy,
    leaks: &BTreeSet<Finding>,
    control_results: &[ControlResult],
    canary_detected: bool,
) -> Vec<Failure> {
    let mut failures: Vec<Failure> = policy
        .allowlist
        .entries
        .iter()
        .filter(|e| reach_of(e).is_none())
        .map(|e| Failure::InvalidAllowlistEntry {
            path: e.path.clone(),
            cite: e.cite.clone(),
            reason: String::new(),
        })
        .collect();
    let controls = &policy.controls.positive_controls;
    failures.extend(controls.iter().filter(|c| !is_valid_control(c)).map(|c| {
        Failure::InvalidPositiveControl {
            name: c.name.clone(),
            path: c.path.clone(),
            reason: String::new(),
        }
    }));
    let canary = &policy.controls.canary;
    let canary_valid = *canary == valid_canary();
    if !canary_valid {
        failures.push(Failure::InvalidCanary {
            path: canary.path.clone(),
            reason: String::new(),
        });
    }
    failures.extend(leaks.iter().map(leak_failure));
    if controls.is_empty() {
        failures.push(Failure::NoPositiveControl);
    }
    failures.extend(control_results.iter().filter(|r| !r.detected).map(|r| {
        Failure::PositiveControlMissing {
            name: r.name.clone(),
        }
    }));
    if canary_valid && !canary_detected {
        failures.push(Failure::CanaryMissing {
            path: canary.path.clone(),
        });
    }
    failures
}

/// The failure a leak of `f` raises.
fn leak_failure(f: &Finding) -> Failure {
    Failure::UnexplainedResidue {
        tool: f.tool,
        path: f.path.clone(),
        field: f.field.clone(),
    }
}

/// The engine's explained findings, each with the citation it gave.
fn reported_explained(v: &Verdict) -> BTreeMap<Finding, String> {
    v.explained
        .iter()
        .map(|e| {
            let finding = Finding::new(e.tool, e.path.clone(), e.field.clone());
            (finding, e.cite.clone())
        })
        .collect()
}

/// The findings the engine's unexplained-residue failures name.
fn reported_leaks(v: &Verdict) -> BTreeSet<Finding> {
    v.failures
        .iter()
        .filter_map(|f| match f {
            Failure::UnexplainedResidue { tool, path, field } => {
                Some(Finding::new(*tool, path.clone(), field.clone()))
            }
            _ => None,
        })
        .collect()
}

/// Failures in a fixed order with every rejection reason emptied, so two lists
/// compare by what failed rather than by order or wording; the unit tests pin
/// the wording.
fn normalized(failures: &[Failure]) -> Vec<String> {
    let mut keys: Vec<String> = failures
        .iter()
        .map(|f| {
            let mut f = f.clone();
            if let Failure::InvalidAllowlistEntry { reason, .. }
            | Failure::InvalidPositiveControl { reason, .. }
            | Failure::InvalidCanary { reason, .. } = &mut f
            {
                reason.clear();
            }
            format!("{f:?}")
        })
        .collect();
    keys.sort();
    keys
}

// --- strategies -------------------------------------------------------------

/// A bounded image drawn from [`finding_pool`].
fn image() -> impl Strategy<Value = BTreeSet<Finding>> {
    prop::collection::vec(prop::sample::select(finding_pool()), 0..=8)
        .prop_map(|findings| findings.into_iter().collect())
}

/// Three independent images from the one small pool, so they overlap.
fn scans_strategy() -> impl Strategy<Value = Scans> {
    (image(), image(), image()).prop_map(|(before, control, after)| Scans {
        before,
        control,
        after,
    })
}

fn policy_from(
    entries: Vec<AllowEntry>,
    positive_controls: Vec<PositiveControl>,
    canary: Canary,
) -> OraclePolicy {
    OraclePolicy {
        allowlist: Allowlist {
            comment: None,
            entries,
        },
        controls: Controls {
            comment: None,
            positive_controls,
            canary,
        },
    }
}

/// A policy drawn from the valid and the rejected pools alike: up to three
/// entries, up to two positive controls (with none, the run fails for having
/// none) and one canary.
fn policy_strategy() -> impl Strategy<Value = OraclePolicy> {
    let entries: Vec<AllowEntry> = valid_entries()
        .into_iter()
        .map(|(e, _)| e)
        .chain(rejected_entries())
        .collect();
    let controls: Vec<PositiveControl> = valid_controls()
        .into_iter()
        .map(|(c, _)| c)
        .chain(rejected_controls())
        .collect();
    let mut canaries = rejected_canaries();
    canaries.push(valid_canary());
    (
        prop::collection::vec(prop::sample::select(entries), 0..=3),
        prop::collection::vec(prop::sample::select(controls), 0..=2),
        prop::sample::select(canaries),
    )
        .prop_map(|(entries, controls, canary)| policy_from(entries, controls, canary))
}

/// A world the verdict must call clean, under a policy of valid parts only: up
/// to three entries, one or two positive controls and the canary. `before` is a
/// baseline of at least one finding, which `after` carries. The control cycle
/// saw some noise, which `after` holds too, and whatever else was drawn.
/// `after` adds findings the drawn entries reach, the canary and each
/// control's planted finding. The canary, planted on every image in a real
/// run, and the controls' findings may also be in the earlier images.
fn clean_world() -> impl Strategy<Value = (Scans, OraclePolicy)> {
    (
        prop::collection::vec(prop::sample::select(finding_pool()), 1..=6),
        image(),
        image(),
        image(),
        prop::collection::vec(prop::sample::select(valid_entries()), 0..=3),
        prop::collection::vec(prop::sample::select(valid_controls()), 1..=2),
        prop::array::uniform2(any::<bool>()),
        prop::array::uniform2(any::<bool>()),
    )
        .prop_map(
            |(baseline, noise, also_seen, drawn, entries, controls, canary_in, planted_in)| {
                let [canary_before, canary_control] = canary_in;
                let [planted_before, planted_control] = planted_in;
                let mut planted: BTreeSet<Finding> =
                    controls.iter().map(|(_, found)| found.clone()).collect();
                let mut before: BTreeSet<Finding> = baseline.into_iter().collect();
                let mut control: BTreeSet<Finding> = noise.union(&also_seen).cloned().collect();
                if planted_before {
                    before.extend(planted.iter().cloned());
                }
                if planted_control {
                    control.extend(planted.iter().cloned());
                }
                if canary_before {
                    before.insert(canary_finding());
                }
                if canary_control {
                    control.insert(canary_finding());
                }
                planted.insert(canary_finding());
                let reached = drawn
                    .into_iter()
                    .filter(|f| entries.iter().any(|(e, reach)| reaches(e, *reach, f)));
                let after = before
                    .iter()
                    .chain(&noise)
                    .cloned()
                    .chain(reached)
                    .chain(planted)
                    .collect();
                let policy = policy_from(
                    entries.into_iter().map(|(e, _)| e).collect(),
                    controls.into_iter().map(|(c, _)| c).collect(),
                    valid_canary(),
                );
                (
                    Scans {
                        before,
                        control,
                        after,
                    },
                    policy,
                )
            },
        )
}

/// `scans` with `leak` new in `after` alone: out of the baseline and the
/// control cycle, so nothing carries it or subtracts it as noise.
fn with_leak(scans: &Scans, leak: &Finding) -> Scans {
    let mut leaky = scans.clone();
    leaky.before.remove(leak);
    leaky.control.remove(leak);
    leaky.after.insert(leak.clone());
    leaky
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(CASES))]

    /// (a) The candidate is `after − before` and the residue
    /// `after − before − control`, both counted here from the images, and the
    /// noise subtracted is the candidates the control cycle also saw.
    #[test]
    fn candidate_and_residue_are_the_set_differences_of_the_images(
        scans in scans_strategy(),
        policy in policy_strategy(),
    ) {
        let v = decide(&scans, &policy);
        let want = expect(&scans, &policy).counts;
        prop_assert_eq!(v.counts.candidate, want.candidate);
        prop_assert_eq!(v.counts.noise_subtracted, want.noise_subtracted);
        prop_assert_eq!(v.counts.residue, want.residue);
    }

    /// (b) The residue splits finding by finding as the labels say: a planted
    /// self-check first, then a finding a valid entry reaches, under the
    /// citation of the first entry that reaches it; everything else is a leak.
    #[test]
    fn residue_splits_into_self_checks_explained_findings_and_leaks(
        scans in scans_strategy(),
        policy in policy_strategy(),
    ) {
        let v = decide(&scans, &policy);
        let want = expect(&scans, &policy);
        prop_assert_eq!(v.counts.self_checks, want.counts.self_checks);
        prop_assert_eq!(v.counts.explained, want.counts.explained);
        prop_assert_eq!(v.counts.unexplained, want.counts.unexplained);
        prop_assert_eq!(reported_explained(&v), want.explained);
        prop_assert_eq!(reported_leaks(&v), want.leaks);
    }

    /// (c) The run reports exactly the expected failures and is clean exactly
    /// when there are none; the per-control results, the blind flag and the
    /// canary flag say what the test sees in `after`.
    #[test]
    fn failures_are_exactly_the_expected_ones_and_clean_means_none(
        scans in scans_strategy(),
        policy in policy_strategy(),
    ) {
        let v = decide(&scans, &policy);
        let want = expect(&scans, &policy);
        prop_assert_eq!(normalized(&v.failures), normalized(&want.failures));
        prop_assert_eq!(v.status == Status::Clean, want.failures.is_empty());
        prop_assert_eq!(&v.positive_controls, &want.control_results);
        prop_assert_eq!(v.blind, want.blind);
        prop_assert_eq!(v.canary_detected, want.canary_detected);
    }

    /// (d) A world built to be clean comes out clean, with the expected counts,
    /// and the same world with one uncoverable finding new in `after` fails
    /// with exactly that leak and nothing else.
    #[test]
    fn a_clean_world_is_clean_and_one_new_leak_fails_it(
        (scans, policy) in clean_world(),
        leak in prop::sample::select(leak_pool()),
    ) {
        let v = decide(&scans, &policy);
        prop_assert_eq!(v.status, Status::Clean, "{:?}", v.failures);
        prop_assert_eq!(v.counts, expect(&scans, &policy).counts);

        let leaky = with_leak(&scans, &leak);
        let v = decide(&leaky, &policy);
        prop_assert_eq!(&v.failures, &[leak_failure(&leak)]);
        prop_assert_eq!(v.status, Status::Fail);
        prop_assert_eq!(v.counts, expect(&leaky, &policy).counts);
    }
}
