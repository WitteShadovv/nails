// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Property tests of the verdict engine against expectations the test works
//! out itself.
//!
//! The hand-written suite in [`crate::tests`] pins specific outcomes of
//! [`crate::verdict::verdict`]. This suite drives it over bounded random scans
//! and policies and compares every answer with one computed here, never with
//! another of the engine's own outputs: the test takes the differences of the
//! images itself, every pool entry below carries a hand-written label saying
//! whether validation must accept it, and findings are matched with
//! [`locates`] and [`reaches`], written apart from the engine's locator.
//!
//! - (a) the candidate count is the changes from `before` to `after` (a
//!   record or feature gained or lost, a restore path whose values differ),
//!   the noise subtracted is the ones the control cycle shows too, and the
//!   residue is the rest;
//! - (b) the residue splits, finding by finding, into the planted self-checks,
//!   the findings a valid entry reaches (each under the citation that reaches
//!   it) and the rest, which are the leaks;
//! - (c) the run reports exactly the expected failures (each rejected entry
//!   and self-check, each leak, no positive control at all, a control
//!   missing or already in the baseline, the canary not detected) and is
//!   clean exactly when there are none; and
//! - (d) a world built to be clean comes out clean, and the same world with
//!   one uncoverable finding new in `after` fails with exactly that leak.
//!
//! A random policy nearly always fails on something, so (d) is the property
//! that exercises a clean verdict and the rule that a single leak fails it.

use crate::catalog::{Catalog, CatalogRow};
use crate::model::{
    AllowEntry, Allowlist, Canary, Change, Controls, Finding, OraclePolicy, PositiveControl, Scans,
    Tool,
};
use crate::verdict::{self, ControlResult, Counts, Failure, Status, Verdict};
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

/// Cases per property: enough to mix the pools while staying fast.
const CASES: u32 = 64;

/// A doc section a residual row points at, and one only a row the overlay must
/// cover points at.
const RESIDUAL_ANCHOR: &str = "threat-model.md#residual-channels";
const LEAK_ANCHOR: &str = "threat-model.md#known-residual-changes";

fn row(id: &str, channel_paths: &[&str], residual: bool, anchor: &str) -> CatalogRow {
    CatalogRow {
        id: id.into(),
        risk: format!("{id} risk"),
        mitigation: format!("{id} mitigation"),
        channel_paths: channel_paths.iter().map(|p| (*p).to_string()).collect(),
        residual,
        doc_anchor: anchor.into(),
    }
}

/// The small synthetic catalog the unit tests pin down: residual path-channel
/// rows, a residual mechanism row with no channel, and a row the overlay must
/// cover. [`valid_entries`] cites the residual rows and anchor;
/// [`rejected_entries`] cites the rest and what the catalog does not have.
fn catalog() -> Catalog {
    Catalog::from_rows([
        row("var-lib-nixos", &["/var/lib/nixos"], false, LEAK_ANCHOR),
        row(
            "timesync-clock",
            &[CLOCK],
            true,
            "decoy-requirements.md#session-time-records",
        ),
        row(
            "timer-stamps",
            &["/var/lib/systemd/timers"],
            true,
            "decoy-requirements.md#session-time-records",
        ),
        row("login-boot-records", &[], true, RESIDUAL_ANCHOR),
    ])
}

/// The engine's verdict, against [`catalog`].
fn decide(scans: &Scans, policy: &OraclePolicy) -> Verdict {
    verdict::verdict(scans, policy, &catalog())
}

// --- labelled pools ---------------------------------------------------------

const CLOCK: &str = "/var/lib/systemd/timesync/clock";
const STAMP: &str = "/var/lib/systemd/timers/stamp-fstrim.timer";
const RECORD: &str = "linux:utmp:event pid=1024-2047";

/// A file `btrfs restore` recovered at `path`.
fn restore(path: &str) -> Finding {
    restore_holding(path, "sha256:0a")
}

/// An entry `btrfs restore` recovered at `path` holding `value`.
fn restore_holding(path: &str, value: &str) -> Finding {
    Finding::new(Tool::BtrfsRestore, path, value)
}

/// An e-mail address `bulk_extractor` carved.
fn email(address: &str) -> Finding {
    Finding::new(Tool::BulkExtractor, "email", address)
}

fn entry(path: &str, field: Option<&str>, cite: &str) -> AllowEntry {
    AllowEntry {
        path: path.into(),
        field: field.map(Into::into),
        cite: cite.into(),
        removed: false,
        note: None,
    }
}

/// Allowlist entries validation must accept: residual citations of exact
/// leaves, one of them for a removal.
fn valid_entries() -> Vec<AllowEntry> {
    vec![
        entry(CLOCK, None, "timesync-clock"),
        entry(STAMP, None, "timer-stamps"),
        entry("/var/log/wtmp.db", None, "login-boot-records"),
        entry("/var/lib/boot-records", None, "login-boot-records"),
        entry("/sys/firmware/efi/efivars/trace", None, RESIDUAL_ANCHOR),
        entry("email", Some("leak@evil.example"), "login-boot-records"),
        entry("/var/log/wtmp", Some(RECORD), "login-boot-records"),
        AllowEntry {
            removed: true,
            ..entry("/var/lib/kept", None, "login-boot-records")
        },
    ]
}

/// Allowlist entries validation must reject, one for each rule. Most name a
/// locus over pool findings, so one wrongly accepted would explain what must
/// stay a leak.
fn rejected_entries() -> Vec<AllowEntry> {
    vec![
        // A whole top-level directory.
        entry("/var", None, "timer-stamps"),
        // A whole system subtree.
        entry("/var/lib", None, "timer-stamps"),
        // Glob wildcards.
        entry("/nix/store/**", None, "timer-stamps"),
        // Not a catalog id.
        entry("/var/lib/kept", None, "no-such-row"),
        // Not a known doc anchor.
        entry("/var/lib/kept", None, "threat-model.md#invented-section"),
        // Outside the cited row's channel.
        entry("/var/log/lastlog", None, "timesync-clock"),
        // An empty citation.
        entry(CLOCK, None, "  "),
        // A feature type with no value.
        entry("email", None, "login-boot-records"),
        // A row the overlay must cover, for the very leak it describes.
        entry("/var/lib/nixos/uid-map", None, "var-lib-nixos"),
        // A section only such rows point at.
        entry("/home/user/secret.txt", None, LEAK_ANCHOR),
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

/// Findings no valid entry reaches and no valid self-check matches, each at a
/// restore path no other pool finding uses. Each sits next to something that is
/// covered, so a guard that let one through shows.
fn leak_pool() -> Vec<Finding> {
    vec![
        // Under no entry at all.
        restore("/home/user/secret.txt"),
        // Below a leaf entry rather than at it.
        restore("/var/lib/boot-records/leak.txt"),
        // Beside a leaf, inside the cited row's channel.
        restore("/var/lib/systemd/timers/stamp-hidden.timer"),
        // A string prefix of a channel, not a path below it.
        restore("/var/lib/nixos-old/uid-map"),
        // The cited feature type with another value.
        email("other@evil.example"),
        // A record of the cited file with another value.
        Finding::new(Tool::Plaso, "/var/log/wtmp", "linux:utmp:event user=hidden"),
        // Plaso's own stat of a file a value-less entry names.
        Finding::new(Tool::Plaso, "/var/log/wtmp.db", "fs:stat"),
        // The canary's value, carved by a channel the canary does not pin.
        Finding::new(Tool::Plaso, "email", "canary@oracle.example"),
    ]
}

/// The findings the random images draw from: a baseline file, a noise file,
/// two contents of one file, a finding each valid entry reaches, the planted
/// self-checks and the leaks. Small, so three images drawn from it overlap and
/// carried baselines, subtracted noise, changes, removals and surviving
/// residue all occur.
fn finding_pool() -> Vec<Finding> {
    let mut pool = vec![
        restore("/etc/hostname"),
        restore("/var/log/lastlog"),
        restore_holding("/etc/shadow", "sha256:11"),
        restore_holding("/etc/shadow", "sha256:22"),
        restore(CLOCK),
        restore_holding(CLOCK, "sha256:cc"),
        restore(STAMP),
        restore("/var/log/wtmp.db"),
        restore("/var/lib/boot-records"),
        restore("/var/lib/kept"),
        restore("/sys/firmware/efi/efivars/trace"),
        email("leak@evil.example"),
        Finding::new(Tool::Plaso, "/var/log/wtmp", RECORD),
        canary_finding(),
    ];
    pool.extend(valid_controls().into_iter().map(|(_, planted)| planted));
    pool.extend(leak_pool());
    pool
}

// --- the expected verdict ---------------------------------------------------

/// Whether the labels say validation must accept entry `e`.
fn is_valid_entry(e: &AllowEntry) -> bool {
    valid_entries().contains(e)
}

/// Whether the labels say validation must accept positive control `c`.
fn is_valid_control(c: &PositiveControl) -> bool {
    valid_controls().iter().any(|(valid, _)| valid == c)
}

/// The test's own locator for a self-check: the tool when one is pinned, the
/// exact path, and the value when one is named.
fn locates(tool: Option<Tool>, path: &str, field: Option<&str>, f: &Finding) -> bool {
    tool.is_none_or(|t| t == f.tool) && f.path == path && field.is_none_or(|v| v == f.field)
}

/// Whether a valid entry reaches a residue finding that changed as `change`:
/// a removal entry only removals and the others only arrivals and changes, at
/// the exact path, with the exact value or, when it names none, the restore
/// channel's entry there.
fn reaches(e: &AllowEntry, f: &Finding, change: Change) -> bool {
    e.removed == (change == Change::Removed)
        && e.path == f.path
        && match &e.field {
            Some(value) => *value == f.field,
            None => f.tool == Tool::BtrfsRestore,
        }
}

/// The values each restore path holds in `image`.
fn restore_values(image: &BTreeSet<Finding>) -> BTreeMap<String, BTreeSet<String>> {
    let mut values: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for f in image.iter().filter(|f| f.tool == Tool::BtrfsRestore) {
        values
            .entry(f.path.clone())
            .or_default()
            .insert(f.field.clone());
    }
    values
}

/// The residue of `scans` with how each finding changed, and the noise count.
/// Records and features are compared one by one; a restore path counts once,
/// as noise when the control cycle holds other values there than `before`,
/// and otherwise by what `after` gained there or, gaining nothing, lost.
fn residue_of(scans: &Scans) -> (BTreeSet<(Finding, Change)>, usize) {
    let mut residue = BTreeSet::new();
    let mut noise = 0;
    let others = |image: &BTreeSet<Finding>| -> BTreeSet<Finding> {
        image
            .iter()
            .filter(|f| f.tool != Tool::BtrfsRestore)
            .cloned()
            .collect()
    };
    let (before, control, after) = (
        others(&scans.before),
        others(&scans.control),
        others(&scans.after),
    );
    for f in after.difference(&before) {
        if control.contains(f) {
            noise += 1;
        } else {
            residue.insert((f.clone(), Change::Added));
        }
    }
    for f in before.difference(&after) {
        if control.contains(f) {
            residue.insert((f.clone(), Change::Removed));
        } else {
            noise += 1;
        }
    }
    let (b, c, a) = (
        restore_values(&scans.before),
        restore_values(&scans.control),
        restore_values(&scans.after),
    );
    let paths: BTreeSet<&String> = b.keys().chain(c.keys()).chain(a.keys()).collect();
    let none = BTreeSet::new();
    for path in paths {
        let vb = b.get(path).unwrap_or(&none);
        let vc = c.get(path).unwrap_or(&none);
        let va = a.get(path).unwrap_or(&none);
        if va == vb {
            continue;
        }
        if vb != vc {
            noise += 1;
            continue;
        }
        let gained: Vec<&String> = va.difference(vb).collect();
        let kind = if vb.is_empty() {
            Change::Added
        } else {
            Change::Changed
        };
        if gained.is_empty() {
            for value in vb.difference(va) {
                residue.insert((restore_holding(path, value), Change::Removed));
            }
        }
        for value in gained {
            residue.insert((restore_holding(path, value), kind));
        }
    }
    (residue, noise)
}

/// The verdict one run must get.
struct Expected {
    /// The reconciling counts.
    counts: Counts,
    /// Each explained finding and change, with the citation that explains it.
    explained: BTreeMap<(Finding, Change), String>,
    /// The residue nothing explains: the leaks.
    leaks: BTreeSet<(Finding, Change)>,
    /// Every failure, with rejection reasons left empty.
    failures: Vec<Failure>,
    /// Per valid positive control, whether it was detected.
    control_results: Vec<ControlResult>,
    /// Whether a valid positive control is not detected.
    blind: bool,
    /// Whether the canary is valid and `after` carries it.
    canary_detected: bool,
}

/// Work out the verdict on `scans` under `policy`: the differences from the
/// images, validity from the labels, every match from [`locates`] and
/// [`reaches`].
fn expect(scans: &Scans, policy: &OraclePolicy) -> Expected {
    let (residue, noise) = residue_of(scans);
    let controls: Vec<&PositiveControl> = policy
        .controls
        .positive_controls
        .iter()
        .filter(|c| is_valid_control(c))
        .collect();
    let canary = Some(&policy.controls.canary).filter(|c| **c == valid_canary());
    let entries: Vec<&AllowEntry> = policy
        .allowlist
        .entries
        .iter()
        .filter(|e| is_valid_entry(e))
        .collect();

    // A planted self-check comes first, never for a removal; otherwise the
    // first valid entry that reaches a finding explains it, and a finding
    // nothing reaches is a leak.
    let planted = |f: &Finding| {
        controls
            .iter()
            .any(|c| locates(c.tool, &c.path, c.field.as_deref(), f))
            || canary.is_some_and(|c| locates(c.tool, &c.path, c.field.as_deref(), f))
    };
    let mut self_checks = 0;
    let mut explained = BTreeMap::new();
    let mut leaks = BTreeSet::new();
    for (f, change) in &residue {
        if *change != Change::Removed && planted(f) {
            self_checks += 1;
        } else if let Some(e) = entries.iter().find(|e| reaches(e, f, *change)) {
            explained.insert((f.clone(), *change), e.cite.clone());
        } else {
            leaks.insert((f.clone(), *change));
        }
    }

    let seen_in = |image: &BTreeSet<Finding>, c: &PositiveControl| {
        image
            .iter()
            .any(|f| locates(c.tool, &c.path, c.field.as_deref(), f))
    };
    let mut control_failures = Vec::new();
    let control_results: Vec<ControlResult> = controls
        .iter()
        .map(|c| {
            let baseline = if seen_in(&scans.before, c) {
                Some("before")
            } else if seen_in(&scans.control, c) {
                Some("control")
            } else {
                None
            };
            let in_after = seen_in(&scans.after, c);
            match baseline {
                Some(image) => control_failures.push(Failure::PositiveControlInBaseline {
                    name: c.name.clone(),
                    image: image.into(),
                }),
                None if !in_after => control_failures.push(Failure::PositiveControlMissing {
                    name: c.name.clone(),
                }),
                None => {}
            }
            ControlResult {
                name: c.name.clone(),
                detected: baseline.is_none() && in_after,
            }
        })
        .collect();
    let blind = control_results.iter().any(|r| !r.detected);
    let canary_detected = canary.is_some_and(|c| {
        scans
            .after
            .iter()
            .any(|f| locates(c.tool, &c.path, c.field.as_deref(), f))
    });
    let failures = expected_failures(policy, &leaks, control_failures, canary_detected);
    Expected {
        counts: Counts {
            candidate: noise + residue.len(),
            noise_subtracted: noise,
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
/// valid control not detected, and a valid canary `after` lacks.
fn expected_failures(
    policy: &OraclePolicy,
    leaks: &BTreeSet<(Finding, Change)>,
    control_failures: Vec<Failure>,
    canary_detected: bool,
) -> Vec<Failure> {
    let mut failures: Vec<Failure> = policy
        .allowlist
        .entries
        .iter()
        .filter(|e| !is_valid_entry(e))
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
    failures.extend(leaks.iter().map(|(f, change)| leak_failure(f, *change)));
    if controls.is_empty() {
        failures.push(Failure::NoPositiveControl);
    }
    failures.extend(control_failures);
    if canary_valid && !canary_detected {
        failures.push(Failure::CanaryMissing {
            path: canary.path.clone(),
        });
    }
    failures
}

/// The failure a leak of `f` that changed as `change` raises.
fn leak_failure(f: &Finding, change: Change) -> Failure {
    Failure::UnexplainedResidue {
        change,
        tool: f.tool,
        path: f.path.clone(),
        field: f.field.clone(),
    }
}

/// The engine's explained findings, each with how it changed and the citation
/// it gave.
fn reported_explained(v: &Verdict) -> BTreeMap<(Finding, Change), String> {
    v.explained
        .iter()
        .map(|e| {
            let finding = Finding::new(e.tool, e.path.clone(), e.field.clone());
            ((finding, e.change), e.cite.clone())
        })
        .collect()
}

/// The findings the engine's unexplained-residue failures name.
fn reported_leaks(v: &Verdict) -> BTreeSet<(Finding, Change)> {
    v.failures
        .iter()
        .filter_map(|f| match f {
            Failure::UnexplainedResidue {
                change,
                tool,
                path,
                field,
            } => Some((Finding::new(*tool, path.clone(), field.clone()), *change)),
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
/// `after` adds findings the drawn arrival entries reach, the canary and each
/// control's planted finding. The canary, planted on every image in a real
/// run, may also be in the earlier images; a control's planted finding never
/// is, or it would prove nothing.
fn clean_world() -> impl Strategy<Value = (Scans, OraclePolicy)> {
    (
        prop::collection::vec(prop::sample::select(finding_pool()), 1..=6),
        image(),
        image(),
        image(),
        prop::collection::vec(prop::sample::select(valid_entries()), 0..=3),
        prop::collection::vec(prop::sample::select(valid_controls()), 1..=2),
        prop::array::uniform2(any::<bool>()),
    )
        .prop_map(
            |(baseline, noise, also_seen, drawn, entries, controls, canary_in)| {
                let [canary_before, canary_control] = canary_in;
                let planted: BTreeSet<Finding> =
                    controls.iter().map(|(_, found)| found.clone()).collect();
                let mut before: BTreeSet<Finding> = baseline.into_iter().collect();
                let mut control: BTreeSet<Finding> = noise.union(&also_seen).cloned().collect();
                before.retain(|f| !planted.contains(f));
                control.retain(|f| !planted.contains(f));
                if canary_before {
                    before.insert(canary_finding());
                }
                if canary_control {
                    control.insert(canary_finding());
                }
                let reached = drawn
                    .into_iter()
                    .filter(|f| entries.iter().any(|e| reaches(e, f, Change::Added)));
                let after = before
                    .iter()
                    .chain(&noise)
                    .cloned()
                    .chain(reached)
                    .chain(planted)
                    .chain([canary_finding()])
                    .collect();
                let policy = policy_from(
                    entries,
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

    /// (a) The candidate count is the changes from `before` to `after`, the
    /// noise subtracted the ones the control cycle shows too and the residue
    /// the rest, all counted here from the images.
    #[test]
    fn candidate_and_residue_are_the_changes_of_the_images(
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
    /// canary flag say what the test sees in the images.
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
        prop_assert_eq!(&v.failures, &[leak_failure(&leak, Change::Added)]);
        prop_assert_eq!(v.status, Status::Fail);
        prop_assert_eq!(v.counts, expect(&leaky, &policy).counts);
    }
}
