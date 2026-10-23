// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Property-test backstop over the verdict engine's reconciliation invariants.
//!
//! The hand-written suite in [`crate::tests`] pins specific outcomes of
//! [`crate::verdict::verdict`]; this suite instead drives it over bounded random
//! scans and policies and asserts the counts always reconcile, whatever the
//! inputs:
//!
//! - (a) the candidate set (`after − before`) splits exactly into the residue
//!   that survives control-cycle subtraction and the noise that is subtracted:
//!   `candidate == residue + noise_subtracted`;
//! - (b) that residue is a disjoint cover of the planted self-checks, the
//!   cited-and-explained findings and the unexplained leaks:
//!   `residue == self_checks + explained + unexplained`; and
//! - (c) a clean verdict is exactly the no-failure state, and an unexplained
//!   leak is always itself a failure, so `Clean` implies an empty failure set,
//!   which implies no unexplained residue.
//!
//! The generators draw from small fixed pools — a handful of findings, catalog
//! citations, positive controls and canaries that line up with the synthetic
//! catalog below — so the three images overlap and every residue partition is
//! reachable, while the case count stays bounded for the normal `cargo test`
//! gate.

use crate::catalog::{Catalog, CatalogRow};
use crate::model::{
    AllowEntry, Allowlist, Canary, Controls, Finding, OraclePolicy, PositiveControl, Scans, Tool,
};
use crate::verdict::{self, Status};
use proptest::prelude::*;
use std::collections::BTreeSet;

/// Cases per property: enough to mix the pools while staying fast.
const CASES: u32 = 64;

/// The same small synthetic catalog the unit tests pin down: two path-channel
/// rows, a mechanism row with no channel, and two resolvable doc anchors. Citing
/// these is what lets a generated allowlist entry land in the `explained`
/// partition rather than being rejected.
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

/// The planted coverage canary, matched by the valid canary config in the pool.
fn canary_finding() -> Finding {
    Finding::new(Tool::BulkExtractor, "email", "canary@oracle.example")
}

/// The planted positive control, matched by the valid control config in the pool.
fn control_finding() -> Finding {
    Finding::new(Tool::Plaso, "/var/log/wtmp.db", "linux:wtmp:event")
}

/// A small pool of findings. It mixes carried baselines, control-cycle noise, an
/// allowlistable residue path, uncitable leaks and the two self-checks, so that
/// three independent images drawn from it overlap and every residue partition is
/// reachable.
fn finding_pool() -> Vec<Finding> {
    vec![
        Finding::new(Tool::BtrfsRestore, "/etc/hostname", ""),
        Finding::new(Tool::BtrfsRestore, "/var/log/lastlog", ""),
        Finding::new(Tool::BtrfsRestore, "/var/lib/nixos/declarative-users", ""),
        Finding::new(Tool::BtrfsRestore, "/var/lib/systemd/timesync/clock", ""),
        Finding::new(Tool::BtrfsRestore, "/home/user/secret.txt", ""),
        Finding::new(Tool::BtrfsRestore, "/var/spool/anacron/cron.daily", ""),
        Finding::new(Tool::BulkExtractor, "email", "leak@evil.example"),
        control_finding(),
        canary_finding(),
    ]
}

/// A pool of candidate allowlist entries: some resolve against the catalog (a
/// subtree channel, a second channel, a mechanism leaf, a specific feature
/// value) and some are rejected (a wholesale directory, a glob, an unknown id),
/// so both the explained partition and the invalid-entry failures are exercised.
fn allow_entry_pool() -> Vec<AllowEntry> {
    vec![
        AllowEntry {
            path: "/var/lib/nixos".into(),
            field: None,
            cite: "var-lib-nixos".into(),
            note: None,
        },
        AllowEntry {
            path: "/var/lib/systemd/timesync/clock".into(),
            field: None,
            cite: "timesync-clock".into(),
            note: None,
        },
        AllowEntry {
            path: "/var/log/wtmp.db".into(),
            field: None,
            cite: "login-boot-records".into(),
            note: None,
        },
        AllowEntry {
            path: "email".into(),
            field: Some("leak@evil.example".into()),
            cite: "login-boot-records".into(),
            note: None,
        },
        AllowEntry {
            path: "/var".into(), // rejected: a wholesale top-level directory
            field: None,
            cite: "var-lib-nixos".into(),
            note: None,
        },
        AllowEntry {
            path: "/nix/store/**".into(), // rejected: glob wildcards
            field: None,
            cite: "var-lib-nixos".into(),
            note: None,
        },
        AllowEntry {
            path: "/var/lib/nixos".into(),
            field: None,
            cite: "no-such-row".into(), // rejected: not a catalog id
            note: None,
        },
    ]
}

/// A pool of positive controls: the valid self-check that matches
/// [`control_finding`], a valid locus whose planted finding is never in the pool
/// (a blind scan whenever it is configured), and a too-broad locus the breadth
/// guard rejects.
fn control_pool() -> Vec<PositiveControl> {
    vec![
        PositiveControl {
            name: "wtmpdb-boot".into(),
            tool: Some(Tool::Plaso),
            path: "/var/log/wtmp.db".into(),
            field: Some("linux:wtmp:event".into()),
            note: None,
        },
        PositiveControl {
            name: "lastlog2".into(),
            tool: Some(Tool::BulkExtractor),
            path: "email".into(),
            field: Some("lastlog2@oracle.example".into()),
            note: None,
        },
        PositiveControl {
            name: "too-broad".into(),
            tool: None,
            path: "/var/log".into(),
            field: None,
            note: None,
        },
    ]
}

/// A pool of canaries: the valid one that matches [`canary_finding`], and a
/// too-broad locus the breadth guard rejects.
fn canary_pool() -> Vec<Canary> {
    vec![
        Canary {
            tool: Some(Tool::BulkExtractor),
            path: "email".into(),
            field: Some("canary@oracle.example".into()),
        },
        Canary {
            tool: None,
            path: "/var/log".into(),
            field: None,
        },
    ]
}

/// A bounded set of findings drawn from [`finding_pool`].
fn finding_set() -> impl Strategy<Value = BTreeSet<Finding>> {
    prop::collection::vec(prop::sample::select(finding_pool()), 0..=6)
        .prop_map(|v| v.into_iter().collect::<BTreeSet<Finding>>())
}

/// Three independent bounded images. Drawing from one small pool makes the
/// before/control/after sets overlap, so carried findings, subtracted noise and
/// surviving residue all occur across the generated cases.
fn scans_strategy() -> impl Strategy<Value = Scans> {
    (finding_set(), finding_set(), finding_set()).prop_map(|(before, control, after)| Scans {
        before,
        control,
        after,
    })
}

/// A bounded allowlist of up to three entries drawn from [`allow_entry_pool`].
fn allowlist_strategy() -> impl Strategy<Value = Allowlist> {
    prop::collection::vec(prop::sample::select(allow_entry_pool()), 0..=3).prop_map(|entries| {
        Allowlist {
            comment: None,
            entries,
        }
    })
}

/// Bounded self-checks: up to two positive controls and one canary from the
/// pools. An empty control list makes the run fail for no positive control, so
/// that branch is covered too.
fn controls_strategy() -> impl Strategy<Value = Controls> {
    (
        prop::collection::vec(prop::sample::select(control_pool()), 0..=2),
        prop::sample::select(canary_pool()),
    )
        .prop_map(|(positive_controls, canary)| Controls {
            comment: None,
            positive_controls,
            canary,
        })
}

/// A bounded policy: a cited allowlist and the scan self-checks.
fn policy_strategy() -> impl Strategy<Value = OraclePolicy> {
    (allowlist_strategy(), controls_strategy()).prop_map(|(allowlist, controls)| OraclePolicy {
        allowlist,
        controls,
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(CASES))]

    /// (a) The candidate set (`after − before`) splits exactly into the residue
    /// that survives control-cycle subtraction and the noise that is subtracted,
    /// so `candidate == residue + noise_subtracted` whatever the three images.
    #[test]
    fn candidate_splits_into_residue_and_subtracted_noise(
        scans in scans_strategy(),
        policy in policy_strategy(),
    ) {
        let counts = verdict::verdict(&scans, &policy, &catalog()).counts;
        prop_assert_eq!(counts.candidate, counts.residue + counts.noise_subtracted);
    }

    /// (b) The residue is a disjoint cover: every surviving finding is counted in
    /// exactly one of the three partitions, so
    /// `residue == self_checks + explained + unexplained`.
    #[test]
    fn residue_is_a_disjoint_cover_of_its_three_partitions(
        scans in scans_strategy(),
        policy in policy_strategy(),
    ) {
        let counts = verdict::verdict(&scans, &policy, &catalog()).counts;
        prop_assert_eq!(
            counts.residue,
            counts.self_checks + counts.explained + counts.unexplained
        );
    }

    /// (c) A clean verdict is exactly the no-failure state, and an unexplained
    /// leak is always itself one of those failures. So `Clean` implies an empty
    /// failure set, which implies no unexplained residue — equivalently, any
    /// unexplained residue keeps the run out of `Clean`.
    #[test]
    fn clean_implies_no_failures_implies_no_unexplained_residue(
        scans in scans_strategy(),
        policy in policy_strategy(),
    ) {
        let v = verdict::verdict(&scans, &policy, &catalog());
        prop_assert_eq!(v.status == Status::Clean, v.failures.is_empty());
        if v.failures.is_empty() {
            prop_assert_eq!(v.counts.unexplained, 0);
        }
        if v.counts.unexplained > 0 {
            prop_assert_eq!(v.status, Status::Fail);
        }
    }
}
