// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The verdict engine's unit tests, over synthetic normalized findings.
//!
//! Every test builds findings by hand — no files, no real catalog — so each
//! asserts a real outcome of the decision logic: a clean pass only on noise and
//! cited differences, a fail on an uncited leak, a rejected wholesale or
//! uncitable allowlist, a blind-fail on a missing positive control, a fail on a
//! missing canary, and that control noise is actually subtracted.

use crate::catalog::{Catalog, CatalogRow};
use crate::model::{
    AllowEntry, Allowlist, Canary, Controls, Finding, OraclePolicy, PositiveControl, Scans, Tool,
};
use crate::verdict::{self, Failure, Status, Verdict, breadth_reason, path_covers};
use std::collections::BTreeSet;

// --- synthetic fixtures -----------------------------------------------------

/// A small catalog: a path-channel row, a second path-channel row, a mechanism
/// row with no channel, and two resolvable doc anchors.
fn catalog() -> Catalog {
    Catalog::from_rows(
        [
            CatalogRow {
                id: "var-lib-nixos".into(),
                risk: "the decoy rewrites these files on every boot".into(),
                mitigation: "compare against a control run".into(),
                channel_paths: vec!["/var/lib/nixos".into()],
            },
            CatalogRow {
                id: "timesync-clock".into(),
                risk: "timesyncd touches it at every sync".into(),
                mitigation: "expected info-level residual".into(),
                channel_paths: vec!["/var/lib/systemd/timesync/clock".into()],
            },
            CatalogRow {
                id: "login-boot-records".into(),
                risk: "the decoy's own writers record the way back".into(),
                mitigation: "power off after the session".into(),
                channel_paths: vec![], // a Channel::Mechanism row
            },
        ],
        [
            "threat-model.md#residual-channels".into(),
            "threat-model.md#known-residual-changes".into(),
        ],
    )
}

fn restore(path: &str) -> Finding {
    Finding::new(Tool::BtrfsRestore, path, "")
}

/// The coverage canary: a planted e-mail feature on every image.
fn canary_finding() -> Finding {
    Finding::new(Tool::BulkExtractor, "email", "canary@oracle.example")
}

fn canary_cfg() -> Canary {
    Canary {
        tool: Some(Tool::BulkExtractor),
        path: "email".into(),
        field: Some("canary@oracle.example".into()),
    }
}

/// A positive control: a planted wtmpdb boot row, read back by plaso. It pins
/// the exact event value plaso reads back, so it names a concrete planted
/// artifact — the only kind a valid self-check may be.
fn control_finding() -> Finding {
    Finding::new(Tool::Plaso, "/var/log/wtmp.db", "linux:wtmp:event")
}

fn control_cfg() -> PositiveControl {
    PositiveControl {
        name: "wtmpdb-boot".into(),
        tool: Some(Tool::Plaso),
        path: "/var/log/wtmp.db".into(),
        field: Some("linux:wtmp:event".into()),
        note: None,
    }
}

fn set(items: impl IntoIterator<Item = Finding>) -> BTreeSet<Finding> {
    items.into_iter().collect()
}

fn entry(path: &str, cite: &str) -> AllowEntry {
    AllowEntry {
        path: path.into(),
        field: None,
        cite: cite.into(),
        note: None,
    }
}

fn allow(entries: Vec<AllowEntry>) -> Allowlist {
    Allowlist {
        comment: None,
        entries,
    }
}

fn controls(positive: Vec<PositiveControl>) -> Controls {
    Controls {
        comment: None,
        positive_controls: positive,
        canary: canary_cfg(),
    }
}

/// A world that comes out CLEAN: baseline `/etc/hostname` and the canary on
/// every image; a noise file in control and after; an allowlisted residue file
/// and the positive control new in after.
fn clean_scans() -> Scans {
    let base = restore("/etc/hostname");
    let noise = restore("/var/log/lastlog");
    let allowed = restore("/var/lib/nixos/declarative-users");
    Scans {
        before: set([base.clone(), canary_finding()]),
        control: set([base.clone(), canary_finding(), noise.clone()]),
        after: set([base, canary_finding(), noise, allowed, control_finding()]),
    }
}

fn clean_policy() -> OraclePolicy {
    OraclePolicy {
        allowlist: allow(vec![entry("/var/lib/nixos", "var-lib-nixos")]),
        controls: controls(vec![control_cfg()]),
    }
}

fn decide(scans: &Scans, policy: &OraclePolicy) -> Verdict {
    verdict::verdict(scans, policy, &catalog())
}

fn has_unexplained(v: &Verdict, path: &str) -> bool {
    v.failures
        .iter()
        .any(|f| matches!(f, Failure::UnexplainedResidue { path: p, .. } if p == path))
}

fn control_missing(v: &Verdict, name: &str) -> bool {
    v.failures
        .iter()
        .any(|f| matches!(f, Failure::PositiveControlMissing { name: n } if n == name))
}

fn invalid_reasons(v: &Verdict) -> Vec<String> {
    let mut reasons = Vec::new();
    for f in &v.failures {
        if let Failure::InvalidAllowlistEntry { reason, .. } = f {
            reasons.push(reason.clone());
        }
    }
    reasons
}

/// Whether some allowlist entry was rejected with a reason containing `needle`.
fn rejected_for(v: &Verdict, needle: &str) -> bool {
    invalid_reasons(v).iter().any(|r| r.contains(needle))
}

/// Whether a positive control named `name` was rejected as an invalid locus.
fn invalid_control(v: &Verdict, name: &str) -> bool {
    v.failures
        .iter()
        .any(|f| matches!(f, Failure::InvalidPositiveControl { name: n, .. } if n == name))
}

/// The rejection reason for the named positive control, if it was rejected.
fn invalid_control_reason(v: &Verdict, name: &str) -> Option<String> {
    v.failures.iter().find_map(|f| match f {
        Failure::InvalidPositiveControl {
            name: n, reason, ..
        } if n == name => Some(reason.clone()),
        _ => None,
    })
}

/// Whether the coverage canary's locus was rejected as invalid.
fn invalid_canary(v: &Verdict) -> bool {
    v.failures
        .iter()
        .any(|f| matches!(f, Failure::InvalidCanary { .. }))
}

// --- the clean baseline -----------------------------------------------------

#[test]
fn clean_when_differences_are_noise_or_cited() {
    let v = decide(&clean_scans(), &clean_policy());
    assert_eq!(v.status, Status::Clean, "{:?}", v.failures);
    assert!(v.failures.is_empty());
    assert!(!v.blind);
    assert!(v.canary_detected);
    // after−before = {noise, allowed, control}; noise is in control, so residue
    // = {allowed, control}; control is a self-check, allowed is cited.
    assert_eq!(v.counts.candidate, 3);
    assert_eq!(v.counts.noise_subtracted, 1);
    assert_eq!(v.counts.residue, 2);
    assert_eq!(v.counts.self_checks, 1);
    assert_eq!(v.counts.explained, 1);
    assert_eq!(v.counts.unexplained, 0);
    assert_eq!(v.explained.len(), 1);
    assert_eq!(v.explained[0].cite, "var-lib-nixos");
    assert_eq!(v.explained[0].path, "/var/lib/nixos/declarative-users");
    assert!(
        !v.explained[0].risk.is_empty(),
        "the cited row's risk is printed"
    );
    assert_eq!(v.positive_controls.len(), 1);
    assert_eq!(v.positive_controls[0].name, "wtmpdb-boot");
    assert!(v.positive_controls[0].detected);
}

// --- a leak -----------------------------------------------------------------

#[test]
fn fail_on_an_uncited_difference() {
    let mut scans = clean_scans();
    scans.after.insert(restore("/home/user/secret.txt"));
    let v = decide(&scans, &clean_policy());
    assert_eq!(v.status, Status::Fail);
    assert!(has_unexplained(&v, "/home/user/secret.txt"));
    assert_eq!(v.counts.unexplained, 1);
    // The cited and the self-check are still accounted for, not swept up.
    assert_eq!(v.counts.explained, 1);
    assert_eq!(v.counts.self_checks, 1);
}

// --- control-noise subtraction is load-bearing ------------------------------

#[test]
fn control_noise_is_subtracted_and_its_absence_flips_the_verdict() {
    // The same unexplained file: when it is in the control cycle it is noise
    // (clean); when it is not, it is residue (fail). Nothing else changes.
    let leaky = restore("/var/spool/anacron/cron.daily");

    let mut noisy = clean_scans();
    noisy.control.insert(leaky.clone());
    noisy.after.insert(leaky.clone());
    let v = decide(&noisy, &clean_policy());
    assert_eq!(
        v.status,
        Status::Clean,
        "subtracted as noise: {:?}",
        v.failures
    );
    assert!(!has_unexplained(&v, "/var/spool/anacron/cron.daily"));

    let mut only_after = clean_scans();
    only_after.after.insert(leaky);
    let v = decide(&only_after, &clean_policy());
    assert_eq!(v.status, Status::Fail, "not in control, so a real leak");
    assert!(has_unexplained(&v, "/var/spool/anacron/cron.daily"));
}

// --- the wholesale / uncitable allowlist is rejected ------------------------

#[test]
fn reject_a_wholesale_top_level_allowlist() {
    let policy = OraclePolicy {
        allowlist: allow(vec![entry("/var", "var-lib-nixos")]),
        controls: controls(vec![control_cfg()]),
    };
    let v = decide(&clean_scans(), &policy);
    assert_eq!(v.status, Status::Fail);
    assert!(rejected_for(&v, "top-level directory"), "{v:?}");
}

#[test]
fn reject_a_wholesale_system_subtree() {
    for path in ["/var/lib", "/nix/store"] {
        let policy = OraclePolicy {
            allowlist: allow(vec![entry(path, "var-lib-nixos")]),
            controls: controls(vec![control_cfg()]),
        };
        let v = decide(&clean_scans(), &policy);
        assert_eq!(v.status, Status::Fail, "{path}");
        assert!(rejected_for(&v, "subtree"), "{path}: {v:?}");
    }
}

#[test]
fn reject_a_glob_allowlist() {
    let policy = OraclePolicy {
        allowlist: allow(vec![entry("/nix/store/**", "var-lib-nixos")]),
        controls: controls(vec![control_cfg()]),
    };
    let v = decide(&clean_scans(), &policy);
    assert_eq!(v.status, Status::Fail);
    assert!(rejected_for(&v, "glob"), "{v:?}");
}

#[test]
fn reject_an_uncitable_allowlist() {
    // A specific /nix/store path is uncitable: no catalog row covers the store,
    // so there is nothing to name — and the store must be scanned, not skipped.
    let policy = OraclePolicy {
        allowlist: allow(vec![entry(
            "/nix/store/abc123-hidden-generation",
            "no-such-row",
        )]),
        controls: controls(vec![control_cfg()]),
    };
    let v = decide(&clean_scans(), &policy);
    assert_eq!(v.status, Status::Fail);
    assert!(rejected_for(&v, "not a residue-catalog id"), "{v:?}");
}

#[test]
fn reject_an_empty_citation() {
    let policy = OraclePolicy {
        allowlist: allow(vec![entry("/var/lib/nixos", "   ")]),
        controls: controls(vec![control_cfg()]),
    };
    let v = decide(&clean_scans(), &policy);
    assert_eq!(v.status, Status::Fail);
    assert!(rejected_for(&v, "empty citation"), "{v:?}");
}

// --- a citation only vouches for its own channel ----------------------------

#[test]
fn a_path_channel_citation_is_confined_to_its_channel() {
    // var-lib-nixos covers /var/lib/nixos, not an unrelated /var/log path.
    let policy = OraclePolicy {
        allowlist: allow(vec![entry("/var/log/evil.log", "var-lib-nixos")]),
        controls: controls(vec![control_cfg()]),
    };
    let v = decide(&clean_scans(), &policy);
    assert_eq!(v.status, Status::Fail);
    assert!(rejected_for(&v, "outside the channel"), "{v:?}");
}

#[test]
fn a_mechanism_row_vouches_for_its_cited_path() {
    // login-boot-records is a mechanism row (no channel paths); it may be cited
    // for a specific record path. The plaso control and the restore file at the
    // same path are told apart by tool: one is the self-check, one is cited.
    let mut scans = clean_scans();
    scans.after.insert(restore("/var/log/wtmp.db"));
    let policy = OraclePolicy {
        allowlist: allow(vec![
            entry("/var/lib/nixos", "var-lib-nixos"),
            entry("/var/log/wtmp.db", "login-boot-records"),
        ]),
        controls: controls(vec![control_cfg()]),
    };
    let v = decide(&scans, &policy);
    assert_eq!(v.status, Status::Clean, "{:?}", v.failures);
    let cited = v
        .explained
        .iter()
        .find(|e| e.path == "/var/log/wtmp.db")
        .unwrap();
    assert_eq!(cited.cite, "login-boot-records");
}

// --- doc-anchor citations ---------------------------------------------------

#[test]
fn a_resolvable_doc_anchor_citation_explains_a_residual_path() {
    let mut scans = clean_scans();
    scans
        .after
        .insert(restore("/sys/firmware/efi/efivars/trace"));
    let policy = OraclePolicy {
        allowlist: allow(vec![
            entry("/var/lib/nixos", "var-lib-nixos"),
            // a residual channel with no catalog id, cited by its section
            entry(
                "/sys/firmware/efi/efivars/trace",
                "threat-model.md#residual-channels",
            ),
        ]),
        controls: controls(vec![control_cfg()]),
    };
    let v = decide(&scans, &policy);
    assert_eq!(v.status, Status::Clean, "{:?}", v.failures);
    let anchor = v.explained.iter().find(|e| e.cite.contains('#')).unwrap();
    assert!(
        anchor.risk.is_empty(),
        "a doc-anchor citation carries no row text"
    );
}

#[test]
fn an_unresolvable_doc_anchor_is_rejected() {
    let policy = OraclePolicy {
        allowlist: allow(vec![entry(
            "/var/lib/nixos",
            "threat-model.md#invented-section",
        )]),
        controls: controls(vec![control_cfg()]),
    };
    let v = decide(&clean_scans(), &policy);
    assert_eq!(v.status, Status::Fail);
    assert!(rejected_for(&v, "not a known residue doc section"), "{v:?}");
}

// --- the scan self-checks ---------------------------------------------------

#[test]
fn fail_blind_when_a_positive_control_is_missing() {
    let mut scans = clean_scans();
    scans.after.remove(&control_finding());
    let v = decide(&scans, &clean_policy());
    assert_eq!(v.status, Status::Fail);
    assert!(v.blind, "a missing positive control means a blind scan");
    assert!(control_missing(&v, "wtmpdb-boot"));
    assert!(!v.positive_controls[0].detected);
}

#[test]
fn a_positive_control_is_expected_residue_not_a_leak() {
    // Only the control is new in after; no allowlist. It must not be counted as
    // an unexplained leak, and the run is clean.
    let scans = Scans {
        before: set([canary_finding()]),
        control: set([canary_finding()]),
        after: set([canary_finding(), control_finding()]),
    };
    let policy = OraclePolicy {
        allowlist: allow(vec![]),
        controls: controls(vec![control_cfg()]),
    };
    let v = decide(&scans, &policy);
    assert_eq!(v.status, Status::Clean, "{:?}", v.failures);
    assert_eq!(v.counts.residue, 1);
    assert_eq!(v.counts.self_checks, 1);
    assert_eq!(v.counts.unexplained, 0);
    assert_eq!(v.counts.explained, 0);
}

#[test]
fn fail_when_no_positive_control_is_configured() {
    // Nothing else wrong: empty residue, canary present — still a fail, because
    // a run with no blindness check cannot prove it sees residue.
    let scans = Scans {
        before: set([canary_finding()]),
        control: set([canary_finding()]),
        after: set([canary_finding()]),
    };
    let policy = OraclePolicy {
        allowlist: allow(vec![]),
        controls: controls(vec![]),
    };
    let v = decide(&scans, &policy);
    assert_eq!(v.status, Status::Fail);
    assert_eq!(v.failures, [Failure::NoPositiveControl]);
    assert!(v.canary_detected);
}

#[test]
fn fail_when_the_canary_is_missing() {
    let mut scans = clean_scans();
    scans.after.remove(&canary_finding());
    let v = decide(&scans, &clean_policy());
    assert_eq!(v.status, Status::Fail);
    assert!(!v.canary_detected);
    assert!(
        v.failures
            .iter()
            .any(|f| matches!(f, Failure::CanaryMissing { .. }))
    );
}

// --- feature (bulk_extractor) allowlisting ----------------------------------

#[test]
fn a_feature_allowlist_must_name_a_specific_value() {
    let policy = OraclePolicy {
        allowlist: allow(vec![AllowEntry {
            path: "email".into(),
            field: None,
            cite: "login-boot-records".into(),
            note: None,
        }]),
        controls: controls(vec![control_cfg()]),
    };
    let v = decide(&clean_scans(), &policy);
    assert_eq!(v.status, Status::Fail);
    assert!(rejected_for(&v, "specific value"), "{v:?}");
}

#[test]
fn a_specific_feature_value_can_be_cited() {
    let leak = Finding::new(Tool::BulkExtractor, "email", "leak@evil.example");
    let mut scans = clean_scans();
    scans.after.insert(leak);
    let policy = OraclePolicy {
        allowlist: allow(vec![
            entry("/var/lib/nixos", "var-lib-nixos"),
            AllowEntry {
                path: "email".into(),
                field: Some("leak@evil.example".into()),
                cite: "login-boot-records".into(),
                note: None,
            },
        ]),
        controls: controls(vec![control_cfg()]),
    };
    let v = decide(&scans, &policy);
    assert_eq!(v.status, Status::Clean, "{:?}", v.failures);
    assert!(v.explained.iter().any(|e| e.field == "leak@evil.example"));
    // A different, uncited feature value would still fail.
    let mut scans2 = clean_scans();
    scans2.after.insert(Finding::new(
        Tool::BulkExtractor,
        "email",
        "other@evil.example",
    ));
    let v2 = decide(&scans2, &clean_policy());
    assert_eq!(v2.status, Status::Fail);
}

// --- the path and breadth guards, directly ----------------------------------

#[test]
fn path_covers_is_component_aware() {
    assert!(path_covers("/var/lib/nixos", "/var/lib/nixos"));
    assert!(path_covers("/var/lib/nixos", "/var/lib/nixos/uid-map"));
    assert!(
        !path_covers("/var/lib/nix", "/var/lib/nixos"),
        "a prefix is not a parent"
    );
    assert!(!path_covers("/var/lib/nixos/uid-map", "/var/lib/nixos"));
    assert!(path_covers("email", "email"));
    assert!(!path_covers("email", "emailx"));
    assert!(!path_covers("email", "/var/log"));
}

#[test]
fn breadth_reason_rejects_broad_paths_only() {
    assert!(breadth_reason("/var").is_some());
    assert!(breadth_reason("/nix").is_some());
    assert!(breadth_reason("/").is_some());
    assert!(breadth_reason("/var/lib").is_some());
    assert!(breadth_reason("/nix/store").is_some());
    assert!(breadth_reason("/nix/store/**").is_some());
    // User-data and mount roots are as off-limits wholesale as the system ones.
    assert!(breadth_reason("/home").is_some());
    assert!(breadth_reason("/home/user").is_some());
    assert!(breadth_reason("/root").is_some());
    assert!(breadth_reason("/mnt/usb").is_some());
    assert!(breadth_reason("/media/disk").is_some());
    assert!(breadth_reason("/var/lib/nixos").is_none());
    assert!(breadth_reason("/var/log/wtmp.db").is_none());
    assert!(breadth_reason("/var/lib/systemd/timesync/clock").is_none());
    // A feature type carries no slash; its breadth is the field requirement.
    assert!(breadth_reason("email").is_none());
}

#[test]
fn path_covers_rejects_an_empty_pattern() {
    // An empty pattern names nothing, so it must cover no absolute path: the
    // cross-absoluteness guard (one side absolute, the other not) returns false
    // rather than letting "" slip through as a universal prefix.
    assert!(!path_covers("", "/foo"));
    assert!(!path_covers("", "/var/lib/nixos"));
    // Equal empty strings are still trivially equal.
    assert!(path_covers("", ""));
}

#[test]
fn path_covers_needs_a_strictly_longer_child() {
    // A pattern only covers a path that is equal or strictly longer with a '/'
    // boundary. Two distinct same-length absolute paths cover neither: the
    // length must be strictly greater, not merely equal.
    assert!(!path_covers("/var/lib/nix", "/var/lib/niy"));
    assert!(!path_covers("/aaa", "/bbb"));
    assert!(path_covers("/var/lib/nix", "/var/lib/nix/x"));
}

#[test]
fn breadth_reason_allows_a_two_segment_non_system_path() {
    // Only the enumerated SYSTEM_ROOTS reject a two-segment path as a whole
    // subtree; a two-segment path under an unlisted top-level directory is
    // specific enough to allowlist.
    assert!(breadth_reason("/data/app").is_none());
    assert!(breadth_reason("/custom/store").is_none());
    // A listed system root at two segments is still rejected, for contrast.
    assert!(breadth_reason("/var/lib").is_some());
}

#[test]
fn is_clean_tracks_the_status() {
    let clean = decide(&clean_scans(), &clean_policy());
    assert_eq!(clean.status, Status::Clean);
    assert!(clean.is_clean(), "a clean verdict reads as clean");

    let mut scans = clean_scans();
    scans.after.insert(restore("/home/user/secret.txt"));
    let failed = decide(&scans, &clean_policy());
    assert_eq!(failed.status, Status::Fail);
    assert!(
        !failed.is_clean(),
        "a failing verdict does not read as clean"
    );
}

#[test]
fn exit_code_is_zero_only_when_clean() {
    let clean = decide(&clean_scans(), &clean_policy());
    assert_eq!(clean.exit_code(), 0, "a clean run exits 0");

    let mut scans = clean_scans();
    scans.after.insert(restore("/home/user/secret.txt"));
    let failed = decide(&scans, &clean_policy());
    assert_eq!(failed.exit_code(), 1, "a failing run exits 1");
}

#[test]
fn summary_renders_the_clean_and_fail_lines() {
    // The one-line summary is a human-facing contract: a clean run names its
    // reconciled residue counts, a failing run is marked FAIL with the
    // unexplained count. This pins the branch and the rendered content.
    let clean = decide(&clean_scans(), &clean_policy());
    assert_eq!(
        clean.summary,
        "CLEAN: 2 residue (1 noise subtracted, 1 cited, 1 self-check)"
    );

    let mut scans = clean_scans();
    scans.after.insert(restore("/home/user/secret.txt"));
    let failed = decide(&scans, &clean_policy());
    assert!(
        failed.summary.starts_with("FAIL"),
        "a failing run is marked FAIL: {}",
        failed.summary
    );
    assert!(
        failed.summary.contains("1 of 3 residue unexplained"),
        "the fail line names the unexplained count: {}",
        failed.summary
    );
}

#[test]
fn timesync_clock_is_citable_within_its_own_channel() {
    // A second path-channel row, to be sure the containment check is per-row.
    let mut scans = clean_scans();
    scans
        .after
        .insert(restore("/var/lib/systemd/timesync/clock"));
    let policy = OraclePolicy {
        allowlist: allow(vec![
            entry("/var/lib/nixos", "var-lib-nixos"),
            entry("/var/lib/systemd/timesync/clock", "timesync-clock"),
        ]),
        controls: controls(vec![control_cfg()]),
    };
    let v = decide(&scans, &policy);
    assert_eq!(v.status, Status::Clean, "{:?}", v.failures);
    // Citing timesync-clock for the nixos path would be out of channel.
    let bad = OraclePolicy {
        allowlist: allow(vec![entry("/var/lib/nixos", "timesync-clock")]),
        controls: controls(vec![control_cfg()]),
    };
    assert_eq!(decide(&clean_scans(), &bad).status, Status::Fail);
}

// --- false-clean hole 1: a path-less citation must not exempt a subtree -------

#[test]
fn a_mechanism_cite_for_a_whole_home_account_is_rejected_by_the_breadth_guard() {
    // /home/user names a whole account, so the breadth guard rejects this locus
    // outright (home is a user-data SYSTEM_ROOT) before the login-boot-records
    // mechanism cite is ever consulted: the path-less citation can never
    // wholesale-exempt the subtree. The leak beneath the locus surfaces as
    // unexplained residue, while the valid path-channel cite stays explained.
    // Leaf coverage for a locus that clears the breadth guard is exercised by
    // the sibling test below.
    let mut scans = clean_scans();
    scans.after.insert(restore("/home/user/secret.txt"));
    let policy = OraclePolicy {
        allowlist: allow(vec![
            entry("/var/lib/nixos", "var-lib-nixos"),
            entry("/home/user", "login-boot-records"),
        ]),
        controls: controls(vec![control_cfg()]),
    };
    let v = decide(&scans, &policy);
    assert_eq!(v.status, Status::Fail, "{:?}", v.failures);
    assert!(has_unexplained(&v, "/home/user/secret.txt"));
    assert!(rejected_for(&v, "subtree"), "{v:?}");
    assert!(
        v.explained
            .iter()
            .any(|e| e.path == "/var/lib/nixos/declarative-users")
    );
}

#[test]
fn a_mechanism_cite_explains_its_exact_leaf_but_not_a_deeper_subtree() {
    // Even a locus deep enough to clear the breadth guard must not become a
    // subtree exemption when cited by a mechanism row: the entry explains only
    // the exact path it names, and a sibling leak beneath it stays unexplained.
    let mut scans = clean_scans();
    scans.after.insert(restore("/var/lib/boot-records"));
    scans
        .after
        .insert(restore("/var/lib/boot-records/leak.txt"));
    let policy = OraclePolicy {
        allowlist: allow(vec![
            entry("/var/lib/nixos", "var-lib-nixos"),
            entry("/var/lib/boot-records", "login-boot-records"),
        ]),
        controls: controls(vec![control_cfg()]),
    };
    let v = decide(&scans, &policy);
    assert_eq!(v.status, Status::Fail, "{:?}", v.failures);
    assert!(
        v.explained
            .iter()
            .any(|e| e.path == "/var/lib/boot-records")
    );
    assert!(has_unexplained(&v, "/var/lib/boot-records/leak.txt"));
}

// --- false-clean hole 2: an ungated self-check must not blanket-exempt --------

#[test]
fn an_invalid_control_locus_fails_and_no_longer_exempts_its_subtree() {
    // A positive control naming a whole directory with no value would absorb ALL
    // residue beneath it as counted self-checks. It must be rejected by the same
    // breadth guard as the allowlist, and the residue it used to swallow must
    // resurface as a leak. A valid control alongside it keeps the run from
    // merely failing blind / no-control.
    let mut scans = clean_scans();
    scans.after.insert(restore("/var/log/hidden-session.log"));
    let bad = PositiveControl {
        name: "logs".into(),
        tool: None,
        path: "/var/log".into(),
        field: None,
        note: None,
    };
    let policy = OraclePolicy {
        allowlist: allow(vec![entry("/var/lib/nixos", "var-lib-nixos")]),
        controls: controls(vec![control_cfg(), bad]),
    };
    let v = decide(&scans, &policy);
    assert_eq!(v.status, Status::Fail, "{:?}", v.failures);
    assert!(invalid_control(&v, "logs"), "{v:?}");
    assert!(has_unexplained(&v, "/var/log/hidden-session.log"));
}

#[test]
fn a_control_with_a_concrete_path_but_no_value_is_rejected() {
    // The breadth guard alone is not enough: a control must pin an exact value,
    // or it would exempt any value seen at its exact path. This is why the
    // shared control fixture names a field.
    let loose = PositiveControl {
        name: "wtmpdb-loose".into(),
        tool: Some(Tool::Plaso),
        path: "/var/log/wtmp.db".into(),
        field: None,
        note: None,
    };
    let policy = OraclePolicy {
        allowlist: allow(vec![entry("/var/lib/nixos", "var-lib-nixos")]),
        controls: controls(vec![control_cfg(), loose]),
    };
    let v = decide(&clean_scans(), &policy);
    assert_eq!(v.status, Status::Fail, "{:?}", v.failures);
    let reason = invalid_control_reason(&v, "wtmpdb-loose").expect("rejected");
    assert!(reason.contains("exact value"), "{reason}");
}

#[test]
fn a_valid_concrete_control_is_detected_and_clean() {
    // The positive half of hole 2: a control naming an exact path AND value is
    // detected, exempts exactly its own planted residue, and the run is clean
    // when nothing else leaks.
    let scans = Scans {
        before: set([canary_finding()]),
        control: set([canary_finding()]),
        after: set([canary_finding(), control_finding()]),
    };
    let policy = OraclePolicy {
        allowlist: allow(vec![]),
        controls: controls(vec![control_cfg()]),
    };
    let v = decide(&scans, &policy);
    assert_eq!(v.status, Status::Clean, "{:?}", v.failures);
    assert!(v.positive_controls[0].detected);
    assert_eq!(v.counts.self_checks, 1);
    assert_eq!(v.counts.unexplained, 0);
}

#[test]
fn an_invalid_canary_locus_fails_the_run() {
    // The canary runs through the same guard: a directory / value-less canary
    // locus is rejected, so it can neither falsely prove coverage nor mask
    // residue beneath it.
    let policy = OraclePolicy {
        allowlist: allow(vec![entry("/var/lib/nixos", "var-lib-nixos")]),
        controls: Controls {
            comment: None,
            positive_controls: vec![control_cfg()],
            canary: Canary {
                tool: None,
                path: "/var/log".into(),
                field: None,
            },
        },
    };
    let v = decide(&clean_scans(), &policy);
    assert_eq!(v.status, Status::Fail, "{:?}", v.failures);
    assert!(invalid_canary(&v), "{v:?}");
    assert!(!v.canary_detected);
}
