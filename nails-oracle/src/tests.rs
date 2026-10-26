// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The verdict engine's unit tests, over synthetic normalized findings.
//!
//! Every test builds findings by hand — no files, no real catalog — so each
//! asserts a real outcome of the decision logic: a clean pass only on noise and
//! cited differences, a fail on an uncited leak (new, changed or removed), a
//! rejected wholesale, uncitable or non-residual allowlist, a blind-fail on a
//! missing positive control or one the baseline already carries, a fail on a
//! missing canary, a blind-fail on a channel that reported nothing for an
//! image, that control noise is actually subtracted, and that every verdict
//! names what it cannot see.

use crate::catalog::{Catalog, CatalogRow};
use crate::model::{
    AllowEntry, Allowlist, Canary, Change, Controls, Finding, OraclePolicy, PositiveControl, Scans,
    Tool,
};
use crate::nix_db::NIX_DB_PATH;
use crate::unseen::Unseen;
use crate::verdict::{self, Failure, Status, Verdict, breadth_reason, path_covers};
use std::collections::BTreeSet;

// --- synthetic fixtures -----------------------------------------------------

/// The residual-channels section, which a residual row points at.
const RESIDUAL_ANCHOR: &str = "threat-model.md#residual-channels";
/// A section only a row the overlay must cover points at.
const LEAK_ANCHOR: &str = "threat-model.md#known-residual-changes";

fn row(id: &str, risk: &str, channel_paths: &[&str], residual: bool, anchor: &str) -> CatalogRow {
    CatalogRow {
        id: id.into(),
        risk: risk.into(),
        mitigation: format!("{id} mitigation"),
        channel_paths: channel_paths.iter().map(|p| (*p).to_string()).collect(),
        residual,
        doc_anchor: anchor.into(),
    }
}

/// A small catalog: two residual path-channel rows, a residual mechanism row
/// with no channel, and a path-channel row the overlay must cover (not
/// residual), each with its doc section.
fn catalog() -> Catalog {
    Catalog::from_rows([
        row(
            "var-lib-nixos",
            "a hidden switch that reached the decoy would record hidden users",
            &["/var/lib/nixos"],
            false,
            LEAK_ANCHOR,
        ),
        row(
            "timesync-clock",
            "timesyncd touches it at every sync",
            &["/var/lib/systemd/timesync/clock"],
            true,
            "decoy-requirements.md#session-time-records",
        ),
        row(
            "timer-stamps",
            "persistent timers stamp their last run",
            &["/var/lib/systemd/timers"],
            true,
            "decoy-requirements.md#session-time-records",
        ),
        row(
            "login-boot-records",
            "the decoy's own writers record the way back",
            &[], // a Channel::Mechanism row
            true,
            RESIDUAL_ANCHOR,
        ),
    ])
}

/// The timesync clock path, the residual leaf the clean world cites.
const CLOCK: &str = "/var/lib/systemd/timesync/clock";

/// A restored file at `path`.
fn restore(path: &str) -> Finding {
    restore_holding(path, "sha256:0a")
}

/// A restored entry at `path` holding `value` (a digest, `dir`, ...).
fn restore_holding(path: &str, value: &str) -> Finding {
    Finding::new(Tool::BtrfsRestore, path, value)
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
        removed: false,
        note: None,
    }
}

fn entry_for(path: &str, field: &str, cite: &str) -> AllowEntry {
    AllowEntry {
        field: Some(field.into()),
        ..entry(path, cite)
    }
}

fn removal_entry(path: &str, cite: &str) -> AllowEntry {
    AllowEntry {
        removed: true,
        ..entry(path, cite)
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
/// (the timesync clock) and the positive control new in after.
fn clean_scans() -> Scans {
    let base = restore("/etc/hostname");
    let noise = restore("/var/log/lastlog");
    let allowed = restore(CLOCK);
    Scans {
        before: set([base.clone(), canary_finding()]),
        control: set([base.clone(), canary_finding(), noise.clone()]),
        after: set([base, canary_finding(), noise, allowed, control_finding()]),
    }
}

fn clean_policy() -> OraclePolicy {
    policy_with(vec![entry(CLOCK, "timesync-clock")])
}

/// The clean world's controls with `entries` as the allowlist.
fn policy_with(entries: Vec<AllowEntry>) -> OraclePolicy {
    OraclePolicy {
        allowlist: allow(entries),
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

/// The unexplained residue at `path` with how it changed and what was seen.
fn unexplained_at(v: &Verdict, path: &str) -> Vec<(Change, String)> {
    v.failures
        .iter()
        .filter_map(|f| match f {
            Failure::UnexplainedResidue {
                change,
                path: p,
                field,
                ..
            } if p == path => Some((*change, field.clone())),
            _ => None,
        })
        .collect()
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

/// The files a reboot rewrites that the verdict names as unseen.
fn reboot_rewritten(v: &Verdict) -> Vec<&str> {
    v.unseen
        .iter()
        .find_map(|class| match class {
            Unseen::RebootRewritten { paths } => Some(paths.iter().map(String::as_str).collect()),
            _ => None,
        })
        .expect("every verdict names the files a reboot rewrites")
}

/// A `ValidPaths` row of the Nix store database registering `store_path`.
fn store_row(store_path: &str) -> Finding {
    Finding::new(
        Tool::NixDb,
        NIX_DB_PATH,
        format!("ValidPaths hash=sha256:00 narSize=1 path={store_path}"),
    )
}

/// The clean world with the Nix store database on every image: the file holds
/// another digest on each, as each start of the oracle's decoy VMs rewrites
/// it, and its one row registers the decoy's own store path on each.
fn scans_with_store_database() -> Scans {
    let mut scans = clean_scans();
    for (image, digest) in [
        (&mut scans.before, "sha256:11"),
        (&mut scans.control, "sha256:22"),
        (&mut scans.after, "sha256:33"),
    ] {
        image.insert(restore_holding(NIX_DB_PATH, digest));
        image.insert(store_row("/nix/store/aaaa-decoy-system"));
    }
    scans
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
    assert_eq!(v.explained[0].cite, "timesync-clock");
    assert_eq!(v.explained[0].path, CLOCK);
    assert_eq!(v.explained[0].change, Change::Added);
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

// --- what the session changed in place or removed --------------------------

#[test]
fn a_file_the_session_rewrote_in_place_is_a_change() {
    // /etc/shadow holds the same digest in before and the control cycle, and
    // another in after: a plain reboot leaves it alone, the session did not.
    let shadow = |digest: &str| restore_holding("/etc/shadow", digest);
    let mut scans = clean_scans();
    scans.before.insert(shadow("sha256:11"));
    scans.control.insert(shadow("sha256:11"));
    scans.after.insert(shadow("sha256:22"));
    let v = decide(&scans, &clean_policy());
    assert_eq!(v.status, Status::Fail);
    assert_eq!(
        unexplained_at(&v, "/etc/shadow"),
        [(Change::Changed, "sha256:22".to_string())]
    );
    // One change, not an addition and a removal.
    assert_eq!(v.counts.residue, 3);
    assert_eq!(v.counts.candidate, 4);
}

#[test]
fn a_file_a_plain_reboot_rewrites_too_is_noise() {
    // random-seed differs on every image: the control cycle shows a reboot
    // rewrites it, so after's new digest is noise, as is after holding the
    // control cycle's digest. Only the new digest is content the verdict could
    // not judge, so only then does it name the file as unseen.
    let seed_path = "/var/lib/systemd/random-seed";
    for (after_digest, unseen) in [("sha256:33", vec![seed_path]), ("sha256:22", vec![])] {
        let seed = |digest: &str| restore_holding(seed_path, digest);
        let mut scans = clean_scans();
        scans.before.insert(seed("sha256:11"));
        scans.control.insert(seed("sha256:22"));
        scans.after.insert(seed(after_digest));
        let v = decide(&scans, &clean_policy());
        assert_eq!(v.status, Status::Clean, "{after_digest}: {:?}", v.failures);
        assert_eq!(v.counts.noise_subtracted, 2, "{after_digest}");
        assert_eq!(reboot_rewritten(&v), unseen, "{after_digest}");
    }
}

#[test]
fn a_path_the_control_cycle_made_differently_is_noise() {
    // Absent from before, made by the control cycle with one content and by
    // the session's cycle with another: a plain reboot makes this path, so
    // its content is boot noise here.
    let mut scans = clean_scans();
    scans
        .control
        .insert(restore_holding("/var/log/lastlog2", "sha256:11"));
    scans
        .after
        .insert(restore_holding("/var/log/lastlog2", "sha256:22"));
    let v = decide(&scans, &clean_policy());
    assert_eq!(v.status, Status::Clean, "{:?}", v.failures);
}

#[test]
fn an_entry_the_session_removed_is_residue_and_a_reboot_removal_is_noise() {
    let temproots = restore_holding("/nix/var/nix/temproots", "dir");
    let mut kept_by_reboot = clean_scans();
    kept_by_reboot.before.insert(temproots.clone());
    kept_by_reboot.control.insert(temproots.clone());
    let v = decide(&kept_by_reboot, &clean_policy());
    assert_eq!(v.status, Status::Fail);
    assert_eq!(
        unexplained_at(&v, "/nix/var/nix/temproots"),
        [(Change::Removed, "dir".to_string())]
    );

    let mut gone_on_reboot = clean_scans();
    gone_on_reboot.before.insert(temproots);
    let v = decide(&gone_on_reboot, &clean_policy());
    assert_eq!(v.status, Status::Clean, "{:?}", v.failures);
    assert_eq!(v.counts.noise_subtracted, 2);
}

#[test]
fn a_record_the_session_removed_is_residue() {
    // A login record in before and the control cycle that after lacks: wtmp
    // was cut, and records are compared one by one, not as one file value.
    let record = Finding::new(
        Tool::Plaso,
        "/var/log/wtmp",
        "linux:utmp:event pid=512-1023",
    );
    let mut scans = clean_scans();
    scans.before.insert(record.clone());
    scans.control.insert(record.clone());
    let v = decide(&scans, &clean_policy());
    assert_eq!(
        unexplained_at(&v, "/var/log/wtmp"),
        [(Change::Removed, record.field.clone())]
    );

    // The control cycle lost it too: noise.
    let mut scans = clean_scans();
    scans.before.insert(record);
    assert_eq!(decide(&scans, &clean_policy()).status, Status::Clean);
}

// --- the Nix store database, which the oracle's decoys rewrite at a start --

#[test]
fn a_store_path_the_session_registered_is_residue_though_a_reboot_rewrites_the_database() {
    // The database file holds another digest on every image, so the restore
    // channel subtracts its change as noise; its rows are compared one by
    // one, and a row new in after alone is residue.
    let mut scans = scans_with_store_database();
    let clean = decide(&scans, &clean_policy());
    assert_eq!(clean.status, Status::Clean, "{:?}", clean.failures);

    let hidden = store_row("/nix/store/bbbb-hidden-package");
    scans.after.insert(hidden.clone());
    let v = decide(&scans, &clean_policy());
    assert_eq!(v.status, Status::Fail);
    assert_eq!(
        unexplained_at(&v, NIX_DB_PATH),
        [(Change::Added, hidden.field.clone())]
    );
    assert!(
        v.failures.contains(&Failure::UnexplainedResidue {
            change: Change::Added,
            tool: Tool::NixDb,
            path: NIX_DB_PATH.into(),
            field: hidden.field,
        }),
        "{:?}",
        v.failures
    );
}

#[test]
fn a_store_path_a_plain_reboot_registers_too_is_noise() {
    let mut scans = scans_with_store_database();
    let booted = store_row("/nix/store/cccc-registered-at-boot");
    scans.control.insert(booted.clone());
    scans.after.insert(booted);
    let v = decide(&scans, &clean_policy());
    assert_eq!(v.status, Status::Clean, "{:?}", v.failures);
    // The rewritten file and the row the control cycle registered as well.
    assert_eq!(v.counts.noise_subtracted, 3);
}

#[test]
fn a_store_path_the_session_removed_is_residue() {
    let mut scans = scans_with_store_database();
    let decoy = store_row("/nix/store/aaaa-decoy-system");
    scans.after.remove(&decoy);
    let v = decide(&scans, &clean_policy());
    assert_eq!(v.status, Status::Fail);
    assert_eq!(
        unexplained_at(&v, NIX_DB_PATH),
        [(Change::Removed, decoy.field)]
    );
}

#[test]
fn a_removal_is_cited_only_by_an_entry_for_removals() {
    let mut scans = clean_scans();
    scans
        .before
        .insert(restore("/var/lib/systemd/timers/stamp-old.timer"));
    scans
        .control
        .insert(restore("/var/lib/systemd/timers/stamp-old.timer"));
    let stamp = "/var/lib/systemd/timers/stamp-old.timer";

    let arrival = policy_with(vec![
        entry(CLOCK, "timesync-clock"),
        entry(stamp, "timer-stamps"),
    ]);
    let v = decide(&scans, &arrival);
    assert_eq!(
        v.status,
        Status::Fail,
        "an arrival entry never covers a removal"
    );
    assert!(has_unexplained(&v, stamp));

    let removal = policy_with(vec![
        entry(CLOCK, "timesync-clock"),
        removal_entry(stamp, "timer-stamps"),
    ]);
    let v = decide(&scans, &removal);
    assert_eq!(v.status, Status::Clean, "{:?}", v.failures);
    let cited = v.explained.iter().find(|e| e.path == stamp).expect("cited");
    assert_eq!(cited.change, Change::Removed);

    // And a removal entry never covers the arrival of the same path.
    let only_removal = policy_with(vec![removal_entry(CLOCK, "timesync-clock")]);
    let v = decide(&clean_scans(), &only_removal);
    assert!(has_unexplained(&v, CLOCK), "{:?}", v.failures);
}

#[test]
fn a_removed_self_check_is_a_leak_not_a_self_check() {
    // Every self-check is planted on after: one missing from it is never
    // counted as its own planted residue.
    let mut scans = clean_scans();
    scans.after.remove(&canary_finding());
    let v = decide(&scans, &clean_policy());
    assert!(!v.canary_detected);
    assert_eq!(
        unexplained_at(&v, "email"),
        [(Change::Removed, "canary@oracle.example".to_string())]
    );
    assert_eq!(v.counts.self_checks, 1);
}

#[test]
fn a_residue_failure_says_how_the_finding_changed() {
    let failure = Failure::UnexplainedResidue {
        change: Change::Removed,
        tool: Tool::BtrfsRestore,
        path: "/nix/var/nix/temproots".into(),
        field: "dir".into(),
    };
    let json = serde_json::to_value(&failure).expect("serializes");
    assert_eq!(json["kind"], "unexplained_residue");
    assert_eq!(json["change"], "removed");
    assert_eq!(json["tool"], "btrfs_restore");
}

#[test]
fn the_counts_reconcile_over_every_kind_of_change() {
    let mut scans = clean_scans();
    // Changed, removed and added residue, and one of each kind of noise.
    for (image, finding) in [
        ("b", restore_holding("/etc/shadow", "sha256:11")),
        ("c", restore_holding("/etc/shadow", "sha256:11")),
        ("a", restore_holding("/etc/shadow", "sha256:22")),
        ("b", restore("/var/lib/kept")),
        ("c", restore("/var/lib/kept")),
        ("a", restore("/home/user/new")),
        (
            "b",
            restore_holding("/var/lib/systemd/random-seed", "sha256:1"),
        ),
        (
            "c",
            restore_holding("/var/lib/systemd/random-seed", "sha256:2"),
        ),
        (
            "a",
            restore_holding("/var/lib/systemd/random-seed", "sha256:3"),
        ),
        ("b", Finding::new(Tool::Plaso, "/var/log/wtmp", "boot")),
    ] {
        match image {
            "b" => scans.before.insert(finding),
            "c" => scans.control.insert(finding),
            _ => scans.after.insert(finding),
        };
    }
    let v = decide(&scans, &clean_policy());
    let c = v.counts;
    assert_eq!(c.candidate, c.noise_subtracted + c.residue);
    assert_eq!(c.residue, c.self_checks + c.explained + c.unexplained);
    assert_eq!(c.unexplained, 3, "{:?}", v.failures);
    // The lastlog noise, the random-seed rewrite and the wtmp record the
    // control cycle lost as well.
    assert_eq!(c.noise_subtracted, 3);
}

// --- the wholesale / uncitable allowlist is rejected ------------------------

#[test]
fn reject_a_wholesale_top_level_allowlist() {
    let v = decide(
        &clean_scans(),
        &policy_with(vec![entry("/var", "timer-stamps")]),
    );
    assert_eq!(v.status, Status::Fail);
    assert!(rejected_for(&v, "top-level directory"), "{v:?}");
}

#[test]
fn reject_a_wholesale_system_subtree() {
    for path in ["/var/lib", "/nix/store"] {
        let v = decide(
            &clean_scans(),
            &policy_with(vec![entry(path, "timer-stamps")]),
        );
        assert_eq!(v.status, Status::Fail, "{path}");
        assert!(rejected_for(&v, "subtree"), "{path}: {v:?}");
    }
}

#[test]
fn reject_a_glob_allowlist() {
    let v = decide(
        &clean_scans(),
        &policy_with(vec![entry("/nix/store/**", "timer-stamps")]),
    );
    assert_eq!(v.status, Status::Fail);
    assert!(rejected_for(&v, "glob"), "{v:?}");
}

#[test]
fn reject_an_uncitable_allowlist() {
    // A specific /nix/store path is uncitable: no catalog row covers the store,
    // so there is nothing to name — and the store must be scanned, not skipped.
    let v = decide(
        &clean_scans(),
        &policy_with(vec![entry(
            "/nix/store/abc123-hidden-generation",
            "no-such-row",
        )]),
    );
    assert_eq!(v.status, Status::Fail);
    assert!(rejected_for(&v, "not a residue-catalog id"), "{v:?}");
}

#[test]
fn reject_an_empty_citation() {
    let v = decide(&clean_scans(), &policy_with(vec![entry(CLOCK, "   ")]));
    assert_eq!(v.status, Status::Fail);
    assert!(rejected_for(&v, "empty citation"), "{v:?}");
}

// --- only a residual row explains a difference -----------------------------

#[test]
fn a_row_the_overlay_must_cover_cannot_excuse_its_own_leak() {
    // var-lib-nixos describes the leak of hidden users into the decoy's
    // /var/lib/nixos. Citing it for a new file there would print the leak's
    // own description as its excuse: the entry is rejected and the file stays
    // a leak.
    let mut scans = clean_scans();
    scans
        .after
        .insert(restore("/var/lib/nixos/declarative-users"));
    let v = decide(
        &scans,
        &policy_with(vec![
            entry(CLOCK, "timesync-clock"),
            entry("/var/lib/nixos/declarative-users", "var-lib-nixos"),
        ]),
    );
    assert_eq!(v.status, Status::Fail);
    assert!(rejected_for(&v, "not a residual row"), "{v:?}");
    assert!(has_unexplained(&v, "/var/lib/nixos/declarative-users"));
    assert!(v.explained.iter().all(|e| e.cite != "var-lib-nixos"));
}

#[test]
fn a_doc_section_only_leak_rows_point_at_cannot_excuse_anything() {
    let mut scans = clean_scans();
    scans.after.insert(restore("/var/lib/nixos/uid-map"));
    let v = decide(
        &scans,
        &policy_with(vec![
            entry(CLOCK, "timesync-clock"),
            entry("/var/lib/nixos/uid-map", LEAK_ANCHOR),
        ]),
    );
    assert_eq!(v.status, Status::Fail);
    assert!(rejected_for(&v, "never a residual trace"), "{v:?}");
    assert!(has_unexplained(&v, "/var/lib/nixos/uid-map"));
}

// --- a citation only vouches for its own channel and exact leaf -----------

#[test]
fn a_path_channel_citation_is_confined_to_its_channel() {
    // timesync-clock covers the clock file, not an unrelated /var/log path.
    let v = decide(
        &clean_scans(),
        &policy_with(vec![entry("/var/log/evil.log", "timesync-clock")]),
    );
    assert_eq!(v.status, Status::Fail);
    assert!(rejected_for(&v, "outside the channel"), "{v:?}");
}

#[test]
fn a_path_channel_citation_covers_its_exact_leaf_and_nothing_beneath_it() {
    // timer-stamps' channel is a directory. A new stamp under it is the leak
    // signature of a timer only the hidden system runs: an entry naming the
    // directory covers the directory's own entry, never a file beneath it,
    // and only an exact leaf within the channel covers a stamp.
    let hidden = "/var/lib/systemd/timers/stamp-hidden-sync.timer";
    let decoy = "/var/lib/systemd/timers/stamp-fstrim.timer";
    let mut scans = clean_scans();
    scans.after.insert(restore(hidden));
    scans.after.insert(restore(decoy));
    let v = decide(
        &scans,
        &policy_with(vec![
            entry(CLOCK, "timesync-clock"),
            entry("/var/lib/systemd/timers", "timer-stamps"),
            entry(decoy, "timer-stamps"),
        ]),
    );
    assert_eq!(v.status, Status::Fail, "{:?}", v.failures);
    assert!(invalid_reasons(&v).is_empty(), "{v:?}");
    assert!(has_unexplained(&v, hidden));
    assert!(v.explained.iter().any(|e| e.path == decoy));
}

#[test]
fn an_entry_without_a_value_covers_the_restore_entry_alone() {
    // A field-less entry vouches for the file's own entry, whatever it holds.
    // A record in that file, or plaso's own stat of it, is cited only by its
    // exact value: no entry waves through every record of a file.
    let wtmp = "/var/lib/boot-records";
    let record = Finding::new(Tool::Plaso, wtmp, "linux:utmp:event user=hidden");
    let stat = Finding::new(Tool::Plaso, wtmp, "fs:stat");
    let mut scans = clean_scans();
    scans.after.insert(restore(wtmp));
    scans.after.insert(record.clone());
    scans.after.insert(stat);
    let v = decide(
        &scans,
        &policy_with(vec![
            entry(CLOCK, "timesync-clock"),
            entry(wtmp, "login-boot-records"),
        ]),
    );
    assert_eq!(v.counts.explained, 2, "{:?}", v.failures);
    assert_eq!(v.counts.unexplained, 2);

    let v = decide(
        &scans,
        &policy_with(vec![
            entry(CLOCK, "timesync-clock"),
            entry(wtmp, "login-boot-records"),
            entry_for(wtmp, "fs:stat", "login-boot-records"),
        ]),
    );
    assert_eq!(
        unexplained_at(&v, wtmp),
        [(Change::Added, record.field.clone())]
    );
}

#[test]
fn a_mechanism_row_vouches_for_its_cited_path() {
    // login-boot-records is a mechanism row (no channel paths); it may be cited
    // for a specific record path. The plaso control and the restore file at the
    // same path are told apart by tool: one is the self-check, one is cited.
    let mut scans = clean_scans();
    scans.after.insert(restore("/var/log/wtmp.db"));
    let v = decide(
        &scans,
        &policy_with(vec![
            entry(CLOCK, "timesync-clock"),
            entry("/var/log/wtmp.db", "login-boot-records"),
        ]),
    );
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
    let v = decide(
        &scans,
        &policy_with(vec![
            entry(CLOCK, "timesync-clock"),
            // a residual channel with no catalog id, cited by its section
            entry("/sys/firmware/efi/efivars/trace", RESIDUAL_ANCHOR),
        ]),
    );
    assert_eq!(v.status, Status::Clean, "{:?}", v.failures);
    let anchor = v.explained.iter().find(|e| e.cite.contains('#')).unwrap();
    assert!(
        anchor.risk.is_empty(),
        "a doc-anchor citation carries no row text"
    );
}

#[test]
fn an_unresolvable_doc_anchor_is_rejected() {
    let v = decide(
        &clean_scans(),
        &policy_with(vec![entry(CLOCK, "threat-model.md#invented-section")]),
    );
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
fn a_positive_control_the_baseline_already_carries_is_not_detected() {
    // Every wtmp file carries a linux:wtmp:event: a control whose value the
    // baseline already has is seen in after whether or not the planted record
    // was, so it proves nothing and the run is blind.
    for in_before in [true, false] {
        let mut scans = clean_scans();
        if in_before {
            scans.before.insert(control_finding());
        } else {
            scans.control.insert(control_finding());
        }
        let v = decide(&scans, &clean_policy());
        assert_eq!(v.status, Status::Fail);
        assert!(v.blind);
        assert!(!v.positive_controls[0].detected);
        let image = if in_before { "before" } else { "control" };
        assert!(
            v.failures.contains(&Failure::PositiveControlInBaseline {
                name: "wtmpdb-boot".into(),
                image: image.into(),
            }),
            "{:?}",
            v.failures
        );
        assert!(!control_missing(&v, "wtmpdb-boot"));
    }
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
    let v = decide(&scans, &policy_with(vec![]));
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
    let v = decide(
        &clean_scans(),
        &policy_with(vec![entry("email", "login-boot-records")]),
    );
    assert_eq!(v.status, Status::Fail);
    assert!(rejected_for(&v, "specific value"), "{v:?}");
}

#[test]
fn a_specific_feature_value_can_be_cited() {
    let leak = Finding::new(Tool::BulkExtractor, "email", "leak@evil.example");
    let mut scans = clean_scans();
    scans.after.insert(leak);
    let v = decide(
        &scans,
        &policy_with(vec![
            entry(CLOCK, "timesync-clock"),
            entry_for("email", "leak@evil.example", "login-boot-records"),
        ]),
    );
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
    // reconciled residue counts and what it cannot see, a failing run is
    // marked FAIL with the unexplained count. This pins the branch and the
    // rendered content.
    let clean = decide(&clean_scans(), &clean_policy());
    assert_eq!(
        clean.summary,
        "CLEAN: 2 residue (1 noise subtracted, 1 cited, 1 self-check); not seen: timestamps, \
         file metadata, process ids within one power-of-two range, sqlite_carved"
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
fn a_path_channel_row_is_citable_only_for_a_leaf_in_its_own_channel() {
    // A second path-channel row, to be sure the containment check is per-row.
    let stamp = "/var/lib/systemd/timers/stamp-fstrim.timer";
    let mut scans = clean_scans();
    scans.after.insert(restore(stamp));
    let v = decide(
        &scans,
        &policy_with(vec![
            entry(CLOCK, "timesync-clock"),
            entry(stamp, "timer-stamps"),
        ]),
    );
    assert_eq!(v.status, Status::Clean, "{:?}", v.failures);
    // Citing timesync-clock for the stamp would be out of channel.
    let bad = policy_with(vec![
        entry(CLOCK, "timesync-clock"),
        entry(stamp, "timesync-clock"),
    ]);
    let v = decide(&scans, &bad);
    assert_eq!(v.status, Status::Fail);
    assert!(rejected_for(&v, "outside the channel"), "{v:?}");
}

// --- false-clean hole 1: a path-less citation must not exempt a subtree -------

#[test]
fn a_mechanism_cite_for_a_whole_home_account_is_rejected_by_the_breadth_guard() {
    // /home/user names a whole account, so the breadth guard rejects this locus
    // outright (home is a user-data SYSTEM_ROOT) before the login-boot-records
    // mechanism cite is ever consulted: the path-less citation can never
    // wholesale-exempt the subtree. The leak beneath the locus surfaces as
    // unexplained residue, while the valid leaf cite stays explained. Leaf
    // coverage for a locus that clears the breadth guard is exercised by the
    // sibling test below.
    let mut scans = clean_scans();
    scans.after.insert(restore("/home/user/secret.txt"));
    let v = decide(
        &scans,
        &policy_with(vec![
            entry(CLOCK, "timesync-clock"),
            entry("/home/user", "login-boot-records"),
        ]),
    );
    assert_eq!(v.status, Status::Fail, "{:?}", v.failures);
    assert!(has_unexplained(&v, "/home/user/secret.txt"));
    assert!(rejected_for(&v, "subtree"), "{v:?}");
    assert!(v.explained.iter().any(|e| e.path == CLOCK));
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
    let v = decide(
        &scans,
        &policy_with(vec![
            entry(CLOCK, "timesync-clock"),
            entry("/var/lib/boot-records", "login-boot-records"),
        ]),
    );
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
        allowlist: allow(vec![entry(CLOCK, "timesync-clock")]),
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
        allowlist: allow(vec![entry(CLOCK, "timesync-clock")]),
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
    let v = decide(&scans, &policy_with(vec![]));
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
        allowlist: allow(vec![entry(CLOCK, "timesync-clock")]),
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

// --- a self-check is bound to the channel it pins ---------------------------

#[test]
fn a_positive_control_on_the_wrong_channel_is_not_detected() {
    // A positive control names the channel that must surface it; every shipped
    // control pins bulk_extractor. The same value carried only under a different
    // channel does not satisfy it, so the scan has not proven the pinned channel
    // can see a trace and the run is blind, never clean. The sentinel sits on
    // every image under the wrong channel, so it subtracts as noise and the only
    // thing under test is the channel gate: dropping the tool check in
    // locator_matches would wrongly count this as detected.
    let wrong_channel = Finding::new(Tool::Plaso, "email", "wtmpdb-boot@oracle.example");
    let scans = Scans {
        before: set([canary_finding(), wrong_channel.clone()]),
        control: set([canary_finding(), wrong_channel.clone()]),
        after: set([canary_finding(), wrong_channel]),
    };
    let control = PositiveControl {
        name: "wtmpdb-boot".into(),
        tool: Some(Tool::BulkExtractor),
        path: "email".into(),
        field: Some("wtmpdb-boot@oracle.example".into()),
        note: None,
    };
    let policy = OraclePolicy {
        allowlist: allow(vec![]),
        controls: controls(vec![control]),
    };
    let v = decide(&scans, &policy);
    assert_eq!(v.status, Status::Fail, "{:?}", v.failures);
    assert!(
        v.blind,
        "a control met only on the wrong channel leaves the scan blind"
    );
    assert!(control_missing(&v, "wtmpdb-boot"));
    assert!(!v.positive_controls[0].detected);
}

#[test]
fn a_canary_on_the_wrong_channel_is_not_detected() {
    // The canary is pinned to its channel the same way. The reserved address
    // carried only under a different channel than the canary names does not
    // prove coverage, so the run fails with a missing canary. A valid control is
    // present and met, so the only failure is the canary, isolating the channel
    // gate on the canary path (check_canary / any_match).
    let wrong_channel = Finding::new(Tool::Plaso, "email", "canary@oracle.example");
    let scans = Scans {
        before: set([wrong_channel.clone()]),
        control: set([wrong_channel.clone()]),
        after: set([wrong_channel, control_finding()]),
    };
    let v = decide(&scans, &clean_policy());
    assert_eq!(v.status, Status::Fail, "{:?}", v.failures);
    assert!(!v.canary_detected);
    assert!(
        v.failures
            .iter()
            .any(|f| matches!(f, Failure::CanaryMissing { .. }))
    );
}

#[test]
fn a_null_tool_control_is_detected_through_any_channel() {
    // A control with no pinned channel (tool null) is satisfied by a matching
    // finding from whichever channel surfaces it. Here the match arrives through
    // plaso while the control names only the path and value. A gate that refused
    // a null tool, instead of reading it as "any channel", would mark this blind.
    let any_channel = PositiveControl {
        name: "any-channel".into(),
        tool: None,
        path: "/var/log/wtmp.db".into(),
        field: Some("linux:wtmp:event".into()),
        note: None,
    };
    let scans = Scans {
        before: set([canary_finding()]),
        control: set([canary_finding()]),
        after: set([canary_finding(), control_finding()]),
    };
    let policy = OraclePolicy {
        allowlist: allow(vec![]),
        controls: controls(vec![any_channel]),
    };
    let v = decide(&scans, &policy);
    assert_eq!(v.status, Status::Clean, "{:?}", v.failures);
    assert!(!v.blind);
    assert!(v.positive_controls[0].detected);
    assert_eq!(v.counts.self_checks, 1);
    assert_eq!(v.counts.unexplained, 0);
}

// --- each configured positive control is weighed on its own -----------------

#[test]
fn a_detected_control_does_not_excuse_a_second_missing_one() {
    // Each positive control must be detected in its own right. With two valid
    // controls and only the first planted, the run is blind and names the second
    // as missing even though the first was found. A loop that stopped at the
    // first detected control, or set blind only when none were detected, would
    // pass this as clean.
    let second = PositiveControl {
        name: "lastlog2".into(),
        tool: Some(Tool::BulkExtractor),
        path: "email".into(),
        field: Some("lastlog2@oracle.example".into()),
        note: None,
    };
    let scans = Scans {
        before: set([canary_finding()]),
        control: set([canary_finding()]),
        after: set([canary_finding(), control_finding()]),
    };
    let policy = OraclePolicy {
        allowlist: allow(vec![]),
        controls: controls(vec![control_cfg(), second]),
    };
    let v = decide(&scans, &policy);
    assert_eq!(v.status, Status::Fail, "{:?}", v.failures);
    assert!(v.blind);
    assert!(control_missing(&v, "lastlog2"));
    assert!(!control_missing(&v, "wtmpdb-boot"));
    assert_eq!(v.positive_controls.len(), 2);
    assert_eq!(v.positive_controls[0].name, "wtmpdb-boot");
    assert!(v.positive_controls[0].detected);
    assert_eq!(v.positive_controls[1].name, "lastlog2");
    assert!(!v.positive_controls[1].detected);
}

#[test]
fn a_configured_but_rejected_control_fails_rather_than_passing_clean() {
    // A configured control that is rejected as too broad is not the same as no
    // control configured: it must fail the run on its own, not fall through to
    // clean and not be reported as "no positive control". The world is otherwise
    // clean, so only the rejected locus can make it fail.
    let too_broad = PositiveControl {
        name: "logs".into(),
        tool: None,
        path: "/var/log".into(),
        field: None,
        note: None,
    };
    let scans = Scans {
        before: set([canary_finding()]),
        control: set([canary_finding()]),
        after: set([canary_finding()]),
    };
    let policy = OraclePolicy {
        allowlist: allow(vec![]),
        controls: controls(vec![too_broad]),
    };
    let v = decide(&scans, &policy);
    assert_eq!(v.status, Status::Fail, "{:?}", v.failures);
    assert!(invalid_control(&v, "logs"), "{v:?}");
    assert!(
        !v.failures.contains(&Failure::NoPositiveControl),
        "a configured-but-rejected control must not read as none configured: {:?}",
        v.failures
    );
}

// --- what the verdict cannot see ---------------------------------------------

#[test]
fn every_verdict_names_the_classes_it_cannot_see() {
    let v = decide(&clean_scans(), &clean_policy());
    assert_eq!(
        v.unseen,
        [
            Unseen::Timestamps,
            Unseen::Metadata,
            Unseen::ProcessIdRange,
            Unseen::SkippedCarvers {
                feature_types: vec!["sqlite_carved".into()],
            },
            Unseen::RebootRewritten { paths: vec![] },
        ]
    );
    let json = serde_json::to_value(&v).expect("serializes");
    assert_eq!(
        json["unseen"],
        serde_json::json!([
            {"kind": "timestamps"},
            {"kind": "metadata"},
            {"kind": "process_id_range"},
            {"kind": "skipped_carvers", "feature_types": ["sqlite_carved"]},
            {"kind": "reboot_rewritten", "paths": []},
        ])
    );
}

#[test]
fn a_file_a_reboot_rewrites_is_unseen_unless_a_channel_reads_its_records() {
    // Four files hold another digest on every image. The verdict cannot judge
    // what after holds in random-seed or in the database's shared-memory
    // index, so it names them; plaso reads the login records of wtmp and the
    // scan the rows of the store database, so those are compared record by
    // record instead. plaso's own stat of random-seed reads no record of it.
    let rewritten = [
        "/var/lib/systemd/random-seed",
        "/nix/var/nix/db/db.sqlite-shm",
        "/var/log/wtmp",
        NIX_DB_PATH,
    ];
    let mut scans = clean_scans();
    for (image, digest) in [
        (&mut scans.before, "sha256:11"),
        (&mut scans.control, "sha256:22"),
        (&mut scans.after, "sha256:33"),
    ] {
        for path in rewritten {
            image.insert(restore_holding(path, digest));
        }
        image.insert(Finding::new(
            Tool::Plaso,
            "/var/lib/systemd/random-seed",
            "fs:stat",
        ));
    }
    scans.before.insert(Finding::new(
        Tool::Plaso,
        "/var/log/wtmp",
        "linux:utmp:event login_type=2",
    ));
    scans
        .control
        .insert(store_row("/nix/store/aaaa-decoy-system"));
    let v = decide(&scans, &clean_policy());
    assert_eq!(
        reboot_rewritten(&v),
        [
            "/nix/var/nix/db/db.sqlite-shm",
            "/var/lib/systemd/random-seed"
        ]
    );
    assert!(
        v.summary
            .ends_with(", sqlite_carved, 2 files a reboot rewrites"),
        "{}",
        v.summary
    );

    // One such file is named in the singular.
    for image in [&mut scans.before, &mut scans.control, &mut scans.after] {
        image.retain(|f| f.path != "/nix/var/nix/db/db.sqlite-shm");
    }
    let v = decide(&scans, &clean_policy());
    assert!(
        v.summary
            .ends_with(", sqlite_carved, 1 file a reboot rewrites"),
        "{}",
        v.summary
    );
}

#[test]
fn a_failing_summary_names_no_unseen_class() {
    // A failing run is already not clean; its line says why, and the classes
    // stay in the verdict's own list.
    let mut scans = clean_scans();
    scans.after.insert(restore("/home/user/secret.txt"));
    let v = decide(&scans, &clean_policy());
    assert_eq!(v.status, Status::Fail);
    assert!(!v.summary.contains("not seen"), "{}", v.summary);
    assert_eq!(v.unseen.len(), 5);
}

// --- a real scan must hear from every channel on every image -----------------

/// The shipped self-check shape: a bulk_extractor e-mail sentinel planted on
/// `after`.
fn planted_finding() -> Finding {
    Finding::new(Tool::BulkExtractor, "email", "planted@oracle.example")
}

fn planted_cfg() -> PositiveControl {
    PositiveControl {
        name: "planted".into(),
        tool: Some(Tool::BulkExtractor),
        path: "email".into(),
        field: Some("planted@oracle.example".into()),
        note: None,
    }
}

/// A clean real scan: every channel reports the same baseline on every image,
/// and `after` adds only the planted bulk_extractor control.
fn complete_scans() -> Scans {
    let baseline = set([
        restore("/etc/hostname"),
        canary_finding(),
        Finding::new(Tool::Plaso, "/var/log/app.log", "syslog:line"),
    ]);
    let mut after = baseline.clone();
    after.insert(planted_finding());
    Scans {
        before: baseline.clone(),
        control: baseline,
        after,
    }
}

fn complete_policy() -> OraclePolicy {
    OraclePolicy {
        allowlist: allow(vec![]),
        controls: controls(vec![planted_cfg()]),
    }
}

fn decide_scan(scans: &Scans, policy: &OraclePolicy) -> Verdict {
    verdict::scan_verdict(scans, policy, &catalog())
}

/// `scans` with every finding of `tool` removed from the images named.
fn without(mut scans: Scans, tool: Tool, images: &[&str]) -> Scans {
    for (name, image) in [
        ("before", &mut scans.before),
        ("control", &mut scans.control),
        ("after", &mut scans.after),
    ] {
        if images.contains(&name) {
            image.retain(|f| f.tool != tool);
        }
    }
    scans
}

fn channel_missing(tool: Tool, image: &str) -> Failure {
    Failure::ChannelMissing {
        tool,
        image: image.into(),
    }
}

#[test]
fn a_scan_verdict_over_every_channel_is_the_plain_verdict() {
    // With every channel reporting on every image the channel rule adds
    // nothing: the run is clean, and exactly what the bare engine decides.
    let v = decide_scan(&complete_scans(), &complete_policy());
    assert_eq!(v.status, Status::Clean, "{:?}", v.failures);
    assert!(!v.blind);
    assert_eq!(v, decide(&complete_scans(), &complete_policy()));
}

#[test]
fn a_dropped_plaso_channel_fails_the_scan_blind() {
    // run-scan.sh drops plaso whole when docker is absent, its image cannot be
    // pulled or one image's timeline fails. Nothing else is wrong, so the bare
    // engine calls this clean; the scan verdict fails it blind, naming plaso on
    // every image.
    let scans = without(
        complete_scans(),
        Tool::Plaso,
        &["before", "control", "after"],
    );
    assert_eq!(decide(&scans, &complete_policy()).status, Status::Clean);

    let v = decide_scan(&scans, &complete_policy());
    assert_eq!(v.status, Status::Fail);
    assert!(v.blind, "a scan that could not look is blind");
    assert_eq!(
        v.failures,
        [
            channel_missing(Tool::Plaso, "before"),
            channel_missing(Tool::Plaso, "control"),
            channel_missing(Tool::Plaso, "after"),
        ]
    );
    assert!(v.summary.starts_with("FAIL (BLIND)"), "{}", v.summary);
}

#[test]
fn a_channel_silent_on_one_image_fails_for_that_image() {
    // A carve that recovered nothing for `after` leaves the restore channel
    // silent there: the channel failure names that channel and that image,
    // and what after lost against the other two images is residue too.
    let scans = without(complete_scans(), Tool::BtrfsRestore, &["after"]);
    let v = decide_scan(&scans, &complete_policy());
    assert_eq!(v.status, Status::Fail);
    assert!(
        v.failures
            .contains(&channel_missing(Tool::BtrfsRestore, "after"))
    );
    assert_eq!(
        unexplained_at(&v, "/etc/hostname"),
        [(Change::Removed, "sha256:0a".to_string())]
    );
}

#[test]
fn every_channel_is_required_on_every_image() {
    // Each channel, silent on one image, fails the run on its own; a
    // finding of another channel never stands in for it.
    for tool in Tool::REQUIRED {
        for image in ["before", "control", "after"] {
            let scans = without(complete_scans(), tool, &[image]);
            let v = decide_scan(&scans, &complete_policy());
            assert!(
                v.failures.contains(&channel_missing(tool, image)),
                "{tool:?} silent on {image}: {:?}",
                v.failures
            );
            assert_eq!(v.status, Status::Fail, "{tool:?} silent on {image}");
        }
    }
}

#[test]
fn a_missing_channel_is_reported_alongside_a_leak() {
    // The channel rule adds its failures to the verdict's own: a leak in the
    // channels that did report still surfaces.
    let mut scans = without(
        complete_scans(),
        Tool::Plaso,
        &["before", "control", "after"],
    );
    scans.after.insert(restore("/home/user/secret.txt"));
    let v = decide_scan(&scans, &complete_policy());
    assert!(has_unexplained(&v, "/home/user/secret.txt"), "{v:?}");
    assert!(
        v.failures.contains(&channel_missing(Tool::Plaso, "after")),
        "{v:?}"
    );
    assert_eq!(v.counts.unexplained, 1);
}
