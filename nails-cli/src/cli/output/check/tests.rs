// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the `check` report and its two renderings.

use super::*;

fn rows() -> Vec<CheckRow> {
    vec![
        CheckRow::from_result("a".into(), &CheckResult::Pass("ok".into())),
        CheckRow::from_result("b".into(), &CheckResult::Warn("careful".into())),
    ]
}

fn report(rows: Vec<CheckRow>) -> CheckReport {
    CheckReport::finalize(
        rows,
        ConfigSummary {
            config_file: None,
            hidden_volume_root: "/mnt/vault".into(),
            state_file: "/mnt/vault/state.json".into(),
            log_path: "/mnt/vault/logs".into(),
            persona_mode: "shared-home",
            minimum_space_mb: 100,
        },
        vec!["/home: overlaid".into()],
        ProfileSummary {
            mode: "none",
            detail: None,
        },
        InheritedSummary {
            inspected: true,
            entries: vec![InheritedEntry {
                name: "dropbox".into(),
                source: "user-autostart",
                remote_linked: true,
                maskable: true,
                origin: "added",
                status: "review",
            }],
            remote_linked: vec!["dropbox".into()],
            unmatched_masks: Vec::new(),
        },
    )
}

#[test]
fn finalize_counts_outcomes_and_sets_ready() {
    let report = report(rows());
    assert!(report.ready);
    assert_eq!(report.summary.passed, 1);
    assert_eq!(report.summary.warnings, 1);
    assert_eq!(report.summary.failed, 0);
}

#[test]
fn the_summary_line_puts_a_single_warning_in_the_singular() {
    let style = Style {
        ascii: true,
        ..Style::default()
    };
    assert_eq!(
        summary_line(&report(rows()), style),
        "[PASS] Ready to activate  (1 passed, 1 warning, 0 failed)"
    );

    let mut rows = rows();
    rows.push(CheckRow::from_result(
        "c".into(),
        &CheckResult::Warn("again".into()),
    ));
    rows.push(CheckRow::from_result(
        "d".into(),
        &CheckResult::fail("boom".to_string()),
    ));
    rows.push(CheckRow::from_result(
        "e".into(),
        &CheckResult::Skipped("no volume".into()),
    ));
    assert_eq!(
        summary_line(&report(rows), style),
        "[FAIL] Not ready: resolve the failing checks above  \
         (1 passed, 2 warnings, 1 failed, 1 skipped)"
    );
}

#[test]
fn a_failing_check_marks_the_report_not_ready() {
    let mut rows = rows();
    rows.push(CheckRow::from_result(
        "c".into(),
        &CheckResult::fail("boom".to_string()),
    ));
    let report = report(rows);
    assert!(!report.ready);
    assert_eq!(report.summary.failed, 1);
}

#[test]
fn json_envelope_carries_checks_and_summary() {
    let report = report(rows());
    let line = Envelope::success(COMMAND, &report).to_line();
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(value["command"], "check");
    assert_eq!(value["data"]["ready"], true);
    assert_eq!(value["data"]["checks"][0]["name"], "a");
    assert_eq!(value["data"]["checks"][0]["status"], "pass");
    assert_eq!(value["data"]["summary"]["warnings"], 1);
}

#[test]
fn json_envelope_carries_inherited_inventory() {
    let report = report(rows());
    let line = Envelope::success(COMMAND, &report).to_line();
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(value["data"]["inherited"]["inspected"], true);
    assert_eq!(value["data"]["inherited"]["entries"][0]["name"], "dropbox");
    assert_eq!(
        value["data"]["inherited"]["entries"][0]["source"],
        "user-autostart"
    );
    assert_eq!(
        value["data"]["inherited"]["entries"][0]["remote_linked"],
        true
    );
    assert_eq!(value["data"]["inherited"]["remote_linked"][0], "dropbox");
    assert_eq!(value["data"]["inherited"]["entries"][0]["origin"], "added");
    assert_eq!(value["data"]["inherited"]["entries"][0]["status"], "review");
}

#[test]
fn not_inspected_summary_is_empty() {
    let summary = InheritedSummary::not_inspected();
    assert!(!summary.inspected);
    assert!(summary.entries.is_empty());
    assert!(summary.remote_linked.is_empty());
}

/// Under "NixOS profile" the report prints the summary's line: the build
/// target, or that there is none, never 0.2's "no profile switch".
#[test]
fn the_profile_section_prints_the_build_target_line() {
    let style = Style {
        ascii: true,
        ..Style::default()
    };
    let overlay_only = "overlay-only: no hidden NixOS system is built; the session runs the \
                        decoy's own system";
    for (detail, expected) in [
        (None, "  [INFO] no hidden NixOS build target".to_string()),
        (
            Some(overlay_only.to_string()),
            format!("  [INFO] {overlay_only}"),
        ),
    ] {
        let mut report = report(rows());
        report.profile.detail = detail;
        let lines = human_lines(&report, style);
        let at = lines
            .iter()
            .position(|line| line == "NixOS profile:")
            .expect("the NixOS profile section");
        assert_eq!(lines[at + 1], expected);
        assert_eq!(lines[at + 2], "");
        assert!(
            lines.iter().all(|line| !line.contains("profile switch")),
            "{lines:#?}"
        );
    }
}
