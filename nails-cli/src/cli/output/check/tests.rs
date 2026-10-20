// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the two renderings of the readiness report.

use super::*;
use nails_core::CheckResult;
use nails_core::app::readiness::{
    ConfigSummary, InheritedEntry, InheritedSummary, ProfileSummary, ReadinessReport,
};

fn rows() -> Vec<CheckRow> {
    vec![
        CheckRow::from_result("a".into(), &CheckResult::Pass("ok".into())),
        CheckRow::from_result("b".into(), &CheckResult::Warn("careful".into())),
    ]
}

fn report(rows: Vec<CheckRow>) -> ReadinessReport {
    ReadinessReport::finalize(
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
        // A NixOS host always shows the section.
        report.nixos_host = true;
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

/// On a non-NixOS host with no NixOS target the section is omitted: a Debian or
/// Ubuntu decoy has no NixOS profile to build, so the line is noise.
#[test]
fn the_profile_section_is_hidden_on_a_non_nixos_host() {
    let style = Style {
        ascii: true,
        ..Style::default()
    };
    let mut report = report(rows());
    report.nixos_host = false;
    report.profile = ProfileSummary {
        mode: "none",
        detail: None,
    };
    let lines = human_lines(&report, style);
    assert!(
        lines.iter().all(|line| line != "NixOS profile:"),
        "{lines:#?}"
    );
    assert!(
        lines
            .iter()
            .all(|line| !line.contains("NixOS build target")),
        "{lines:#?}"
    );
}

/// An explicit flake is the operator's own choice and is shown on any host, so a
/// Debian decoy pointed at a flake still reports it.
#[test]
fn an_explicit_flake_shows_the_profile_section_on_any_host() {
    let style = Style {
        ascii: true,
        ..Style::default()
    };
    let mut report = report(rows());
    report.nixos_host = false;
    report.profile = ProfileSummary {
        mode: "flake",
        detail: Some("NixOS flake: /cfg#host".to_string()),
    };
    let lines = human_lines(&report, style);
    let at = lines
        .iter()
        .position(|line| line == "NixOS profile:")
        .expect("an explicit flake is reported on any host");
    assert!(lines[at + 1].contains("/cfg#host"), "{lines:#?}");
}
