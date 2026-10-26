// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for what `activate` reports.

use super::*;

/// The one-line envelope `activate --json` prints for `result`, built by the
/// function the printer uses, as a value checked against the committed schema.
fn envelope_value(result: &ActivateResult<'_>, duration: f64) -> serde_json::Value {
    let line = activate_envelope_line(result, duration);
    assert_eq!(line.lines().count(), 1, "one physical line: {line}");
    crate::cli::output::test_support::envelope("activate", &line)
}

#[test]
fn a_preflight_refusal_lists_each_check_with_its_fix() {
    let error = NailsError::PreFlightCheckFailed(vec![(
        "systemd-version".to_string(),
        "systemd 252 is too old".to_string(),
        Some("Use Debian 13".to_string()),
    )]);
    let data = activate_data(&ActivateResult::Failed(&error), 0.5);
    assert_eq!(data.status, "failed");
    let checks = data.failed_checks.unwrap();
    assert_eq!(checks[0].name, "systemd-version");

    let value = envelope_value(&ActivateResult::Failed(&error), 0.5);
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["command"], "activate");
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], "not_ready");
    assert_eq!(value["data"]["failed_checks"][0]["name"], "systemd-version");

    let (_, err) = human_lines(
        &ActivateResult::Failed(&error),
        0.5,
        &OutputSettings::default(),
    );
    assert!(err.iter().any(|l| l.contains("Use Debian 13")), "{err:?}");
}

#[test]
fn already_active_is_one_ok_envelope_with_its_own_status() {
    let data = activate_data(&ActivateResult::AlreadyActive, 0.0);
    assert_eq!(data.status, "already_active");
    let value = envelope_value(&ActivateResult::AlreadyActive, 0.0);
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["status"], "already_active");
    // The version-1 line stream is gone: no `type` tag, one envelope only.
    assert!(value.get("type").is_none(), "{value}");
    assert!(value["data"].get("type").is_none(), "{value}");
}

/// A prepared entry with a hidden NixOS toplevel, one masked unit, and one
/// decision of each shown kind plus a `Leave` that the output omits.
fn entry(warnings: Vec<String>) -> Entry {
    use nails_core::session::policy::Decision;
    use nails_teardown::whole_root::plan::{DecoyRoot, PLAN_VERSION, Plan, RootSide, Tools};
    let side = |system: Option<&str>| RootSide {
        init: "/usr/lib/systemd/systemd".into(),
        system: system.map(Into::into),
    };
    Entry {
        plan: Plan {
            version: PLAN_VERSION,
            hidden_root: "/mnt/data".into(),
            hidden_dev: None,
            accepted_decoy_storage: None,
            upper: "/mnt/data/root/upper".into(),
            work: "/mnt/data/root/work".into(),
            owner: None,
            decoy_root: DecoyRoot {
                source: "/dev/vda2".into(),
                fstype: "ext4".into(),
                data: None,
            },
            decoy: side(None),
            hidden: side(Some("/nix/store/aaa-nixos-system-hidden")),
            policy_mounts: Vec::new(),
            masks: vec!["dev-vda3.swap".to_string()],
            boot_masks: vec!["systemd-boot-random-seed.service".to_string()],
            generator_masks: Vec::new(),
            session_units: Vec::new(),
            backend: Vec::new(),
            tools: Tools::default(),
            armed: None,
            entered_at: None,
            run_noexec: false,
            carried: Vec::new(),
            decoy_mounts: Vec::new(),
            read_only_disks: false,
            failed_at_entry: Vec::new(),
            kernel_settings: Vec::new(),
        },
        decisions: vec![
            Decision::ReadOnlyBind {
                target: "/boot".into(),
            },
            Decision::Overlay {
                target: "/home".into(),
            },
            Decision::Leave {
                target: "/proc".into(),
                reason: "virtual",
            },
        ],
        warnings,
    }
}

#[test]
fn an_entering_result_lists_the_system_filesystems_and_masks() {
    let entry = entry(Vec::new());
    let data = activate_data(&ActivateResult::Entering(&entry), 2.34);

    assert_eq!(data.status, "entering");
    assert_eq!(
        data.hidden_system.as_deref(),
        Some("/nix/store/aaa-nixos-system-hidden")
    );
    // `Leave` decisions are not reported: nothing happens to them.
    assert_eq!(
        data.filesystems,
        vec!["/boot: read-only", "/home: overlaid"]
    );
    // As `status --json` lists them: the boot-loader masks too.
    assert_eq!(
        data.masked_units,
        vec!["dev-vda3.swap", "systemd-boot-random-seed.service"]
    );
    assert_eq!(
        data.message,
        "Prepared in 2.3s; soft-rebooting into the hidden session"
    );
    let value = envelope_value(&ActivateResult::Entering(&entry), 2.34);
    assert_eq!(value["ok"], true);
    assert!(value["data"].get("warnings").is_none(), "{value}");
    assert!(value["data"].get("failed_checks").is_none(), "{value}");
}

#[test]
fn an_entry_with_warnings_reports_its_own_status_and_carries_them() {
    let entry = entry(vec![
        "hidden kernel differs from the running one".to_string(),
    ]);
    let data = activate_data(&ActivateResult::Entering(&entry), 1.0);
    assert_eq!(data.status, "entering_with_warnings");
    let value = envelope_value(&ActivateResult::Entering(&entry), 1.0);
    // Entering with warnings is exit 9, still a success for `ok`.
    assert_eq!(value["ok"], true);
    assert_eq!(
        value["data"]["warnings"][0],
        "hidden kernel differs from the running one"
    );
}

#[test]
fn the_human_entering_lines_show_details_warnings_and_the_switch_notice() {
    let entry = entry(vec!["hidden kernel differs".to_string()]);
    let (out, err) = human_lines(
        &ActivateResult::Entering(&entry),
        3.0,
        &OutputSettings::default(),
    );

    assert!(err.is_empty(), "{err:?}");
    assert_eq!(
        out,
        vec![
            "\u{2713} Hidden session prepared in 3.0s".to_string(),
            "  Hidden system: /nix/store/aaa-nixos-system-hidden".to_string(),
            "  /boot: read-only".to_string(),
            "  /home: overlaid".to_string(),
            "\u{26a0} hidden kernel differs".to_string(),
            String::new(),
            "Soft-rebooting into the hidden session now: every program closes and you are \
             logged out. Log in at the hidden session's login screen (a display manager \
             set to log an account in automatically logs it in again, as at boot)."
                .to_string(),
        ]
    );
}

#[test]
fn quiet_entering_output_drops_the_details_but_keeps_the_warnings() {
    let entry = entry(vec!["hidden kernel differs".to_string()]);
    let quiet = OutputSettings {
        verbosity: nails_core::Verbosity::Quiet,
        ascii: true,
        ..OutputSettings::default()
    };
    let (out, _) = human_lines(&ActivateResult::Entering(&entry), 3.0, &quiet);

    assert_eq!(out[0], "[PASS] Hidden session prepared in 3.0s");
    assert_eq!(out[1], "[WARN] hidden kernel differs");
    assert!(
        !out.iter().any(|line| line.contains("Hidden system")),
        "{out:?}"
    );
    assert!(!out.iter().any(|line| line.contains("/boot")), "{out:?}");
}

#[test]
fn a_plain_failure_names_the_error_on_stderr_and_promises_no_leftovers() {
    let error = NailsError::InvalidState("the root is not a mount point".to_string());
    let data = activate_data(&ActivateResult::Failed(&error), 0.1);
    assert_eq!(data.status, "failed");
    assert!(data.failed_checks.is_none());
    assert_eq!(data.message, format!("Activation failed: {error}"));
    assert_eq!(failure_error(&error).code, "activation_failed");

    let (out, err) = human_lines(
        &ActivateResult::Failed(&error),
        0.1,
        &OutputSettings::default(),
    );
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(
        err,
        vec![
            format!("\u{2717} Activation failed: {error}"),
            "  Nothing was changed: no next root is left behind.".to_string(),
        ]
    );
}

/// A cancel is the one cancel shape, no failure: it reads the same whether the
/// operator answered `n` or pressed Ctrl+C, at the prompt or during the entry.
#[test]
fn a_cancel_reads_as_the_one_cancel_shape() {
    let cancelled = ActivateResult::Failed(&NailsError::Cancelled);
    let value = envelope_value(&cancelled, 0.0);
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], "cancelled");
    assert_eq!(
        value["error"]["message"],
        "Activation cancelled; nothing was changed."
    );
    // The cancel shape carries no data.
    assert!(value.get("data").is_none(), "{value}");

    let (out, err) = human_lines(&cancelled, 0.0, &OutputSettings::default());
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(
        err,
        vec!["\u{25cb} Activation cancelled; nothing was changed.".to_string()]
    );
}

#[test]
fn a_multi_line_fix_is_indented_line_by_line() {
    let error = NailsError::PreFlightCheckFailed(vec![
        (
            "hidden-root".to_string(),
            "not mounted".to_string(),
            Some("Unlock the volume\nMount it at /mnt/data".to_string()),
        ),
        ("tpm".to_string(), "absent".to_string(), None),
    ]);
    let (_, err) = human_lines(
        &ActivateResult::Failed(&error),
        0.0,
        &OutputSettings::default(),
    );
    assert_eq!(
        err,
        vec![
            "\u{2717} Pre-flight checks failed".to_string(),
            "  - hidden-root: not mounted".to_string(),
            "      Unlock the volume".to_string(),
            "      Mount it at /mnt/data".to_string(),
            "  - tpm: absent".to_string(),
            "  Nothing was changed: no next root is left behind.".to_string(),
        ]
    );
    let value = envelope_value(&ActivateResult::Failed(&error), 0.0);
    assert!(
        value["data"]["failed_checks"][1].get("fix").is_none(),
        "{value}"
    );
}

#[test]
fn already_active_prints_one_success_line() {
    let (out, err) = human_lines(
        &ActivateResult::AlreadyActive,
        0.0,
        &OutputSettings::default(),
    );
    assert_eq!(out, vec!["\u{2713} Already in the hidden session"]);
    assert!(err.is_empty());
}

/// An overlay-only entry keeps the decoy's own system: it names no hidden
/// system, on the terminal or in JSON.
#[test]
fn an_overlay_only_entry_names_no_hidden_system() {
    let mut entry = entry(Vec::new());
    entry.plan.decoy.system = Some("/nix/store/bbb-nixos-system-decoy".into());
    entry.plan.hidden.system = entry.plan.decoy.system.clone();
    let (out, _) = human_lines(
        &ActivateResult::Entering(&entry),
        3.0,
        &OutputSettings::default(),
    );
    assert!(
        !out.iter().any(|line| line.contains("Hidden system")),
        "{out:?}"
    );
    let value = envelope_value(&ActivateResult::Entering(&entry), 3.0);
    assert!(value["data"].get("hidden_system").is_none(), "{value}");
}
