// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Output formatting for the activate command.
//!
//! Activation prints its result *before* it enqueues the soft-reboot, because
//! the switch ends the terminal it runs in. Under `--json` the stream is NDJSON:
//! progress lines, then one result line.

use nails_core::NailsError;
use nails_core::output::Mark;
use nails_core::session::Entry;
use serde::Serialize;

use super::OutputSettings;
use crate::cli::output::envelope::SCHEMA_VERSION;

/// A streamed progress line for `activate --json`.
#[derive(Debug, Serialize)]
struct ActivateProgressEvent {
    schema_version: u32,
    command: &'static str,
    #[serde(rename = "type")]
    event_type: &'static str,
    phase: &'static str,
}

#[derive(Debug, Serialize)]
struct FailedCheckJson {
    name: String,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<String>,
}

/// The final NDJSON line for `activate --json`.
#[derive(Debug, Serialize)]
struct ActivateResultEvent {
    schema_version: u32,
    command: &'static str,
    #[serde(rename = "type")]
    event_type: &'static str,
    ok: bool,
    /// `entering`, `entering_with_warnings`, `already_active` or `error`.
    status: &'static str,
    /// Seconds spent preparing the entry.
    duration: f64,
    /// The hidden NixOS toplevel entered, when one was built.
    #[serde(skip_serializing_if = "Option::is_none")]
    hidden_system: Option<String>,
    /// What happens to each decoy filesystem in the hidden root.
    filesystems: Vec<String>,
    /// Units masked in the hidden root.
    masked_units: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_checks: Option<Vec<FailedCheckJson>>,
}

/// What `activate` reports.
#[derive(Debug)]
pub enum ActivateResult<'a> {
    /// The entry is prepared; the soft-reboot follows.
    Entering(&'a Entry),
    /// Already in the hidden session.
    AlreadyActive,
    /// It failed.
    Failed(&'a NailsError),
}

/// Emit a progress event on stdout, ahead of the final result line.
pub fn print_activate_progress(phase: &'static str) {
    let event = ActivateProgressEvent {
        schema_version: SCHEMA_VERSION,
        command: "activate",
        event_type: "progress",
        phase,
    };
    crate::cli::output::println_tolerating_broken_pipe(
        &serde_json::to_string(&event).unwrap_or_default(),
    );
}

/// `duration` (in seconds) as `status` shows the recorded activation time.
fn shown_duration(duration: f64) -> String {
    nails_core::timing::format_duration(
        std::time::Duration::try_from_secs_f64(duration).unwrap_or_default(),
    )
}

fn filesystems(entry: &Entry) -> Vec<String> {
    entry
        .decisions
        .iter()
        .filter(|d| !matches!(d, nails_core::session::policy::Decision::Leave { .. }))
        .map(nails_core::session::policy::Decision::describe)
        .collect()
}

fn result_event(result: &ActivateResult<'_>, duration: f64) -> ActivateResultEvent {
    let mut event = ActivateResultEvent {
        schema_version: SCHEMA_VERSION,
        command: "activate",
        event_type: "result",
        ok: true,
        status: "already_active",
        duration,
        hidden_system: None,
        filesystems: Vec::new(),
        masked_units: Vec::new(),
        warnings: Vec::new(),
        message: "Already in the hidden session; nothing to do".to_string(),
        failed_checks: None,
    };
    match result {
        ActivateResult::AlreadyActive => {}
        ActivateResult::Entering(entry) => {
            event.status = if entry.warnings.is_empty() {
                "entering"
            } else {
                "entering_with_warnings"
            };
            event.hidden_system = entry
                .plan
                .hidden
                .system
                .as_ref()
                .map(|p| p.display().to_string());
            event.filesystems = filesystems(entry);
            event.masked_units = entry.plan.masks.clone();
            event.warnings = entry.warnings.clone();
            event.message = format!(
                "Prepared in {}; soft-rebooting into the hidden session",
                shown_duration(duration)
            );
        }
        ActivateResult::Failed(error) => {
            event.ok = false;
            event.status = "error";
            match error {
                NailsError::PreFlightCheckFailed(failures) => {
                    event.message = "Pre-flight checks failed".to_string();
                    event.failed_checks = Some(
                        failures
                            .iter()
                            .map(|(name, reason, fix)| FailedCheckJson {
                                name: name.clone(),
                                reason: reason.clone(),
                                fix: fix.clone(),
                            })
                            .collect(),
                    );
                }
                other => event.message = format!("Activation failed: {other}"),
            }
        }
    }
    event
}

/// Print the final activation result line in NDJSON.
pub fn print_activate_json_result(result: &ActivateResult<'_>, duration: f64) {
    crate::cli::output::println_tolerating_broken_pipe(
        &serde_json::to_string(&result_event(result, duration)).unwrap_or_default(),
    );
}

/// The human lines for a result: results on stdout, failures on stderr.
fn human_lines(
    result: &ActivateResult<'_>,
    duration: f64,
    settings: &OutputSettings,
) -> (Vec<String>, Vec<String>) {
    let out_style = settings.stdout_style();
    let err_style = settings.stderr_style();
    let mut out = Vec::new();
    let mut err = Vec::new();
    match result {
        ActivateResult::AlreadyActive => {
            out.push(out_style.marked(Mark::Pass, "Already in the hidden session"));
        }
        ActivateResult::Entering(entry) => {
            out.push(out_style.marked(
                Mark::Pass,
                format!("Hidden session prepared in {}", shown_duration(duration)),
            ));
            if !settings.is_quiet() {
                if let Some(system) = &entry.plan.hidden.system {
                    out.push(format!("  Hidden system: {}", system.display()));
                }
                for line in filesystems(entry) {
                    out.push(format!("  {line}"));
                }
            }
            for warning in &entry.warnings {
                out.push(out_style.marked(Mark::Warn, warning));
            }
            out.push(String::new());
            out.push(
                "Soft-rebooting into the hidden session now: every program closes and you are \
                 logged out. Log in at the hidden session's login screen (a display manager \
                 set to log an account in automatically logs it in again, as at boot)."
                    .to_string(),
            );
        }
        ActivateResult::Failed(error) => {
            if let NailsError::PreFlightCheckFailed(failures) = error {
                err.push(err_style.marked(Mark::Fail, "Pre-flight checks failed"));
                for (name, reason, fix) in failures.iter() {
                    err.push(format!("  - {name}: {reason}"));
                    if let Some(fix) = fix {
                        for line in fix.lines() {
                            err.push(format!("      {line}"));
                        }
                    }
                }
            } else {
                err.push(err_style.marked(Mark::Fail, format!("Activation failed: {error}")));
            }
            err.push("  Nothing was changed: no next root is left behind.".to_string());
        }
    }
    (out, err)
}

/// Print the activation result in human-readable form.
pub fn print_activate_human(result: &ActivateResult<'_>, duration: f64, settings: &OutputSettings) {
    let (out, err) = human_lines(result, duration, settings);
    for line in out {
        crate::cli::output::println_tolerating_broken_pipe(&line);
    }
    for line in err {
        crate::cli::output::eprintln_tolerating_broken_pipe(&line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_preflight_refusal_lists_each_check_with_its_fix() {
        let error = NailsError::PreFlightCheckFailed(vec![(
            "systemd-version".to_string(),
            "systemd 252 is too old".to_string(),
            Some("Use Debian 13".to_string()),
        )]);
        let event = result_event(&ActivateResult::Failed(&error), 0.5);
        assert!(!event.ok);
        assert_eq!(event.status, "error");
        let checks = event.failed_checks.unwrap();
        assert_eq!(checks[0].name, "systemd-version");
        let (_, err) = human_lines(
            &ActivateResult::Failed(&error),
            0.5,
            &OutputSettings::default(),
        );
        assert!(err.iter().any(|l| l.contains("Use Debian 13")), "{err:?}");
    }

    #[test]
    fn already_active_is_a_success_with_its_own_status() {
        let event = result_event(&ActivateResult::AlreadyActive, 0.0);
        assert!(event.ok);
        assert_eq!(event.status, "already_active");
        let text = serde_json::to_string(&event).unwrap();
        assert!(text.contains("\"type\":\"result\""));
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
                boot_masks: Vec::new(),
                session_units: Vec::new(),
                backend: Vec::new(),
                tools: Tools::default(),
                armed: None,
                entered_at: None,
                run_noexec: false,
                carried: Vec::new(),
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
        let event = result_event(&ActivateResult::Entering(&entry), 2.34);

        assert!(event.ok);
        assert_eq!(event.status, "entering");
        assert_eq!(
            event.hidden_system.as_deref(),
            Some("/nix/store/aaa-nixos-system-hidden")
        );
        // `Leave` decisions are not reported: nothing happens to them.
        assert_eq!(
            event.filesystems,
            vec!["/boot: read-only", "/home: overlaid"]
        );
        assert_eq!(event.masked_units, vec!["dev-vda3.swap"]);
        assert_eq!(
            event.message,
            "Prepared in 2.3s; soft-rebooting into the hidden session"
        );
        let value = serde_json::to_value(&event).unwrap();
        assert!(value.get("warnings").is_none(), "{value}");
        assert!(value.get("failed_checks").is_none(), "{value}");
    }

    #[test]
    fn an_entry_with_warnings_reports_its_own_status_and_carries_them() {
        let entry = entry(vec![
            "hidden kernel differs from the running one".to_string(),
        ]);
        let event = result_event(&ActivateResult::Entering(&entry), 1.0);
        assert_eq!(event.status, "entering_with_warnings");
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(
            value["warnings"][0],
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
        let event = result_event(&ActivateResult::Failed(&error), 0.1);
        assert!(!event.ok);
        assert!(event.failed_checks.is_none());
        assert_eq!(event.message, format!("Activation failed: {error}"));

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
        let event = result_event(&ActivateResult::Failed(&error), 0.0);
        let value = serde_json::to_value(&event).unwrap();
        assert!(value["failed_checks"][1].get("fix").is_none(), "{value}");
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
}
