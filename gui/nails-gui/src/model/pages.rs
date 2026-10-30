// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The pages of the model's states: the decoy's check, a hidden session's
//! status, the record that cannot be read and each way a session can end.
//! What the window shows in each comes from the engine's last answers, which
//! the [`Model`] keeps.

use std::collections::BTreeSet;

use nails_api::CheckOutcome;

use super::activation::Risk;
use super::{Check, CheckView, Model, Page};
use crate::envelope::{
    self, Attention, CheckStatus, ErrorBody, Place, Readiness, RecoverData, StatusData,
};
use crate::text;
use crate::worker::{Failure, Kind};

impl Model {
    pub(super) fn session_page(&self) -> Page {
        let Some(status) = &self.status else {
            return match &self.status_error {
                Some(error) => self.status_failed_page(error),
                None => busy_page(text::STARTING, ""),
            };
        };
        match status.place {
            Place::Decoy => self.decoy_page(status),
            Place::Hidden => self.hidden_page(status),
            Place::Activating => Page {
                heading: text::ACTIVATING.to_string(),
                description: text::ACTIVATING_WHERE.to_string(),
                ..Page::default()
            },
            Place::Unknown => self.place_unknown_page(self.status_error.as_ref()),
        }
    }

    /// The page of a status the engine could not build at all, with no data
    /// to say where the machine is: its settings could not be read, or it
    /// failed otherwise. It names no place.
    pub(super) fn status_failed_page(&self, error: &ErrorBody) -> Page {
        let next = error
            .next
            .as_ref()
            .map(|next| text::next_step(self.engine.as_deref(), &next.command));
        let (heading, fix) = if error.code == "config" {
            (
                text::SETTINGS_UNREADABLE,
                next.unwrap_or_else(|| text::next_step(self.engine.as_deref(), "config validate")),
            )
        } else {
            (text::STATUS_UNAVAILABLE, next.unwrap_or_default())
        };
        Page {
            heading: heading.to_string(),
            description: text::sentence(&error.message),
            note: text::NOTHING_CHANGED.to_string(),
            urgent: true,
            fix,
            ..Page::default()
        }
    }

    /// The page of a status whose record could not be read at all, so the
    /// engine does not guess where the machine is, and neither does the page.
    pub(super) fn place_unknown_page(&self, error: Option<&ErrorBody>) -> Page {
        Page {
            description: text::PLACE_UNKNOWN.to_string(),
            ..self.record_unreadable_page(None, error)
        }
    }

    pub(super) fn decoy_page(&self, status: &StatusData) -> Page {
        let fix = status
            .remediation
            .as_deref()
            .map(text::engine_fix)
            .unwrap_or_default();
        let description = match status.attention {
            Some(Attention::Interrupted) => {
                // Clean Up runs `recover`, which asks nothing, as the
                // CLI's does: the page says what it does in place of the
                // command a terminal would run.
                return Page {
                    heading: text::INTERRUPTED.to_string(),
                    description: text::DECOY_INTERRUPTED.to_string(),
                    busy: (self.running == Some(Kind::Recover))
                        .then(|| text::CLEANING_UP.to_string()),
                    facts: self.volume_fact(status),
                    fix: text::CLEAN_UP_WHAT.to_string(),
                    action: Some(text::CLEAN_UP),
                    ..Page::default()
                };
            }
            Some(Attention::RecordUnreadable) => {
                return self.record_unreadable_page(Some(status), self.status_error.as_ref());
            }
            Some(Attention::SwitchRefused) => text::decoy_switch_refused(status.reason.as_deref()),
            Some(Attention::EndedAbnormally) => text::DECOY_ENDED_ABNORMALLY.to_string(),
            Some(Attention::VolumeCovered) => text::DECOY_VOLUME_COVERED.to_string(),
            _ => text::DECOY_IDLE.to_string(),
        };
        let mut page = Page {
            description,
            facts: self.volume_fact(status),
            ..Page::default()
        };
        match &self.check {
            Check::NotRun | Check::Running(_) => {
                page.heading = text::CHECKING.to_string();
                page.busy = Some(text::CHECKING.to_string());
                if let Check::Running(rows) = &self.check {
                    page.checks.clone_from(rows);
                }
                page.fix = fix;
            }
            Check::Done(report) => {
                page.heading = if report.ready {
                    text::READY
                } else {
                    text::NOT_READY
                }
                .to_string();
                if !report.ready {
                    page.note = text::problems(report.summary.failed);
                }
                page.facts.push((
                    text::FACT_THIS_COMPUTER.to_string(),
                    text::checks_passed(report.summary.passed),
                ));
                page.facts.extend(
                    self.allowed
                        .iter()
                        .map(|risk| (text::FACT_ALLOWED.to_string(), risk.what().to_string())),
                );
                page.checks = report_rows(report, &self.allowed);
                page.fix = fix;
                page.action = Some(if report.ready {
                    text::ACTIVATE
                } else {
                    text::CHECK_AGAIN
                });
                page.links = self.links(Place::Decoy);
            }
            Check::Failed(error) => {
                page.heading = text::CHECK_FAILED.to_string();
                page.note = text::sentence(&error.message);
                let next = error
                    .next
                    .as_ref()
                    .map(|next| text::next_step(self.engine.as_deref(), &next.command))
                    .unwrap_or_default();
                page.fix = join(&fix, &next);
                page.action = Some(text::CHECK_AGAIN);
                page.links = self.links(Place::Decoy);
            }
        }
        page
    }

    pub(super) fn hidden_page(&self, status: &StatusData) -> Page {
        let fix = status.remediation.as_deref().map(text::engine_fix);
        let root = status.hidden_root.clone().unwrap_or_default();
        match status.attention {
            Some(Attention::NoWayBack) => Page {
                heading: text::NO_WAY_BACK.to_string(),
                description: text::HIDDEN_NO_WAY_BACK.to_string(),
                note: status
                    .reason
                    .as_deref()
                    .map(text::no_way_back_reason)
                    .unwrap_or_default(),
                urgent: true,
                fix: text::HOLD_POWER_BUTTON.to_string(),
                ..Page::default()
            },
            Some(Attention::VolumeCovered) => Page {
                heading: text::HIDDEN_SESSION.to_string(),
                description: text::hidden_volume_covered(status.uptime_seconds, &root),
                facts: self.volume_fact(status),
                fix: fix.unwrap_or_default(),
                action: Some(text::DEACTIVATE),
                links: self.links(Place::Hidden),
                ..Page::default()
            },
            attention => Page {
                heading: text::HIDDEN_SESSION.to_string(),
                description: text::hidden_active(status.uptime_seconds),
                note: match attention {
                    None => String::new(),
                    Some(_) => status
                        .reason
                        .as_deref()
                        .map(text::sentence)
                        .unwrap_or_default(),
                },
                facts: self.volume_fact(status),
                fix: fix.unwrap_or_default(),
                // Without the hidden volume the way back has nothing to
                // return with: the session ends with an emergency. Nor can a
                // tool reach it.
                action: (attention != Some(Attention::VolumeLost)).then_some(text::DEACTIVATE),
                links: if attention == Some(Attention::VolumeLost) {
                    Vec::new()
                } else {
                    self.links(Place::Hidden)
                },
                ..Page::default()
            },
        }
    }

    pub(super) fn record_unreadable_page(
        &self,
        status: Option<&StatusData>,
        error: Option<&ErrorBody>,
    ) -> Page {
        let fix = status
            .and_then(|status| status.remediation.as_deref())
            .map(text::engine_fix)
            .or_else(|| {
                error
                    .and_then(|error| error.next.as_ref())
                    .map(|next| text::next_step(self.engine.as_deref(), &next.command))
            })
            .unwrap_or_default();
        // Only a status of the decoy, which shows no session is active, can
        // be the reason to reset the record. Reset Record runs `recover`,
        // which asks nothing, as the CLI's does: the page says what it does
        // in place of the command a terminal would run.
        let on_the_decoy = status.is_some_and(|status| status.place == Place::Decoy);
        let fix = if on_the_decoy {
            text::RESET_RECORD_WHAT.to_string()
        } else {
            fix
        };
        Page {
            heading: text::RECORD_UNREADABLE.to_string(),
            description: text::DECOY_RECORD_UNREADABLE.to_string(),
            note: error
                .map(|error| text::sentence(&error.message))
                .unwrap_or_default(),
            busy: (on_the_decoy && self.running == Some(Kind::Recover))
                .then(|| text::RESETTING_RECORD.to_string()),
            facts: status
                .map(|status| self.volume_fact(status))
                .unwrap_or_default(),
            fix,
            action: on_the_decoy.then_some(text::RESET_RECORD),
            ..Page::default()
        }
    }

    pub(super) fn unreadable_page(&self, why: &str) -> Page {
        Page {
            heading: text::UNREADABLE.to_string(),
            description: "NAILS answered in a way this window cannot read.".to_string(),
            note: text::sentence(why),
            urgent: true,
            fix: text::MISMATCH_FIX.to_string(),
            ..Page::default()
        }
    }

    pub(super) fn failure_page(&self, failure: &Failure) -> Page {
        let binary = self.engine.as_deref();
        let (heading, description, note, fix) = match failure {
            Failure::Mismatch { window, engine } => (
                text::MISMATCH,
                text::mismatch(window, engine),
                text::NOTHING_CHANGED.to_string(),
                text::MISMATCH_FIX.to_string(),
            ),
            Failure::Refused(error) => (
                text::REFUSED,
                text::sentence(&error.message),
                text::NOTHING_CHANGED.to_string(),
                text::open_from_terminal(binary),
            ),
            Failure::Lost { in_flight } => (
                text::LOST,
                text::LOST_WHY.to_string(),
                if *in_flight {
                    text::LOST_IN_FLIGHT
                } else {
                    text::NOTHING_CHANGED
                }
                .to_string(),
                text::open_from_terminal(binary),
            ),
            Failure::Unreadable(why) => return self.unreadable_page(why),
            Failure::PasswordDismissed | Failure::PasswordUnavailable => (
                text::PASSWORD_NEEDED,
                text::PASSWORD_NEEDED_WHY.to_string(),
                String::new(),
                text::open_from_terminal(binary),
            ),
            Failure::NotStarted(why) => (
                text::NOT_STARTED,
                format!(
                    "The window could not start its controls: {}",
                    text::sentence(why)
                ),
                text::NOTHING_CHANGED.to_string(),
                text::open_from_terminal(binary),
            ),
        };
        Page {
            heading: heading.to_string(),
            description,
            note,
            urgent: true,
            fix,
            ..Page::default()
        }
    }

    pub(super) fn volume_fact(&self, status: &StatusData) -> Vec<(String, String)> {
        status
            .hidden_root
            .as_ref()
            .map(|root| vec![(text::FACT_HIDDEN_VOLUME.to_string(), root.clone())])
            .unwrap_or_default()
    }
}

/// What a recovery's envelope `value` says it did, or why it did not run, as
/// the line the page shows over the status that follows.
pub(super) fn recovered(value: &serde_json::Value) -> String {
    let data = match envelope::read::<RecoverData>(value, "recover") {
        Ok(envelope) => match (envelope.data, envelope.error) {
            (Some(data), _) => data,
            (None, Some(error)) => return text::sentence(&error.message),
            (None, None) => return text::NOTHING_CHANGED.to_string(),
        },
        Err(error) => return text::sentence(&error.0),
    };
    let mut lines = vec![
        match data.outcome.as_str() {
            "rolled_back" => text::CLEANED_UP,
            "record_reset" => text::RECORD_RESET,
            _ => text::NOTHING_TO_CLEAN_UP,
        }
        .to_string(),
    ];
    if !data.remaining_mounts.is_empty() {
        lines.push(text::mounts_stayed(&data.remaining_mounts));
    }
    if data.backend.iter().any(|device| device.state == "in_use") {
        lines.push(text::DEVICE_IN_USE.to_string());
    }
    lines.join("\n")
}

/// The checks a finished report shows: the failures with their fixes first,
/// then the warnings. The passed ones are counted, not listed. A failure the
/// person can allow for one activation, and has not, offers that.
fn report_rows(report: &Readiness, allowed: &BTreeSet<Risk>) -> Vec<CheckView> {
    let row = |status: CheckStatus, outcome: CheckOutcome| {
        report
            .checks
            .iter()
            .filter(move |row| row.status == status)
            .map(move |row| CheckView {
                outcome,
                word: text::outcome_word(outcome).to_string(),
                message: text::sentence(&row.message),
                fix: row
                    .remediation
                    .as_deref()
                    .map(|fix| format!("Fix: {}", text::engine_fix(fix)))
                    .unwrap_or_default(),
                allow: Risk::of_check(&row.name)
                    .filter(|risk| outcome == CheckOutcome::Fail && !allowed.contains(risk)),
            })
    };
    row(CheckStatus::Fail, CheckOutcome::Fail)
        .chain(row(CheckStatus::Warn, CheckOutcome::Warn))
        .collect()
}

/// The page once the emergency fired: the session ends, and nothing is to
/// read or answer but the way out that needs neither the window nor NAILS.
pub(super) fn ending_now_page() -> Page {
    Page {
        heading: text::ENDING.to_string(),
        description: text::EMERGENCY_NOW.to_string(),
        urgent: true,
        fix: text::POWER_BUTTON_IF_STILL_ON.to_string(),
        no_input: true,
        ..Page::default()
    }
}

pub(super) fn busy_page(heading: &str, description: &str) -> Page {
    Page {
        heading: heading.to_string(),
        description: description.to_string(),
        busy: Some(heading.to_string()),
        ..Page::default()
    }
}

/// Two lines as one text, either of them possibly empty.
pub(super) fn join(first: &str, second: &str) -> String {
    match (first.is_empty(), second.is_empty()) {
        (true, _) => second.to_string(),
        (_, true) => first.to_string(),
        _ => format!("{first}\n{second}"),
    }
}
