// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The page the window shows, worked out from what the worker reports.
//!
//! The [`Model`] keeps nothing of its own over a session: everything it
//! shows comes from the engine's answers (`status`, `check`) and the events
//! of the request that runs. It takes each [`Update`] and returns the asks
//! that follow from it (a status once the handshake passed, a check once a
//! decoy's status came in), and [`Model::page`] says what to draw.
//!
//! The decoy's page is the check, which runs when the window opens and on
//! Check Again; a hidden session's page is its status. Anything that ends
//! the session gets a page of its own that says what happened, what was not
//! changed and what fixes it.
//!
//! An operation the engine confirms first goes through [`Model::plan`]: the
//! screen that asks for it gives the [`Asker`] that words the question once
//! the plan holds, and [`Model::answer`] turns the person's answer into the
//! apply or the withdrawal.

use std::path::PathBuf;

use nails_api::CheckOutcome;
use nails_api::Event;
use nails_api::protocol::CheckArgs;

use crate::client::{Plan, PlanData};
use crate::envelope::{self, Attention, CheckStatus, ErrorBody, Place, Readiness, StatusData};
use crate::text;
use crate::worker::{Ask, Failure, Kind, Update};

/// One check as a page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckView {
    /// How it came out.
    pub outcome: CheckOutcome,
    /// That outcome as a word.
    pub word: String,
    /// The check's sentence.
    pub message: String,
    /// What fixes it, when it failed and the engine says.
    pub fix: String,
}

/// The question a plan asks before its apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// Its title.
    pub heading: String,
    /// What it asks about.
    pub body: String,
    /// The label of the button that applies the plan.
    pub confirm: String,
    /// Whether that button destroys something.
    pub destructive: bool,
}

/// What a screen that asks for a plan says once the plan holds.
pub type Asker = fn(&PlanData) -> Question;

/// The page the window draws.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Page {
    /// The verdict.
    pub heading: String,
    /// Where things stand.
    pub description: String,
    /// A line more under it, when there is one.
    pub note: String,
    /// The heading names an error, to be announced at once.
    pub urgent: bool,
    /// What runs, while something does.
    pub busy: Option<String>,
    /// Facts, a title and a value each.
    pub facts: Vec<(String, String)>,
    /// Checks.
    pub checks: Vec<CheckView>,
    /// The line that names the fix or the next step.
    pub fix: String,
    /// The label of the main action, when there is one.
    pub action: Option<&'static str>,
    /// The question of a plan that waits for an answer.
    pub question: Option<Question>,
}

#[derive(Debug, Clone, PartialEq)]
enum Stage {
    Starting,
    WaitingForPassword,
    Connected,
    Unreadable(String),
    Ended(Failure),
}

#[derive(Debug, Clone, PartialEq)]
enum Check {
    NotRun,
    Running(Vec<CheckView>),
    Done(Readiness),
    Failed(ErrorBody),
}

/// What the window knows of the session.
#[derive(Debug, Clone)]
pub struct Model {
    engine: Option<PathBuf>,
    stage: Stage,
    status: Option<StatusData>,
    status_error: Option<ErrorBody>,
    check: Check,
    running: Option<Kind>,
    asker: Option<Asker>,
    question: Option<Question>,
    notice: Option<String>,
}

impl Model {
    /// A window for `engine` (when known: the pages name it in the lines
    /// they give), which `waits_for_password` while pkexec asks for it.
    #[must_use]
    pub fn new(engine: Option<PathBuf>, waits_for_password: bool) -> Self {
        Self {
            engine,
            stage: if waits_for_password {
                Stage::WaitingForPassword
            } else {
                Stage::Starting
            },
            status: None,
            status_error: None,
            check: Check::NotRun,
            running: None,
            asker: None,
            question: None,
            notice: None,
        }
    }

    /// Take in `update` and return the asks that follow from it.
    pub fn apply(&mut self, update: Update) -> Vec<Ask> {
        match update {
            Update::Connected(_) => {
                self.stage = Stage::Connected;
                vec![Ask::Status]
            }
            Update::Running(kind) => {
                self.running = Some(kind);
                if kind == Kind::Check {
                    self.check = Check::Running(Vec::new());
                }
                Vec::new()
            }
            Update::Event(event) => {
                self.event(event);
                Vec::new()
            }
            Update::Answered(kind, answer) => {
                self.running = None;
                self.answered(kind, &answer.envelope)
            }
            Update::Planned(data) => {
                self.running = None;
                match self.asker.take() {
                    Some(asker) => {
                        self.question = Some(asker(&data));
                        Vec::new()
                    }
                    // No screen waits for this plan: drop it at once.
                    None => vec![Ask::Withdraw],
                }
            }
            Update::Withdrawn => {
                self.running = None;
                self.question = None;
                Vec::new()
            }
            Update::Ended(failure) => {
                self.running = None;
                self.question = None;
                self.stage = Stage::Ended(failure);
                Vec::new()
            }
        }
    }

    /// Ask for `plan`, whose question `asker` words once the plan holds.
    pub fn plan(&mut self, plan: Plan, asker: Asker) -> Ask {
        self.asker = Some(asker);
        self.notice = None;
        Ask::Plan(plan)
    }

    /// The person's answer to the question that waits: the apply, or the
    /// withdrawal.
    pub fn answer(&mut self, confirmed: bool) -> Ask {
        self.question = None;
        if confirmed { Ask::Apply } else { Ask::Withdraw }
    }

    /// What the main action asks for, while the page has one.
    #[must_use]
    pub fn action(&self) -> Option<Ask> {
        (self.page().action == Some(text::CHECK_AGAIN)).then(|| Ask::Check(CheckArgs::default()))
    }

    /// Whether the window should close by itself: the person dismissed the
    /// password dialog, which is a cancel.
    #[must_use]
    pub fn quits(&self) -> bool {
        self.stage == Stage::Ended(Failure::PasswordDismissed)
    }

    fn event(&mut self, event: Event) {
        if let (
            Check::Running(rows),
            Event::Check {
                outcome, message, ..
            },
        ) = (&mut self.check, event)
        {
            rows.push(CheckView {
                outcome,
                word: text::outcome_word(outcome).to_string(),
                message: text::sentence(&message),
                fix: String::new(),
            });
        }
    }

    fn answered(&mut self, kind: Kind, value: &serde_json::Value) -> Vec<Ask> {
        match kind {
            Kind::Status => match envelope::read::<StatusData>(value, "status") {
                Ok(envelope) => {
                    self.status = envelope.data;
                    self.status_error = envelope.error;
                    let check = self.check == Check::NotRun
                        && self.status.as_ref().is_some_and(checks_on_open);
                    if check {
                        vec![Ask::Check(CheckArgs::default())]
                    } else {
                        Vec::new()
                    }
                }
                Err(error) => {
                    self.stage = Stage::Unreadable(error.0);
                    Vec::new()
                }
            },
            Kind::Check => {
                match envelope::read::<Readiness>(value, "check") {
                    Ok(envelope) => {
                        self.check = match (envelope.data, envelope.error) {
                            (Some(report), _) => Check::Done(report),
                            (None, error) => Check::Failed(error.unwrap_or_else(|| ErrorBody {
                                code: "check".to_string(),
                                message: "the check gave no result".to_string(),
                                next: None,
                            })),
                        };
                    }
                    Err(error) => self.stage = Stage::Unreadable(error.0),
                }
                Vec::new()
            }
            Kind::Plan | Kind::Apply => {
                self.question = None;
                self.notice = value["error"]["message"].as_str().map(text::sentence);
                vec![Ask::Status]
            }
        }
    }

    /// The page to draw now.
    #[must_use]
    pub fn page(&self) -> Page {
        let mut page = match &self.stage {
            Stage::Starting => busy_page(text::STARTING, ""),
            Stage::WaitingForPassword => {
                busy_page(text::WAITING_FOR_PASSWORD, text::WAITING_FOR_PASSWORD_WHY)
            }
            Stage::Unreadable(why) => self.unreadable_page(why),
            Stage::Ended(failure) => self.failure_page(failure),
            Stage::Connected => self.session_page(),
        };
        if let Some(notice) = &self.notice {
            page.note = join(notice, &page.note);
        }
        if self.running.is_some() && page.busy.is_none() {
            page.action = None;
        }
        page.question.clone_from(&self.question);
        page
    }

    fn session_page(&self) -> Page {
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
    fn status_failed_page(&self, error: &ErrorBody) -> Page {
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
    fn place_unknown_page(&self, error: Option<&ErrorBody>) -> Page {
        Page {
            description: text::PLACE_UNKNOWN.to_string(),
            ..self.record_unreadable_page(None, error)
        }
    }

    fn decoy_page(&self, status: &StatusData) -> Page {
        let fix = status
            .remediation
            .as_deref()
            .map(text::engine_fix)
            .unwrap_or_default();
        let description = match status.attention {
            Some(Attention::Interrupted) => {
                return Page {
                    heading: text::INTERRUPTED.to_string(),
                    description: text::DECOY_INTERRUPTED.to_string(),
                    facts: self.volume_fact(status),
                    fix,
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
                page.checks = report_rows(report);
                let next = if report.ready {
                    text::activate_from_terminal(self.engine.as_deref())
                } else {
                    String::new()
                };
                page.fix = join(&fix, &next);
                page.action = Some(text::CHECK_AGAIN);
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
            }
        }
        page
    }

    fn hidden_page(&self, status: &StatusData) -> Page {
        let fix = status.remediation.as_deref().map(text::engine_fix);
        let root = status.hidden_root.clone().unwrap_or_default();
        match status.attention {
            Some(Attention::NoWayBack) => Page {
                heading: text::NO_WAY_BACK.to_string(),
                description: text::hidden_no_way_back(status.reason.as_deref()),
                urgent: true,
                fix: text::HOLD_POWER_BUTTON.to_string(),
                ..Page::default()
            },
            Some(Attention::VolumeCovered) => Page {
                heading: text::HIDDEN_SESSION.to_string(),
                description: text::hidden_volume_covered(status.uptime_seconds, &root),
                facts: self.volume_fact(status),
                fix: fix.unwrap_or_default(),
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
                fix: fix.unwrap_or_else(|| text::deactivate_from_terminal(self.engine.as_deref())),
                ..Page::default()
            },
        }
    }

    fn record_unreadable_page(
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
        Page {
            heading: text::RECORD_UNREADABLE.to_string(),
            description: text::DECOY_RECORD_UNREADABLE.to_string(),
            note: error
                .map(|error| text::sentence(&error.message))
                .unwrap_or_default(),
            facts: status
                .map(|status| self.volume_fact(status))
                .unwrap_or_default(),
            fix,
            ..Page::default()
        }
    }

    fn unreadable_page(&self, why: &str) -> Page {
        Page {
            heading: text::UNREADABLE.to_string(),
            description: "NAILS answered in a way this window cannot read.".to_string(),
            note: text::sentence(why),
            urgent: true,
            fix: text::MISMATCH_FIX.to_string(),
            ..Page::default()
        }
    }

    fn failure_page(&self, failure: &Failure) -> Page {
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

    fn volume_fact(&self, status: &StatusData) -> Vec<(String, String)> {
        status
            .hidden_root
            .as_ref()
            .map(|root| vec![(text::FACT_HIDDEN_VOLUME.to_string(), root.clone())])
            .unwrap_or_default()
    }
}

/// Whether the decoy's page is its check: not while an interrupted
/// activation or an unreadable record waits to be dealt with first.
fn checks_on_open(status: &StatusData) -> bool {
    status.place == Place::Decoy
        && !matches!(
            status.attention,
            Some(Attention::Interrupted | Attention::RecordUnreadable)
        )
}

/// The checks a finished report shows: the failures with their fixes first,
/// then the warnings. The passed ones are counted, not listed.
fn report_rows(report: &Readiness) -> Vec<CheckView> {
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
            })
    };
    row(CheckStatus::Fail, CheckOutcome::Fail)
        .chain(row(CheckStatus::Warn, CheckOutcome::Warn))
        .collect()
}

fn busy_page(heading: &str, description: &str) -> Page {
    Page {
        heading: heading.to_string(),
        description: description.to_string(),
        busy: Some(heading.to_string()),
        ..Page::default()
    }
}

/// Two lines as one text, either of them possibly empty.
fn join(first: &str, second: &str) -> String {
    match (first.is_empty(), second.is_empty()) {
        (true, _) => second.to_string(),
        (_, true) => first.to_string(),
        _ => format!("{first}\n{second}"),
    }
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
