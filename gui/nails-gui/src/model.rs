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
//! Check Again; once it passed, its action activates ([`activation`]). An
//! interrupted activation and a record that cannot be read come first, each
//! with the one action that deals with it, Clean Up and Reset Record (both
//! `nails recover`), after which the status and the check run again. A
//! hidden session's page is its status, whose action deactivates
//! ([`deactivation`]). Anything that ends the session gets a page of its own
//! that says what happened, what was not changed and what fixes it.
//!
//! An operation the engine confirms first goes through a plan: the screen
//! that asks for it gives the [`Asker`] that words the question once the plan
//! holds ([`Model::plan`]), and [`Model::answer`] turns the person's answer
//! into the apply or the withdrawal. An activation and a deactivation are
//! such operations too, whose questions the model words itself; a
//! deactivation's offers a second action ([`Model::alternative`]).

use std::collections::BTreeSet;
use std::path::PathBuf;

use nails_api::CheckOutcome;
use nails_api::Event;

use crate::client::{Plan, PlanData};
use crate::envelope::{self, Attention, ErrorBody, Place, Readiness, StatusData};
use crate::text;
use crate::worker::{Ask, Failure, Kind, Update};

pub mod activation;
pub mod deactivation;
mod pages;

use activation::{Activation, Outcome, Risk};
use deactivation::{Applied, Deactivation, Ending};
use pages::{busy_page, join, recovered};

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
    /// The risk the person can allow for one activation instead, when the
    /// check refused one.
    pub allow: Option<Risk>,
}

/// One step of an activation as its page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepView {
    /// What the step does.
    pub label: String,
    /// Done, or now.
    pub state: &'static str,
}

/// The question a plan, or a risk to allow, asks first.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Question {
    /// Its title.
    pub heading: String,
    /// What it asks about.
    pub body: String,
    /// The label of the button that confirms it.
    pub confirm: String,
    /// Whether that button destroys something or takes a risk.
    pub destructive: bool,
    /// The prompt of a word to type before the button acts, when the
    /// question asks for one.
    pub prompt: Option<String>,
    /// Whether the button waits for that word still.
    pub locked: bool,
    /// The label of a second action beside the confirming one, when the
    /// question offers two (a deactivation's two endings).
    pub alternative: Option<String>,
}

/// What a screen that asks for a plan says once the plan holds.
pub type Asker = fn(&PlanData) -> Question;

/// How the main action looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ActionKind {
    /// The page's suggested next step.
    #[default]
    Suggested,
    /// A plain button (Cancel).
    Plain,
}

/// The page the window draws.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Page {
    /// The verdict.
    pub heading: String,
    /// Where things stand.
    pub description: String,
    /// A line more under it, when there is one.
    pub note: String,
    /// The heading is announced at once: an error, or the logout.
    pub urgent: bool,
    /// What runs, while something does.
    pub busy: Option<String>,
    /// Facts, a title and a value each.
    pub facts: Vec<(String, String)>,
    /// The steps of an activation.
    pub steps: Vec<StepView>,
    /// Checks.
    pub checks: Vec<CheckView>,
    /// The line that names the fix or the next step.
    pub fix: String,
    /// The label of the main action, when there is one.
    pub action: Option<&'static str>,
    /// How the main action looks.
    pub action_kind: ActionKind,
    /// The page takes no input at all, not even the window's Close.
    pub no_input: bool,
    /// The question that waits for an answer.
    pub question: Option<Question>,
}

/// What the window does for a control the person used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Hand the worker this ask.
    Ask(Ask),
    /// Shut the window's writing half of the pipe: the helper reads the
    /// window as gone, which cancels an activation before its point of no
    /// return. The session ends with the answer that follows.
    HangUp,
}

#[derive(Debug, Clone, PartialEq)]
enum Stage {
    Starting,
    WaitingForPassword,
    Connected,
    Unreadable(String),
    Ended(Failure),
    /// The window hung up and the helper gave its last answer.
    Over(Box<Page>),
}

#[derive(Debug, Clone, PartialEq)]
enum Check {
    NotRun,
    Running(Vec<CheckView>),
    Done(Readiness),
    Failed(ErrorBody),
}

/// What a plan was asked for.
#[derive(Debug, Clone, Copy)]
enum PlanFor {
    /// A screen, which words its question.
    Screen(Asker),
    /// The activation.
    Activation,
    /// A deactivation, whose question offers both endings.
    Deactivation,
}

/// What the open question asks.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Asking {
    /// Whether to apply the plan that holds.
    Plan,
    /// Whether to allow `risk` for one activation; `typed` so far.
    Allow { risk: Risk, typed: String },
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
    plan_for: Option<PlanFor>,
    asking: Option<Asking>,
    question: Option<Question>,
    notice: Option<String>,
    allowed: BTreeSet<Risk>,
    activation: Option<Activation>,
    deactivation: Option<Deactivation>,
    hung_up: bool,
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
            plan_for: None,
            asking: None,
            question: None,
            notice: None,
            allowed: BTreeSet::new(),
            activation: None,
            deactivation: None,
            hung_up: false,
        }
    }

    /// Take in `update` and return the asks that follow from it.
    pub fn apply(&mut self, update: Update) -> Vec<Ask> {
        if matches!(self.stage, Stage::Over(_)) {
            // The window hung up and has its answer: nothing comes after it.
            return Vec::new();
        }
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
                self.event(&event);
                Vec::new()
            }
            Update::Answered(kind, answer) => {
                self.running = None;
                self.answered(kind, &answer.envelope)
            }
            Update::Planned(data) => {
                self.running = None;
                self.planned(&data)
            }
            Update::Withdrawn => {
                self.running = None;
                self.close_question();
                let activation = matches!(self.plan_for, Some(PlanFor::Activation));
                self.plan_for = None;
                // An activation or a deactivation whose plan was gone never
                // started, and what was allowed for an activation goes with
                // it: the check that ran with it runs again from the status.
                if matches!(self.activation, Some(Activation::Running { .. })) {
                    self.activation = None;
                }
                self.deactivation = None;
                if activation && self.forget_allowed() {
                    return vec![Ask::Status];
                }
                Vec::new()
            }
            Update::Ended(failure) => {
                self.running = None;
                if matches!(self.activation, Some(Activation::PastThePoint))
                    || matches!(self.deactivation, Some(Deactivation::Ending { .. }))
                {
                    // The switch ends the session with the decoy's, or with
                    // the hidden one: the page stays as it is.
                    return Vec::new();
                }
                self.close_question();
                self.stage = Stage::Ended(failure);
                Vec::new()
            }
        }
    }

    /// Ask for `plan`, whose question `asker` words once the plan holds.
    pub fn plan(&mut self, plan: Plan, asker: Asker) -> Ask {
        self.plan_for = Some(PlanFor::Screen(asker));
        self.notice = None;
        Ask::Plan(plan)
    }

    /// The person's answer to the question that waits: the apply or the
    /// withdrawal of a plan, or the check that follows a risk allowed.
    pub fn answer(&mut self, confirmed: bool) -> Option<Ask> {
        self.question = None;
        match self.asking.take() {
            Some(Asking::Allow { risk, typed }) => {
                if !(confirmed && activation::is_the_word(&typed)) {
                    return None;
                }
                self.allowed.insert(risk);
                Some(Ask::Check(activation::check_args(&self.allowed)))
            }
            Some(Asking::Plan) | None => {
                let activation = matches!(self.plan_for, Some(PlanFor::Activation));
                if !confirmed {
                    // The status that follows a withdrawal runs the check
                    // again, without what was allowed for this activation.
                    if activation {
                        self.forget_allowed();
                    }
                    return Some(Ask::Withdraw);
                }
                if activation {
                    self.activation = Some(Activation::started());
                }
                if matches!(self.plan_for, Some(PlanFor::Deactivation)) {
                    // Power Off, on the plan of a return: the plan of a
                    // power-off replaces it, and is applied once it holds.
                    self.deactivation = Some(Deactivation::Replanning);
                    return Some(Ask::Plan(Plan::Deactivate(Ending::PowerOff.args())));
                }
                Some(Ask::Apply)
            }
        }
    }

    /// The person chose the open question's second action: a deactivation's
    /// return to the decoy, which applies the plan that holds.
    pub fn alternative(&mut self) -> Option<Ask> {
        let offered = self
            .question
            .as_ref()
            .is_some_and(|question| question.alternative.is_some());
        if !offered || !matches!(self.plan_for, Some(PlanFor::Deactivation)) {
            return None;
        }
        self.close_question();
        self.deactivation = Some(Deactivation::ending(Ending::Return));
        Some(Ask::Apply)
    }

    /// What the page's main action does, while the page has one.
    pub fn action(&mut self) -> Option<Effect> {
        match self.page().action? {
            text::CHECK_AGAIN => Some(Effect::Ask(Ask::Check(activation::check_args(
                &self.allowed,
            )))),
            text::ACTIVATE => {
                self.plan_for = Some(PlanFor::Activation);
                self.notice = None;
                Some(Effect::Ask(Ask::Plan(Plan::Activate(
                    activation::activate_args(&self.allowed),
                ))))
            }
            text::DEACTIVATE => {
                // The plan of a return names what the return would not put
                // back, which the question shows beside both endings.
                self.plan_for = Some(PlanFor::Deactivation);
                self.notice = None;
                Some(Effect::Ask(Ask::Plan(Plan::Deactivate(
                    Ending::Return.args(),
                ))))
            }
            text::CANCEL => self.cancel(),
            text::CLEAN_UP | text::RESET_RECORD => {
                self.notice = None;
                Some(Effect::Ask(Ask::Recover))
            }
            _ => None,
        }
    }

    /// What Escape does on the page: it cancels an activation before its
    /// point of no return, and nothing else.
    pub fn escape(&mut self) -> Option<Effect> {
        if self.question.is_some() {
            return None;
        }
        self.cancel()
    }

    /// Ask whether to allow, for one activation, the risk the check of row
    /// `index` refused.
    pub fn allow(&mut self, index: usize) {
        if self.question.is_some() {
            return;
        }
        let page = self.page();
        let Some(check) = page.checks.get(index) else {
            return;
        };
        let Some(risk) = check.allow else {
            return;
        };
        self.asking = Some(Asking::Allow {
            risk,
            typed: String::new(),
        });
        self.question = Some(activation::allow_question(&check.message, true));
    }

    /// What the person typed so far into the open question's field.
    pub fn typed(&mut self, typed: &str) {
        if let Some(Asking::Allow { typed: so_far, .. }) = &mut self.asking {
            typed.clone_into(so_far);
            if let Some(question) = &mut self.question {
                question.locked = !activation::is_the_word(typed);
            }
        }
    }

    /// Whether the window should close by itself: the person dismissed the
    /// password dialog, which is a cancel.
    #[must_use]
    pub fn quits(&self) -> bool {
        self.stage == Stage::Ended(Failure::PasswordDismissed)
    }

    fn cancel(&mut self) -> Option<Effect> {
        let activation = self.activation.as_mut()?;
        if !activation.cancel() {
            return None;
        }
        self.hung_up = true;
        Some(Effect::HangUp)
    }

    fn close_question(&mut self) {
        self.question = None;
        self.asking = None;
    }

    /// Forget the risks allowed, which hold for one activation: it was
    /// answered or withdrawn, or a recovery ran. A check that ran with them
    /// no longer stands, so it runs again once a status is in. Whether
    /// anything was allowed.
    fn forget_allowed(&mut self) -> bool {
        if self.allowed.is_empty() {
            return false;
        }
        self.allowed.clear();
        self.check = Check::NotRun;
        true
    }

    fn event(&mut self, event: &Event) {
        if let Some(activation) = &mut self.activation {
            activation.event(event);
            return;
        }
        if let (
            Check::Running(rows),
            Event::Check {
                outcome, message, ..
            },
        ) = (&mut self.check, event)
        {
            rows.push(CheckView {
                outcome: *outcome,
                word: text::outcome_word(*outcome).to_string(),
                message: text::sentence(message),
                fix: String::new(),
                allow: None,
            });
        }
    }

    fn planned(&mut self, data: &PlanData) -> Vec<Ask> {
        let question = match (self.plan_for, data) {
            (Some(PlanFor::Activation), PlanData::Activate(plan)) => {
                let in_decoy_home = match &self.check {
                    Check::Done(report) => report.in_decoy_home(),
                    _ => false,
                };
                activation::activate_question(plan, &self.allowed, in_decoy_home)
            }
            (Some(PlanFor::Deactivation), PlanData::Deactivate(plan)) => {
                if self.deactivation == Some(Deactivation::Replanning) && plan.poweroff {
                    // The person chose to power off already.
                    self.deactivation = Some(Deactivation::ending(Ending::PowerOff));
                    return vec![Ask::Apply];
                }
                if self.deactivation.is_some() || plan.poweroff {
                    // Not the plan the window asked for: drop it.
                    self.deactivation = None;
                    self.plan_for = None;
                    return vec![Ask::Withdraw];
                }
                deactivation::question(plan)
            }
            (Some(PlanFor::Screen(asker)), data) => asker(data),
            // No screen waits for this plan: drop it at once.
            _ => {
                self.plan_for = None;
                return vec![Ask::Withdraw];
            }
        };
        self.asking = Some(Asking::Plan);
        self.question = Some(question);
        Vec::new()
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
                        vec![Ask::Check(activation::check_args(&self.allowed))]
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
            Kind::Recover => {
                self.notice = Some(recovered(value));
                // What it left is the status's to say, and then the check's,
                // which runs without anything allowed before.
                self.forget_allowed();
                self.check = Check::NotRun;
                vec![Ask::Status]
            }
            Kind::Apply if matches!(self.plan_for, Some(PlanFor::Activation)) => {
                self.plan_for = None;
                self.close_question();
                self.activation_answered(value)
            }
            Kind::Apply if matches!(self.plan_for, Some(PlanFor::Deactivation)) => {
                self.plan_for = None;
                self.close_question();
                match deactivation::applied(value) {
                    Applied::Enqueued(enqueued) => {
                        self.deactivation = Some(enqueued);
                        Vec::new()
                    }
                    Applied::Failed(message) => {
                        self.deactivation = None;
                        self.notice = (!message.is_empty()).then_some(message);
                        vec![Ask::Status]
                    }
                }
            }
            Kind::Plan | Kind::Apply => {
                self.plan_for = None;
                self.close_question();
                // A plan that settled instead of holding switches nothing.
                self.deactivation = None;
                self.notice = value["error"]["message"].as_str().map(text::sentence);
                vec![Ask::Status]
            }
        }
    }

    /// The helper's answer to an activation's apply.
    fn activation_answered(&mut self, value: &serde_json::Value) -> Vec<Ask> {
        // Whatever it says, what was allowed held for this activation only.
        self.forget_allowed();
        let outcome = activation::outcome(value);
        if outcome == Outcome::Entering {
            // The switch is under way: Logging Out, whether the point of no
            // return was heard or not.
            self.activation = Some(Activation::PastThePoint);
            return Vec::new();
        }
        self.activation = None;
        if self.hung_up {
            self.stage = Stage::Over(Box::new(activation::over_page(
                &outcome,
                self.engine.as_deref(),
            )));
            return Vec::new();
        }
        self.notice = match outcome {
            Outcome::Failed(message) | Outcome::Cancelled(message) if !message.is_empty() => {
                Some(message)
            }
            _ => None,
        };
        // Whatever stopped it, the page checks again from the status.
        self.check = Check::NotRun;
        vec![Ask::Status]
    }

    /// The page to draw now.
    #[must_use]
    pub fn page(&self) -> Page {
        let mut page = match &self.stage {
            Stage::Over(page) => return (**page).clone(),
            Stage::Starting => busy_page(text::STARTING, ""),
            Stage::WaitingForPassword => {
                busy_page(text::WAITING_FOR_PASSWORD, text::WAITING_FOR_PASSWORD_WHY)
            }
            Stage::Unreadable(why) => self.unreadable_page(why),
            Stage::Ended(failure) => self.failure_page(failure),
            Stage::Connected => match (&self.activation, self.deactivation) {
                (Some(activation), _) => activation.page(),
                (None, Some(deactivation)) => deactivation.page(),
                (None, None) => self.session_page(),
            },
        };
        if let Some(notice) = &self.notice {
            page.note = join(notice, &page.note);
        }
        // Nothing to press while a request runs, but the Cancel of the
        // activation that runs.
        if self.running.is_some() && page.action != Some(text::CANCEL) {
            page.action = None;
        }
        page.question.clone_from(&self.question);
        page
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

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "model_activation_tests.rs"]
mod activation_tests;

#[cfg(test)]
#[path = "model_recover_tests.rs"]
mod recover_tests;

#[cfg(test)]
#[path = "model_deactivation_tests.rs"]
mod deactivation_tests;
