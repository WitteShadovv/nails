// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Activating from the window: a risk allowed for one activation, the
//! question before it, the steps as they stream, the point of no return and
//! what the window shows after it.
//!
//! - **A risk allowed for one activation.** A problem the CLI lets the person
//!   allow with a flag (`--allow-persistent-decoy`) gets "Allow for This
//!   Activation…" under it. That opens a question whose button acts only
//!   once the person typed the word it shows: allowing a risk is never one
//!   click. The window then checks again with the flag, names the risk on the
//!   page and in the question before the activation, and gives the flag to
//!   that activation. Once its apply is answered or its plan withdrawn, or a
//!   recovery ran, the window forgets the risk and checks again without the
//!   flag. Nothing is stored. No decoy reaches this yet: the launcher's gate
//!   refuses a decoy that keeps a persistent record before the window opens,
//!   so only a decoy that starts keeping one afterwards would show it.
//! - **The question** names what the plan says: the logout, each risk
//!   allowed, the attach gate's warning, the decoy home, a hidden system to
//!   build and a missing settings file.
//! - **The steps** stream from the apply: the checks the entry runs again
//!   come first, then each step the engine names. Cancel (and Escape) shuts
//!   the window's writing half of the pipe, which the helper reads as the
//!   window gone: before the point of no return the activation unwinds, and
//!   after it the helper finishes alone. Either way the helper still answers,
//!   and its answer is the last word of the session.
//! - **Past the point of no return** the page is "Logging Out" and takes no
//!   input at all. The switch ends the window with the decoy's session, so a
//!   pipe that closes from then on is no failure.
//! - **A switch that never comes.** The engine says when the logout will not
//!   come: past the point of no return it reports the activation finished
//!   without success (the soft-reboot could not be enqueued, and the entry
//!   was rolled back), and its answer says why. The page then leaves Logging
//!   Out at once. Once the soft-reboot is enqueued the engine has nothing
//!   more to say, since systemd runs the switch; it stops the decoy's
//!   programs, this window's with them, within seconds. So a window still
//!   there [a minute later](super::SWITCH_OVERDUE) gives the person a way
//!   out: its Close works again, and the page says how to see where things
//!   stand. The same holds when the helper went away before it said either.

use std::collections::BTreeSet;
use std::path::Path;

use nails_api::Event;
use nails_api::protocol::{ActivateArgs, ActivatePlanData, CheckArgs};

use super::{ActionKind, Page, Question, StepView};
use crate::text;

/// A risk a person can allow for one activation, behind a typed word: the
/// refusal a CLI flag turns into a warning for one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Risk {
    /// The decoy keeps a persistent record of the session (the
    /// `decoy-persistence` check; `--allow-persistent-decoy`).
    PersistentDecoy,
}

impl Risk {
    /// The risk a failed check of `name` can be allowed as, if any. Only the
    /// refusals whose fix the CLI names a flag for are.
    #[must_use]
    pub fn of_check(name: &str) -> Option<Risk> {
        match name {
            "decoy-persistence" => Some(Risk::PersistentDecoy),
            _ => None,
        }
    }

    /// What it is, as the page and the question name it.
    #[must_use]
    pub fn what(self) -> &'static str {
        match self {
            Risk::PersistentDecoy => text::RISK_PERSISTENT_DECOY,
        }
    }
}

/// The check's arguments with the risks `allowed`.
#[must_use]
pub fn check_args(allowed: &BTreeSet<Risk>) -> CheckArgs {
    CheckArgs {
        allow_persistent_decoy: allowed.contains(&Risk::PersistentDecoy),
        ..CheckArgs::default()
    }
}

/// The activation's arguments with the risks `allowed`.
#[must_use]
pub fn activate_args(allowed: &BTreeSet<Risk>) -> ActivateArgs {
    ActivateArgs {
        allow_persistent_decoy: allowed.contains(&Risk::PersistentDecoy),
        ..ActivateArgs::default()
    }
}

/// Whether `typed` is the word that allows a risk: case, and spaces around
/// it, do not matter.
#[must_use]
pub fn is_the_word(typed: &str) -> bool {
    typed.trim().eq_ignore_ascii_case(text::ALLOW_WORD)
}

/// The question that allows `risk`, which the check refused with `message`;
/// `locked` until the word is typed.
#[must_use]
pub fn allow_question(message: &str, locked: bool) -> Question {
    Question {
        heading: text::ALLOW_QUESTION.to_string(),
        body: format!("{message}\n{}", text::ALLOW_ONCE),
        confirm: text::ALLOW_CONFIRM.to_string(),
        destructive: true,
        prompt: Some(text::type_to_continue(text::ALLOW_WORD)),
        locked,
        alternative: None,
    }
}

/// The question before the activation `data` plans: the risks the entry does
/// not refuse first, each with its fix, as the CLI writes them before it asks
/// to log out; then the logout, and each line that applies, the risks
/// `allowed` first.
#[must_use]
pub fn activate_question(
    data: &ActivatePlanData,
    allowed: &BTreeSet<Risk>,
    in_decoy_home: bool,
) -> Question {
    let mut lines: Vec<String> = data
        .advisories
        .iter()
        .flat_map(|advisory| {
            std::iter::once(advisory.message.as_str())
                .chain(advisory.fix.iter().flat_map(|fix| fix.lines()))
                .map(|line| text::sentence(&text::engine_fix(line)))
        })
        .collect();
    lines.push(text::ACTIVATE_CONSEQUENCE.to_string());
    lines.extend(allowed.iter().map(|risk| text::allowed_by_you(risk.what())));
    if let Some(warning) = &data.warning {
        lines.push(text::sentence(warning));
    }
    if in_decoy_home {
        lines.push(text::DECOY_HOME.to_string());
    }
    if data.builds_hidden_system {
        lines.push(text::BUILDS_HIDDEN_SYSTEM.to_string());
    }
    if let Some(notice) = &data.defaults_notice {
        lines.push(text::sentence(notice));
    }
    Question {
        heading: text::ACTIVATE_QUESTION.to_string(),
        body: lines.join("\n"),
        confirm: text::LOG_OUT_AND_ACTIVATE.to_string(),
        destructive: false,
        prompt: None,
        locked: false,
        alternative: None,
    }
}

/// An activation's apply, as far as it got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Activation {
    /// Its steps run: the labels of those the engine named so far, the last
    /// of them the one that runs. `cancelling` once the window hung up.
    Running {
        /// The steps so far.
        steps: Vec<String>,
        /// Whether the window hung up to cancel it.
        cancelling: bool,
    },
    /// Past its point of no return: the switch follows, whatever the window
    /// does.
    PastThePoint,
    /// Past its point of no return, the engine said the soft-reboot could
    /// not be enqueued: the switch never comes, and the answer that follows
    /// says why.
    NotEnqueued,
}

impl Activation {
    /// An apply that has just been asked for.
    #[must_use]
    pub fn started() -> Self {
        Activation::Running {
            steps: Vec::new(),
            cancelling: false,
        }
    }

    /// Take in an event of the apply. The checks the entry runs again are
    /// the first step, which the window names itself.
    pub fn event(&mut self, event: &Event) {
        match event {
            Event::Step { label, .. } => {
                if let Activation::Running { steps, .. } = self {
                    steps.push(label.clone());
                }
            }
            Event::PointOfNoReturn => *self = Activation::PastThePoint,
            Event::Finished { success: false } if *self == Activation::PastThePoint => {
                *self = Activation::NotEnqueued;
            }
            _ => {}
        }
    }

    /// Start cancelling, when that still can: true once, before the point
    /// of no return.
    pub fn cancel(&mut self) -> bool {
        match self {
            Activation::Running { cancelling, .. } if !*cancelling => {
                *cancelling = true;
                true
            }
            _ => false,
        }
    }

    /// The page while it runs.
    #[must_use]
    pub fn page(&self) -> Page {
        match self {
            Activation::Running { steps, cancelling } => {
                let all: Vec<&str> = std::iter::once(text::STEP_CHECKING)
                    .chain(steps.iter().map(String::as_str))
                    .collect();
                let now = all.len() - 1;
                Page {
                    heading: text::ACTIVATING.to_string(),
                    description: text::ACTIVATING_WHERE.to_string(),
                    busy: Some(
                        if *cancelling {
                            text::CANCELLING
                        } else {
                            all[now]
                        }
                        .to_string(),
                    ),
                    steps: all
                        .iter()
                        .enumerate()
                        .map(|(i, label)| StepView {
                            label: (*label).to_string(),
                            state: if i == now {
                                text::STEP_NOW
                            } else {
                                text::STEP_DONE
                            },
                        })
                        .collect(),
                    action: (!*cancelling).then_some(text::CANCEL),
                    action_kind: ActionKind::Plain,
                    ..Page::default()
                }
            }
            Activation::PastThePoint => Page {
                heading: text::LOGGING_OUT.to_string(),
                description: text::LOG_IN_AGAIN.to_string(),
                urgent: true,
                no_input: true,
                ..Page::default()
            },
            Activation::NotEnqueued => Page {
                heading: text::ACTIVATION_FAILED.to_string(),
                description: text::LOGOUT_NOT_ASKED.to_string(),
                urgent: true,
                no_input: true,
                ..Page::default()
            },
        }
    }
}

/// How the helper's answer to an activation's apply reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The switch is under way.
    Entering,
    /// Nothing to do: the session is active already; the engine's words.
    AlreadyActive(String),
    /// It was cancelled before its point of no return; the engine's words.
    Cancelled(String),
    /// It failed or was refused; the engine's words.
    Failed(String),
}

/// Read the envelope `value` of an activation's apply.
#[must_use]
pub fn outcome(value: &serde_json::Value) -> Outcome {
    let message = value["error"]["message"]
        .as_str()
        .map(text::sentence)
        .unwrap_or_default();
    match value["data"]["status"].as_str() {
        Some("entering" | "entering_with_warnings") if value["ok"] == true => Outcome::Entering,
        Some("already_active") if value["ok"] == true => Outcome::AlreadyActive(
            value["data"]["message"]
                .as_str()
                .map(text::sentence)
                .unwrap_or_default(),
        ),
        _ if value["error"]["code"] == "cancelled" => Outcome::Cancelled(message),
        _ => Outcome::Failed(message),
    }
}

/// The page once the window hung up on an activation and the helper gave
/// its last answer, `outcome`: the session is over, so its next step is to
/// open the window again.
#[must_use]
pub fn over_page(outcome: &Outcome, engine: Option<&Path>) -> Page {
    let (heading, description, urgent) = match outcome {
        Outcome::Entering => return Activation::PastThePoint.page(),
        Outcome::AlreadyActive(message) => (text::HIDDEN_SESSION, message.clone(), false),
        Outcome::Cancelled(message) => (text::ACTIVATION_CANCELLED, message.clone(), false),
        Outcome::Failed(message) => (text::ACTIVATION_FAILED, message.clone(), true),
    };
    Page {
        heading: heading.to_string(),
        description,
        urgent,
        fix: text::open_again(engine),
        ..Page::default()
    }
}
