// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Deactivating from the window: the question with both endings, the apply,
//! and the page while the hidden session ends.
//!
//! - **The question** comes from the plan of a return to the decoy, which
//!   names what the return will not put back: the engine's warnings, such as
//!   a network tool the way back will not find and what stays on the decoy
//!   without it, or that the computer then powers off instead of returning.
//!   It offers both endings: Power Off, the safer one and the suggested
//!   button, and Return to Decoy. The focus starts on Cancel. Where the plan
//!   says the return powers off instead, the question says so first, in the
//!   CLI's words; where it powers off whatever happens before it runs, there
//!   is no Return to Decoy to offer, only Power Off.
//! - **Return to Decoy** applies that plan. **Power Off** asks for the plan
//!   of a power-off, which has nothing to warn of, and applies it as soon as
//!   it holds: the person has answered already.
//! - **Ending the Hidden Session** shows from the person's choice on. The
//!   switch ends the window with the session, so a pipe that closes from
//!   then on is no failure. A return the plan said may power off instead
//!   says so there too, as the CLI does once it has asked. An apply the
//!   engine refused brings the session's page back with the engine's words.

use nails_api::protocol::{DeactivateArgs, DeactivatePlanData, PowerOffInstead};

use super::{Page, Question};
use crate::envelope::{self, DeactivateData, DeactivateStatus};
use crate::text;

/// How a deactivated hidden session ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// At the decoy's login screen.
    Return,
    /// With the computer off.
    PowerOff,
}

impl Ending {
    /// The arguments of the plan of a deactivation that ends so.
    #[must_use]
    pub fn args(self) -> DeactivateArgs {
        DeactivateArgs {
            poweroff: self == Ending::PowerOff,
        }
    }
}

/// The question before a deactivation, from the plan `data` of a return:
/// that the return powers off instead, where it does; the consequence; then
/// each warning of the engine's.
#[must_use]
pub fn question(data: &DeactivatePlanData) -> Question {
    let mut lines: Vec<String> = data
        .powers_off_instead
        .iter()
        .map(|bound| text::powers_off_instead(bound.certain))
        .collect();
    lines.push(text::DEACTIVATE_CONSEQUENCE.to_string());
    lines.extend(
        data.warnings
            .iter()
            .map(|warning| text::sentence(&text::engine_fix(warning))),
    );
    // A return the way back turns into a power-off, whatever happens before
    // it runs, is no ending to offer.
    let certain = data
        .powers_off_instead
        .as_ref()
        .is_some_and(|bound| bound.certain);
    Question {
        heading: text::DEACTIVATE_QUESTION.to_string(),
        body: lines.join("\n"),
        confirm: text::POWER_OFF.to_string(),
        destructive: false,
        prompt: None,
        locked: false,
        alternative: (!certain).then(|| text::RETURN_TO_DECOY.to_string()),
    }
}

/// A deactivation the person chose an ending for, as far as it got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deactivation {
    /// Power Off was chosen on the plan of a return: the plan of a power-off
    /// was asked for, and is applied once it holds.
    Replanning,
    /// The apply was asked for, or answered: the session ends `ending`, and
    /// `left_open` devices of the hidden volume could not be marked to close.
    Ending {
        /// How the session ends.
        ending: Ending,
        /// Why the way back powers off instead of returning, as the plan of
        /// the return said, if it did.
        instead: Option<PowerOffInstead>,
        /// The devices the apply's answer names as left open.
        left_open: usize,
    },
}

impl Deactivation {
    /// The session ends `ending`, as far as the window knows yet.
    #[must_use]
    pub fn ending(ending: Ending) -> Self {
        Deactivation::Ending {
            ending,
            instead: None,
            left_open: 0,
        }
    }

    /// The session returns to the decoy on a plan that said why the way back
    /// powers off instead, if it did.
    #[must_use]
    pub fn returning(instead: Option<PowerOffInstead>) -> Self {
        Deactivation::Ending {
            ending: Ending::Return,
            instead,
            left_open: 0,
        }
    }

    /// The deactivation the apply's answer enqueued, keeping what the plan
    /// of the return that was `asked` said about a power-off instead: the
    /// answer does not repeat it.
    #[must_use]
    pub fn keeping(self, asked: Option<Deactivation>) -> Self {
        match (self, asked) {
            (
                Deactivation::Ending {
                    ending: Ending::Return,
                    left_open,
                    ..
                },
                Some(Deactivation::Ending {
                    ending: Ending::Return,
                    instead,
                    ..
                }),
            ) => Deactivation::Ending {
                ending: Ending::Return,
                instead,
                left_open,
            },
            (answer, _) => answer,
        }
    }

    /// The page while the session ends: it takes no input but the Emergency.
    #[must_use]
    pub fn page(&self) -> Page {
        let (ending, instead, left_open) = match self {
            Deactivation::Replanning => (Ending::PowerOff, None, 0),
            Deactivation::Ending {
                ending,
                instead,
                left_open,
            } => (*ending, instead.as_ref(), *left_open),
        };
        Page {
            heading: text::ENDING.to_string(),
            description: match (ending, instead) {
                (Ending::Return, Some(instead)) => {
                    text::returning_powers_off(&text::engine_fix(&instead.what), instead.certain)
                }
                (Ending::Return, None) => text::RETURNING.to_string(),
                (Ending::PowerOff, _) => text::POWERING_OFF.to_string(),
            },
            note: if left_open > 0 {
                text::BACKEND_LEFT_OPEN.to_string()
            } else {
                String::new()
            },
            urgent: true,
            no_input: true,
            ..Page::default()
        }
    }
}

/// How the helper answered a deactivation's apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    /// The switch is enqueued.
    Enqueued(Deactivation),
    /// It failed or was refused, in the engine's words; nothing switches.
    Failed(String),
}

/// Read the envelope `value` of a deactivation's apply.
#[must_use]
pub fn applied(value: &serde_json::Value) -> Applied {
    let envelope = match envelope::read::<DeactivateData>(value, "deactivate") {
        Ok(envelope) => envelope,
        Err(error) => return Applied::Failed(text::sentence(&error.0)),
    };
    match (envelope.ok, envelope.data, envelope.error) {
        (true, Some(data), _) => Applied::Enqueued(Deactivation::Ending {
            ending: match data.status {
                DeactivateStatus::ReturnRequested => Ending::Return,
                DeactivateStatus::PoweroffRequested => Ending::PowerOff,
            },
            instead: None,
            left_open: data.backend_left_open.len(),
        }),
        (_, _, Some(error)) => Applied::Failed(text::sentence(&error.message)),
        _ => Applied::Failed(text::NOTHING_CHANGED.to_string()),
    }
}
