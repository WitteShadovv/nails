// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Deactivating from the window: the question, the apply, and the page while
//! the hidden session ends.
//!
//! A hidden session ends in one way: the computer powers off.
//!
//! - **The question** comes from the plan of that power-off
//!   ([`args`]). It says the session ends and the computer powers off, then
//!   any warning of the engine's. It offers Power Off, the suggested button,
//!   and Cancel, where the focus starts.
//! - **Power Off** applies that plan.
//! - **Ending the Hidden Session** shows from the person's choice on. The
//!   power-off ends the window with the session, so a pipe that closes from
//!   then on is no failure. An apply the engine refused brings the session's
//!   page back with the engine's words.

use nails_api::protocol::{DeactivateArgs, DeactivatePlanData};

use super::{Page, Question};
use crate::envelope::{self, DeactivateData};
use crate::text;

/// The arguments of the plan of a deactivation: a power-off, which is how
/// every hidden session ends.
#[must_use]
pub fn args() -> DeactivateArgs {
    DeactivateArgs { poweroff: true }
}

/// The question before a deactivation, from its plan `data`: the
/// consequence, then each warning of the engine's.
#[must_use]
pub fn question(data: &DeactivatePlanData) -> Question {
    let mut lines = vec![text::DEACTIVATE_CONSEQUENCE.to_string()];
    lines.extend(
        data.warnings
            .iter()
            .map(|warning| text::sentence(&text::engine_fix(warning))),
    );
    Question {
        heading: text::DEACTIVATE_QUESTION.to_string(),
        body: lines.join("\n"),
        confirm: text::POWER_OFF.to_string(),
        destructive: false,
        prompt: None,
        locked: false,
    }
}

/// A deactivation the person confirmed: its apply was asked for, or
/// answered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Deactivation {
    /// The devices of the hidden volume the apply's answer names as left
    /// open: they could not be marked to close.
    pub left_open: usize,
}

impl Deactivation {
    /// The page while the session ends: it takes no input but the Emergency.
    #[must_use]
    pub fn page(&self) -> Page {
        Page {
            heading: text::ENDING.to_string(),
            description: text::POWERING_OFF.to_string(),
            note: if self.left_open > 0 {
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
    /// The power-off is enqueued.
    Enqueued(Deactivation),
    /// It failed or was refused, in the engine's words; nothing switches.
    Failed(String),
}

/// Read the envelope `value` of a deactivation's apply. Whatever switch an
/// answer that succeeded names, the window reads it as the power-off it
/// asked for.
#[must_use]
pub fn applied(value: &serde_json::Value) -> Applied {
    let envelope = match envelope::read::<DeactivateData>(value, "deactivate") {
        Ok(envelope) => envelope,
        Err(error) => return Applied::Failed(text::sentence(&error.0)),
    };
    match (envelope.ok, envelope.data, envelope.error) {
        (true, Some(data), _) => Applied::Enqueued(Deactivation {
            left_open: data.backend_left_open.len(),
        }),
        (_, _, Some(error)) => Applied::Failed(text::sentence(&error.message)),
        _ => Applied::Failed(text::NOTHING_CHANGED.to_string()),
    }
}
