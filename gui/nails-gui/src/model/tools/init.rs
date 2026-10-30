// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Set Up Hidden Volume: `nails init <volume>`, as a plan, its token and its
//! apply.
//!
//! The volume is the one the session's status names, or else the folder the
//! engine lies in, as the engine itself derives it. The plan checks every
//! precondition that can be read and writes nothing; its question says what
//! the apply writes and that a settings file or record already there stays.
//! The apply checks again and writes the layout; its page lists each part,
//! made or already there, with the engine's warnings and notes.

use nails_api::CheckOutcome;
use nails_api::protocol::{InitArgs, InitPlanData};

use super::{Context, ToolKind, error_of, group, row, tool_page};
use crate::client::{Answer, Plan};
use crate::envelope::{self, InitData, InitItemStatus};
use crate::model::{Page, Question};
use crate::text;
use crate::worker::{Ask, Kind};

/// What Set Up knows.
#[derive(Debug, Clone, Default)]
pub(crate) struct SetUp {
    /// How the last plan or apply came out.
    outcome: Option<Outcome>,
}

#[derive(Debug, Clone)]
enum Outcome {
    /// The layout is written.
    Done(InitData),
    /// The engine refused or failed, in its words.
    Failed(String),
}

impl SetUp {
    /// Whether the layout was written, so the check may find otherwise.
    pub(crate) fn changed(&self) -> bool {
        matches!(self.outcome, Some(Outcome::Done(_)))
    }

    /// The ask for `label`, the page's action, for the hidden volume `root`.
    pub(crate) fn action(&mut self, label: &str, root: Option<&str>) -> Option<Ask> {
        let root = root.filter(|root| root.starts_with('/'))?;
        if label != text::SET_UP_ACTION {
            return None;
        }
        self.outcome = None;
        Some(Ask::Plan(Plan::Init(InitArgs {
            path: root.to_string(),
            allow_decoy_storage: false,
            hardware_config: None,
            no_hardware_config: false,
        })))
    }

    /// Take in the answer of a plan that settled, or of the apply.
    pub(crate) fn answered(&mut self, _kind: Kind, answer: &Answer) {
        self.outcome = Some(match envelope::read::<InitData>(&answer.envelope, "init") {
            Ok(read) => match read.data {
                Some(data) => Outcome::Done(data),
                None => Outcome::Failed(
                    error_of(&answer.envelope)
                        .map_or_else(|| text::NOTHING_CHANGED.to_string(), |(_, message)| message),
                ),
            },
            Err(error) => Outcome::Failed(text::sentence(&error.0)),
        });
    }

    /// The page.
    pub(crate) fn page(&self, cx: &Context) -> Page {
        let root = cx.root.as_deref().unwrap_or_default();
        let mut page = match &self.outcome {
            Some(Outcome::Done(data)) => done_page(data),
            Some(Outcome::Failed(message)) => Page {
                heading: text::SET_UP_FAILED.to_string(),
                note: message.clone(),
                urgent: true,
                ..tool_page(ToolKind::SetUp, &text::set_up_what(root))
            },
            None => tool_page(ToolKind::SetUp, &text::set_up_what(root)),
        };
        page.busy = match cx.running {
            Some(Kind::Plan) => Some(text::CHECKING_VOLUME.to_string()),
            Some(Kind::Apply) => Some(text::SETTING_UP.to_string()),
            _ => None,
        };
        if !matches!(self.outcome, Some(Outcome::Done(_))) && root.starts_with('/') {
            page.action = Some(text::SET_UP_ACTION);
        }
        page
    }
}

/// The page once the layout is written.
fn done_page(data: &InitData) -> Page {
    let items = data
        .items
        .iter()
        .map(|item| {
            let (outcome, word) = match item.status {
                InitItemStatus::Created => (CheckOutcome::Pass, text::CREATED_WORD),
                InitItemStatus::AlreadyPresent => (CheckOutcome::Skipped, text::ALREADY_THERE),
            };
            row(outcome, word, item.path.clone(), String::new())
        })
        .collect();
    let notes = data
        .warnings
        .iter()
        .map(|warning| {
            row(
                CheckOutcome::Warn,
                text::SEVERITY_WARN,
                text::sentence(warning),
                String::new(),
            )
        })
        .chain(data.notes.iter().map(|note| {
            row(
                CheckOutcome::Skipped,
                text::SEVERITY_NOTE,
                text::sentence(note),
                String::new(),
            )
        }))
        .collect();
    Page {
        heading: text::SET_UP_DONE.to_string(),
        groups: [
            group(text::GROUP_NOTES, notes),
            group(text::GROUP_LAYOUT, items),
        ]
        .into_iter()
        .flatten()
        .collect(),
        fix: text::SET_UP_NEXT.to_string(),
        ..tool_page(ToolKind::SetUp, &text::set_up_done(&data.root))
    }
}

/// The question of the plan `data`.
pub(crate) fn question(data: &InitPlanData) -> Question {
    let mut lines = vec![text::set_up_consequence(&data.path)];
    if let Some(hardware) = &data.hardware_config {
        lines.push(text::set_up_nixos(hardware));
    }
    lines.extend(data.warnings.iter().map(|warning| text::sentence(warning)));
    Question {
        heading: text::SET_UP_QUESTION.to_string(),
        body: lines.join("\n"),
        confirm: text::SET_UP_CONFIRM.to_string(),
        destructive: false,
        prompt: None,
        locked: false,
        alternative: None,
    }
}
