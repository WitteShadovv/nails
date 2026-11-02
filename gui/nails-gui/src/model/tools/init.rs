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

use nails_api::protocol::{InitArgs, InitPlanData, Op};
use nails_api::{Allowable, CheckOutcome};

use super::{Context, ToolKind, error_of, fits, group, row, tool_page};
use crate::client::{Answer, Plan};
use crate::envelope::{self, InitData, InitItemStatus};
use crate::model::{Field, Page, Question, Switch};
use crate::text;
use crate::worker::{Ask, Kind};

/// What Set Up knows.
#[derive(Debug, Clone, Default)]
pub(crate) struct SetUp {
    /// How the last plan or apply came out.
    outcome: Option<Outcome>,
    /// The hidden NixOS layout is left out (`--no-hardware-config`).
    no_layout: bool,
    /// The hardware configuration to seed it from, as typed
    /// (`--hardware-config`); empty for the one the engine reads by default.
    hardware_config: String,
    /// The engine refused the last plan for a hidden volume on this
    /// computer's storage, which `--allow-decoy-storage` accepts.
    storage_refused: bool,
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

    /// The hardware configuration field changed to `typed`.
    pub(crate) fn edited(&mut self, typed: &str) {
        typed.clone_into(&mut self.hardware_config);
    }

    /// The hidden NixOS layout's switch turned `on` or off.
    pub(crate) fn toggled(&mut self, on: bool) {
        self.no_layout = !on;
    }

    /// The plan's arguments for the hidden volume `root`: without the hidden
    /// NixOS layout when its switch is off, else seeded from the file typed,
    /// when one is, and with the hidden volume on this computer's storage
    /// allowed when `allow`. `None` until the helper would take them.
    fn args(&self, root: &str, allow: bool) -> Option<InitArgs> {
        let file = self.hardware_config.trim();
        let args = InitArgs {
            path: root.to_string(),
            allow_decoy_storage: allow,
            hardware_config: (!self.no_layout && !file.is_empty()).then(|| file.to_string()),
            no_hardware_config: self.no_layout,
        };
        fits(&Op::InitPlan(args.clone())).then_some(args)
    }

    /// Whether the page offers to allow the hidden volume on this
    /// computer's storage: the engine named that for its last refusal, and
    /// a plan for the hidden volume `root` can go.
    pub(crate) fn offers_storage(&self, root: Option<&str>) -> bool {
        self.storage_refused && root.and_then(|root| self.args(root, false)).is_some()
    }

    /// The refusal the question before allowing it repeats.
    pub(crate) fn refusal(&self) -> Option<&str> {
        match &self.outcome {
            Some(Outcome::Failed(message)) => message.lines().next(),
            _ => None,
        }
    }

    /// The plan again for the hidden volume `root`, its place on this
    /// computer's storage allowed for that plan alone once its question was
    /// answered with the word.
    pub(crate) fn allow_storage(&mut self, root: Option<&str>) -> Option<Ask> {
        if !self.offers_storage(root) {
            return None;
        }
        self.plan(root?, true)
    }

    /// The ask for `label`, the page's action, for the hidden volume `root`.
    pub(crate) fn action(&mut self, label: &str, root: Option<&str>) -> Option<Ask> {
        let root = root.filter(|root| root.starts_with('/'))?;
        if label != text::SET_UP_ACTION {
            return None;
        }
        self.plan(root, false)
    }

    /// The plan for the hidden volume `root`, its place on this computer's
    /// storage allowed when `allow`. A new plan ends whatever the last
    /// refusal offered.
    fn plan(&mut self, root: &str, allow: bool) -> Option<Ask> {
        let args = self.args(root, allow)?;
        self.outcome = None;
        self.storage_refused = false;
        Some(Ask::Plan(Plan::Init(args)))
    }

    /// Take in the answer of a plan that settled, or of the apply.
    pub(crate) fn answered(&mut self, _kind: Kind, answer: &Answer) {
        self.storage_refused = false;
        self.outcome =
            Some(match envelope::read::<InitData>(&answer.envelope, "init") {
                Ok(read) => match read.data {
                    Some(data) => Outcome::Done(data),
                    None => {
                        self.storage_refused = read
                            .error
                            .as_ref()
                            .is_some_and(|error| error.allowable == Some(Allowable::DecoyStorage));
                        Outcome::Failed(error_of(&answer.envelope).map_or_else(
                            || text::NOTHING_CHANGED.to_string(),
                            |(_, message)| message,
                        ))
                    }
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
        // Never in a hidden session, by either reading: fail closed.
        if !matches!(self.outcome, Some(Outcome::Done(_))) && root.starts_with('/') && !cx.hidden {
            page.action = Some(text::SET_UP_ACTION);
            if self.offers_storage(Some(root)) {
                page.secondary = Some(text::ALLOW_FOR_SET_UP);
            }
            page.action_locked = self.args(root, false).is_none();
            page.switch_first = true;
            page.switch = Some(Switch {
                title: text::SWITCH_LAYOUT.to_string(),
                subtitle: text::LAYOUT_WHAT.to_string(),
                on: !self.no_layout,
            });
            if !self.no_layout {
                let file = self.hardware_config.trim();
                page.field = Some(Field {
                    label: text::FIELD_HARDWARE_CONFIG.to_string(),
                    text: self.hardware_config.clone(),
                    hint: if file.is_empty()
                        || (file.starts_with('/') && !file.chars().any(char::is_control))
                    {
                        text::HARDWARE_CONFIG_HINT
                    } else {
                        text::HARDWARE_CONFIG_NOT_ABSOLUTE
                    }
                    .to_string(),
                });
            }
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
    // A layout the engine leaves out, as the switch asked or as this host
    // has none: why, in its words.
    if let Some(skipped) = &data.skipped {
        lines.push(text::sentence(skipped));
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
