// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The window's tools: Verify, Rehearsal, Settings, Discard Hidden Changes
//! and Set Up Hidden Volume, each a page of its own over the session's page.
//!
//! A row of the session's page opens a tool, once that page settled: Verify
//! and Rehearsal on both sides, Settings in a hidden session, where settings
//! change, and Discard Hidden Changes and Set Up Hidden Volume on the decoy
//! only. The engine refuses a discard in a hidden
//! session, whose system it would change under it; it would run a set up
//! there, on the volume the session runs from, so the window is what keeps
//! Set Up off a hidden session's page. The window offers both only where its
//! own reading of the mount table agrees with the engine's status that this
//! is the decoy: where the two disagree, it fails closed. Back (or Escape)
//! leaves a tool for the session's page, whose status it asks for again; a
//! discard or a set up that ran also brings the decoy's check back, since
//! either can change what the check finds.
//!
//! - **Verify** ([`verify`]) and each step of the **rehearsal**
//!   ([`rehearsal`]) are requests of their own, as their CLI commands ask
//!   nothing first.
//! - **Settings** ([`settings`]) reads them with `config show`, and changes
//!   one through a plan, its token and its apply, as `config set` and
//!   `config unset` do.
//! - **Discard** ([`discard`]) and **Set Up** ([`init`]) go through a plan,
//!   its token and its apply: the plan's answer words the question, and only
//!   the person's yes sends the apply with the plan's token. A discard whose
//!   plan warns asks for the folder to be typed first.
//!
//! The helper serves one request at a time, and a verify or a scan can run
//! for minutes. Meanwhile a tool's page takes nothing but the window's Close
//! and, in a hidden session, the Emergency control, whose way out does not
//! wait for the helper ([`crate::emergency`]).

use std::path::{Path, PathBuf};

use super::{CheckView, Effect, Group, Model, Page, PlanFor, Question, View};
use crate::client::{Answer, PlanData};
use crate::envelope::Place;
use crate::text;
use crate::worker::{Ask, Kind};

mod discard;
mod init;
mod rehearsal;
mod settings;
mod verify;

pub use discard::{canonical_folder, holds_a_home, valid_folder};

/// A tool the session's page offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolKind {
    /// Look for traces.
    Verify,
    /// Plant test words, scan for them, remove them.
    Rehearsal,
    /// Delete the hidden changes of a folder.
    Discard,
    /// Lay out the hidden volume.
    SetUp,
    /// See and change the settings.
    Settings,
}

impl ToolKind {
    /// The tools a page of `place` offers, in their order.
    #[must_use]
    pub fn offered(place: Place) -> &'static [ToolKind] {
        match place {
            Place::Decoy => &[
                ToolKind::Verify,
                ToolKind::Rehearsal,
                ToolKind::Discard,
                ToolKind::SetUp,
            ],
            Place::Hidden => &[ToolKind::Verify, ToolKind::Rehearsal, ToolKind::Settings],
            Place::Activating | Place::Unknown => &[],
        }
    }

    /// The row's title, which is the tool page's too.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            ToolKind::Verify => text::VERIFY,
            ToolKind::Rehearsal => text::REHEARSAL,
            ToolKind::Discard => text::DISCARD,
            ToolKind::SetUp => text::SET_UP,
            ToolKind::Settings => text::SETTINGS,
        }
    }

    /// The line under the row's title.
    #[must_use]
    pub fn what(self) -> &'static str {
        match self {
            ToolKind::Verify => text::VERIFY_WHAT,
            ToolKind::Rehearsal => text::REHEARSAL_WHAT,
            ToolKind::Discard => text::DISCARD_WHAT,
            ToolKind::SetUp => text::SET_UP_ROW,
            ToolKind::Settings => text::SETTINGS_ROW,
        }
    }
}

/// A row of the session's page that opens a tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// The tool it opens.
    pub tool: ToolKind,
    /// Its title.
    pub title: String,
    /// The line under it.
    pub subtitle: String,
}

/// The tool whose page shows, and what it knows.
#[derive(Debug, Clone)]
pub(super) enum Tool {
    Verify(verify::Verify),
    Rehearsal(rehearsal::Rehearsal),
    Discard(discard::Discard),
    SetUp(init::SetUp),
    Settings(settings::Settings),
}

impl Tool {
    fn kind(&self) -> ToolKind {
        match self {
            Tool::Verify(_) => ToolKind::Verify,
            Tool::Rehearsal(_) => ToolKind::Rehearsal,
            Tool::Discard(_) => ToolKind::Discard,
            Tool::SetUp(_) => ToolKind::SetUp,
            Tool::Settings(_) => ToolKind::Settings,
        }
    }
}

/// What a tool knows of where it runs, from the session's last status.
#[derive(Debug, Clone)]
pub(super) struct Context {
    /// The window runs in a hidden session.
    pub hidden: bool,
    /// The request that runs, if any.
    pub running: Option<Kind>,
    /// The hidden volume, as the status names it or the engine's folder.
    pub root: Option<String>,
    /// The engine, for a line a page gives to run in a terminal.
    pub engine: Option<PathBuf>,
}

/// Whether `typed` is the folder `word` a question asks for: the same
/// folder as the engine reads both, the spaces around it, a repeated or
/// trailing slash and a `.` aside.
#[must_use]
pub fn is_the_folder(word: &str, typed: &str) -> bool {
    match (canonical_folder(word), canonical_folder(typed)) {
        (Some(word), Some(typed)) => word == typed,
        _ => false,
    }
}

/// A row of a group: `word` and `message`, and `fix` under them.
pub(super) fn row(
    outcome: nails_api::CheckOutcome,
    word: &str,
    message: String,
    fix: String,
) -> CheckView {
    CheckView {
        outcome,
        word: word.to_string(),
        message,
        fix,
        allow: None,
    }
}

/// A group titled `title` of `rows`, or none when it has no rows.
pub(super) fn group(title: &str, rows: Vec<CheckView>) -> Option<Group> {
    (!rows.is_empty()).then(|| Group {
        title: title.to_string(),
        rows,
    })
}

/// The page every tool's page starts from: its title, Back, and nothing
/// else yet.
pub(super) fn tool_page(kind: ToolKind, description: &str) -> Page {
    Page {
        heading: kind.title().to_string(),
        description: description.to_string(),
        view: View::Tool(kind),
        back: true,
        ..Page::default()
    }
}

/// The engine's error message of `value`, an envelope that failed, as a
/// sentence; `None` for one that did not fail.
pub(super) fn error_of(value: &serde_json::Value) -> Option<(String, String)> {
    let error = value.get("error")?;
    let code = error["code"].as_str().unwrap_or_default().to_string();
    let message = error["message"].as_str().map(text::sentence)?;
    Some((code, message))
}

impl Model {
    /// The rows of the session's page that open a tool on `place`: those of
    /// a hidden session where the window's own reading says it runs in one,
    /// whatever the status says.
    pub(super) fn links(&self, place: Place) -> Vec<Link> {
        let place = match place {
            Place::Decoy if self.in_hidden_session => Place::Hidden,
            place => place,
        };
        ToolKind::offered(place)
            .iter()
            .map(|&tool| Link {
                tool,
                title: tool.title().to_string(),
                subtitle: tool.what().to_string(),
            })
            .collect()
    }

    /// Open the tool of the session page's row `index`, and return what it
    /// asks for first.
    pub fn open(&mut self, index: usize) -> Option<Ask> {
        if self.question.is_some() || self.running.is_some() {
            return None;
        }
        let link = self.page().links.into_iter().nth(index)?;
        self.notice = None;
        let (tool, first) = match link.tool {
            ToolKind::Verify => (Tool::Verify(verify::Verify::default()), None),
            ToolKind::Rehearsal => {
                let (rehearsal, first) = rehearsal::Rehearsal::open(self.planted_here);
                (Tool::Rehearsal(rehearsal), Some(first))
            }
            ToolKind::Discard => (Tool::Discard(discard::Discard::default()), None),
            ToolKind::SetUp => (Tool::SetUp(init::SetUp::default()), None),
            ToolKind::Settings => {
                let (settings, first) = settings::Settings::open();
                (Tool::Settings(settings), Some(first))
            }
        };
        self.tool = Some(tool);
        first
    }

    /// Leave the open tool for the session's page, once nothing runs and no
    /// question waits, and ask for the status that brings it up to date.
    pub fn back(&mut self) -> Option<Ask> {
        if self.question.is_some() || self.running.is_some() {
            return None;
        }
        // A setting's page goes back to the list of settings first.
        if let Some(Tool::Settings(settings)) = &mut self.tool
            && settings.back()
        {
            return None;
        }
        let tool = self.tool.take()?;
        let changed = match &tool {
            Tool::Discard(discard) => discard.changed(),
            Tool::SetUp(set_up) => set_up.changed(),
            Tool::Rehearsal(rehearsal) => {
                // What the page learnt outlives it, for the window's life:
                // one hidden session, as the switch ends the window.
                self.planted_here = rehearsal.planted_here();
                false
            }
            Tool::Verify(_) | Tool::Settings(_) => false,
        };
        if changed {
            // What the check found may have changed with it.
            self.check = super::Check::NotRun;
        }
        Some(Ask::Status)
    }

    /// What the person typed so far into the open tool's field.
    pub fn edited(&mut self, typed: &str) {
        match &mut self.tool {
            Some(Tool::Discard(discard)) => discard.edited(typed),
            Some(Tool::Settings(settings)) => settings.edited(typed),
            _ => {}
        }
    }

    /// The person picked row `index` of the open tool's rows: a setting, or
    /// a state or an option of one.
    pub fn choose(&mut self, index: usize) -> Option<Ask> {
        if self.question.is_some() || self.running.is_some() {
            return None;
        }
        let hidden = self.context().hidden;
        let Some(Tool::Settings(settings)) = &mut self.tool else {
            return None;
        };
        let ask = settings.choose(index, hidden)?;
        if matches!(ask, Ask::Plan(_)) {
            self.plan_for = Some(PlanFor::Tool);
        }
        Some(ask)
    }

    /// What the page's second action does, while the page has one.
    pub fn secondary(&mut self) -> Option<Effect> {
        let label = self.page().secondary?;
        self.tool_action(label)
    }

    fn context(&self) -> Context {
        Context {
            hidden: self.in_hidden_session
                || self
                    .status
                    .as_ref()
                    .is_some_and(|status| status.place == Place::Hidden),
            running: self.running,
            root: self
                .status
                .as_ref()
                .and_then(|status| status.hidden_root.as_deref())
                .or_else(|| {
                    self.engine
                        .as_deref()
                        .and_then(Path::parent)
                        .and_then(Path::to_str)
                })
                .map(str::to_string),
            engine: self.engine.clone(),
        }
    }

    /// The open tool's page.
    pub(super) fn tool_page(&self) -> Option<Page> {
        let cx = self.context();
        Some(match self.tool.as_ref()? {
            Tool::Verify(verify) => verify.page(&cx),
            Tool::Rehearsal(rehearsal) => rehearsal.page(&cx),
            Tool::Discard(discard) => discard.page(&cx),
            Tool::SetUp(set_up) => set_up.page(&cx),
            Tool::Settings(settings) => settings.page(&cx),
        })
    }

    /// What the open tool's action `label` does.
    pub(super) fn tool_action(&mut self, label: &str) -> Option<Effect> {
        let Context { hidden, root, .. } = self.context();
        let ask = match self.tool.as_mut()? {
            Tool::Verify(verify) => verify.action(label),
            Tool::Rehearsal(rehearsal) => rehearsal.action(label, hidden),
            // Never in a hidden session, by either reading: fail closed.
            Tool::Discard(discard) if !hidden => discard.action(label),
            Tool::SetUp(set_up) if !hidden => set_up.action(label, root.as_deref()),
            Tool::Discard(_) | Tool::SetUp(_) => None,
            Tool::Settings(settings) => settings.action(label, hidden),
        }?;
        if matches!(ask, Ask::Plan(_)) {
            self.plan_for = Some(PlanFor::Tool);
        }
        Some(Effect::Ask(ask))
    }

    /// Whether the answer of a `kind` request is the open tool's.
    pub(super) fn answers_tool(&self, kind: Kind) -> bool {
        match kind {
            Kind::Verify | Kind::Rehearse | Kind::Config => self.tool.is_some(),
            Kind::Plan | Kind::Apply => matches!(self.plan_for, Some(PlanFor::Tool)),
            Kind::Status | Kind::Check | Kind::Recover => false,
        }
    }

    /// Take in the answer of the open tool's `kind` request.
    pub(super) fn tool_answered(&mut self, kind: Kind, answer: &Answer) -> Vec<Ask> {
        if matches!(kind, Kind::Plan | Kind::Apply) {
            // A plan that settled, or the apply: the plan is over.
            self.plan_for = None;
            self.close_question();
        }
        match self.tool.as_mut() {
            Some(Tool::Verify(verify)) => verify.answered(answer),
            Some(Tool::Rehearsal(rehearsal)) => rehearsal.answered(answer),
            Some(Tool::Discard(discard)) => discard.answered(kind, answer),
            Some(Tool::SetUp(set_up)) => set_up.answered(kind, answer),
            Some(Tool::Settings(settings)) => return settings.answered(kind, answer),
            None => {}
        }
        Vec::new()
    }

    /// The question of the plan `data` the open tool asked for, and the
    /// word it asks to be typed first, if any; `None` when it is not the
    /// tool's plan.
    pub(super) fn tool_question(&self, data: &PlanData) -> Option<(Question, Option<String>)> {
        match (self.tool.as_ref()?, data) {
            (Tool::Discard(_), PlanData::Discard(plan)) => Some(discard::question(plan)),
            (Tool::SetUp(_), PlanData::Init(plan)) => Some((init::question(plan), None)),
            (Tool::Settings(settings), PlanData::ConfigEdit(plan)) => {
                settings.question(plan).map(|question| (question, None))
            }
            _ => None,
        }
    }

    /// The kind of the open tool, if any.
    #[must_use]
    pub fn open_tool(&self) -> Option<ToolKind> {
        self.tool.as_ref().map(Tool::kind)
    }
}

#[cfg(test)]
#[path = "tools_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tools_settings_tests.rs"]
mod settings_tests;
