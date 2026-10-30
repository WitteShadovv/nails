// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The window's tools: Verify and Rehearsal, each a page of its own over the
//! session's page.
//!
//! A row of the session's page opens a tool, once that page settled, on both
//! sides. Back (or Escape) leaves a tool for the session's page, whose status
//! it asks for again.
//!
//! - **Verify** ([`verify`]) and each step of the **rehearsal**
//!   ([`rehearsal`]) are requests of their own, as their CLI commands ask
//!   nothing first.
//!
//! The helper serves one request at a time, and a verify or a scan can run
//! for minutes. Meanwhile a tool's page takes nothing but the window's Close
//! and, in a hidden session, the Emergency control, whose way out does not
//! wait for the helper ([`crate::emergency`]).

use super::{CheckView, Effect, Group, Model, Page, View};
use crate::client::Answer;
use crate::envelope::Place;
use crate::text;
use crate::worker::{Ask, Kind};

mod rehearsal;
mod verify;

/// A tool the session's page offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolKind {
    /// Look for traces.
    Verify,
    /// Plant test words, scan for them, remove them.
    Rehearsal,
}

impl ToolKind {
    /// The tools a page of `place` offers, in their order.
    #[must_use]
    pub fn offered(place: Place) -> &'static [ToolKind] {
        match place {
            Place::Decoy | Place::Hidden => &[ToolKind::Verify, ToolKind::Rehearsal],
            Place::Activating | Place::Unknown => &[],
        }
    }

    /// The row's title, which is the tool page's too.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            ToolKind::Verify => text::VERIFY,
            ToolKind::Rehearsal => text::REHEARSAL,
        }
    }

    /// The line under the row's title.
    #[must_use]
    pub fn what(self) -> &'static str {
        match self {
            ToolKind::Verify => text::VERIFY_WHAT,
            ToolKind::Rehearsal => text::REHEARSAL_WHAT,
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
}

impl Tool {
    fn kind(&self) -> ToolKind {
        match self {
            Tool::Verify(_) => ToolKind::Verify,
            Tool::Rehearsal(_) => ToolKind::Rehearsal,
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
    /// The rows of the session's page that open a tool on `place`.
    pub(super) fn links(&self, place: Place) -> Vec<Link> {
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
                let (rehearsal, first) = rehearsal::Rehearsal::open();
                (Tool::Rehearsal(rehearsal), Some(first))
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
        self.tool.take()?;
        Some(Ask::Status)
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
        }
    }

    /// The open tool's page.
    pub(super) fn tool_page(&self) -> Option<Page> {
        let cx = self.context();
        Some(match self.tool.as_ref()? {
            Tool::Verify(verify) => verify.page(&cx),
            Tool::Rehearsal(rehearsal) => rehearsal.page(&cx),
        })
    }

    /// What the open tool's action `label` does.
    pub(super) fn tool_action(&mut self, label: &str) -> Option<Effect> {
        let hidden = self.context().hidden;
        let ask = match self.tool.as_mut()? {
            Tool::Verify(verify) => verify.action(label),
            Tool::Rehearsal(rehearsal) => rehearsal.action(label, hidden),
        }?;
        Some(Effect::Ask(ask))
    }

    /// Whether the answer of a `kind` request is the open tool's.
    pub(super) fn answers_tool(&self, kind: Kind) -> bool {
        match kind {
            Kind::Verify | Kind::Rehearse => self.tool.is_some(),
            Kind::Status | Kind::Check | Kind::Recover | Kind::Plan | Kind::Apply => false,
        }
    }

    /// Take in the answer of the open tool's `kind` request.
    pub(super) fn tool_answered(&mut self, _kind: Kind, answer: &Answer) -> Vec<Ask> {
        match self.tool.as_mut() {
            Some(Tool::Verify(verify)) => verify.answered(answer),
            Some(Tool::Rehearsal(rehearsal)) => rehearsal.answered(answer),
            None => {}
        }
        Vec::new()
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
