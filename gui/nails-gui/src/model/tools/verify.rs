// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Verify: `nails verify`, standard or deep, and its result.
//!
//! The result page puts the verdict first, in the window's words, and never
//! more than the engine found: no known trace is no proof of none. Then what
//! it found, each with the engine's sentence and fix, and then every area
//! the run did not check, word for word as the engine lists them.

use nails_api::CheckOutcome;
use nails_api::protocol::VerifyArgs;

use super::{Context, ToolKind, error_of, group, row, tool_page};
use crate::client::Answer;
use crate::envelope::{self, Severity, VerifyData, VerifyStatus};
use crate::model::{ActionKind, Page};
use crate::text;
use crate::worker::{Ask, Kind};

/// What Verify knows.
#[derive(Debug, Clone, Default)]
pub(crate) struct Verify {
    /// Whether the last scan asked for was a deep one.
    deep: bool,
    /// How the last verify came out.
    outcome: Option<Outcome>,
}

#[derive(Debug, Clone)]
enum Outcome {
    Done(VerifyData),
    Failed(String),
}

impl Verify {
    /// The ask for `label`, one of the page's actions.
    pub(crate) fn action(&mut self, label: &str) -> Option<Ask> {
        self.deep = match label {
            text::VERIFY | text::VERIFY_AGAIN => false,
            text::DEEP_SCAN => true,
            _ => return None,
        };
        Some(Ask::Verify(VerifyArgs {
            deep: self.deep,
            ..VerifyArgs::default()
        }))
    }

    /// Take in the answer of a verify.
    pub(crate) fn answered(&mut self, answer: &Answer) {
        self.outcome = Some(
            match envelope::read::<VerifyData>(&answer.envelope, "verify") {
                Ok(read) => match read.data {
                    Some(data) => Outcome::Done(data),
                    None => Outcome::Failed(
                        error_of(&answer.envelope)
                            .map(|(_, message)| message)
                            .unwrap_or_else(|| text::NOTHING_CHANGED.to_string()),
                    ),
                },
                Err(error) => Outcome::Failed(text::sentence(&error.0)),
            },
        );
    }

    /// The page.
    pub(crate) fn page(&self, cx: &Context) -> Page {
        if cx.running == Some(Kind::Verify) {
            let mut page = tool_page(ToolKind::Verify, text::VERIFY_WHAT);
            page.heading = text::VERIFYING.to_string();
            page.busy = Some(text::LOOKING_FOR_TRACES.to_string());
            if self.deep {
                page.note = text::DEEP_SCAN_WHAT.to_string();
            }
            return page;
        }
        let mut page = match &self.outcome {
            None => Page {
                note: text::DEEP_SCAN_WHAT.to_string(),
                ..tool_page(ToolKind::Verify, text::VERIFY_WHAT)
            },
            Some(Outcome::Done(data)) => result_page(data),
            Some(Outcome::Failed(message)) => Page {
                heading: text::VERIFY_FAILED.to_string(),
                note: message.clone(),
                urgent: true,
                ..tool_page(ToolKind::Verify, text::NOTHING_CHANGED)
            },
        };
        page.action = Some(if self.outcome.is_some() {
            text::VERIFY_AGAIN
        } else {
            text::VERIFY
        });
        page.action_kind = ActionKind::Suggested;
        page.secondary = Some(text::DEEP_SCAN);
        page
    }
}

/// The page of a verify that answered with `data`.
fn result_page(data: &VerifyData) -> Page {
    let attention = data
        .findings
        .iter()
        .filter(|finding| finding.severity != Severity::Info)
        .count();
    let (heading, description, urgent) = match data.status {
        VerifyStatus::Secure => (
            text::NO_KNOWN_TRACES,
            text::verify_secure(
                data.checks_run,
                data.scan_depth == envelope::ScanDepth::Deep,
            ),
            false,
        ),
        VerifyStatus::Warning => (
            text::POSSIBLE_TRACES,
            text::possible_traces(attention),
            false,
        ),
        VerifyStatus::Critical => (text::TRACES_FOUND, text::traces_found(attention), true),
    };
    let mut findings = data.findings.clone();
    // The heaviest first: what is a trace, then what may be one, then notes.
    findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));
    let found = findings
        .iter()
        .map(|finding| {
            let (outcome, word) = match finding.severity {
                Severity::Critical => (CheckOutcome::Fail, text::SEVERITY_CRITICAL),
                Severity::Warn => (CheckOutcome::Warn, text::SEVERITY_WARN),
                Severity::Info => (CheckOutcome::Skipped, text::SEVERITY_NOTE),
            };
            row(
                outcome,
                word,
                text::sentence(&finding.message),
                finding
                    .fix_guidance
                    .as_deref()
                    .map(|fix| format!("Fix: {}", text::engine_fix(fix)))
                    .unwrap_or_default(),
            )
        })
        .collect();
    let not_checked = data
        .areas_not_checked
        .iter()
        .map(|area| {
            row(
                CheckOutcome::Skipped,
                text::NOT_CHECKED,
                text::sentence(&text::engine_fix(area)),
                String::new(),
            )
        })
        .collect();
    Page {
        heading: heading.to_string(),
        urgent,
        groups: [
            // Notes alone are no find: a page that found no known trace
            // calls them what they are.
            group(
                if attention == 0 {
                    text::GROUP_NOTED
                } else {
                    text::GROUP_FOUND
                },
                found,
            ),
            group(text::GROUP_NOT_CHECKED_RUN, not_checked),
        ]
        .into_iter()
        .flatten()
        .collect(),
        ..tool_page(ToolKind::Verify, &description)
    }
}
