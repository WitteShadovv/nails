// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Discard Hidden Changes: `nails discard <folder>`, as a plan, its token
//! and its apply.
//!
//! The person types the folder (its full path; the window sends nothing
//! else, since the helper ends the session over a path of the wrong shape)
//! and presses Discard…. The window sends the folder as the engine reads
//! it, from its components ([`canonical_folder`]): `//home`, `/./home` and
//! `/home/` are all `/home` to the engine, so they are `/home` to the plan,
//! the question and the word it asks for too. The plan's answer says what
//! the apply would delete, and the question says exactly that: every hidden
//! change in the folder goes, and each path it deletes from the hidden
//! volume. A plan that warns asks for the folder itself to be typed before
//! Delete acts: a folder that holds a home (the person's own files in the
//! hidden sessions are among its hidden changes) and `/nix` (its hidden Nix
//! database and store paths go too). A plan with nothing to delete answers
//! at once, with no question.

use std::path::{Component, Path};

use nails_api::CheckOutcome;
use nails_api::protocol::{DiscardPlanArgs, DiscardPlanData};

use super::{Context, ToolKind, error_of, group, row, tool_page};
use crate::client::{Answer, Plan};
use crate::envelope::{self, DiscardData};
use crate::model::{ActionKind, Field, Page, Question};
use crate::text;
use crate::worker::{Ask, Kind};

/// The homes a folder can hold: a discard of any of them, of a folder in
/// one or of a folder above one deletes the person's own files of the
/// hidden sessions with it.
const HOMES: [&str; 3] = ["/home", "/root", "/var/home"];

/// What Discard knows.
#[derive(Debug, Clone, Default)]
pub(crate) struct Discard {
    /// The folder as typed.
    folder: String,
    /// How the last plan or apply came out.
    outcome: Option<Outcome>,
    /// An apply deleted something.
    deleted: bool,
}

#[derive(Debug, Clone)]
enum Outcome {
    /// Nothing to delete in the folder.
    Nothing(String),
    /// The apply deleted what it lists.
    Discarded(DiscardData),
    /// The engine refused or failed, in its words.
    Failed { applied: bool, message: String },
}

/// `folder` as the engine reads it, from its components: each repeated or
/// trailing slash and each `.` dropped, as Rust's `Path` drops them for the
/// engine. `None` for one the engine refuses or the helper does not take:
/// not absolute, with a `..`, with a control character, or the root itself.
#[must_use]
pub fn canonical_folder(folder: &str) -> Option<String> {
    let folder = folder.trim();
    if !folder.starts_with('/') || folder.chars().any(char::is_control) {
        return None;
    }
    let mut canonical = String::new();
    for component in Path::new(folder).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                canonical.push('/');
                canonical.push_str(name.to_str()?);
            }
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    (!canonical.is_empty()).then_some(canonical)
}

/// Whether `folder` is a path the helper takes and the engine plans for.
#[must_use]
pub fn valid_folder(folder: &str) -> bool {
    canonical_folder(folder).is_some()
}

/// Whether a discard of `target` deletes a home's hidden changes: the
/// target is a home, lies in one or holds one, compared by component, as
/// the engine finds the hidden copy of the target.
#[must_use]
pub fn holds_a_home(target: &str) -> bool {
    let target = Path::new(target.trim());
    HOMES
        .iter()
        .any(|home| target.starts_with(home) || Path::new(home).starts_with(target))
}

impl Discard {
    /// Whether an apply deleted something, so the check may find otherwise.
    pub(crate) fn changed(&self) -> bool {
        self.deleted
    }

    /// The folder field changed to `typed`.
    pub(crate) fn edited(&mut self, typed: &str) {
        typed.clone_into(&mut self.folder);
    }

    /// The ask for `label`, the page's action.
    pub(crate) fn action(&mut self, label: &str) -> Option<Ask> {
        if label != text::DISCARD_ACTION {
            return None;
        }
        let target = canonical_folder(&self.folder)?;
        self.outcome = None;
        Some(Ask::Plan(Plan::Discard(DiscardPlanArgs {
            target,
            allow_decoy_storage: false,
        })))
    }

    /// Take in the answer of a plan that settled, or of the apply.
    pub(crate) fn answered(&mut self, kind: Kind, answer: &Answer) {
        let applied = kind == Kind::Apply;
        let read = match envelope::read::<DiscardData>(&answer.envelope, "discard") {
            Ok(read) => read,
            Err(error) => {
                self.outcome = Some(Outcome::Failed {
                    applied,
                    message: text::sentence(&error.0),
                });
                return;
            }
        };
        self.outcome = Some(match (read.data, error_of(&answer.envelope)) {
            (Some(data), _) if data.removed.is_empty() => Outcome::Nothing(data.target),
            (Some(data), _) => {
                self.deleted = true;
                // Done: the folder goes, so Discard… waits for the next one.
                self.folder.clear();
                Outcome::Discarded(data)
            }
            (None, error) => Outcome::Failed {
                applied,
                message: error.map_or_else(|| text::NOTHING_CHANGED.to_string(), |(_, m)| m),
            },
        });
    }

    /// The page.
    pub(crate) fn page(&self, cx: &Context) -> Page {
        let mut page = match &self.outcome {
            Some(Outcome::Discarded(data)) => Page {
                heading: text::DISCARDED.to_string(),
                groups: group(
                    text::GROUP_DELETED,
                    data.removed
                        .iter()
                        .map(|path| {
                            row(
                                CheckOutcome::Skipped,
                                text::DELETED_WORD,
                                path.clone(),
                                String::new(),
                            )
                        })
                        .collect(),
                )
                .into_iter()
                .collect(),
                ..tool_page(ToolKind::Discard, &text::discarded(&data.target))
            },
            Some(Outcome::Nothing(target)) => Page {
                note: text::nothing_to_discard(target),
                ..tool_page(ToolKind::Discard, text::DISCARD_WHAT)
            },
            Some(Outcome::Failed { applied, message }) => Page {
                heading: if *applied {
                    text::DISCARD_FAILED
                } else {
                    text::NOT_DISCARDED
                }
                .to_string(),
                note: message.clone(),
                urgent: *applied,
                ..tool_page(ToolKind::Discard, text::DISCARD_WHAT)
            },
            None => tool_page(ToolKind::Discard, text::DISCARD_WHAT),
        };
        page.busy = match cx.running {
            Some(Kind::Plan) => Some(text::LOOKING_AT_CHANGES.to_string()),
            Some(Kind::Apply) => Some(text::DELETING.to_string()),
            _ => None,
        };
        let typed = !self.folder.trim().is_empty();
        page.field = Some(Field {
            label: text::FIELD_FOLDER.to_string(),
            text: self.folder.clone(),
            hint: if typed && !valid_folder(&self.folder) {
                text::FOLDER_NOT_ABSOLUTE
            } else {
                text::FOLDER_HINT
            }
            .to_string(),
        });
        // Never in a hidden session, by either reading: fail closed.
        if !cx.hidden {
            page.action = Some(text::DISCARD_ACTION);
        }
        page.action_kind = ActionKind::Destructive;
        page.action_locked = !valid_folder(&self.folder);
        page
    }
}

/// The question of the plan `data`, and the word it asks for first when
/// the plan warns: the folder itself.
pub(crate) fn question(data: &DiscardPlanData) -> (Question, Option<String>) {
    let home = holds_a_home(&data.target);
    let mut lines = vec![
        text::discard_consequence(&data.target),
        text::DISCARD_LIST.to_string(),
    ];
    lines.extend(data.removals.iter().cloned());
    if data.resets_nix_store {
        lines.push(text::DISCARD_NIX.to_string());
    }
    let word = (home || data.resets_nix_store).then(|| data.target.clone());
    (
        Question {
            heading: text::DISCARD_QUESTION.to_string(),
            body: lines.join("\n"),
            confirm: text::DELETE.to_string(),
            destructive: true,
            prompt: word
                .as_deref()
                .map(|target| text::discard_type(target, home)),
            locked: word.is_some(),
            alternative: None,
        },
        word,
    )
}
