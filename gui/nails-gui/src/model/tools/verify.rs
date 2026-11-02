// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Verify: `nails verify`, standard or deep, and its result.
//!
//! The result page puts the verdict first, in the window's words, and never
//! more than the engine found: no known trace is no proof of none. Then what
//! it found, each with the engine's sentence and fix, and then every area
//! the run did not check, word for word as the engine lists them.
//!
//! **Scan an Image** (`verify --offline --root`) looks at a decoy's disk or
//! image mounted read-only instead of this computer, with the examiner's
//! view of its setup traces when that switch is on (`--examiner`), and the
//! raw disk behind it when one is named (`--disk`). Its result is read as
//! Verify's is, the examiner's view after it, grouped by what it suggests.
//! An argument the helper would refuse unread, which would end the window's
//! session, is never sent: the scan waits for a full path. A folder the
//! engine refuses as holding nothing to scan says why and how to mount the
//! image so that nothing writes to it, and the line of that advice that runs
//! the CLI's scan says to scan again instead.

use nails_api::CheckOutcome;
use nails_api::protocol::{Op, VerifyArgs};

use super::{Context, ToolKind, error_of, fits, group, row, tool_page};
use crate::client::Answer;
use crate::envelope::{self, ExaminerView, Severity, VerifyData, VerifyStatus};
use crate::model::{ActionKind, Choice, Field, Page, Switch};
use crate::text;
use crate::worker::{Ask, Kind};

/// What Verify knows.
#[derive(Debug, Clone, Default)]
pub(crate) struct Verify {
    /// Whether the last scan asked for was a deep one.
    deep: bool,
    /// How the last verify came out.
    outcome: Option<Outcome>,
    /// The page that scans an image, while it is open.
    image: Option<ImageScan>,
    /// Whether the scan asked for last was of an image.
    asked_image: bool,
}

/// What the page that scans an image holds.
#[derive(Debug, Clone, Default)]
struct ImageScan {
    /// Where the image is mounted, as typed.
    root: String,
    /// Whether the examiner's view is on.
    examiner: bool,
    /// The disk behind it, as typed.
    disk: String,
    /// How its last scan came out, while the page still holds what it
    /// scanned.
    outcome: Option<Outcome>,
    /// The image that scan read.
    scanned: String,
}

impl ImageScan {
    /// The scan's arguments, the paths with spaces around them dropped; the
    /// disk counts only with the examiner's view, which it belongs to. `None`
    /// until the helper would take them.
    fn args(&self) -> Option<VerifyArgs> {
        let disk = self.disk.trim();
        let args = VerifyArgs {
            offline: true,
            root: Some(self.root.trim().to_string()),
            examiner: self.examiner,
            disk: (self.examiner && !disk.is_empty()).then(|| disk.to_string()),
            ..VerifyArgs::default()
        };
        fits(&Op::Verify(args.clone())).then_some(args)
    }
}

#[derive(Debug, Clone)]
enum Outcome {
    Done(VerifyData),
    /// The scan did not run: why, and what to do before the next one, when
    /// the engine says.
    Failed {
        why: String,
        fix: String,
    },
}

/// The code of an image root the engine refuses, before it scans anything,
/// as holding nothing to scan.
const NOTHING_TO_SCAN: &str = "nothing_to_scan";

/// What the engine's line that runs the CLI's scan of an image names.
const CLI_IMAGE_SCAN: &str = "verify --offline";

impl Verify {
    /// The ask for `label`, one of the page's actions.
    pub(crate) fn action(&mut self, label: &str) -> Option<Ask> {
        if let Some(image) = &self.image {
            if label != text::SCAN_IMAGE_ACTION {
                return None;
            }
            let args = image.args()?;
            if let Some(image) = &mut self.image {
                image.scanned = args.root.clone().unwrap_or_default();
            }
            self.asked_image = true;
            self.deep = false;
            return Some(Ask::Verify(args));
        }
        self.deep = match label {
            text::VERIFY | text::VERIFY_AGAIN => false,
            text::DEEP_SCAN => true,
            _ => return None,
        };
        self.asked_image = false;
        Some(Ask::Verify(VerifyArgs {
            deep: self.deep,
            ..VerifyArgs::default()
        }))
    }

    /// The person picked row `index` of the page: Scan an Image, the one
    /// row Verify's page has.
    pub(crate) fn choose(&mut self, index: usize) {
        if index == 0 && self.image.is_none() {
            self.image = Some(ImageScan::default());
        }
    }

    /// Back, from the page that scans an image to Verify's: whether there was
    /// such a page to leave.
    pub(crate) fn back(&mut self) -> bool {
        self.image.take().is_some()
    }

    /// The field `index` after the switch changed to `typed`: the disk behind
    /// the image. A result no longer matches what the page holds once that
    /// changes, so it goes.
    pub(crate) fn edited_more(&mut self, index: usize, typed: &str) {
        if let (Some(image), 0) = (&mut self.image, index)
            && image.disk != typed
        {
            typed.clone_into(&mut image.disk);
            image.outcome = None;
        }
    }

    /// The field changed to `typed`: where the image is mounted. The last
    /// result goes with a change.
    pub(crate) fn edited(&mut self, typed: &str) {
        if let Some(image) = &mut self.image
            && image.root != typed
        {
            typed.clone_into(&mut image.root);
            image.outcome = None;
        }
    }

    /// The examiner's view turned `on` or off. The last result goes with a
    /// change.
    pub(crate) fn toggled(&mut self, on: bool) {
        if let Some(image) = &mut self.image
            && image.examiner != on
        {
            image.examiner = on;
            image.outcome = None;
        }
    }

    /// Take in the answer of a verify.
    pub(crate) fn answered(&mut self, answer: &Answer) {
        let outcome = Some(
            match envelope::read::<VerifyData>(&answer.envelope, "verify") {
                Ok(read) => match read.data {
                    Some(data) => Outcome::Done(data),
                    None => refused(&answer.envelope),
                },
                Err(error) => Outcome::Failed {
                    why: text::sentence(&error.0),
                    fix: String::new(),
                },
            },
        );
        match &mut self.image {
            Some(image) if self.asked_image => image.outcome = outcome,
            _ => self.outcome = outcome,
        }
    }

    /// The page.
    pub(crate) fn page(&self, cx: &Context) -> Page {
        if let Some(image) = &self.image {
            return image_page(image, cx);
        }
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
            Some(Outcome::Failed { why, fix }) => Page {
                heading: text::VERIFY_FAILED.to_string(),
                note: why.clone(),
                fix: fix.clone(),
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
        page.choices = vec![Choice {
            title: text::SCAN_IMAGE_ROW.to_string(),
            subtitle: text::SCAN_IMAGE_ROW_WHAT.to_string(),
        }];
        page
    }
}

/// The page that scans an image: where it is mounted, the examiner's view
/// and the disk behind it, then the last scan's result.
fn image_page(image: &ImageScan, cx: &Context) -> Page {
    let mut page = image_page_of(image, cx);
    page.subpage = Some(text::SCAN_IMAGE.to_string());
    page
}

fn image_page_of(image: &ImageScan, cx: &Context) -> Page {
    if cx.running == Some(Kind::Verify) {
        return Page {
            heading: text::SCANNING_IMAGE.to_string(),
            busy: Some(text::LOOKING_FOR_TRACES.to_string()),
            ..tool_page(ToolKind::Verify, text::SCAN_IMAGE_WHAT)
        };
    }
    let mut page = match &image.outcome {
        None => Page {
            heading: text::SCAN_IMAGE.to_string(),
            ..tool_page(ToolKind::Verify, text::SCAN_IMAGE_WHAT)
        },
        Some(Outcome::Done(data)) => result_page(data),
        Some(Outcome::Failed { why, fix }) => Page {
            heading: text::VERIFY_FAILED.to_string(),
            note: why.clone(),
            fix: fix.clone(),
            urgent: true,
            ..tool_page(ToolKind::Verify, text::NOTHING_CHANGED)
        },
    };
    let full = |typed: &str| typed.trim().starts_with('/');
    page.field = Some(Field {
        label: text::FIELD_IMAGE_ROOT.to_string(),
        text: image.root.clone(),
        hint: if image.root.trim().is_empty() || full(&image.root) {
            text::IMAGE_ROOT_HINT
        } else {
            text::IMAGE_ROOT_NOT_ABSOLUTE
        }
        .to_string(),
    });
    page.switch = Some(Switch {
        title: text::SWITCH_EXAMINER.to_string(),
        subtitle: text::EXAMINER_WHAT.to_string(),
        on: image.examiner,
    });
    if image.examiner {
        page.more_fields = vec![Field {
            label: text::FIELD_DISK.to_string(),
            text: image.disk.clone(),
            hint: if image.disk.trim().is_empty() || full(&image.disk) {
                text::DISK_HINT
            } else {
                text::DISK_NOT_ABSOLUTE
            }
            .to_string(),
        }];
    }
    // Only a scan that ran is of an image: a refusal names its folder itself.
    if matches!(image.outcome, Some(Outcome::Done(_))) {
        page.facts
            .push((text::FACT_SCANNED_IMAGE.to_string(), image.scanned.clone()));
    }
    page.action = Some(text::SCAN_IMAGE_ACTION);
    page.action_kind = ActionKind::Suggested;
    page.action_locked = image.args().is_none();
    page
}

/// The outcome of a verify that answered `envelope`, an error: the engine's
/// message. A root with nothing to scan answers why and then how to mount the
/// image first: the page gives why as its note and the advice as its fix, in
/// the engine's words but for the advice's line that runs the CLI's scan,
/// which in the window is Scan Image again.
fn refused(envelope: &serde_json::Value) -> Outcome {
    let Some((code, message)) = error_of(envelope) else {
        return Outcome::Failed {
            why: text::NOTHING_CHANGED.to_string(),
            fix: String::new(),
        };
    };
    match message.split_once('\n') {
        Some((why, advice)) if code == NOTHING_TO_SCAN => Outcome::Failed {
            why: text::sentence(why),
            fix: advice
                .lines()
                .map(|line| {
                    if line.contains(CLI_IMAGE_SCAN) {
                        text::MOUNT_THEN_SCAN_AGAIN.to_string()
                    } else {
                        text::engine_fix(line)
                    }
                })
                .collect::<Vec<_>>()
                .join("\n"),
        },
        _ => Outcome::Failed {
            why: message,
            fix: String::new(),
        },
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
    let mut groups: Vec<_> = [
        // Notes alone are no find: a page that found no known trace calls
        // them what they are.
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
    .collect();
    if let Some(examiner) = &data.examiner {
        groups.extend(examiner_groups(examiner));
    }
    Page {
        heading: heading.to_string(),
        urgent,
        groups,
        ..tool_page(ToolKind::Verify, &description)
    }
}

/// The examiner's view of an image: a group for each conclusion with its
/// traces, where each lies first, then what the view did not look at.
fn examiner_groups(examiner: &ExaminerView) -> Vec<crate::model::Group> {
    let mut groups: Vec<_> = examiner
        .groups
        .iter()
        .filter_map(|conclusion| {
            group(
                &text::examiner_group(&conclusion.conclusion),
                conclusion
                    .findings
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
                            format!(
                                "{}: {}",
                                finding.location,
                                text::sentence(&text::engine_fix(&finding.evidence))
                            ),
                            String::new(),
                        )
                    })
                    .collect(),
            )
        })
        .collect();
    groups.extend(group(
        text::GROUP_EXAMINER_NOT_CHECKED,
        examiner
            .not_checked
            .iter()
            .map(|area| {
                row(
                    CheckOutcome::Skipped,
                    text::NOT_CHECKED,
                    text::sentence(&text::engine_fix(area)),
                    String::new(),
                )
            })
            .collect(),
    ));
    groups
}
