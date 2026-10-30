// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Rehearsal: the four steps of `nails rehearse` and the scan's result.
//!
//! The page shows the three steps of a rehearsal and where it stands, from
//! the engine's `rehearse status`, which runs when the page opens: plant the
//! test words in a hidden session, end that session as usual, then scan this
//! computer's disks for them from the decoy or a later hidden session. Its
//! action is the step that comes next: Plant Test Words in a hidden session,
//! Scan for Test Words once they are planted, and once a scan ran Scan Again,
//! with Remove Test Words (`rehearse reset`) on the decoy, where the engine
//! allows it.
//!
//! A scan in the session that planted the test words is refused by the
//! engine, which then cannot have read what the session wrote. The window
//! knows that session only when it planted there itself, or once the engine
//! refused a scan for that reason; it then offers no scan until the session
//! ended.
//!
//! **The scan's result never reads as more than the scan proved.** Found:
//! where, first. Otherwise a disk whose storage can hide the test words
//! (compressed, copy-on-write, encrypted, no filesystem the scan knows) is
//! not checked, and the verdict says so instead of passing; a disk that
//! could not be read in full leaves the scan incomplete. Every result lists
//! first what the scan did not check: those disks, then each blind spot the
//! engine names for every scan of its kind, word for word.

use nails_api::CheckOutcome;
use nails_api::protocol::{RehearsePlantArgs, RehearseScanArgs};

use super::{Context, ToolKind, error_of, group, row, tool_page};
use crate::client::Answer;
use crate::envelope::{self, Channel, DeviceScan, Phase, RehearseData, ScanReport};
use crate::model::{Group, Page, StepView};
use crate::text;
use crate::worker::{Ask, Kind, Rehearse};

/// The engine's code for a scan refused in the session that planted.
const SAME_SESSION: &str = "same_boot";

/// The step of a rehearsal asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Status,
    Plant,
    Scan,
    Reset,
}

/// What Rehearsal knows.
#[derive(Debug, Clone)]
pub(crate) struct Rehearsal {
    /// The step asked for last.
    asked: Step,
    /// Where the rehearsal stands, by the engine's last answer.
    phase: Option<Phase>,
    /// Where the test words went.
    channels: Vec<Channel>,
    /// What the last step showed that the page shows over its steps.
    shown: Option<Shown>,
    /// The engine's words for a step that failed.
    notice: Option<String>,
    /// The test words were planted in this very session.
    planted_here: bool,
}

/// What the page shows over the rehearsal's steps.
#[derive(Debug, Clone)]
enum Shown {
    /// The plant this window made.
    Planted,
    /// A scan's result, and its exit code.
    Scan(Box<ScanReport>, u8),
    /// What the reset removed.
    Removed(Vec<String>),
}

impl Rehearsal {
    /// A rehearsal page that opens, and the status it asks for first.
    pub(crate) fn open() -> (Self, Ask) {
        (
            Self {
                asked: Step::Status,
                phase: None,
                channels: Vec::new(),
                shown: None,
                notice: None,
                planted_here: false,
            },
            Ask::Rehearse(Rehearse::Status),
        )
    }

    /// The ask for `label`, one of the page's actions, in a hidden session
    /// when `hidden`.
    pub(crate) fn action(&mut self, label: &str, hidden: bool) -> Option<Ask> {
        let (step, ask) = match label {
            text::PLANT if hidden => (Step::Plant, Rehearse::Plant(RehearsePlantArgs::default())),
            text::SCAN | text::SCAN_AGAIN => {
                (Step::Scan, Rehearse::Scan(RehearseScanArgs::default()))
            }
            text::REMOVE_TEST_WORDS if !hidden => (Step::Reset, Rehearse::Reset),
            _ => return None,
        };
        self.asked = step;
        self.notice = None;
        Some(Ask::Rehearse(ask))
    }

    /// Take in the answer of the step asked for.
    pub(crate) fn answered(&mut self, answer: &Answer) {
        let read = match envelope::read::<RehearseData>(&answer.envelope, "rehearse") {
            Ok(read) => read,
            Err(error) => {
                self.notice = Some(text::sentence(&error.0));
                return;
            }
        };
        let Some(data) = read.data else {
            let (code, message) = error_of(&answer.envelope)
                .unwrap_or_else(|| (String::new(), text::NOTHING_CHANGED.to_string()));
            if self.asked == Step::Scan && code == SAME_SESSION {
                self.planted_here = true;
                self.notice = Some(text::REHEARSAL_SAME_SESSION.to_string());
            } else {
                self.notice = Some(message);
            }
            return;
        };
        self.phase = Some(data.phase);
        self.channels = data.channels;
        self.shown = match self.asked {
            Step::Status => None,
            Step::Plant => {
                self.planted_here = true;
                Some(Shown::Planted)
            }
            Step::Scan => data
                .scan
                .map(|report| Shown::Scan(Box::new(report), answer.exit)),
            Step::Reset => Some(Shown::Removed(data.removed)),
        };
    }

    /// The page.
    pub(crate) fn page(&self, cx: &Context) -> Page {
        let mut page = match &self.shown {
            _ if cx.running == Some(Kind::Rehearse) => self.busy_page(),
            Some(Shown::Scan(report, exit)) => scan_page(report, *exit, &self.channels),
            Some(Shown::Planted) => Page {
                heading: text::PLANTED.to_string(),
                groups: planted_groups(&self.channels),
                ..tool_page(
                    ToolKind::Rehearsal,
                    &text::planted_in(planted(&self.channels)),
                )
            },
            Some(Shown::Removed(removed)) => Page {
                heading: text::TEST_WORDS_REMOVED.to_string(),
                groups: group(
                    text::GROUP_REMOVED,
                    removed
                        .iter()
                        .map(|path| {
                            row(
                                CheckOutcome::Skipped,
                                text::REMOVED_WORD,
                                text::without_canary(path),
                                String::new(),
                            )
                        })
                        .collect(),
                )
                .into_iter()
                .collect(),
                ..tool_page(ToolKind::Rehearsal, text::REHEARSAL_GONE)
            },
            None => tool_page(ToolKind::Rehearsal, text::REHEARSAL_WHAT),
        };
        if cx.running != Some(Kind::Rehearse) {
            self.next(&mut page, cx.hidden);
        }
        page
    }

    fn busy_page(&self) -> Page {
        let (heading, busy, description) = match self.asked {
            Step::Status => (
                text::REHEARSAL,
                text::READING_REHEARSAL,
                text::REHEARSAL_WHAT,
            ),
            Step::Plant => (text::REHEARSAL, text::PLANTING, text::REHEARSAL_WHAT),
            Step::Scan => (text::SCANNING, text::READING_DISKS, text::SCAN_HOW_LONG),
            Step::Reset => (text::REHEARSAL, text::REMOVING, text::REHEARSAL_WHAT),
        };
        Page {
            heading: heading.to_string(),
            busy: Some(busy.to_string()),
            ..tool_page(ToolKind::Rehearsal, description)
        }
    }

    /// The steps, where the rehearsal stands, and the action of the step
    /// that comes next, in a hidden session when `hidden`.
    fn next(&self, page: &mut Page, hidden: bool) {
        let Some(phase) = self.phase else {
            // The status did not answer: there is nothing to go on.
            page.note = join_notice(self.notice.as_deref(), "");
            return;
        };
        let (states, line, action, secondary) = match phase {
            Phase::None if hidden => ([NOW, NEXT, NEXT], "", Some(text::PLANT), None),
            Phase::None => (
                [NEXT, NEXT, NEXT],
                text::REHEARSAL_STARTS_HIDDEN,
                None,
                None,
            ),
            Phase::Planted if self.planted_here => {
                ([DONE, NOW, NEXT], text::AFTER_PLANT, None, None)
            }
            Phase::Planted => (
                [DONE, DONE, NOW],
                text::REHEARSAL_PLANTED,
                Some(text::SCAN),
                (!hidden).then_some(text::REMOVE_TEST_WORDS),
            ),
            Phase::Scanned => (
                [DONE, DONE, DONE],
                if hidden {
                    text::REMOVE_ON_DECOY
                } else {
                    text::REHEARSAL_SCANNED
                },
                Some(text::SCAN_AGAIN),
                (!hidden).then_some(text::REMOVE_TEST_WORDS),
            ),
        };
        // A scan's or a reset's result takes the steps' place.
        if !matches!(self.shown, Some(Shown::Scan(..) | Shown::Removed(_))) {
            page.steps = [text::STEP_PLANT, text::STEP_END, text::STEP_SCAN]
                .iter()
                .zip(states)
                .map(|(label, state)| StepView {
                    label: (*label).to_string(),
                    state,
                })
                .collect();
        }
        page.note = join_notice(self.notice.as_deref(), &page.note);
        if page.fix.is_empty() {
            line.clone_into(&mut page.fix);
        }
        page.action = action;
        page.secondary = secondary;
    }
}

const DONE: &str = text::STEP_DONE;
const NOW: &str = text::STEP_NOW;
const NEXT: &str = text::STEP_NEXT;

fn join_notice(notice: Option<&str>, note: &str) -> String {
    crate::model::pages::join(notice.unwrap_or_default(), note)
}

/// How many places took the test words.
fn planted(channels: &[Channel]) -> usize {
    channels
        .iter()
        .filter(|channel| channel.skipped.is_none())
        .count()
}

/// The places the test words went, and those they did not.
fn planted_groups(channels: &[Channel]) -> Vec<Group> {
    let planted = channels
        .iter()
        .filter(|channel| channel.skipped.is_none())
        .map(|channel| {
            row(
                CheckOutcome::Pass,
                text::PLANTED_WORD,
                place(channel, &channel.location),
                String::new(),
            )
        })
        .collect();
    [
        group(text::GROUP_PLANTED, planted),
        group(text::GROUP_NOT_TESTED, not_tested(channels)),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// The places the test words never went: a scan says nothing of them.
fn not_tested(channels: &[Channel]) -> Vec<crate::model::CheckView> {
    channels
        .iter()
        .filter_map(|channel| {
            let reason = channel.skipped.as_deref()?;
            Some(row(
                CheckOutcome::Skipped,
                text::NOT_TESTED,
                place(channel, reason),
                String::new(),
            ))
        })
        .collect()
}

/// `what` of a place the test words go into, as a row says it.
fn place(channel: &Channel, what: &str) -> String {
    format!(
        "{}: {}",
        text::channel(&channel.kind),
        text::without_canary(what)
    )
}

/// The page of a scan that answered with `report` and `exit`.
fn scan_page(report: &ScanReport, exit: u8, channels: &[Channel]) -> Page {
    let found: Vec<&DeviceScan> = report
        .devices
        .iter()
        .filter(|device| !device.hits.is_empty())
        .collect();
    // A disk whose storage can hide the test words, and where none was
    // found, is not checked: a clean read of it proves nothing.
    let hidden_from_scan: Vec<&DeviceScan> = report
        .devices
        .iter()
        .filter(|device| device.blind_spot.is_some() && device.hits.is_empty())
        .collect();
    let unread: Vec<&DeviceScan> = report
        .devices
        .iter()
        .filter(|device| device.error.is_some() || device.limit_reached)
        .collect();
    let (heading, description, urgent) = if let Some(first) = found.first() {
        (
            text::TEST_WORDS_FOUND,
            text::test_words_found(&first.device, first.hits[0].offset),
            true,
        )
    } else if !hidden_from_scan.is_empty() {
        (
            text::NOT_A_CLEAN_RESULT,
            text::blind_spots(hidden_from_scan.len()),
            false,
        )
    } else if !unread.is_empty() {
        (text::SCAN_INCOMPLETE, text::incomplete(unread.len()), false)
    } else if exit != 0 {
        // The engine did not call it clean, for a reason the window does
        // not read: never a pass.
        (
            text::NOT_A_CLEAN_RESULT,
            text::NOT_CLEAN_UNEXPLAINED.to_string(),
            false,
        )
    } else {
        let bytes = report.devices.iter().map(|device| device.size).sum();
        (
            text::PASSED,
            text::passed(report.devices.len(), bytes),
            false,
        )
    };
    let mut not_checked: Vec<_> = hidden_from_scan
        .iter()
        .map(|device| {
            let reason = device.blind_spot.as_deref().unwrap_or_default();
            row(
                CheckOutcome::Warn,
                text::NOT_CHECKED,
                format!("{}: {}", device.device, text::sentence(reason)),
                String::new(),
            )
        })
        .collect();
    not_checked.extend(report.not_visible.iter().map(|line| {
        row(
            CheckOutcome::Skipped,
            text::NOT_CHECKED,
            text::sentence(&text::engine_fix(line)),
            String::new(),
        )
    }));
    let disks = report
        .devices
        .iter()
        .filter(|device| device.blind_spot.is_none() || !device.hits.is_empty())
        .map(disk_row)
        .collect();
    let not_checked = group(text::GROUP_NOT_CHECKED_SCAN, not_checked);
    let disks = group(text::GROUP_DISKS, disks);
    // What the scan did not check comes first, but where the test words were
    // found: there, where they are matters most.
    let groups = if found.is_empty() {
        [not_checked, disks]
    } else {
        [disks, not_checked]
    };
    Page {
        heading: heading.to_string(),
        urgent,
        groups: groups
            .into_iter()
            .chain([group(text::GROUP_NOT_TESTED, not_tested(channels))])
            .flatten()
            .collect(),
        ..tool_page(ToolKind::Rehearsal, &description)
    }
}

/// The row of one disk the scan read, or tried to.
fn disk_row(device: &DeviceScan) -> crate::model::CheckView {
    if let Some(hit) = device.hits.first() {
        let more = device.hits.len() > 1 || device.hits_capped;
        let message = if more {
            format!(
                "{}, byte {} and more places on it",
                device.device, hit.offset
            )
        } else {
            format!("{}, byte {}", device.device, hit.offset)
        };
        return row(CheckOutcome::Fail, text::FOUND_WORD, message, String::new());
    }
    if let Some(error) = &device.error {
        return row(
            CheckOutcome::Warn,
            text::INCOMPLETE_WORD,
            format!("{}: not read: {}", device.device, text::sentence(error)),
            String::new(),
        );
    }
    if device.limit_reached {
        return row(
            CheckOutcome::Warn,
            text::INCOMPLETE_WORD,
            format!(
                "{}: read {} of {}",
                device.device,
                text::size(device.bytes_scanned),
                text::size(device.size)
            ),
            String::new(),
        );
    }
    row(
        CheckOutcome::Pass,
        text::READ_WORD,
        format!(
            "{}: {} read in full",
            device.device,
            text::size(device.size)
        ),
        String::new(),
    )
}
