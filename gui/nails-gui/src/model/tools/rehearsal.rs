// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Rehearsal: the four steps of `nails rehearse` and the scan's result.
//!
//! The page shows the three steps of a rehearsal and where it stands, from
//! the engine's `rehearse status`, which runs when the page opens: plant the
//! test words in a hidden session, end that session as usual, then scan this
//! computer's disks for them from a later hidden session (or the decoy).
//! Its action is the step that comes next: Plant Test Words in a hidden
//! session, for the account named in its field when one is (`rehearse plant
//! --user`), else for the window's own; Scan for Test Words once they are
//! planted, and once a scan ran
//! Scan Again, with Remove Test Words (`rehearse reset`) on the decoy, where
//! the engine allows it. No window opens on the decoy in this release, so a
//! hidden session's page names the line that removes them there instead.
//!
//! A scan in the session that planted the test words is refused by the
//! engine, which then cannot have read what the session wrote. The window
//! knows that session only when it planted there itself, or once the engine
//! refused a scan for that reason, and it keeps knowing it when the page
//! closes and opens again ([`Rehearsal::planted_here`]): for as long as the
//! window lives, which is that session at most, it offers no plain scan,
//! only Scan in This Session, which asks first (`--allow-same-boot`), and
//! whose result never reads as a pass, since such a scan proves little. A
//! window opened again in the session that planted learns it again from the
//! engine's refusal.
//!
//! A step that fails replaces whatever the page showed before with what
//! failed and the engine's words: a scan that could not run is never read
//! as the verdict of the scan before it.
//!
//! **The scan's result never reads as more than the scan proved.** Found:
//! where, first. Otherwise a disk whose storage can hide the test words
//! (compressed, copy-on-write, encrypted, no filesystem the scan knows) is
//! not checked, and the verdict says so instead of passing; a disk that
//! could not be read in full leaves the scan incomplete. Every result lists
//! first what the scan did not check: those disks, then each blind spot the
//! engine names for every scan of its kind, word for word.

use nails_api::CheckOutcome;
use nails_api::protocol::{Op, RehearsePlantArgs, RehearseScanArgs};

use super::{Context, ToolKind, error_of, fits, group, row, tool_page};
use crate::client::Answer;
use crate::envelope::{self, Channel, DeviceScan, Phase, RehearseData, ScanReport};
use crate::model::{Choice, Field, Group, Page, Question, StepView, Switch};
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
    /// The account the test words are planted for, as typed: empty for the
    /// window's own.
    account: String,
    /// The page that scans other disks or images, and what was typed there.
    other: OtherDisks,
    /// The arguments of the last scan asked for, which Scan Again repeats.
    last_scan: RehearseScanArgs,
}

/// The page that scans the disks the person names, or images of them,
/// instead of this computer's mounted disks (`rehearse scan --device`, or
/// `--offline --image` with `--token-file`; `--max-bytes` for both).
#[derive(Debug, Clone, Default)]
struct OtherDisks {
    /// Whether the page shows.
    open: bool,
    /// Whether it scans images (`--offline`).
    images: bool,
    /// The disks, as typed.
    disks: String,
    /// The images, as typed.
    image_paths: String,
    /// The token file, as typed.
    token_file: String,
    /// Where each disk's read stops, in megabytes, as typed.
    stop_after: String,
}

/// The one path `typed` names, spaces around it dropped, when it is a full
/// path the helper takes; spaces inside it are part of it.
fn full_path(typed: &str) -> Option<String> {
    let path = typed.trim();
    (path.starts_with('/') && !path.chars().any(char::is_control)).then(|| path.to_string())
}

/// The bytes `typed` megabytes make (a megabyte is a million bytes): none
/// when it is empty, `Err` when it is no whole number.
fn megabytes(typed: &str) -> Result<Option<u64>, ()> {
    let typed = typed.trim();
    if typed.is_empty() {
        return Ok(None);
    }
    typed
        .parse::<u64>()
        .ok()
        .and_then(|mb| mb.checked_mul(1_000_000))
        .map(Some)
        .ok_or(())
}

impl OtherDisks {
    /// The scan's arguments: the disks, or with the switch the images and
    /// the token file, and where each read stops. `None` until the helper
    /// would take them.
    fn args(&self) -> Option<RehearseScanArgs> {
        let max_bytes = megabytes(&self.stop_after).ok()?;
        let args = if self.images {
            let token = self.token_file.trim();
            RehearseScanArgs {
                offline: true,
                images: vec![full_path(&self.image_paths)?],
                token_file: if token.is_empty() {
                    None
                } else {
                    Some(full_path(token)?)
                },
                max_bytes,
                ..RehearseScanArgs::default()
            }
        } else {
            // A disk is named: an empty field would scan this computer's
            // own disks, which is the rehearsal's plain scan.
            RehearseScanArgs {
                devices: vec![full_path(&self.disks)?],
                max_bytes,
                ..RehearseScanArgs::default()
            }
        };
        fits(&Op::RehearseScan(args.clone())).then_some(args)
    }

    /// Its page: the switch first, as it says what the fields take, then the
    /// disks, or the images and the token file, then where each read stops.
    fn page(&self) -> Page {
        let mut page = Page {
            heading: text::SCAN_OTHER.to_string(),
            ..tool_page(ToolKind::Rehearsal, text::SCAN_OTHER_WHAT)
        };
        page.switch_first = true;
        page.switch = Some(Switch {
            title: text::SWITCH_IMAGES.to_string(),
            subtitle: text::IMAGES_WHAT.to_string(),
            on: self.images,
        });
        let field = |label: &str, typed: &str, hint: &str| Field {
            label: label.to_string(),
            text: typed.to_string(),
            hint: hint.to_string(),
        };
        let stop_after = field(
            text::FIELD_STOP_AFTER,
            &self.stop_after,
            if megabytes(&self.stop_after).is_ok() {
                text::STOP_AFTER_HINT
            } else {
                text::STOP_AFTER_NOT_A_NUMBER
            },
        );
        // The hint of a path field: what it takes, or why what it holds is
        // not taken, by the same reading the scan's arguments use.
        let path_hint = |typed: &str, hint: &'static str, needed: &'static str| {
            if typed.trim().is_empty() {
                needed
            } else if full_path(typed).is_none() {
                text::PATH_NOT_ABSOLUTE
            } else {
                hint
            }
        };
        if self.images {
            page.field = Some(field(
                text::FIELD_IMAGE,
                &self.image_paths,
                path_hint(&self.image_paths, text::IMAGE_HINT, text::IMAGE_NEEDED),
            ));
            page.more_fields = vec![
                field(
                    text::FIELD_TOKEN_FILE,
                    &self.token_file,
                    path_hint(
                        &self.token_file,
                        text::TOKEN_FILE_HINT,
                        text::TOKEN_FILE_HINT,
                    ),
                ),
                stop_after,
            ];
        } else {
            page.field = Some(field(
                text::FIELD_DISK_SCAN,
                &self.disks,
                path_hint(&self.disks, text::DISK_SCAN_HINT, text::DISK_SCAN_NEEDED),
            ));
            page.more_fields = vec![stop_after];
        }
        page.action = Some(text::SCAN);
        page.action_locked = self.args().is_none();
        page
    }
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
    /// A plant, a scan or a reset that could not run.
    Failed(Step),
}

impl Rehearsal {
    /// A rehearsal page that opens, and the status it asks for first; with
    /// `planted_here`, what the window learnt before that this session
    /// planted the test words.
    pub(crate) fn open(planted_here: bool) -> (Self, Ask) {
        (
            Self {
                asked: Step::Status,
                phase: None,
                channels: Vec::new(),
                shown: None,
                notice: None,
                planted_here,
                account: String::new(),
                other: OtherDisks::default(),
                last_scan: RehearseScanArgs::default(),
            },
            Ask::Rehearse(Rehearse::Status),
        )
    }

    /// Whether the window learnt that this session planted the test words.
    pub(crate) fn planted_here(&self) -> bool {
        self.planted_here
    }

    /// The field changed to `typed`: the account of the plant, or on the
    /// page that scans other disks the disks or the images.
    pub(crate) fn edited(&mut self, typed: &str) {
        let other = &mut self.other;
        let field = match (other.open, other.images) {
            (false, _) => &mut self.account,
            (true, false) => &mut other.disks,
            (true, true) => &mut other.image_paths,
        };
        typed.clone_into(field);
    }

    /// The field `index` after the first changed to `typed`, on the page
    /// that scans other disks: the token file, with the images, then where
    /// each read stops.
    pub(crate) fn edited_more(&mut self, index: usize, typed: &str) {
        let other = &mut self.other;
        let field = match (other.open, other.images, index) {
            (true, true, 0) => &mut other.token_file,
            (true, true, 1) | (true, false, 0) => &mut other.stop_after,
            _ => return,
        };
        typed.clone_into(field);
    }

    /// The switch to images turned `on` or off.
    pub(crate) fn toggled(&mut self, on: bool) {
        if self.other.open {
            self.other.images = on;
        }
    }

    /// The person picked row `index` of the page: Scan Other Disks, the one
    /// row it has, where a scan is offered.
    pub(crate) fn choose(&mut self, index: usize) {
        let scans = matches!(
            (self.phase, self.planted_here),
            (Some(Phase::Planted | Phase::Scanned), false)
        );
        if index == 0 && scans {
            self.other.open = true;
        }
    }

    /// Whether the page offers a scan in the session that planted the test
    /// words, which needs the CLI's `--allow-same-boot` and asks first.
    pub(crate) fn offers_same_boot(&self) -> bool {
        self.planted_here
            && matches!(self.phase, Some(Phase::Planted | Phase::Scanned))
            && !self.other.open
    }

    /// The scan in the session that planted, asked for once its question
    /// was answered with the word.
    pub(crate) fn scan_same_boot(&mut self) -> Rehearse {
        self.asked = Step::Scan;
        self.notice = None;
        self.last_scan = RehearseScanArgs::default();
        Rehearse::Scan(RehearseScanArgs {
            allow_same_boot: true,
            ..RehearseScanArgs::default()
        })
    }

    /// Back, from the page that scans other disks to the rehearsal's:
    /// whether there was such a page to leave.
    pub(crate) fn back(&mut self) -> bool {
        std::mem::take(&mut self.other.open)
    }

    /// The ask for `label`, one of the page's actions, in a hidden session
    /// when `hidden`.
    pub(crate) fn action(&mut self, label: &str, hidden: bool) -> Option<Ask> {
        let (step, ask) = match label {
            text::PLANT if hidden => (Step::Plant, Rehearse::Plant(self.plant_args()?)),
            // The page that scans other disks gives way to the scan, whose
            // result is the rehearsal's; what was typed there stays.
            text::SCAN if self.other.open => {
                let args = self.other.args()?;
                self.other.open = false;
                self.last_scan = args.clone();
                (Step::Scan, Rehearse::Scan(args))
            }
            text::SCAN => {
                self.last_scan = RehearseScanArgs::default();
                (Step::Scan, Rehearse::Scan(RehearseScanArgs::default()))
            }
            // Again what was scanned last, other disks too.
            text::SCAN_AGAIN => (Step::Scan, Rehearse::Scan(self.last_scan.clone())),
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
                self.failed(text::sentence(&error.0));
                return;
            }
        };
        let Some(data) = read.data else {
            let (code, message) = error_of(&answer.envelope)
                .unwrap_or_else(|| (String::new(), text::NOTHING_CHANGED.to_string()));
            if self.asked == Step::Scan && code == SAME_SESSION {
                self.planted_here = true;
                self.failed(text::REHEARSAL_SAME_SESSION.to_string());
            } else {
                self.failed(message);
            }
            return;
        };
        // A scan that read its token from a file read no rehearsal state:
        // what it answers of one is not the volume's, which stays as the
        // last answer that read it said.
        let read_state = !(self.asked == Step::Scan && self.last_scan.token_file.is_some());
        if read_state {
            self.phase = Some(data.phase);
            if data.phase == Phase::None {
                // Nothing is planted, here or anywhere.
                self.planted_here = false;
            }
            self.channels = data.channels;
        }
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

    /// The step asked for failed, in `message`: what failed replaces what the
    /// page showed before.
    fn failed(&mut self, message: String) {
        self.notice = Some(message);
        self.shown = match self.asked {
            // The page had nothing to show yet.
            Step::Status => None,
            step => Some(Shown::Failed(step)),
        };
    }

    /// The page.
    pub(crate) fn page(&self, cx: &Context) -> Page {
        if self.other.open && cx.running != Some(Kind::Rehearse) {
            return self.other.page();
        }
        let mut page = match &self.shown {
            _ if cx.running == Some(Kind::Rehearse) => self.busy_page(),
            Some(Shown::Failed(step)) => Page {
                heading: match step {
                    Step::Plant => text::PLANT_FAILED,
                    Step::Reset => text::REMOVE_FAILED,
                    Step::Scan | Step::Status => text::SCAN_FAILED,
                }
                .to_string(),
                urgent: true,
                ..tool_page(ToolKind::Rehearsal, text::REHEARSAL_WHAT)
            },
            Some(Shown::Scan(report, exit)) => {
                scan_page(report, *exit, &self.channels, self.planted_here)
            }
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
            self.next(&mut page, cx);
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
    /// that comes next, where `cx` says the window runs.
    fn next(&self, page: &mut Page, cx: &Context) {
        let hidden = cx.hidden;
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
            // The session that planted: its scan proves little, and asks
            // first (`--allow-same-boot`).
            Phase::Planted if self.planted_here => (
                [DONE, NOW, NEXT],
                text::AFTER_PLANT,
                None,
                Some(text::SCAN_SAME_BOOT),
            ),
            // A scan in the session that planted ends nothing: the session
            // still has to end, and its scan did not count.
            Phase::Scanned if self.planted_here => (
                [DONE, NOW, NEXT],
                text::AFTER_PLANT,
                None,
                Some(text::SCAN_SAME_BOOT),
            ),
            Phase::Planted => (
                [DONE, DONE, NOW],
                if hidden {
                    text::REHEARSAL_PLANTED
                } else {
                    text::REHEARSAL_PLANTED_DECOY
                },
                Some(text::SCAN),
                (!hidden).then_some(text::REMOVE_TEST_WORDS),
            ),
            Phase::Scanned => (
                [DONE, DONE, DONE],
                text::REHEARSAL_SCANNED,
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
        if hidden && phase == Phase::Scanned && !self.planted_here {
            // No window opens on the decoy in this release: the line that
            // removes the test words there, once they are done with.
            page.fix = join_notice(
                Some(&page.fix),
                &text::remove_on_decoy(cx.engine.as_deref()),
            );
        }
        if matches!(action, Some(text::SCAN | text::SCAN_AGAIN)) {
            page.choices = vec![Choice {
                title: text::SCAN_OTHER_ROW.to_string(),
                subtitle: text::SCAN_OTHER_ROW_WHAT.to_string(),
            }];
        }
        if action == Some(text::PLANT) {
            let named = self.plant_args().is_some();
            page.field = Some(Field {
                label: text::FIELD_ACCOUNT.to_string(),
                text: self.account.clone(),
                hint: if named {
                    text::ACCOUNT_HINT
                } else {
                    text::ACCOUNT_NOT_A_NAME
                }
                .to_string(),
            });
            page.action_locked = !named;
        }
        page.action = action;
        page.secondary = secondary;
    }

    /// The plant's arguments for the account typed, spaces around it dropped
    /// (none when it is empty: the plant is for the window's own). `None`
    /// when the helper would refuse that name unread, as it refuses a request
    /// that ends the window's session: such a plant is never asked for.
    fn plant_args(&self) -> Option<RehearsePlantArgs> {
        let name = self.account.trim();
        let args = RehearsePlantArgs {
            user: (!name.is_empty()).then(|| name.to_string()),
        };
        fits(&Op::RehearsePlant(args.clone())).then_some(args)
    }
}

/// The question before a scan in the session that planted the test words:
/// what such a scan proves, and that it holds once. Its button acts only
/// once the word is typed.
pub(crate) fn same_boot_question() -> Question {
    Question {
        heading: text::SAME_BOOT_QUESTION.to_string(),
        body: format!("{}\n{}", text::SAME_BOOT_WHAT, text::SAME_BOOT_ONCE),
        confirm: text::SAME_BOOT_CONFIRM.to_string(),
        destructive: true,
        prompt: Some(text::type_to_continue(text::ALLOW_WORD)),
        locked: true,
        alternative: None,
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
fn scan_page(report: &ScanReport, exit: u8, channels: &[Channel], same_session: bool) -> Page {
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
    } else if same_session {
        // A scan in the session that planted may not see what the session
        // wrote yet: never a pass.
        (
            text::NOT_A_CLEAN_RESULT,
            text::NOT_CLEAN_SAME_SESSION.to_string(),
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
