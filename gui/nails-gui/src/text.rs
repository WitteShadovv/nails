// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The words the window shows, in one place.
//!
//! Titles and buttons are in header capitalisation, everything else in
//! sentence capitalisation. A title is the verdict; the sentence under it
//! says where things stand; a refusal says what happened, what was not
//! changed and what fixes it. Nothing here claims more than the engine
//! reports: where the engine gives its own reason or fix, the window shows
//! that one.

use std::path::Path;

use crate::launch;

/// The window's title, the same on every page and on the decoy: it names
/// nothing about NAILS.
pub const WINDOW_TITLE: &str = "Session";

/// The window's app id on Wayland and X11, which is also the name of the menu
/// entry a hidden session gets: neutral, like the title.
pub const APP_ID: &str = "session";

/// While the handshake runs.
pub const STARTING: &str = "Starting";

/// While pkexec's password dialog is up.
pub const WAITING_FOR_PASSWORD: &str = "Waiting for Your Password";
/// Why the window asks for the password.
pub const WAITING_FOR_PASSWORD_WHY: &str =
    "The window asks for your password each time it opens, to reach its controls.";

/// pkexec could not get the password.
pub const PASSWORD_NEEDED: &str = "Password Needed";
/// Why the window cannot go on without it.
pub const PASSWORD_NEEDED_WHY: &str = "The window needs your password to work and did not get it.";

/// The check runs.
pub const CHECKING: &str = "Checking This Computer";
/// The check passed.
pub const READY: &str = "Ready to Activate";
/// A check failed.
pub const NOT_READY: &str = "Not Ready to Activate";
/// The check could not run.
pub const CHECK_FAILED: &str = "Check Failed";
/// The main action of a decoy page.
pub const CHECK_AGAIN: &str = "Check Again";

/// A hidden session runs.
pub const HIDDEN_SESSION: &str = "Hidden Session";
/// An activation runs.
pub const ACTIVATING: &str = "Activating";
/// An interrupted activation left files in memory.
pub const INTERRUPTED: &str = "Activation Interrupted";
/// The record cannot be read.
pub const RECORD_UNREADABLE: &str = "Record Cannot Be Read";
/// A hidden session has no way back.
pub const NO_WAY_BACK: &str = "No Way Back";

/// The decoy, with nothing to report.
pub const DECOY_IDLE: &str = "Decoy. No hidden session is active.";
/// The decoy after an interrupted activation.
pub const DECOY_INTERRUPTED: &str =
    "Decoy. An activation was interrupted and left files in memory.";
/// The decoy whose record cannot be read.
pub const DECOY_RECORD_UNREADABLE: &str = "Decoy. The record on the hidden volume cannot be read.";
/// A record that cannot be read anywhere, where the engine does not guess
/// the place.
pub const PLACE_UNKNOWN: &str = "The record on the hidden volume cannot be read, so it is not \
     known whether a hidden session is active.";
/// The settings could not be read, so there is no status.
pub const SETTINGS_UNREADABLE: &str = "Settings Cannot Be Read";
/// The status failed for another reason.
pub const STATUS_UNAVAILABLE: &str = "Status Not Available";
/// The decoy after a session that did not end normally.
pub const DECOY_ENDED_ABNORMALLY: &str = "Decoy. The last hidden session did not end normally.";
/// The decoy with a disk over the hidden volume.
pub const DECOY_VOLUME_COVERED: &str = "Decoy. A disk is mounted over the hidden volume.";
/// An activation under way.
pub const ACTIVATING_WHERE: &str = "Activating. The hidden session opens at the next login screen.";
/// What the power button does when nothing else can help.
pub const HOLD_POWER_BUTTON: &str = "Hold the power button until the computer is off.";

/// A refusal changed nothing.
pub const NOTHING_CHANGED: &str = "Nothing was changed.";

/// The window and the engine are of different releases.
pub const MISMATCH: &str = "Different Releases";
/// What fixes it.
pub const MISMATCH_FIX: &str = "Fix: use the window and NAILS from one release.";
/// The helper refused a request.
pub const REFUSED: &str = "Request Refused";
/// The pipe closed.
pub const LOST: &str = "Connection Lost";
/// What it means.
pub const LOST_WHY: &str = "The window lost its connection to NAILS.";
/// A request was waiting when it closed.
pub const LOST_IN_FLIGHT: &str =
    "The last request did not get an answer. Open the window again to see where things stand.";
/// An answer the window cannot read.
pub const UNREADABLE: &str = "Unexpected Answer";
/// The helper could not be started.
pub const NOT_STARTED: &str = "Controls Not Available";

/// Labels of the facts a page lists.
pub const FACT_HIDDEN_VOLUME: &str = "Hidden volume";
/// The check's tally.
pub const FACT_THIS_COMPUTER: &str = "This computer";

/// The decoy after its last switch was refused, with the engine's reason.
#[must_use]
pub fn decoy_switch_refused(reason: Option<&str>) -> String {
    match reason {
        Some(reason) => format!(
            "Decoy. The last activation stopped at the switch: {}.",
            trim_end_stop(reason)
        ),
        None => "Decoy. The last activation stopped at the switch.".to_string(),
    }
}

/// A hidden session that has run for `uptime`.
#[must_use]
pub fn hidden_active(uptime_seconds: Option<i64>) -> String {
    match uptime_seconds {
        Some(seconds) => format!("Hidden session active for {}.", duration(seconds)),
        None => "Hidden session active.".to_string(),
    }
}

/// A hidden session without a way back, with the engine's reason.
#[must_use]
pub fn hidden_no_way_back(reason: Option<&str>) -> String {
    match reason {
        Some(reason) => format!(
            "Hidden session without a way back: {}.",
            trim_end_stop(reason)
        ),
        None => "Hidden session without a way back.".to_string(),
    }
}

/// A hidden session with a disk mounted over its volume at `root`.
#[must_use]
pub fn hidden_volume_covered(uptime_seconds: Option<i64>, root: &str) -> String {
    format!(
        "{} A disk is mounted over the hidden volume: files saved under {root} go to that disk.",
        hidden_active(uptime_seconds)
    )
}

/// A duration as the window writes one: `2 h 10 min`, `40 min`, or less.
#[must_use]
pub fn duration(seconds: i64) -> String {
    let minutes = seconds.max(0) / 60;
    let (hours, minutes) = (minutes / 60, minutes % 60);
    match (hours, minutes) {
        (0, 0) => "less than 1 min".to_string(),
        (0, minutes) => format!("{minutes} min"),
        (hours, 0) => format!("{hours} h"),
        (hours, minutes) => format!("{hours} h {minutes} min"),
    }
}

/// How many checks passed.
#[must_use]
pub fn checks_passed(passed: usize) -> String {
    match passed {
        1 => "1 check passed".to_string(),
        n => format!("{n} checks passed"),
    }
}

/// How many problems a check found, and that nothing was changed.
#[must_use]
pub fn problems(failed: usize) -> String {
    match failed {
        1 => format!("1 problem. {NOTHING_CHANGED}"),
        n => format!("{n} problems. {NOTHING_CHANGED}"),
    }
}

/// The word for one check's outcome: words carry the meaning, the colour
/// only follows.
#[must_use]
pub fn outcome_word(outcome: nails_api::CheckOutcome) -> &'static str {
    match outcome {
        nails_api::CheckOutcome::Pass => "Passed",
        nails_api::CheckOutcome::Warn => "Warning",
        nails_api::CheckOutcome::Fail => "Failed",
        nails_api::CheckOutcome::Skipped => "Not checked",
    }
}

/// A fix the engine gave, ready to show: its code quotes dropped, since
/// the window shows the command as plain text.
#[must_use]
pub fn engine_fix(remediation: &str) -> String {
    remediation.replace('`', "")
}

/// The next step as the CLI's line for `engine`, when the engine names one.
#[must_use]
pub fn next_step(engine: Option<&Path>, command: &str) -> String {
    format!("Next: {}", launch::sudo_line(engine, command))
}

/// The line that opens the window from a terminal with `engine`.
#[must_use]
pub fn open_from_terminal(engine: Option<&Path>) -> String {
    format!("Open a terminal and run: {}", launch::gui_line(engine))
}

/// What the window says while activation is left to the terminal.
#[must_use]
pub fn activate_from_terminal(engine: Option<&Path>) -> String {
    format!(
        "Activate from a terminal: {}",
        launch::sudo_line(engine, "activate")
    )
}

/// What the window says while deactivation is left to the terminal.
#[must_use]
pub fn deactivate_from_terminal(engine: Option<&Path>) -> String {
    format!(
        "Deactivate from a terminal: {}",
        launch::sudo_line(engine, "deactivate")
    )
}

/// The two releases, when the window and the engine differ.
#[must_use]
pub fn mismatch(
    window: &nails_api::protocol::Hello,
    engine: &nails_api::protocol::Hello,
) -> String {
    if window.engine == engine.engine {
        format!(
            "This window speaks protocol {} and NAILS on the hidden volume protocol {}. \
             They work together only when both come from one release.",
            window.protocol, engine.protocol
        )
    } else {
        format!(
            "This window is from release {} and NAILS on the hidden volume from release {}. \
             They work together only when both come from one release.",
            window.engine, engine.engine
        )
    }
}

/// A sentence of the engine's, as the window shows it: with a capital first
/// letter and a full stop.
#[must_use]
pub fn sentence(text: &str) -> String {
    let text = text.trim();
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let mut out: String = first.to_uppercase().chain(chars).collect();
    if !out.ends_with(['.', '?', ':']) {
        out.push('.');
    }
    out
}

fn trim_end_stop(text: &str) -> &str {
    text.trim().trim_end_matches('.')
}

#[cfg(test)]
#[path = "text_tests.rs"]
mod tests;
