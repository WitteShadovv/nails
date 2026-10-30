// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The words of the window's tools: Verify, Rehearsal, Discard Hidden
//! Changes and Set Up Hidden Volume.
//!
//! Each says what its operation does and found in the window's own words,
//! with the engine's sentences where the engine gives one (a finding, a
//! refusal, a reason a disk was not checked). None claims more than the
//! engine reports: a verify that found nothing is no proof, and a scan whose
//! disks can hide the test words is no clean result.

/// Back to the main page, from a tool's.
pub const BACK: &str = "Back";
/// A step not reached yet.
pub const STEP_NEXT: &str = "Next";

/// The row that opens Verify, its page's title and main action: the CLI's
/// verb.
pub const VERIFY: &str = "Verify";
/// What Verify does.
pub const VERIFY_WHAT: &str = "Look for known traces a hidden session can leave on this computer.";
/// The second action of Verify's page.
pub const DEEP_SCAN: &str = "Deep Scan";
/// What a deep scan adds.
pub const DEEP_SCAN_WHAT: &str = "Deep Scan also searches temporary and log folders, shell \
     histories, recent-file lists and the system log. It takes longer.";
/// While a verify runs.
pub const VERIFYING: &str = "Verifying";
/// What runs meanwhile.
pub const LOOKING_FOR_TRACES: &str = "Looking for traces";
/// The main action once a verify answered.
pub const VERIFY_AGAIN: &str = "Verify Again";
/// A verify that found no known trace.
pub const NO_KNOWN_TRACES: &str = "No Known Traces Found";
/// A verify that found possible traces.
pub const POSSIBLE_TRACES: &str = "Possible Traces Found";
/// A verify that found traces.
pub const TRACES_FOUND: &str = "Traces Found";
/// A verify that could not run.
pub const VERIFY_FAILED: &str = "Verify Could Not Run";
/// The group of what a verify found.
pub const GROUP_FOUND: &str = "Found";
/// The group of what a verify did not look at.
pub const GROUP_NOT_CHECKED_RUN: &str = "Not checked by this run";
/// A finding that is a trace.
pub const SEVERITY_CRITICAL: &str = "Critical";
/// A finding that may be one.
pub const SEVERITY_WARN: &str = "Warning";
/// A finding that is a note, not a trace.
pub const SEVERITY_NOTE: &str = "Note";
/// Something a run or a scan did not look at.
pub const NOT_CHECKED: &str = "Not checked";

/// What a verify of `checks` checks that found nothing says: no proof, as
/// the CLI says too.
#[must_use]
pub fn verify_secure(checks: usize, deep: bool) -> String {
    let scan = if deep { "deep" } else { "standard" };
    format!(
        "A {scan} scan of {} found no known trace. This is not proof that there is none.",
        count(checks, "check", "checks")
    )
}

/// What a verify that found `n` possible traces says.
#[must_use]
pub fn possible_traces(n: usize) -> String {
    format!(
        "Verify found {}. Each one says what it is and how to deal with it.",
        count(n, "possible trace", "possible traces")
    )
}

/// What a verify that found `n` traces says.
#[must_use]
pub fn traces_found(n: usize) -> String {
    format!(
        "Verify found {} that a hidden session can leave. Each one says what it is and how \
         to deal with it.",
        count(n, "trace", "traces")
    )
}

/// The row that opens Rehearsal, and its page's title.
pub const REHEARSAL: &str = "Rehearsal";
/// What a rehearsal is for.
pub const REHEARSAL_WHAT: &str =
    "Test that a hidden session leaves nothing on this computer's disk.";
/// The first step of a rehearsal.
pub const STEP_PLANT: &str = "Plant test words in a hidden session";
/// The second.
pub const STEP_END: &str = "End that session as usual";
/// The third.
pub const STEP_SCAN: &str = "Scan this computer's disks for the test words";
/// While the rehearsal is read.
pub const READING_REHEARSAL: &str = "Reading the rehearsal";
/// The action that plants the test words.
pub const PLANT: &str = "Plant Test Words";
/// While they are planted.
pub const PLANTING: &str = "Planting the test words";
/// The action that scans for them.
pub const SCAN: &str = "Scan for Test Words";
/// The same, once a scan ran.
pub const SCAN_AGAIN: &str = "Scan Again";
/// While a scan runs.
pub const SCANNING: &str = "Scanning";
/// What runs meanwhile.
pub const READING_DISKS: &str = "Reading this computer's disks";
/// How long a scan takes.
pub const SCAN_HOW_LONG: &str = "Each disk is read in full, which can take a long time.";
/// The action that removes the rehearsal.
pub const REMOVE_TEST_WORDS: &str = "Remove Test Words";
/// While it is removed.
pub const REMOVING: &str = "Removing the test words";
/// The test words were planted.
pub const PLANTED: &str = "Test Words Planted";
/// What comes after the plant.
pub const AFTER_PLANT: &str = "Next, end this session as usual with Deactivate\u{2026} on the main \
     page. Then, with the hidden volume mounted again, open Rehearsal on the decoy or in your \
     next hidden session and scan.";
/// A rehearsal opened on the decoy with nothing planted.
pub const REHEARSAL_STARTS_HIDDEN: &str =
    "Rehearsals start in a hidden session. Activate first, then open Rehearsal there.";
/// A rehearsal whose test words wait for their scan.
pub const REHEARSAL_PLANTED: &str = "The test words are planted. Scan for them on the decoy or \
     in a hidden session after the one that planted them.";
/// A rehearsal that was scanned before.
pub const REHEARSAL_SCANNED: &str = "A scan has run. Scan again whenever you want.";
/// Where the test words can be removed.
pub const REMOVE_ON_DECOY: &str = "Remove the test words on the decoy once you are done.";
/// A scan refused in the session that planted the test words.
pub const REHEARSAL_SAME_SESSION: &str = "The test words were planted in this session, so a scan \
     here could miss what has not reached the disk yet. End this session first, then scan on \
     the decoy or in your next hidden session.";
/// The rehearsal was removed.
pub const TEST_WORDS_REMOVED: &str = "Test Words Removed";
/// What that means.
pub const REHEARSAL_GONE: &str = "The rehearsal is gone from the hidden volume.";
/// The group of the places the test words went.
pub const GROUP_PLANTED: &str = "Planted";
/// One of them.
pub const PLANTED_WORD: &str = "Planted";
/// A place they did not go.
pub const NOT_PLANTED: &str = "Not planted";
/// The group of what was removed.
pub const GROUP_REMOVED: &str = "Removed";
/// One of them.
pub const REMOVED_WORD: &str = "Removed";

/// The test words were found.
pub const TEST_WORDS_FOUND: &str = "Test Words Found";
/// A scan whose disks can hide the test words.
pub const NOT_A_CLEAN_RESULT: &str = "Not a Clean Result";
/// A scan that could not read every disk in full.
pub const SCAN_INCOMPLETE: &str = "Scan Incomplete";
/// A scan the engine did not call clean, for a reason the window does not
/// read.
pub const NOT_CLEAN_UNEXPLAINED: &str =
    "The test words were not found, but the scan did not end as a clean result.";
/// A scan that read every disk in full and found nothing.
pub const PASSED: &str = "Passed";
/// The group of what a scan did not check, first on every result but one
/// that found the test words.
pub const GROUP_NOT_CHECKED_SCAN: &str = "Not checked by this scan";
/// The group of the disks a scan read.
pub const GROUP_DISKS: &str = "Disks";
/// The group of the places the test words never went.
pub const GROUP_NOT_TESTED: &str = "Not tested, because the test words were never planted there";
/// A disk where the test words were found.
pub const FOUND_WORD: &str = "Found";
/// A disk read in full, with nothing found.
pub const READ_WORD: &str = "Read";
/// A disk not read in full.
pub const INCOMPLETE_WORD: &str = "Incomplete";
/// A place the test words never went.
pub const NOT_TESTED: &str = "Not tested";

/// Where the test words were found first.
#[must_use]
pub fn test_words_found(device: &str, offset: u64) -> String {
    format!(
        "The test words are on this computer's disk ({device}, byte {offset}). Do not rely on \
         hidden sessions on this computer until you know why."
    )
}

/// A scan of which `n` disks can hide the test words.
#[must_use]
pub fn blind_spots(n: usize) -> String {
    format!(
        "The test words were not found, but {} can hide them from this scan, so {} not checked.",
        count(n, "disk", "disks"),
        if n == 1 { "it was" } else { "they were" }
    )
}

/// A scan of which `n` disks could not be read in full.
#[must_use]
pub fn incomplete(n: usize) -> String {
    format!(
        "{} could not be read completely. The test words were not found on what was read.",
        sentence_start(&count(n, "disk", "disks"))
    )
}

/// A scan that read `n` disks of `bytes` in full and found nothing.
#[must_use]
pub fn passed(n: usize, bytes: u64) -> String {
    format!(
        "The test words are not on the {} this scan read in full ({}).",
        count(n, "disk", "disks"),
        size(bytes)
    )
}

/// The test words, planted in `n` places.
#[must_use]
pub fn planted_in(n: usize) -> String {
    format!(
        "The test words are planted in {} of this hidden session.",
        count(n, "place", "places")
    )
}

/// What a kind of place the test words go into is called.
#[must_use]
pub fn channel(kind: &str) -> &str {
    match kind {
        "overlay-file" => "File in a system folder",
        "home-file" => "File in your home",
        "recent-files" => "Recent files list",
        "system-log" => "System log",
        "process-cmdline" => "Command line of a program",
        "notification" => "Desktop notification",
        other => other,
    }
}

/// A path or place as the engine names it, with the stand-in for the test
/// words in the window's words.
#[must_use]
pub fn without_canary(location: &str) -> String {
    location.replace("<canary>", "(test words)")
}

/// The row that opens Discard Hidden Changes, and its page's title.
pub const DISCARD: &str = "Discard Hidden Changes";
/// What a discard does.
pub const DISCARD_WHAT: &str = "Delete what hidden sessions changed in a folder, so the next \
     hidden session sees this computer's own copy of it.";
/// The field for the folder.
pub const FIELD_FOLDER: &str = "Folder";
/// What it takes.
pub const FOLDER_HINT: &str = "The folder's full path, such as /etc/apt";
/// A folder that is no full path.
pub const FOLDER_NOT_ABSOLUTE: &str = "Give the folder's full path, starting with /.";
/// The action that asks for the plan; the question follows.
pub const DISCARD_ACTION: &str = "Discard\u{2026}";
/// The question before a discard.
pub const DISCARD_QUESTION: &str = "Discard Hidden Changes?";
/// The heading of the list of what a discard deletes.
pub const DISCARD_LIST: &str = "Deleted from the hidden volume:";
/// What a discard of /nix does besides.
pub const DISCARD_NIX: &str = "Discarding /nix also drops the hidden Nix database and store paths.";
/// The button that deletes.
pub const DELETE: &str = "Delete";
/// While the plan is made.
pub const LOOKING_AT_CHANGES: &str = "Looking at the hidden changes";
/// While the apply deletes.
pub const DELETING: &str = "Deleting the hidden changes";
/// The hidden changes were deleted.
pub const DISCARDED: &str = "Hidden Changes Discarded";
/// A discard that failed.
pub const DISCARD_FAILED: &str = "Discard Failed";
/// The group of what a discard deleted.
pub const GROUP_DELETED: &str = "Deleted";
/// One of them.
pub const DELETED_WORD: &str = "Deleted";

/// What a discard of `target` deletes, and what follows.
#[must_use]
pub fn discard_consequence(target: &str) -> String {
    format!(
        "Every hidden change in {target} is deleted for good. The next hidden session sees this \
         computer's own {target}."
    )
}

/// The prompt of the word a discard of `target` asks for: the folder
/// itself, and for a home what goes with it.
#[must_use]
pub fn discard_type(target: &str, holds_a_home: bool) -> String {
    if holds_a_home {
        format!("Type {target} to delete every hidden change in it, your files there included")
    } else {
        format!("Type {target} to delete every hidden change in it")
    }
}

/// What follows a discard of `target`.
#[must_use]
pub fn discarded(target: &str) -> String {
    format!("The next hidden session sees this computer's own {target}.")
}

/// A discard of `target` with nothing to delete.
#[must_use]
pub fn nothing_to_discard(target: &str) -> String {
    format!("Hidden sessions changed nothing in {target}, so nothing was deleted.")
}

/// The row that opens Set Up Hidden Volume, and its page's title.
pub const SET_UP: &str = "Set Up Hidden Volume";
/// What it does, under its row.
pub const SET_UP_ROW: &str = "Write the folders and the settings file NAILS needs.";
/// The action that asks for the plan; the question follows.
pub const SET_UP_ACTION: &str = "Set Up\u{2026}";
/// The question before a set up.
pub const SET_UP_QUESTION: &str = "Set Up the Hidden Volume?";
/// The button that sets it up.
pub const SET_UP_CONFIRM: &str = "Set Up";
/// While the plan is made.
pub const CHECKING_VOLUME: &str = "Checking the hidden volume";
/// While the apply writes.
pub const SETTING_UP: &str = "Setting up the hidden volume";
/// The hidden volume was set up.
pub const SET_UP_DONE: &str = "Hidden Volume Set Up";
/// The step after it.
pub const SET_UP_NEXT: &str = "Go back to check this computer again before you activate.";
/// A set up that was refused or failed.
pub const SET_UP_FAILED: &str = "Hidden Volume Not Set Up";
/// The group of what a set up wrote.
pub const GROUP_LAYOUT: &str = "On the hidden volume";
/// A part it made.
pub const CREATED_WORD: &str = "Created";
/// A part that was there.
pub const ALREADY_THERE: &str = "Already there";
/// The group of what the person should know about it.
pub const GROUP_NOTES: &str = "Notes";

/// What a set up of the hidden volume at `root` does.
#[must_use]
pub fn set_up_what(root: &str) -> String {
    format!(
        "Write the folders, the settings file and the record NAILS needs on the hidden volume at \
         {root}, where they are missing."
    )
}

/// The question's consequence line for the hidden volume at `root`.
#[must_use]
pub fn set_up_consequence(root: &str) -> String {
    format!(
        "NAILS writes its folders, a settings file and a record on the hidden volume at {root}, \
         where they are missing. A settings file or record that is there already stays as it is."
    )
}

/// The line for a set up that also writes the hidden NixOS configuration from
/// `hardware`.
#[must_use]
pub fn set_up_nixos(hardware: &str) -> String {
    format!("It also writes the hidden NixOS configuration, based on {hardware}.")
}

/// What follows a set up of the hidden volume at `root`.
#[must_use]
pub fn set_up_done(root: &str) -> String {
    format!("The hidden volume at {root} has what NAILS needs.")
}

/// `n` of a thing, in the right number.
#[must_use]
pub fn count(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// A size as the window writes one: decimal units with a space, a decimal
/// under 10.
#[must_use]
pub fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["kB", "MB", "GB", "TB", "PB"];
    if bytes < 1000 {
        return format!("{bytes} B");
    }
    #[allow(clippy::cast_precision_loss)]
    let mut value = bytes as f64 / 1000.0;
    let mut unit = 0;
    while value >= 1000.0 && unit + 1 < UNITS.len() {
        value /= 1000.0;
        unit += 1;
    }
    if value < 10.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{value:.0} {}", UNITS[unit])
    }
}

fn sentence_start(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}
