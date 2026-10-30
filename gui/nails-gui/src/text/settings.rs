// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The words of Settings: a label and a line for each key of `nails.toml` a
//! value can be set for, the words of its values and choices, and what the
//! page says about a change.

/// The row that opens Settings, and its page's title.
pub const SETTINGS: &str = "Settings";
/// What it does, under its row.
pub const SETTINGS_ROW: &str = "See and change how hidden sessions work.";
/// When a change takes effect, as `config set` says it in a hidden session.
pub const SETTINGS_WHEN: &str = "NAILS reads the settings each time it runs. The drive watch and \
     the sleep guard of this session keep what they started with until the next activation.";
/// While the settings are read.
pub const READING_SETTINGS: &str = "Reading the settings";
/// The action that reads them again, after a read that failed.
pub const READ_AGAIN: &str = "Read Again";
/// While a change is checked.
pub const CHECKING_CHANGE: &str = "Checking the change";
/// While it is saved.
pub const SAVING: &str = "Saving";
/// The action that saves a typed value; the question follows.
pub const SAVE_ACTION: &str = "Save\u{2026}";
/// The action that removes a key from the file, so its default holds.
pub const USE_DEFAULT: &str = "Use the Default\u{2026}";
/// The question before a change.
pub const SAVE_QUESTION: &str = "Save the Change?";
/// Its button.
pub const SAVE: &str = "Save";
/// The field of a value to type.
pub const FIELD_VALUE: &str = "New value";
/// A saved change.
pub const SAVED: &str = "Saved.";
/// A change the file held already.
pub const ALREADY_SAID: &str = "The settings already say that, so nothing was written.";
/// A plan whose file changed before its apply.
pub const STALE: &str = "The settings file changed after you asked, so nothing was written. The \
     window read it again: check the value and save it again.";
/// An answer the window did not expect: it changes nothing more, and the
/// settings are read again.
pub const UNEXPECTED_SETTINGS: &str = "The answer about the settings is not one this window \
     expects, so it changes nothing more and reads the settings again.";
/// The two keys a hidden session's record names, during a session.
pub const SESSION_KEY_FIXED: &str = "This cannot change while a hidden session runs: to end the \
     session and return to the decoy, NAILS needs the session's record where the session saved \
     it. Change it on another computer, with the hidden volume mounted there.";
/// The row of a value now.
pub const FACT_NOW: &str = "Now";
/// The row of where it comes from.
pub const FACT_FROM: &str = "Comes from";
/// The mark of the choice in force.
pub const CHOSEN: &str = "Now";
/// A boolean on.
pub const ON: &str = "On";
/// A boolean off.
pub const OFF: &str = "Off";
/// A value the file does not set.
pub const NOT_SET: &str = "Not set";
/// What a key falls back to when it is removed.
pub const THE_DEFAULT: &str = "the default";
/// An empty list.
pub const NONE: &str = "None";
/// The list that names every entry.
pub const ALL: &str = "All";

/// Where the settings file is, or that there is none yet.
#[must_use]
pub fn settings_file(path: &str, exists: bool) -> String {
    if exists {
        format!("The settings file: {path}")
    } else {
        format!("No settings file yet at {path}: every setting has its default.")
    }
}

/// Where a value comes from, as `config show` names its source.
#[must_use]
pub fn source(source: &str) -> &'static str {
    match source {
        "file" => "The settings file",
        "default" => "The default",
        "derived" => "The folder NAILS runs from",
        "cli" => "This run",
        _ => "Not known",
    }
}

/// The line of a change in the question: `label` from `before` to `after`.
#[must_use]
pub fn change_line(label: &str, before: &str, after: &str) -> String {
    format!("{label}: from {before} to {after}.")
}

/// The file a change is saved in.
#[must_use]
pub fn saved_in(path: &str) -> String {
    format!("It is saved in {path}.")
}

/// A key's label and the line under it on its page.
#[must_use]
pub fn setting(key: &str) -> (&'static str, &'static str) {
    match key {
        "hidden_volume_root" => (
            "Hidden volume",
            "Where the hidden volume is mounted. Its layers, its record and its logs lie under it.",
        ),
        "state_file_path" => (
            "Record",
            "The file in which the hidden volume keeps its record of the last session.",
        ),
        "log_path" => (
            "Log folder",
            "The folder of NAILS's log, on the hidden volume.",
        ),
        "minimum_space_mb" => (
            "Space to keep free",
            "The check refuses an activation when the hidden volume has less free space, in MB.",
        ),
        "rebuild_space_mb" => (
            "Space for a hidden system build",
            "The free space a build of the hidden NixOS system needs on the hidden volume, in MB.",
        ),
        "show_opsec_reminders" => (
            "Reminders",
            "Status reminds you after 6, 12 and 24 hours in a hidden session.",
        ),
        "nixos_flake" => (
            "Hidden NixOS system",
            "The flake of the hidden NixOS system, built before the switch. Not set, activation \
             looks for one on the hidden volume.",
        ),
        "persona.mask_inherited" => (
            "Programs that do not start",
            "Autostart entries and user units of the decoy kept out of the hidden session, by the \
             names the check lists.",
        ),
        "persona.mode" => (
            "Home in the session",
            "Which home the hidden session starts in.",
        ),
        "backend_watch.auto_emergency" => (
            "End the session when the drive fails",
            "On, a failure of the drive that lasts longer than the failure delay ends the session \
             and returns to the decoy. Off, you get an alert and end it yourself.",
        ),
        "backend_watch.debounce_secs" => (
            "Failure delay",
            "How long a failure of the drive must last before it ends the session by itself, in \
             seconds.",
        ),
        "backend_watch.enabled" => (
            "Watch the drive",
            "Watch the drive during the session and alert you when it fails.",
        ),
        "backend_watch.poll_interval_secs" => (
            "Drive check interval",
            "Seconds between two checks of the drive.",
        ),
        "session_mounts.alert" => (
            "Alert for other disks",
            "Alert you when a disk other than the hidden volume is mounted with write access during \
             the session.",
        ),
        "session_mounts.read_only" => (
            "Other disks read-only",
            "Make every other disk read-only for the session, so nothing is written to it.",
        ),
        "sleep_policy.mode" => (
            "When the computer would sleep",
            "Sleep keeps the whole session in memory, its key included.",
        ),
        _ => ("Setting", ""),
    }
}

/// A choice's label and the line under it.
#[must_use]
pub fn choice(key: &str, value: &str) -> (&'static str, &'static str) {
    match (key, value) {
        ("persona.mode", "shared-home") => (
            "Decoy home",
            "The decoy's home: its accounts, keys and app data are live in the session.",
        ),
        ("persona.mode", "fresh-home") => (
            "Empty home",
            "A home of its own, kept on the hidden volume.",
        ),
        ("sleep_policy.mode", "warn") => ("Warn", "The check warns when the computer would sleep."),
        ("sleep_policy.mode", "block") => (
            "Keep awake",
            "The computer cannot sleep, a closed lid included, while the session runs.",
        ),
        ("sleep_policy.mode", "teardown") => (
            "Power off",
            "The computer powers off when it is about to sleep.",
        ),
        _ => ("", ""),
    }
}

/// What a field for a value of a kind takes.
#[must_use]
pub fn field_hint(kind: &str) -> &'static str {
    match kind {
        "integer" => "A whole number",
        "path" => "A full path, starting with /",
        "names" => "Names separated by commas, or * for all of them",
        _ => "The value",
    }
}

/// The unit a whole-number key counts in, if any.
#[must_use]
pub fn unit(key: &str) -> Option<&'static str> {
    match key {
        "minimum_space_mb" | "rebuild_space_mb" => Some("MB"),
        "backend_watch.debounce_secs" | "backend_watch.poll_interval_secs" => Some("s"),
        _ => None,
    }
}
