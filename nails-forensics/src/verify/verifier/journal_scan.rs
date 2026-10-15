// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The deep scan's journal search: entries that name the tool, its
//! configuration file, the unlock command or the hidden volume, and what a
//! group of them means where verify found it.
//!
//! sudo logs every command run with it, so its records of the operator's own
//! commands (an unlock, a mount, `nails` itself, this verify run among them)
//! name these tokens on any host where NAILS is used. They are reported as
//! sudo's records, not as traces of a hidden session. Whether an entry can
//! outlast a power-off depends on where the journal keeps it: an entry that is
//! only in the runtime journal is in RAM.

use super::*;

/// The persistent journal's directory. A journal file below it is on disk
/// unless the directory is a tmpfs; everything else `journalctl` reads is the
/// runtime journal in RAM.
const PERSISTENT_JOURNAL_DIR: &str = "/var/log/journal";

/// What a group of journal hits is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    /// sudo's records of commands run with it.
    SudoRecord,
    /// Any other entry.
    Other,
}

/// Where verify found the hits, which decides what they mean.
#[derive(Debug, Clone, Copy)]
struct JournalPlace {
    /// verify runs inside the hidden session, so the journal is the session's.
    in_session: bool,
    /// The journal keeps files on disk, so an entry may be there too.
    on_disk: bool,
    /// verify was started with sudo, which logged this run as well.
    under_sudo: bool,
}

impl<F: Filesystem> Verifier<F> {
    /// Grep the live systemd journal for the tokens that reveal the hidden
    /// environment, returning the findings and whether the journal was
    /// searched.
    ///
    /// The journald relinquish/flush hooks around every transition keep the
    /// hidden session's records off the persistent decoy journal; this is the
    /// forensic cross-check that they held. Each needle is a token that reveals
    /// the hidden environment — the tool name, the hidden volume mount path, the
    /// config file name and the encrypted-backend command name. A needle's hits
    /// are split into sudo's records of commands and other entries, each group
    /// rated by where it was found (see `journal_finding`). When the journal
    /// cannot be searched (no journald, no access) nothing is reported as
    /// clean: the second element is `false` so the caller records the journal
    /// as an area it could not inspect.
    pub(super) fn scan_journal(&self, in_session: bool) -> (Vec<Finding>, bool) {
        let place = JournalPlace {
            in_session,
            on_disk: self.journal_keeps_files_on_disk(),
            under_sudo: self
                .invoking_user
                .as_deref()
                .is_some_and(|user| !user.is_empty()),
        };
        let mut findings = Vec::new();

        for (needle, label) in self.journal_needles() {
            let Ok(hits) = self.journal.grep(&needle) else {
                // A single unreadable probe means the journal is not available
                // to this run at all; stop and report it as not-checked rather
                // than as clean.
                return (findings, false);
            };
            let (sudo, other): (Vec<String>, Vec<String>) =
                hits.into_iter().partition(|hit| is_sudo_record(hit));
            for (kind, group) in [(EntryKind::SudoRecord, sudo), (EntryKind::Other, other)] {
                if !group.is_empty() {
                    findings.push(journal_finding(kind, &group, &needle, label, place));
                }
            }
        }

        (findings, true)
    }

    /// The tokens the journal leak search greps for, each with a human label.
    ///
    /// Sourced from the shared artifact registry and the active configuration so
    /// the search never drifts from what the tool actually writes: the tool name,
    /// the config file name, the configured hidden volume mount path and the
    /// encrypted-backend command names a hidden session runs.
    fn journal_needles(&self) -> Vec<(String, &'static str)> {
        let mut needles: Vec<(String, &'static str)> = vec![
            (crate::artifacts::TOOL_NAME.to_string(), "the tool name"),
            (
                crate::artifacts::CONFIG_FILE_NAME.to_string(),
                "the configuration file name",
            ),
            ("cryptsetup".to_string(), "the backend unlock command"),
        ];

        if let Some(hidden_root) = self.hidden_root() {
            let path = hidden_root.to_string_lossy().to_string();
            if !path.is_empty() {
                needles.push((path, "the hidden volume mount path"));
            }
        }

        needles
    }

    /// Whether the journal keeps files on disk: a journal file in
    /// `/var/log/journal` or in a machine directory below it, unless that
    /// directory is a tmpfs. Without one, every entry `journalctl` reads is in
    /// the runtime journal in RAM. Inside the hidden session the directory is
    /// the root overlay's, so its files may be on the decoy disk or on the
    /// hidden volume.
    fn journal_keeps_files_on_disk(&self) -> bool {
        let dir = Path::new(PERSISTENT_JOURNAL_DIR);
        if matches!(
            self.filesystem.get_filesystem_type(dir),
            Ok(Some(ref fstype)) if fstype == "tmpfs"
        ) {
            return false;
        }
        let entries = self.filesystem.list_directory(dir).unwrap_or_default();
        entries.iter().any(|entry| {
            is_journal_file(entry)
                || self
                    .filesystem
                    .list_directory(entry)
                    .is_ok_and(|files| files.iter().any(|file| is_journal_file(file)))
        })
    }
}

/// The finding for one group of a needle's hits.
///
/// Entries that may be on disk warn. Kept in RAM, the hidden session's journal
/// and sudo's records of commands are notes: the way back or a power-off
/// removes them, and every command run with sudo leaves such a record. On the
/// decoy any other entry warns, because it is either the decoy's own record or
/// one a hidden session left, and only the operator can tell which.
fn journal_finding(
    kind: EntryKind,
    hits: &[String],
    needle: &str,
    label: &str,
    place: JournalPlace,
) -> Finding {
    let count = hits.len();
    let what = match kind {
        EntryKind::SudoRecord => {
            format!("{count} sudo record{}", if count == 1 { "" } else { "s" })
        }
        EntryKind::Other => format!("{count} entr{}", if count == 1 { "y" } else { "ies" }),
    };
    let journal = if place.in_session {
        "The running session's journal"
    } else {
        "Systemd journal"
    };
    let origin = match kind {
        EntryKind::SudoRecord if place.under_sudo => {
            ": commands run with sudo, this verify run included"
        }
        EntryKind::SudoRecord => ": commands run with sudo",
        EntryKind::Other if place.in_session => "",
        EntryKind::Other => ": the decoy's own records or ones a hidden session left",
    };
    let (kept, remedy) = match (place.on_disk, place.in_session) {
        (false, true) => (
            "The journal is in RAM: the way back to the decoy or a power-off removes these \
             entries.",
            "",
        ),
        (false, false) => (
            "The journal is in RAM: a power-off removes these entries.",
            "",
        ),
        (true, true) => (
            "The journal keeps files on disk (/var/log/journal), so what was logged on the \
             decoy before the switch can be on the decoy disk.",
            " On the decoy, vacuum the journal (journalctl --rotate --vacuum-time=1s) and \
             switch it to a volatile journal (Storage=volatile).",
        ),
        (true, false) => (
            "The journal keeps files on disk (/var/log/journal), so these entries outlast a \
             power-off.",
            " Vacuum the journal (journalctl --rotate --vacuum-time=1s) and switch the decoy \
             to a volatile journal (Storage=volatile).",
        ),
    };
    let severity = if place.on_disk || (kind == EntryKind::Other && !place.in_session) {
        Severity::Warn
    } else {
        Severity::Info
    };
    // sudo pads the user name with spaces; the sample reads better without.
    let sample = hits.first().map(|hit| hit.trim()).unwrap_or_default();
    Finding::new(
        severity,
        "journal",
        format!("{journal} has {what} referencing {label} (\"{needle}\"){origin}"),
    )
    .with_fix_guidance(format!(
        "{kept} Inspect with: journalctl --grep '{needle}'.{remedy} Sample: {sample}"
    ))
}

/// Whether `path` names a journal file: `*.journal`, or `*.journal~` for one
/// journald set aside as damaged.
fn is_journal_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".journal") || name.ends_with(".journal~"))
}

/// Whether a journal message is sudo's record of a command run with it, such
/// as `alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id`.
fn is_sudo_record(message: &str) -> bool {
    message.contains(" ; USER=") && message.contains(" ; COMMAND=")
}
