// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reading the systemd journal for a deep-scan leak search.
//!
//! The deep verify pass greps the live journal for the tokens a hidden session
//! would leave there if the journald relinquish/flush hooks failed: the tool
//! name, the hidden volume mount path and the encrypted-backend command names.
//! A persistent decoy journal that still holds any of these is a leak onto the
//! decoy disk, so `verify --deep` reports each hit.
//!
//! The journal is read through the [`JournalReader`] trait so the search logic is
//! tested against a deterministic fake, never the host journal: the real reader
//! ([`JournalctlReader`]) shells out to `journalctl --grep`, while tests inject a
//! [`FakeJournalReader`] with canned matches.

use crate::Result;
use crate::process::{ProcessCommand, ProcessRunner, RealProcessRunner};
use std::time::Duration;

/// How long a single `journalctl --grep` probe may run before it is abandoned.
///
/// A deep scan runs several probes back to back; bounding each one keeps a hung
/// or enormous journal from stalling `verify` indefinitely.
const JOURNAL_GREP_DEADLINE: Duration = Duration::from_secs(30);

/// Searches the systemd journal for a literal token.
///
/// Implementors return the journal lines that contain `needle`. An empty vector
/// means the journal was searched and nothing matched (a clean result); an
/// `Err` means the journal could not be searched at all, which the deep scan
/// reports as an area it could not inspect rather than as "clean".
pub trait JournalReader: Send + Sync {
    /// Return every journal entry whose message contains `needle`.
    fn grep(&self, needle: &str) -> Result<Vec<String>>;
}

/// The production reader: `journalctl --grep` against the live system journal.
#[derive(Debug, Default, Clone, Copy)]
pub struct JournalctlReader;

impl JournalReader for JournalctlReader {
    fn grep(&self, needle: &str) -> Result<Vec<String>> {
        // `--grep` takes a PCRE pattern, so the literal token is escaped to match
        // itself rather than being interpreted (a `.` in `nails.toml` must not
        // match an arbitrary character). `-q` suppresses the informational "--
        // No entries --"/boot banners, `--no-pager` keeps it non-interactive and
        // `--output=cat` drops the per-line metadata so only message text is
        // returned.
        let pattern = format!("--grep={}", escape_pcre(needle));
        let command = ProcessCommand::tool("journalctl")
            .args(["--no-pager", "-q", "--output=cat", pattern.as_str()])
            .deadline(JOURNAL_GREP_DEADLINE);

        let (success, stdout, stderr) = RealProcessRunner.run_text(&command)?;

        let matches: Vec<String> = stdout
            .lines()
            .map(str::trim_end)
            .filter(|line| !line.is_empty() && !line.starts_with("-- "))
            .map(str::to_string)
            .collect();

        // `journalctl --grep` exits non-zero when nothing matched, so a non-zero
        // status with no stdout is a clean result, not a failure. Only treat it
        // as unreadable when it also wrote a diagnostic to stderr (no journal
        // access, journald absent), so an honest "not searched" is reported
        // instead of a false "clean".
        if matches.is_empty() && !success && !stderr.trim().is_empty() {
            return Err(crate::NailsError::InvalidState(format!(
                "journalctl could not search the journal: {}",
                stderr.trim()
            )));
        }

        Ok(matches)
    }
}

/// Escape the PCRE metacharacters in `needle` so `journalctl --grep` matches it
/// as a literal string.
fn escape_pcre(needle: &str) -> String {
    const META: &[char] = &[
        '\\', '^', '$', '.', '|', '?', '*', '+', '(', ')', '[', ']', '{', '}',
    ];
    let mut escaped = String::with_capacity(needle.len());
    for ch in needle.chars() {
        if META.contains(&ch) {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

/// A deterministic [`JournalReader`] for tests: returns the canned lines whose
/// text contains the searched needle, so the deep-scan reporting is exercised
/// without touching the host journal.
#[cfg(test)]
#[derive(Debug, Default, Clone)]
pub(crate) struct FakeJournalReader {
    /// Canned journal lines. A `grep(needle)` returns those that contain
    /// `needle`.
    entries: Vec<String>,
    /// When set, every `grep` fails with this message, modelling a journal that
    /// could not be read.
    unreadable: Option<String>,
}

#[cfg(test)]
impl FakeJournalReader {
    /// A reader over the given canned journal lines.
    pub(crate) fn with_entries<I, S>(entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            entries: entries.into_iter().map(Into::into).collect(),
            unreadable: None,
        }
    }

    /// A reader whose every search fails, modelling an unreadable journal.
    pub(crate) fn unreadable(message: impl Into<String>) -> Self {
        Self {
            entries: Vec::new(),
            unreadable: Some(message.into()),
        }
    }
}

#[cfg(test)]
impl JournalReader for FakeJournalReader {
    fn grep(&self, needle: &str) -> Result<Vec<String>> {
        if let Some(message) = &self.unreadable {
            return Err(crate::NailsError::InvalidState(message.clone()));
        }
        Ok(self
            .entries
            .iter()
            .filter(|line| line.contains(needle))
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_pcre_escapes_metacharacters() {
        assert_eq!(escape_pcre("nails.toml"), "nails\\.toml");
        assert_eq!(escape_pcre("/mnt/hidden"), "/mnt/hidden");
        assert_eq!(escape_pcre("a+b*c?"), "a\\+b\\*c\\?");
    }

    #[test]
    fn fake_reader_returns_only_matching_lines() {
        let reader = FakeJournalReader::with_entries([
            "sudo: pam_unix(sudo:session): session opened for user root",
            "nails activate completed",
        ]);
        assert_eq!(
            reader.grep("nails").unwrap(),
            vec!["nails activate completed"]
        );
        assert!(reader.grep("veracrypt").unwrap().is_empty());
    }

    #[test]
    fn fake_reader_can_model_an_unreadable_journal() {
        let reader = FakeJournalReader::unreadable("permission denied");
        assert!(reader.grep("nails").is_err());
    }

    #[test]
    fn real_reader_is_refused_in_the_test_runtime() {
        // The production reader shells out to journalctl, which the process
        // runner refuses from a test context; it must surface that as an error
        // (the deep scan then reports the journal as not-checked) rather than
        // claiming a clean journal.
        assert!(JournalctlReader.grep("nails").is_err());
    }
}
