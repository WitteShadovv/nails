//! journald persistent-storage pre-flight check
//!
//! Refuses activation on a host whose systemd-journald keeps a persistent journal
//! on the decoy disk, unless the operator opts in.
//!
//! # Security
//!
//! When journald stores its journal persistently under `/var/log/journal`, the
//! records a hidden session produces before `/var` is overlaid — and anything
//! journald fails to re-home onto the overlay — survive on the decoy disk across
//! deactivation and reboot. The overlay re-home and the detach-time relinquish
//! shrink that window, but a persistent decoy journal remains a standing hazard,
//! so this check surfaces it before any state is written. It never vacuums or
//! rotates the decoy journal: destroying the decoy's own log history is itself a
//! deniability tell.

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result};
use std::path::Path;

/// Main journald configuration file.
const JOURNALD_CONF: &str = "/etc/systemd/journald.conf";
/// Persistent journal directory journald creates under `Storage=persistent`/`auto`.
const JOURNAL_DIR: &str = "/var/log/journal";

/// Effective `Storage=` setting of systemd-journald.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournaldStorage {
    /// Always store on disk under `/var/log/journal`.
    Persistent,
    /// Store only in the volatile `/run/log/journal` (tmpfs).
    Volatile,
    /// Store nothing (forward only).
    None,
    /// Persist when `/var/log/journal` exists, otherwise stay volatile.
    Auto,
}

/// Parse the effective `Storage=` value from journald configuration text.
///
/// systemd concatenates the main file and its drop-ins, with the last assignment
/// winning, so this scans every line and keeps the last recognised value. Keys
/// are matched case-insensitively; full-line `#`/`;` comments and lines without a
/// `Storage=` assignment are ignored. Returns `None` when no `Storage=` is set,
/// which leaves journald's built-in `auto` default to the caller.
pub fn parse_journald_storage(config_text: &str) -> Option<JournaldStorage> {
    let mut storage = None;
    for raw in config_text.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if !key.trim().eq_ignore_ascii_case("Storage") {
            continue;
        }
        // systemd .conf files do not support trailing inline comments, so the
        // whole right-hand side is the value.
        match value.trim().to_ascii_lowercase().as_str() {
            "persistent" => storage = Some(JournaldStorage::Persistent),
            "volatile" => storage = Some(JournaldStorage::Volatile),
            "none" => storage = Some(JournaldStorage::None),
            "auto" => storage = Some(JournaldStorage::Auto),
            // An unrecognised value leaves the previous setting in place rather
            // than silently downgrading to the default.
            _ => {}
        }
    }
    storage
}

/// Pre-flight check that refuses a persistent decoy journal.
#[derive(Debug, Default)]
pub struct JournaldStorageCheck {
    /// When set, a persistent journal is accepted (reported as a warning) instead
    /// of failing the check. Wired from `--allow-persistent-journal`.
    allow_persistent: bool,
}

impl JournaldStorageCheck {
    /// Create the check. `allow_persistent` mirrors the override flag.
    pub fn new(allow_persistent: bool) -> Self {
        Self { allow_persistent }
    }

    /// Whether `/var/log/journal` is a real on-disk directory (not tmpfs, not
    /// absent), which is what makes `Storage=auto` behave persistently.
    fn persistent_dir_present<F: Filesystem>(fs: &F) -> bool {
        let dir = Path::new(JOURNAL_DIR);
        if !fs.is_directory(dir).unwrap_or(false) {
            return false;
        }
        // A journal directory backed by tmpfs is volatile despite existing.
        !matches!(
            fs.get_filesystem_type(dir),
            Ok(Some(ref fstype)) if fstype == "tmpfs"
        )
    }

    /// Decide whether the effective storage persists to the decoy disk.
    fn persists_to_disk(storage: JournaldStorage, dir_present: bool) -> bool {
        match storage {
            JournaldStorage::Persistent => true,
            JournaldStorage::Volatile | JournaldStorage::None => false,
            JournaldStorage::Auto => dir_present,
        }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for JournaldStorageCheck {
    fn name(&self) -> &'static str {
        "journald-storage"
    }

    fn description(&self) -> &'static str {
        "Validates journald does not persist the decoy journal to disk"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // A missing config file means journald runs on its built-in default
        // (auto), so treat an unreadable file as "no explicit Storage=".
        let storage = fs
            .read_file_content(Path::new(JOURNALD_CONF))
            .ok()
            .and_then(|text| parse_journald_storage(&text))
            .unwrap_or(JournaldStorage::Auto);

        let dir_present = Self::persistent_dir_present(fs);

        if !Self::persists_to_disk(storage, dir_present) {
            return Ok(CheckResult::Pass(
                "journald does not persist a journal to the decoy disk".into(),
            ));
        }

        if self.allow_persistent {
            return Ok(CheckResult::Warn(
                "journald keeps a persistent journal on the decoy disk; accepted via \
                 --allow-persistent-journal. Records logged before /var is overlaid may \
                 survive on the decoy disk."
                    .into(),
            ));
        }

        Ok(CheckResult::fail(
            "journald keeps a persistent journal on the decoy disk (/var/log/journal). \
             Records written before /var is overlaid can survive deactivation and reboot. \
             Set Storage=volatile in journald.conf, or pass --allow-persistent-journal to \
             accept the risk."
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::{MockFilesystem, PathKind};

    #[test]
    fn parses_explicit_values_case_insensitively() {
        assert_eq!(
            parse_journald_storage("[Journal]\nStorage=persistent\n"),
            Some(JournaldStorage::Persistent)
        );
        assert_eq!(
            parse_journald_storage("storage=VOLATILE"),
            Some(JournaldStorage::Volatile)
        );
        assert_eq!(
            parse_journald_storage("Storage=none"),
            Some(JournaldStorage::None)
        );
        assert_eq!(
            parse_journald_storage("Storage=auto"),
            Some(JournaldStorage::Auto)
        );
    }

    #[test]
    fn ignores_comments_and_takes_the_last_assignment() {
        let text = "#Storage=persistent\nStorage=volatile\nStorage=persistent\n";
        assert_eq!(
            parse_journald_storage(text),
            Some(JournaldStorage::Persistent)
        );
        assert_eq!(parse_journald_storage("# Storage=persistent\n"), None);
        assert_eq!(parse_journald_storage("SystemMaxUse=1G\n"), None);
    }

    #[test]
    fn unknown_value_keeps_the_previous_setting() {
        assert_eq!(
            parse_journald_storage("Storage=volatile\nStorage=bogus\n"),
            Some(JournaldStorage::Volatile)
        );
        assert_eq!(parse_journald_storage("Storage=bogus\n"), None);
    }

    #[test]
    fn persists_to_disk_matrix() {
        assert!(JournaldStorageCheck::persists_to_disk(
            JournaldStorage::Persistent,
            false
        ));
        assert!(!JournaldStorageCheck::persists_to_disk(
            JournaldStorage::Volatile,
            true
        ));
        assert!(!JournaldStorageCheck::persists_to_disk(
            JournaldStorage::None,
            true
        ));
        assert!(JournaldStorageCheck::persists_to_disk(
            JournaldStorage::Auto,
            true
        ));
        assert!(!JournaldStorageCheck::persists_to_disk(
            JournaldStorage::Auto,
            false
        ));
    }

    #[test]
    fn fails_on_explicit_persistent_storage() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(JOURNALD_CONF, "[Journal]\nStorage=persistent\n");

        let check = JournaldStorageCheck::new(false);
        let result = check.run(&fs).unwrap();

        assert!(result.is_fail(), "persistent storage must fail: {result:?}");
    }

    #[test]
    fn override_turns_persistent_into_a_warning() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(JOURNALD_CONF, "[Journal]\nStorage=persistent\n");

        let check = JournaldStorageCheck::new(true);
        let result = check.run(&fs).unwrap();

        assert!(result.is_warn(), "override must warn, not fail: {result:?}");
    }

    #[test]
    fn passes_on_volatile_storage() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(JOURNALD_CONF, "[Journal]\nStorage=volatile\n");

        let check = JournaldStorageCheck::new(false);
        let result = check.run(&fs).unwrap();

        assert!(result.is_pass(), "volatile storage must pass: {result:?}");
    }

    #[test]
    fn auto_without_journal_dir_passes() {
        // No journald.conf and no /var/log/journal: auto stays volatile.
        let fs = MockFilesystem::new();

        let check = JournaldStorageCheck::new(false);
        let result = check.run(&fs).unwrap();

        assert!(
            result.is_pass(),
            "auto without a journal dir must pass: {result:?}"
        );
    }

    #[test]
    fn auto_with_persistent_journal_dir_fails() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(JOURNALD_CONF, "[Journal]\nStorage=auto\n");
        fs.mock_set_path_type(JOURNAL_DIR, PathKind::Dir);

        let check = JournaldStorageCheck::new(false);
        let result = check.run(&fs).unwrap();

        assert!(
            result.is_fail(),
            "auto with an on-disk journal dir must fail: {result:?}"
        );
    }

    #[test]
    fn auto_with_tmpfs_journal_dir_passes() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(JOURNALD_CONF, "[Journal]\nStorage=auto\n");
        fs.mock_set_path_type(JOURNAL_DIR, PathKind::Dir);
        fs.mock_set_filesystem_type(Path::new(JOURNAL_DIR), "tmpfs");

        let check = JournaldStorageCheck::new(false);
        let result = check.run(&fs).unwrap();

        assert!(
            result.is_pass(),
            "a tmpfs journal dir is volatile and must pass: {result:?}"
        );
    }
}
