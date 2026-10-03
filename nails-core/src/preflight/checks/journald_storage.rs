//! journald persistent-storage detection
//!
//! Parses the effective systemd-journald `Storage=` setting and decides whether
//! the journal persists onto the decoy disk. The verdict is folded into
//! [`DecoyPersistenceCheck`](super::decoy_posture::DecoyPersistenceCheck), which
//! fails activation closed on a persistent decoy journal unless the operator
//! opts in.
//!
//! # Security
//!
//! When journald stores its journal persistently under `/var/log/journal`, the
//! records a hidden session produces before `/var` is overlaid — and anything
//! journald fails to re-home onto the overlay — survive on the decoy disk across
//! deactivation and reboot. The overlay re-home and the detach-time relinquish
//! shrink that window, but a persistent decoy journal remains a standing hazard,
//! so this is surfaced before any state is written. Nothing here vacuums or
//! rotates the decoy journal: destroying the decoy's own log history is itself a
//! deniability tell.

use crate::Filesystem;
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

/// The effective `Storage=` of the running journald, read from the main config
/// file. A missing or unreadable file means journald runs on its built-in
/// default (`auto`), so that is returned when no explicit value is found.
pub fn effective_journald_storage<F: Filesystem>(fs: &F) -> JournaldStorage {
    fs.read_file_content(Path::new(JOURNALD_CONF))
        .ok()
        .and_then(|text| parse_journald_storage(&text))
        .unwrap_or(JournaldStorage::Auto)
}

/// Whether `/var/log/journal` is a real on-disk directory (not tmpfs, not
/// absent), which is what makes `Storage=auto` behave persistently.
pub fn persistent_journal_dir_present<F: Filesystem>(fs: &F) -> bool {
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
pub fn journal_persists_to_disk(storage: JournaldStorage, dir_present: bool) -> bool {
    match storage {
        JournaldStorage::Persistent => true,
        JournaldStorage::Volatile | JournaldStorage::None => false,
        JournaldStorage::Auto => dir_present,
    }
}

/// Whether the live journald configuration persists the journal to the decoy
/// disk. Combines the effective `Storage=` value with the presence of an on-disk
/// `/var/log/journal`.
pub fn journald_persists_to_decoy<F: Filesystem>(fs: &F) -> bool {
    journal_persists_to_disk(
        effective_journald_storage(fs),
        persistent_journal_dir_present(fs),
    )
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
        assert!(journal_persists_to_disk(JournaldStorage::Persistent, false));
        assert!(!journal_persists_to_disk(JournaldStorage::Volatile, true));
        assert!(!journal_persists_to_disk(JournaldStorage::None, true));
        assert!(journal_persists_to_disk(JournaldStorage::Auto, true));
        assert!(!journal_persists_to_disk(JournaldStorage::Auto, false));
    }

    #[test]
    fn missing_config_defaults_to_auto() {
        let fs = MockFilesystem::new();
        assert_eq!(effective_journald_storage(&fs), JournaldStorage::Auto);
    }

    #[test]
    fn auto_without_journal_dir_does_not_persist() {
        let fs = MockFilesystem::new();
        assert!(!journald_persists_to_decoy(&fs));
    }

    #[test]
    fn explicit_persistent_persists() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(JOURNALD_CONF, "[Journal]\nStorage=persistent\n");
        assert!(journald_persists_to_decoy(&fs));
    }

    #[test]
    fn auto_with_on_disk_journal_dir_persists() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(JOURNALD_CONF, "[Journal]\nStorage=auto\n");
        fs.mock_set_path_type(JOURNAL_DIR, PathKind::Dir);
        assert!(journald_persists_to_decoy(&fs));
    }

    #[test]
    fn auto_with_tmpfs_journal_dir_does_not_persist() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(JOURNALD_CONF, "[Journal]\nStorage=auto\n");
        fs.mock_set_path_type(JOURNAL_DIR, PathKind::Dir);
        fs.mock_set_filesystem_type(Path::new(JOURNAL_DIR), "tmpfs");
        assert!(!journald_persists_to_decoy(&fs));
    }
}
