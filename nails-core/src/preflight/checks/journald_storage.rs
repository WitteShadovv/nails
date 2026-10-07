// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! journald persistent-storage detection
//!
//! Resolves the effective systemd-journald `Storage=` setting from
//! `journald.conf` and all of its drop-ins (see [`super::systemd_conf`]) and
//! decides whether the journal persists onto the decoy disk. The verdict is folded into
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

use super::systemd_conf::{self, Assignment};
use crate::Filesystem;
use std::path::Path;

/// journald's configuration name; resolved with its drop-ins by
/// [`systemd_conf`].
const JOURNALD_CONF: &str = "journald.conf";
/// The section journald reads its settings from.
const JOURNAL_SECTION: &str = "Journal";
/// Persistent journal directory journald creates under `Storage=persistent`/`auto`,
/// relative to the root.
const JOURNAL_DIR: &str = "var/log/journal";

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

/// Fold `Storage=` assignments, in application order, into the effective value.
///
/// journald matches values exactly (case-sensitive, no unquoting), so an
/// unrecognised value is ignored and leaves the previous setting in place
/// rather than silently downgrading to the default. An empty `Storage=` is
/// taken as a reset to the built-in default, the conservative reading. Returns
/// `None` when no valid `Storage=` is in effect, which leaves journald's
/// built-in `auto` default to the caller.
fn storage_from(assignments: &[Assignment]) -> Option<JournaldStorage> {
    let mut storage = None;
    for assignment in assignments.iter().filter(|a| a.key == "Storage") {
        match assignment.value.as_str() {
            "persistent" => storage = Some(JournaldStorage::Persistent),
            "volatile" => storage = Some(JournaldStorage::Volatile),
            "none" => storage = Some(JournaldStorage::None),
            "auto" => storage = Some(JournaldStorage::Auto),
            "" => storage = None,
            _ => {}
        }
    }
    storage
}

/// Parse the effective `Storage=` value from one journald configuration text.
///
/// Only the `[Journal]` section counts and the syntax follows systemd (see
/// [`systemd_conf`]); the last valid assignment wins.
pub fn parse_journald_storage(config_text: &str) -> Option<JournaldStorage> {
    let mut assignments = Vec::new();
    let _ = systemd_conf::parse_section(config_text, JOURNAL_SECTION, &mut assignments);
    storage_from(&assignments)
}

/// The effective `Storage=` of the running journald, resolved from the main
/// configuration file and every drop-in the way systemd does.
pub fn effective_journald_storage<F: Filesystem>(fs: &F) -> JournaldStorage {
    effective_journald_storage_at(fs, Path::new("/"))
}

/// [`effective_journald_storage`] for the system tree rooted at `root`. When
/// nothing sets a valid `Storage=`, journald runs on its built-in default
/// (`auto`).
pub fn effective_journald_storage_at<F: Filesystem>(fs: &F, root: &Path) -> JournaldStorage {
    let assignments = systemd_conf::section_assignments(fs, root, JOURNALD_CONF, JOURNAL_SECTION);
    storage_from(&assignments).unwrap_or(JournaldStorage::Auto)
}

/// Whether `/var/log/journal` is a real on-disk directory (not tmpfs, not
/// absent), which is what makes `Storage=auto` behave persistently.
pub fn persistent_journal_dir_present<F: Filesystem>(fs: &F, root: &Path) -> bool {
    let dir = root.join(JOURNAL_DIR);
    let dir = dir.as_path();
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
    journald_persists_to_decoy_at(fs, Path::new("/"))
}

/// [`journald_persists_to_decoy`] for the system tree rooted at `root`.
pub fn journald_persists_to_decoy_at<F: Filesystem>(fs: &F, root: &Path) -> bool {
    journal_persists_to_disk(
        effective_journald_storage_at(fs, root),
        persistent_journal_dir_present(fs, root),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RealFilesystem;
    use crate::filesystem::{MockFilesystem, PathKind};

    const MAIN: &str = "/etc/systemd/journald.conf";
    const DIR: &str = "/var/log/journal";

    fn write(root: &Path, rel: &str, content: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn parses_explicit_values() {
        assert_eq!(
            parse_journald_storage("[Journal]\nStorage=persistent\n"),
            Some(JournaldStorage::Persistent)
        );
        assert_eq!(
            parse_journald_storage("[Journal]\nStorage=volatile"),
            Some(JournaldStorage::Volatile)
        );
        assert_eq!(
            parse_journald_storage("[Journal]\nStorage=none"),
            Some(JournaldStorage::None)
        );
        assert_eq!(
            parse_journald_storage("[Journal]\nStorage=auto"),
            Some(JournaldStorage::Auto)
        );
    }

    #[test]
    fn keys_values_and_sections_match_like_journald() {
        // journald matches keys and values case-sensitively and never unquotes.
        assert_eq!(parse_journald_storage("[Journal]\nstorage=volatile"), None);
        assert_eq!(parse_journald_storage("[Journal]\nStorage=VOLATILE"), None);
        assert_eq!(
            parse_journald_storage("[Journal]\nStorage=\"volatile\""),
            None
        );
        // Outside [Journal] nothing counts.
        assert_eq!(parse_journald_storage("Storage=volatile\n"), None);
        assert_eq!(
            parse_journald_storage("[Journal]\nStorage=volatile\n[Other]\nStorage=persistent\n"),
            Some(JournaldStorage::Volatile)
        );
    }

    #[test]
    fn ignores_comments_and_takes_the_last_assignment() {
        let text = "[Journal]\n#Storage=persistent\nStorage=volatile\nStorage=persistent\n";
        assert_eq!(
            parse_journald_storage(text),
            Some(JournaldStorage::Persistent)
        );
        assert_eq!(
            parse_journald_storage("[Journal]\n# Storage=persistent\n"),
            None
        );
        assert_eq!(parse_journald_storage("[Journal]\nSystemMaxUse=1G\n"), None);
    }

    #[test]
    fn unknown_value_keeps_the_previous_setting_and_empty_resets() {
        assert_eq!(
            parse_journald_storage("[Journal]\nStorage=volatile\nStorage=bogus\n"),
            Some(JournaldStorage::Volatile)
        );
        assert_eq!(parse_journald_storage("[Journal]\nStorage=bogus\n"), None);
        assert_eq!(
            parse_journald_storage("[Journal]\nStorage=volatile\nStorage=\n"),
            None
        );
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
        fs.mock_add_file(MAIN, "[Journal]\nStorage=persistent\n");
        assert!(journald_persists_to_decoy(&fs));
    }

    #[test]
    fn auto_with_on_disk_journal_dir_persists() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(MAIN, "[Journal]\nStorage=auto\n");
        fs.mock_set_path_type(DIR, PathKind::Dir);
        assert!(journald_persists_to_decoy(&fs));
    }

    #[test]
    fn auto_with_tmpfs_journal_dir_does_not_persist() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(MAIN, "[Journal]\nStorage=auto\n");
        fs.mock_set_path_type(DIR, PathKind::Dir);
        fs.mock_set_filesystem_type(Path::new(DIR), "tmpfs");
        assert!(!journald_persists_to_decoy(&fs));
    }

    #[test]
    fn volatile_drop_in_over_persistent_main_does_not_persist() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "etc/systemd/journald.conf",
            "[Journal]\nStorage=persistent\n",
        );
        write(
            root,
            "etc/systemd/journald.conf.d/50-volatile.conf",
            "[Journal]\nStorage=volatile\n",
        );
        std::fs::create_dir_all(root.join(JOURNAL_DIR)).unwrap();
        assert_eq!(
            effective_journald_storage_at(&RealFilesystem, root),
            JournaldStorage::Volatile
        );
        assert!(!journald_persists_to_decoy_at(&RealFilesystem, root));
    }

    #[test]
    fn persistent_drop_in_over_volatile_main_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "etc/systemd/journald.conf",
            "[Journal]\nStorage=volatile\n",
        );
        write(
            root,
            "usr/lib/systemd/journald.conf.d/10-persist.conf",
            "[Journal]\nStorage=persistent\n",
        );
        assert!(journald_persists_to_decoy_at(&RealFilesystem, root));
    }

    #[test]
    fn auto_drop_in_resolves_to_auto() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "usr/lib/systemd/journald.conf",
            "[Journal]\nStorage=volatile\n",
        );
        write(
            root,
            "run/systemd/journald.conf.d/10-auto.conf",
            "[Journal]\nStorage=auto\n",
        );
        let storage = effective_journald_storage_at(&RealFilesystem, root);
        assert_eq!(storage, JournaldStorage::Auto);
        // No journal directory in the tree: auto stays volatile.
        assert!(!journald_persists_to_decoy_at(&RealFilesystem, root));
        // With an on-disk journal directory, auto persists. (The tempdir itself
        // may sit on tmpfs, so the directory verdict is supplied directly.)
        assert!(journal_persists_to_disk(storage, true));
    }
}
