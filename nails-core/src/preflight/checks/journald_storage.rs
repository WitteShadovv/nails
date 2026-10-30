// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! journald persistent-storage detection
//!
//! Resolves the effective systemd-journald `Storage=` setting from
//! `journald.conf` and all of its drop-ins (see [`super::systemd_conf`]), the
//! `journal.storage` credential and the built-in default, and decides whether
//! the journal persists onto the decoy disk. The verdict is folded into
//! [`DecoyPersistenceCheck`](super::decoy_posture::DecoyPersistenceCheck), which
//! fails activation closed on a persistent decoy journal unless the operator
//! opts in.
//!
//! # Security
//!
//! With a persistent journal under `/var/log/journal`, the decoy journald
//! writes the window around each soft-reboot to the decoy disk: the sudo line
//! of the activation, the hidden build's progress, the decoy's shutdown before
//! the switch and its start after the way back, under one boot ID. The hidden
//! session's own records stay off that disk only while every barrier holds:
//! the root overlay keeps the hidden journald's files below `/var` on the
//! hidden volume, the scrub on the way back deletes the runtime journal before
//! the decoy journald can flush it to disk, and the kmsg cursor keeps the
//! hidden session's kernel records out. A volatile journal keeps all of this
//! in RAM, so a persistent one is surfaced before any state is written.
//! Nothing here vacuums or rotates the decoy journal: destroying the decoy's
//! own log history is itself a deniability tell.

use super::systemd_conf::{self, Assignment, Unread};
use crate::{Filesystem, runtime_safety};
use std::path::Path;

/// journald's configuration name; resolved with its drop-ins by
/// [`systemd_conf`].
const JOURNALD_CONF: &str = "journald.conf";
/// The section journald reads its settings from.
const JOURNAL_SECTION: &str = "Journal";
/// Persistent journal directory journald creates under `Storage=persistent`/`auto`,
/// relative to the root.
const JOURNAL_DIR: &str = "var/log/journal";
/// The vendor configuration file, relative to the root: the one place whose
/// commented `#Storage=` NAILS trusts for the built-in default (see
/// [`vendor_storage_hint`]).
const VENDOR_CONF_DIR: &str = "usr/lib/systemd";
/// The first systemd release whose built-in `Storage=` default is `persistent`
/// rather than `auto` (systemd v259 NEWS).
const PERSISTENT_DEFAULT_SINCE: u32 = 259;
/// The first systemd release whose journald reads the `journal.storage`
/// credential (systemd v256).
const STORAGE_CREDENTIAL_SINCE: u32 = 256;
/// The `journal.storage` credential journald was handed, relative to the root:
/// its service's `$CREDENTIALS_DIRECTORY`, where journald reads it. The service
/// manager copies there what `ImportCredential=journal.*` finds, in a
/// credential store, encrypted or not, or among the credentials passed at boot,
/// so this is what journald got rather than what a store holds. Only root can
/// read it.
const RECEIVED_STORAGE_CREDENTIAL: &str =
    "run/credentials/systemd-journald.service/journal.storage";

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

/// One `Storage=` value, as journald matches it: exactly, case-sensitive and
/// without unquoting. An unrecognised value is `None`.
fn storage_value(value: &str) -> Option<JournaldStorage> {
    match value {
        "persistent" => Some(JournaldStorage::Persistent),
        "volatile" => Some(JournaldStorage::Volatile),
        "none" => Some(JournaldStorage::None),
        "auto" => Some(JournaldStorage::Auto),
        _ => None,
    }
}

/// Fold `Storage=` assignments, in application order, into the effective value.
///
/// journald matches values exactly (case-sensitive, no unquoting) and ignores
/// a value it does not recognise, an empty one included, so that leaves the
/// previous setting in place: an empty `Storage=` resets nothing, and does not
/// hand the choice to the credential. Returns `None` when no valid `Storage=`
/// is in effect, which leaves the credential and journald's built-in default
/// to the caller.
fn storage_from(assignments: &[Assignment]) -> Option<JournaldStorage> {
    assignments
        .iter()
        .rev()
        .filter(|a| a.key == "Storage")
        .find_map(|a| storage_value(&a.value))
}

/// journald's built-in `Storage=` default when no configuration and no
/// credential set it, by service-manager version.
///
/// Below systemd 259 the default is `auto`; from 259 it is `persistent` (v259
/// NEWS), unless the *vendor* `usr/lib/systemd/journald.conf` documents a
/// different default in its commented `#Storage=` (a distro that kept the old
/// `auto`). An unknown version fails closed to `persistent`: a decoy whose
/// journal might reach the disk is surfaced rather than assumed amnesic.
pub fn built_in_default(
    systemd_major: Option<u32>,
    vendor_hint: Option<JournaldStorage>,
) -> JournaldStorage {
    match systemd_major {
        Some(version) if version < PERSISTENT_DEFAULT_SINCE => JournaldStorage::Auto,
        Some(_) => vendor_hint.unwrap_or(JournaldStorage::Persistent),
        None => JournaldStorage::Persistent,
    }
}

/// The effective `Storage=` from the three sources, in journald's precedence:
/// an explicit assignment in any configuration file wins; failing that the
/// `journal.storage` credential, if journald applied it ([`storage_credential`]);
/// failing that the version's built-in default.
fn resolve_storage(
    explicit: Option<JournaldStorage>,
    credential: Option<JournaldStorage>,
    vendor_hint: Option<JournaldStorage>,
    systemd_major: Option<u32>,
) -> JournaldStorage {
    explicit
        .or(credential)
        .unwrap_or_else(|| built_in_default(systemd_major, vendor_hint))
}

/// The `[Journal] #Storage=` the vendor file documents as the built-in default,
/// if any. Only `usr/lib/systemd/journald.conf` is read, and only its commented
/// hint: a distro that keeps journald's pre-259 `auto` default documents it
/// there, while a stale `/etc` comment is never trusted. The last commented
/// `Storage=` under `[Journal]` wins, as journald would fold real assignments.
fn vendor_storage_hint<F: Filesystem>(fs: &F, root: &Path) -> Option<JournaldStorage> {
    let path = root.join(VENDOR_CONF_DIR).join(JOURNALD_CONF);
    let text = systemd_conf::read_config_text(fs, &path)?;
    let mut in_section = false;
    let mut hint = None;
    for line in text.lines() {
        let line = line.trim_start_matches([' ', '\t']);
        if let Some(header) = line.strip_prefix('[') {
            in_section = header.strip_suffix(']') == Some(JOURNAL_SECTION);
            continue;
        }
        let Some(rest) = line.strip_prefix('#').or_else(|| line.strip_prefix(';')) else {
            continue;
        };
        if !in_section {
            continue;
        }
        if let Some((key, value)) = rest.split_once('=')
            && key.trim() == "Storage"
            && let Some(parsed) = storage_value(value.trim())
        {
            hint = Some(parsed);
        }
    }
    hint
}

/// The `Storage=` the `journal.storage` credential gives journald, read as
/// journald reads it: only from systemd 256 (an unknown version counts as
/// older), only the credential journald was handed, and only when its whole
/// content is a value exactly. journald strips nothing, so `volatile` with a
/// trailing newline, as `echo` writes it, is a value it ignores. It reads the
/// credential without asking for its size, and such a read fails on a NUL
/// anywhere in the content, so a credential holding a NUL counts for nothing
/// either. A credential that cannot be read (only root can) counts for
/// nothing. That misses a volatile one, which fails closed; a persistent one
/// has had journald create the on-disk `/var/log/journal`, which `auto`
/// persists to.
fn storage_credential<F: Filesystem>(
    fs: &F,
    root: &Path,
    systemd_major: Option<u32>,
) -> Option<JournaldStorage> {
    if systemd_major? < STORAGE_CREDENTIAL_SINCE {
        return None;
    }
    let data = fs
        .read_file_content(&root.join(RECEIVED_STORAGE_CREDENTIAL))
        .ok()?;
    // journald reads the credential without asking for its size, a read that
    // fails on a NUL anywhere, so it ignores such a credential. No value holds
    // a NUL, so matching the whole content ignores it here too.
    storage_value(&data)
}

/// The running service manager's major version, or `None` when it cannot be
/// read or host interaction is skipped (a unit-test binary). `None` makes the
/// built-in default fail closed, so a decoy of an unknown systemd is treated as
/// persistent rather than assumed amnesic.
fn host_systemd_major() -> Option<u32> {
    if runtime_safety::should_skip_host_interaction() {
        return None;
    }
    nails_session::session::systemd::running_version(&crate::process::RealProcessRunner)
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

/// [`effective_journald_storage`] for the system tree rooted at `root`. When no
/// configuration file sets a valid `Storage=`, the `journal.storage` credential
/// decides, and failing that journald's version-dependent built-in default
/// ([`built_in_default`]). A configuration NAILS cannot read as journald does
/// ([`Unread`]) counts as persistent.
pub fn effective_journald_storage_at<F: Filesystem>(fs: &F, root: &Path) -> JournaldStorage {
    storage_under_version(fs, root, host_systemd_major())
}

/// [`effective_journald_storage_at`] under a service manager of major version
/// `systemd_major`, `None` when it is not known.
fn storage_under_version<F: Filesystem>(
    fs: &F,
    root: &Path,
    systemd_major: Option<u32>,
) -> JournaldStorage {
    resolved_storage(fs, root, systemd_major).unwrap_or(JournaldStorage::Persistent)
}

/// [`storage_under_version`], or the reason NAILS cannot tell where journald
/// keeps the journal.
fn resolved_storage<F: Filesystem>(
    fs: &F,
    root: &Path,
    systemd_major: Option<u32>,
) -> Result<JournaldStorage, Unread> {
    let assignments = systemd_conf::section_assignments(fs, root, JOURNALD_CONF, JOURNAL_SECTION)?;
    Ok(resolve_storage(
        storage_from(&assignments),
        storage_credential(fs, root, systemd_major),
        vendor_storage_hint(fs, root),
        systemd_major,
    ))
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

/// [`journald_persists_to_decoy`] for the system tree rooted at `root`. A
/// configuration NAILS cannot read as journald does persists.
pub fn journald_persists_to_decoy_at<F: Filesystem>(fs: &F, root: &Path) -> bool {
    journald_persistence_at(fs, root).unwrap_or(true)
}

/// Whether the journal persists to the decoy disk under `root`, or why NAILS
/// cannot tell: journald's configuration holds an entry that the systemd
/// releases do not read alike, or a file NAILS cannot read ([`Unread`]).
pub fn journald_persistence_at<F: Filesystem>(fs: &F, root: &Path) -> Result<bool, Unread> {
    Ok(journal_persists_to_disk(
        resolved_storage(fs, root, host_systemd_major())?,
        persistent_journal_dir_present(fs, root),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RealFilesystem;
    use crate::filesystem::{MockFilesystem, PathKind};

    const MAIN: &str = "/etc/systemd/journald.conf";
    const DIR: &str = "/var/log/journal";
    const CREDENTIAL: &str = "/run/credentials/systemd-journald.service/journal.storage";

    fn write(root: &Path, rel: &str, content: impl AsRef<[u8]>) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    /// The effective storage of the mock system under systemd `version`.
    fn storage(fs: &MockFilesystem, version: Option<u32>) -> JournaldStorage {
        storage_under_version(fs, Path::new("/"), version)
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
    fn an_unknown_or_empty_value_keeps_the_previous_setting() {
        assert_eq!(
            parse_journald_storage("[Journal]\nStorage=volatile\nStorage=bogus\n"),
            Some(JournaldStorage::Volatile)
        );
        assert_eq!(parse_journald_storage("[Journal]\nStorage=bogus\n"), None);
        // journald ignores an empty value as it ignores any it does not know.
        assert_eq!(
            parse_journald_storage("[Journal]\nStorage=volatile\nStorage=\n"),
            Some(JournaldStorage::Volatile)
        );
        assert_eq!(parse_journald_storage("[Journal]\nStorage=\n"), None);
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
    fn built_in_default_is_version_and_vendor_aware() {
        // Below 259 the default is auto, whatever the vendor documents.
        assert_eq!(built_in_default(Some(255), None), JournaldStorage::Auto);
        assert_eq!(
            built_in_default(Some(258), Some(JournaldStorage::Persistent)),
            JournaldStorage::Auto
        );
        // From 259 the default is persistent, unless the vendor file documents
        // another one in its commented #Storage=.
        assert_eq!(
            built_in_default(Some(259), None),
            JournaldStorage::Persistent
        );
        assert_eq!(
            built_in_default(Some(262), Some(JournaldStorage::Auto)),
            JournaldStorage::Auto
        );
        // An unknown version fails closed, ignoring any vendor hint.
        assert_eq!(built_in_default(None, None), JournaldStorage::Persistent);
        assert_eq!(
            built_in_default(None, Some(JournaldStorage::Volatile)),
            JournaldStorage::Persistent
        );
    }

    #[test]
    fn resolve_follows_conf_then_credential_then_default() {
        // An explicit assignment wins over everything.
        assert_eq!(
            resolve_storage(
                Some(JournaldStorage::Volatile),
                Some(JournaldStorage::Persistent),
                Some(JournaldStorage::Auto),
                Some(259),
            ),
            JournaldStorage::Volatile
        );
        // No assignment: the credential decides, over the built-in default.
        assert_eq!(
            resolve_storage(None, Some(JournaldStorage::None), None, None),
            JournaldStorage::None
        );
        // Neither: the version-and-vendor built-in default.
        assert_eq!(
            resolve_storage(None, None, None, Some(259)),
            JournaldStorage::Persistent
        );
        assert_eq!(
            resolve_storage(None, None, Some(JournaldStorage::Auto), Some(259)),
            JournaldStorage::Auto
        );
    }

    #[test]
    fn an_unknown_version_with_no_config_counts_as_persistent() {
        // Under the unit-test runtime the running version cannot be read, so
        // the built-in default is the fail-closed one: a decoy with no journald
        // configuration counts as persistent and is refused.
        let fs = MockFilesystem::new();
        assert_eq!(effective_journald_storage(&fs), JournaldStorage::Persistent);
        assert!(journald_persists_to_decoy(&fs));
    }

    #[test]
    fn the_storage_credential_decides_when_no_conf_sets_storage() {
        // From systemd 256 journald reads the credential it was handed, which
        // keeps the journal in RAM over a persistent built-in default.
        let fs = MockFilesystem::new();
        fs.mock_add_file(CREDENTIAL, "volatile");
        assert_eq!(storage(&fs, Some(256)), JournaldStorage::Volatile);
        assert_eq!(storage(&fs, Some(259)), JournaldStorage::Volatile);
        // An explicit Storage= in a conf file still wins over the credential.
        fs.mock_add_file(MAIN, "[Journal]\nStorage=persistent\n");
        assert_eq!(storage(&fs, Some(259)), JournaldStorage::Persistent);
    }

    /// journald below 256 has no `journal.storage` credential, and a version
    /// that cannot be read counts as one of those, so the credential decides
    /// nothing there. NAILS used to take it on any version, which judged an
    /// Ubuntu 24.04 decoy (systemd 255) with a persistent journal volatile.
    #[test]
    fn the_storage_credential_counts_only_from_systemd_256() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(CREDENTIAL, "volatile");
        assert_eq!(storage(&fs, Some(255)), JournaldStorage::Auto);
        assert_eq!(storage(&fs, None), JournaldStorage::Persistent);
        // The live check runs with an unknown version under test.
        assert!(journald_persists_to_decoy(&fs));
    }

    /// journald matches the credential's whole content exactly, fails to read
    /// one that holds a NUL anywhere, and reads only the one it was handed: a
    /// value it would have to trim, a value with a NUL before, after or inside
    /// it, or a file in a credential store it was not given, counts for
    /// nothing and the persistent default decides.
    #[test]
    fn the_storage_credential_is_matched_as_journald_matches_it() {
        for (data, expected) in [
            ("volatile\n", JournaldStorage::Persistent),
            (" volatile", JournaldStorage::Persistent),
            ("Volatile", JournaldStorage::Persistent),
            ("", JournaldStorage::Persistent),
            ("none", JournaldStorage::None),
            ("volatile\0", JournaldStorage::Persistent),
            ("volatile\0\n", JournaldStorage::Persistent),
            ("\0volatile", JournaldStorage::Persistent),
            ("vola\0tile", JournaldStorage::Persistent),
        ] {
            let fs = MockFilesystem::new();
            fs.mock_add_file(CREDENTIAL, data);
            assert_eq!(storage(&fs, Some(259)), expected, "{data:?}");
        }
        let fs = MockFilesystem::new();
        fs.mock_add_file("/etc/credstore/journal.storage", "volatile");
        fs.mock_add_file("/run/credentials/@system/journal.storage", "volatile");
        assert_eq!(storage(&fs, Some(259)), JournaldStorage::Persistent);
    }

    /// An empty `Storage=` keeps the earlier file's setting, so the credential,
    /// which ranks below every file, does not get to decide.
    #[test]
    fn an_empty_storage_keeps_a_files_setting_over_the_credential() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "etc/systemd/journald.conf",
            "[Journal]\nStorage=persistent\n",
        );
        write(
            root,
            "etc/systemd/journald.conf.d/50-reset.conf",
            "[Journal]\nStorage=\n",
        );
        write(root, &CREDENTIAL[1..], "volatile");
        assert_eq!(
            storage_under_version(&RealFilesystem, root, Some(259)),
            JournaldStorage::Persistent
        );
    }

    /// journald stops reading at a line that is not valid UTF-8, unless it is
    /// a comment, and skips every drop-in after it. A Latin-1 value in the
    /// main file thus hides the drop-in's `Storage=volatile` from journald, and
    /// the built-in default decides; NAILS used to read the drop-in and pass
    /// the decoy.
    #[test]
    fn a_volatile_drop_in_behind_a_line_that_is_not_utf8_does_not_count() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // 'ö' and 'ß' in Latin-1, in a value: systemd has no trailing comments.
        write(
            root,
            "etc/systemd/journald.conf",
            b"[Journal]\nSystemMaxUse=200M # Gr\xF6\xDFe\nStorage=volatile\n",
        );
        write(
            root,
            "etc/systemd/journald.conf.d/50-volatile.conf",
            "[Journal]\nStorage=volatile\n",
        );
        assert_eq!(
            storage_under_version(&RealFilesystem, root, Some(259)),
            JournaldStorage::Persistent
        );
        assert_eq!(
            storage_under_version(&RealFilesystem, root, Some(255)),
            JournaldStorage::Auto
        );
        assert!(journald_persists_to_decoy_at(&RealFilesystem, root));
    }

    #[test]
    fn a_vendor_comment_is_the_default_hint_but_etc_comments_are_ignored() {
        // The vendor file's commented #Storage=auto documents a kept pre-259
        // default; built_in_default(>=259, this hint) then reads as auto (see
        // built_in_default_is_version_and_vendor_aware).
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "usr/lib/systemd/journald.conf",
            "[Journal]\n#Storage=auto\n#Compress=yes\n",
        );
        assert_eq!(
            vendor_storage_hint(&RealFilesystem, root),
            Some(JournaldStorage::Auto)
        );
        // A comment in /etc is never read as the default hint.
        write(
            root,
            "etc/systemd/journald.conf",
            "[Journal]\n#Storage=persistent\n",
        );
        assert_eq!(
            vendor_storage_hint(&RealFilesystem, root),
            Some(JournaldStorage::Auto)
        );
        // A real (non-comment) vendor assignment is an explicit setting, not a
        // hint, so it is not picked up as the commented default.
        write(
            root,
            "usr/lib/systemd/journald.conf",
            "[Journal]\nStorage=persistent\n",
        );
        assert_eq!(vendor_storage_hint(&RealFilesystem, root), None);
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
    fn the_journal_directory_is_judged_by_the_mount_a_lookup_reaches() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(MAIN, "[Journal]\nStorage=auto\n");
        fs.mock_set_path_type(DIR, PathKind::Dir);

        // A tmpfs stacked on the on-disk journal directory: the journal lands
        // in RAM.
        fs.mock_set_mount_table(
            "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
             40 1 8:1 /var/log/journal /var/log/journal rw - ext4 /dev/vda1 rw\n\
             41 40 0:50 / /var/log/journal rw - tmpfs tmpfs rw\n",
        );
        assert!(!journald_persists_to_decoy(&fs));

        // A tmpfs on the journal directory that a later mount on /var/log
        // covers: the journal lands on that disk.
        fs.mock_set_mount_table(
            "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
             41 1 0:50 / /var/log/journal rw - tmpfs tmpfs rw\n\
             42 1 8:2 / /var/log rw - ext4 /dev/vda2 rw\n",
        );
        assert!(journald_persists_to_decoy(&fs));
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

    /// A configuration NAILS cannot read as journald does persists, whatever
    /// its files set: from systemd 260 journald reads none of it, and its
    /// default is `persistent` from 259. The reason names the entry.
    #[test]
    fn an_unread_configuration_counts_as_persistent() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(MAIN, "[Journal]\nStorage=volatile\n");
        let entry = "/etc/systemd/journald.conf.d/50-x.conf";
        fs.mock_set_directory_contents(
            Path::new("/etc/systemd/journald.conf.d"),
            vec![std::path::PathBuf::from(entry)],
        );
        fs.mock_set_path_type(entry, PathKind::Dir);
        assert_eq!(effective_journald_storage(&fs), JournaldStorage::Persistent);
        assert!(journald_persists_to_decoy(&fs));
        assert_eq!(
            journald_persistence_at(&fs, Path::new("/")),
            Err(Unread {
                path: std::path::PathBuf::from(entry),
                cause: systemd_conf::UnreadCause::NotRegular,
            })
        );

        fs.mock_set_path_type(entry, PathKind::Missing);
        assert_eq!(journald_persistence_at(&fs, Path::new("/")), Ok(false));
    }
}
