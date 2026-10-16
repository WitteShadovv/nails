// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The journal search on the decoy: sudo's records of the operator's own
//! commands are reported as such, and what an entry means depends on whether
//! the journal keeps it in RAM or on disk.

use super::Verifier;
use crate::verify::journal::FakeJournalReader;
use crate::verify::{Finding, Severity, StateFileStatus, VerifyResult, VerifyStatus};
use crate::{MockFilesystem, RuntimeEnv};
use std::path::{Path, PathBuf};

/// sudo's record of the unlock the operator ran, with the padding sudo puts
/// before the user name.
const UNLOCK_RECORD: &str = "    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; \
                             COMMAND=/usr/bin/cryptsetup open /dev/sdb2 data";
/// sudo's record of a verify run, started without a terminal.
const VERIFY_RECORD: &str = "root : PWD=/ ; USER=root ; COMMAND=/mnt/hidden/nails verify --deep";

/// A deep scan of the decoy whose journal holds `entries`.
fn scan(fs: MockFilesystem, entries: &[&str], env: Option<RuntimeEnv>) -> VerifyResult {
    let config = crate::config::Config {
        hidden_volume_root: PathBuf::from("/mnt/hidden"),
        ..crate::config::Config::default()
    };
    let mut verifier = Verifier::with_config(fs, config, None, StateFileStatus::NotChecked)
        .with_journal_reader(Box::new(FakeJournalReader::with_entries(
            entries.iter().copied(),
        )));
    if let Some(env) = env {
        verifier = verifier.with_runtime_env(&env);
    }
    verifier.run(true).unwrap()
}

/// A decoy whose journald keeps its files on disk.
fn persistent_journal() -> MockFilesystem {
    let fs = MockFilesystem::new();
    let dir = Path::new("/var/log/journal");
    let machine = dir.join("0123456789abcdef0123456789abcdef");
    fs.mock_set_directory_contents(dir, vec![machine.clone()]);
    fs.mock_set_directory_contents(&machine, vec![machine.join("system.journal")]);
    fs
}

fn journal(result: &VerifyResult) -> Vec<&Finding> {
    result
        .findings
        .iter()
        .filter(|f| f.category == "journal")
        .collect()
}

fn guidance(finding: &Finding) -> &str {
    finding.fix_guidance.as_deref().unwrap_or_default()
}

#[test]
fn sudo_records_in_ram_are_notes_and_other_entries_warn() {
    let other = "systemd-cryptsetup[412]: Volume data unlocked";
    let result = scan(MockFilesystem::new(), &[UNLOCK_RECORD, other], None);

    let found = journal(&result);
    assert_eq!(found.len(), 2, "{found:#?}");
    let sudo = found
        .iter()
        .find(|f| f.message.contains("sudo record"))
        .expect("the unlock's sudo record");
    assert_eq!(sudo.severity, Severity::Info);
    assert_eq!(
        sudo.message,
        "Systemd journal has 1 sudo record referencing the backend unlock command \
         (\"cryptsetup\"): commands run with sudo"
    );
    assert!(guidance(sudo).starts_with("The journal is in RAM: a power-off removes"));
    // The sample drops sudo's padding.
    assert!(
        guidance(sudo).ends_with(&format!("Sample: {}", UNLOCK_RECORD.trim_start())),
        "{}",
        guidance(sudo)
    );

    let entry = found
        .iter()
        .find(|f| f.message.contains("1 entry"))
        .expect("the other entry");
    assert_eq!(entry.severity, Severity::Warn);
    assert!(
        entry
            .message
            .ends_with(": the decoy's own records or ones a hidden session left"),
        "{}",
        entry.message
    );
    assert!(
        found
            .iter()
            .all(|f| !f.message.contains("hidden-session trace"))
    );
    assert_eq!(result.status, VerifyStatus::Warning);
}

#[test]
fn a_run_started_with_sudo_can_be_clean_and_names_its_own_record() {
    let env = RuntimeEnv {
        sudo_user: Some("alice".to_string()),
        ..RuntimeEnv::default()
    };
    let result = scan(MockFilesystem::new(), &[VERIFY_RECORD], Some(env));

    let found = journal(&result);
    assert!(!found.is_empty());
    for finding in &found {
        assert_eq!(finding.severity, Severity::Info, "{finding:?}");
        assert!(
            finding
                .message
                .ends_with(": commands run with sudo, this verify run included"),
            "{}",
            finding.message
        );
    }
    assert_eq!(
        result.status,
        VerifyStatus::Secure,
        "{:#?}",
        result.findings
    );
}

#[test]
fn entries_a_persistent_journal_keeps_on_disk_warn() {
    let result = scan(persistent_journal(), &[UNLOCK_RECORD], None);

    let found = journal(&result);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(found[0].severity, Severity::Warn);
    assert!(
        found[0].message.contains("1 sudo record"),
        "{}",
        found[0].message
    );
    let text = guidance(found[0]);
    assert!(text.contains("outlast a power-off"), "{text}");
    assert!(text.contains("Storage=volatile"), "{text}");
    assert_eq!(result.status, VerifyStatus::Warning);
}

#[test]
fn a_journal_directory_on_tmpfs_is_in_ram() {
    let fs = persistent_journal();
    fs.mock_set_filesystem_type(Path::new("/var/log/journal"), "tmpfs");
    let result = scan(fs, &[UNLOCK_RECORD], None);

    let found = journal(&result);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(found[0].severity, Severity::Info);
    assert!(guidance(found[0]).contains("in RAM"));
}

#[test]
fn a_journal_directory_without_journal_files_is_in_ram() {
    let fs = MockFilesystem::new();
    let dir = Path::new("/var/log/journal");
    fs.mock_set_directory_contents(dir, vec![dir.join("README")]);
    let result = scan(fs, &[UNLOCK_RECORD], None);

    assert_eq!(journal(&result)[0].severity, Severity::Info);
}

#[test]
fn a_record_without_sudos_fields_is_no_sudo_record() {
    // The command field alone, or sudo's session lines, do not make a record
    // of a command: only "USER=" and "COMMAND=" together do.
    let result = scan(
        MockFilesystem::new(),
        &["sudo[123]: root : COMMAND=/mnt/hidden/control nails activate"],
        None,
    );

    let found = journal(&result);
    assert!(!found.is_empty());
    assert!(
        found
            .iter()
            .all(|f| f.severity == Severity::Warn && !f.message.contains("sudo record")),
        "{found:#?}"
    );
}
