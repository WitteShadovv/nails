// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A verify run inside the hidden session. The live root is the session's
//! overlay, so its own files, its state and its journal must not read as
//! residue on the decoy, while a real decoy trace still does.

use super::Verifier;
use crate::MockFilesystem;
use crate::config::Config;
use crate::filesystem::PathKind;
use crate::state::StateFile;
use crate::verify::journal::FakeJournalReader;
use crate::verify::{Finding, Severity, StateFileStatus, VerifyResult, VerifyStatus};
use crate::{RealFilesystem, SystemState};
use nails_teardown::whole_root::plan::{PLAN_VERSION, Plan};
use std::path::{Path, PathBuf};

const HIDDEN: &str = "/mnt/hidden";
const UPPER: &str = "/mnt/hidden/root/upper";
/// The link `nails init` stages for the hidden NixOS module, as the live root
/// of the session shows it.
const STAGED_LINK: &str = "/etc/nixos/nails/configuration.nix";
/// The udev rule the entry installs when the disks the session does not use
/// are read-only.
const READ_ONLY_RULE: &str = "/run/udev/rules.d/60-overlay-runtime.rules";

/// `/` as a root overlay with its upper at `upper`, and the hidden volume.
fn mountinfo(upper: &str) -> String {
    format!(
        "1 0 0:40 / / rw - overlay overlay rw,lowerdir=/run/decoy,upperdir={upper},\
         workdir=/mnt/hidden/root/work\n\
         2 1 254:0 / /mnt/hidden rw - ext4 /dev/mapper/data rw\n"
    )
}

/// The session plan the entry writes, for the root overlay at [`UPPER`].
fn plan_json(read_only_disks: bool) -> String {
    let json = format!(
        r#"{{"version":{PLAN_VERSION},"hidden_root":"{HIDDEN}","upper":"{UPPER}","work":"{HIDDEN}/root/work","decoy_root":{{"source":"/dev/vda2","fstype":"ext4"}},"decoy":{{"init":"/sbin/init"}},"hidden":{{"init":"/sbin/init"}},"read_only_disks":{read_only_disks}}}"#
    );
    Plan::from_json(&json).expect("the fixture is a valid plan");
    json
}

/// A hidden session as `activate` leaves it: the overlay root, the plan and
/// the runtime directory, and the mounted hidden volume with its config and
/// state file. `plan` is the plan's read-only-disks flag, or no plan.
fn session_fs(plan: Option<bool>) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/proc/self/mountinfo", &mountinfo(UPPER));
    if let Some(read_only_disks) = plan {
        fs.mock_add_file(
            "/run/overlay-runtime/plan.json",
            &plan_json(read_only_disks),
        );
    }
    fs.mock_set_path_type("/run/overlay-runtime", PathKind::Dir);
    fs.mock_set_path_type(HIDDEN, PathKind::Dir);
    fs.mock_set_path_exists("/mnt/hidden/config/nails.toml", true);
    fs.mock_set_path_exists("/mnt/hidden/state.json", true);
    fs
}

/// Stage the link to the hidden module the way `nails init` does: in the
/// upper, which the live root shows. Without `in_upper` the live root shows a
/// link the upper does not hold, so it comes from the decoy beneath.
fn stage_link(fs: &MockFilesystem, in_upper: bool) {
    fs.mock_set_is_symlink(STAGED_LINK, true);
    if in_upper {
        fs.mock_set_is_symlink(&format!("{UPPER}{STAGED_LINK}"), true);
    }
}

fn config() -> Config {
    Config {
        hidden_volume_root: PathBuf::from(HIDDEN),
        state_file_path: PathBuf::from("/mnt/hidden/state.json"),
        ..Config::default()
    }
}

/// A verifier over `fs` whose state file records an active session.
fn verifier_with(fs: &MockFilesystem, config: Config) -> Verifier<MockFilesystem> {
    let state = StateFile {
        state: SystemState::Active {
            activated_at: chrono::Utc::now(),
        },
        ..StateFile::default()
    };
    let status = StateFileStatus::Present {
        path: config.state_file_path.clone(),
        state: "active".to_string(),
    };
    Verifier::with_config(fs.clone(), config, Some(state), status)
        .with_journal_reader(Box::new(FakeJournalReader::default()))
}

fn session_verifier(fs: &MockFilesystem) -> Verifier<MockFilesystem> {
    verifier_with(fs, config())
}

/// Whether the run said it is inside the hidden session.
fn has_session_note(result: &VerifyResult) -> bool {
    result
        .findings
        .iter()
        .any(|f| f.category == "session" && f.severity == Severity::Info)
}

/// The artifact finding for exactly `path`.
fn artifact<'a>(result: &'a VerifyResult, path: &str) -> Option<&'a Finding> {
    let message = format!("Artifact file found: {path}");
    result.findings.iter().find(|f| f.message == message)
}

#[test]
fn an_init_seeded_session_reports_its_own_files_as_notes_and_nothing_critical() {
    let fs = session_fs(Some(false));
    stage_link(&fs, true);
    let reader = FakeJournalReader::with_entries([
        "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/run/wrappers/bin/mount \
         /dev/mapper/data /mnt/hidden",
        "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/mnt/hidden/nails verify --deep",
    ]);
    let result = session_verifier(&fs)
        .with_journal_reader(Box::new(reader))
        .run(true)
        .unwrap();

    assert_eq!(
        result.status,
        VerifyStatus::Secure,
        "{:#?}",
        result.findings
    );
    let link = artifact(&result, STAGED_LINK).expect("the staged link is reported");
    assert_eq!(link.severity, Severity::Info);
    let guidance = link.fix_guidance.as_deref().unwrap();
    assert!(
        guidance.contains(&format!("{UPPER}{STAGED_LINK}")),
        "{guidance}"
    );
    assert!(guidance.contains("verify --offline --root"), "{guidance}");
    assert!(!guidance.contains("rm -rf"), "{guidance}");
    // The registry's entry for the staged module source names the same link
    // on the hidden root.
    let source = artifact(&result, &format!("{UPPER}{STAGED_LINK}")).expect("module source");
    assert_eq!(source.severity, Severity::Info);

    for own in [
        "/run/overlay-runtime",
        "records an active session",
        "Hidden volume path is accessible",
        "State file exists",
    ] {
        assert!(
            !result.findings.iter().any(|f| f.message.contains(own)),
            "{own}: {:#?}",
            result.findings
        );
    }
    let session: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "session")
        .collect();
    assert_eq!(session.len(), 1, "{session:?}");
    assert_eq!(session[0].severity, Severity::Info);

    let journal: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "journal")
        .collect();
    assert_eq!(journal.len(), 2, "{journal:#?}");
    for finding in journal {
        assert_eq!(finding.severity, Severity::Info, "{finding:?}");
        assert!(
            finding
                .message
                .starts_with("The running session's journal has ")
                && finding.message.contains(" sudo record"),
            "{}",
            finding.message
        );
        assert!(
            finding.fix_guidance.as_deref().unwrap().contains("in RAM"),
            "{finding:?}"
        );
    }
}

#[test]
fn in_the_session_entries_a_persistent_journal_keeps_warn() {
    let fs = session_fs(Some(false));
    let dir = Path::new("/var/log/journal");
    let machine = dir.join("0123456789abcdef0123456789abcdef");
    fs.mock_set_directory_contents(dir, vec![machine.clone()]);
    fs.mock_set_directory_contents(&machine, vec![machine.join("system.journal")]);
    let reader = FakeJournalReader::with_entries([
        "root : PWD=/ ; USER=root ; COMMAND=/mnt/hidden/nails activate",
    ]);
    let result = session_verifier(&fs)
        .with_journal_reader(Box::new(reader))
        .run(true)
        .unwrap();

    let journal: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == "journal")
        .collect();
    assert!(!journal.is_empty());
    for finding in journal {
        assert_eq!(finding.severity, Severity::Warn, "{finding:?}");
        let guidance = finding.fix_guidance.as_deref().unwrap();
        assert!(guidance.contains("can be on the decoy disk"), "{guidance}");
        assert!(guidance.contains("On the decoy, vacuum"), "{guidance}");
    }
    assert_eq!(result.status, VerifyStatus::Warning);
}

#[test]
fn a_decoy_path_the_upper_does_not_hold_is_a_decoy_trace_with_no_rm_advice() {
    let fs = session_fs(Some(false));
    stage_link(&fs, false);
    let result = session_verifier(&fs).run(false).unwrap();

    let link = artifact(&result, STAGED_LINK).expect("the decoy's link is reported");
    assert_eq!(link.severity, Severity::Critical);
    let guidance = link.fix_guidance.as_deref().unwrap();
    assert!(
        guidance.contains("Trace on the decoy filesystem"),
        "{guidance}"
    );
    assert!(
        guidance.contains("only hides it in the hidden layer"),
        "{guidance}"
    );
    assert!(guidance.contains("verify --offline --root"), "{guidance}");
    assert!(!guidance.contains("rm -rf"), "{guidance}");
    assert_eq!(result.status, VerifyStatus::Critical);
}

#[test]
fn in_the_session_only_its_own_runtime_paths_are_skipped() {
    let fs = session_fs(Some(false));
    // Earlier builds' fixed runtime paths come from the decoy's /run.
    fs.mock_set_path_exists("/run/nails", true);
    fs.mock_set_path_exists("/run/nails-pivot", true);
    let result = session_verifier(&fs).run(false).unwrap();

    assert!(artifact(&result, "/run/overlay-runtime").is_none());
    for legacy in ["/run/nails", "/run/nails-pivot"] {
        let finding = artifact(&result, legacy).unwrap_or_else(|| panic!("{legacy} is reported"));
        assert_eq!(finding.severity, Severity::Warn);
    }
}

#[test]
fn the_read_only_rule_is_the_sessions_own_only_when_the_entry_installed_it() {
    let installed = session_fs(Some(true));
    installed.mock_set_path_exists(READ_ONLY_RULE, true);
    let result = session_verifier(&installed).run(false).unwrap();
    assert!(
        artifact(&result, READ_ONLY_RULE).is_none(),
        "{:#?}",
        result.findings
    );

    let leftover = session_fs(Some(false));
    leftover.mock_set_path_exists(READ_ONLY_RULE, true);
    let result = session_verifier(&leftover).run(false).unwrap();
    let rule = artifact(&result, READ_ONLY_RULE).expect("a rule the entry did not install");
    assert_eq!(rule.severity, Severity::Warn);
}

#[test]
fn without_a_plan_the_upper_comes_from_the_mount_table() {
    // No readable plan: the root overlay's upper on the hidden volume marks
    // the session, and that upper (not a fixed path) holds the link.
    let upper = "/mnt/hidden/layers/upper";
    let fs = MockFilesystem::new();
    fs.mock_add_file("/proc/self/mountinfo", &mountinfo(upper));
    fs.mock_set_is_symlink(STAGED_LINK, true);
    fs.mock_set_is_symlink(&format!("{upper}{STAGED_LINK}"), true);
    fs.mock_set_path_exists(READ_ONLY_RULE, true);
    let mut settings = config();
    settings.session_mounts.read_only = true;
    let result = verifier_with(&fs, settings).run(false).unwrap();

    let link = artifact(&result, STAGED_LINK).expect("the staged link is reported");
    assert_eq!(link.severity, Severity::Info, "{link:?}");
    assert!(
        artifact(&result, READ_ONLY_RULE).is_none(),
        "{:#?}",
        result.findings
    );
    assert!(has_session_note(&result), "{:#?}", result.findings);
}

#[test]
fn an_overlay_root_that_is_not_the_hidden_session_keeps_the_decoy_findings() {
    // An overlay root whose upper is neither the plan's nor on the hidden
    // volume (a container, a live system) is no hidden session.
    let fs = session_fs(None);
    fs.mock_add_file("/proc/self/mountinfo", &mountinfo("/var/lib/other/upper"));
    stage_link(&fs, false);
    let result = session_verifier(&fs).run(false).unwrap();

    assert!(!has_session_note(&result), "{:#?}", result.findings);
    let link = artifact(&result, STAGED_LINK).expect("the link is reported");
    assert_eq!(link.severity, Severity::Critical);
    assert!(link.fix_guidance.as_deref().unwrap().contains("rm -rf"));
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.category == "state" && f.message.contains("records an active session")),
        "{:#?}",
        result.findings
    );
}

/// On the decoy, an interrupted activation's runtime directory is one
/// critical finding that says to run `nails recover`, not a second one that
/// says to deactivate, which the decoy refuses. A runtime file nothing else
/// reports keeps its own finding, with advice that removes it: `nails
/// recover` leaves the read-only rule and an earlier release's paths alone.
#[test]
fn a_runtime_leftover_on_the_decoy_is_reported_once_and_points_at_recover() {
    let fs = session_fs(Some(false));
    fs.mock_add_file(
        "/proc/self/mountinfo",
        "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n2 1 254:0 / /mnt/hidden rw - ext4 /dev/mapper/data rw\n",
    );
    fs.mock_set_path_exists(READ_ONLY_RULE, true);
    fs.mock_set_path_exists("/run/nails-pivot", true);
    let result = session_verifier(&fs).run(false).unwrap();

    assert!(!has_session_note(&result), "{:#?}", result.findings);
    let about_runtime: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| f.message.contains("/run/overlay-runtime"))
        .collect();
    assert_eq!(about_runtime.len(), 1, "{about_runtime:#?}");
    assert_eq!(about_runtime[0].severity, Severity::Critical);
    assert!(
        about_runtime[0]
            .fix_guidance
            .as_deref()
            .is_some_and(|fix| fix.contains("sudo ") && fix.contains("recover")),
        "{about_runtime:#?}"
    );
    let rule = artifact(&result, READ_ONLY_RULE).expect("the rule is reported");
    let fix = rule.fix_guidance.as_deref().unwrap();
    assert!(
        fix.contains("power off, or remove it as root: rm /run/udev/rules.d/"),
        "{fix}"
    );
    assert!(
        !fix.contains("recover") && !fix.contains("deactivate"),
        "{fix}"
    );
    let legacy = artifact(&result, "/run/nails-pivot").expect("the old path is reported");
    let fix = legacy.fix_guidance.as_deref().unwrap();
    assert!(
        fix.contains("earlier release") && fix.contains("power off"),
        "{fix}"
    );
    assert!(!fix.contains("recover"), "{fix}");
}

#[test]
fn a_plan_for_another_upper_does_not_make_a_session() {
    let fs = session_fs(Some(false));
    fs.mock_add_file("/proc/self/mountinfo", &mountinfo("/var/lib/other/upper"));
    let result = session_verifier(&fs).run(false).unwrap();
    assert!(!has_session_note(&result), "{:#?}", result.findings);
}

#[test]
fn an_offline_scan_finds_a_dangling_link_at_a_decoy_path() {
    // The leaked link points at the hidden volume, which does not resolve under
    // the image root: lstat still finds it, where following it would not.
    let root = tempfile::tempdir().unwrap();
    let link = root.path().join("etc/nixos/nails/configuration.nix");
    std::fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink("/mnt/data/config/nixos/configuration.nix", &link).unwrap();
    assert!(!link.exists() && link.is_symlink());

    let result = Verifier::new(RealFilesystem)
        .offline_under(root.path().to_path_buf())
        .run(false)
        .unwrap();

    let finding = artifact(&result, STAGED_LINK).expect("the dangling link is reported");
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(result.status, VerifyStatus::Critical);
}
