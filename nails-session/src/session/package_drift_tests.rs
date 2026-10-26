// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::filesystem::{MockFilesystem, PathKind};
use crate::session::layout::Layout;
use nails_base::packages::dpkg::State;
use std::time::{Duration, SystemTime};

// ---------------------------------------------------------------------------
// the judges
// ---------------------------------------------------------------------------

fn deb(name: &str, arch: Option<&str>, version: &str) -> dpkg::Package {
    dpkg::Package {
        name: name.to_string(),
        architecture: arch.map(str::to_string),
        version: Some(version.to_string()),
        state: Some(State::Installed),
    }
}

fn changed(owners: &[(&str, Option<&str>)]) -> BTreeSet<(String, Option<String>)> {
    owners
        .iter()
        .map(|(name, arch)| (name.to_string(), arch.map(str::to_string)))
        .collect()
}

fn change(name: &str, decoy: Option<&str>, hidden: Option<&str>) -> Change {
    Change {
        name: name.to_string(),
        decoy: decoy.map(str::to_string),
        hidden: hidden.map(str::to_string),
    }
}

/// The decoy's record: libc6 for two architectures, an SSH client and a
/// removed logger.
fn decoy_record() -> Vec<dpkg::Package> {
    let mut rsyslog = deb("rsyslog", Some("amd64"), "8.2504.0-1");
    rsyslog.state = Some(State::ConfigFiles);
    vec![
        deb("libc6", Some("amd64"), "2.41-12"),
        deb("libc6", Some("i386"), "2.41-12"),
        deb("openssh-client", Some("amd64"), "1:10.0p1-7"),
        rsyslog,
    ]
}

#[test]
fn a_copy_that_matches_the_decoys_record_follows_it() {
    let verdict = judge_dpkg(&decoy_record(), &decoy_record(), &changed(&[]));
    assert_eq!(verdict, Verdict::Follows { own: Some(0) });
}

#[test]
fn a_package_the_decoy_changed_since_the_copy_drifted() {
    let mut hidden = decoy_record();
    // The copy was made before the decoy updated the SSH client, installed
    // curl and removed rsyslog.
    hidden[2].version = Some("1:10.0p1-5".to_string());
    hidden[3].state = Some(State::Installed);
    let mut decoy = decoy_record();
    decoy.push(deb("curl", Some("amd64"), "8.14.1-2"));

    let verdict = judge_dpkg(&decoy, &hidden, &changed(&[]));
    assert_eq!(
        verdict,
        Verdict::Drifted(Drift::Stale(vec![
            change("curl", Some("8.14.1-2"), None),
            change("openssh-client", Some("1:10.0p1-7"), Some("1:10.0p1-5")),
            change("rsyslog", None, Some("8.2504.0-1")),
        ]))
    );
}

#[test]
fn a_package_a_hidden_session_changed_itself_is_its_own() {
    let mut hidden = decoy_record();
    // A hidden session installed the Tor Browser launcher, updated the SSH
    // client and purged libc6:i386, each leaving files (or their deletions)
    // in the upper's info directory.
    hidden.push(deb("torbrowser-launcher", Some("amd64"), "0.3.7-3"));
    hidden[2].version = Some("1:10.0p1-8".to_string());
    hidden.remove(1);
    let owners = changed(&[
        ("torbrowser-launcher", None),
        ("openssh-client", None),
        ("libc6", Some("i386")),
    ]);
    assert_eq!(
        judge_dpkg(&decoy_record(), &hidden, &owners),
        Verdict::Follows { own: Some(3) }
    );
}

#[test]
fn an_architecture_is_named_where_the_record_has_several() {
    // The decoy updated libc6 for both architectures; a hidden session had
    // changed only the i386 one, which is therefore its own.
    let hidden = decoy_record();
    let mut decoy = decoy_record();
    decoy[0].version = Some("2.41-13".to_string());
    decoy[1].version = Some("2.41-13".to_string());
    let verdict = judge_dpkg(&decoy, &hidden, &changed(&[("libc6", Some("i386"))]));
    assert_eq!(
        verdict,
        Verdict::Drifted(Drift::Stale(vec![change(
            "libc6:amd64",
            Some("2.41-13"),
            Some("2.41-12")
        )]))
    );
    // An info file without an architecture is the package's for each.
    let verdict = judge_dpkg(&decoy, &hidden, &changed(&[("libc6", None)]));
    assert_eq!(verdict, Verdict::Follows { own: Some(2) });
}

#[test]
fn only_packages_with_their_files_on_disk_count() {
    // Both sides have rsyslog removed with its configuration kept, at
    // different versions, and the SSH client in different installed states
    // at one version: nothing differs that a package manager acts on.
    let mut hidden = decoy_record();
    hidden[3].version = Some("8.2402.0-1".to_string());
    hidden[2].state = Some(State::TriggersPending);
    assert_eq!(
        judge_dpkg(&decoy_record(), &hidden, &changed(&[])),
        Verdict::Follows { own: Some(0) }
    );
}

fn arch(name: &str, version: &str) -> pacman::Package {
    pacman::Package {
        name: name.to_string(),
        version: version.to_string(),
    }
}

/// The decoy's pacman database.
fn decoy_local() -> Vec<pacman::Package> {
    vec![
        arch("firefox", "131.0-1"),
        arch("glibc", "2.42+r17-1"),
        arch("linux", "6.17.1.arch1-1"),
    ]
}

#[test]
fn no_entry_of_hidden_sessions_shares_the_decoys_database() {
    assert_eq!(judge_pacman(&decoy_local(), &[], &[]), Verdict::Shared);
}

#[test]
fn packages_only_hidden_sessions_changed_are_their_own() {
    // A hidden session installed tor and updated firefox.
    let kept = [arch("tor", "0.4.8.17-1"), arch("firefox", "132.0-1")];
    let removed = [arch("firefox", "131.0-1")];
    assert_eq!(
        judge_pacman(&decoy_local(), &kept, &removed),
        Verdict::Follows { own: Some(2) }
    );
}

#[test]
fn a_package_both_changed_is_listed_twice() {
    // A hidden session updated firefox to 132.0-1; the decoy then updated it
    // to 133.0-1, and installed tor after a hidden session had.
    let mut decoy = decoy_local();
    decoy[0] = arch("firefox", "133.0-1");
    decoy.push(arch("tor", "0.4.8.18-1"));
    let kept = [arch("firefox", "132.0-1"), arch("tor", "0.4.8.17-1")];
    let removed = [arch("firefox", "131.0-1")];
    assert_eq!(
        judge_pacman(&decoy, &kept, &removed),
        Verdict::Drifted(Drift::Merged {
            twice: vec![
                change("firefox", Some("133.0-1"), Some("132.0-1")),
                change("tor", Some("0.4.8.18-1"), Some("0.4.8.17-1")),
            ],
            removed: vec![],
        })
    );
}

#[test]
fn the_same_update_on_both_sides_is_one_entry() {
    let mut decoy = decoy_local();
    decoy[0] = arch("firefox", "132.0-1");
    let kept = [arch("firefox", "132.0-1")];
    let removed = [arch("firefox", "131.0-1")];
    assert_eq!(
        judge_pacman(&decoy, &kept, &removed),
        Verdict::Follows { own: Some(1) }
    );
}

#[test]
fn a_package_hidden_sessions_removed_and_the_decoy_changed_is_listed_without_its_files() {
    let mut decoy = decoy_local();
    decoy[0] = arch("firefox", "133.0-1");
    let removed = [arch("firefox", "131.0-1")];
    assert_eq!(
        judge_pacman(&decoy, &[], &removed),
        Verdict::Drifted(Drift::Merged {
            twice: vec![],
            removed: vec![change("firefox", Some("133.0-1"), None)],
        })
    );
    // Removed and left alone on the decoy, it is gone in hidden sessions.
    assert_eq!(
        judge_pacman(&decoy_local(), &[], &removed),
        Verdict::Follows { own: Some(1) }
    );
}

fn stamp(size: u64, seconds: u64) -> rpm::Stamp {
    rpm::Stamp {
        size,
        modified: SystemTime::UNIX_EPOCH + Duration::from_secs(seconds),
    }
}

#[test]
fn a_count_of_packages_reads_as_words() {
    assert_eq!(packages(0), "0 packages");
    assert_eq!(packages(1), "1 package");
    assert_eq!(packages(2), "2 packages");
}

#[test]
fn rpms_copy_drifted_when_the_decoys_database_was_written_after_it() {
    assert_eq!(
        judge_rpm(stamp(4096, 200), stamp(4096, 100)),
        Verdict::Drifted(Drift::Older)
    );
    // The same time with another size cannot be the same database.
    assert_eq!(
        judge_rpm(stamp(8192, 100), stamp(4096, 100)),
        Verdict::Drifted(Drift::Older)
    );
    // A copy written later, or unchanged since it was made, follows.
    for hidden in [stamp(8192, 300), stamp(4096, 200)] {
        assert_eq!(
            judge_rpm(stamp(4096, 200), hidden),
            Verdict::Follows { own: None }
        );
    }
}

// ---------------------------------------------------------------------------
// reading, the row and the advisory
// ---------------------------------------------------------------------------

const ROOT: &str = "/decoy";
const HIDDEN: &str = "/mnt/data";
const UPPER: &str = "/mnt/data/root/upper";

/// A dpkg status file of `packages` (name, version), all installed.
fn status(packages: &[(&str, &str)]) -> String {
    packages
        .iter()
        .map(|(name, version)| {
            format!(
                "Package: {name}\nStatus: install ok installed\nArchitecture: amd64\n\
                 Version: {version}\nDescription: {name}\n a package\n"
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A decoy with dpkg's `decoy` record and hidden sessions with `hidden`'s
/// copy of it, when given, in the root upper.
fn debian(decoy: &str, hidden: Option<&str>) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_add_file(&format!("{ROOT}/var/lib/dpkg/status"), decoy);
    if let Some(hidden) = hidden {
        fs.mock_add_file(&format!("{UPPER}/var/lib/dpkg/status"), hidden);
    }
    fs
}

fn check() -> PackageDriftCheck {
    PackageDriftCheck::new(PathBuf::from(ROOT), PathBuf::from(HIDDEN)).as_privileged(true)
}

fn run(check: &PackageDriftCheck, fs: &MockFilesystem) -> CheckResult {
    PreFlightCheck::<MockFilesystem>::run(check, fs).unwrap()
}

#[test]
fn a_decoy_without_a_package_database_passes() {
    let result = run(&check(), &MockFilesystem::new());
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        result.message(),
        "the decoy keeps no dpkg, pacman or rpm package database"
    );
}

#[test]
fn hidden_sessions_without_a_copy_see_the_decoys_record() {
    let fs = debian(&status(&[("libc6", "2.41-12")]), None);
    let result = run(&check(), &fs);
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        result.message(),
        "hidden sessions see the decoy's own dpkg package database (/var/lib/dpkg/status)"
    );
    // Without root nothing needs reading for that.
    let result = run(&check().as_privileged(false), &fs);
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn a_copy_that_lags_behind_the_decoy_warns_with_the_packages_and_the_fix() {
    let fs = debian(
        &status(&[("libc6", "2.41-13"), ("curl", "8.14.1-2")]),
        Some(&status(&[("libc6", "2.41-12"), ("tor", "0.4.8.17-1")])),
    );
    let info = format!("{UPPER}/var/lib/dpkg/info");
    fs.mock_set_directory_contents(
        Path::new(&info),
        vec![
            Path::new(&info).join("tor.list"),
            Path::new(&info).join("tor.md5sums"),
            Path::new(&info).join("format"),
        ],
    );
    let result = run(&check(), &fs);
    assert!(result.is_warn(), "{result:?}");
    let message = result.message();
    assert!(
        message.starts_with(
            "the decoy installed, updated or removed 2 packages since hidden sessions made \
             their own copy of the dpkg package database (/var/lib/dpkg/status), which still \
             records them as they were: curl (8.14.1-2 on the decoy, not in hidden sessions), \
             libc6 (2.41-13 on the decoy, 2.41-12 in hidden sessions)\n"
        ),
        "{message}"
    );
    assert!(message.contains("`sudo apt-get full-upgrade`"), "{message}");
    assert!(message.contains(GUIDE), "{message}");
    assert!(!message.contains("tor ("), "its own package: {message}");
}

#[test]
fn a_copy_without_root_cannot_be_judged() {
    let fs = debian(
        &status(&[("libc6", "2.41-13")]),
        Some(&status(&[("libc6", "2.41-12")])),
    );
    let result = run(&check().as_privileged(false), &fs);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().starts_with(
            "could not tell whether hidden sessions' copy of the dpkg package database \
             (/var/lib/dpkg/status) follows the decoy's: only root reads"
        ),
        "{result:?}"
    );
    assert!(
        result.message().ends_with(&format!(
            "\nRun `{}` to see it.",
            sudo_line(NextStep::Check)
        )),
        "{result:?}"
    );
}

#[test]
fn a_deleted_or_replaced_record_warns_with_the_discard_that_brings_it_back() {
    for (setup, path, what) in [
        ("whiteout", "/var/lib/dpkg/status", "deleted"),
        ("directory", "/var/lib/dpkg/status", "replaced"),
        ("link", "/var/lib/dpkg", "replaced"),
        ("file", "/var/lib", "replaced"),
    ] {
        let fs = debian(&status(&[("libc6", "2.41-12")]), None);
        let upper = |rel: &str| format!("{UPPER}{rel}");
        match setup {
            "whiteout" => fs.mock_set_whiteout(&upper(path)),
            "directory" => fs.mock_set_path_type(&upper(path), PathKind::Dir),
            "link" => fs.mock_set_path_type(&upper(path), PathKind::Symlink),
            _ => fs.mock_set_path_type(&upper(path), PathKind::File),
        }
        let result = run(&check(), &fs);
        assert!(result.is_warn(), "{setup}: {result:?}");
        assert!(
            result.message().starts_with(&format!(
                "a hidden session {what} {path}, so hidden sessions"
            )),
            "{setup}: {result:?}"
        );
        let line = sudo_line_for(NextStep::Discard, path);
        assert!(
            result.message().contains(&format!("`{line}`")),
            "{result:?}"
        );

        let allowed = check().allowing_decoy_storage(true);
        let line = sudo_line_for(NextStep::Discard, &format!("--allow-decoy-storage {path}"));
        let result = run(&allowed, &fs);
        assert!(
            result.message().contains(&format!("`{line}`")),
            "{result:?}"
        );
    }
}

#[test]
fn a_link_on_the_way_on_the_decoy_is_not_followed() {
    let fs = debian(&status(&[("libc6", "2.41-12")]), None);
    fs.mock_set_path_type(&format!("{ROOT}/var/lib/dpkg"), PathKind::Symlink);
    let result = run(&check(), &fs);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result
            .message()
            .ends_with("/var/lib/dpkg on the decoy is a symbolic link"),
        "{result:?}"
    );
}

#[test]
fn a_record_on_a_decoy_filesystem_of_its_own_is_judged_against_its_upper() {
    let fs = debian(
        &status(&[("libc6", "2.41-13")]),
        // A copy in the root upper is not what hidden sessions see.
        Some(&status(&[("libc6", "2.41-12")])),
    );
    fs.mock_set_mount_table(
        "1 0 8:2 / /decoy rw - ext4 /dev/vda2 rw\n2 1 8:3 / /decoy/var rw - ext4 /dev/vda3 rw\n",
    );
    let result = run(&check(), &fs);
    assert!(result.is_pass(), "{result:?}");
    assert!(result.message().contains("decoy's own"), "{result:?}");

    // The /var filesystem's upper holds hidden sessions' copy.
    fs.mock_add_file(
        "/mnt/data/root/mounts/var/upper/lib/dpkg/status",
        &status(&[("libc6", "2.41-11")]),
    );
    let result = run(&check(), &fs);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result
            .message()
            .contains("libc6 (2.41-13 on the decoy, 2.41-11 in hidden sessions)"),
        "{result:?}"
    );
}

#[test]
fn a_root_alone_in_the_mount_table_keeps_the_copy_in_the_root_upper() {
    let fs = debian(
        &status(&[("libc6", "2.41-13")]),
        Some(&status(&[("libc6", "2.41-12")])),
    );
    fs.mock_set_mount_table("1 0 8:2 / /decoy rw - ext4 /dev/vda2 rw\n");
    let result = run(&check(), &fs);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result
            .message()
            .contains("libc6 (2.41-13 on the decoy, 2.41-12 in hidden sessions)"),
        "{result:?}"
    );
}

#[test]
fn a_copy_that_follows_says_how_many_packages_are_hidden_sessions_own() {
    let decoy = status(&[("libc6", "2.41-12")]);
    let fs = debian(&decoy, Some(&decoy));
    let result = run(&check(), &fs);
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        result.message(),
        "hidden sessions keep their own copy of the dpkg package database \
         (/var/lib/dpkg/status), which follows the decoy's"
    );

    let fs = debian(
        &decoy,
        Some(&status(&[
            ("libc6", "2.41-12"),
            ("tor", "0.4.8.17-1"),
            ("torsocks", "2.4.0-1"),
        ])),
    );
    let info = PathBuf::from(format!("{UPPER}/var/lib/dpkg/info"));
    fs.mock_set_directory_contents(
        &info,
        vec![info.join("tor.list"), info.join("torsocks.list")],
    );
    let result = run(&check(), &fs);
    assert!(result.is_pass(), "{result:?}");
    assert!(
        result
            .message()
            .ends_with("which follows the decoy's but for the 2 packages they changed themselves"),
        "{result:?}"
    );
}

#[test]
fn one_fix_is_named_once_for_every_database_that_needs_it() {
    let fs = debian(
        &status(&[("libc6", "2.41-13")]),
        Some(&status(&[("libc6", "2.41-12")])),
    );
    let local = PathBuf::from(format!("{ROOT}/var/lib/pacman/local"));
    fs.mock_set_path_type(&local.display().to_string(), PathKind::Dir);
    fs.mock_set_directory_contents(&local, vec![local.join("firefox-131.0-1")]);
    let upper = PathBuf::from(format!("{UPPER}/var/lib/pacman/local"));
    fs.mock_set_path_type(&upper.display().to_string(), PathKind::Dir);
    fs.mock_set_directory_contents(&upper, vec![upper.join("tor-0.4.8.17-1")]);

    let result = run(&check().as_privileged(false), &fs);
    assert!(result.is_warn(), "{result:?}");
    let sudo = format!("Run `{}` to see it.", sudo_line(NextStep::Check));
    assert_eq!(result.message().matches("could not tell").count(), 2);
    assert_eq!(result.message().matches(&sudo).count(), 1, "{result:?}");
    assert!(
        result.message().ends_with(&format!("\n{sudo}")),
        "{result:?}"
    );
}

#[test]
fn an_unreadable_record_cannot_be_judged() {
    let fs = debian(&status(&[("libc6", "2.41-13")]), Some(""));
    fs.mock_set_file_size(
        &format!("{ROOT}/var/lib/dpkg/status"),
        nails_base::packages::READ_LIMIT + 1,
    );
    let result = run(&check(), &fs);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result
            .message()
            .contains("/var/lib/dpkg/status on the decoy cannot be read"),
        "{result:?}"
    );
}

/// A decoy with pacman's `decoy` entries, and hidden sessions with `kept`
/// entries and the `removed` ones deleted in the root upper.
fn arch_linux(decoy: &[&str], kept: &[&str], removed: &[&str]) -> MockFilesystem {
    let fs = MockFilesystem::new();
    let local = PathBuf::from(format!("{ROOT}/var/lib/pacman/local"));
    fs.mock_set_path_type(&local.display().to_string(), PathKind::Dir);
    fs.mock_set_directory_contents(&local, decoy.iter().map(|e| local.join(e)).collect());
    if !kept.is_empty() || !removed.is_empty() {
        let upper = PathBuf::from(format!("{UPPER}/var/lib/pacman/local"));
        fs.mock_set_path_type(&upper.display().to_string(), PathKind::Dir);
        for entry in removed {
            fs.mock_set_whiteout(&upper.join(entry).display().to_string());
        }
        fs.mock_set_directory_contents(
            &upper,
            kept.iter().chain(removed).map(|e| upper.join(e)).collect(),
        );
    }
    fs
}

#[test]
fn pacman_entries_both_sides_changed_warn_with_the_reinstall() {
    let fs = arch_linux(
        &["firefox-133.0-1", "linux-6.17.1.arch1-1", "ALPM_DB_VERSION"],
        &["firefox-132.0-1"],
        &["firefox-131.0-1"],
    );
    let result = run(&check(), &fs);
    assert!(result.is_warn(), "{result:?}");
    let message = result.message();
    assert!(
        message.starts_with(
            "the decoy changed 1 package that hidden sessions changed too, so hidden sessions \
             see each twice in the pacman package database (/var/lib/pacman/local) and keep \
             their own files of it: firefox (133.0-1 on the decoy, 132.0-1 in hidden \
             sessions)\n"
        ),
        "{message}"
    );
    assert!(message.contains("`sudo pacman -U <file>`"), "{message}");
}

#[test]
fn pacman_entries_of_hidden_sessions_alone_pass() {
    let fs = arch_linux(
        &["firefox-131.0-1", "linux-6.17.1.arch1-1"],
        &["tor-0.4.8.17-1"],
        &[],
    );
    let result = run(&check(), &fs);
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        result.message(),
        "hidden sessions see the decoy's pacman package database (/var/lib/pacman/local) with \
         the 1 package they changed themselves, none of which the decoy changed since"
    );
    // Without root the decoy's entries cannot be listed.
    let result = run(&check().as_privileged(false), &fs);
    assert!(result.is_warn(), "{result:?}");
    assert!(result.message().contains("only root reads"), "{result:?}");
}

/// A decoy with rpm's database written at `decoy`, and hidden sessions'
/// copy written at `hidden` when given.
fn fedora(decoy: u64, hidden: Option<u64>) -> MockFilesystem {
    let fs = MockFilesystem::new();
    let at = |base: &str, seconds: u64| {
        let path = format!("{base}/usr/lib/sysimage/rpm/rpmdb.sqlite");
        fs.mock_set_file_size(&path, 16 << 20);
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(seconds);
        fs.mock_set_modified_time(Path::new(&path), time.into());
    };
    at(ROOT, decoy);
    if let Some(hidden) = hidden {
        at(UPPER, hidden);
    }
    // Fedora keeps the old place as a link to the new one.
    fs.mock_set_path_type(&format!("{ROOT}/var/lib/rpm"), PathKind::Symlink);
    fs
}

#[test]
fn rpms_copy_is_judged_by_time_even_without_root() {
    let check = check().as_privileged(false);
    let result = run(&check, &fedora(2_000, None));
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        result.message(),
        "hidden sessions see the decoy's own rpm package database \
         (/usr/lib/sysimage/rpm/rpmdb.sqlite)"
    );

    let result = run(&check, &fedora(2_000, Some(3_000)));
    assert!(result.is_pass(), "{result:?}");
    assert!(
        result.message().contains("written no earlier"),
        "{result:?}"
    );

    let result = run(&check, &fedora(3_000, Some(2_000)));
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().starts_with(
            "the decoy's rpm package database (/usr/lib/sysimage/rpm/rpmdb.sqlite) changed \
             after hidden sessions last changed their own copy"
        ),
        "{result:?}"
    );
    assert!(
        result.message().contains("`sudo dnf upgrade --refresh`"),
        "{result:?}"
    );
}

#[test]
fn a_long_list_names_five_and_counts_the_rest() {
    let decoy: Vec<(String, String)> = (0..8)
        .map(|i| (format!("pkg{i}"), "2".to_string()))
        .collect();
    let mut decoy: Vec<(&str, &str)> = decoy
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    // Hidden sessions' copy records only the one package both sides keep.
    let hidden = status(&[("base-files", "13.8")]);
    decoy.push(("base-files", "13.8"));
    let fs = debian(&status(&decoy), Some(&hidden));
    let result = run(&check(), &fs);
    let message = result.message();
    assert!(message.contains("8 packages"), "{message}");
    assert!(message.contains("pkg4 (2 on the decoy"), "{message}");
    assert!(!message.contains("pkg5 ("), "{message}");
    assert!(message.contains(", and 3 more\n"), "{message}");
}

#[test]
fn the_advisory_is_the_warning_an_entry_shows() {
    let layout = Layout::new(Path::new(HIDDEN));
    let fs = debian(&status(&[("libc6", "2.41-12")]), None);
    assert_eq!(
        advisory(&fs, Path::new(ROOT), &layout, Some(&[]), false),
        None
    );

    let fs = debian(
        &status(&[("libc6", "2.41-13")]),
        Some(&status(&[("libc6", "2.41-12")])),
    );
    let advisory = advisory(&fs, Path::new(ROOT), &layout, Some(&[]), false).expect("a drift");
    assert_eq!(advisory.name, NAME);
    let result = run(&check(), &fs);
    assert_eq!(advisory.text(), result.message());
    let fix = advisory.fix.as_deref().expect("a fix");
    assert_eq!(
        advisory.text(),
        format!("{}\n{fix}", advisory.message),
        "the fix on a line of its own"
    );
    let without = Advisory {
        fix: None,
        ..advisory.clone()
    };
    assert_eq!(without.text(), advisory.message);
}

#[test]
fn the_check_names_itself_and_needs_the_hidden_volume() {
    let check = check();
    assert_eq!(PreFlightCheck::<MockFilesystem>::name(&check), NAME);
    assert_eq!(NAME, "package-drift");
    assert!(PreFlightCheck::<MockFilesystem>::requires_hidden_volume(
        &check
    ));
    assert!(PreFlightCheck::<MockFilesystem>::description(&check).contains("package database"));
}

#[test]
fn reading_leaves_the_decoys_access_times_alone() {
    use crate::filesystem::RealFilesystem;
    use std::os::unix::fs::MetadataExt;

    let decoy = tempfile::tempdir().unwrap();
    let hidden = tempfile::tempdir().unwrap();
    let status_path = decoy.path().join("var/lib/dpkg/status");
    let local = decoy.path().join("var/lib/pacman/local");
    std::fs::create_dir_all(status_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(local.join("firefox-133.0-1")).unwrap();
    std::fs::write(&status_path, status(&[("libc6", "2.41-13")])).unwrap();
    let copy = hidden.path().join("root/upper/var/lib/dpkg/status");
    std::fs::create_dir_all(copy.parent().unwrap()).unwrap();
    std::fs::write(&copy, status(&[("libc6", "2.41-12")])).unwrap();
    std::fs::create_dir_all(
        hidden
            .path()
            .join("root/upper/var/lib/pacman/local/firefox-132.0-1"),
    )
    .unwrap();
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    for path in [&status_path, &local] {
        std::fs::File::open(path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_accessed(old))
            .unwrap();
    }
    let atime = |path: &Path| {
        let meta = std::fs::metadata(path).unwrap();
        (meta.atime(), meta.atime_nsec())
    };
    let before = (atime(&status_path), atime(&local));

    let check = PackageDriftCheck::new(decoy.path().to_path_buf(), hidden.path().to_path_buf())
        .as_privileged(true);
    let result = PreFlightCheck::<RealFilesystem>::run(&check, &RealFilesystem).unwrap();
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains("libc6 (2.41-13 on the decoy"),
        "{result:?}"
    );
    assert!(
        result.message().contains("firefox (133.0-1 on the decoy"),
        "{result:?}"
    );
    assert_eq!((atime(&status_path), atime(&local)), before);
}

#[test]
fn without_the_mount_table_a_copy_cannot_be_placed() {
    let fs = debian(
        &status(&[("libc6", "2.41-13")]),
        Some(&status(&[("libc6", "2.41-13")])),
    );
    fs.mock_set_mount_table_error("permission denied");
    let result = run(&check(), &fs);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result
            .message()
            .contains("the mount table cannot be read, so where hidden sessions keep their copy"),
        "{result:?}"
    );

    // A decoy without a package database still passes.
    let fs = MockFilesystem::new();
    fs.mock_set_mount_table_error("permission denied");
    assert!(run(&check(), &fs).is_pass());
}

#[test]
fn a_record_with_no_package_read_cannot_be_judged() {
    let record = status(&[("libc6", "2.41-13")]);
    for (decoy, hidden, named) in [
        ("Description: no package\n", record.as_str(), "on the decoy"),
        (
            record.as_str(),
            "Description: no package\n",
            "hidden sessions' copy",
        ),
    ] {
        let result = run(&check(), &debian(decoy, Some(hidden)));
        assert!(result.is_warn(), "{result:?}");
        assert!(
            result.message().contains(named)
                && result
                    .message()
                    .contains("records no package NAILS can read"),
            "{result:?}"
        );
    }
}

#[test]
fn a_copy_listed_but_not_looked_up_cannot_be_judged() {
    let fs = debian(&status(&[("libc6", "2.41-13")]), None);
    let dir = PathBuf::from(format!("{UPPER}/var/lib/dpkg"));
    fs.mock_set_directory_contents(&dir, vec![dir.join("status")]);
    let result = run(&check(), &fs);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result
            .message()
            .contains("listed, but it cannot be looked up"),
        "{result:?}"
    );
}

/// An upper this process may not look into is not taken for one without a
/// copy: without root it names the `sudo` line, as root it says why.
#[test]
fn an_upper_closed_to_the_check_cannot_be_judged() {
    use crate::filesystem::RealFilesystem;
    use std::os::unix::fs::PermissionsExt;

    if rustix::process::geteuid().is_root() {
        // Root looks into any directory.
        return;
    }
    let decoy = tempfile::tempdir().unwrap();
    let hidden = tempfile::tempdir().unwrap();
    let status_path = decoy.path().join("var/lib/dpkg/status");
    std::fs::create_dir_all(status_path.parent().unwrap()).unwrap();
    std::fs::write(&status_path, status(&[("libc6", "2.41-13")])).unwrap();
    let upper = hidden.path().join("root/upper");
    std::fs::create_dir_all(upper.join("var/lib/dpkg")).unwrap();
    std::fs::write(
        upper.join("var/lib/dpkg/status"),
        status(&[("libc6", "2.41-12")]),
    )
    .unwrap();
    std::fs::set_permissions(&upper, std::fs::Permissions::from_mode(0o000)).unwrap();

    let judge = |privileged: bool| {
        let check = PackageDriftCheck::new(decoy.path().to_path_buf(), hidden.path().to_path_buf())
            .as_privileged(privileged);
        PreFlightCheck::<RealFilesystem>::run(&check, &RealFilesystem).unwrap()
    };
    let unprivileged = judge(false);
    let privileged = judge(true);
    std::fs::set_permissions(&upper, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(unprivileged.is_warn(), "{unprivileged:?}");
    assert!(
        unprivileged
            .message()
            .contains("only root reads the decoy's package database"),
        "{unprivileged:?}"
    );
    assert!(privileged.is_warn(), "{privileged:?}");
    assert!(
        privileged
            .message()
            .contains("what hidden sessions keep at /var cannot be read"),
        "{privileged:?}"
    );
}
