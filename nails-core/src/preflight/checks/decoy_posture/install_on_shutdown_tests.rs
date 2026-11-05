// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::RealFilesystem;
use crate::filesystem::{MockFilesystem, PathKind};
use crate::preflight::checks::decoy_posture::DecoyPersistenceCheck;
use crate::preflight::{CheckResult, PreFlightCheck};

/// The files `/etc/apt/apt.conf.d` holds on a stock decoy, copied unchanged
/// from the packages that ship them (see nails-base's apt_conf tests).
const DEBIAN_13: &[u8] = include_bytes!(
    "../../../../../nails-base/src/packages/fixtures/apt/debian-13-50unattended-upgrades"
);
const UBUNTU_24_04: &[u8] = include_bytes!(
    "../../../../../nails-base/src/packages/fixtures/apt/ubuntu-24.04-50unattended-upgrades"
);
const UBUNTU_26_04: &[u8] = include_bytes!(
    "../../../../../nails-base/src/packages/fixtures/apt/ubuntu-26.04-50unattended-upgrades"
);
const AUTO_UPGRADES: &[u8] =
    include_bytes!("../../../../../nails-base/src/packages/fixtures/apt/20auto-upgrades");
const AUTOREMOVE: &[u8] =
    include_bytes!("../../../../../nails-base/src/packages/fixtures/apt/01autoremove");

/// The setting turned on, as a person writes it.
const ON: &str = "Unattended-Upgrade::InstallOnShutdown \"true\";\n";
const OFF: &str = "Unattended-Upgrade::InstallOnShutdown \"false\";\n";

/// An invocation id as systemd writes it.
const INVOCATION_ID: &str = "8028a17235414b4e80c950b24a7487d7"; // pragma: allowlist secret

fn write(root: &Path, rel: &str, content: &[u8]) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn link(root: &Path, rel: &str, target: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(target, path).unwrap();
}

/// The helper runs: systemd's marker of an active unit.
fn run_helper(root: &Path) {
    link(
        root,
        "run/systemd/units/invocation:unattended-upgrades.service",
        INVOCATION_ID,
    );
}

/// The helper is enabled, as its package enables it.
fn enable_helper(root: &Path) {
    link(
        root,
        "etc/systemd/system/multi-user.target.wants/unattended-upgrades.service",
        "/usr/lib/systemd/system/unattended-upgrades.service",
    );
}

/// A stock decoy of `release` (one of the fixtures), its helper enabled and
/// running.
fn stock(release: &[u8]) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(root, "etc/apt/apt.conf.d/01autoremove", AUTOREMOVE);
    write(root, "etc/apt/apt.conf.d/20auto-upgrades", AUTO_UPGRADES);
    write(root, "etc/apt/apt.conf.d/50unattended-upgrades", release);
    enable_helper(root);
    run_helper(root);
    tmp
}

/// A mock decoy whose helper runs (when `running`) and whose
/// `apt.conf.d` holds `parts`: each name with its content, or with none
/// for a file whose read fails.
fn mock_decoy(running: bool, parts: &[(&str, Option<&str>)]) -> MockFilesystem {
    let fs = MockFilesystem::new();
    if running {
        fs.create_symlink(
            Path::new(INVOCATION_ID),
            Path::new("/run/systemd/units/invocation:unattended-upgrades.service"),
        )
        .unwrap();
    }
    mock_parts(&fs, "/etc/apt/apt.conf.d", parts);
    fs
}

/// Make `dir` a directory of the mock that lists `parts`.
fn mock_parts(fs: &MockFilesystem, dir: &str, parts: &[(&str, Option<&str>)]) {
    fs.mock_set_path_type(dir, PathKind::Dir);
    let mut entries = Vec::new();
    for (name, content) in parts {
        let path = format!("{dir}/{name}");
        match content {
            Some(content) => fs.mock_add_file(&path, content),
            None => fs.mock_set_path_type(&path, PathKind::File),
        }
        entries.push(PathBuf::from(path));
    }
    fs.mock_set_directory_contents(Path::new(dir), entries);
}

fn find(root: &Path) -> Finding {
    finding(&RealFilesystem, root, None)
}

fn find_with_upper(root: &Path, upper: &Path) -> Finding {
    finding(&RealFilesystem, root, Some(upper))
}

fn blocker(finding: &Finding) -> &str {
    &finding
        .blocker
        .as_ref()
        .unwrap_or_else(|| panic!("no refusal: {finding:?}"))
        .0
}

#[test]
fn the_stock_decoys_keep_the_setting_off() {
    for release in [DEBIAN_13, UBUNTU_24_04, UBUNTU_26_04] {
        let tmp = stock(release);
        assert_eq!(find(tmp.path()), Finding::default());
    }
}

#[test]
fn the_setting_on_with_the_helper_running_is_refused() {
    let tmp = stock(DEBIAN_13);
    let root = tmp.path();
    write(root, "etc/apt/apt.conf.d/99local", ON.as_bytes());
    let found = find(root);
    let message = blocker(&found);
    assert!(
        message.contains(
            "Unattended-Upgrade::InstallOnShutdown is on in /etc/apt/apt.conf.d/99local:1"
        ),
        "{message}"
    );
    assert!(message.contains("on the decoy disk"), "{message}");
    assert!(message.contains("logs that run there"), "{message}");
    // The session starts its own copy of the enabled helper.
    assert!(
        message.contains("when a session ends with deactivate"),
        "{message}"
    );
    let fix = &found.blocker.as_ref().unwrap().1;
    assert!(
        fix.contains("`Unattended-Upgrade::InstallOnShutdown \"false\";`"),
        "{fix}"
    );
    assert!(fix.contains("/etc/apt/apt.conf.d/99local"), "{fix}");
    assert!(fix.contains("a line only deleted"), "{fix}");
    assert!(found.warning.is_none());
}

#[test]
fn every_spelling_apt_reads_as_true_is_refused() {
    for text in [
        "Unattended-Upgrade { InstallOnShutdown \"1\"; };\n",
        "unattended-upgrade::installonshutdown on;\n",
        "Unattended-Upgrade::InstallOnShutdown \"0x1\";\n",
        "Unattended-Upgrade::InstallOnShutdown \"yes\"; // installs at shutdown\n",
    ] {
        let tmp = stock(UBUNTU_24_04);
        write(tmp.path(), "etc/apt/apt.conf.d/52local", text.as_bytes());
        assert!(find(tmp.path()).blocker.is_some(), "{text:?}");
    }
    for text in [
        "Unattended-Upgrade::InstallOnShutdown \"2\";\n",
        "Unattended-Upgrade::InstallOnShutdown \"\";\n",
        "// Unattended-Upgrade::InstallOnShutdown \"true\";\n",
        "Unattended-Upgrade::InstallOnShutdownX \"true\";\n",
    ] {
        let tmp = stock(UBUNTU_24_04);
        write(tmp.path(), "etc/apt/apt.conf.d/52local", text.as_bytes());
        assert_eq!(find(tmp.path()), Finding::default(), "{text:?}");
    }
}

#[test]
fn the_last_setting_apt_reads_wins() {
    // A later part turns it off again.
    let tmp = stock(UBUNTU_26_04);
    write(tmp.path(), "etc/apt/apt.conf.d/52on", ON.as_bytes());
    write(tmp.path(), "etc/apt/apt.conf.d/99off", OFF.as_bytes());
    assert_eq!(find(tmp.path()), Finding::default());

    // apt.conf is read after the parts.
    let tmp = stock(UBUNTU_26_04);
    write(tmp.path(), "etc/apt/apt.conf.d/99on", ON.as_bytes());
    write(tmp.path(), "etc/apt/apt.conf", OFF.as_bytes());
    assert_eq!(find(tmp.path()), Finding::default());

    let tmp = stock(UBUNTU_26_04);
    write(tmp.path(), "etc/apt/apt.conf.d/00off", OFF.as_bytes());
    write(tmp.path(), "etc/apt/apt.conf", ON.as_bytes());
    assert!(
        blocker(&find(tmp.path())).contains("is on in /etc/apt/apt.conf:1"),
        "{:?}",
        find(tmp.path())
    );

    // A clear of the setting, or of the scope above it, unsets it.
    for clear in [
        "#clear Unattended-Upgrade;\n",
        "#clear Unattended-Upgrade::InstallOnShutdown;\n",
    ] {
        let tmp = stock(DEBIAN_13);
        write(tmp.path(), "etc/apt/apt.conf.d/52on", ON.as_bytes());
        write(tmp.path(), "etc/apt/apt.conf.d/99clear", clear.as_bytes());
        assert_eq!(find(tmp.path()), Finding::default(), "{clear:?}");
    }
}

#[test]
fn the_files_apt_skips_by_name_or_kind_are_skipped() {
    for name in [
        ".99hidden",
        "99local.bak",
        "99local.dpkg-old",
        "99local.ucf-dist",
        "99local~",
        "99local.disabled",
        "99local.",
        "99 local",
    ] {
        let tmp = stock(DEBIAN_13);
        write(
            tmp.path(),
            &format!("etc/apt/apt.conf.d/{name}"),
            ON.as_bytes(),
        );
        assert_eq!(find(tmp.path()), Finding::default(), "{name:?}");
    }
    // A directory, and a link that leads nowhere, are no files to apt.
    let tmp = stock(DEBIAN_13);
    write(tmp.path(), "etc/apt/apt.conf.d/99dir.conf/x", ON.as_bytes());
    link(
        tmp.path(),
        "etc/apt/apt.conf.d/99gone",
        "/nonexistent/99gone",
    );
    assert_eq!(find(tmp.path()), Finding::default());
    // A link to a file is read.
    let tmp = stock(DEBIAN_13);
    write(tmp.path(), "srv/on.conf", ON.as_bytes());
    link(
        tmp.path(),
        "etc/apt/apt.conf.d/99linked.conf",
        &tmp.path().join("srv/on.conf").display().to_string(),
    );
    assert!(find(tmp.path()).blocker.is_some());
}

#[test]
fn what_nails_cannot_read_as_apt_reads_it_is_refused_as_if_on() {
    for (text, why) in [
        (
            "Unattended-Upgrade::InstallOnShutdown \"false\"\n",
            "/etc/apt/apt.conf.d/99local:2 is refused by apt (Extra junk at end of file)",
        ),
        (
            "#include \"/etc/elsewhere.conf\";\n",
            "/etc/apt/apt.conf.d/99local:1 has apt read another file",
        ),
        (
            "Dir::Etc::main \"elsewhere.conf\";\n",
            "/etc/apt/apt.conf.d/99local:1 sets Dir::Etc::main, which moves the files apt reads",
        ),
        (
            "#clear Dir;\n",
            "/etc/apt/apt.conf.d/99local:1 clears Dir, which moves the files apt reads",
        ),
        (
            "RootDir \"/srv/root\";\n",
            "/etc/apt/apt.conf.d/99local:1 sets RootDir",
        ),
    ] {
        let tmp = stock(DEBIAN_13);
        write(tmp.path(), "etc/apt/apt.conf.d/99local", text.as_bytes());
        let found = find(tmp.path());
        let message = blocker(&found);
        assert!(message.starts_with("NAILS cannot tell"), "{message}");
        assert!(message.contains("so it counts as on"), "{message}");
        assert!(message.contains(why), "{why}: {message}");
        assert!(
            found
                .blocker
                .as_ref()
                .unwrap()
                .1
                .starts_with("fix or remove"),
            "{found:?}"
        );
    }
}

#[test]
fn an_unreadable_or_oversized_file_is_refused_as_if_on() {
    let fs = mock_decoy(true, &[("50unattended-upgrades", None)]);
    let found = finding(&fs, Path::new("/"), None);
    let message = blocker(&found);
    assert!(
        message.contains("/etc/apt/apt.conf.d/50unattended-upgrades cannot be read"),
        "{message}"
    );

    let fs = mock_decoy(true, &[("50unattended-upgrades", Some(""))]);
    fs.mock_set_file_size("/etc/apt/apt.conf.d/50unattended-upgrades", FILE_LIMIT + 1);
    let found = finding(&fs, Path::new("/"), None);
    assert!(
        blocker(&found).contains("more than NAILS reads"),
        "{found:?}"
    );

    // The directory itself cannot be listed.
    let fs = mock_decoy(true, &[]);
    fs.mock_set_unreadable_dir("/etc/apt/apt.conf.d");
    let found = finding(&fs, Path::new("/"), None);
    assert!(
        blocker(&found).contains("/etc/apt/apt.conf.d cannot be listed"),
        "{found:?}"
    );
}

#[test]
fn without_a_helper_running_or_starting_the_setting_does_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "etc/apt/apt.conf.d/50unattended-upgrades",
        DEBIAN_13,
    );
    write(tmp.path(), "etc/apt/apt.conf.d/99local", ON.as_bytes());
    assert_eq!(find(tmp.path()), Finding::default());
    // A mask outranks the link that enables it.
    enable_helper(tmp.path());
    link(
        tmp.path(),
        "etc/systemd/system/unattended-upgrades.service",
        "/dev/null",
    );
    assert_eq!(find(tmp.path()), Finding::default());
}

#[test]
fn a_helper_stopped_but_enabled_only_warns_of_the_way_back() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(
        root,
        "etc/apt/apt.conf.d/50unattended-upgrades",
        UBUNTU_24_04,
    );
    write(root, "etc/apt/apt.conf.d/99local", ON.as_bytes());
    enable_helper(root);
    let found = find(root);
    assert!(found.blocker.is_none(), "{found:?}");
    let warning = found.warning.expect("a warning");
    assert!(
        warning.contains("unattended-upgrades.service is stopped on the decoy but enabled"),
        "{warning}"
    );
    assert!(
        warning.contains("(/etc/apt/apt.conf.d/99local:1)"),
        "{warning}"
    );
    assert!(
        warning.contains("when the session ends with deactivate"),
        "{warning}"
    );
    assert!(
        warning.contains("into the session's overlay on the hidden volume"),
        "{warning}"
    );
    assert!(
        warning.contains(&sudo_line(NextStep::DeactivatePoweroff)),
        "{warning}"
    );
}

#[test]
fn a_session_that_turns_the_setting_on_in_its_overlay_warns() {
    let tmp = stock(DEBIAN_13);
    let upper = tempfile::tempdir().unwrap();
    write(upper.path(), "etc/apt/apt.conf.d/99session", ON.as_bytes());
    let found = find_with_upper(tmp.path(), upper.path());
    assert!(found.blocker.is_none(), "{found:?}");
    let warning = found.warning.expect("a warning");
    assert!(
        warning.contains("the hidden session starts its own copy"),
        "{warning}"
    );
    assert!(
        warning.contains("/etc/apt/apt.conf.d/99session:1 in the hidden session's overlay"),
        "{warning}"
    );
    // The decoy alone keeps it off.
    assert_eq!(find(tmp.path()), Finding::default());
}

#[test]
fn a_file_of_the_upper_replaces_the_decoys() {
    // The session edited the decoy's own file and turned the setting on.
    let tmp = stock(UBUNTU_26_04);
    let upper = tempfile::tempdir().unwrap();
    let edited = [UBUNTU_26_04, ON.as_bytes()].concat();
    write(
        upper.path(),
        "etc/apt/apt.conf.d/50unattended-upgrades",
        &edited,
    );
    let warning = find_with_upper(tmp.path(), upper.path())
        .warning
        .expect("a warning");
    assert!(
        warning.contains("/etc/apt/apt.conf.d/50unattended-upgrades:"),
        "{warning}"
    );

    // The decoy turns it on; the session's copy of the file turns it off.
    let tmp = stock(UBUNTU_26_04);
    std::fs::remove_file(
        tmp.path()
            .join("run/systemd/units/invocation:unattended-upgrades.service"),
    )
    .unwrap();
    write(tmp.path(), "etc/apt/apt.conf", ON.as_bytes());
    let upper = tempfile::tempdir().unwrap();
    write(upper.path(), "etc/apt/apt.conf", OFF.as_bytes());
    assert!(find(tmp.path()).warning.is_some());
    assert_eq!(
        find_with_upper(tmp.path(), upper.path()),
        Finding::default()
    );
}

#[test]
fn a_directory_of_the_upper_is_read_both_ways() {
    // The decoy turns it off last; the session's own file turns it on
    // before that. Merged with the decoy's directory the decoy's file wins,
    // but a directory a session made again shows the session's files alone.
    let tmp = stock(DEBIAN_13);
    write(tmp.path(), "etc/apt/apt.conf.d/99zz-off", OFF.as_bytes());
    let upper = tempfile::tempdir().unwrap();
    write(upper.path(), "etc/apt/apt.conf.d/52on", ON.as_bytes());
    let warning = find_with_upper(tmp.path(), upper.path())
        .warning
        .expect("a warning");
    assert!(
        warning.contains("/etc/apt/apt.conf.d/52on:1 in the hidden session's overlay"),
        "{warning}"
    );
}

#[test]
fn a_whiteout_in_the_upper_deletes_the_decoys_file() {
    // The helper is stopped but enabled: the session starts its copy.
    let fs = mock_decoy(false, &[("99on", Some(ON))]);
    fs.mock_set_directory_contents(
        Path::new("/etc/systemd/system"),
        vec![PathBuf::from("/etc/systemd/system/multi-user.target.wants")],
    );
    fs.mock_set_is_symlink(
        "/etc/systemd/system/multi-user.target.wants/unattended-upgrades.service",
        true,
    );
    let upper = Path::new("/hidden/upper");
    let found = finding(&fs, Path::new("/"), Some(upper));
    assert!(found.warning.is_some(), "{found:?}");

    // A session deleted the decoy's file.
    fs.mock_set_path_type("/hidden/upper/etc", PathKind::Dir);
    fs.mock_set_path_type("/hidden/upper/etc/apt", PathKind::Dir);
    mock_parts(&fs, "/hidden/upper/etc/apt/apt.conf.d", &[]);
    fs.mock_set_directory_contents(
        Path::new("/hidden/upper/etc/apt/apt.conf.d"),
        vec![PathBuf::from("/hidden/upper/etc/apt/apt.conf.d/99on")],
    );
    fs.mock_set_whiteout("/hidden/upper/etc/apt/apt.conf.d/99on");
    let found = finding(&fs, Path::new("/"), Some(upper));
    assert_eq!(found, Finding::default());
}

#[test]
fn a_link_in_the_upper_on_the_way_to_apts_files_cannot_be_read() {
    let tmp = stock(DEBIAN_13);
    let upper = tempfile::tempdir().unwrap();
    link(upper.path(), "etc/apt", "/srv/apt");
    let warning = find_with_upper(tmp.path(), upper.path())
        .warning
        .expect("a warning");
    assert!(warning.contains("NAILS cannot tell"), "{warning}");
    assert!(warning.contains("a symbolic link at /etc/apt"), "{warning}");
}

#[test]
fn the_session_enables_or_unmasks_the_helper_in_its_overlay() {
    // Not enabled on the decoy: the session enabled it.
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "etc/apt/apt.conf.d/99on", ON.as_bytes());
    assert_eq!(find(tmp.path()), Finding::default());
    let upper = tempfile::tempdir().unwrap();
    enable_helper(upper.path());
    assert!(find_with_upper(tmp.path(), upper.path()).warning.is_some());

    // Masked on the decoy, the mask is the session's to keep.
    enable_helper(tmp.path());
    link(
        tmp.path(),
        "etc/systemd/system/unattended-upgrades.service",
        "/dev/null",
    );
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(
        find_with_upper(tmp.path(), empty.path()),
        Finding::default()
    );
    // A mask of the session's own.
    let masked_upper = tempfile::tempdir().unwrap();
    link(
        masked_upper.path(),
        "etc/systemd/system/unattended-upgrades.service",
        "/dev/null",
    );
    let unmasked = tempfile::tempdir().unwrap();
    write(unmasked.path(), "etc/apt/apt.conf.d/99on", ON.as_bytes());
    enable_helper(unmasked.path());
    assert_eq!(
        find_with_upper(unmasked.path(), masked_upper.path()),
        Finding::default()
    );
}

/// The check around the finding: a refusal of its own, which the override
/// turns into a warning, and which the window and status do not count.
#[test]
fn the_check_refuses_and_the_override_warns() {
    let tmp = stock(DEBIAN_13);
    let root = tmp.path();
    write(
        root,
        "etc/systemd/journald.conf",
        b"[Journal]\nStorage=volatile\n",
    );
    write(root, "sys/kernel/kexec_crash_loaded", b"0\n");
    write(root, "etc/apt/apt.conf.d/99local", ON.as_bytes());

    let refused = DecoyPersistenceCheck::new(false, false)
        .with_root(root)
        .run(&RealFilesystem)
        .unwrap();
    assert!(refused.is_fail(), "{refused:?}");
    assert!(
        matches!(
            refused,
            CheckResult::Fail {
                allowable: Some(nails_api::Allowable::PersistentDecoy),
                ..
            }
        ),
        "{refused:?}"
    );
    let message = refused.message();
    assert!(
        message.contains("unattended-upgrades installs"),
        "{message}"
    );
    // Its own words, not the log blockers'.
    assert!(!message.contains("journal"), "{message}");
    let remediation = refused.remediation().unwrap();
    assert!(
        remediation.starts_with("Set `Unattended-Upgrade::InstallOnShutdown \"false\";`"),
        "{remediation}"
    );
    assert!(
        remediation.contains("--allow-persistent-decoy"),
        "{remediation}"
    );
    assert!(!remediation.contains("amnesic"), "{remediation}");

    let allowed = DecoyPersistenceCheck::new(true, false)
        .with_root(root)
        .run(&RealFilesystem)
        .unwrap();
    assert!(allowed.is_warn(), "{allowed:?}");
    let message = allowed.message();
    assert!(message.contains("--allow-persistent-decoy"), "{message}");
    assert!(
        message.contains("At the switch unattended-upgrades installs the pending updates"),
        "{message}"
    );
    assert!(!message.contains("Records written before"), "{message}");
}

#[test]
fn the_check_warns_of_the_session_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(
        root,
        "etc/systemd/journald.conf",
        b"[Journal]\nStorage=volatile\n",
    );
    write(root, "sys/kernel/kexec_crash_loaded", b"0\n");
    write(root, "etc/apt/apt.conf.d/50unattended-upgrades", DEBIAN_13);
    write(root, "etc/apt/apt.conf.d/99local", ON.as_bytes());
    enable_helper(root);
    let result = DecoyPersistenceCheck::new(false, false)
        .with_root(root)
        .run(&RealFilesystem)
        .unwrap();
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result
            .message()
            .contains("stopped on the decoy but enabled"),
        "{result:?}"
    );
}

#[test]
fn the_window_and_status_do_not_count_it() {
    let fs = mock_decoy(true, &[("99local", Some(ON))]);
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    assert!(finding(&fs, Path::new("/"), None).blocker.is_some());
    assert!(DecoyPersistenceCheck::persistence_findings(&fs).is_empty());
    assert!(!DecoyPersistenceCheck::decoy_is_persistent(&fs));
    assert!(!DecoyPersistenceCheck::decoy_kdump_armed(&fs));
}

#[test]
fn the_finding_writes_nothing() {
    let fs = mock_decoy(true, &[("99local", Some(OFF))]);
    fs.mock_set_path_type("/hidden/upper/etc", PathKind::Dir);
    fs.mock_set_path_type("/hidden/upper/etc/apt", PathKind::Dir);
    mock_parts(
        &fs,
        "/hidden/upper/etc/apt/apt.conf.d",
        &[("99session", Some(ON))],
    );
    fs.mock_set_directory_contents(
        Path::new("/etc/systemd/system"),
        vec![PathBuf::from("/etc/systemd/system/multi-user.target.wants")],
    );
    fs.mock_set_is_symlink(
        "/etc/systemd/system/multi-user.target.wants/unattended-upgrades.service",
        true,
    );
    assert!(
        finding(&fs, Path::new("/"), Some(Path::new("/hidden/upper")))
            .warning
            .is_some()
    );
    let before = fs.mock_ops().len();
    let _ = finding(&fs, Path::new("/"), Some(Path::new("/hidden/upper")));
    assert!(fs.mock_written_paths().is_empty());
    assert_eq!(fs.mock_ops().len(), before);
}
