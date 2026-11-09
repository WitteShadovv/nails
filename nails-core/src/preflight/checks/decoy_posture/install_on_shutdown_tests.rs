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

/// The helper's process, as the tests number it.
const PID: u32 = 412;

/// The helper's unit, in the cgroup tree.
const CGROUP: &str = "sys/fs/cgroup/system.slice/unattended-upgrades.service";

/// The environment systemd 257 starts the helper with, `extra` added, each
/// entry ended by a NUL as `/proc/<pid>/environ` holds them.
fn environ(extra: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in [
        "LANG=C.UTF-8",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
        "INVOCATION_ID=8028a17235414b4e80c950b24a7487d7", // pragma: allowlist secret
        "JOURNAL_STREAM=8:4321",
        "SYSTEMD_EXEC_PID=412",
    ]
    .iter()
    .chain(extra)
    {
        out.extend_from_slice(entry.as_bytes());
        out.push(0);
    }
    out
}

/// `/proc/<pid>/stat` of the helper as the kernel writes it, started
/// `ticks` clock ticks after the boot: its `comm` cut to 15 bytes.
fn stat_line(pid: u32, ticks: u64) -> String {
    format!(
        "{pid} (unattended-upgr) S 1 {pid} {pid} 0 -1 4194560 3145 0 23 0 41 9 0 0 20 0 2 0 \
         {ticks} 47042560 4823 18446744073709551615 1 1 0 0 0 0 0 16781312 16386 0 0 0 17 1 0 \
         0 0 0 0 0 0 0 0 0 0 0 0\n"
    )
}

/// Seconds since the epoch, now.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The helper runs, its process started an hour after a boot at `boot`
/// seconds since the epoch, with the environment `env`: its unit's cgroup
/// lists it, as systemd's cgroup tree shows a running unit.
fn run_helper_since(root: &Path, boot: u64, env: &[u8]) {
    write(
        root,
        &format!("{CGROUP}/cgroup.events"),
        b"populated 1\nfrozen 0\n",
    );
    write(
        root,
        &format!("{CGROUP}/cgroup.procs"),
        format!("{PID}\n").as_bytes(),
    );
    write(
        root,
        &format!("proc/{PID}/stat"),
        stat_line(PID, 3600 * 100).as_bytes(),
    );
    write(root, &format!("proc/{PID}/environ"), env);
    write(
        root,
        "proc/stat",
        format!("cpu  10 0 10 100 0 0 0 0 0 0\nbtime {boot}\nprocesses 900\n").as_bytes(),
    );
}

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

/// The helper runs, started after every file the test writes: a day from
/// now, so that what the files say counts and not what it kept.
fn run_helper(root: &Path) {
    run_helper_since(root, now() + 86_400, &environ(&[]));
}

/// python3-gi installed under `root`, as Debian 13 packages it.
fn install_gi(root: &Path) {
    polling::tests::install(root, polling::tests::PYTHON3_GI[0]);
}

/// The helper stops: its unit's cgroup goes with it.
fn stop_helper(root: &Path) {
    std::fs::remove_dir_all(root.join(CGROUP)).unwrap();
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
/// running, with its release's python3-gi installed.
fn stock(release: &[u8]) -> tempfile::TempDir {
    let tmp = stock_without_gi(release);
    let at = [DEBIAN_13, UBUNTU_24_04, UBUNTU_26_04]
        .iter()
        .position(|stock| *stock == release)
        .expect("a stock release");
    polling::tests::install(tmp.path(), polling::tests::PYTHON3_GI[at]);
    tmp
}

/// A stock decoy of `release` as [`stock`], without python3-gi, as Debian
/// 13's cloud image is.
fn stock_without_gi(release: &[u8]) -> tempfile::TempDir {
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
/// for a file whose read fails. python3-gi is installed.
fn mock_decoy(running: bool, parts: &[(&str, Option<&str>)]) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/usr/lib/python3/dist-packages/gi/__init__.py", "");
    if running {
        mock_run_helper(&fs, Some(&environ(&[])));
    }
    mock_parts(&fs, "/etc/apt/apt.conf.d", parts);
    fs
}

/// The helper runs on the mock: systemd's marker of an active unit and its
/// cgroup's process, which started after every file of the mock changed (a
/// path with no change time set changed at the epoch), with the environment
/// `env`, or one that cannot be read.
fn mock_run_helper(fs: &MockFilesystem, env: Option<&[u8]>) {
    let marker = "/run/systemd/units/invocation:unattended-upgrades.service";
    fs.create_symlink(Path::new(INVOCATION_ID), Path::new(marker))
        .unwrap();
    fs.mock_set_change_time(
        marker,
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(2_000_003_600),
    );
    fs.mock_add_file(&format!("/{CGROUP}/cgroup.procs"), &format!("{PID}\n"));
    fs.mock_add_file(&format!("/proc/{PID}/stat"), &stat_line(PID, 3600 * 100));
    match env {
        Some(env) => fs.mock_set_file_bytes(&format!("/proc/{PID}/environ"), env),
        None => fs.mock_set_path_type(&format!("/proc/{PID}/environ"), PathKind::File),
    }
    fs.mock_add_file("/proc/stat", "btime 2000000000\n");
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
        .finding
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
    let fix = &found.blocker.as_ref().unwrap().fix;
    assert!(
        fix.contains("`Unattended-Upgrade::InstallOnShutdown \"false\";`"),
        "{fix}"
    );
    assert!(
        fix.contains(
            "in /etc/apt/apt.conf.d/99local or in a file of /etc/apt/apt.conf.d that apt reads \
             after it"
        ),
        "{fix}"
    );
    assert!(fix.contains("a line only deleted"), "{fix}");
    assert_eq!(
        found.blocker.as_ref().unwrap().at_the_switch,
        AtTheSwitch::Installs
    );
    assert!(found.warning.is_none());
}

#[test]
fn the_fix_of_the_setting_in_apt_conf_names_that_file_alone() {
    // apt reads /etc/apt/apt.conf after every part, so no part can turn off
    // what it turns on.
    let tmp = stock(DEBIAN_13);
    write(tmp.path(), "etc/apt/apt.conf", ON.as_bytes());
    let found = find(tmp.path());
    let fix = &found.blocker.as_ref().expect("a refusal").fix;
    assert!(
        fix.contains(
            "`Unattended-Upgrade::InstallOnShutdown \"false\";` on the decoy, in \
             /etc/apt/apt.conf (a line only deleted"
        ),
        "{fix}"
    );
    assert!(!fix.contains("reads after it"), "{fix}");

    // A part that turns it off before apt.conf turns it on again does not.
    write(tmp.path(), "etc/apt/apt.conf.d/99off", OFF.as_bytes());
    assert!(find(tmp.path()).blocker.is_some());
    // Set off in apt.conf itself, as the fix says, it is off.
    write(
        tmp.path(),
        "etc/apt/apt.conf",
        [ON, OFF].concat().as_bytes(),
    );
    assert_eq!(find(tmp.path()), Finding::default());
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
    // A directory, and a link that leads nowhere, are no files to apt. The
    // link may have led to one when the running helper started, which
    // leaves what it holds unknown where no file sets the setting (see
    // since_start_tests.rs).
    let tmp = stock(DEBIAN_13);
    write(tmp.path(), "etc/apt/apt.conf.d/99dir.conf/x", ON.as_bytes());
    assert_eq!(find(tmp.path()), Finding::default());
    link(
        tmp.path(),
        "etc/apt/apt.conf.d/99gone",
        "/nonexistent/99gone",
    );
    let found = find(tmp.path());
    let message = blocker(&found);
    assert!(
        message.contains(
            "no file of apt's configuration sets it now, but /etc/apt/apt.conf.d/99gone is \
             reached through a symbolic link"
        ),
        "{message}"
    );
    assert!(!message.contains("is on in"), "{message}");
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
        let fix = &found.blocker.as_ref().unwrap().fix;
        assert!(
            fix.starts_with(&format!(
                "fix or remove what keeps NAILS from reading the setting ({why}"
            )),
            "{fix}"
        );
        assert_eq!(
            found.blocker.as_ref().unwrap().at_the_switch,
            AtTheSwitch::Unknown,
            "{found:?}"
        );
    }
}

#[test]
fn a_file_apt_refuses_is_refused_with_what_the_helper_writes() {
    // The file the scenario under nix/distro-tests writes, with no `;`,
    // which apt reports at its end, line 2, and the false of a line whose
    // `;` is missing: apt refuses both, and the helper then installs
    // nothing at the signal but writes its two ERROR lines.
    for (text, at) in [
        (
            "Nails::Fact \"NAILS_FACT_SYNTAX\"\n",
            "/etc/apt/apt.conf.d/99local:2",
        ),
        (
            "Unattended-Upgrade::InstallOnShutdown \"false\"\n",
            "/etc/apt/apt.conf.d/99local:2",
        ),
    ] {
        let tmp = stock(UBUNTU_24_04);
        write(tmp.path(), "etc/apt/apt.conf.d/99local", text.as_bytes());
        let found = find(tmp.path());
        let refusal = found.blocker.as_ref().expect("a refusal");
        let message = &refusal.finding;
        // What happens, not a doubt: the helper installs nothing for
        // certain.
        assert!(
            message.starts_with(&format!(
                "apt refuses {at} (Extra junk at end of file): at activation unattended-upgrades' \
                 shutdown helper reads apt's configuration again, finds that file refused and \
                 installs nothing, but writes two ERROR lines"
            )),
            "{message}"
        );
        assert!(!message.contains("cannot tell"), "{message}");
        assert!(!message.contains("counts it as on"), "{message}");
        assert!(
            message.contains(
                "two ERROR lines (`Apt returned an error thus shutdown mode is disabled` and \
                 apt's message) to /var/log/unattended-upgrades/unattended-upgrades-shutdown.log \
                 on the decoy disk, or to the journal if it started with the file already refused"
            ),
            "{message}"
        );
        assert_eq!(
            refusal.fix,
            format!(
                "fix what apt refuses at {at} (Extra junk at end of file), or remove that file"
            )
        );
        assert_eq!(refusal.at_the_switch, AtTheSwitch::ErrorLines);
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
fn a_line_nails_does_not_read_is_not_called_refused_by_apt() {
    // apt reads both lines; NAILS does not, and says so.
    for (text, why) in [
        (
            format!("// {}\n{ON}", "x".repeat(apt_conf::MAX_LINE)),
            "/etc/apt/apt.conf.d/99local:1 holds more than 4000 bytes, which NAILS does not read",
        ),
        (
            "Foo \"x\0\";\n".to_string(),
            "/etc/apt/apt.conf.d/99local:1 holds a NUL byte, which NAILS does not read",
        ),
    ] {
        let tmp = stock(UBUNTU_24_04);
        write(tmp.path(), "etc/apt/apt.conf.d/99local", text.as_bytes());
        let message = blocker(&find(tmp.path())).to_string();
        assert!(message.starts_with("NAILS cannot tell"), "{message}");
        assert!(message.contains(why), "{message}");
        assert!(!message.contains("refused by apt"), "{message}");
    }
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
    stop_helper(tmp.path());
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
    install_gi(tmp.path());
    write(tmp.path(), "etc/apt/apt.conf.d/99on", ON.as_bytes());
    assert_eq!(find(tmp.path()), Finding::default());
    let upper = tempfile::tempdir().unwrap();
    enable_helper(upper.path());
    let warning = find_with_upper(tmp.path(), upper.path())
        .warning
        .expect("a warning");
    assert!(
        warning.starts_with(
            "unattended-upgrades.service is stopped on the decoy, and the hidden session's \
             overlay enables it, so the session starts it, and \
             Unattended-Upgrade::InstallOnShutdown is on there (/etc/apt/apt.conf.d/99on:1)"
        ),
        "{warning}"
    );

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
    install_gi(unmasked.path());
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
fn the_override_of_a_setting_nails_cannot_tell_says_no_install_runs_for_certain() {
    // What NAILS does not follow: the warning does not say that the helper
    // installs. A file apt refuses: the helper installs nothing at the
    // signal, which the finding says once, and the warning says what it
    // writes instead.
    for (text, said, sentence) in [
        (
            &b"#include \"/etc/elsewhere.conf\";\n"[..],
            "NAILS cannot tell whether unattended-upgrades installs the pending updates at \
             activation, as its shutdown helper does when Unattended-Upgrade::InstallOnShutdown \
             is on, so it counts as on: /etc/apt/apt.conf.d/99local:1 has apt read another file",
            None,
        ),
        (
            &b"Nails::Fact \"x\"\n"[..],
            "apt refuses /etc/apt/apt.conf.d/99local:2 (Extra junk at end of file): at \
             activation unattended-upgrades' shutdown helper reads apt's configuration again, \
             finds that file refused and installs nothing",
            Some(
                "At the switch unattended-upgrades' shutdown helper writes those two ERROR lines \
                 on the decoy disk, unless it started with the file already refused.",
            ),
        ),
    ] {
        let tmp = stock(UBUNTU_26_04);
        let root = tmp.path();
        write(
            root,
            "etc/systemd/journald.conf",
            b"[Journal]\nStorage=volatile\n",
        );
        write(root, "sys/kernel/kexec_crash_loaded", b"0\n");
        write(root, "etc/apt/apt.conf.d/99local", text);
        let refused = DecoyPersistenceCheck::new(false, false)
            .with_root(root)
            .run(&RealFilesystem)
            .unwrap();
        assert!(refused.is_fail(), "{refused:?}");
        let allowed = DecoyPersistenceCheck::new(true, false)
            .with_root(root)
            .run(&RealFilesystem)
            .unwrap();
        assert!(allowed.is_warn(), "{allowed:?}");
        let message = allowed.message();
        assert!(message.contains(said), "{message}");
        assert!(
            !message.contains("At the switch unattended-upgrades installs"),
            "{message}"
        );
        assert!(
            message.matches("installs nothing").count() <= 1,
            "{message}"
        );
        // The words run as one text, with no gap a wrapped literal leaves,
        // before the host's own warnings.
        let ours = message.split(" Also: ").next().unwrap_or_default();
        assert!(!ours.contains("  "), "{message}");
        match sentence {
            Some(sentence) => assert!(message.contains(sentence), "{message}"),
            None => assert!(!message.contains("At the switch"), "{message}"),
        }
    }
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

/// Where the decoy's `apt.conf.d` holds the entry of the name `name`, by its
/// bytes.
fn part_path(root: &Path, name: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    root.join("etc/apt/apt.conf.d")
        .join(std::ffi::OsStr::from_bytes(name))
}

#[test]
fn a_name_or_a_value_apt_reads_by_the_locale_is_refused_as_if_on() {
    // apt's isalpha() takes 0xe9 for a letter in ISO-8859-1, where apt reads
    // `99caf\xe9`, and skips it in the C locale and a UTF-8 one.
    let tmp = stock(DEBIAN_13);
    std::fs::write(part_path(tmp.path(), b"99caf\xe9"), ON).unwrap();
    let message = blocker(&find(tmp.path())).to_string();
    assert!(message.starts_with("NAILS cannot tell"), "{message}");
    assert!(
        message.contains(
            "/etc/apt/apt.conf.d/99caf\u{fffd} has a name with a byte beyond ASCII, which apt \
             reads or skips by the system's locale"
        ),
        "{message}"
    );
    // A name another rule skips, and what is no file, stay skipped.
    let tmp = stock(DEBIAN_13);
    std::fs::write(part_path(tmp.path(), b"99caf\xe9.bak"), ON).unwrap();
    std::fs::create_dir(part_path(tmp.path(), b"99d\xe9")).unwrap();
    assert_eq!(find(tmp.path()), Finding::default());

    // strcasecmp() reads `W\xddTH` as `with` in tr_TR.ISO-8859-9.
    let tmp = stock(UBUNTU_24_04);
    write(
        tmp.path(),
        "etc/apt/apt.conf.d/99local",
        b"Unattended-Upgrade::InstallOnShutdown \"W\xddTH\";\n",
    );
    let found = find(tmp.path());
    let message = blocker(&found);
    assert!(
        message.contains(
            "/etc/apt/apt.conf.d/99local:1 sets it to a value with a byte beyond ASCII, which apt \
             reads by the system's locale"
        ),
        "{message}"
    );
    assert_eq!(
        found.blocker.as_ref().unwrap().at_the_switch,
        AtTheSwitch::Unknown
    );
    // Only the value read last counts.
    write(tmp.path(), "etc/apt/apt.conf.d/99zz-off", OFF.as_bytes());
    assert_eq!(find(tmp.path()), Finding::default());
}

#[test]
fn a_file_of_the_most_nails_reads_is_read() {
    let fs = mock_decoy(true, &[("99local", Some(ON))]);
    fs.mock_set_file_size("/etc/apt/apt.conf.d/99local", FILE_LIMIT);
    let found = finding(&fs, Path::new("/"), None);
    assert!(
        blocker(&found).contains("is on in /etc/apt/apt.conf.d/99local:1"),
        "{found:?}"
    );
}

#[test]
fn a_link_among_apts_files_leaves_the_sessions_setting_unknown() {
    // The decoy's part links to a file the session edited: the session's
    // helper reads the edit through the overlay, NAILS the decoy's file.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    install_gi(root);
    write(root, "etc/apt/apt.conf.d/50unattended-upgrades", DEBIAN_13);
    write(root, "etc/apt/x.conf", OFF.as_bytes());
    link(root, "etc/apt/apt.conf.d/99x", "../x.conf");
    enable_helper(root);
    let upper = tempfile::tempdir().unwrap();
    write(upper.path(), "etc/apt/x.conf", ON.as_bytes());
    let found = find_with_upper(root, upper.path());
    assert!(found.blocker.is_none(), "{found:?}");
    let warning = found.warning.expect("a warning");
    assert!(
        warning.contains(
            "NAILS cannot tell whether Unattended-Upgrade::InstallOnShutdown is on there"
        ),
        "{warning}"
    );
    assert!(
        warning.contains(
            "/etc/apt/apt.conf.d/99x is a symbolic link, which NAILS does not follow through the \
             hidden session's overlay"
        ),
        "{warning}"
    );
    // The decoy's own helper follows it on the decoy, and so does NAILS.
    run_helper(root);
    write(root, "etc/apt/x.conf", ON.as_bytes());
    assert!(
        blocker(&find_with_upper(root, upper.path()))
            .contains("is on in /etc/apt/apt.conf.d/99x:1"),
        "{:?}",
        find_with_upper(root, upper.path())
    );

    // A link the overlay holds among apt's files, and the main file.
    for rel in ["etc/apt/apt.conf.d/99session", "etc/apt/apt.conf"] {
        let tmp = stock(UBUNTU_26_04);
        let upper = tempfile::tempdir().unwrap();
        write(upper.path(), "srv/on.conf", ON.as_bytes());
        link(upper.path(), rel, "/srv/on.conf");
        let warning = find_with_upper(tmp.path(), upper.path())
            .warning
            .expect("a warning");
        assert!(
            warning.contains(&format!(
                "/{rel} in the hidden session's overlay is a symbolic link"
            )),
            "{warning}"
        );
    }

    // A directory on the way that is a link on the decoy.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    install_gi(root);
    write(root, "srv/apt.conf.d/50unattended-upgrades", UBUNTU_24_04);
    std::fs::create_dir_all(root.join("etc/apt")).unwrap();
    link(root, "etc/apt/apt.conf.d", "../../srv/apt.conf.d");
    enable_helper(root);
    let upper = tempfile::tempdir().unwrap();
    let warning = find_with_upper(root, upper.path())
        .warning
        .expect("a warning");
    assert!(
        warning.contains(
            "/etc/apt/apt.conf.d on the decoy is a symbolic link, which NAILS does not follow \
             through the hidden session's overlay"
        ),
        "{warning}"
    );
    // The decoy alone reads it through the link, as its helper does.
    assert_eq!(find(root), Finding::default());
}

#[test]
fn a_session_without_etc_apt_reads_no_setting() {
    // The decoy turns the setting on and its helper is stopped but enabled.
    for gone in ["/hidden/upper/etc", "/hidden/upper/etc/apt"] {
        let fs = mock_decoy(false, &[("99on", Some(ON))]);
        mock_enable(&fs);
        assert!(
            finding(&fs, Path::new("/"), None).warning.is_some(),
            "{gone}"
        );
        fs.mock_set_path_type("/hidden/upper/etc", PathKind::Dir);
        fs.mock_set_whiteout(gone);
        assert_eq!(
            finding(&fs, Path::new("/"), Some(Path::new("/hidden/upper"))),
            Finding::default(),
            "{gone}"
        );
    }
}

/// The helper enabled on the mock decoy, as its package enables it.
fn mock_enable(fs: &MockFilesystem) {
    fs.mock_set_directory_contents(
        Path::new("/etc/systemd/system"),
        vec![PathBuf::from("/etc/systemd/system/multi-user.target.wants")],
    );
    fs.mock_set_is_symlink(
        "/etc/systemd/system/multi-user.target.wants/unattended-upgrades.service",
        true,
    );
}

#[test]
fn the_session_unmasks_the_decoys_mask_with_anything_but_a_mask() {
    // A whiteout of the decoy's mask.
    let fs = mock_decoy(false, &[("99on", Some(ON))]);
    mock_enable(&fs);
    fs.create_symlink(
        Path::new("/dev/null"),
        Path::new("/etc/systemd/system/unattended-upgrades.service"),
    )
    .unwrap();
    let upper = Some(Path::new("/hidden/upper"));
    assert_eq!(finding(&fs, Path::new("/"), upper), Finding::default());
    fs.mock_set_whiteout("/hidden/upper/etc/systemd/system/unattended-upgrades.service");
    let warning = finding(&fs, Path::new("/"), upper)
        .warning
        .expect("a warning");
    assert!(
        warning.starts_with(
            "unattended-upgrades.service is masked on the decoy, but the hidden session's overlay \
             unmasks it, so the session starts it"
        ),
        "{warning}"
    );

    // A unit file of the session's own in the mask's place.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(root, "etc/apt/apt.conf.d/99on", ON.as_bytes());
    enable_helper(root);
    link(
        root,
        "etc/systemd/system/unattended-upgrades.service",
        "/dev/null",
    );
    let upper = tempfile::tempdir().unwrap();
    write(
        upper.path(),
        "etc/systemd/system/unattended-upgrades.service",
        b"[Service]\nExecStart=/usr/share/unattended-upgrades/unattended-upgrade-shutdown \
          --wait-for-signal\n",
    );
    let warning = find_with_upper(root, upper.path())
        .warning
        .expect("a warning");
    assert!(
        warning.starts_with("unattended-upgrades.service is masked on the decoy, but"),
        "{warning}"
    );

    // Enabled in the overlay alone, and unmasked there.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(root, "etc/apt/apt.conf.d/99on", ON.as_bytes());
    link(
        root,
        "etc/systemd/system/unattended-upgrades.service",
        "/dev/null",
    );
    enable_helper(upper.path());
    let warning = find_with_upper(root, upper.path())
        .warning
        .expect("a warning");
    assert!(
        warning.starts_with(
            "unattended-upgrades.service is masked on the decoy, but the hidden session's overlay \
             unmasks and enables it, so the session starts it"
        ),
        "{warning}"
    );
}

#[test]
fn what_nails_cannot_tell_of_the_session_is_said_so() {
    let start: Result<SessionStart, String> = Err("a lookup failed".to_string());
    let warning = session_warning(
        &start,
        false,
        Setting::On("/etc/apt/apt.conf.d/99on:1".to_string()),
    )
    .expect("a warning");
    assert!(
        warning.starts_with(
            "NAILS cannot tell whether the hidden session starts its own copy of \
             unattended-upgrades' shutdown helper (a lookup failed), and \
             Unattended-Upgrade::InstallOnShutdown is on there (/etc/apt/apt.conf.d/99on:1): if \
             the session starts it, it installs"
        ),
        "{warning}"
    );
    assert!(
        session_warning(&start, false, Setting::Off).is_none(),
        "nothing installs"
    );
    let unknown =
        session_warning(&start, true, Setting::Unknown("why".to_string())).expect("a warning");
    assert!(unknown.starts_with("NAILS cannot tell whether the hidden session starts"));
    assert!(unknown.ends_with(": why"), "{unknown}");
    assert_eq!(
        way_back(Some(&start)),
        ", and NAILS cannot tell whether a session's own copy installs them again, into its \
         overlay on the hidden volume, when the session ends with deactivate (a lookup failed)"
    );
    assert_eq!(way_back(None), "");
}

/// The helper runs and started before every file the test writes, in 2001:
/// whatever of apt's configuration it reads changed since.
fn run_helper_long_ago(root: &Path) {
    run_helper_since(root, 1_000_000_000, &environ(&[]));
}

#[test]
fn a_setting_no_file_sets_is_refused_after_a_change_since_the_helper_started() {
    // The stock files of each release set nothing, so what the helper read
    // when it started counts: a line deleted since stays in effect.
    for release in [DEBIAN_13, UBUNTU_24_04, UBUNTU_26_04] {
        let tmp = stock(release);
        run_helper_long_ago(tmp.path());
        let found = find(tmp.path());
        let refusal = found.blocker.as_ref().expect("a refusal");
        let message = &refusal.finding;
        assert!(message.starts_with("NAILS cannot tell"), "{message}");
        assert!(
            message.contains(
                "so it counts as on: no file of apt's configuration sets it now, but /etc/apt \
                 changed after the helper started, and the helper keeps what it read when it \
                 started, the value of a line deleted since included, until it restarts"
            ),
            "{message}"
        );
        assert!(
            refusal.fix.starts_with(
                "set `Unattended-Upgrade::InstallOnShutdown \"false\";` on the decoy in a file of \
                 /etc/apt/apt.conf.d, which the helper reads again at the switch"
            ),
            "{}",
            refusal.fix
        );
        assert!(
            refusal.fix.contains("or reboot the decoy"),
            "{}",
            refusal.fix
        );
        assert_eq!(refusal.at_the_switch, AtTheSwitch::Unknown);
    }
    // A false or a #clear, of the setting or of its scope, wins at the
    // signal over what the helper kept.
    for text in [
        OFF,
        "#clear Unattended-Upgrade::InstallOnShutdown;\n",
        "#clear Unattended-Upgrade;\n",
    ] {
        let tmp = stock(DEBIAN_13);
        run_helper_long_ago(tmp.path());
        write(tmp.path(), "etc/apt/apt.conf.d/99local", text.as_bytes());
        assert_eq!(find(tmp.path()).blocker, None, "{text}");
    }
    // A helper started after every change reads what the files say.
    let tmp = stock(UBUNTU_26_04);
    assert_eq!(find(tmp.path()).blocker, None);
    // So does the hidden session's copy, which starts afresh: a helper only
    // stopped but enabled keeps nothing.
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "etc/apt/apt.conf.d/50unattended-upgrades",
        DEBIAN_13,
    );
    enable_helper(tmp.path());
    assert_eq!(find(tmp.path()).blocker, None);
}

/// A mock decoy whose helper runs with the stock files of Debian 13, its
/// marker made at `marker` and its process started at `process` seconds
/// since the epoch, and each of apt's files and directories changed at
/// `files`, but the one at `late`, which changed at `late_at`.
fn mock_times(marker: u64, process: u64, files: u64, late: &str, late_at: u64) -> MockFilesystem {
    use std::time::{Duration, UNIX_EPOCH};
    let stock = String::from_utf8_lossy(DEBIAN_13).into_owned();
    let fs = mock_decoy(true, &[("50unattended-upgrades", Some(&stock))]);
    fs.mock_set_path_type("/etc/apt", PathKind::Dir);
    let at = |secs: u64| UNIX_EPOCH + Duration::from_secs(secs);
    fs.mock_set_change_time(
        "/run/systemd/units/invocation:unattended-upgrades.service",
        at(marker),
    );
    // Started an hour after the boot.
    fs.mock_add_file("/proc/stat", &format!("btime {}\n", process - 3600));
    for path in [
        "/etc/apt",
        "/etc/apt/apt.conf.d",
        "/etc/apt/apt.conf.d/50unattended-upgrades",
    ] {
        fs.mock_set_change_time(path, at(files));
    }
    fs.mock_set_change_time(late, at(late_at));
    fs
}

#[test]
fn the_earlier_of_the_marker_and_the_process_start_is_when_the_helper_started() {
    let t = 2_000_000_000;
    let part = "/etc/apt/apt.conf.d/50unattended-upgrades";
    // Nothing changed after either.
    let fs = mock_times(t, t, t - 100, part, t - 100);
    assert_eq!(finding(&fs, Path::new("/"), None).blocker, None);
    // A part changed after the marker, before the process started: the
    // clock may have been set back in between.
    let fs = mock_times(t, t + 100, t - 100, part, t + 50);
    let found = finding(&fs, Path::new("/"), None);
    assert!(
        blocker(&found).contains(&format!("but {part} changed after the helper started")),
        "{found:?}"
    );
    // A part changed after the process started, before the marker: the
    // clock may have been set forward.
    let fs = mock_times(t + 100, t, t - 100, part, t + 50);
    assert!(finding(&fs, Path::new("/"), None).blocker.is_some());
    // The directory, where a deleted part shows.
    let fs = mock_times(t, t, t - 100, "/etc/apt/apt.conf.d", t + 1);
    assert!(
        blocker(&finding(&fs, Path::new("/"), None))
            .contains("but /etc/apt/apt.conf.d changed after the helper started")
    );
    // A change in the second the helper started counts, as a filesystem
    // may keep change times to the second.
    let fs = mock_times(t, t, t - 100, part, t);
    assert!(finding(&fs, Path::new("/"), None).blocker.is_some());
    let fs = mock_times(t, t, t - 100, part, t - 1);
    assert_eq!(finding(&fs, Path::new("/"), None).blocker, None);
}

#[test]
fn a_link_among_apts_files_leaves_a_setting_no_file_sets_unknown() {
    // The files are older than the helper, but where a link leads NAILS
    // does not follow when that changed.
    let fs = mock_times(2_000_000_000, 2_000_000_000, 1_000, "/etc/apt", 1_000);
    // The mock looks up a file where its link leads and reads it by the
    // path it is given.
    fs.mock_add_file("/srv/99linked", "");
    fs.create_symlink(
        Path::new("/srv/99linked"),
        Path::new("/etc/apt/apt.conf.d/99linked"),
    )
    .unwrap();
    fs.mock_set_file_bytes("/etc/apt/apt.conf.d/99linked", b"// nothing set here\n");
    fs.mock_set_directory_contents(
        Path::new("/etc/apt/apt.conf.d"),
        vec![
            PathBuf::from("/etc/apt/apt.conf.d/50unattended-upgrades"),
            PathBuf::from("/etc/apt/apt.conf.d/99linked"),
        ],
    );
    let found = finding(&fs, Path::new("/"), None);
    assert!(
        blocker(&found).contains(
            "but /etc/apt/apt.conf.d/99linked is reached through a symbolic link, so NAILS \
             cannot tell whether what it leads to changed after the helper started"
        ),
        "{found:?}"
    );
    // A false set in a file wins, link or not.
    fs.mock_set_file_bytes("/etc/apt/apt.conf.d/99linked", OFF.as_bytes());
    assert_eq!(finding(&fs, Path::new("/"), None).blocker, None);
}

#[test]
fn what_nails_cannot_read_of_the_running_helper_is_refused_as_if_on() {
    // No /proc/stat: when the helper started cannot be told, which counts
    // where no file sets the setting.
    let tmp = stock(DEBIAN_13);
    std::fs::remove_file(tmp.path().join("proc/stat")).unwrap();
    let message = blocker(&find(tmp.path())).to_string();
    assert!(
        message.contains("when unattended-upgrades.service started cannot be read: /proc/stat"),
        "{message}"
    );
    // But not where a file sets it.
    write(tmp.path(), "etc/apt/apt.conf.d/99local", OFF.as_bytes());
    assert_eq!(find(tmp.path()).blocker, None);

    // A /proc/<pid>/stat that is none.
    let tmp = stock(DEBIAN_13);
    write(
        tmp.path(),
        &format!("proc/{PID}/stat"),
        b"412 (unattended-upgr\n",
    );
    let message = blocker(&find(tmp.path())).to_string();
    assert!(message.contains("/proc/412/stat is not one"), "{message}");

    // No process in the unit's cgroup: what the helper reads first cannot
    // be told, whatever the files say.
    let tmp = stock(DEBIAN_13);
    write(tmp.path(), &format!("{CGROUP}/cgroup.procs"), b"");
    write(tmp.path(), "etc/apt/apt.conf.d/99local", OFF.as_bytes());
    let message = blocker(&find(tmp.path())).to_string();
    assert!(
        message.contains(
            "/sys/fs/cgroup/system.slice/unattended-upgrades.service/cgroup.procs lists no \
             process of unattended-upgrades.service"
        ),
        "{message}"
    );

    // An environment NAILS cannot read, as of a process gone since its
    // cgroup was listed: no claim that root could.
    let fs = MockFilesystem::new();
    mock_run_helper(&fs, None);
    mock_parts(&fs, "/etc/apt/apt.conf.d", &[("99local", Some(OFF))]);
    let found = finding(&fs, Path::new("/"), None);
    let refusal = found.blocker.as_ref().expect("a refusal");
    assert!(
        refusal.finding.contains(
            "the environment of unattended-upgrades.service (PID 412), where apt takes APT_CONFIG \
             from, cannot be read ("
        ),
        "{}",
        refusal.finding
    );
    assert!(
        !refusal.finding.contains("only root can read it"),
        "{}",
        refusal.finding
    );
    assert_eq!(refusal.at_the_switch, AtTheSwitch::Unknown);
}

#[test]
fn an_environment_the_kernel_refuses_is_one_only_root_can_tell() {
    use std::os::unix::fs::PermissionsExt;
    // The helper's environment, as /proc shows it to all but root.
    let tmp = stock(DEBIAN_13);
    let environ = tmp.path().join(format!("proc/{PID}/environ"));
    std::fs::set_permissions(&environ, std::fs::Permissions::from_mode(0o000)).unwrap();
    let found = find(tmp.path());
    if nix::unistd::geteuid().is_root() {
        // Root reads it whatever its mode, as it reads the helper's.
        assert_eq!(found.blocker, None);
        return;
    }
    let refusal = found.blocker.as_ref().expect("a refusal");
    assert!(
        refusal.finding.starts_with("NAILS cannot tell"),
        "{}",
        refusal.finding
    );
    assert!(
        refusal.finding.contains(
            "the environment of unattended-upgrades.service (PID 412), where apt takes APT_CONFIG \
             from, cannot be read ("
        ),
        "{}",
        refusal.finding
    );
    assert!(
        refusal.finding.ends_with("; only root can read it"),
        "{}",
        refusal.finding
    );
    assert_eq!(refusal.at_the_switch, AtTheSwitch::NeedsRoot);
    assert!(
        refusal.fix.starts_with("run the check as root (`sudo "),
        "{}",
        refusal.fix
    );
    assert!(refusal.fix.contains(" check`)"), "{}", refusal.fix);
}

/// A stock decoy of `release` whose helper runs with `APT_CONFIG` set to
/// `value`, started after every file the test writes.
fn stock_with_apt_config(release: &[u8], value: &str) -> tempfile::TempDir {
    let tmp = stock(release);
    run_helper_since(
        tmp.path(),
        now() + 86_400,
        &environ(&[&format!("APT_CONFIG={value}")]),
    );
    tmp
}

#[test]
fn the_file_the_helpers_apt_config_names_is_read_first() {
    // The setting turned on where the package's own file has it, in a copy
    // of Debian 13's 50unattended-upgrades that APT_CONFIG names.
    let stock_text = String::from_utf8_lossy(DEBIAN_13);
    let turned_on = stock_text.replace(
        "//Unattended-Upgrade::InstallOnShutdown \"false\";",
        "Unattended-Upgrade::InstallOnShutdown \"true\";",
    );
    assert_ne!(turned_on, stock_text, "the stock file has the line");
    let tmp = stock_with_apt_config(DEBIAN_13, "/etc/nails-apt.conf");
    let root = tmp.path();
    write(root, "etc/nails-apt.conf", turned_on.as_bytes());
    let found = find(root);
    let refusal = found.blocker.as_ref().expect("a refusal");
    assert!(
        refusal.finding.contains(
            "Unattended-Upgrade::InstallOnShutdown is on in the helper's APT_CONFIG file \
             /etc/nails-apt.conf:"
        ),
        "{}",
        refusal.finding
    );
    assert!(
        refusal.fix.contains(
            "in the helper's APT_CONFIG file /etc/nails-apt.conf or in a file of \
             /etc/apt/apt.conf.d that apt reads after it"
        ),
        "{}",
        refusal.fix
    );
    assert_eq!(refusal.at_the_switch, AtTheSwitch::Installs);
    // Every part comes after it: a false there wins.
    write(root, "etc/apt/apt.conf.d/99local", OFF.as_bytes());
    assert_eq!(find(root).blocker, None);
    // Without APT_CONFIG the file is not read.
    let tmp = stock(DEBIAN_13);
    write(tmp.path(), "etc/nails-apt.conf", turned_on.as_bytes());
    assert_eq!(find(tmp.path()).blocker, None);
    // An APT_CONFIG that is empty is none, as apt takes it.
    let tmp = stock_with_apt_config(DEBIAN_13, "");
    assert_eq!(find(tmp.path()).blocker, None);
}

#[test]
fn an_apt_config_nails_cannot_follow_is_refused_as_if_on() {
    for (value, written, why) in [
        (
            "/etc/missing.conf",
            None,
            "the helper's APT_CONFIG file /etc/missing.conf is no file NAILS can read",
        ),
        (
            "etc/relative.conf",
            None,
            "the helper's APT_CONFIG names etc/relative.conf, a relative path",
        ),
        (
            "/etc/apt/../nails-apt.conf",
            Some(("etc/nails-apt.conf", OFF)),
            "has a `..` in its path, which NAILS does not follow",
        ),
        (
            // It moves the parts NAILS reads.
            "/etc/nails-apt.conf",
            Some((
                "etc/nails-apt.conf",
                "Dir::Etc::parts \"/srv/apt.conf.d\";\n",
            )),
            "the helper's APT_CONFIG file /etc/nails-apt.conf:1 sets Dir::Etc::parts",
        ),
    ] {
        let tmp = stock_with_apt_config(UBUNTU_24_04, value);
        if let Some((rel, text)) = written {
            write(tmp.path(), rel, text.as_bytes());
        }
        // A part's false comes after APT_CONFIG but changes nothing here.
        write(tmp.path(), "etc/apt/apt.conf.d/99local", OFF.as_bytes());
        let found = find(tmp.path());
        let message = blocker(&found);
        assert!(message.starts_with("NAILS cannot tell"), "{message}");
        assert!(message.contains(why), "{value}: {message}");
    }

    // Processes of the unit that run with values apart.
    let tmp = stock(UBUNTU_26_04);
    let root = tmp.path();
    write(root, &format!("{CGROUP}/cgroup.procs"), b"412\n413\n");
    write(root, "proc/413/stat", stat_line(413, 3600 * 100).as_bytes());
    write(
        root,
        "proc/413/environ",
        &environ(&["APT_CONFIG=/etc/nails-apt.conf"]),
    );
    let message = blocker(&find(root)).to_string();
    assert!(
        message.contains(
            "the processes of unattended-upgrades.service run with different values of APT_CONFIG"
        ),
        "{message}"
    );
}

#[test]
fn the_session_reads_the_file_apt_config_names_through_its_overlay() {
    let tmp = stock_with_apt_config(UBUNTU_26_04, "/etc/nails/apt.conf");
    let root = tmp.path();
    write(root, "etc/nails/apt.conf", OFF.as_bytes());
    // The decoy's file, which the session sees through its overlay.
    let upper = tempfile::tempdir().unwrap();
    assert_eq!(find_with_upper(root, upper.path()), Finding::default());
    // The session's own copy of it turns the setting on.
    write(upper.path(), "etc/nails/apt.conf", ON.as_bytes());
    let found = find_with_upper(root, upper.path());
    assert!(found.blocker.is_none(), "{found:?}");
    let warning = found.warning.expect("a warning");
    assert!(
        warning.contains(
            "the helper's APT_CONFIG file /etc/nails/apt.conf:1 in the hidden session's overlay"
        ),
        "{warning}"
    );
    // A link on the decoy on the way to it resolves through the overlay.
    let tmp = stock_with_apt_config(UBUNTU_26_04, "/etc/nails/apt.conf");
    let root = tmp.path();
    write(root, "srv/nails/apt.conf", OFF.as_bytes());
    link(
        root,
        "etc/nails",
        &root.join("srv/nails").display().to_string(),
    );
    let upper = tempfile::tempdir().unwrap();
    // The decoy's helper follows it.
    assert_eq!(find(root).blocker, None);
    let warning = find_with_upper(root, upper.path())
        .warning
        .expect("a warning");
    assert!(
        warning.contains(
            "/etc/nails on the decoy is a symbolic link, which NAILS does not follow through the \
             hidden session's overlay"
        ),
        "{warning}"
    );
}

#[test]
fn a_stock_decoy_without_python3_gi_warns_of_the_helpers_lines() {
    // Debian 13's cloud image: the helper enabled, python3-gi not installed.
    let tmp = stock_without_gi(DEBIAN_13);
    write(
        tmp.path(),
        "etc/systemd/journald.conf",
        b"[Journal]\nStorage=volatile\n",
    );
    let found = find(tmp.path());
    assert_eq!(found.blocker, None);
    assert_eq!(found.warning, None);
    let polling = found.polling.expect("a warning");
    assert!(polling.contains("python3-gi is not installed"), "{polling}");
    assert!(polling.ends_with("(apt install python3-gi)"), "{polling}");
    // The check warns of it with the rest.
    let result = DecoyPersistenceCheck::new(false, false)
        .with_root(tmp.path())
        .run(&RealFilesystem)
        .unwrap();
    assert!(
        result.message().contains("python3-gi is not installed"),
        "{result:?}"
    );
}

#[path = "install_on_shutdown/since_start_tests.rs"]
mod since_start;
