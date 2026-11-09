// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! decoy-persistence where a lookup fails, or where the automount guard does
//! not make it: a blocker NAILS cannot tell about counts as one the decoy
//! has and is refused with the same override, a warning it cannot tell
//! about warns, and status and the window's launcher count it as a record
//! the decoy keeps, with why NAILS cannot tell.

use super::*;
use crate::filesystem::MockFilesystem;
use crate::filesystem::automount::mount_fix;
use crate::preflight::checks::automount_fixture::{reached, with_automounts};
use std::io::ErrorKind;

/// A decoy whose journald sets `Storage=storage`, on a `noatime` disk root.
fn decoy(storage: &str) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        &format!("[Journal]\nStorage={storage}\n"),
    );
    fs.mock_add_file(
        MOUNTINFO,
        "36 35 0:32 / / rw,noatime shared:1 - ext4 /dev/sda1 rw\n",
    );
    fs
}

/// The check's result on `fs` of a NixOS decoy, with the override when
/// `allow`.
fn run(fs: &MockFilesystem, allow: bool) -> CheckResult {
    DecoyPersistenceCheck::new(allow, true).run(fs).unwrap()
}

/// Assert that `result` refuses for a record the decoy may keep, saying
/// `says`, and that the override lifts it for the same decoy `fs`.
fn refused_as_untold(fs: &MockFilesystem, result: &CheckResult, says: &str) {
    assert!(result.is_fail(), "{result:?}");
    let message = result.message();
    assert!(
        message.starts_with("decoy keeps, or may keep, a persistent record"),
        "{message}"
    );
    assert!(message.contains(says), "{message}");
    assert_eq!(result.allowable(), Some(Allowable::PersistentDecoy));
    let allowed = run(fs, true);
    assert!(allowed.is_warn(), "{allowed:?}");
    assert!(allowed.message().contains(says), "{allowed:?}");
}

/// Under `Storage=auto` the journal persists when `/var/log/journal` is a
/// directory on the disk. A lookup of it that fails used to count as no
/// directory, and `auto` as volatile; now NAILS cannot tell, and refuses as
/// for a persistent journal. A decoy set to `volatile` or `none` is not
/// refused for it, and status counts it as persistent, saying why.
#[test]
fn under_auto_a_journal_directory_nails_cannot_look_up_is_refused() {
    let fs = decoy("auto");
    fs.mock_set_lookup_error("/var/log/journal", ErrorKind::PermissionDenied);
    let result = run(&fs, false);
    refused_as_untold(
        &fs,
        &result,
        "NAILS cannot tell where systemd-journald keeps the journal, so it counts as \
         persistent: NAILS cannot read /var/log/journal; run the command again with sudo",
    );
    let findings = DecoyPersistenceCheck::persistence(&fs);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(
        findings[0].untold.as_deref(),
        Some("NAILS cannot read /var/log/journal")
    );
    assert!(DecoyPersistenceCheck::decoy_is_persistent(&fs));

    for storage in ["volatile", "none"] {
        let fs = decoy(storage);
        fs.mock_set_lookup_error("/var/log/journal", ErrorKind::PermissionDenied);
        let result = run(&fs, false);
        assert!(result.is_pass(), "{storage}: {result:?}");
        assert!(DecoyPersistenceCheck::persistence(&fs).is_empty());
    }
}

/// A journal directory behind an automount point that nothing is mounted on
/// yet is not looked up: the refusal names the point and says once how to
/// mount it, and nothing at or below the point is looked up.
#[test]
fn a_journal_directory_behind_an_automount_point_is_refused_without_a_lookup() {
    let point = "/var/log/journal";
    let fs = decoy("auto");
    with_automounts(&fs, &[point]);
    let result = run(&fs, false);
    refused_as_untold(
        &fs,
        &result,
        "NAILS does not look up /var/log/journal, since the lookup would mount the automount \
         point /var/log/journal",
    );
    let fix = mount_fix(&[Path::new(point)]);
    let remediation = result.remediation().expect("the refusal names its fix");
    assert!(remediation.contains(&fix), "{remediation}");
    let said = format!("{}\n{remediation}", result.message());
    assert_eq!(said.matches(fix.as_str()).count(), 1, "{said}");
    assert!(!reached(&fs, point), "{:?}", fs.mock_lookups());
}

/// Without a mount table nothing is looked up, and the check cannot rule a
/// blocker out: it refuses, with the override. Status and the window's
/// launcher count the decoy as persistent, and kdump as armed.
#[test]
fn without_a_mount_table_nothing_is_looked_up_and_the_check_refuses() {
    let fs = decoy("volatile");
    fs.mock_set_mount_table_error("no mountinfo");
    let result = run(&fs, false);
    refused_as_untold(
        &fs,
        &result,
        "NAILS cannot read the mount table (/proc/self/mountinfo: no mountinfo), which shows \
         where a lookup would mount an automount point, so it looks up nothing",
    );
    assert_eq!(fs.mock_lookups(), Vec::<PathBuf>::new());
    let findings = DecoyPersistenceCheck::persistence(&fs);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].untold.is_some(), "{findings:?}");
    let kdump = DecoyPersistenceCheck::kdump_on_decoy(&fs).expect("kdump cannot be told");
    assert!(kdump.untold.is_some(), "{kdump:?}");
    assert_eq!(fs.mock_lookups(), Vec::<PathBuf>::new());
}

/// A crash-kernel marker whose lookup fails cannot tell whether kdump is
/// armed: refused as if it were, which the same override lifts, and status
/// counts kdump as armed.
#[test]
fn a_crash_kernel_marker_that_cannot_be_looked_up_refuses_as_armed() {
    let fs = decoy("volatile");
    fs.mock_set_lookup_error(KEXEC_CRASH_LOADED, ErrorKind::Other);
    let result = run(&fs, false);
    refused_as_untold(
        &fs,
        &result,
        "cannot tell whether kdump is armed: /sys/kernel/kexec_crash_loaded cannot be probed (",
    );
    assert!(DecoyPersistenceCheck::decoy_kdump_armed(&fs));
    let kdump = DecoyPersistenceCheck::kdump_on_decoy(&fs).expect("refused as armed");
    assert!(
        kdump
            .untold
            .as_deref()
            .is_some_and(|why| why.starts_with("/sys/kernel/kexec_crash_loaded cannot be probed")),
        "{kdump:?}"
    );
}

/// The unit directory `/etc/systemd/system` of `fs` lists the dependency
/// directory `multi-user.target.wants`.
fn wants_dir(fs: &MockFilesystem) -> &'static str {
    let wants = "/etc/systemd/system/multi-user.target.wants";
    fs.mock_set_directory_contents(Path::new("/etc/systemd/system"), vec![PathBuf::from(wants)]);
    wants
}

/// An enabling link of a kdump unit that cannot be looked up may enable it:
/// refused as if kdump were armed. An enabling link found, whose mask cannot
/// be looked up, counts the unit as enabled unless it is masked, and is
/// refused the same way.
#[test]
fn a_kdump_unit_nails_cannot_tell_is_enabled_refuses_as_armed() {
    let fs = decoy("volatile");
    let wants = wants_dir(&fs);
    fs.mock_set_lookup_error(wants, ErrorKind::Other);
    let result = run(&fs, false);
    refused_as_untold(
        &fs,
        &result,
        "cannot tell whether kdump is armed: NAILS cannot tell whether kdump-tools.service is \
         enabled: NAILS cannot look up /etc/systemd/system/multi-user.target.wants/\
         kdump-tools.service (",
    );
    assert!(
        result
            .message()
            .contains("so it is refused as if kdump were armed"),
        "{result:?}"
    );

    let fs = decoy("volatile");
    let wants = wants_dir(&fs);
    fs.create_symlink(
        Path::new("/lib/systemd/system/kdump-tools.service"),
        &Path::new(wants).join("kdump-tools.service"),
    )
    .unwrap();
    fs.mock_set_lookup_error(
        "/etc/systemd/system/kdump-tools.service",
        ErrorKind::PermissionDenied,
    );
    let result = run(&fs, false);
    refused_as_untold(
        &fs,
        &result,
        "kdump-tools.service is enabled unless /etc/systemd/system/kdump-tools.service masks \
         it, which NAILS cannot tell: NAILS cannot look up /etc/systemd/system/kdump-tools.\
         service; run the command again with sudo",
    );
}

/// The `syslog.service` alias names the enabled syslog daemon. One NAILS
/// cannot look up may name a daemon that writes logs to the decoy disk:
/// refused, with the override.
#[test]
fn a_syslog_alias_nails_cannot_look_up_refuses() {
    let fs = decoy("volatile");
    fs.mock_set_lookup_error("/etc/systemd/system/syslog.service", ErrorKind::Other);
    let result = run(&fs, false);
    refused_as_untold(
        &fs,
        &result,
        "NAILS cannot tell which daemon syslog.service names: NAILS cannot look up \
         /etc/systemd/system/syslog.service (",
    );
}

/// Without a daemon found by its own names, an enabled `syslog.service`
/// counts: one whose invocation marker NAILS cannot look up may run, and
/// is refused with the override.
#[test]
fn a_syslog_service_nails_cannot_tell_runs_refuses() {
    let fs = decoy("volatile");
    fs.mock_set_lookup_error(
        "/run/systemd/units/invocation:syslog.service",
        ErrorKind::Other,
    );
    let result = run(&fs, false);
    refused_as_untold(
        &fs,
        &result,
        "NAILS cannot tell whether syslog.service runs: NAILS cannot look up \
         /run/systemd/units/invocation:syslog.service (",
    );
}

/// A `syslog.service` link that names no other service, such as a mask in
/// `/etc/systemd/system`, names no daemon: the next unit directory's link
/// names it, as before NAILS told a lookup that failed from no link.
#[test]
fn a_syslog_alias_that_names_no_service_is_passed_over() {
    let fs = decoy("volatile");
    fs.create_symlink(
        Path::new("/dev/null"),
        Path::new("/etc/systemd/system/syslog.service"),
    )
    .unwrap();
    fs.create_symlink(
        Path::new("/usr/lib/systemd/system/nanolog.service"),
        Path::new("/usr/lib/systemd/system/syslog.service"),
    )
    .unwrap();
    fs.create_symlink(
        Path::new("8028a17235414b4e80c950b24a7487d7"),
        Path::new("/run/systemd/units/invocation:nanolog.service"),
    )
    .unwrap();
    let result = run(&fs, false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().contains(
            "a syslog daemon (nanolog.service, enabled as syslog.service) is active and writes \
             logs to the decoy disk"
        ),
        "{result:?}"
    );
}

/// A unit whose invocation marker cannot be looked up may run: a logger's
/// refuses as active, kdump's refuses as armed, and sssd's warns that NAILS
/// cannot tell whether sssd is in use. A route that shows the unit running
/// still counts it as active.
#[test]
fn a_unit_nails_cannot_tell_runs_counts_as_one_that_may() {
    let marker = |unit: &str| format!("/run/systemd/units/invocation:{unit}");
    let fs = decoy("volatile");
    fs.mock_set_lookup_error(&marker("rsyslog.service"), ErrorKind::Other);
    let result = run(&fs, false);
    refused_as_untold(
        &fs,
        &result,
        "NAILS cannot tell whether rsyslog.service runs: NAILS cannot look up \
         /run/systemd/units/invocation:rsyslog.service (",
    );
    let findings = DecoyPersistenceCheck::persistence(&fs);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].untold.is_some(), "{findings:?}");

    // Its cgroup shows it running: a record the decoy keeps.
    fs.mock_add_file(
        "/sys/fs/cgroup/system.slice/rsyslog.service/cgroup.events",
        "populated 1\n",
    );
    let result = run(&fs, false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .starts_with("decoy keeps a persistent record"),
        "{result:?}"
    );
    assert!(result.message().contains("rsyslog is active"), "{result:?}");

    let fs = decoy("volatile");
    fs.mock_set_lookup_error(&marker("kdump-tools.service"), ErrorKind::Other);
    refused_as_untold(
        &fs,
        &run(&fs, false),
        "cannot tell whether kdump is armed: NAILS cannot tell whether kdump-tools.service \
         runs: NAILS cannot look up /run/systemd/units/invocation:kdump-tools.service (",
    );

    let fs = decoy("volatile");
    fs.mock_set_lookup_error(&marker("sssd.service"), ErrorKind::Other);
    let result = run(&fs, false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains(
            "NAILS cannot tell whether sssd is in use on the decoy: NAILS cannot tell whether \
             sssd.service runs: NAILS cannot look up /run/systemd/units/invocation:sssd.service ("
        ),
        "{result:?}"
    );
}

/// A state file of sssd whose lookup fails may show sssd in use: it warns,
/// and the `rm` advice leaves out a file NAILS cannot tell is there. A
/// directory of the KCM unit that cannot be looked up may hold the unit, so
/// the socket stays sssd's.
#[test]
fn an_sssd_place_nails_cannot_look_up_warns() {
    let fs = decoy("volatile");
    fs.mock_set_lookup_error("/var/lib/sss/db", ErrorKind::PermissionDenied);
    fs.mock_set_path_type("/var/lib/sss/mc/passwd", crate::filesystem::PathKind::File);
    let finding = sssd::sssd_finding(&fs, Path::new("/"), false).expect("sssd warns");
    assert!(
        finding.starts_with(
            "sssd is in use on the decoy (/var/lib/sss/mc/passwd holds its state), and NAILS \
             cannot tell all it would show: NAILS cannot tell whether \
             /var/lib/sss/db/config.ldb is there: NAILS cannot look up \
             /var/lib/sss/db/config.ldb; run the command again with sudo."
        ),
        "{finding}"
    );
    assert!(finding.contains("(rm /var/lib/sss/mc/passwd)"), "{finding}");

    let fs = decoy("volatile");
    fs.mock_set_lookup_error("/var/lib/sss", ErrorKind::Other);
    let result = run(&fs, false);
    assert!(result.is_warn(), "{result:?}");
    let message = result.message();
    assert!(
        message.contains(
            "NAILS cannot tell whether sssd is in use on the decoy: NAILS cannot tell whether \
             /var/lib/sss/db/config.ldb is there: NAILS cannot look up \
             /var/lib/sss/db/config.ldb ("
        ),
        "{message}"
    );
    assert!(!message.contains("rm /var/lib/sss"), "{message}");
    // The first file NAILS cannot tell about stands for the rest beside it.
    assert_eq!(message.matches("/var/lib/sss/mc").count(), 0, "{message}");
}

/// A unit directory whose lookup fails may hold `sssd-kcm.socket`, so a KCM
/// socket a root `kcm` serves still counts as sssd's.
#[test]
fn a_kcm_unit_directory_nails_cannot_look_up_keeps_the_socket_sssds() {
    let fs = decoy("volatile");
    fs.mock_set_path_type(
        "/run/.heim_org.h5l.kcm-socket",
        crate::filesystem::PathKind::File,
    );
    fs.mock_add_file(
        "/proc/1/net/unix",
        "Num       RefCount Protocol Flags    Type St Inode Path\n\
         0000000000000000: 00000002 00000000 00010000 0001 01 23456 \
         /run/.heim_org.h5l.kcm-socket\n",
    );
    fs.mock_set_inode(Path::new("/proc/1/ns/mnt"), 7);
    fs.mock_set_inode(Path::new("/proc/731/ns/mnt"), 7);
    fs.mock_add_file("/proc/731/comm", "kcm\n");
    fs.mock_add_file("/proc/731/status", "Uid:\t0\t0\t0\t0\n");
    fs.mock_set_directory_contents(Path::new("/proc"), vec![PathBuf::from("/proc/731")]);
    // With every unit directory missing, the socket is Heimdal's.
    assert_eq!(sssd::sssd_finding(&fs, Path::new("/"), false), None);
    // The lookup of a directory on the way to one fails, where `is_symlink`
    // used to answer that no link is there.
    fs.mock_set_path_type("/usr", crate::filesystem::PathKind::Dir);
    fs.mock_set_lookup_error("/usr/local", ErrorKind::PermissionDenied);
    let finding = sssd::sssd_finding(&fs, Path::new("/"), false).expect("the socket counts");
    assert!(
        finding.contains("its Kerberos ticket cache listens on /run/.heim_org.h5l.kcm-socket"),
        "{finding}"
    );
}

/// A blocker NAILS cannot tell about refuses, while a warning it cannot tell
/// about warns: the guard did not list an include directory of sudoers,
/// which a reader passes over, and the warnings' own view settles it as a
/// warning, naming the point and saying how to mount it.
#[test]
fn a_warning_part_the_guard_does_not_look_at_warns() {
    let fs = decoy("volatile");
    with_automounts(&fs, &["/srv"]);
    fs.mock_add_file(
        "/etc/sudoers",
        "Defaults env_reset\n@includedir /srv/sudoers.d\n",
    );
    let result = run(&fs, false);
    assert!(result.is_warn(), "{result:?}");
    let message = result.message();
    assert!(
        message.starts_with(
            "NAILS cannot tell about everything it checks: NAILS does not look up \
             /srv/sudoers.d, since the lookup would mount the automount point /srv."
        ),
        "{message}"
    );
    assert!(
        message.contains("Where it could look: decoy keeps no durable trace"),
        "{message}"
    );
    assert!(
        message.ends_with(&mount_fix(&[Path::new("/srv")])),
        "{message}"
    );
    assert!(!reached(&fs, "/srv"), "{:?}", fs.mock_lookups());
}

/// The kdump probe of status reads through the guard too: a unit directory
/// it did not look up, which the probe itself passes over, may hold an
/// enabling link, and kdump counts as armed, or NAILS cannot tell.
#[test]
fn the_kdump_probe_of_status_counts_a_directory_it_did_not_look_up() {
    let fs = decoy("volatile");
    with_automounts(&fs, &["/lib"]);
    let kdump = DecoyPersistenceCheck::kdump_on_decoy(&fs).expect("kdump cannot be told");
    assert_eq!(
        kdump.untold.as_deref(),
        Some(
            "NAILS does not look up /lib/systemd/system, since the lookup would mount the \
             automount point /lib"
        )
    );
    assert!(DecoyPersistenceCheck::decoy_kdump_armed(&fs));
    assert!(!reached(&fs, "/lib"), "{:?}", fs.mock_lookups());
    // An amnesic decoy without the point has no kdump finding.
    assert_eq!(
        DecoyPersistenceCheck::kdump_on_decoy(&decoy("volatile")),
        None
    );
}

/// nixos-upgrade.timer, whose lookup fails, may be enabled: a warning, as
/// for an enabled one. Only NixOS looks it up.
#[test]
fn a_nixos_upgrade_timer_nails_cannot_look_up_warns() {
    let fs = decoy("volatile");
    fs.mock_set_lookup_error(NIXOS_UPGRADE_TIMER, ErrorKind::PermissionDenied);
    let result = run(&fs, false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains(
            "NAILS cannot tell whether nixos-upgrade.timer is enabled, which can rebuild the \
             decoy (and touch EFI NVRAM) while the hidden session is active: NAILS cannot look \
             up /etc/systemd/system/timers.target.wants/nixos-upgrade.timer; run the command \
             again with sudo"
        ),
        "{result:?}"
    );
    let elsewhere = DecoyPersistenceCheck::new(false, false).run(&fs).unwrap();
    assert!(elsewhere.is_pass(), "{elsewhere:?}");
}
