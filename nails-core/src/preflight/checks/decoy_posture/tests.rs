// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::RealFilesystem;
use crate::filesystem::{MockFilesystem, PathKind};

/// Mark a systemd unit active by creating its runtime invocation marker.
fn set_unit_active(fs: &MockFilesystem, unit: &str) {
    let marker = format!("/{}/invocation:{unit}", loggers::INVOCATION_DIR);
    fs.mock_set_path_exists(&marker, true);
}

/// A mountinfo with a single `/` entry of the given fstype and options.
fn root_mountinfo(fstype: &str, opts: &str) -> String {
    format!("36 35 0:32 / / {opts} shared:1 - {fstype} /dev/sda1 rw\n")
}

#[test]
fn clean_decoy_on_a_disk_root_passes() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));

    let check = DecoyPersistenceCheck::new(false, true);
    let result = check.run(&fs).unwrap();
    assert!(result.is_pass(), "clean decoy must pass: {result:?}");
}

#[test]
fn sudo_io_logging_warns() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
    fs.mock_add_file(
        "/etc/sudoers",
        "Defaults env_reset\nDefaults log_output\nDefaults logfile=/var/log/sudo.log\n",
    );

    let result = DecoyPersistenceCheck::new(false, true).run(&fs).unwrap();
    assert!(result.is_warn(), "sudo I/O logging must warn: {result:?}");
    assert!(result.message().contains("sudo I/O logging"), "{result:?}");
    assert!(result.message().contains("/var/log/sudo.log"), "{result:?}");
}

#[test]
fn persistent_journal_fails_closed() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=persistent\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));

    let check = DecoyPersistenceCheck::new(false, true);
    let result = check.run(&fs).unwrap();
    assert!(result.is_fail(), "persistent journal must fail: {result:?}");
    assert!(result.remediation().is_some());
}

#[test]
fn journald_auto_without_dir_passes() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/systemd/journald.conf", "[Journal]\nStorage=auto\n");
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));

    let check = DecoyPersistenceCheck::new(false, true);
    assert!(check.run(&fs).unwrap().is_pass());
}

#[test]
fn journald_auto_with_disk_dir_fails() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/systemd/journald.conf", "[Journal]\nStorage=auto\n");
    fs.mock_set_path_type("/var/log/journal", PathKind::Dir);
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));

    let check = DecoyPersistenceCheck::new(false, true);
    assert!(check.run(&fs).unwrap().is_fail());
}

#[test]
fn journald_auto_with_tmpfs_dir_passes() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/systemd/journald.conf", "[Journal]\nStorage=auto\n");
    fs.mock_set_path_type("/var/log/journal", PathKind::Dir);
    fs.mock_set_filesystem_type(Path::new("/var/log/journal"), "tmpfs");
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));

    let check = DecoyPersistenceCheck::new(false, true);
    assert!(check.run(&fs).unwrap().is_pass());
}

#[test]
fn active_rsyslog_fails_closed() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
    set_unit_active(&fs, "rsyslog.service");

    let check = DecoyPersistenceCheck::new(false, true);
    let result = check.run(&fs).unwrap();
    assert!(result.is_fail(), "active rsyslog must fail: {result:?}");
    assert!(result.message().contains("rsyslog"));
}

#[test]
fn a_syslog_service_named_syslog_fails_closed() {
    // NixOS's services.rsyslogd runs the daemon as syslog.service.
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
    set_unit_active(&fs, "syslog.service");

    let check = DecoyPersistenceCheck::new(false, true);
    let result = check.run(&fs).unwrap();
    assert!(
        result.is_fail(),
        "an active syslog.service must fail: {result:?}"
    );
    assert!(result.message().contains("syslog.service"));
}

#[test]
fn active_syslog_ng_fails_closed() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
    set_unit_active(&fs, "syslog-ng.service");

    let check = DecoyPersistenceCheck::new(false, true);
    assert!(check.run(&fs).unwrap().is_fail());
}

#[test]
fn active_auditd_fails_closed() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
    set_unit_active(&fs, "auditd.service");

    let check = DecoyPersistenceCheck::new(false, true);
    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(result.message().contains("auditd"));
}

#[test]
fn override_turns_blocker_into_warning() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=persistent\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));

    let check = DecoyPersistenceCheck::new(true, true);
    let result = check.run(&fs).unwrap();
    assert!(result.is_warn(), "override must warn, not fail: {result:?}");
}

#[test]
fn a_disk_root_alone_does_not_warn() {
    // decoy-root accepts only a root on a block device, so a disk root is the
    // only kind a supported decoy has: its type is no finding.
    for fstype in ["ext4", "xfs", "btrfs", "f2fs"] {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/etc/systemd/journald.conf",
            "[Journal]\nStorage=volatile\n",
        );
        fs.mock_add_file(MOUNTINFO, &root_mountinfo(fstype, "rw,relatime"));

        let result = DecoyPersistenceCheck::new(false, true).run(&fs).unwrap();
        assert!(result.is_pass(), "{fstype}: {result:?}");
    }
}

#[test]
fn strictatime_root_warns() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,strictatime"));

    let check = DecoyPersistenceCheck::new(false, true);
    let result = check.run(&fs).unwrap();
    assert!(result.is_warn());
    assert!(result.message().contains("atime"));
}

#[test]
fn core_pattern_disk_path_warns() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
    fs.mock_add_file(CORE_PATTERN, "/var/crash/core.%e.%p\n");

    let check = DecoyPersistenceCheck::new(false, true);
    let result = check.run(&fs).unwrap();
    assert!(result.is_warn());
    assert!(result.message().contains("core_pattern"));
}

/// A clean decoy on a disk root whose kernel pipes core dumps to
/// systemd-coredump, with `coredump.conf` set to `text` (none when empty).
fn coredump_decoy(text: &str) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
    fs.mock_add_file(
        CORE_PATTERN,
        "|/run/current-system/sw/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %d\n",
    );
    if !text.is_empty() {
        fs.mock_add_file("/etc/systemd/coredump.conf", text);
    }
    fs
}

#[test]
fn coredump_with_storage_none_and_no_processing_passes() {
    let fs = coredump_decoy("[Coredump]\nStorage=none\nProcessSizeMax=0\n");
    let result = DecoyPersistenceCheck::new(false, true).run(&fs).unwrap();
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn coredump_with_storage_none_alone_still_warns_and_names_process_size_max() {
    let fs = coredump_decoy("[Coredump]\nStorage=none\n");
    let result = DecoyPersistenceCheck::new(false, true).run(&fs).unwrap();
    assert!(result.is_warn(), "{result:?}");
    let message = result.message();
    assert_eq!(message.matches("systemd-coredump").count(), 1, "{message}");
    assert!(message.contains("ProcessSizeMax"), "{message}");
    assert!(message.contains("/var/lib/systemd/coredump"), "{message}");
}

#[test]
fn coredump_external_warns_once() {
    let fs = coredump_decoy("[Coredump]\nStorage=external\n");
    let result = DecoyPersistenceCheck::new(false, false).run(&fs).unwrap();
    assert!(result.is_warn(), "{result:?}");
    let message = result.message();
    assert_eq!(message.matches("systemd-coredump").count(), 1, "{message}");
    assert!(message.contains("Storage=external"), "{message}");
    assert!(
        message.contains("/etc/systemd/coredump.conf.d/"),
        "outside NixOS the fix is a drop-in: {message}"
    );
}

#[test]
fn coredump_without_any_configuration_takes_the_defaults_and_warns() {
    // The pipe shows systemd-coredump is installed; with no coredump.conf at
    // all it keeps every core (Storage=external by default).
    let fs = coredump_decoy("");
    let result = DecoyPersistenceCheck::new(false, true).run(&fs).unwrap();
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result
            .message()
            .contains("systemd.coredump.settings.Coredump"),
        "on NixOS the fix is the option: {result:?}"
    );
}

#[test]
fn coredump_settings_count_only_while_the_kernel_pipes_to_it() {
    // A coredump.conf left behind while the kernel pipes elsewhere, or the
    // pattern is the plain `core`, raises nothing about systemd-coredump.
    for pattern in ["|/bin/false\n", "core\n"] {
        let fs = coredump_decoy("[Coredump]\nStorage=external\n");
        fs.mock_add_file(CORE_PATTERN, pattern);
        let result = DecoyPersistenceCheck::new(false, true).run(&fs).unwrap();
        assert!(result.is_pass(), "{pattern:?}: {result:?}");
    }
}

fn write(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

#[test]
fn coredump_drop_ins_override_the_main_file() {
    use super::coredump::CoredumpSettings;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    assert!(
        !CoredumpSettings::read(&RealFilesystem, root).keeps_cores_off_disk(),
        "the defaults keep cores"
    );
    write(
        root,
        "usr/lib/systemd/coredump.conf",
        "[Coredump]\n#Storage=external\n#ProcessSizeMax=32G\n",
    );
    write(
        root,
        "etc/systemd/coredump.conf.d/50-discard.conf",
        "[Coredump]\nStorage=none\nProcessSizeMax=0\n",
    );
    assert!(CoredumpSettings::read(&RealFilesystem, root).keeps_cores_off_disk());
    // A later drop-in that turns processing back on wins again.
    write(
        root,
        "etc/systemd/coredump.conf.d/60-size.conf",
        "[Coredump]\nProcessSizeMax=2G\n",
    );
    assert!(!CoredumpSettings::read(&RealFilesystem, root).keeps_cores_off_disk());
}

#[test]
fn persistent_journald_drop_in_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(
        root,
        "etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    write(
        root,
        "etc/systemd/journald.conf.d/90-persist.conf",
        "[Journal]\nStorage=persistent\n",
    );
    let result = DecoyPersistenceCheck::new(false, false)
        .with_root(root)
        .run(&RealFilesystem)
        .unwrap();
    assert!(result.is_fail(), "{}", result.message());
    assert!(result.message().contains("journald"));
    assert!(result.message().contains("journald.conf.d"));
}

#[test]
fn volatile_journald_drop_in_passes() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // Debian/Ubuntu: the vendor main file keeps auto, the journal
    // directory exists, and a drop-in makes the journal volatile.
    write(
        root,
        "usr/lib/systemd/journald.conf",
        "[Journal]\n#Storage=auto\n",
    );
    write(
        root,
        "etc/systemd/journald.conf.d/50-volatile.conf",
        "[Journal]\nStorage=volatile\n",
    );
    std::fs::create_dir_all(root.join("var/log/journal")).unwrap();
    let result = DecoyPersistenceCheck::new(false, false)
        .with_root(root)
        .run(&RealFilesystem)
        .unwrap();
    assert!(!result.is_fail(), "{}", result.message());
    assert!(DecoyPersistenceCheck::blockers(&RealFilesystem, root).is_empty());
}

#[test]
fn pstore_records_warn() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
    fs.mock_set_directory_contents(
        Path::new(PSTORE_DIR),
        vec![std::path::PathBuf::from(format!(
            "{PSTORE_DIR}/dmesg-efi-1"
        ))],
    );

    let check = DecoyPersistenceCheck::new(false, true);
    let result = check.run(&fs).unwrap();
    assert!(result.is_warn());
    assert!(result.message().contains("pstore"));
}

#[test]
fn kdump_armed_warns() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
    fs.mock_add_file(KEXEC_CRASH_LOADED, "1\n");

    let check = DecoyPersistenceCheck::new(false, true);
    let result = check.run(&fs).unwrap();
    assert!(result.is_warn());
    assert!(result.message().contains("kdump"));
}

#[test]
fn a_syslog_ng_template_instance_fails_closed() {
    // systemd runs syslog-ng from a template; only the instance is active, so
    // the fixed-name check must match the stem and name it.
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
    fs.mock_set_directory_contents(
        Path::new("/run/systemd/units"),
        vec![std::path::PathBuf::from(
            "/run/systemd/units/invocation:syslog-ng@default.service",
        )],
    );
    let result = DecoyPersistenceCheck::new(false, true).run(&fs).unwrap();
    assert!(result.is_fail(), "{result:?}");
    assert!(result.message().contains("syslog-ng"), "{result:?}");
}

#[test]
fn a_logger_running_only_as_a_process_fails_closed() {
    // A daemon started outside systemd, or one a recent systemd leaves no marker
    // for, is caught by its process name.
    for (comm, needle) in [
        ("rsyslogd", "rsyslog"),
        ("syslog-ng", "syslog-ng"),
        ("metalog", "metalog"),
        ("auditd", "auditd"),
    ] {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/etc/systemd/journald.conf",
            "[Journal]\nStorage=volatile\n",
        );
        fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
        fs.mock_set_directory_contents(
            Path::new("/proc"),
            vec![std::path::PathBuf::from("/proc/907")],
        );
        fs.mock_add_file("/proc/907/comm", &format!("{comm}\n"));
        let result = DecoyPersistenceCheck::new(false, true).run(&fs).unwrap();
        assert!(result.is_fail(), "{comm}: {result:?}");
        assert!(result.message().contains(needle), "{comm}: {result:?}");
    }
}

#[test]
fn a_logger_matched_by_unit_and_process_is_reported_once() {
    // NixOS runs rsyslogd as syslog.service, and its process is rsyslogd: both
    // routes fire, but the decoy keeps one syslog finding.
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
    set_unit_active(&fs, "syslog.service");
    fs.mock_set_directory_contents(
        Path::new("/proc"),
        vec![std::path::PathBuf::from("/proc/513")],
    );
    fs.mock_add_file("/proc/513/comm", "rsyslogd\n");
    let result = DecoyPersistenceCheck::new(false, true).run(&fs).unwrap();
    assert!(result.is_fail(), "{result:?}");
    assert_eq!(
        result
            .message()
            .matches("writes logs to the decoy disk")
            .count(),
        1,
        "{result:?}"
    );
}

#[test]
fn an_argv0_without_a_matching_comm_still_counts() {
    // comm can be truncated or renamed; argv[0]'s basename catches the daemon.
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
    fs.mock_set_directory_contents(
        Path::new("/proc"),
        vec![std::path::PathBuf::from("/proc/42")],
    );
    fs.mock_add_file("/proc/42/comm", "renamed\n");
    fs.mock_add_file("/proc/42/cmdline", "/usr/sbin/rsyslogd\0-n\0");
    let result = DecoyPersistenceCheck::new(false, true).run(&fs).unwrap();
    assert!(result.is_fail(), "{result:?}");
    assert!(result.message().contains("rsyslog"), "{result:?}");
}

#[test]
fn kdump_tools_service_warns_without_a_loaded_crash_kernel() {
    // Ubuntu arms kdump-tools by default (24.10+); the crash kernel may not be
    // loaded when check runs, but the enabled service still means a panic dumps.
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
    set_unit_active(&fs, "kdump-tools.service");
    let result = DecoyPersistenceCheck::new(false, false).run(&fs).unwrap();
    assert!(result.is_warn(), "{result:?}");
    assert!(result.message().contains("kdump"), "{result:?}");
}

#[test]
fn coredump_socket_form_is_read_as_systemd_coredump() {
    // systemd 262 / Linux 6.17+: the kernel sends dumps to a socket, not a pipe.
    // The pattern must be understood, not misreported as a raw disk path.
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
    fs.mock_add_file(CORE_PATTERN, "@@/run/systemd/coredumpd/kernel\n");
    fs.mock_add_file(
        "/etc/systemd/coredump.conf",
        "[Coredump]\nStorage=external\n",
    );
    let result = DecoyPersistenceCheck::new(false, false).run(&fs).unwrap();
    assert!(result.is_warn(), "{result:?}");
    assert!(result.message().contains("systemd-coredump"), "{result:?}");
    assert!(
        !result
            .message()
            .contains("writes core dumps to the decoy disk (@@"),
        "the socket form must not be misread as a plain path: {result:?}"
    );

    // With Storage=none and no processing, the socket decoy keeps nothing.
    fs.mock_add_file(
        "/etc/systemd/coredump.conf",
        "[Coredump]\nStorage=none\nProcessSizeMax=0\n",
    );
    assert!(
        DecoyPersistenceCheck::new(false, false)
            .run(&fs)
            .unwrap()
            .is_pass()
    );
}

#[test]
fn sudo_rs_ignores_the_sudoers_log_settings() {
    // sudo-rs (Ubuntu's default from 25.10) does not write a logfile or I/O log;
    // the same sudoers settings must be judged for the original sudo but not for
    // sudo-rs, selected through update-alternatives.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(
        root,
        "etc/sudoers",
        "Defaults logfile=/var/log/sudo.log\nDefaults log_output\n",
    );

    write(root, "usr/bin/sudo", "original sudo");
    let classic = sudo_logging::decoy_sudo_findings(&RealFilesystem, root);
    assert!(
        !classic.is_empty(),
        "the original sudo's settings must be judged: {classic:?}"
    );

    std::fs::remove_file(root.join("usr/bin/sudo")).unwrap();
    write(root, "usr/lib/cargo/bin/sudo", "sudo-rs");
    std::os::unix::fs::symlink("../lib/cargo/bin/sudo", root.join("usr/bin/sudo")).unwrap();
    let sudo_rs = sudo_logging::decoy_sudo_findings(&RealFilesystem, root);
    assert!(
        sudo_rs.is_empty(),
        "sudo-rs ignores these settings, so nothing is reported: {sudo_rs:?}"
    );
}

#[test]
fn nixos_upgrade_timer_warns_only_on_nixos() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
    fs.mock_set_path_exists(NIXOS_UPGRADE_TIMER, true);

    // On NixOS the timer warns.
    let nixos = DecoyPersistenceCheck::new(false, true);
    assert!(nixos.run(&fs).unwrap().is_warn());

    // On a non-NixOS host the same marker is ignored.
    let other = DecoyPersistenceCheck::new(false, false);
    assert!(other.run(&fs).unwrap().is_pass());
}

#[test]
fn check_performs_no_writes() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=persistent\n",
    );
    fs.mock_set_path_type("/var/log/journal", PathKind::Dir);
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,strictatime"));
    fs.mock_add_file(CORE_PATTERN, "/var/crash/core\n");
    fs.mock_add_file(KEXEC_CRASH_LOADED, "1\n");
    set_unit_active(&fs, "rsyslog.service");

    let before = fs.mock_ops().len();
    let check = DecoyPersistenceCheck::new(false, true);
    let _ = check.run(&fs).unwrap();
    assert!(fs.mock_written_paths().is_empty(), "nothing was written");
    assert_eq!(
        fs.read_file_content(Path::new("/etc/systemd/journald.conf"))
            .unwrap(),
        "[Journal]\nStorage=persistent\n",
        "the journald configuration is left as it was"
    );
    let after = fs.mock_ops();
    assert_eq!(
        after.len(),
        before,
        "decoy-persistence check must not write: {after:?}"
    );
}

#[test]
fn decoy_is_persistent_tracks_blockers_and_writes_nothing() {
    // Volatile journal, no syslog/auditd: the decoy keeps no durable trace.
    let volatile = MockFilesystem::new();
    volatile.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    volatile.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
    let before = volatile.mock_ops().len();
    assert!(!DecoyPersistenceCheck::decoy_is_persistent(&volatile));
    assert_eq!(
        volatile.mock_ops().len(),
        before,
        "persistence probe must not write"
    );

    // A persistent journal makes the decoy persistent regardless of override.
    let persistent = MockFilesystem::new();
    persistent.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=persistent\n",
    );
    persistent.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
    assert!(DecoyPersistenceCheck::decoy_is_persistent(&persistent));

    // Active auditd alone is enough to count as a persistent decoy.
    let auditd = MockFilesystem::new();
    auditd.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    auditd.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
    set_unit_active(&auditd, "auditd.service");
    assert!(DecoyPersistenceCheck::decoy_is_persistent(&auditd));
}

#[test]
fn a_unit_with_a_populated_cgroup_counts_as_active_without_a_marker() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));
    fs.mock_add_file(
        "/sys/fs/cgroup/system.slice/auditd.service/cgroup.events",
        "populated 1\nfrozen 0\n",
    );
    fs.mock_add_file(
        "/sys/fs/cgroup/system.slice/syslog.service/cgroup.events",
        "populated 0\nfrozen 0\n",
    );
    let result = DecoyPersistenceCheck::new(false, true).run(&fs).unwrap();
    assert!(result.is_fail(), "{result:?}");
    assert!(result.message().contains("auditd"));
    assert!(!result.message().contains("syslog.service"));
}
