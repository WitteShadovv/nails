// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::RealFilesystem;
use crate::filesystem::{MockFilesystem, PathKind};

/// Mark a systemd unit active by creating its runtime invocation marker.
fn set_unit_active(fs: &MockFilesystem, unit: &str) {
    let marker = format!("/{INVOCATION_DIR}/invocation:{unit}");
    fs.mock_set_path_exists(&marker, true);
}

/// A mountinfo with a single `/` entry of the given fstype and options.
fn root_mountinfo(fstype: &str, opts: &str) -> String {
    format!("36 35 0:32 / / {opts} shared:1 - {fstype} /dev/sda1 rw\n")
}

#[test]
fn clean_volatile_decoy_passes() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));

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
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
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
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));

    let check = DecoyPersistenceCheck::new(false, true);
    let result = check.run(&fs).unwrap();
    assert!(result.is_fail(), "persistent journal must fail: {result:?}");
    assert!(result.remediation().is_some());
}

#[test]
fn journald_auto_without_dir_passes() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/systemd/journald.conf", "[Journal]\nStorage=auto\n");
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));

    let check = DecoyPersistenceCheck::new(false, true);
    assert!(check.run(&fs).unwrap().is_pass());
}

#[test]
fn journald_auto_with_disk_dir_fails() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/systemd/journald.conf", "[Journal]\nStorage=auto\n");
    fs.mock_set_path_type("/var/log/journal", PathKind::Dir);
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));

    let check = DecoyPersistenceCheck::new(false, true);
    assert!(check.run(&fs).unwrap().is_fail());
}

#[test]
fn journald_auto_with_tmpfs_dir_passes() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/systemd/journald.conf", "[Journal]\nStorage=auto\n");
    fs.mock_set_path_type("/var/log/journal", PathKind::Dir);
    fs.mock_set_filesystem_type(Path::new("/var/log/journal"), "tmpfs");
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));

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
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
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
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
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
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
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
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
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
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));

    let check = DecoyPersistenceCheck::new(true, true);
    let result = check.run(&fs).unwrap();
    assert!(result.is_warn(), "override must warn, not fail: {result:?}");
}

#[test]
fn persistent_root_fs_warns() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("ext4", "rw,noatime"));

    let check = DecoyPersistenceCheck::new(false, true);
    let result = check.run(&fs).unwrap();
    assert!(result.is_warn(), "persistent root fs must warn: {result:?}");
    assert!(result.message().contains("persistent"));
}

#[test]
fn strictatime_root_warns() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    // tmpfs root so only the atime finding fires.
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,strictatime"));

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
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
    fs.mock_add_file(CORE_PATTERN, "/var/crash/core.%e.%p\n");

    let check = DecoyPersistenceCheck::new(false, true);
    let result = check.run(&fs).unwrap();
    assert!(result.is_warn());
    assert!(result.message().contains("core_pattern"));
}

#[test]
fn coredump_external_warns() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
    fs.mock_add_file(
        CORE_PATTERN,
        "|/run/current-system/sw/lib/systemd/systemd-coredump %P\n",
    );
    fs.mock_add_file(
        "/etc/systemd/coredump.conf",
        "[Coredump]\nStorage=external\n",
    );

    let check = DecoyPersistenceCheck::new(false, true);
    let result = check.run(&fs).unwrap();
    assert!(result.is_warn());
    assert!(result.message().contains("coredump") || result.message().contains("systemd-coredump"));
}

#[test]
fn coredump_none_does_not_warn_on_that_axis() {
    let external = |text: &str| {
        let mut assignments = Vec::new();
        let _ = systemd_conf::parse_section(text, "Coredump", &mut assignments);
        coredump_external_from(&assignments)
    };
    assert!(!external("[Coredump]\nStorage=none\n"));
    assert!(!external("[Coredump]\nStorage=journal\n"));
    assert!(external("[Coredump]\nStorage=external\n"));
    // Unset defaults to external; outside [Coredump] nothing counts.
    assert!(external("[Coredump]\n"));
    assert!(external("Storage=none\n"));
    // Last assignment wins.
    assert!(!external("[Coredump]\nStorage=external\nStorage=none\n"));
}

fn write(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

#[test]
fn coredump_drop_in_overrides_the_main_file() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    assert!(
        !coredump_storage_external(&RealFilesystem, root),
        "not installed"
    );
    write(
        root,
        "usr/lib/systemd/coredump.conf",
        "[Coredump]\n#Storage=external\n",
    );
    assert!(
        coredump_storage_external(&RealFilesystem, root),
        "default external"
    );
    write(
        root,
        "etc/systemd/coredump.conf.d/50-none.conf",
        "[Coredump]\nStorage=none\n",
    );
    assert!(!coredump_storage_external(&RealFilesystem, root));
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
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
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
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
    fs.mock_add_file(KEXEC_CRASH_LOADED, "1\n");

    let check = DecoyPersistenceCheck::new(false, true);
    let result = check.run(&fs).unwrap();
    assert!(result.is_warn());
    assert!(result.message().contains("kdump"));
}

#[test]
fn nixos_upgrade_timer_warns_only_on_nixos() {
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    fs.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
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
    volatile.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
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
    persistent.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
    assert!(DecoyPersistenceCheck::decoy_is_persistent(&persistent));

    // Active auditd alone is enough to count as a persistent decoy.
    let auditd = MockFilesystem::new();
    auditd.mock_add_file(
        "/etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    auditd.mock_add_file(MOUNTINFO, &root_mountinfo("tmpfs", "rw,noatime"));
    set_unit_active(&auditd, "auditd.service");
    assert!(DecoyPersistenceCheck::decoy_is_persistent(&auditd));
}
