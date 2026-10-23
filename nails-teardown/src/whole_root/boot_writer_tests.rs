// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for starting the decoy's wtmpdb boot writer after the way back.

use super::*;
use std::os::unix::fs::PermissionsExt;

/// Debian 13's unit for the writer, as its package ships it.
const DEBIAN_UNIT: &str = "[Unit]\n\
    Description=Write boot and shutdown times into wtmpdb\n\
    Documentation=man:wtmpdb(8)\n\
    DefaultDependencies=no\n\
    RequiresMountsFor=/var/log\n\
    Conflicts=shutdown.target\n\
    After=systemd-remount-fs.service systemd-tmpfiles-setup.service\n\
    Before=shutdown.target\n\
    # Ask for the dbus socket.\n\
    Wants=dbus.socket\n\
    After=dbus.socket\n\
    \n\
    [Service]\n\
    Type=oneshot\n\
    ExecStart=/usr/bin/wtmpdb boot\n\
    ExecStop=/usr/bin/wtmpdb shutdown\n\
    RemainAfterExit=true\n\
    \n\
    [Install]\n\
    WantedBy=default.target\n";

/// The boot clock at a switch, as the units carry it.
const SWITCHED_AT: Duration = Duration::from_micros(987_654_321);

fn service(start: &str) -> String {
    format!("[Unit]\nDescription=x\n\n[Service]\nType=oneshot\n{start}\n")
}

#[test]
fn debian_s_writer_command_is_read_from_its_unit() {
    assert_eq!(
        start_command(DEBIAN_UNIT),
        Some(vec!["/usr/bin/wtmpdb".to_string(), "boot".to_string()])
    );
    // Options of the writer's own are kept, and a reset before the command is
    // honoured as systemd honours it.
    assert_eq!(
        start_command(&service("ExecStart=\nExecStart = /usr/bin/wtmpdb boot -q")),
        Some(vec![
            "/usr/bin/wtmpdb".to_string(),
            "boot".to_string(),
            "-q".to_string()
        ])
    );
}

#[test]
fn a_start_command_this_module_cannot_run_unchanged_is_never_replaced() {
    for start in [
        // Not one command.
        "",
        "ExecStart=/usr/bin/wtmpdb boot\nExecStart=/usr/bin/true",
        "ExecStart=/usr/bin/wtmpdb boot\nExecStart=",
        // A prefix, quoting, an escape, a variable or a specifier.
        "ExecStart=-/usr/bin/wtmpdb boot",
        "ExecStart=@/usr/bin/wtmpdb wtmpdb boot",
        "ExecStart=+/usr/bin/wtmpdb boot",
        "ExecStart=/usr/bin/wtmpdb boot \"-f\" /x",
        "ExecStart=/usr/bin/wtmpdb boot $OPTS",
        "ExecStart=/usr/bin/wtmpdb boot -f %S/wtmp.db",
        "ExecStart=/usr/bin/wtmpdb boot ; /usr/bin/true",
        "ExecStart=/usr/bin/wtmpdb \\\n boot",
        // Not the writer's boot step.
        "ExecStart=/usr/bin/wtmpdb shutdown",
        "ExecStart=wtmpdb boot",
        "ExecStart=/usr/bin/true boot",
        "ExecStart=/usr/bin/wtmpdb",
    ] {
        assert_eq!(start_command(&service(start)), None, "{start:?}");
    }
    // A start command outside [Service] is no start command.
    assert_eq!(
        start_command("[Unit]\nExecStart=/usr/bin/wtmpdb boot\n"),
        None
    );
}

/// A decoy root under `root` whose records are in wtmpdb, as on Debian 13.
fn debian_decoy(root: &Path) {
    for dir in ["var/log", "usr/bin", "usr/lib/systemd/system"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    std::fs::write(root.join("var/log/wtmp.db"), b"SQLite format 3\x00").unwrap();
    std::fs::write(root.join("usr/bin/wtmpdb"), b"\x7fELF").unwrap();
    std::fs::write(
        root.join("usr/lib/systemd/system").join(WRITER_UNIT),
        DEBIAN_UNIT,
    )
    .unwrap();
}

#[test]
fn the_writer_is_found_only_where_the_package_s_unit_starts_it() {
    let found = Some(vec!["/usr/bin/wtmpdb".to_string(), "boot".to_string()]);
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    debian_decoy(root);
    assert_eq!(writer_command(root), found);

    // Without the database, wtmpdb does not record this decoy's boots.
    std::fs::remove_file(root.join("var/log/wtmp.db")).unwrap();
    assert_eq!(writer_command(root), None);
    // Upstream's path for it counts as well.
    std::fs::create_dir_all(root.join("var/lib/wtmpdb")).unwrap();
    std::fs::write(root.join("var/lib/wtmpdb/wtmp.db"), b"").unwrap();
    assert_eq!(writer_command(root), found);

    // Without the program the command names, there is nothing to start.
    std::fs::remove_file(root.join("usr/bin/wtmpdb")).unwrap();
    assert_eq!(writer_command(root), None);
}

#[test]
fn a_unit_the_decoy_changes_itself_is_left_as_it_is() {
    for changed in [
        "etc/systemd/system/wtmpdb-update-boot.service",
        "etc/systemd/system/wtmpdb-update-boot.service.d",
        "usr/lib/systemd/system/wtmpdb-update-boot.service.d",
        "lib/systemd/system/wtmpdb-update-boot.service.d",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        debian_decoy(root);
        std::fs::create_dir_all(root.join(changed)).unwrap();
        assert_eq!(writer_command(root), None, "{changed}");
    }
    // A unit masked by a link of the administrator's counts too.
    let dir = tempfile::tempdir().unwrap();
    debian_decoy(dir.path());
    std::fs::create_dir_all(dir.path().join(ADMIN_UNIT_DIR)).unwrap();
    std::os::unix::fs::symlink(
        "/dev/null",
        dir.path().join(ADMIN_UNIT_DIR).join(WRITER_UNIT),
    )
    .unwrap();
    assert_eq!(writer_command(dir.path()), None);
}

#[test]
fn the_drop_in_replaces_only_the_start_command() {
    let dir = tempfile::tempdir().unwrap();
    let binary = Path::new("/run/overlay-runtime-boot/control");
    let writer = ["/usr/bin/wtmpdb".to_string(), "boot".to_string()];
    install_dropin(dir.path(), binary, SWITCHED_AT, &writer).unwrap();
    let path = dir.path().join(DROPIN_DIR).join(DROPIN_NAME);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "[Service]\nExecStart=\n\
         ExecStart=/run/overlay-runtime-boot/control boot-writer 987654321 /usr/bin/wtmpdb boot\n"
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644,
        "readable by PID 1 without a warning"
    );
    assert_eq!(
        writer_args(SWITCHED_AT, &writer),
        [WRITER_ARG, "987654321", "/usr/bin/wtmpdb", "boot"]
    );

    // Removing it takes the directory too when nothing else is in it, and
    // leaves one the decoy has its own drop-ins in.
    remove_dropin(dir.path());
    assert!(!dir.path().join(DROPIN_DIR).exists());
    install_dropin(dir.path(), binary, SWITCHED_AT, &writer).unwrap();
    std::fs::write(dir.path().join(DROPIN_DIR).join("10-decoy.conf"), "").unwrap();
    remove_dropin(dir.path());
    assert!(!path.exists());
    assert!(dir.path().join(DROPIN_DIR).join("10-decoy.conf").exists());
}

#[test]
fn only_a_kernel_that_switches_at_exec_starts_the_writer_in_a_namespace() {
    for release in [
        "6.2.0",
        "6.8.0-45-generic",
        "6.12.48+deb13-amd64",
        "6.17.0-5-generic",
        "7.0.0",
    ] {
        assert!(enters_at_exec(release), "{release}");
    }
    for release in [
        "6.1.0-18-amd64",
        "5.15.0-91-generic",
        "6",
        "",
        "linux",
        "6.x",
    ] {
        assert!(!enters_at_exec(release), "{release}");
    }
}

#[test]
fn the_namespace_s_boot_clock_starts_at_the_switch() {
    let secs = Duration::from_secs;
    // Ten seconds after the switch, the writer sees an uptime of ten seconds.
    assert_eq!(clock_offset(secs(3600), secs(3590)), secs(3590));
    // Long after the switch it sees the cap, which wtmpdb still takes as an
    // uptime (it names the row soft-reboot past 300 seconds).
    assert_eq!(clock_offset(secs(3600), secs(600)), secs(3600) - UPTIME_CAP);
    assert!(UPTIME_CAP < secs(300));
    // A switch the clock has not reached (a bad argument) is taken as now; the
    // boot clock is never set below zero.
    assert_eq!(clock_offset(secs(100), secs(500)), secs(100));
    assert_eq!(clock_offset(secs(100), Duration::ZERO), Duration::ZERO);
}

#[test]
fn the_offsets_line_is_what_the_kernel_parses() {
    // "<clock> <seconds> <nanoseconds>", the nanoseconds in 0..1e9: a negative
    // offset with a fraction borrows one second.
    assert_eq!(offsets_line(Duration::from_secs(10)), "boottime -10 0\n");
    assert_eq!(
        offsets_line(Duration::new(10, 250_000_000)),
        "boottime -11 750000000\n"
    );
    assert_eq!(offsets_line(Duration::new(0, 1)), "boottime -1 999999999\n");
    assert_eq!(offsets_line(Duration::ZERO), "boottime -0 0\n");
}

#[test]
fn an_empty_writer_command_starts_nothing() {
    assert!(prepare(SWITCHED_AT, &[]).is_none());
}

#[test]
fn the_runtime_names_carry_no_product_name() {
    for name in [
        WRITER_ARG,
        DROPIN_NAME,
        DROPIN_PATH,
        &no_bus_address(),
        &dropin_text(
            Path::new("/run/x"),
            SWITCHED_AT,
            &["/usr/bin/wtmpdb".into()],
        ),
    ] {
        assert!(!name.to_lowercase().contains("nails"), "{name}");
    }
    assert_eq!(DROPIN_PATH, format!("/run/{DROPIN_DIR}/{DROPIN_NAME}"));
}
