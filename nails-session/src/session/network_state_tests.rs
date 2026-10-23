// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use nails_teardown::whole_root::network::NetworkRecord;
use std::fs;
use std::os::unix::fs::PermissionsExt;

/// A fake `/sys/class/net`, a hostname file, a `/proc/sys` with a network
/// setting and a `/run` with per-link runtime state, under one temporary root.
fn world() -> (tempfile::TempDir, Places) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let places = Places {
        run: root.join("run"),
        sys_class_net: root.join("sys"),
        proc_hostname: root.join("hostname"),
        proc_sys: root.join("proc-sys"),
    };
    let eth0 = places.sys_class_net.join("eth0");
    fs::create_dir_all(eth0.join("device")).unwrap();
    fs::write(eth0.join("ifindex"), "2\n").unwrap();
    fs::write(eth0.join("address"), "aa:bb:cc:dd:ee:ff\n").unwrap();
    fs::write(&places.proc_hostname, "decoy-host\n").unwrap();
    fs::create_dir_all(places.proc_sys.join("net/ipv4")).unwrap();
    fs::write(places.proc_sys.join("net/ipv4/ip_forward"), "0\n").unwrap();
    fs::create_dir_all(places.run.join("NetworkManager/devices")).unwrap();
    fs::write(places.run.join("NetworkManager/devices/2"), "[device]\n").unwrap();
    (dir, places)
}

#[test]
fn the_record_is_written_privately_and_matches_what_was_captured() {
    let (dir, places) = world();
    let out = dir.path().join("runtime/net-identity");
    fs::create_dir_all(out.parent().unwrap()).unwrap();

    record_with(&places, &NetTools::default(), &out);

    let expected = NetworkRecord::capture(&places, &NetTools::default());
    let written = NetworkRecord::decode(&fs::read(&out).unwrap()).unwrap();
    assert_eq!(written, expected);
    // Private: the record names the decoy's hardware address and hostname.
    let mode = fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn a_write_to_a_missing_directory_creates_no_file() {
    let (dir, places) = world();
    // `out`'s parent does not exist, so the atomic write fails before it ever
    // creates `out`. This does NOT exercise the stale-record cleanup: `out`
    // never existed, so there is nothing to remove (see the next test).
    let out = dir.path().join("no-such-dir/net-identity");
    record_with(&places, &NetTools::default(), &out);
    assert!(!out.exists());
}

#[test]
fn a_failed_write_removes_a_stale_record_from_a_prior_capture() {
    let (dir, _places) = world();
    let out = dir.path().join("runtime/net-identity");
    fs::create_dir_all(out.parent().unwrap()).unwrap();
    // A record a PRIOR successful capture left in the fixed, soft-reboot
    // persisted runtime directory; it names a decoy state that may no longer
    // be current.
    fs::write(&out, b"stale-prior-identity").unwrap();

    // This capture's atomic write fails (ENOSPC, a read-only remount, a failed
    // rename). The stale record must not survive: the way back reads whatever
    // file is here and would otherwise set the OLD MAC and hostname back.
    write_record(&out, b"current", |_, _| {
        Err(std::io::Error::other("injected"))
    });

    assert!(
        !out.exists(),
        "a failed capture left a stale net-identity for the way back to apply"
    );
}
