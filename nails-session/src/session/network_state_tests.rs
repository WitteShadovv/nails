// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use nails_teardown::whole_root::network::NetworkRecord;
use std::fs;
use std::os::unix::fs::PermissionsExt;

/// A fake `/sys/class/net`, a hostname file, an `/etc/hostname` and a `/run`
/// with per-link runtime state, under one temporary root.
fn world() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let eth0 = root.join("sys/eth0");
    fs::create_dir_all(eth0.join("device")).unwrap();
    fs::write(eth0.join("ifindex"), "2\n").unwrap();
    fs::write(eth0.join("address"), "aa:bb:cc:dd:ee:ff\n").unwrap();
    fs::write(root.join("hostname"), "decoy-host\n").unwrap();
    fs::write(root.join("etc-hostname"), "decoy-host\n").unwrap();
    fs::create_dir_all(root.join("run/NetworkManager/devices")).unwrap();
    fs::write(root.join("run/NetworkManager/devices/2"), "[device]\n").unwrap();
    dir
}

#[test]
fn the_record_is_written_privately_and_matches_what_was_captured() {
    let world = world();
    let root = world.path();
    let out = root.join("runtime/net-identity");
    fs::create_dir_all(out.parent().unwrap()).unwrap();

    record(
        &root.join("sys"),
        &root.join("hostname"),
        &root.join("etc-hostname"),
        &root.join("run"),
        &out,
    );

    let expected = NetworkRecord::capture(
        &root.join("sys"),
        &root.join("hostname"),
        &root.join("etc-hostname"),
        &root.join("run"),
    );
    let written = NetworkRecord::decode(&fs::read(&out).unwrap()).unwrap();
    assert_eq!(written, expected);
    // Private: the record names the decoy's hardware address and hostname.
    let mode = fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn a_record_that_cannot_be_written_leaves_no_file() {
    let world = world();
    let root = world.path();
    // `out`'s parent does not exist, so the atomic write fails.
    let out = root.join("no-such-dir/net-identity");
    record(
        &root.join("sys"),
        &root.join("hostname"),
        &root.join("etc-hostname"),
        &root.join("run"),
        &out,
    );
    assert!(!out.exists());
}
