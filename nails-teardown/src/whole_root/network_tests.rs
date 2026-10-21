// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use std::fs;
use std::os::unix::fs::FileTypeExt;

/// A fake `/sys/class/net` tree. A link with a `device` entry reads as a
/// hardware device; one without reads as virtual.
fn sys_with(links: &[(&str, u32, &str, bool)]) -> tempfile::TempDir {
    let sys = tempfile::tempdir().unwrap();
    for (name, index, mac, is_hardware) in links {
        let dir = sys.path().join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("ifindex"), format!("{index}\n")).unwrap();
        fs::write(dir.join("address"), format!("{mac}\n")).unwrap();
        if *is_hardware {
            fs::create_dir(dir.join("device")).unwrap();
        }
    }
    sys
}

fn link(name: &str, index: u32, virtual_link: bool, mac: Option<&str>) -> Link {
    Link {
        index,
        name: name.to_string(),
        virtual_link,
        mac: mac.map(str::to_string),
    }
}

#[test]
fn the_links_are_read_with_their_index_address_and_whether_the_kernel_made_them() {
    let sys = sys_with(&[
        ("lo", 1, "00:00:00:00:00:00", false),
        ("eth0", 2, "aa:bb:cc:dd:ee:ff", true),
        ("wg0", 7, "", false),
    ]);
    let links = observe_links(sys.path());
    assert_eq!(
        links,
        vec![
            link("eth0", 2, false, Some("aa:bb:cc:dd:ee:ff")),
            link("lo", 1, true, Some("00:00:00:00:00:00")),
            // An empty address file is no address.
            link("wg0", 7, true, None),
        ]
    );
    // An entry without an interface index is not a link.
    fs::create_dir(sys.path().join("bonding_masters")).unwrap();
    assert_eq!(observe_links(sys.path()).len(), 3);
    // A missing directory is no links, not an error.
    assert!(observe_links(&sys.path().join("gone")).is_empty());
}

#[test]
fn a_virtual_link_that_was_not_there_at_entry_is_deleted_and_a_new_device_is_left() {
    let record = NetworkRecord {
        links: vec![link("lo", 1, true, None), link("eth0", 2, false, None)],
        hostname: b"decoy".to_vec(),
        etc_hostname_present: true,
        run: Vec::new(),
    };
    let current = vec![
        link("lo", 1, true, None),
        link("eth0", 2, false, None),
        // The session's tunnel: virtual, new.
        link("wg0", 9, true, Some("de:ad:be:ef:00:01")),
        // A hot-plugged adapter: a device, new, so left alone.
        link("eth1", 10, false, Some("aa:00:00:00:00:02")),
    ];
    let plan = plan(&record, &current, b"decoy");
    assert_eq!(plan.delete, vec!["wg0".to_string()]);
    assert!(plan.set_mac.is_empty());
    assert!(plan.hostname.is_none());
}

#[test]
fn a_device_whose_address_the_session_changed_gets_its_own_back() {
    let record = NetworkRecord {
        links: vec![
            link("lo", 1, true, Some("00:00:00:00:00:00")),
            link("eth0", 2, false, Some("aa:bb:cc:dd:ee:ff")),
            link("wlan0", 3, false, Some("11:22:33:44:55:66")),
        ],
        hostname: b"decoy".to_vec(),
        etc_hostname_present: true,
        run: Vec::new(),
    };
    let current = vec![
        link("lo", 1, true, Some("00:00:00:00:00:00")),
        // Randomised by the session.
        link("eth0", 2, false, Some("de:ad:be:ef:ca:fe")),
        // Unchanged.
        link("wlan0", 3, false, Some("11:22:33:44:55:66")),
    ];
    let plan = plan(&record, &current, b"decoy");
    assert!(plan.delete.is_empty());
    assert_eq!(
        plan.set_mac,
        vec![("eth0".to_string(), "aa:bb:cc:dd:ee:ff".to_string())]
    );
}

#[test]
fn a_recorded_link_that_is_gone_now_needs_no_address() {
    let record = NetworkRecord {
        links: vec![link("eth0", 2, false, Some("aa:bb:cc:dd:ee:ff"))],
        hostname: Vec::new(),
        etc_hostname_present: true,
        run: Vec::new(),
    };
    // The decoy's device is not in the current list: nothing to set it on.
    assert!(plan(&record, &[], b"").set_mac.is_empty());
}

#[test]
fn the_hostname_is_set_back_only_on_a_decoy_without_etc_hostname_and_only_when_it_changed() {
    let base = NetworkRecord {
        links: Vec::new(),
        hostname: b"decoy-host".to_vec(),
        etc_hostname_present: false,
        run: Vec::new(),
    };
    // No /etc/hostname and the name changed: set it back.
    assert_eq!(
        plan(&base, &[], b"hidden-host").hostname,
        Some(b"decoy-host".to_vec())
    );
    // No /etc/hostname but the name is already the decoy's: nothing.
    assert!(plan(&base, &[], b"decoy-host").hostname.is_none());
    // The decoy has /etc/hostname: it resets the name itself.
    let with_file = NetworkRecord {
        etc_hostname_present: true,
        ..base.clone()
    };
    assert!(plan(&with_file, &[], b"hidden-host").hostname.is_none());
    // An empty recorded hostname is never written.
    let empty = NetworkRecord {
        hostname: Vec::new(),
        ..base
    };
    assert!(plan(&empty, &[], b"hidden-host").hostname.is_none());
}

#[test]
fn the_record_round_trips_and_rejects_a_runtime_path_that_escapes() {
    let sys = sys_with(&[("eth0", 2, "aa:bb:cc:dd:ee:ff", true)]);
    let run = run_with_state();
    let (_host_dir, host) = hostname_file("decoy-host");
    let record = NetworkRecord::capture(sys.path(), &host, Path::new("/etc/hostname"), run.path());
    assert_eq!(NetworkRecord::decode(&record.encode()), Some(record));
    // Garbage, and a record whose runtime path leaves the managed directories.
    assert!(NetworkRecord::decode(b"not json").is_none());
    let escaping = br#"{"links":[],"hostname":[],"etc_hostname_present":false,
        "run":[{"path":"NetworkManager/../../etc","kind":"Dir"}]}"#;
    assert!(NetworkRecord::decode(escaping).is_none());
    let foreign = br#"{"links":[],"hostname":[],"etc_hostname_present":false,
        "run":[{"path":"systemd/system","kind":"Dir"}]}"#;
    assert!(NetworkRecord::decode(foreign).is_none());
}

#[test]
fn the_hostname_file_is_read_trimmed_and_written_back() {
    let (_dir, path) = hostname_file("decoy-host\n");
    assert_eq!(read_hostname(&path), b"decoy-host");
    write_hostname(&path, b"other").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"other");
    // An absent file reads as empty.
    assert!(read_hostname(Path::new("/no/such/hostname")).is_empty());
}

/// A `/run` with the decoy's NetworkManager and resolved per-link state.
fn run_with_state() -> tempfile::TempDir {
    let run = tempfile::tempdir().unwrap();
    let r = run.path();
    fs::create_dir_all(r.join("NetworkManager/devices")).unwrap();
    fs::write(
        r.join("NetworkManager/devices/2"),
        "[device]\nmanaged=true\n",
    )
    .unwrap();
    fs::create_dir_all(r.join("systemd/resolve/netif")).unwrap();
    fs::write(r.join("systemd/resolve/netif/2"), "DNS=10.0.2.3\n").unwrap();
    run
}

fn hostname_file(content: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hostname");
    fs::write(&path, content).unwrap();
    (dir, path)
}

#[test]
fn the_runtime_directories_come_back_as_entry_left_them() {
    let run = run_with_state();
    let r = run.path();
    let record = NetworkRecord {
        links: Vec::new(),
        hostname: Vec::new(),
        etc_hostname_present: true,
        run: snapshot_run(r),
    };
    // The hidden session: a new device file, a changed one, a whole new tree.
    fs::write(
        r.join("NetworkManager/devices/2"),
        "[device]\nmanaged=true\nconnection=hidden\n",
    )
    .unwrap();
    fs::write(r.join("NetworkManager/devices/9"), "[device]\n").unwrap();
    fs::create_dir_all(r.join("systemd/resolve/netif")).unwrap();
    fs::write(r.join("systemd/resolve/netif/9"), "DNS=10.213.77.53\n").unwrap();

    restore_run(r, &record);

    assert_eq!(
        fs::read_to_string(r.join("NetworkManager/devices/2")).unwrap(),
        "[device]\nmanaged=true\n"
    );
    assert!(!r.join("NetworkManager/devices/9").exists());
    assert!(!r.join("systemd/resolve/netif/9").exists());
    assert!(r.join("systemd/resolve/netif/2").is_file());
    assert_eq!(
        snapshot_run(r),
        record.run,
        "entry's state, entry for entry"
    );
}

#[test]
fn a_runtime_directory_the_decoy_did_not_have_is_removed() {
    let run = tempfile::tempdir().unwrap();
    let r = run.path();
    // The decoy ran neither service: nothing to copy.
    let record = NetworkRecord {
        links: Vec::new(),
        hostname: Vec::new(),
        etc_hostname_present: true,
        run: snapshot_run(r),
    };
    assert!(record.run.is_empty());
    // The hidden session's NetworkManager wrote a device file.
    fs::create_dir_all(r.join("NetworkManager/devices")).unwrap();
    fs::write(r.join("NetworkManager/devices/3"), "[device]\n").unwrap();
    restore_run(r, &record);
    assert!(!r.join("NetworkManager/devices").exists());
}

#[test]
fn a_socket_in_the_runtime_state_is_never_copied() {
    let run = tempfile::tempdir().unwrap();
    let r = run.path();
    fs::create_dir_all(r.join("NetworkManager/devices")).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        r.join("NetworkManager/devices/control.sock"),
        rustix::fs::FileType::Socket,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    let snapshot = snapshot_run(r);
    assert!(
        snapshot
            .iter()
            .all(|entry| entry.path != Path::new("NetworkManager/devices/control.sock")),
        "{snapshot:?}"
    );
    assert!(
        fs::symlink_metadata(r.join("NetworkManager/devices/control.sock"))
            .unwrap()
            .file_type()
            .is_socket()
    );
}

#[test]
fn restore_without_a_record_changes_nothing() {
    let run = run_with_state();
    let before = snapshot_run(run.path());
    let (_host_dir, host) = hostname_file("live-host");
    let sys = sys_with(&[("wg0", 9, "de:ad:be:ef:00:01", false)]);
    // No record at all, and an unparsable one: both leave the world untouched.
    restore(run.path(), sys.path(), &host, None);
    restore(run.path(), sys.path(), &host, Some(b"not a record"));
    assert_eq!(snapshot_run(run.path()), before);
    assert_eq!(read_hostname(&host), b"live-host");
    assert!(observe_links(sys.path()).iter().any(|l| l.name == "wg0"));
}

#[test]
fn restore_puts_the_hostname_and_runtime_state_back_without_touching_links() {
    let run = run_with_state();
    let r = run.path();
    let (_host_dir, host) = hostname_file("hidden-host");
    // The decoy has only lo, no /etc/hostname, and the recorded runtime state.
    let sys = sys_with(&[("lo", 1, "00:00:00:00:00:00", false)]);
    let record = NetworkRecord {
        links: observe_links(sys.path()),
        hostname: b"decoy-host".to_vec(),
        etc_hostname_present: false,
        run: snapshot_run(r),
    };
    // The session changed the hostname and a device file.
    fs::write(r.join("NetworkManager/devices/2"), "hidden\n").unwrap();

    restore(r, sys.path(), &host, Some(&record.encode()));

    assert_eq!(read_hostname(&host), b"decoy-host", "the hostname is back");
    assert_eq!(
        fs::read_to_string(r.join("NetworkManager/devices/2")).unwrap(),
        "[device]\nmanaged=true\n",
        "the runtime state is back"
    );
}

#[test]
fn the_record_name_carries_no_product_name() {
    assert!(!RECORD_NAME.to_lowercase().contains("nails"));
}
