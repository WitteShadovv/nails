// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::test_support::write_executable;
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
    assert!(restore(run.path(), sys.path(), &host, None).is_empty());
    assert!(restore(run.path(), sys.path(), &host, Some(b"not a record")).is_empty());
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

    let kept = restore(r, sys.path(), &host, Some(&record.encode()));

    assert!(kept.is_empty(), "no address to set back: {kept:?}");
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

#[test]
fn an_absent_runtime_directory_is_skipped_while_a_present_one_is_still_copied() {
    // NetworkManager state is present; systemd/resolve/netif does not exist.
    let run = tempfile::tempdir().unwrap();
    let r = run.path();
    fs::create_dir_all(r.join("NetworkManager/devices")).unwrap();
    fs::write(r.join("NetworkManager/devices/2"), "[device]\n").unwrap();

    // The absent directory reads as NotFound and is simply skipped, so the
    // present directory's state still makes it into the copy. A guard that
    // does not recognise NotFound would abandon the whole copy instead.
    let snapshot = snapshot_run(r);
    assert!(
        snapshot
            .iter()
            .any(|entry| entry.path == Path::new("NetworkManager/devices/2")),
        "the present directory's file is copied even though the other is absent: {snapshot:?}"
    );
}

#[test]
fn a_non_notfound_error_reading_runtime_state_abandons_the_whole_copy() {
    // NetworkManager is a plain file, so reading NetworkManager/devices below
    // it fails with a not-a-directory error, which is not NotFound. The
    // systemd state is present and would be copied if that error were wrongly
    // swallowed as a missing directory.
    let run = tempfile::tempdir().unwrap();
    let r = run.path();
    fs::write(r.join("NetworkManager"), "not a directory").unwrap();
    fs::create_dir_all(r.join("systemd/resolve/netif")).unwrap();
    fs::write(r.join("systemd/resolve/netif/2"), "DNS=10.0.2.3\n").unwrap();

    // A real error must propagate: the copy is abandoned, never partially kept.
    assert!(
        snapshot_run(r).is_empty(),
        "a non-NotFound error abandons the copy rather than skipping the entry"
    );
}

#[test]
fn the_runtime_copy_stops_at_the_maximum_depth() {
    let run = tempfile::tempdir().unwrap();
    let r = run.path();
    // NetworkManager/devices is depth 0; a/b/c/d descends to RUN_MAX_DEPTH, and
    // `e` sits one level below that, past the limit.
    let at_limit = r.join("NetworkManager/devices/a/b/c/d");
    fs::create_dir_all(&at_limit).unwrap();
    fs::write(at_limit.join("e"), "too deep\n").unwrap();

    let snapshot = snapshot_run(r);
    assert!(
        snapshot
            .iter()
            .any(|entry| entry.path == Path::new("NetworkManager/devices/a/b/c/d")),
        "the directory at the maximum depth is still copied: {snapshot:?}"
    );
    assert!(
        snapshot
            .iter()
            .all(|entry| entry.path != Path::new("NetworkManager/devices/a/b/c/d/e")),
        "nothing below the maximum depth is copied: {snapshot:?}"
    );
}

#[test]
fn runtime_state_at_the_size_limit_is_copied_but_past_it_abandons_the_copy() {
    // A file of exactly RUN_MAX_BYTES is within budget and is copied.
    let at = tempfile::tempdir().unwrap();
    let a = at.path();
    fs::create_dir_all(a.join("NetworkManager/devices")).unwrap();
    fs::write(
        a.join("NetworkManager/devices/at_limit"),
        vec![b'x'; RUN_MAX_BYTES],
    )
    .unwrap();
    let snapshot = snapshot_run(a);
    assert!(
        snapshot
            .iter()
            .any(|entry| entry.path == Path::new("NetworkManager/devices/at_limit")),
        "a file at exactly the limit is kept: {snapshot:?}"
    );

    // One byte past the budget abandons the whole copy.
    let over = tempfile::tempdir().unwrap();
    let o = over.path();
    fs::create_dir_all(o.join("NetworkManager/devices")).unwrap();
    fs::write(
        o.join("NetworkManager/devices/over"),
        vec![b'x'; RUN_MAX_BYTES + 1],
    )
    .unwrap();
    assert!(
        snapshot_run(o).is_empty(),
        "a file past the limit abandons the copy"
    );
}

#[test]
fn a_restored_file_gets_its_parent_directory_created() {
    let run = tempfile::tempdir().unwrap();
    let r = run.path();
    // A record that lists a file without first listing its parent directory:
    // restoring it must create the parent before writing the file, so the
    // write does not fail and silently drop the state.
    let record = NetworkRecord {
        links: Vec::new(),
        hostname: Vec::new(),
        etc_hostname_present: true,
        run: vec![RunEntry {
            path: PathBuf::from("NetworkManager/devices/2"),
            kind: RunKind::File(b"[device]\n".to_vec()),
        }],
    };
    restore_run(r, &record);
    assert_eq!(
        fs::read(r.join("NetworkManager/devices/2")).unwrap(),
        b"[device]\n",
        "the file is written, its parent having been created first"
    );
}

/// The decoy device's address, as entry recorded it.
const DECOY_MAC: &str = "aa:bb:cc:dd:ee:ff";
/// The random address the hidden session gave it.
const SESSION_MAC: &str = "de:ad:be:ef:ca:fe";

/// Set a fake link up (`IFF_UP` and the broadcast and multicast flags of an
/// Ethernet device, as the kernel prints them) or down.
fn set_up(sys: &Path, name: &str, up: bool) {
    let flags = if up { "0x1003\n" } else { "0x1002\n" };
    fs::write(sys.join(name).join("flags"), flags).unwrap();
}

fn flags(sys: &Path, name: &str) -> String {
    read_trimmed(&sys.join(name).join("flags")).unwrap()
}

fn address(sys: &Path, name: &str) -> String {
    read_trimmed(&sys.join(name).join("address")).unwrap()
}

/// A plan that sets each `(name, mac)` back.
fn set_back(macs: &[(&str, &str)]) -> RestorePlan {
    RestorePlan {
        delete: Vec::new(),
        set_mac: macs
            .iter()
            .map(|(name, mac)| (name.to_string(), mac.to_string()))
            .collect(),
        hostname: None,
    }
}

/// A fake `ip` in `dir` that changes the fake `/sys/class/net` tree `sys` as
/// the kernel would (`link set dev NAME up`, `down` or `address MAC`) and logs
/// each call. A link in `busy_while_up` refuses an address change while it is
/// up, as a driver without live address change does (`EBUSY`); a link in
/// `refusing` refuses it always. A link that is not there fails every call.
fn fake_ip(dir: &Path, sys: &Path, busy_while_up: &[&str], refusing: &[&str]) -> PathBuf {
    let tool = dir.join("ip");
    write_executable(
        &tool,
        format!(
            "#!/bin/sh\n\
             echo \"$*\" >> '{calls}'\n\
             [ \"$1 $2 $3\" = 'link set dev' ] || exit 1\n\
             link='{sys}'/\"$4\"\n\
             read -r flags < \"$link/flags\" || exit 1\n\
             case \"$5\" in\n\
             up) echo 0x1003 > \"$link/flags\" ;;\n\
             down) echo 0x1002 > \"$link/flags\" ;;\n\
             address)\n\
             case ' {refusing} ' in *\" $4 \"*) exit 2 ;; esac\n\
             case ' {busy} ' in *\" $4 \"*) [ \"$flags\" = 0x1003 ] && exit 2 ;; esac\n\
             echo \"$6\" > \"$link/address\" ;;\n\
             *) exit 1 ;;\n\
             esac\n",
            calls = dir.join("calls").display(),
            sys = sys.display(),
            refusing = refusing.join(" "),
            busy = busy_while_up.join(" "),
        ),
        0o755,
    );
    tool
}

/// The calls the fake `ip` in `dir` logged, in order.
fn ip_calls(dir: &Path) -> Vec<String> {
    fs::read_to_string(dir.join("calls"))
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn an_address_the_driver_changes_live_is_set_without_taking_the_link_down() {
    let sys = sys_with(&[("eth0", 2, SESSION_MAC, true)]);
    set_up(sys.path(), "eth0", true);
    let dir = tempfile::tempdir().unwrap();
    let ip = fake_ip(dir.path(), sys.path(), &[], &[]);

    let kept = apply_links_with(Some(&ip), &set_back(&[("eth0", DECOY_MAC)]), sys.path());

    assert!(kept.is_empty(), "{kept:?}");
    assert_eq!(address(sys.path(), "eth0"), DECOY_MAC);
    assert_eq!(
        ip_calls(dir.path()),
        [format!("link set dev eth0 address {DECOY_MAC}")],
        "one live change, no down and up"
    );
    assert_eq!(flags(sys.path(), "eth0"), "0x1003");
}

#[test]
fn a_driver_that_refuses_a_live_change_gets_the_address_with_the_link_down_and_up_again() {
    let sys = sys_with(&[("eth0", 2, SESSION_MAC, true)]);
    set_up(sys.path(), "eth0", true);
    let dir = tempfile::tempdir().unwrap();
    // A USB Ethernet adapter whose driver refuses to change a running device.
    let ip = fake_ip(dir.path(), sys.path(), &["eth0"], &[]);

    let kept = apply_links_with(Some(&ip), &set_back(&[("eth0", DECOY_MAC)]), sys.path());

    assert!(kept.is_empty(), "{kept:?}");
    assert_eq!(address(sys.path(), "eth0"), DECOY_MAC);
    let set = format!("link set dev eth0 address {DECOY_MAC}");
    assert_eq!(
        ip_calls(dir.path()),
        [
            set.as_str(),
            "link set dev eth0 down",
            set.as_str(),
            "link set dev eth0 up"
        ]
    );
    assert_eq!(flags(sys.path(), "eth0"), "0x1003", "up again, as it was");
}

#[test]
fn a_link_that_was_down_stays_down() {
    let sys = sys_with(&[
        ("eth0", 2, SESSION_MAC, true),
        ("wlan0", 3, "de:ad:be:ef:ca:fd", true),
    ]);
    set_up(sys.path(), "eth0", false);
    set_up(sys.path(), "wlan0", false);
    let dir = tempfile::tempdir().unwrap();
    // eth0's driver refuses a change only while the link runs, so on the down
    // link it takes at once; wlan0's refuses it always.
    let ip = fake_ip(dir.path(), sys.path(), &["eth0"], &["wlan0"]);
    let plan = set_back(&[("eth0", DECOY_MAC), ("wlan0", "11:22:33:44:55:66")]);

    let kept = apply_links_with(Some(&ip), &plan, sys.path());

    assert_eq!(address(sys.path(), "eth0"), DECOY_MAC);
    assert_eq!(kept, ["wlan0"]);
    assert_eq!(
        ip_calls(dir.path()),
        [
            format!("link set dev eth0 address {DECOY_MAC}"),
            "link set dev wlan0 address 11:22:33:44:55:66".to_string(),
        ],
        "one change each, and neither link is brought up"
    );
    assert_eq!(flags(sys.path(), "eth0"), "0x1002");
    assert_eq!(flags(sys.path(), "wlan0"), "0x1002");
}

#[test]
fn an_address_that_still_does_not_take_is_reported() {
    let sys = sys_with(&[("eth0", 2, SESSION_MAC, true)]);
    set_up(sys.path(), "eth0", true);
    let dir = tempfile::tempdir().unwrap();
    // A driver that refuses the change even with the link down.
    let ip = fake_ip(dir.path(), sys.path(), &[], &["eth0"]);
    let plan = set_back(&[("eth0", DECOY_MAC)]);

    let kept = apply_links_with(Some(&ip), &plan, sys.path());

    assert_eq!(kept, ["eth0"], "the session's address stayed");
    assert_eq!(address(sys.path(), "eth0"), SESSION_MAC);
    let set = format!("link set dev eth0 address {DECOY_MAC}");
    assert_eq!(
        ip_calls(dir.path()),
        [
            set.as_str(),
            "link set dev eth0 down",
            set.as_str(),
            "link set dev eth0 up"
        ]
    );
    assert_eq!(flags(sys.path(), "eth0"), "0x1003", "up again, as it was");

    // Without `ip` nothing changes, and the device is reported all the same.
    assert_eq!(apply_links_with(None, &plan, sys.path()), ["eth0"]);
}

#[test]
fn a_device_that_is_gone_has_no_address_left_to_report() {
    // An adapter pulled after the links were read: its address went with it.
    let sys = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ip = fake_ip(dir.path(), sys.path(), &[], &[]);

    let kept = apply_links_with(Some(&ip), &set_back(&[("eth1", DECOY_MAC)]), sys.path());

    assert!(kept.is_empty(), "{kept:?}");
    assert_eq!(
        ip_calls(dir.path()),
        [format!("link set dev eth1 address {DECOY_MAC}")],
        "no down and up for a link that is not there"
    );
}
