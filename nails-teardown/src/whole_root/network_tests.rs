// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::test_support::{FakeNet, FakeNetKernel};
use std::fs;

/// A fake `/sys/class/net` tree. A link with a `device` entry reads as a
/// hardware device; one without reads as virtual.
fn sys_with(links: &[(&str, u32, &str, bool)]) -> tempfile::TempDir {
    let sys = tempfile::tempdir().unwrap();
    for (name, index, mac, is_hardware) in links {
        add_link(sys.path(), name, *index, mac, *is_hardware);
    }
    sys
}

fn add_link(sys: &Path, name: &str, index: u32, mac: &str, is_hardware: bool) {
    let dir = sys.join(name);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("ifindex"), format!("{index}\n")).unwrap();
    fs::write(dir.join("address"), format!("{mac}\n")).unwrap();
    if is_hardware {
        fs::create_dir(dir.join("device")).unwrap();
    }
}

/// Make link `name` of the fake tree a Wi-Fi interface of radio `phy`.
fn on_radio(sys: &Path, name: &str, phy: &str) {
    std::os::unix::fs::symlink(
        format!("../../ieee80211/{phy}"),
        sys.join(name).join("phy80211"),
    )
    .unwrap();
}

fn link(name: &str, index: u32, virtual_link: bool, mac: Option<&str>) -> Link {
    Link {
        index,
        name: name.to_string(),
        virtual_link,
        mac: mac.map(str::to_string),
        phy: None,
    }
}

/// A Wi-Fi interface of radio `phy`.
fn wifi(name: &str, index: u32, phy: &str) -> Link {
    Link {
        phy: Some(phy.to_string()),
        ..link(name, index, false, Some("02:00:00:00:00:aa"))
    }
}

/// A record of `links` and `hostname`, with nothing else known.
fn record_of(links: Vec<Link>, hostname: &[u8]) -> NetworkRecord {
    NetworkRecord {
        links: Some(links),
        hostname: hostname.to_vec(),
        policy: Policy::default(),
        run: Some(Vec::new()),
    }
}

#[test]
fn the_links_are_read_with_their_index_address_radio_and_whether_the_kernel_made_them() {
    let sys = sys_with(&[
        ("lo", 1, "00:00:00:00:00:00", false),
        ("eth0", 2, "aa:bb:cc:dd:ee:ff", true),
        ("wlan0", 3, "02:00:00:00:00:aa", true),
        ("wg0", 7, "", false),
    ]);
    on_radio(sys.path(), "wlan0", "phy0");
    let links = observe_links(sys.path()).unwrap();
    assert_eq!(
        links,
        vec![
            link("eth0", 2, false, Some("aa:bb:cc:dd:ee:ff")),
            link("lo", 1, true, Some("00:00:00:00:00:00")),
            // An empty address file is no address.
            link("wg0", 7, true, None),
            wifi("wlan0", 3, "phy0"),
        ]
    );
    // Neither a directory without an interface index nor a file is a link.
    fs::create_dir(sys.path().join("bonding_masters")).unwrap();
    fs::write(sys.path().join("bonding_opts"), "").unwrap();
    assert_eq!(observe_links(sys.path()).unwrap().len(), 4);
    // A list that cannot be read is unknown, not empty.
    assert_eq!(observe_links(&sys.path().join("gone")), None);
    // So is a link whose index is not a number.
    fs::write(sys.path().join("wg0/ifindex"), "seven\n").unwrap();
    assert_eq!(observe_links(sys.path()), None);
}

#[test]
fn a_virtual_link_that_is_not_the_decoys_is_deleted_and_a_new_device_is_left() {
    let record = record_of(
        vec![link("lo", 1, true, None), link("eth0", 2, false, None)],
        b"decoy",
    );
    let current = vec![
        link("lo", 1, true, None),
        link("eth0", 2, false, None),
        // The session's tunnel: virtual, new.
        link("wg0", 9, true, Some("de:ad:be:ef:00:01")),
        // A hot-plugged adapter: a device, new, so left alone.
        link("eth1", 10, false, Some("aa:00:00:00:00:02")),
    ];
    let plan = plan(&record, &current, b"decoy");
    assert_eq!(plan.delete, ["wg0"]);
    assert!(plan.delete_wireless.is_empty());
    assert!(plan.set_mac.is_empty());
    assert!(plan.hostname.is_none());
}

#[test]
fn a_link_the_session_made_again_under_a_decoy_links_name_is_deleted() {
    // The decoy's wg0 was up at entry; its own stop took it down for the
    // switch, and the session brought up a tunnel of its own as wg0.
    let record = record_of(
        vec![
            link("lo", 1, true, None),
            link("wg0", 5, true, None),
            link("eth0", 2, false, Some("aa:bb:cc:dd:ee:ff")),
        ],
        b"decoy",
    );
    let current = vec![
        link("lo", 1, true, None),
        link("wg0", 12, true, None),
        // A device the driver registered again under its name: not the
        // decoy's link, but hardware, so left alone, and its address too.
        link("eth0", 13, false, Some("de:ad:be:ef:ca:fe")),
    ];
    let plan = plan(&record, &current, b"decoy");
    assert_eq!(plan.delete, ["wg0"]);
    assert!(plan.set_mac.is_empty(), "{:?}", plan.set_mac);
}

#[test]
fn a_decoy_link_the_session_only_renamed_is_still_the_decoys() {
    // The session renamed the decoy's bridge and Wi-Fi interface (a link file
    // of its own, say): each keeps its index, so neither is deleted, and the
    // interface gets its address back under its new name.
    let record = record_of(
        vec![link("br0", 4, true, None), wifi("wlp3s0", 3, "phy0")],
        b"decoy",
    );
    let current = vec![
        link("lan", 4, true, None),
        Link {
            mac: Some(SESSION_MAC.to_string()),
            ..wifi("wlan0", 3, "phy0")
        },
    ];
    let plan = plan(&record, &current, b"decoy");
    assert!(plan.delete.is_empty(), "{plan:?}");
    assert!(plan.delete_wireless.is_empty(), "{plan:?}");
    assert_eq!(
        plan.set_mac,
        vec![("wlan0".to_string(), "02:00:00:00:00:aa".to_string())]
    );
}

#[test]
fn a_wifi_interface_the_session_added_on_a_decoy_radio_is_deleted_and_a_new_adapter_is_left() {
    let record = record_of(vec![wifi("wlan0", 3, "phy0")], b"decoy");
    let current = vec![
        wifi("wlan0", 3, "phy0"),
        // A monitor interface on the decoy's radio, and one on a radio the
        // decoy did not have (a Wi-Fi adapter plugged in during the session).
        wifi("wlan0mon", 14, "phy0"),
        wifi("wlan1", 15, "phy1"),
    ];
    let plan = plan(&record, &current, b"decoy");
    assert_eq!(plan.delete_wireless, ["wlan0mon"]);
    assert!(plan.delete.is_empty());
}

#[test]
fn an_interface_made_in_place_of_the_decoys_goes_and_the_decoys_is_not_made_again() {
    // The session's iwd deleted the decoy's interface when it started and made
    // one of its own on the same radio, under a new index.
    let record = record_of(vec![wifi("wlan0", 3, "phy0")], b"decoy");
    let current = vec![wifi("wlan0", 16, "phy0")];
    let plan = plan(&record, &current, b"decoy");
    assert_eq!(plan.delete_wireless, ["wlan0"]);
    assert!(plan.set_mac.is_empty(), "{:?}", plan.set_mac);
}

#[test]
fn a_device_whose_address_the_session_changed_gets_its_own_back() {
    let record = record_of(
        vec![
            link("lo", 1, true, Some("00:00:00:00:00:00")),
            link("eth0", 2, false, Some("aa:bb:cc:dd:ee:ff")),
            link("wlan0", 3, false, Some("11:22:33:44:55:66")),
        ],
        b"decoy",
    );
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
    let record = record_of(vec![link("eth0", 2, false, Some("aa:bb:cc:dd:ee:ff"))], b"");
    // The decoy's device is not in the current list: nothing to set it on.
    assert!(plan(&record, &[], b"").set_mac.is_empty());
}

#[test]
fn without_the_decoys_links_no_link_is_deleted_or_changed() {
    let record = NetworkRecord {
        links: None,
        ..record_of(Vec::new(), b"decoy")
    };
    let current = vec![
        link("br0", 4, true, None),
        link("eth0", 2, false, Some("de:ad:be:ef:ca:fe")),
        wifi("wlan0mon", 14, "phy0"),
    ];
    let plan = plan(&record, &current, b"decoy");
    assert_eq!(plan, RestorePlan::default());
}

#[test]
fn the_hostname_is_set_back_wherever_it_differs() {
    let record = record_of(Vec::new(), b"decoy-host");
    // The session's name: set the decoy's back, whatever /etc/hostname holds
    // (PID 1 then sets a valid one again itself, and keeps this one when the
    // file is missing, empty or names no valid host).
    assert_eq!(
        plan(&record, &[], b"hidden-host").hostname,
        Some(b"decoy-host".to_vec())
    );
    // Already the decoy's: nothing.
    assert!(plan(&record, &[], b"decoy-host").hostname.is_none());
    // A hostname entry could not read is never written.
    let empty = record_of(Vec::new(), b"");
    assert!(plan(&empty, &[], b"hidden-host").hostname.is_none());
}

/// The places of a test world: a fake `/sys/class/net`, hostname file,
/// `/proc/sys` and `/run`, all below `root`.
fn places(root: &Path) -> Places {
    Places {
        run: root.join("run"),
        sys_class_net: root.join("sys"),
        proc_hostname: root.join("hostname"),
        proc_sys: root.join("proc-sys"),
    }
}

/// A test world: lo and eth0, the hostname `decoy-host`, forwarding off and
/// NetworkManager's per-link state for eth0.
fn world() -> (tempfile::TempDir, Places) {
    let dir = tempfile::tempdir().unwrap();
    let places = places(dir.path());
    fs::create_dir_all(&places.sys_class_net).unwrap();
    add_link(&places.sys_class_net, "lo", 1, "00:00:00:00:00:00", false);
    add_link(&places.sys_class_net, "eth0", 2, "aa:bb:cc:dd:ee:ff", true);
    fs::write(&places.proc_hostname, "decoy-host\n").unwrap();
    fs::create_dir_all(places.proc_sys.join("net/ipv4")).unwrap();
    fs::write(places.proc_sys.join("net/ipv4/ip_forward"), "0\n").unwrap();
    fs::create_dir_all(places.run.join("NetworkManager/devices")).unwrap();
    fs::write(
        places.run.join("NetworkManager/devices/2"),
        "[device]\nmanaged=true\n",
    )
    .unwrap();
    (dir, places)
}

#[test]
fn the_record_round_trips_and_rejects_what_the_way_back_could_not_act_on() {
    let (_dir, places) = world();
    let record = NetworkRecord::capture(&places, &FakeNetKernel::offline());
    assert_eq!(NetworkRecord::decode(&record.encode()), Some(record));
    assert!(NetworkRecord::decode(b"not json").is_none());
    let policy = r#"{"rules_v4":null,"rules_v6":null,"tables":null,"settings":[]}"#;
    let with = |links: &str, policy: &str, run: &str| {
        format!(r#"{{"links":{links},"hostname":[],"policy":{policy},"run":{run}}}"#).into_bytes()
    };
    assert!(NetworkRecord::decode(&with("null", policy, "null")).is_some());
    // A runtime path that leaves the managed directories.
    for path in ["NetworkManager/../../etc", "systemd/system"] {
        let run = format!(r#"[{{"path":"{path}","kind":"Dir","uid":0,"gid":0,"mode":493}}]"#);
        assert!(
            NetworkRecord::decode(&with("[]", policy, &run)).is_none(),
            "{path}"
        );
    }
    // A setting outside the network settings, and a table in no known family.
    let setting = r#"{"rules_v4":null,"rules_v6":null,"tables":null,
        "settings":[{"key":"kernel/modprobe","value":"/tmp/x"}]}"#;
    assert!(NetworkRecord::decode(&with("[]", setting, "[]")).is_none());
    let table = r#"{"rules_v4":null,"rules_v6":null,"settings":[],
        "tables":[{"family":"ip; flush ruleset","name":"x","handle":1}]}"#;
    assert!(NetworkRecord::decode(&with("[]", table, "[]")).is_none());
}

#[test]
fn the_hostname_file_is_read_trimmed_and_written_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hostname");
    fs::write(&path, "decoy-host\n").unwrap();
    assert_eq!(read_hostname(&path), b"decoy-host");
    write_hostname(&path, b"other").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"other");
    // An absent file reads as empty.
    assert!(read_hostname(Path::new("/no/such/hostname")).is_empty());
}

#[test]
fn restore_without_a_record_changes_nothing() {
    let (_dir, places) = world();
    add_link(&places.sys_class_net, "wg0", 9, "", false);
    fs::write(&places.proc_hostname, "live-host\n").unwrap();
    let before = network_run::snapshot(&places.run);
    // No record at all, and an unparsable one: both leave the world untouched.
    let kernel = FakeNetKernel::new(Some(&places.sys_class_net), FakeNet::default());
    assert_eq!(restore_with(&places, &kernel, None), Kept::default());
    assert_eq!(
        restore_with(&places, &kernel, Some(b"not a record")),
        Kept::default()
    );
    assert!(kernel.calls().is_empty(), "{:?}", kernel.calls());
    assert_eq!(network_run::snapshot(&places.run), before);
    assert_eq!(read_hostname(&places.proc_hostname), b"live-host");
    assert!(places.sys_class_net.join("wg0").exists());
}

#[test]
fn restore_puts_the_hostname_settings_and_runtime_state_back() {
    let (_dir, places) = world();
    let record = NetworkRecord::capture(&places, &FakeNetKernel::offline());
    // The session: its hostname, forwarding on, a device file of its own.
    fs::write(&places.proc_hostname, "hidden-host\n").unwrap();
    fs::write(places.proc_sys.join("net/ipv4/ip_forward"), "1\n").unwrap();
    let devices = places.run.join("NetworkManager/devices");
    fs::write(devices.join("2"), "[device]\nconnection-uuid=hidden\n").unwrap();
    fs::write(devices.join("9"), "[device]\n").unwrap();

    let kept = restore_with(&places, &FakeNetKernel::offline(), Some(&record.encode()));

    assert_eq!(read_hostname(&places.proc_hostname), b"decoy-host");
    assert_eq!(
        fs::read_to_string(places.proc_sys.join("net/ipv4/ip_forward")).unwrap(),
        "0"
    );
    assert_eq!(
        fs::read_to_string(devices.join("2")).unwrap(),
        "[device]\nmanaged=true\n"
    );
    assert!(!devices.join("9").exists());
    // A kernel that listed neither at entry leaves the rules and tables
    // unknown, and the way back leaves them alone.
    assert_eq!(
        kept,
        Kept {
            unknown: vec!["IPv4 rules", "IPv6 rules", "firewall tables"],
            ..Kept::default()
        }
    );
}

#[test]
fn restore_leaves_the_links_and_runtime_state_alone_when_entry_could_not_read_them() {
    let (_dir, places) = world();
    // Entry could read neither the links nor the runtime state.
    let record = NetworkRecord {
        links: None,
        run: None,
        ..NetworkRecord::capture(&places, &FakeNetKernel::offline())
    };
    // The decoy's own bridge, the session's change to the decoy's device file.
    add_link(&places.sys_class_net, "br0", 4, "02:00:00:00:00:04", false);
    let devices = places.run.join("NetworkManager/devices");
    fs::write(devices.join("2"), "[device]\nconnection-uuid=hidden\n").unwrap();
    let kernel = FakeNetKernel::new(Some(&places.sys_class_net), FakeNet::default());

    let kept = restore_with(&places, &kernel, Some(&record.encode()));

    assert!(places.sys_class_net.join("br0").exists());
    assert!(
        kernel
            .calls()
            .iter()
            .all(|call| !call.contains("link") && !call.starts_with("set")),
        "{:?}",
        kernel.calls()
    );
    assert_eq!(
        fs::read_to_string(devices.join("2")).unwrap(),
        "[device]\nconnection-uuid=hidden\n",
        "an unknown copy deletes and rewrites nothing"
    );
    assert!(kept.unknown.contains(&"links"), "{kept:?}");
    assert!(kept.unknown.contains(&"runtime state"), "{kept:?}");
}

#[test]
fn restore_deletes_the_sessions_links_and_names_what_it_could_not() {
    let (_dir, places) = world();
    on_radio(&places.sys_class_net, "eth0", "phy0");
    let record = NetworkRecord::capture(&places, &FakeNetKernel::offline());
    // The session's tunnel, its tunnel made again under a name the decoy had
    // not, and a monitor interface on the decoy's radio.
    add_link(&places.sys_class_net, "wg0", 9, "", false);
    add_link(&places.sys_class_net, "mon0", 10, "02:00:00:00:00:0a", true);
    on_radio(&places.sys_class_net, "mon0", "phy0");

    // A kernel that changes nothing leaves both, and both are named.
    let kept = restore_with(&places, &FakeNetKernel::offline(), Some(&record.encode()));
    assert_eq!(kept.links, ["wg0", "mon0"]);

    let kernel = FakeNetKernel::new(Some(&places.sys_class_net), FakeNet::default());
    let kept = restore_with(&places, &kernel, Some(&record.encode()));
    assert!(!places.sys_class_net.join("wg0").exists());
    assert!(!places.sys_class_net.join("mon0").exists());
    assert!(kept.links.is_empty(), "{kept:?}");
    assert!(places.sys_class_net.join("eth0").exists());
    assert_eq!(kernel.calls(), ["delete wireless mon0", "delete link wg0"]);
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
        set_mac: macs
            .iter()
            .map(|(name, mac)| (name.to_string(), mac.to_string()))
            .collect(),
        ..RestorePlan::default()
    }
}

/// A kernel that changes the fake tree `sys` as the kernel would, whose
/// links in `busy_while_up` refuse an address change while they are up, as a
/// driver without live address change does (`EBUSY`), and whose links in
/// `refusing` refuse it always.
fn kernel_for(sys: &Path, busy_while_up: &[&str], refusing: &[&str]) -> FakeNetKernel {
    let names = |list: &[&str]| list.iter().map(|name| name.to_string()).collect();
    FakeNetKernel::new(
        Some(sys),
        FakeNet {
            busy_while_up: names(busy_while_up),
            refusing: names(refusing),
            ..FakeNet::default()
        },
    )
}

#[test]
fn the_links_are_deleted_each_the_way_the_kernel_deletes_it() {
    let sys = sys_with(&[
        ("wg0", 9, "", false),
        ("mon0", 10, "02:00:00:00:00:0a", true),
    ]);
    let kernel = kernel_for(sys.path(), &[], &[]);
    let plan = RestorePlan {
        delete: vec!["wg0".to_string()],
        delete_wireless: vec!["mon0".to_string()],
        ..RestorePlan::default()
    };

    let kept = apply_links_with(&kernel, &plan, sys.path());

    assert_eq!(kept, Kept::default());
    assert_eq!(kernel.calls(), ["delete wireless mon0", "delete link wg0"]);
    assert!(observe_links(sys.path()).unwrap().is_empty());

    // A kernel that changes nothing deletes neither, and both are named.
    let sys = sys_with(&[
        ("wg0", 9, "", false),
        ("mon0", 10, "02:00:00:00:00:0a", true),
    ]);
    let kept = apply_links_with(&FakeNetKernel::offline(), &plan, sys.path());
    assert_eq!(kept.links, ["wg0", "mon0"]);
}

#[test]
fn an_address_the_driver_changes_live_is_set_without_taking_the_link_down() {
    let sys = sys_with(&[("eth0", 2, SESSION_MAC, true)]);
    set_up(sys.path(), "eth0", true);
    let kernel = kernel_for(sys.path(), &[], &[]);

    let kept = apply_links_with(&kernel, &set_back(&[("eth0", DECOY_MAC)]), sys.path());

    assert_eq!(kept, Kept::default());
    assert_eq!(address(sys.path(), "eth0"), DECOY_MAC);
    assert_eq!(
        kernel.calls(),
        [format!("set eth0 address {DECOY_MAC}")],
        "one live change, no down and up"
    );
    assert_eq!(flags(sys.path(), "eth0"), "0x1003");
}

#[test]
fn a_driver_that_refuses_a_live_change_gets_the_address_with_the_link_down_and_up_again() {
    let sys = sys_with(&[("eth0", 2, SESSION_MAC, true)]);
    set_up(sys.path(), "eth0", true);
    // A USB Ethernet adapter whose driver refuses to change a running device.
    let kernel = kernel_for(sys.path(), &["eth0"], &[]);

    let kept = apply_links_with(&kernel, &set_back(&[("eth0", DECOY_MAC)]), sys.path());

    assert_eq!(kept, Kept::default());
    assert_eq!(address(sys.path(), "eth0"), DECOY_MAC);
    let set = format!("set eth0 address {DECOY_MAC}");
    assert_eq!(
        kernel.calls(),
        [set.as_str(), "set eth0 down", set.as_str(), "set eth0 up"]
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
    // eth0's driver refuses a change only while the link runs, so on the down
    // link it takes at once; wlan0's refuses it always.
    let kernel = kernel_for(sys.path(), &["eth0"], &["wlan0"]);
    let plan = set_back(&[("eth0", DECOY_MAC), ("wlan0", "11:22:33:44:55:66")]);

    let kept = apply_links_with(&kernel, &plan, sys.path());

    assert_eq!(address(sys.path(), "eth0"), DECOY_MAC);
    assert_eq!(kept.addresses, ["wlan0"]);
    assert_eq!(
        kernel.calls(),
        [
            format!("set eth0 address {DECOY_MAC}"),
            "set wlan0 address 11:22:33:44:55:66".to_string(),
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
    // A driver that refuses the change even with the link down.
    let kernel = kernel_for(sys.path(), &[], &["eth0"]);
    let plan = set_back(&[("eth0", DECOY_MAC)]);

    let kept = apply_links_with(&kernel, &plan, sys.path());

    assert_eq!(kept.addresses, ["eth0"], "the session's address stayed");
    assert_eq!(address(sys.path(), "eth0"), SESSION_MAC);
    let set = format!("set eth0 address {DECOY_MAC}");
    assert_eq!(
        kernel.calls(),
        [set.as_str(), "set eth0 down", set.as_str(), "set eth0 up"]
    );
    assert_eq!(flags(sys.path(), "eth0"), "0x1003", "up again, as it was");

    // A kernel that changes nothing leaves it, and the device is reported all
    // the same.
    assert_eq!(
        apply_links_with(&FakeNetKernel::offline(), &plan, sys.path()).addresses,
        ["eth0"]
    );
}

#[test]
fn a_device_that_is_gone_has_no_address_left_to_report() {
    // An adapter pulled after the links were read: its address went with it.
    let sys = tempfile::tempdir().unwrap();
    let kernel = kernel_for(sys.path(), &[], &[]);

    let kept = apply_links_with(&kernel, &set_back(&[("eth1", DECOY_MAC)]), sys.path());

    assert_eq!(kept, Kept::default());
    assert!(
        kernel.calls().is_empty(),
        "nothing is asked of a link that is not there: {:?}",
        kernel.calls()
    );
}

#[test]
fn the_record_name_carries_no_product_name() {
    assert!(!RECORD_NAME.to_lowercase().contains("nails"));
}

/// A way back whose restore left nothing of the session's and checked it all
/// has failed nothing, and so is a return; what entry could not record is
/// left alone and is no failure either, and neither is a network setting it
/// could not write back.
#[test]
fn nothing_failed_when_all_is_back_or_only_left_alone() {
    assert!(!Kept::default().failed());
    let left_alone = Kept {
        settings: vec!["net/ipv4/ip_forward".to_string()],
        unknown: vec!["links", "IPv4 rules", "IPv6 rules", "firewall tables"],
        ..Kept::default()
    };
    assert!(!left_alone.failed(), "{left_alone:?}");
}

/// Each part still the session's, and each part the way back could not read
/// back, is a failure on its own.
#[test]
fn each_part_the_way_back_could_not_undo_or_check_is_a_failure() {
    let parts = [
        Kept {
            addresses: vec!["eth0".to_string()],
            ..Kept::default()
        },
        Kept {
            links: vec!["tunl0".to_string()],
            ..Kept::default()
        },
        Kept {
            rules: vec!["-4 100: from all lookup 51820".to_string()],
            ..Kept::default()
        },
        Kept {
            tables: vec!["inet mullvad".to_string()],
            ..Kept::default()
        },
        Kept {
            unverified: vec!["IPv6 rules"],
            ..Kept::default()
        },
    ];
    for kept in parts {
        assert!(kept.failed(), "{kept:?}");
    }
}

/// A kernel that takes no change still shows, in its list of links, the
/// address the session gave the decoy's device and the link it made: those
/// are failures.
#[test]
fn a_kernel_that_takes_no_change_fails_where_the_session_changed_what_it_would_undo() {
    let (_dir, places) = world();
    let record = NetworkRecord::capture(&places, &FakeNetKernel::offline());
    let kernel = FakeNetKernel::offline();
    assert!(
        !restore_with(&places, &kernel, Some(&record.encode())).failed(),
        "nothing to undo"
    );
    fs::write(
        places.sys_class_net.join("eth0/address"),
        "02:00:00:00:00:99\n",
    )
    .unwrap();
    add_link(&places.sys_class_net, "wg0", 9, "", false);

    let kept = restore_with(&places, &kernel, Some(&record.encode()));

    assert!(kept.failed());
    assert_eq!(kept.addresses, ["eth0"]);
    assert_eq!(kept.links, ["wg0"]);
}

/// Links the kernel's list cannot be read of now are unverified: the way back
/// does not know whether a link or address of the session's is still there.
#[test]
fn links_that_cannot_be_read_on_the_way_back_are_unverified() {
    let (_dir, places) = world();
    let record = NetworkRecord::capture(&places, &FakeNetKernel::offline());
    fs::write(places.sys_class_net.join("eth0/ifindex"), "two\n").unwrap();

    let kept = restore_with(&places, &FakeNetKernel::offline(), Some(&record.encode()));

    assert_eq!(kept.unverified, ["links"]);
    assert!(!kept.unknown.contains(&"links"), "{kept:?}");
    assert!(kept.failed());
}

/// Before the switch the hidden session tells what the way back could not
/// undo of the links as they are now: a fallback tunnel device the kernel
/// keeps. Nothing changes.
#[test]
fn the_way_back_foresees_what_it_could_not_undo_now() {
    let (_dir, places) = world();
    let sys = &places.sys_class_net;
    let record = NetworkRecord::capture(&places, &FakeNetKernel::offline()).encode();
    assert_eq!(foresee(&places, Some(&record)), Foreseen::default());
    assert!(!foresee(&places, Some(&record)).powers_off());

    add_link(sys, "tunl0", 7, "", false);
    add_link(sys, "wg0", 9, "", false);
    fs::write(sys.join("eth0/address"), "02:00:00:00:00:99\n").unwrap();

    let foreseen = foresee(&places, Some(&record));
    assert_eq!(
        foreseen,
        Foreseen {
            kernel_kept: vec!["tunl0".to_string()],
        }
    );
    assert!(foreseen.powers_off());
    assert_eq!(address(sys, "eth0"), "02:00:00:00:00:99", "nothing changed");
    assert!(sys.join("wg0").exists());
}

/// Nothing is foreseen where the way back leaves the links alone: with no
/// record, a record without them, or a fallback device the decoy had at
/// entry; nor where the links cannot be read now.
#[test]
fn nothing_is_foreseen_where_the_way_back_leaves_the_links_alone() {
    let (_dir, places) = world();
    let sys = &places.sys_class_net;
    add_link(sys, "tunl0", 7, "", false);
    assert_eq!(foresee(&places, None), Foreseen::default());
    let offline = FakeNetKernel::offline();
    let record = NetworkRecord::capture(&places, &offline).encode();
    assert_eq!(foresee(&places, Some(&record)), Foreseen::default());
    let without_links = NetworkRecord {
        links: None,
        ..NetworkRecord::capture(&places, &offline)
    };
    add_link(sys, "sit0", 8, "", false);
    assert_eq!(
        foresee(&places, Some(&without_links.encode())),
        Foreseen::default()
    );
    fs::write(sys.join("eth0/ifindex"), "two\n").unwrap();
    assert_eq!(foresee(&places, Some(&record)), Foreseen::default());
}
