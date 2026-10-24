// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::test_support::write_executable;
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
    let record = NetworkRecord::capture(&places, &NetTools::default());
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
    let tools = NetTools::default();
    assert_eq!(restore_with(&places, &tools, None), Kept::default());
    assert_eq!(
        restore_with(&places, &tools, Some(b"not a record")),
        Kept::default()
    );
    assert_eq!(network_run::snapshot(&places.run), before);
    assert_eq!(read_hostname(&places.proc_hostname), b"live-host");
    assert!(places.sys_class_net.join("wg0").exists());
}

#[test]
fn restore_puts_the_hostname_settings_and_runtime_state_back() {
    let (_dir, places) = world();
    let record = NetworkRecord::capture(&places, &NetTools::default());
    // The session: its hostname, forwarding on, a device file of its own.
    fs::write(&places.proc_hostname, "hidden-host\n").unwrap();
    fs::write(places.proc_sys.join("net/ipv4/ip_forward"), "1\n").unwrap();
    let devices = places.run.join("NetworkManager/devices");
    fs::write(devices.join("2"), "[device]\nconnection-uuid=hidden\n").unwrap();
    fs::write(devices.join("9"), "[device]\n").unwrap();

    let kept = restore_with(&places, &NetTools::default(), Some(&record.encode()));

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
    // Without `ip` or `nft` at entry the rules and tables are unknown, and
    // the way back leaves them alone.
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
        ..NetworkRecord::capture(&places, &NetTools::default())
    };
    // The decoy's own bridge, the session's change to the decoy's device file.
    add_link(&places.sys_class_net, "br0", 4, "02:00:00:00:00:04", false);
    let devices = places.run.join("NetworkManager/devices");
    fs::write(devices.join("2"), "[device]\nconnection-uuid=hidden\n").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let tools = NetTools {
        ip: Some(fake_ip(dir.path(), &places.sys_class_net, &[], &[])),
        ..NetTools::default()
    };

    let kept = restore_with(&places, &tools, Some(&record.encode()));

    assert!(places.sys_class_net.join("br0").exists());
    assert!(
        ip_calls(dir.path())
            .iter()
            .all(|call| !call.starts_with("link")),
        "{:?}",
        ip_calls(dir.path())
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
    let record = NetworkRecord::capture(&places, &NetTools::default());
    // The session's tunnel, its tunnel made again under a name the decoy had
    // not, and a monitor interface on the decoy's radio.
    add_link(&places.sys_class_net, "wg0", 9, "", false);
    add_link(&places.sys_class_net, "mon0", 10, "02:00:00:00:00:0a", true);
    on_radio(&places.sys_class_net, "mon0", "phy0");
    let dir = tempfile::tempdir().unwrap();
    let mut tools = NetTools {
        ip: Some(fake_ip(dir.path(), &places.sys_class_net, &[], &[])),
        iw: None,
        nft: None,
    };

    // Without `iw` the monitor interface stays, and is named.
    let kept = restore_with(&places, &tools, Some(&record.encode()));
    assert!(!places.sys_class_net.join("wg0").exists());
    assert_eq!(kept.links, ["mon0"]);

    tools.iw = Some(fake_iw(dir.path(), &places.sys_class_net));
    let kept = restore_with(&places, &tools, Some(&record.encode()));
    assert!(!places.sys_class_net.join("mon0").exists());
    assert!(kept.links.is_empty(), "{kept:?}");
    assert!(places.sys_class_net.join("eth0").exists());
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

/// A fake `ip` in `dir` that changes the fake `/sys/class/net` tree `sys` as
/// the kernel would (`link delete dev NAME`, `link set dev NAME up`, `down` or
/// `address MAC`) and logs each call. A link in `busy_while_up` refuses an
/// address change while it is up, as a driver without live address change
/// does (`EBUSY`); a link in `refusing` refuses it always. A link that is not
/// there fails every call.
fn fake_ip(dir: &Path, sys: &Path, busy_while_up: &[&str], refusing: &[&str]) -> PathBuf {
    let tool = dir.join("ip");
    write_executable(
        &tool,
        format!(
            "#!/bin/sh\n\
             echo \"$*\" >> '{calls}'\n\
             if [ \"$1 $2 $3\" = 'link delete dev' ]; then\n\
             [ -d '{sys}'/\"$4\" ] && rm -r '{sys}'/\"$4\"; exit $?\n\
             fi\n\
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

/// A fake `iw` in `dir` that deletes an interface of the fake tree `sys`
/// (`dev NAME del`) and logs each call.
fn fake_iw(dir: &Path, sys: &Path) -> PathBuf {
    let tool = dir.join("iw");
    write_executable(
        &tool,
        format!(
            "#!/bin/sh\n\
             echo \"iw $*\" >> '{calls}'\n\
             [ \"$1 $3\" = 'dev del' ] && [ -d '{sys}'/\"$2\" ] && rm -r '{sys}'/\"$2\"\n",
            calls = dir.join("calls").display(),
            sys = sys.display(),
        ),
        0o755,
    );
    tool
}

/// The calls the fake tools in `dir` logged, in order.
fn ip_calls(dir: &Path) -> Vec<String> {
    fs::read_to_string(dir.join("calls"))
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn the_links_are_deleted_with_the_tool_each_one_needs() {
    let sys = sys_with(&[
        ("wg0", 9, "", false),
        ("mon0", 10, "02:00:00:00:00:0a", true),
    ]);
    let dir = tempfile::tempdir().unwrap();
    let ip = fake_ip(dir.path(), sys.path(), &[], &[]);
    let iw = fake_iw(dir.path(), sys.path());
    let plan = RestorePlan {
        delete: vec!["wg0".to_string()],
        delete_wireless: vec!["mon0".to_string()],
        ..RestorePlan::default()
    };

    let kept = apply_links_with(Some(&ip), Some(&iw), &plan, sys.path());

    assert_eq!(kept, Kept::default());
    assert_eq!(
        ip_calls(dir.path()),
        ["iw dev mon0 del", "link delete dev wg0"]
    );
    assert!(observe_links(sys.path()).unwrap().is_empty());

    // Without the tools nothing goes, and both are named.
    let sys = sys_with(&[
        ("wg0", 9, "", false),
        ("mon0", 10, "02:00:00:00:00:0a", true),
    ]);
    let kept = apply_links_with(None, None, &plan, sys.path());
    assert_eq!(kept.links, ["wg0", "mon0"]);
}

#[test]
fn an_address_the_driver_changes_live_is_set_without_taking_the_link_down() {
    let sys = sys_with(&[("eth0", 2, SESSION_MAC, true)]);
    set_up(sys.path(), "eth0", true);
    let dir = tempfile::tempdir().unwrap();
    let ip = fake_ip(dir.path(), sys.path(), &[], &[]);

    let kept = apply_links_with(
        Some(&ip),
        None,
        &set_back(&[("eth0", DECOY_MAC)]),
        sys.path(),
    );

    assert_eq!(kept, Kept::default());
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

    let kept = apply_links_with(
        Some(&ip),
        None,
        &set_back(&[("eth0", DECOY_MAC)]),
        sys.path(),
    );

    assert_eq!(kept, Kept::default());
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

    let kept = apply_links_with(Some(&ip), None, &plan, sys.path());

    assert_eq!(address(sys.path(), "eth0"), DECOY_MAC);
    assert_eq!(kept.addresses, ["wlan0"]);
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

    let kept = apply_links_with(Some(&ip), None, &plan, sys.path());

    assert_eq!(kept.addresses, ["eth0"], "the session's address stayed");
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
    assert_eq!(
        apply_links_with(None, None, &plan, sys.path()).addresses,
        ["eth0"]
    );
}

#[test]
fn a_device_that_is_gone_has_no_address_left_to_report() {
    // An adapter pulled after the links were read: its address went with it.
    let sys = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ip = fake_ip(dir.path(), sys.path(), &[], &[]);

    let kept = apply_links_with(
        Some(&ip),
        None,
        &set_back(&[("eth1", DECOY_MAC)]),
        sys.path(),
    );

    assert_eq!(kept, Kept::default());
    assert_eq!(
        ip_calls(dir.path()),
        [format!("link set dev eth1 address {DECOY_MAC}")],
        "no down and up for a link that is not there"
    );
}

#[test]
fn the_record_name_carries_no_product_name() {
    assert!(!RECORD_NAME.to_lowercase().contains("nails"));
}
