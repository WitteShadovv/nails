// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::netlink::route::{AF_INET, AF_INET6, rule_for_tests};
use crate::test_support::{FakeNet, FakeNetKernel};
use std::fs;

/// An IPv4 rule of `priority` that looks up `table`.
fn v4(priority: u32, table: u32) -> Rule {
    rule_for_tests(AF_INET, priority, table, 0)
}

/// An IPv6 rule of `priority` that looks up `table`.
fn v6(priority: u32, table: u32) -> Rule {
    rule_for_tests(AF_INET6, priority, table, 0)
}

fn table(family: &str, name: &str, handle: u64) -> Table {
    Table {
        family: family.to_string(),
        name: name.to_string(),
        handle,
    }
}

#[test]
fn an_item_is_added_only_where_no_recorded_one_accounts_for_it() {
    let recorded = [1, 2, 2, 3];
    assert_eq!(added(&recorded, &[1, 2, 2, 3]), Vec::<&i32>::new());
    // A second copy of a recorded item, and a new one.
    assert_eq!(added(&recorded, &[2, 2, 2, 4, 1]), [&2, &4]);
    // What is gone now is not added.
    assert_eq!(added(&recorded, &[]), Vec::<&i32>::new());
}

/// A rule the kernel lists with the flag of an interface that is gone is the
/// rule entry recorded: the way back does not delete it.
#[test]
fn a_decoy_rule_whose_interface_went_with_the_decoy_s_stop_stays() {
    let attached = rule_for_tests(AF_INET, 100, 51820, 0);
    let detached = rule_for_tests(AF_INET, 100, 51820, 0x8);
    assert_eq!(added(&[attached], &[detached]), Vec::<&Rule>::new());
}

/// A fake `/proc/sys` with the network settings below `root`.
fn proc_sys(root: &Path) -> PathBuf {
    let sys = root.join("proc-sys");
    for (key, value, mode) in [
        ("net/ipv4/ip_forward", "0\n", 0o644),
        ("net/ipv4/conf/all/forwarding", "0\n", 0o644),
        ("net/ipv4/conf/all/arp_ignore", "0\n", 0o644),
        ("net/ipv4/conf/all/mc_forwarding", "0\n", 0o444),
        ("net/ipv4/conf/default/src_valid_mark", "0\n", 0o644),
        ("net/ipv6/conf/all/use_tempaddr", "-1\n", 0o644),
        ("net/ipv6/conf/all/stable_secret", "::1\n", 0o600),
        ("net/ipv6/conf/default/disable_ipv6", "0\n", 0o644),
        // Not a directory the record reads.
        ("net/ipv4/conf/eth0/arp_ignore", "0\n", 0o644),
    ] {
        let path = sys.join(key);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, value).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }
    sys
}

fn setting(key: &str, value: &str) -> Setting {
    Setting {
        key: PathBuf::from(key),
        value: value.to_string(),
    }
}

#[test]
fn the_settings_for_all_and_new_devices_are_read_that_every_user_reads_and_root_writes() {
    let dir = tempfile::tempdir().unwrap();
    let sys = proc_sys(dir.path());
    assert_eq!(
        read_settings(&sys),
        [
            setting("net/ipv4/ip_forward", "0"),
            setting("net/ipv4/conf/all/arp_ignore", "0"),
            setting("net/ipv4/conf/all/forwarding", "0"),
            setting("net/ipv4/conf/default/src_valid_mark", "0"),
            setting("net/ipv6/conf/all/use_tempaddr", "-1"),
            setting("net/ipv6/conf/default/disable_ipv6", "0"),
        ]
    );
    // Without IPv6 (or any of it) there is simply less to read.
    fs::remove_dir_all(sys.join("net/ipv6")).unwrap();
    assert_eq!(read_settings(&sys).len(), 4);
}

#[test]
fn the_settings_the_session_changed_are_written_back() {
    let dir = tempfile::tempdir().unwrap();
    let sys = proc_sys(dir.path());
    // The decoy's own arp_ignore, not the kernel's default: what goes back is
    // what entry found.
    fs::write(sys.join("net/ipv4/conf/all/arp_ignore"), "1\n").unwrap();
    let recorded = read_settings(&sys);
    // A VPN app's settings, and forwarding a container runtime turned on.
    fs::write(sys.join("net/ipv4/ip_forward"), "1\n").unwrap();
    fs::write(sys.join("net/ipv4/conf/all/arp_ignore"), "2\n").unwrap();
    fs::write(sys.join("net/ipv4/conf/default/src_valid_mark"), "1\n").unwrap();
    // One the way back cannot write any more.
    let use_tempaddr = sys.join("net/ipv6/conf/all/use_tempaddr");
    fs::write(&use_tempaddr, "2\n").unwrap();
    fs::set_permissions(&use_tempaddr, fs::Permissions::from_mode(0o444)).unwrap();

    let kept = restore_settings(&sys, &recorded);

    assert_eq!(read_settings(&sys)[..4], recorded[..4]);
    assert_eq!(kept, ["net/ipv6/conf/all/use_tempaddr"]);
    // An empty value is written as one newline, which reads as empty.
    let empty = [setting("net/ipv4/conf/all/forwarding", "")];
    assert!(restore_settings(&sys, &empty).is_empty());
    assert_eq!(
        fs::read_to_string(sys.join("net/ipv4/conf/all/forwarding")).unwrap(),
        "\n"
    );
}

/// The kernel of a decoy with the kernel's own rules, a rule and a table of
/// a VPN of its own, and its settings below `dir`.
fn decoy(dir: &Path) -> (FakeNetKernel, PathBuf) {
    let net = FakeNet {
        rules: [
            Some(vec![
                v4(0, 255),
                v4(32765, 51820),
                v4(32766, 254),
                v4(32767, 253),
            ]),
            Some(vec![v6(0, 255), v6(32766, 254)]),
        ],
        tables: Some(vec![
            table("inet", "filter", 1),
            table("ip", "wg-quick-wg0", 2),
        ]),
        ..FakeNet::default()
    };
    (FakeNetKernel::new(None, net), proc_sys(dir))
}

/// Change the fake kernel's state.
fn with_state(kernel: &FakeNetKernel, change: impl FnOnce(&mut FakeNet)) {
    change(&mut kernel.state.lock().unwrap());
}

#[test]
fn the_rules_and_tables_the_session_added_are_deleted_and_the_decoys_stay() {
    let dir = tempfile::tempdir().unwrap();
    let (kernel, sys) = decoy(dir.path());
    let policy = Policy::capture(&kernel, &sys);
    let decoy_rules = kernel.state.lock().unwrap().rules.clone();
    // The session: a WireGuard full tunnel of its own (two rules per family
    // and a table), the decoy's tunnel table made again under its name after
    // the decoy's stop deleted it, a VPN app's blocking table, and arp_ignore.
    with_state(&kernel, |net| {
        net.rules[0]
            .as_mut()
            .unwrap()
            .extend([v4(32763, 254), v4(32764, 52072)]);
        net.rules[1] = Some(vec![v6(0, 255), v6(32765, 52072), v6(32766, 254)]);
        net.tables = Some(vec![
            table("inet", "filter", 1),
            table("ip", "wg-quick-wg0", 7),
            table("ip", "nm-wg-hidden", 8),
            table("inet", "mullvad", 9),
        ]);
    });
    fs::write(sys.join("net/ipv4/conf/all/arp_ignore"), "2\n").unwrap();
    let mut kept = Kept::default();

    policy.restore(&kernel, &sys, &mut kept);

    assert_eq!(kept, Kept::default());
    let state = kernel.state.lock().unwrap().clone();
    assert_eq!(state.rules, decoy_rules);
    assert_eq!(
        state.tables,
        Some(vec![table("inet", "filter", 1)]),
        "the decoy's tunnel table went at its stop; the one the session made again goes"
    );
    assert_eq!(
        fs::read_to_string(sys.join("net/ipv4/conf/all/arp_ignore")).unwrap(),
        "0"
    );
    assert_eq!(
        state.calls,
        [
            "delete rule IPv4 32763",
            "delete rule IPv4 32764",
            "delete rule IPv6 32765",
            "delete table ip wg-quick-wg0",
            "delete table ip nm-wg-hidden",
            "delete table inet mullvad",
        ]
    );
}

#[test]
fn what_could_not_be_deleted_is_named() {
    let dir = tempfile::tempdir().unwrap();
    let (kernel, sys) = decoy(dir.path());
    let policy = Policy::capture(&kernel, &sys);
    with_state(&kernel, |net| {
        net.rules[0] = Some(vec![v4(0, 255), v4(100, 7)]);
        net.kept_rules = vec![v4(100, 7)];
        net.tables = Some(vec![table("inet", "filter", 1), table("inet", "locked", 5)]);
        net.kept_tables = vec!["locked".to_string()];
    });
    let mut kept = Kept::default();

    policy.restore(&kernel, &sys, &mut kept);

    assert_eq!(kept.rules, ["IPv4 rule 100 (table 7)"]);
    assert_eq!(kept.tables, ["inet locked"]);
    assert!(kept.failed());
}

#[test]
fn a_list_entry_could_not_read_is_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (kernel, sys) = decoy(dir.path());
    // No IPv6 at entry, and no list of tables.
    with_state(&kernel, |net| {
        net.rules[1] = None;
        net.tables = None;
    });
    let policy = Policy::capture(&kernel, &sys);
    assert_eq!(policy.rules_v6, None);
    assert_eq!(policy.tables, None);
    let session_tables = vec![table("inet", "filter", 1), table("inet", "mullvad", 9)];
    with_state(&kernel, |net| {
        net.rules[1] = Some(vec![v6(0, 255), v6(5, 9)]);
        net.tables = Some(session_tables.clone());
    });
    let mut kept = Kept::default();

    policy.restore(&kernel, &sys, &mut kept);

    assert_eq!(kept.unknown, ["IPv6 rules", "firewall tables"]);
    let state = kernel.state.lock().unwrap().clone();
    assert_eq!(
        state.tables,
        Some(session_tables),
        "without the decoy's list no table is deleted"
    );
    assert!(
        state.calls.iter().all(|call| !call.contains("delete")),
        "{:?}",
        state.calls
    );
    // What entry could not read is no failure: the way back cannot tell
    // what of it is the session's.
    assert!(!kept.failed(), "{kept:?}");
}

/// Where nf_tables was not in the kernel at entry there was no table; a
/// table the session's nf_tables holds on the way back is the session's.
#[test]
fn every_table_goes_where_entry_found_none() {
    let dir = tempfile::tempdir().unwrap();
    let (kernel, sys) = decoy(dir.path());
    with_state(&kernel, |net| net.tables = Some(Vec::new()));
    let policy = Policy::capture(&kernel, &sys);
    with_state(&kernel, |net| {
        net.tables = Some(vec![table("inet", "mullvad", 1), table("ip", "nat", 2)]);
    });
    let mut kept = Kept::default();

    policy.restore(&kernel, &sys, &mut kept);

    assert_eq!(kept, Kept::default());
    assert_eq!(kernel.state.lock().unwrap().tables, Some(Vec::new()));
}

/// A part the kernel cannot list now is unverified, not left alone: the
/// session's rules or tables may still be loaded.
#[test]
fn a_list_that_cannot_be_read_on_the_way_back_is_unverified() {
    let dir = tempfile::tempdir().unwrap();
    let (kernel, sys) = decoy(dir.path());
    let policy = Policy::capture(&kernel, &sys);
    // IPv6 went away, and nf_tables cannot be listed now.
    with_state(&kernel, |net| {
        net.rules[1] = None;
        net.tables = None;
    });
    let mut kept = Kept::default();

    policy.restore(&kernel, &sys, &mut kept);

    assert!(kept.unknown.is_empty(), "{kept:?}");
    assert_eq!(kept.unverified, ["IPv6 rules", "firewall tables"]);
    assert!(kept.failed());

    // A list that answers before the deletions and not after them is
    // unverified as well.
    let dir = tempfile::tempdir().unwrap();
    let (kernel, sys) = decoy(dir.path());
    let policy = Policy::capture(&kernel, &sys);
    with_state(&kernel, |net| net.lists_left = Some(1));
    let mut kept = Kept::default();
    policy.restore(&kernel, &sys, &mut kept);
    assert_eq!(
        kept.unverified,
        ["IPv4 rules", "IPv6 rules", "firewall tables"]
    );
}

#[test]
fn only_a_policy_the_way_back_can_act_on_is_valid() {
    let valid = Policy {
        rules_v4: Some(vec![v4(1, 254)]),
        rules_v6: None,
        tables: Some(vec![table("inet", "filter", 1)]),
        settings: vec![
            setting("net/ipv4/ip_forward", "0"),
            setting("net/ipv6/conf/default/use_tempaddr", "2"),
        ],
    };
    assert!(valid.is_valid());
    // A rule of the other family in a family's list.
    let crossed = Policy {
        rules_v6: Some(vec![v4(1, 254)]),
        ..valid.clone()
    };
    assert!(!crossed.is_valid());
    // A rule whose body does not parse as one the kernel lists.
    let cut: Rule = serde_json::from_str(r#"{"body":[2,0,0]}"#).unwrap();
    let broken = Policy {
        rules_v4: Some(vec![cut]),
        ..valid.clone()
    };
    assert!(!broken.is_valid());
    for (family, name) in [("inet6", "filter"), ("inet", "")] {
        let policy = Policy {
            tables: Some(vec![table(family, name, 1)]),
            ..valid.clone()
        };
        assert!(!policy.is_valid(), "{family} {name}");
    }
    for key in [
        "kernel/modprobe",
        "net/ipv4/conf/all",
        "net/ipv4/conf/all/../../../../kernel/modprobe",
        "/proc/sys/net/ipv4/ip_forward",
        "net/ipv4/conf/eth0/forwarding",
        "net/ipv4/conf/all/x/y",
    ] {
        let policy = Policy {
            settings: vec![setting(key, "1")],
            ..valid.clone()
        };
        assert!(!policy.is_valid(), "{key}");
    }
}
