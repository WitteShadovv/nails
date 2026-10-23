// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use std::fs;

/// `ip -N -4 rule show` from iproute2 7.0 in a network namespace, with the
/// rules wg-quick, Tailscale and a VRF add and one per selector `ip` prints.
const CAPTURED_RULES: &str = "\
0:\tfrom all lookup 255
100:\tfrom all iif lo uidrange 0-0 ipproto ipproto-6 dport 443 lookup 7 proto 4
101:\tfrom all oif nosuch0 [detached] lookup 8
102:\tfrom 10.0.0.0/8 to 192.168.0.0/16 tos 0x10 goto 32766
103:\tfrom all lookup [l3mdev-table]
5250:\tfrom all fwmark 0x80000/0xff0000 7
32764:\tfrom all lookup 254 suppress_prefixlength 0
32765:\tnot from all fwmark 0xca6c lookup 51820
32766:\tfrom all lookup 254
32767:\tfrom all lookup 253
";

/// `nft -j list tables` from nftables 1.1.6 in a network namespace.
const CAPTURED_TABLES: &str = r#"{"nftables": [{"metainfo": {"version": "1.1.6", "release_name": "Commodore Bullmoose #7", "json_schema_version": 1}}, {"table": {"family": "inet", "name": "probe", "handle": 1}}, {"table": {"family": "ip", "name": "wg-quick-wg0", "handle": 2}}, {"table": {"family": "ip6", "name": "nm-wg-x", "handle": 3}}, {"table": {"family": "netdev", "name": "ingressprobe", "handle": 4}}]}"#;

fn rule(priority: u32, spec: &str) -> Rule {
    Rule {
        priority,
        spec: spec.split_whitespace().map(str::to_string).collect(),
    }
}

fn table(family: &str, name: &str, handle: u64) -> Table {
    Table {
        family: family.to_string(),
        name: name.to_string(),
        handle,
    }
}

#[test]
fn the_rules_are_read_as_ip_takes_them_back() {
    assert_eq!(
        parse_rules(CAPTURED_RULES).unwrap(),
        [
            rule(0, "from all lookup 255"),
            // The numeric protocol `ip` prints is one it does not read back.
            rule(
                100,
                "from all iif lo uidrange 0-0 ipproto 6 dport 443 lookup 7 proto 4"
            ),
            // Printed only: an interface that is gone.
            rule(101, "from all oif nosuch0 lookup 8"),
            rule(102, "from 10.0.0.0/8 to 192.168.0.0/16 tos 0x10 goto 32766"),
            rule(103, "from all l3mdev"),
            // The unreachable type, as a number.
            rule(5250, "from all fwmark 0x80000/0xff0000 7"),
            rule(32764, "from all lookup 254 suppress_prefixlength 0"),
            rule(32765, "not from all fwmark 0xca6c lookup 51820"),
            rule(32766, "from all lookup 254"),
            rule(32767, "from all lookup 253"),
        ]
    );
    assert_eq!(parse_rules("").unwrap(), []);
    // Anything else is no list at all.
    for bad in [
        "from all lookup 254\n",
        "x:\tfrom all lookup 254\n",
        "0:\tfrom all ipproto\n",
    ] {
        assert_eq!(parse_rules(bad), None, "{bad}");
    }
}

#[test]
fn the_tables_are_read_with_their_handles() {
    assert_eq!(
        parse_tables(CAPTURED_TABLES).unwrap(),
        [
            table("inet", "probe", 1),
            table("ip", "wg-quick-wg0", 2),
            table("ip6", "nm-wg-x", 3),
            table("netdev", "ingressprobe", 4),
        ]
    );
    let empty = r#"{"nftables": [{"metainfo": {"version": "1.1.6", "json_schema_version": 1}}]}"#;
    assert_eq!(parse_tables(empty).unwrap(), []);
    for bad in [
        "table inet probe\n",
        r#"{"tables": []}"#,
        r#"{"nftables": [{"table": {"family": "inet", "name": "probe"}}]}"#,
        r#"{"nftables": [{"table": {"family": "ipx", "name": "probe", "handle": 1}}]}"#,
    ] {
        assert_eq!(parse_tables(bad), None, "{bad}");
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

/// A fake `ip` in `dir` that keeps each family's rules as `ip -N rule show`
/// prints them, in `rules-4` and `rules-6` (a family without its file fails,
/// as a kernel without IPv6 does), and deletes the first line `rule del`
/// matches. A rule naming `refused` is never deleted.
fn fake_ip(dir: &Path) -> PathBuf {
    let tool = dir.join("ip");
    fs::write(
        &tool,
        format!(
            "#!/bin/sh\n\
             echo \"ip $*\" >> '{dir}/calls'\n\
             [ \"$1\" = -N ] && shift\n\
             state='{dir}/rules'\"$1\"\n\
             [ -f \"$state\" ] || exit 1\n\
             case \"$2 $3\" in\n\
             'rule show') cat \"$state\" ;;\n\
             'rule del')\n\
             [ \"$4\" = priority ] || exit 1\n\
             priority=$5; shift 5\n\
             line=\"$priority:\t$*\"\n\
             case \"$line\" in *refused*) exit 2 ;; esac\n\
             grep -qxF \"$line\" \"$state\" || exit 2\n\
             awk -v line=\"$line\" '!gone && $0 == line {{ gone = 1; next }} {{ print }}' \"$state\" > \"$state.new\"\n\
             mv \"$state.new\" \"$state\" ;;\n\
             *) exit 1 ;;\n\
             esac\n",
            dir = dir.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
    tool
}

/// A fake `nft` in `dir` that keeps the tables as `family name handle` lines
/// in `tables`, lists them as `nft -j list tables` does and deletes one by
/// handle. A table named `locked` is never deleted.
fn fake_nft(dir: &Path) -> PathBuf {
    let tool = dir.join("nft");
    fs::write(
        &tool,
        format!(
            "#!/bin/sh\n\
             echo \"nft $*\" >> '{dir}/calls'\n\
             state='{dir}/tables'\n\
             case \"$*\" in\n\
             '-j list tables')\n\
             printf '{{\"nftables\": [{{\"metainfo\": {{\"json_schema_version\": 1}}}}'\n\
             while read -r family name handle; do\n\
             printf ', {{\"table\": {{\"family\": \"%s\", \"name\": \"%s\", \"handle\": %s}}}}' \"$family\" \"$name\" \"$handle\"\n\
             done < \"$state\"\n\
             echo ']}}' ;;\n\
             'delete table '*' handle '*)\n\
             grep -q \"^$3 locked $5$\" \"$state\" && exit 1\n\
             grep -q \"^$3 .* $5$\" \"$state\" || exit 1\n\
             grep -v \"^$3 .* $5$\" \"$state\" > \"$state.new\"\n\
             mv \"$state.new\" \"$state\" ;;\n\
             *) exit 1 ;;\n\
             esac\n",
            dir = dir.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
    tool
}

/// The calls the fakes in `dir` logged, in order.
fn calls(dir: &Path) -> Vec<String> {
    fs::read_to_string(dir.join("calls"))
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

/// A decoy with the kernel's own rules, one rule and table of a VPN of its
/// own, and its settings.
fn decoy(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    fs::write(
        dir.join("rules-4"),
        "0:\tfrom all lookup 255\n\
         32765:\tnot from all fwmark 0xca6c lookup 51820\n\
         32766:\tfrom all lookup 254\n\
         32767:\tfrom all lookup 253\n",
    )
    .unwrap();
    fs::write(
        dir.join("rules-6"),
        "0:\tfrom all lookup 255\n32766:\tfrom all lookup 254\n",
    )
    .unwrap();
    fs::write(dir.join("tables"), "inet filter 1\nip wg-quick-wg0 2\n").unwrap();
    (fake_ip(dir), fake_nft(dir), proc_sys(dir))
}

#[test]
fn the_rules_and_tables_the_session_added_are_deleted_and_the_decoys_stay() {
    let dir = tempfile::tempdir().unwrap();
    let (ip, nft, sys) = decoy(dir.path());
    let policy = Policy::capture(Some(&ip), Some(&nft), &sys);
    let decoy_rules = fs::read_to_string(dir.path().join("rules-4")).unwrap();
    // The session: a WireGuard full tunnel of its own (two rules per family
    // and a table), the decoy's tunnel table made again under its name after
    // the decoy's stop deleted it, a VPN app's blocking table, and arp_ignore.
    fs::write(
        dir.path().join("rules-4"),
        format!(
            "{decoy_rules}32763:\tfrom all lookup 254 suppress_prefixlength 0\n\
             32764:\tnot from all fwmark 0xcb68 lookup 52072\n"
        ),
    )
    .unwrap();
    fs::write(
        dir.path().join("rules-6"),
        "0:\tfrom all lookup 255\n32765:\tnot from all fwmark 0xcb68 lookup 52072\n\
         32766:\tfrom all lookup 254\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("tables"),
        "inet filter 1\nip wg-quick-wg0 7\nip nm-wg-hidden 8\ninet mullvad 9\n",
    )
    .unwrap();
    fs::write(sys.join("net/ipv4/conf/all/arp_ignore"), "2\n").unwrap();
    let mut kept = Kept::default();

    policy.restore(Some(&ip), Some(&nft), &sys, &mut kept);

    assert_eq!(kept, Kept::default());
    assert_eq!(
        fs::read_to_string(dir.path().join("rules-4")).unwrap(),
        decoy_rules
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("rules-6")).unwrap(),
        "0:\tfrom all lookup 255\n32766:\tfrom all lookup 254\n"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("tables")).unwrap(),
        "inet filter 1\n",
        "the decoy's tunnel table went at its stop; the one the session made again goes"
    );
    assert_eq!(
        fs::read_to_string(sys.join("net/ipv4/conf/all/arp_ignore")).unwrap(),
        "0"
    );
    let deletions: Vec<String> = calls(dir.path())
        .into_iter()
        .filter(|call| call.contains("del"))
        .collect();
    assert_eq!(
        deletions,
        [
            "ip -4 rule del priority 32763 from all lookup 254 suppress_prefixlength 0",
            "ip -4 rule del priority 32764 not from all fwmark 0xcb68 lookup 52072",
            "ip -6 rule del priority 32765 not from all fwmark 0xcb68 lookup 52072",
            "nft delete table ip handle 7",
            "nft delete table ip handle 8",
            "nft delete table inet handle 9",
        ]
    );
}

#[test]
fn what_could_not_be_deleted_is_named() {
    let dir = tempfile::tempdir().unwrap();
    let (ip, nft, sys) = decoy(dir.path());
    let policy = Policy::capture(Some(&ip), Some(&nft), &sys);
    fs::write(
        dir.path().join("rules-4"),
        "0:\tfrom all lookup 255\n100:\tfrom all lookup refused\n",
    )
    .unwrap();
    fs::write(dir.path().join("tables"), "inet filter 1\ninet locked 5\n").unwrap();
    let mut kept = Kept::default();

    policy.restore(Some(&ip), Some(&nft), &sys, &mut kept);

    assert_eq!(kept.rules, ["-4 100: from all lookup refused"]);
    assert_eq!(kept.tables, ["inet locked"]);
}

#[test]
fn a_list_entry_could_not_read_is_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (ip, nft, sys) = decoy(dir.path());
    // No IPv6 at entry, and no nft.
    fs::remove_file(dir.path().join("rules-6")).unwrap();
    let policy = Policy::capture(Some(&ip), None, &sys);
    assert_eq!(policy.rules_v6, None);
    assert_eq!(policy.tables, None);
    let session_tables = "inet filter 1\ninet mullvad 9\n";
    fs::write(dir.path().join("tables"), session_tables).unwrap();
    let mut kept = Kept::default();

    policy.restore(Some(&ip), Some(&nft), &sys, &mut kept);

    assert_eq!(kept.unknown, ["IPv6 rules", "firewall tables"]);
    assert_eq!(
        fs::read_to_string(dir.path().join("tables")).unwrap(),
        session_tables,
        "without the decoy's list no table is deleted"
    );
    assert!(calls(dir.path()).iter().all(|call| !call.contains("del")));

    // Neither is anything deleted without the tools on the way back.
    let full = Policy::capture(Some(&ip), Some(&nft), &sys);
    let mut kept = Kept::default();
    full.restore(None, None, &sys, &mut kept);
    assert_eq!(
        kept.unknown,
        ["IPv4 rules", "IPv6 rules", "firewall tables"]
    );
}

#[test]
fn a_list_that_cannot_be_read_on_the_way_back_is_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let (ip, nft, sys) = decoy(dir.path());
    let policy = Policy::capture(Some(&ip), Some(&nft), &sys);
    // IPv6 went away, and nft now prints something else.
    fs::remove_file(dir.path().join("rules-6")).unwrap();
    fs::write(&nft, "#!/bin/sh\necho 'table inet filter'\n").unwrap();
    let mut kept = Kept::default();

    policy.restore(Some(&ip), Some(&nft), &sys, &mut kept);

    assert_eq!(kept.unknown, ["IPv6 rules", "firewall tables"]);
}

#[test]
fn only_a_policy_the_way_back_can_act_on_is_valid() {
    let valid = Policy {
        rules_v4: Some(vec![rule(1, "from all lookup 254")]),
        rules_v6: None,
        tables: Some(vec![table("inet", "filter", 1)]),
        settings: vec![
            setting("net/ipv4/ip_forward", "0"),
            setting("net/ipv6/conf/default/use_tempaddr", "2"),
        ],
    };
    assert!(valid.is_valid());
    let with_rule = |spec: Vec<String>| Policy {
        rules_v6: Some(vec![Rule { priority: 1, spec }]),
        ..valid.clone()
    };
    assert!(!with_rule(vec![String::new()]).is_valid());
    assert!(!with_rule(vec!["lookup 254".to_string()]).is_valid());
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
