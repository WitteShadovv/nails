// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The way back's network restore against a real network namespace, without
//! root.
//!
//! The record, the plan and reading the links are unit-tested against a fake
//! `/sys/class/net`, and the tools against fakes; this proves the parts a mock
//! cannot show: that the applier actually removes a link and sets an address
//! back through `ip`, reading the result back from the kernel's own sysfs, and
//! that the whole record and restore, from the real `ip`'s list of rules and
//! the kernel's settings below `/proc/sys/net` to the deletes and writes, puts
//! a namespace back as entry found it. It runs in a throwaway network
//! namespace, so the host's own links are out of reach and a bungled change
//! can harm nothing.
//!
//! It needs the `dummy` link type, which an unprivileged user namespace can use
//! only when the module is already loaded, and `ip` itself; the firewall-table
//! test needs `nft` and nf_tables. Each one missing is a host skip, which
//! `NAILS_REQUIRE_USERNS=1` leaves a skip, and so is a sysfs the namespace
//! cannot mount; a missing user namespace is the skip that variable turns into
//! a failure.

use nails_core::test_path;
use nails_core::test_support::{Rerun, skip_host};
use nails_teardown::whole_root::network::{
    self, Kept, NetTools, NetworkRecord, Places, RestorePlan, apply_links,
};
use nails_teardown::whole_root::network_policy::Policy;
use nails_teardown::whole_root::tools;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Run `tool args…`, `true` when it succeeded.
fn ok(tool: &Path, args: &[&str]) -> bool {
    Command::new(tool)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Run `tool args…` and return what it printed, panicking when it fails.
fn output(tool: &Path, args: &[&str]) -> String {
    let out = Command::new(tool).args(args).output().unwrap();
    assert!(out.status.success(), "{args:?}: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

/// Whether link `name` exists in the current network namespace.
fn link_present(ip: &Path, name: &str) -> bool {
    ok(ip, &["link", "show", name])
}

/// `ip`, or a host skip.
fn ip_or_skip() -> PathBuf {
    match tools::find(None, "ip") {
        Some(ip) => ip,
        None => skip_host("iproute2 (ip) is not installed"),
    }
}

/// Move this run into a throwaway network namespace of its own, and mount its
/// sysfs over `/sys` in this run's private mount namespace: the applier reads
/// each link back from `/sys/class/net`, which shows the links of the
/// namespace that mounted it.
fn fresh_network_namespace() {
    use nix::mount::{MsFlags, mount};
    use nix::sched::{CloneFlags, unshare};
    if let Err(e) = unshare(CloneFlags::CLONE_NEWNET) {
        skip_host(&format!("cannot create a network namespace: {e}"));
    }
    if let Err(e) = mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::empty(),
        None::<&str>,
    ) {
        skip_host(&format!("cannot mount sysfs in the network namespace: {e}"));
    }
}

/// Add a dummy link `name`; the dummy type needs its module, which an
/// unprivileged user namespace cannot load, so a failure is a host skip.
fn add_dummy(ip: &Path, name: &str) {
    if !ok(ip, &["link", "add", name, "type", "dummy"]) {
        skip_host("the dummy link type is unavailable in this namespace");
    }
}

/// Link `name`'s sysfs attribute `file` below `class_net`, trimmed.
fn attr(class_net: &Path, name: &str, file: &str) -> String {
    std::fs::read_to_string(class_net.join(name).join(file))
        .unwrap()
        .trim_end()
        .to_string()
}

/// Whether link `name` is up: `IFF_UP` in the hex flags the kernel prints.
fn is_up(class_net: &Path, name: &str) -> bool {
    let flags = attr(class_net, name, "flags");
    u32::from_str_radix(flags.trim_start_matches("0x"), 16).unwrap() & 0x1 != 0
}

/// A network setting of this namespace, below `/proc/sys/net`.
fn setting(key: &str) -> String {
    std::fs::read_to_string(Path::new("/proc/sys/net").join(key))
        .unwrap()
        .trim_end()
        .to_string()
}

fn set_setting(key: &str, value: &str) {
    std::fs::write(Path::new("/proc/sys/net").join(key), value).unwrap();
}

#[test]
fn apply_links_deletes_the_link_the_session_made_in_a_network_namespace() {
    let _ = Rerun::new(test_path!(
        apply_links_deletes_the_link_the_session_made_in_a_network_namespace
    ))
    .in_user_mount_ns()
    .run(|| {
        let ip = ip_or_skip();
        fresh_network_namespace();
        // The session's virtual link.
        add_dummy(&ip, "probe0");
        assert!(link_present(&ip, "probe0"), "the link was created");

        // The way back's applier deletes the link the session made.
        let kept = apply_links(
            &RestorePlan {
                delete: vec!["probe0".to_string()],
                ..RestorePlan::default()
            },
            Path::new(network::SYS_CLASS_NET),
        );

        assert_eq!(kept, Kept::default());
        assert!(
            !link_present(&ip, "probe0"),
            "the link the session made is gone"
        );
        assert!(
            link_present(&ip, "lo"),
            "the namespace's own loopback stays"
        );
    });
}

#[test]
fn apply_links_sets_the_decoys_address_back_in_a_network_namespace() {
    let _ = Rerun::new(test_path!(
        apply_links_sets_the_decoys_address_back_in_a_network_namespace
    ))
    .in_user_mount_ns()
    .run(|| {
        let ip = ip_or_skip();
        fresh_network_namespace();
        let class_net = Path::new(network::SYS_CLASS_NET);
        // Two of the decoy's devices with the session's address, one up and
        // one down.
        for (name, state) in [("probe0", "up"), ("probe1", "down")] {
            add_dummy(&ip, name);
            let session = ["link", "set", "dev", name, "address", "02:00:00:00:00:99"];
            assert!(ok(&ip, &session), "the session's address on {name}");
            assert!(ok(&ip, &["link", "set", "dev", name, state]));
        }

        let kept = apply_links(
            &RestorePlan {
                set_mac: vec![
                    ("probe0".to_string(), "02:00:00:00:00:01".to_string()),
                    ("probe1".to_string(), "02:00:00:00:00:02".to_string()),
                ],
                ..RestorePlan::default()
            },
            class_net,
        );

        assert_eq!(kept, Kept::default(), "every address is set back");
        assert_eq!(attr(class_net, "probe0", "address"), "02:00:00:00:00:01");
        assert_eq!(attr(class_net, "probe1", "address"), "02:00:00:00:00:02");
        assert!(is_up(class_net, "probe0"), "the link that was up stays up");
        assert!(
            !is_up(class_net, "probe1"),
            "the link that was down stays down"
        );
    });
}

#[test]
fn the_way_back_puts_a_namespaces_links_rules_and_settings_back() {
    let _ = Rerun::new(test_path!(
        the_way_back_puts_a_namespaces_links_rules_and_settings_back
    ))
    .in_user_mount_ns()
    .run(|| {
        let ip = ip_or_skip();
        fresh_network_namespace();
        let class_net = Path::new(network::SYS_CLASS_NET);
        let ipv6 = Path::new("/proc/sys/net/ipv6").exists();
        // The decoy: a device with its own address, and a link its own stop
        // takes down for the switch.
        add_dummy(&ip, "decoy0");
        add_dummy(&ip, "reuse0");
        assert!(ok(
            &ip,
            &[
                "link",
                "set",
                "dev",
                "decoy0",
                "address",
                "02:00:00:00:00:01"
            ]
        ));
        assert!(ok(&ip, &["link", "set", "dev", "decoy0", "up"]));
        let scratch = tempfile::tempdir().unwrap();
        // The live hostname of a user namespace cannot be written through
        // /proc, so a file stands in for it.
        let places = Places {
            run: scratch.path().join("run"),
            sys_class_net: class_net.to_path_buf(),
            proc_hostname: scratch.path().join("hostname"),
            proc_sys: PathBuf::from(network::PROC_SYS),
        };
        std::fs::write(&places.proc_hostname, "decoy-host\n").unwrap();
        let tools = NetTools {
            ip: Some(ip.clone()),
            ..NetTools::default()
        };
        let rules = |family| output(&ip, &["-N", family, "rule", "show"]);
        let rules_v4 = rules("-4");
        let record = NetworkRecord::capture(&places, &tools);

        // The session: a random address on the decoy's device, a link of its
        // own and one made again under the name of the decoy's, a WireGuard
        // full tunnel's rules, a VPN app's settings and forwarding, and its
        // hostname.
        assert!(ok(
            &ip,
            &[
                "link",
                "set",
                "dev",
                "decoy0",
                "address",
                "02:00:00:00:00:99"
            ]
        ));
        add_dummy(&ip, "sess0");
        assert!(ok(&ip, &["link", "delete", "dev", "reuse0"]));
        add_dummy(&ip, "reuse0");
        let families: &[&str] = if ipv6 { &["-4", "-6"] } else { &["-4"] };
        for &family in families {
            let tunnel = [
                family, "rule", "add", "not", "fwmark", "51820", "table", "51820",
            ];
            assert!(ok(&ip, &tunnel));
            let main = [
                family,
                "rule",
                "add",
                "table",
                "main",
                "suppress_prefixlength",
                "0",
            ];
            assert!(ok(&ip, &main));
        }
        set_setting("ipv4/ip_forward", "1");
        set_setting("ipv4/conf/all/arp_ignore", "2");
        set_setting("ipv4/conf/all/src_valid_mark", "1");
        std::fs::write(&places.proc_hostname, "hidden-host\n").unwrap();

        let kept = network::restore_with(&places, &tools, Some(&record.encode()));

        let mut unknown = vec!["firewall tables"];
        if !ipv6 {
            unknown.insert(0, "IPv6 rules");
        }
        assert_eq!(
            kept,
            Kept {
                unknown,
                ..Kept::default()
            }
        );
        assert!(!link_present(&ip, "sess0"), "the session's link is gone");
        assert!(
            !link_present(&ip, "reuse0"),
            "the link made again under the decoy's name is gone"
        );
        assert!(link_present(&ip, "decoy0"));
        assert_eq!(attr(class_net, "decoy0", "address"), "02:00:00:00:00:01");
        assert!(is_up(class_net, "decoy0"));
        assert_eq!(rules("-4"), rules_v4);
        if ipv6 {
            assert!(!rules("-6").contains("51820"), "{}", rules("-6"));
        }
        assert_eq!(setting("ipv4/ip_forward"), "0");
        assert_eq!(setting("ipv4/conf/all/arp_ignore"), "0");
        assert_eq!(setting("ipv4/conf/all/src_valid_mark"), "0");
        assert_eq!(
            std::fs::read_to_string(&places.proc_hostname).unwrap(),
            "decoy-host"
        );
    });
}

#[test]
fn the_way_back_deletes_the_firewall_tables_the_session_added() {
    let _ = Rerun::new(test_path!(
        the_way_back_deletes_the_firewall_tables_the_session_added
    ))
    .in_user_mount_ns()
    .run(|| {
        let Some(nft) = tools::find(None, "nft") else {
            skip_host("nftables (nft) is not installed");
        };
        fresh_network_namespace();
        // The decoy: a firewall table of its own, and its WireGuard tunnel's.
        if !ok(&nft, &["add", "table", "inet", "keep"]) {
            skip_host("nf_tables is unavailable in this namespace");
        }
        assert!(ok(&nft, &["add", "table", "ip", "wg-quick-wg0"]));
        let before = output(&nft, &["-j", "list", "tables"]);
        let proc_sys = Path::new(network::PROC_SYS);
        let policy = Policy::capture(None, Some(&nft), proc_sys);

        // The decoy's stop takes its tunnel down; the session brings up its
        // own under the same name, and a VPN app's blocking table.
        assert!(ok(&nft, &["delete", "table", "ip", "wg-quick-wg0"]));
        assert!(ok(&nft, &["add", "table", "ip", "wg-quick-wg0"]));
        assert!(ok(&nft, &["add", "table", "inet", "mullvad"]));
        let mut kept = Kept::default();

        policy.restore(None, Some(&nft), proc_sys, &mut kept);

        assert!(kept.tables.is_empty(), "{kept:?}");
        assert_eq!(kept.unknown, ["IPv4 rules", "IPv6 rules"]);
        assert_eq!(output(&nft, &["list", "tables"]), "table inet keep\n");
        // The `keep` table's object, up to its closing brace.
        let keep = |json: &str| {
            json.split("{\"table\": ")
                .find(|table| table.contains("\"keep\""))
                .and_then(|table| table.split('}').next())
                .map(str::to_string)
        };
        assert_eq!(
            keep(&output(&nft, &["-j", "list", "tables"])),
            keep(&before),
            "the decoy's table stays, with its handle"
        );
    });
}
