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
//! What entry found is read in that namespace, never assumed: a new network
//! namespace starts with a copy of the host's IPv4 settings, so on a host that
//! forwards (one that runs Docker, say) forwarding is on at entry. The decoy
//! gets settings of its own that are not the kernel's defaults, so a way back
//! that wrote defaults fails on every host, not only on one that forwards.
//!
//! It needs `ip` and the `dummy` link type (its module loaded, or installed
//! for the kernel to load), and the firewall-table test needs `nft` and
//! nf_tables. It takes `ip` and `nft` only from the system locations the way
//! back searches, never from `PATH`, as `apply_links` finds `ip` there itself.
//! CI provides them, so each one missing is a skip that
//! `NAILS_REQUIRE_USERNS=1` turns into a failure, as it does a missing user
//! namespace, a network namespace the run cannot create and a sysfs it cannot
//! mount.
//!
//! One test runs the whole way back over a fake network state that it cannot
//! put back, with a file bound over `/dev/console` in its own mount
//! namespace: the power-off the way back then asks for writes nothing there.

use nails_core::test_path;
use nails_core::test_support::{Rerun, skip, skip_host, write_executable};
use nails_teardown::mountinfo::parse_mountinfo;
use nails_teardown::whole_root::network::{
    self, Kept, NetTools, NetworkRecord, Places, RestorePlan, apply_links,
};
use nails_teardown::whole_root::network_policy::Policy;
use nails_teardown::whole_root::plan::{
    Arm, DecoyRoot, Direction, PLAN_NAME, PLAN_VERSION, Plan, RootSide, Tools,
};
use nails_teardown::whole_root::tools;
use nails_teardown::whole_root::transition::{self, Env, Outcome, PowerOff};
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

/// `ip` where the way back finds it, or a skip.
fn ip_or_skip() -> PathBuf {
    match tools::find(None, "ip") {
        Some(ip) => ip,
        None => skip("iproute2 (ip) is in none of the system locations the way back searches"),
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
        skip(&format!("cannot create a network namespace: {e}"));
    }
    if let Err(e) = mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::empty(),
        None::<&str>,
    ) {
        skip(&format!("cannot mount sysfs in the network namespace: {e}"));
    }
}

/// Add a dummy link `name`, or skip where the kernel has no dummy link type
/// (its module neither loaded nor installed).
fn add_dummy(ip: &Path, name: &str) {
    if !ok(ip, &["link", "add", name, "type", "dummy"]) {
        skip("the dummy link type is unavailable in this namespace");
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

/// This namespace's network settings for all devices and for new ones, each
/// with its value: forwarding and every key of the `all` and `default`
/// directories below `/proc/sys/net/ipv4/conf` and `/proc/sys/net/ipv6/conf`
/// that can be read.
fn settings() -> Vec<(String, String)> {
    let mut keys = vec!["ipv4/ip_forward".to_string()];
    for dir in [
        "ipv4/conf/all",
        "ipv4/conf/default",
        "ipv6/conf/all",
        "ipv6/conf/default",
    ] {
        let Ok(entries) = std::fs::read_dir(Path::new("/proc/sys/net").join(dir)) else {
            continue;
        };
        let mut names: Vec<String> = entries
            .map(|entry| format!("{dir}/{}", entry.unwrap().file_name().to_string_lossy()))
            .collect();
        names.sort();
        keys.extend(names);
    }
    keys.into_iter()
        .filter_map(|key| {
            let value = std::fs::read_to_string(Path::new("/proc/sys/net").join(&key)).ok()?;
            Some((key, value.trim_end().to_string()))
        })
        .collect()
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
        // The decoy's own arp_ignore and src_valid_mark, which are not the
        // kernel's defaults. The namespace starts with the host's IPv4
        // settings, on most hosts the defaults, and a way back that wrote
        // defaults instead of what entry found would put those back too.
        // Forwarding stays as the host has it, so the way back turns it on
        // again where the host forwards and off where it does not.
        set_setting("ipv4/conf/all/arp_ignore", "1");
        set_setting("ipv4/conf/all/src_valid_mark", "1");
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
        let rules_v6 = ipv6.then(|| rules("-6"));
        // As entry finds them here: the host's IPv4 settings, which the
        // namespace started with, and the decoy's own.
        let settings_then = settings();
        let record = NetworkRecord::capture(&places, &tools);

        // The session: a random address on the decoy's device, a link of its
        // own and one made again under the name of the decoy's, a WireGuard
        // full tunnel's rules, a VPN app's settings and forwarding, each to a
        // value entry did not find, and its hostname.
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
        for (key, value, other) in [
            ("ipv4/ip_forward", "1", "0"),
            ("ipv4/conf/all/arp_ignore", "2", "0"),
            ("ipv4/conf/all/src_valid_mark", "1", "0"),
        ] {
            set_setting(key, if setting(key) == value { other } else { value });
        }
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
        assert_eq!(ipv6.then(|| rules("-6")), rules_v6);
        // Writing forwarding back changes `accept_redirects` and the
        // forwarding for new devices too, so every setting is compared.
        assert_eq!(settings(), settings_then);
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
            skip("nftables (nft) is in none of the system locations the way back searches");
        };
        fresh_network_namespace();
        // The decoy: a firewall table of its own, and its WireGuard tunnel's.
        if !ok(&nft, &["add", "table", "inet", "keep"]) {
            skip("nf_tables is unavailable in this namespace");
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

/// A plan armed for the way back to an FHS decoy whose init is
/// `/usr/lib/systemd/systemd`, with nothing else to put back.
fn way_back_plan(hidden: &Path) -> Plan {
    Plan {
        version: PLAN_VERSION,
        hidden_root: hidden.to_path_buf(),
        hidden_dev: None,
        accepted_decoy_storage: None,
        upper: hidden.join("root/upper"),
        work: hidden.join("root/work"),
        owner: None,
        decoy_root: DecoyRoot {
            source: PathBuf::from("/dev/null"),
            fstype: "ext4".to_string(),
            data: None,
        },
        decoy: RootSide {
            init: PathBuf::from("/usr/lib/systemd/systemd"),
            system: None,
        },
        hidden: RootSide {
            init: PathBuf::from("/usr/lib/systemd/systemd"),
            system: None,
        },
        policy_mounts: Vec::new(),
        masks: Vec::new(),
        boot_masks: Vec::new(),
        generator_masks: Vec::new(),
        session_units: Vec::new(),
        backend: Vec::new(),
        tools: Tools::default(),
        armed: Some(Arm::now(Direction::Leave)),
        entered_at: Some(1),
        run_noexec: false,
        carried: Vec::new(),
        decoy_mounts: Vec::new(),
        read_only_disks: false,
        failed_at_entry: Vec::new(),
        kernel_settings: Vec::new(),
        pids: nails_teardown::whole_root::fresh_pids::Record::default(),
    }
}

/// Add link `name` with interface index `index` to the fake `/sys/class/net`
/// at `class_net`, virtual as the kernel lists a link it made.
fn add_fake_link(class_net: &Path, name: &str, index: u32) {
    let dir = class_net.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("ifindex"), format!("{index}\n")).unwrap();
}

/// A way back that cannot put the network state back powers off, and says
/// nothing on the screen while it does: a line there would tell anyone
/// watching, on the emergency path above all, that a hidden session has just
/// ended. The console is a file here, bound over `/dev/console` in this run's
/// mount namespace, so whatever the way back writes to it is read back. The
/// network state is a fake one below a temporary directory: the session's
/// link stays there, as no `ip` is given to delete it.
#[test]
fn a_way_back_that_powers_off_writes_nothing_on_the_console() {
    let _ = Rerun::new(test_path!(
        a_way_back_that_powers_off_writes_nothing_on_the_console
    ))
    .in_user_mount_ns()
    .run(|| {
        use nix::mount::{MsFlags, mount};
        if !Path::new("/dev/console").exists() {
            skip_host("this host has no /dev/console");
        }
        let dir = tempfile::tempdir().unwrap();
        let console = dir.path().join("console");
        std::fs::write(&console, "").unwrap();
        if let Err(e) = mount(
            Some(&console),
            "/dev/console",
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        ) {
            skip(&format!("cannot bind a file over /dev/console: {e}"));
        }
        // The way back, armed with the record entry took of the decoy's
        // network: its loopback link and its hostname.
        let run = dir.path().join("run");
        let runtime = run.join("overlay-runtime");
        std::fs::create_dir_all(&runtime).unwrap();
        let nextroot = dir.path().join("nextroot");
        std::fs::create_dir_all(nextroot.join("etc")).unwrap();
        std::fs::write(nextroot.join("etc/os-release"), "ID=debian\n").unwrap();
        std::fs::create_dir_all(nextroot.join("usr/lib/systemd")).unwrap();
        write_executable(&nextroot.join("usr/lib/systemd/systemd"), "", 0o755);
        way_back_plan(&dir.path().join("hidden"))
            .write_atomic(&runtime.join(PLAN_NAME))
            .unwrap();
        let places = Places {
            run: run.clone(),
            sys_class_net: dir.path().join("sys/class/net"),
            proc_hostname: dir.path().join("hostname"),
            proc_sys: dir.path().join("proc/sys"),
        };
        std::fs::write(&places.proc_hostname, "decoy-host\n").unwrap();
        add_fake_link(&places.sys_class_net, "lo", 1);
        let record = NetworkRecord::capture(&places, &NetTools::default());
        std::fs::write(runtime.join(network::RECORD_NAME), record.encode()).unwrap();
        // The session's tunnel, still there when the way back runs.
        add_fake_link(&places.sys_class_net, "wg0", 9);
        let calls = dir.path().join("calls");
        let systemctl = dir.path().join("systemctl");
        write_executable(
            &systemctl,
            format!("#!/bin/sh\necho \"$*\" >> '{}'\n", calls.display()),
            0o755,
        );

        let outcome = transition::run(&Env {
            run: run.clone(),
            nextroot: nextroot.clone(),
            runtime_dir: runtime,
            kmsg: run.join("no-kmsg"),
            systemctl: Some(systemctl),
            now: nails_teardown::whole_root::plan::unix_now(),
            mounts: parse_mountinfo(&format!(
                "40 1 0:40 / {} rw - overlay overlay rw\n",
                nextroot.display()
            )),
            pid_places: None,
            network: places,
            network_tools: Some(NetTools::default()),
            power_off: PowerOff {
                grace: std::time::Duration::ZERO,
                kernel: || false,
            },
        });

        // The way back ran and asked for the power-off: the stand-in kernel
        // refused it, so it returned after all, with the link that stayed.
        let Outcome::Returned { network, .. } = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(network.links, ["wg0"]);
        let calls = std::fs::read_to_string(&calls).unwrap_or_default();
        assert!(
            calls.lines().any(|call| call == "--force poweroff"),
            "{calls}"
        );
        assert_eq!(
            std::fs::read_to_string(&console).unwrap(),
            "",
            "the way back wrote on the console"
        );
    });
}
