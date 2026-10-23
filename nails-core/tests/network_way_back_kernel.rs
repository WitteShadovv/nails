// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The way back's link changes against a real network namespace, without root.
//!
//! The record, the plan and reading the links are unit-tested against a fake
//! `/sys/class/net`, and the address change against a fake `ip`; this proves
//! the parts a mock cannot show: that the applier actually removes a link and
//! sets an address back through `ip`, and reads the result back from the
//! kernel's own sysfs. It runs in a throwaway network namespace, so the host's
//! own links are out of reach and a bungled change can harm nothing.
//!
//! It needs the `dummy` link type, which an unprivileged user namespace can use
//! only when the module is already loaded, and `ip` itself. Either one missing
//! is a host skip, which `NAILS_REQUIRE_USERNS=1` leaves a skip, and so is a
//! sysfs the namespace cannot mount; a missing user namespace is the skip that
//! variable turns into a failure.

use nails_core::test_path;
use nails_core::test_support::{Rerun, skip_host};
use nails_teardown::whole_root::network::{self, RestorePlan, apply_links};
use nails_teardown::whole_root::tools;
use std::path::Path;
use std::process::{Command, Stdio};

/// Whether link `name` exists in the current network namespace.
fn link_present(ip: &Path, name: &str) -> bool {
    Command::new(ip)
        .args(["link", "show", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[test]
fn apply_links_deletes_the_link_the_session_made_in_a_network_namespace() {
    let _ = Rerun::new(test_path!(
        apply_links_deletes_the_link_the_session_made_in_a_network_namespace
    ))
    .in_user_mount_ns()
    .run(|| {
        use nix::sched::{CloneFlags, unshare};
        let Some(ip) = tools::find(None, "ip") else {
            skip_host("iproute2 (ip) is not installed");
        };
        // A throwaway network namespace of this run's own.
        if let Err(e) = unshare(CloneFlags::CLONE_NEWNET) {
            skip_host(&format!("cannot create a network namespace: {e}"));
        }
        // The session's virtual link. The dummy type needs its module, which an
        // unprivileged user namespace cannot load; a failure here is a host skip.
        let made = Command::new(&ip)
            .args(["link", "add", "probe0", "type", "dummy"])
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if !made {
            skip_host("the dummy link type is unavailable in this namespace");
        }
        assert!(link_present(&ip, "probe0"), "the link was created");

        // The way back's applier deletes the link the session made.
        let kept = apply_links(
            &RestorePlan {
                delete: vec!["probe0".to_string()],
                set_mac: Vec::new(),
                hostname: None,
            },
            Path::new(network::SYS_CLASS_NET),
        );

        assert!(kept.is_empty(), "no address to set back: {kept:?}");
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

/// Run `ip args…`, `true` when it succeeded.
fn ip_ok(ip: &Path, args: &[&str]) -> bool {
    Command::new(ip)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
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

#[test]
fn apply_links_sets_the_decoys_address_back_in_a_network_namespace() {
    let _ = Rerun::new(test_path!(
        apply_links_sets_the_decoys_address_back_in_a_network_namespace
    ))
    .in_user_mount_ns()
    .run(|| {
        use nix::mount::{MsFlags, mount};
        use nix::sched::{CloneFlags, unshare};
        let Some(ip) = tools::find(None, "ip") else {
            skip_host("iproute2 (ip) is not installed");
        };
        if let Err(e) = unshare(CloneFlags::CLONE_NEWNET) {
            skip_host(&format!("cannot create a network namespace: {e}"));
        }
        // The applier reads each address back from /sys/class/net, which shows
        // the links of the namespace that mounted it: mount this namespace's
        // own over it, in this run's private mount namespace.
        if let Err(e) = mount(
            Some("sysfs"),
            "/sys",
            Some("sysfs"),
            MsFlags::empty(),
            None::<&str>,
        ) {
            skip_host(&format!("cannot mount sysfs in the network namespace: {e}"));
        }
        let class_net = Path::new(network::SYS_CLASS_NET);
        // Two of the decoy's devices with the session's address, one up and
        // one down.
        for (name, state) in [("probe0", "up"), ("probe1", "down")] {
            if !ip_ok(&ip, &["link", "add", name, "type", "dummy"]) {
                skip_host("the dummy link type is unavailable in this namespace");
            }
            let session = ["link", "set", "dev", name, "address", "02:00:00:00:00:99"];
            assert!(ip_ok(&ip, &session), "the session's address on {name}");
            assert!(ip_ok(&ip, &["link", "set", "dev", name, state]));
        }

        let kept = apply_links(
            &RestorePlan {
                delete: Vec::new(),
                set_mac: vec![
                    ("probe0".to_string(), "02:00:00:00:00:01".to_string()),
                    ("probe1".to_string(), "02:00:00:00:00:02".to_string()),
                ],
                hostname: None,
            },
            class_net,
        );

        assert!(kept.is_empty(), "every address is set back: {kept:?}");
        assert_eq!(attr(class_net, "probe0", "address"), "02:00:00:00:00:01");
        assert_eq!(attr(class_net, "probe1", "address"), "02:00:00:00:00:02");
        assert!(is_up(class_net, "probe0"), "the link that was up stays up");
        assert!(
            !is_up(class_net, "probe1"),
            "the link that was down stays down"
        );
    });
}
