// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The way back's link deletion against a real network namespace, without root.
//!
//! The record, the plan and reading the links are unit-tested against a fake
//! `/sys/class/net`; this proves the one part a mock cannot show: that the
//! applier actually removes a link through `ip`. It runs in a throwaway network
//! namespace, so the host's own links are out of reach and a bungled delete can
//! harm nothing.
//!
//! It needs the `dummy` link type, which an unprivileged user namespace can use
//! only when the module is already loaded, and `ip` itself. Either one missing
//! is a host skip, which `NAILS_REQUIRE_USERNS=1` leaves a skip; a missing user
//! namespace is the skip that variable turns into a failure.

use nails_core::test_path;
use nails_core::test_support::{Rerun, skip_host};
use nails_teardown::whole_root::network::{RestorePlan, apply_links};
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
        apply_links(&RestorePlan {
            delete: vec!["probe0".to_string()],
            set_mac: Vec::new(),
            hostname: None,
        });

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
