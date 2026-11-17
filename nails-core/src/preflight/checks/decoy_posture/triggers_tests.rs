// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::super::super::systemd_conf::Assignment;
use super::*;

/// The targets of a socket called `socket` whose `[Socket]` section is the
/// one `Key=value` line `line`.
fn targets(line: &str, socket: &str) -> Vec<Target> {
    let (key, value) = line.split_once('=').unwrap();
    let assignments = [Assignment {
        key: key.to_string(),
        value: value.to_string(),
    }];
    socket_targets(&assignments, socket)
}

#[test]
fn a_unit_the_host_may_name_is_one_nails_cannot_tell_about() {
    let mut triggers = Triggers::default();
    triggers.starts.insert(
        "a.service".to_string(),
        "a.socket is enabled and starts a.service".to_string(),
    );
    for target in targets("Service=audit%H.service", "kick.socket") {
        triggers
            .maybe
            .push((target, "kick.socket may start it".to_string()));
    }
    assert_eq!(
        triggers.of("a.service"),
        Some(Ok("a.socket is enabled and starts a.service".to_string()))
    );
    assert_eq!(
        triggers.of("auditd.service"),
        Some(Err(
            "NAILS cannot tell whether a timer, path or socket unit starts auditd.service: \
             kick.socket may start it"
                .to_string()
        ))
    );
    // The service of its own name, which systemd starts where the host's
    // value gives no name it takes, is one it may start too.
    assert!(triggers.of("kick.service").is_some_and(|how| how.is_err()));
    assert_eq!(triggers.of("tuned.service"), None);
}
