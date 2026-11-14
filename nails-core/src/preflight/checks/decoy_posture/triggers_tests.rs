// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::super::super::systemd_conf::Assignment;
use super::*;

/// The `[Socket]` assignments of `text`, one `Key=value` a line.
fn section(text: &str) -> Vec<Assignment> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| Assignment {
            key: key.to_string(),
            value: value.to_string(),
        })
        .collect()
}

#[test]
fn a_socket_starts_its_service_or_the_one_of_its_own_name() {
    for (text, service) in [
        ("ListenStream=/run/x.sock", Some("tuned.service")),
        ("Service=firewalld.service", Some("firewalld.service")),
        ("Service=a.service\nService=b.service", Some("b.service")),
        // Accept=yes starts instances of tuned@.service instead.
        ("Accept=yes", None),
        ("Accept=true\nService=x.service", None),
    ] {
        assert_eq!(
            socket_service(&section(text), "tuned.socket"),
            Ok(service.map(str::to_string)),
            "{text:?}"
        );
    }
    assert!(socket_service(&section("Service=%N.service"), "tuned.socket").is_err());
}
