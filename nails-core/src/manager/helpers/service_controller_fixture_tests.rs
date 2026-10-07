// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `parse_active_units` against `systemctl list-units` output captured in a
//! NixOS VM, in exactly the invocations the controller runs.

use super::parse_active_units;
use crate::kernel_fixtures;

/// Every captured line yields exactly one unit name: a `.service` with no
/// status bullet in front of it.
fn assert_unit_names(stdout: &str) -> Vec<String> {
    let units = parse_active_units(stdout.as_bytes());
    let lines = stdout.lines().filter(|l| !l.trim().is_empty()).count();
    assert_eq!(units.len(), lines, "one unit per line: {units:?}");
    for unit in &units {
        assert!(
            unit.ends_with(".service") && !unit.starts_with(['●', '*', '○']),
            "a bare unit name, not a bullet or a column: {unit:?}"
        );
    }
    units
}

#[test]
fn captured_active_units_parse_to_bare_unit_names() {
    let Some(stdout) = kernel_fixtures::vm("systemctl-list-units-active.txt") else {
        return;
    };
    let units = assert_unit_names(&stdout);
    assert!(
        units.iter().any(|u| u == "systemd-journald.service"),
        "journald is active in the capture: {units:?}"
    );
}

#[test]
fn captured_all_units_include_inactive_ones() {
    let (Some(all), Some(active)) = (
        kernel_fixtures::vm("systemctl-list-units-all.txt"),
        kernel_fixtures::vm("systemctl-list-units-active.txt"),
    ) else {
        return;
    };
    let all = assert_unit_names(&all);
    let active = parse_active_units(active.as_bytes());
    assert!(all.len() > active.len(), "--all lists inactive units too");
    for unit in &active {
        assert!(all.contains(unit), "{unit} is in the --all listing");
    }
}
