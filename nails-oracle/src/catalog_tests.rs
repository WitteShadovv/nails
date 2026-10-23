// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the residue-catalog facts the verdict needs.

use super::*;

fn sample() -> Catalog {
    Catalog::from_rows(
        [CatalogRow {
            id: "var-lib-nixos".into(),
            risk: "rewritten every boot".into(),
            mitigation: "compare against a control run".into(),
            channel_paths: vec!["/var/lib/nixos".into()],
        }],
        ["threat-model.md#known-residual-changes".into()],
    )
}

#[test]
fn rows_and_anchors_resolve_only_when_present() {
    let catalog = sample();
    assert_eq!(catalog.len(), 1);
    assert!(!catalog.is_empty());
    assert_eq!(
        catalog.row("var-lib-nixos").unwrap().risk,
        "rewritten every boot"
    );
    assert!(catalog.row("no-such-row").is_none());
    assert!(catalog.anchor_exists("threat-model.md#known-residual-changes"));
    assert!(!catalog.anchor_exists("threat-model.md#invented"));
}

#[test]
fn empty_catalog_reports_empty() {
    let catalog = Catalog::default();
    assert_eq!(catalog.len(), 0);
    assert!(catalog.is_empty(), "a catalog with no rows is empty");
}

// Links the real catalog: the oracle's citable set is the project's own.
// The ids and anchor asserted here are ones the catalog's own tests pin as
// stable, so this guards the wiring without coupling to volatile rows.
#[test]
fn from_forensics_carries_the_live_catalog() {
    let catalog = Catalog::from_forensics();
    assert!(catalog.len() >= 3, "the live catalog is never this small");
    let nixos = catalog
        .row("var-lib-nixos")
        .expect("var-lib-nixos is catalogued");
    assert_eq!(nixos.channel_paths, ["/var/lib/nixos"]);
    assert!(!nixos.risk.trim().is_empty());
    // A Channel::Mechanism row carries no channel paths.
    let boot = catalog
        .row("login-boot-records")
        .expect("login-boot-records is catalogued");
    assert!(boot.channel_paths.is_empty());
    assert!(catalog.row("timesync-clock").is_some());
    assert!(catalog.anchor_exists("threat-model.md#residual-channels"));
}
