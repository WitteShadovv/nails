// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The dependency graph between the workspace crates.
//!
//! Cargo already refuses a cycle. This test pins the direction on top of
//! that: each crate may depend only on the NAILS crates listed here, so a new
//! edge (the platform reaching for the session, verification reaching for the
//! orchestration) is a deliberate change to this table and to the crate
//! graph in docs/architecture.md.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Every workspace crate and the NAILS crates it may depend on.
const GRAPH: &[(&str, &[&str])] = &[
    ("nails-teardown", &[]),
    // The machine-readable contract types (`--json` envelope, exit codes, result
    // payloads, the progress-event stream). Serde and nothing else: no NAILS
    // dependency, so a consumer can link the wire shapes without the tool.
    ("nails-api", &[]),
    // Reaches `nails-api` for the typed progress events its reporter adapter
    // produces; `nails-api` carries no NAILS dependency, so this adds no cycle.
    ("nails-base", &["nails-api", "nails-teardown"]),
    ("nails-platform", &["nails-base"]),
    (
        "nails-session",
        &["nails-base", "nails-platform", "nails-teardown"],
    ),
    (
        "nails-forensics",
        &[
            "nails-base",
            "nails-platform",
            "nails-session",
            "nails-teardown",
        ],
    ),
    (
        "nails-core",
        &[
            "nails-api",
            "nails-base",
            "nails-forensics",
            "nails-platform",
            "nails-session",
            "nails-teardown",
        ],
    ),
    ("nails-cli", &["nails-api", "nails-core", "nails-teardown"]),
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("nails-core sits in the workspace directory")
        .to_path_buf()
}

fn manifest(path: &Path) -> toml::Table {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    text.parse()
        .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// The NAILS crates in the `[dependencies]` table of `member`'s manifest.
fn nails_dependencies(member: &str) -> BTreeSet<String> {
    let manifest = manifest(&workspace_root().join(member).join("Cargo.toml"));
    manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .map(|deps| {
            deps.keys()
                .filter(|name| name.starts_with("nails-"))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn the_graph_names_every_workspace_member() {
    let workspace = manifest(&workspace_root().join("Cargo.toml"));
    let members: BTreeSet<&str> = workspace["workspace"]["members"]
        .as_array()
        .expect("workspace members")
        .iter()
        .map(|member| member.as_str().expect("member path"))
        .collect();
    let graph: BTreeSet<&str> = GRAPH.iter().map(|(name, _)| *name).collect();
    assert_eq!(members, graph);
}

#[test]
fn each_crate_depends_only_on_the_crates_below_it() {
    let allowed: BTreeMap<&str, BTreeSet<String>> = GRAPH
        .iter()
        .map(|(name, deps)| (*name, deps.iter().map(|d| (*d).to_string()).collect()))
        .collect();
    for (name, deps) in &allowed {
        assert_eq!(&nails_dependencies(name), deps, "{name}");
    }
}

#[test]
fn the_table_is_ordered_bottom_up() {
    // Every crate depends only on crates listed before it, so the table reads
    // as the build order and cannot hide a cycle.
    let mut seen = BTreeSet::new();
    for (name, deps) in GRAPH {
        for dep in *deps {
            assert!(seen.contains(dep), "{name} depends on {dep}, listed later");
        }
        seen.insert(*name);
    }
}
