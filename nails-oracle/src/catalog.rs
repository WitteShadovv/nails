// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The residue-catalog facts the verdict needs, and the adapter that fills
//! them from the live catalog linked out of `nails-forensics`.
//!
//! Splitting a [`Catalog`] value out of the engine is deliberate: [`verdict`]
//! takes a `&Catalog`, so its tests inject a small synthetic catalog and never
//! depend on the real one's evolving contents, while the shipped binary builds
//! the catalog from [`Catalog::from_forensics`] so the set of citable rows can
//! never drift from the catalog the rest of the project enforces.
//!
//! [`verdict`]: crate::verdict::verdict

use std::collections::{BTreeMap, BTreeSet};

/// The residue-catalog row fields a citation resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogRow {
    /// The stable kebab-case id, the primary citation handle.
    pub id: String,
    /// Why an examiner cares — printed to explain an allowlisted finding.
    pub risk: String,
    /// What the operator does about it — printed alongside `risk`.
    pub mitigation: String,
    /// The row's channel paths; empty for a `Channel::Mechanism` row, which
    /// vouches for a trace that is not pinned to a fixed path.
    pub channel_paths: Vec<String>,
}

/// The slice of the residue catalog the oracle consults: every citable row by
/// id, and every doc anchor a row resolves to.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    rows: BTreeMap<String, CatalogRow>,
    anchors: BTreeSet<String>,
}

impl Catalog {
    /// Build from explicit rows and doc anchors. Used by the engine's tests to
    /// pin down exactly which citations are valid.
    pub fn from_rows(
        rows: impl IntoIterator<Item = CatalogRow>,
        anchors: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            rows: rows.into_iter().map(|row| (row.id.clone(), row)).collect(),
            anchors: anchors.into_iter().collect(),
        }
    }

    /// The row with this id, or `None` when the id is not catalogued. Mirrors
    /// `nails_forensics::residue_catalog::class`.
    pub fn row(&self, id: &str) -> Option<&CatalogRow> {
        self.rows.get(id)
    }

    /// Whether this `<file>.md#<anchor>` citation resolves to a doc section a
    /// catalog row points at. Every such anchor is one the catalog's own tests
    /// prove resolves to a real heading.
    pub fn anchor_exists(&self, anchor: &str) -> bool {
        self.anchors.contains(anchor)
    }

    /// How many rows are catalogued.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the catalog is empty.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Build from the residue catalog linked out of `nails-forensics`, so the
    /// oracle's citable rows are exactly the project's own, with no manifest to
    /// regenerate and no chance of drift.
    pub fn from_forensics() -> Self {
        use nails_forensics::residue_catalog::{Channel, catalog};
        let mut rows = Vec::new();
        let mut anchors = BTreeSet::new();
        for row in catalog() {
            let channel_paths = match row.channel {
                Channel::Paths(paths) => paths.iter().map(|p| p.to_string()).collect(),
                Channel::Mechanism(_) => Vec::new(),
            };
            rows.push(CatalogRow {
                id: row.id.to_string(),
                risk: row.risk.to_string(),
                mitigation: row.mitigation.to_string(),
                channel_paths,
            });
            anchors.insert(row.doc_anchor.to_string());
        }
        Self::from_rows(rows, anchors)
    }
}

#[cfg(test)]
#[path = "catalog_tests.rs"]
mod tests;
