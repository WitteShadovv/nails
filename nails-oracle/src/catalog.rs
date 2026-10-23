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

use std::collections::BTreeMap;

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
    /// Whether the row is a residual channel the overlay cannot cover. Only
    /// such a row can explain a difference: any other row names a trace the
    /// overlay must prevent, so that trace showing in `after` is a leak.
    pub residual: bool,
    /// The doc section that explains the row, `<file>.md#<anchor>`.
    pub doc_anchor: String,
}

/// The slice of the residue catalog the oracle consults: every citable row by
/// id, and every doc anchor a row resolves to.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    rows: BTreeMap<String, CatalogRow>,
    /// Each doc anchor a row points at, and whether a residual row is among
    /// those that do.
    anchors: BTreeMap<String, bool>,
}

impl Catalog {
    /// Build from explicit rows; the doc anchors are the rows' own. Used by the
    /// engine's tests to pin down exactly which citations are valid.
    pub fn from_rows(rows: impl IntoIterator<Item = CatalogRow>) -> Self {
        let mut catalog = Self::default();
        for row in rows {
            let residual = catalog.anchors.entry(row.doc_anchor.clone()).or_default();
            *residual |= row.residual;
            catalog.rows.insert(row.id.clone(), row);
        }
        catalog
    }

    /// The row with this id, or `None` when the id is not catalogued. Mirrors
    /// `nails_forensics::residue_catalog::class`.
    pub fn row(&self, id: &str) -> Option<&CatalogRow> {
        self.rows.get(id)
    }

    /// Whether this `<file>.md#<anchor>` citation is a doc section a catalog
    /// row points at: `None` when no row does, `Some(true)` when a residual
    /// row is among them and `Some(false)` when only rows the overlay must
    /// cover point at it. Every such anchor is one the catalog's own tests
    /// prove resolves to a real heading.
    pub fn anchor(&self, anchor: &str) -> Option<bool> {
        self.anchors.get(anchor).copied()
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
        Self::from_rows(catalog().iter().map(|row| CatalogRow {
            id: row.id.to_string(),
            risk: row.risk.to_string(),
            mitigation: row.mitigation.to_string(),
            channel_paths: match row.channel {
                Channel::Paths(paths) => paths.iter().map(|p| p.to_string()).collect(),
                Channel::Mechanism(_) => Vec::new(),
            },
            residual: row.residual,
            doc_anchor: row.doc_anchor.to_string(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, residual: bool, doc_anchor: &str) -> CatalogRow {
        CatalogRow {
            id: id.into(),
            risk: format!("{id} risk"),
            mitigation: format!("{id} mitigation"),
            channel_paths: Vec::new(),
            residual,
            doc_anchor: doc_anchor.into(),
        }
    }

    #[test]
    fn rows_and_anchors_resolve_only_when_present() {
        let catalog = Catalog::from_rows([row(
            "timesync-clock",
            true,
            "decoy-requirements.md#session-time-records",
        )]);
        assert_eq!(catalog.len(), 1);
        assert!(!catalog.is_empty());
        assert_eq!(
            catalog.row("timesync-clock").unwrap().risk,
            "timesync-clock risk"
        );
        assert!(catalog.row("no-such-row").is_none());
        assert_eq!(
            catalog.anchor("decoy-requirements.md#session-time-records"),
            Some(true)
        );
        assert_eq!(catalog.anchor("threat-model.md#invented"), None);
    }

    #[test]
    fn an_anchor_is_residual_when_any_row_pointing_at_it_is() {
        // Two rows share a section: it stays citable through the residual one
        // whichever order they come in, and a section only a row the overlay
        // must cover points at is known but not residual.
        let shared = "threat-model.md#residual-channels";
        for rows in [
            [row("a", false, shared), row("b", true, shared)],
            [row("b", true, shared), row("a", false, shared)],
        ] {
            let mut rows = Vec::from(rows);
            rows.push(row("c", false, "threat-model.md#known-residual-changes"));
            let catalog = Catalog::from_rows(rows);
            assert_eq!(catalog.anchor(shared), Some(true));
            assert_eq!(
                catalog.anchor("threat-model.md#known-residual-changes"),
                Some(false)
            );
        }
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
        // A leak the overlay must prevent, so it can never excuse a difference.
        assert!(!nixos.residual);
        // A Channel::Mechanism row carries no channel paths.
        let boot = catalog
            .row("login-boot-records")
            .expect("login-boot-records is catalogued");
        assert!(boot.channel_paths.is_empty());
        assert!(boot.residual);
        assert_eq!(boot.doc_anchor, "threat-model.md#residual-channels");
        assert!(catalog.row("timesync-clock").is_some_and(|r| r.residual));
        assert_eq!(
            catalog.anchor("threat-model.md#residual-channels"),
            Some(true)
        );
    }
}
