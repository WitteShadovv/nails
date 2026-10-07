// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Markdown tables generated from the catalog.
//!
//! The docs hold each generated table between a pair of markers:
//!
//! ```text
//! <!-- residue-catalog:begin NAME -->
//! ...generated...
//! <!-- residue-catalog:end NAME -->
//! ```
//!
//! [`sync_document`] rewrites every marked block in a document from the
//! catalog. A unit test runs it over the committed docs and fails when the
//! result differs; `REGENERATE_CATALOG_DOCS=1 cargo test -p nails-core
//! residue_catalog` writes the regenerated docs instead.

use super::{CATALOG, Channel, E2e, Probe, ProbeSeverity, ResidueClass, ResidueKind};

/// The documents (relative to `docs/`) that carry generated blocks.
pub const GENERATED_DOCS: &[&str] = &["decoy-requirements.md", "threat-model.md"];

/// Marker prefix for the start of a block.
const BEGIN: &str = "<!-- residue-catalog:begin ";
/// Marker prefix for the end of a block.
const END: &str = "<!-- residue-catalog:end ";
/// Marker suffix.
const CLOSE: &str = " -->";

/// Errors found while syncing a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncError {
    /// A begin marker has no matching end marker.
    Unterminated(String),
    /// A block name the generator does not know.
    UnknownBlock(String),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::Unterminated(name) => write!(f, "block {name} has no end marker"),
            SyncError::UnknownBlock(name) => write!(f, "unknown generated block {name}"),
        }
    }
}

/// Render the named block for a document. `doc` is the file the block lives
/// in, so links to its own sections become bare anchors.
pub fn render_block(name: &str, doc: &str) -> Option<String> {
    let table = match name {
        "fail-closed" => fail_closed_table(doc),
        "session" => catalog_table(doc, ResidueKind::Session),
        "setup" => catalog_table(doc, ResidueKind::Setup),
        "residual" => residual_table(doc),
        _ => return None,
    };
    Some(table)
}

/// Rewrite every generated block in `text`, leaving everything else as is.
///
/// # Errors
///
/// Fails on an unterminated block or a block name the generator does not know.
pub fn sync_document(text: &str, doc: &str) -> Result<String, SyncError> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        let after_begin = &rest[start + BEGIN.len()..];
        let Some(name_end) = after_begin.find(CLOSE) else {
            return Err(SyncError::Unterminated(String::new()));
        };
        let name = after_begin[..name_end].trim().to_string();
        let end_marker = format!("{END}{name}{CLOSE}");
        let body_start = start + BEGIN.len() + name_end + CLOSE.len();
        let Some(end_offset) = rest[body_start..].find(&end_marker) else {
            return Err(SyncError::Unterminated(name));
        };
        let block =
            render_block(&name, doc).ok_or_else(|| SyncError::UnknownBlock(name.clone()))?;
        out.push_str(&rest[..body_start]);
        out.push('\n');
        out.push_str(&block);
        out.push_str(&end_marker);
        rest = &rest[body_start + end_offset + end_marker.len()..];
    }
    out.push_str(rest);
    Ok(out)
}

/// A link to the row's doc section, relative to `doc`.
fn link(row: &ResidueClass, doc: &str, text: &str) -> String {
    let target = match row.doc_anchor.split_once('#') {
        Some((file, anchor)) if file == doc => format!("#{anchor}"),
        _ => row.doc_anchor.to_string(),
    };
    format!("[{text}]({target})")
}

/// Markdown for where a class lands.
fn channel_cell(channel: &Channel) -> String {
    match channel {
        Channel::Paths(paths) => paths
            .iter()
            .map(|path| format!("`{path}`"))
            .collect::<Vec<_>>()
            .join(", "),
        Channel::Mechanism(text) => (*text).to_string(),
    }
}

/// Markdown for one probe point.
fn probe_cell(probe: &Probe, blocks: bool) -> String {
    match probe {
        Probe::Check(name) if blocks => format!("`{name}` (refuses)"),
        Probe::Check(name) => format!("`{name}`"),
        Probe::Paths { severity, .. } => {
            let level = match severity {
                ProbeSeverity::Info => "info",
                ProbeSeverity::Warn => "warn",
                ProbeSeverity::Critical => "critical",
            };
            format!("path probe ({level})")
        }
        Probe::None(reason) => format!("none: {reason}"),
    }
}

/// Markdown for the VM test column.
fn e2e_cell(e2e: &E2e) -> String {
    match e2e {
        E2e::Test(name) => format!("`{name}`"),
        E2e::None(reason) => format!("none: {reason}"),
    }
}

/// The decoy-persistence findings that refuse activation.
fn fail_closed_table(doc: &str) -> String {
    let mut out = String::from("| Finding | Why it matters |\n|---|---|\n");
    for row in CATALOG.iter().filter(|row| {
        row.preflight_blocks
            && row.preflight == Probe::Check("decoy-persistence")
            && matches!(row.channel, Channel::Paths(_))
    }) {
        out.push_str(&format!(
            "| {} | {} |\n",
            link(row, doc, row.title),
            row.risk
        ));
    }
    out
}

/// The full catalog table for one kind of residue.
fn catalog_table(doc: &str, kind: ResidueKind) -> String {
    let mut out = String::from(
        "| Class | Where | Platforms | Pre-flight | Verify | Mitigation | VM test |\n\
         |---|---|---|---|---|---|---|\n",
    );
    for row in CATALOG.iter().filter(|row| row.kind == kind) {
        out.push_str(&format!(
            "| {} (`{}`) | {} | {} | {} | {} | {} | {} |\n",
            link(row, doc, row.title),
            row.id,
            channel_cell(&row.channel),
            row.platforms.label(),
            probe_cell(&row.preflight, row.preflight_blocks),
            probe_cell(&row.verify, false),
            row.mitigation,
            e2e_cell(&row.e2e),
        ));
    }
    out
}

/// The channels the overlay cannot cover, for the threat model.
fn residual_table(doc: &str) -> String {
    let mut out = String::from(
        "| Channel | Why it survives the overlay | Bounded by | Detected by |\n|---|---|---|---|\n",
    );
    for row in CATALOG.iter().filter(|row| row.residual) {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            link(row, doc, row.title),
            row.risk,
            row.mitigation,
            probe_cell(&row.verify, false),
        ));
    }
    out
}
