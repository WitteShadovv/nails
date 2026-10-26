// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The normalized data model the forensic oracle reasons over.
//!
//! The oracle compares three images of one host — `before` a hidden session,
//! a clean `control` boot cycle that ran no session, and `after` the session
//! was torn down — by the traces that disk-image analysis tools recover from
//! each. Every tool's output is normalized into a flat set of [`Finding`]s so
//! the verdict can take set differences across the three images.
//!
//! A [`Finding`] is keyed by `(tool, path, field)`. The meaning of `path` and
//! `field` is tool-specific and documented on [`Finding`]; the verdict logic
//! treats them opaquely, which is what keeps it independent of the best-effort
//! parsers in [`crate::scan`]. The one thing it knows of a channel is whether
//! it reports one entry per path ([`Tool::one_entry_per_path`]), which decides
//! how a change at that path is weighed.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Which analysis tool surfaced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tool {
    /// `btrfs restore` or `debugfs rdump`: an entry (a file, a directory or a
    /// symlink) recovered from the image's live tree, with what it holds.
    BtrfsRestore,
    /// `bulk_extractor`: a feature (an e-mail address, a URL, ...) or a
    /// login record carved from anywhere in the image, including free space
    /// and stale extents — the channel that still sees a
    /// deleted-but-not-overwritten trace.
    BulkExtractor,
    /// `plaso` / `log2timeline`: a timeline event parsed from a log or record,
    /// the format-aware channel that reads the *content* of a record rather
    /// than just its presence.
    Plaso,
    /// The rows of the Nix store database the restore carve recovered
    /// (`/nix/var/nix/db/db.sqlite`), read with `sqlite3`: a store path the
    /// database registers. The oracle's decoy VMs rewrite the database file
    /// at every start, so the restore channel can only call it noise; its
    /// rows say what changed.
    NixDb,
}

impl Tool {
    /// The analysis channels a real scan must hear from on every image (see
    /// [`crate::verdict::scan_verdict`]). [`Tool::NixDb`] is not among them:
    /// an image has a Nix store database only on a Nix decoy, and the scan
    /// stops when the restore carve holds one but its rows are missing.
    pub const REQUIRED: [Tool; 3] = [Tool::BtrfsRestore, Tool::BulkExtractor, Tool::Plaso];

    /// Whether the channel reports one entry per path on an image, so that a
    /// path holds one value that a later image can replace: the restore
    /// channel, whose finding at a path is that entry's kind and content. A
    /// different value there is a change of that entry, and a path whose value
    /// the control cycle changed too is one a plain reboot rewrites. The other
    /// channels report many findings under one path (the records of a file,
    /// the rows of a database, the values of a feature type), each its own
    /// trace.
    pub fn one_entry_per_path(self) -> bool {
        matches!(self, Tool::BtrfsRestore)
    }
}

/// How a residue finding differs between `before` and `after`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    /// New in `after`: neither `before` nor the control cycle has it.
    Added,
    /// A restore entry `before` and the control cycle agree on holds another
    /// value in `after`: a file whose content changed, a symlink pointed
    /// elsewhere, an entry of another kind at the same path.
    Changed,
    /// In `before` and in the control cycle, but gone from `after`: a file, a
    /// record or a feature the session removed.
    Removed,
}

/// One normalized observation from one tool over one image.
///
/// Findings compare as a set keyed by every field here, so the same trace seen
/// in two images collapses to one key and the set difference is exact. The
/// meaning of `path` and `field` depends on `tool`:
///
/// - [`Tool::BtrfsRestore`]: `path` is the absolute on-image path of a
///   recovered entry; `field` is its kind and content: `sha256:<digest>` for a
///   file, `dir` for a directory, `symlink:<target>` for a symbolic link and
///   `other` for anything else a carver recovers.
/// - [`Tool::BulkExtractor`]: `path` is the feature *type* (`email`, `url`,
///   `utmp_carved`, ...); `field` is the feature *value*, or for a carved
///   object its content (a login record's fields, or a content hash).
/// - [`Tool::Plaso`]: `path` is the event's source path, or `journal` for a
///   systemd-journal line; `field` is the event's data type, followed for a
///   record by the content fields that say what it records.
/// - [`Tool::NixDb`]: `path` is the database's on-image path; `field` is one
///   of its `ValidPaths` rows, the table name followed by the columns that say
///   what the row registers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Finding {
    /// The tool that surfaced it.
    pub tool: Tool,
    /// Where it was seen (see the type docs for the per-tool meaning).
    pub path: String,
    /// What was seen there (see the type docs for the per-tool meaning).
    pub field: String,
}

impl Finding {
    /// A finding of `tool` at `path` carrying `field`.
    pub fn new(tool: Tool, path: impl Into<String>, field: impl Into<String>) -> Self {
        Self {
            tool,
            path: path.into(),
            field: field.into(),
        }
    }
}

/// The three images one oracle run compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageLabel {
    /// The host before any hidden session (the clean baseline).
    Before,
    /// A clean boot cycle that ran no hidden session (the noise baseline).
    Control,
    /// The host after a hidden session was torn down (the image under test).
    After,
}

impl ImageLabel {
    /// Every label, in the fixed order the scanner walks them.
    pub const ALL: [ImageLabel; 3] = [ImageLabel::Before, ImageLabel::Control, ImageLabel::After];

    /// The sub-directory name the scan writes this image's outputs under.
    pub fn dir_name(self) -> &'static str {
        match self {
            ImageLabel::Before => "before",
            ImageLabel::Control => "control",
            ImageLabel::After => "after",
        }
    }
}

/// The three normalized scans a verdict compares.
#[derive(Debug, Clone, Default)]
pub struct Scans {
    /// Findings from the `before` image.
    pub before: BTreeSet<Finding>,
    /// Findings from the clean `control` cycle.
    pub control: BTreeSet<Finding>,
    /// Findings from the `after` image under test.
    pub after: BTreeSet<Finding>,
}

impl Scans {
    /// The findings of the image `label` names.
    pub fn image(&self, label: ImageLabel) -> &BTreeSet<Finding> {
        match label {
            ImageLabel::Before => &self.before,
            ImageLabel::Control => &self.control,
            ImageLabel::After => &self.after,
        }
    }
}

/// One cited exemption: a location that is expected to differ in `after`, and
/// exactly one residual residue-catalog row (or threat-model section) that says
/// why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowEntry {
    /// The exact locus this entry covers: an absolute path covers that path
    /// alone, never anything beneath it; a bare word is a feature type or
    /// another locus that is not a path (`journal`), which must be paired with
    /// a specific `field`.
    pub path: String,
    /// When set, only the finding whose `field` equals this is covered. When
    /// absent, the entry covers the restore channel's finding at `path`, the
    /// entry itself, whatever it holds; a record or a feature is covered only
    /// by naming it, so no entry can wave through every record of a file.
    #[serde(default)]
    pub field: Option<String>,
    /// Exactly one citation: a residue-catalog `id` (kebab-case, no `#`) of a
    /// residual row, or a threat-model doc anchor (`<file>.md#<anchor>`) a
    /// residual row points at. The field is required, so there is no way to
    /// exempt a location for no stated reason.
    pub cite: String,
    /// Covers the finding's removal from `after` instead of its arrival or
    /// change: a trace the session is expected to delete is cited apart from
    /// one it is expected to leave.
    #[serde(default)]
    pub removed: bool,
    /// Optional human note. Ignored by the engine.
    #[serde(default)]
    pub note: Option<String>,
}

/// The cited allowlist: the only differences, beyond control-cycle noise, that
/// a clean verdict tolerates.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowlist {
    /// A free-text header, for the committed file. Ignored by the engine.
    #[serde(default, rename = "_comment")]
    pub comment: Option<String>,
    /// The cited entries.
    #[serde(default)]
    pub entries: Vec<AllowEntry>,
}

/// A record planted on the `after` image that the scan must detect. Missing it
/// means the scan cannot see a trace it should, so no clean verdict is trusted.
/// It counts as detected only when `before` and the control cycle lack it, so
/// a value the baseline already carries can never stand in for the planted one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PositiveControl {
    /// A short name, used in the verdict and in reports.
    pub name: String,
    /// Require this channel to surface it; any tool when absent.
    #[serde(default)]
    pub tool: Option<Tool>,
    /// The locus it is planted at (an absolute path, or a feature type).
    pub path: String,
    /// The specific value expected, or any value at `path` when absent.
    #[serde(default)]
    pub field: Option<String>,
    /// Optional human note. Ignored by the engine.
    #[serde(default)]
    pub note: Option<String>,
}

/// A fixed marker planted on every image. Finding it proves the scan actually
/// read the image's contents (a coverage proof); missing it fails the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Canary {
    /// Require this channel to surface it; any tool when absent.
    #[serde(default)]
    pub tool: Option<Tool>,
    /// The locus the marker is planted at.
    pub path: String,
    /// The marker value, or any value at `path` when absent.
    #[serde(default)]
    pub field: Option<String>,
}

/// The scan's self-checks: the planted controls that prove it is not blind and
/// the canary that proves it covered the image.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Controls {
    /// A free-text header, for the committed file. Ignored by the engine.
    #[serde(default, rename = "_comment")]
    pub comment: Option<String>,
    /// The planted positive controls. A run with none cannot prove it sees
    /// residue, so the verdict rejects an empty list.
    #[serde(default)]
    pub positive_controls: Vec<PositiveControl>,
    /// The coverage canary.
    pub canary: Canary,
}

/// Everything the verdict weighs besides the scans themselves.
#[derive(Debug, Clone)]
pub struct OraclePolicy {
    /// The cited exemptions.
    pub allowlist: Allowlist,
    /// The scan self-checks.
    pub controls: Controls,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_name_is_the_exact_output_subdirectory_per_label() {
        // The scanner joins the outputs root with this name to find each
        // image's parser output, so it is a fixed on-disk contract: a wrong
        // or empty name points the scan at the wrong (or no) directory.
        assert_eq!(ImageLabel::Before.dir_name(), "before");
        assert_eq!(ImageLabel::Control.dir_name(), "control");
        assert_eq!(ImageLabel::After.dir_name(), "after");
    }

    #[test]
    fn image_returns_the_findings_of_the_named_label() {
        // The channel check walks the three images by label; each label must
        // reach its own set, or one image's findings would vouch for another's.
        let one = |path: &str| BTreeSet::from([Finding::new(Tool::BtrfsRestore, path, "")]);
        let scans = Scans {
            before: one("/before"),
            control: one("/control"),
            after: one("/after"),
        };
        assert_eq!(scans.image(ImageLabel::Before), &one("/before"));
        assert_eq!(scans.image(ImageLabel::Control), &one("/control"));
        assert_eq!(scans.image(ImageLabel::After), &one("/after"));
    }

    #[test]
    fn only_the_restore_channel_reports_one_entry_per_path() {
        // The verdict compares the restore channel path by path and the other
        // channels finding by finding: a wrong answer would weigh a file's
        // records as one value, or a file's content as a set of records.
        assert!(Tool::BtrfsRestore.one_entry_per_path());
        assert!(!Tool::BulkExtractor.one_entry_per_path());
        assert!(!Tool::Plaso.one_entry_per_path());
        assert!(!Tool::NixDb.one_entry_per_path());
    }

    #[test]
    fn the_nix_db_channel_is_not_required_on_every_image() {
        // A decoy that is not a Nix system has no store database, so its rows
        // cannot be required of every image the way the other channels are.
        assert_eq!(
            Tool::REQUIRED,
            [Tool::BtrfsRestore, Tool::BulkExtractor, Tool::Plaso]
        );
        assert_eq!(
            serde_json::to_value(Tool::NixDb).expect("serializes"),
            "nix_db"
        );
    }

    #[test]
    fn dir_name_is_distinct_for_every_label() {
        // The three outputs must land in three different directories; a stub
        // that collapses them to one constant would silently merge the images.
        let names: Vec<&str> = ImageLabel::ALL.iter().map(|l| l.dir_name()).collect();
        assert_eq!(names, ["before", "control", "after"]);
        let unique: BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(unique.len(), ImageLabel::ALL.len());
    }
}
