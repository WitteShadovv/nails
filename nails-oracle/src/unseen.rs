// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the verdict cannot see, named in every verdict so that a clean one
//! does not claim more than its keys tell apart.
//!
//! Most classes follow from how the channels key a finding and are the same on
//! every run: no key holds a time, a file is keyed by its content and not its
//! metadata, a process id by its power-of-two range, and some carvers' objects
//! are left out. One class is this run's own: a file a plain reboot rewrites
//! too is subtracted as noise whatever `after` holds there, so a session's
//! write to it reads the same as the reboot's, unless a channel reads the
//! file's records (plaso the login records of `wtmp`, the scan the rows of the
//! Nix store database). The verdict lists those files by path.

use crate::carved::SKIPPED_CARVERS;
use crate::model::{Finding, Scans, Tool};
use crate::plaso::is_file_event;
use serde::Serialize;
use std::collections::BTreeSet;

/// A class of change the verdict cannot see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Unseen {
    /// A change to a time alone. No key holds a time, so a file the session
    /// only read or touched reads as unchanged.
    Timestamps,
    /// A change to the mode, owner or extended attributes of a file whose
    /// content stays the same: a file is keyed by its content.
    Metadata,
    /// A process id in the same power-of-two range as the one a fresh boot
    /// gives that process: a record keeps a process id as its range.
    ProcessIdRange,
    /// What these bulk_extractor carvers reconstruct, a database carved from
    /// free space, unless its content carries an e-mail address, a URL or a
    /// domain the value recorders find.
    SkippedCarvers {
        /// The carvers' feature types.
        feature_types: Vec<String>,
    },
    /// The files of this run that a plain reboot rewrites too and whose
    /// records no channel reads: the control cycle changed each as well, so
    /// what `after` holds there was subtracted as noise although neither
    /// `before` nor the control cycle holds it. A session's write to such a
    /// file reads the same.
    RebootRewritten {
        /// The files' on-image paths.
        paths: Vec<String>,
    },
}

impl Unseen {
    /// How the clean summary line names the class, or `None` when this run
    /// has nothing of it to name.
    fn label(&self) -> Option<String> {
        match self {
            Unseen::Timestamps => Some("timestamps".to_string()),
            Unseen::Metadata => Some("file metadata".to_string()),
            Unseen::ProcessIdRange => Some("process ids within one power-of-two range".to_string()),
            Unseen::SkippedCarvers { feature_types } => {
                (!feature_types.is_empty()).then(|| feature_types.join(", "))
            }
            Unseen::RebootRewritten { paths } => match paths.len() {
                0 => None,
                1 => Some("1 file a reboot rewrites".to_string()),
                n => Some(format!("{n} files a reboot rewrites")),
            },
        }
    }
}

/// Every class the verdict cannot see in this run: the fixed ones, and the
/// paths of `rewritten` (the restore paths the residue subtracted as noise
/// while `after` differs from both other images) whose records no channel
/// reads on any image.
pub(crate) fn classes(scans: &Scans, rewritten: &[&str]) -> Vec<Unseen> {
    let read = paths_with_records(scans);
    let paths = rewritten
        .iter()
        .filter(|path| !read.contains(**path))
        .map(|path| (*path).to_string())
        .collect();
    vec![
        Unseen::Timestamps,
        Unseen::Metadata,
        Unseen::ProcessIdRange,
        Unseen::SkippedCarvers {
            feature_types: SKIPPED_CARVERS.iter().map(|t| (*t).to_string()).collect(),
        },
        Unseen::RebootRewritten { paths },
    ]
}

/// The paths whose records a channel read on some image: a file plaso parsed
/// an event out of, beyond the `fs:` events it reports for every file, and a
/// database whose rows the scan read.
fn paths_with_records(scans: &Scans) -> BTreeSet<&str> {
    [&scans.before, &scans.control, &scans.after]
        .into_iter()
        .flatten()
        .filter(|f| is_record(f))
        .map(|f| f.path.as_str())
        .collect()
}

/// Whether a finding is a record read out of the file at its path.
fn is_record(f: &Finding) -> bool {
    match f.tool {
        Tool::Plaso => !is_file_event(&f.field),
        Tool::NixDb => true,
        Tool::BtrfsRestore | Tool::BulkExtractor => false,
    }
}

/// The end of a clean summary line: `; not seen: ` and every class this run
/// has something of, or nothing when it has none.
pub(crate) fn summary_suffix(unseen: &[Unseen]) -> String {
    let labels: Vec<String> = unseen.iter().filter_map(Unseen::label).collect();
    if labels.is_empty() {
        return String::new();
    }
    format!("; not seen: {}", labels.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_class_with_nothing_to_name_is_left_off_the_summary() {
        assert_eq!(summary_suffix(&[]), "");
        let nothing = [
            Unseen::SkippedCarvers {
                feature_types: vec![],
            },
            Unseen::RebootRewritten { paths: vec![] },
        ];
        assert_eq!(summary_suffix(&nothing), "");
        let carvers = [Unseen::SkippedCarvers {
            feature_types: vec!["a_carved".into(), "b_carved".into()],
        }];
        assert_eq!(summary_suffix(&carvers), "; not seen: a_carved, b_carved");
    }
}
