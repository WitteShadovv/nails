// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the oracle's data model.

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
fn dir_name_is_distinct_for_every_label() {
    // The three outputs must land in three different directories; a stub
    // that collapses them to one constant would silently merge the images.
    let names: Vec<&str> = ImageLabel::ALL.iter().map(|l| l.dir_name()).collect();
    assert_eq!(names, ["before", "control", "after"]);
    let unique: BTreeSet<&str> = names.iter().copied().collect();
    assert_eq!(unique.len(), ImageLabel::ALL.len());
}
