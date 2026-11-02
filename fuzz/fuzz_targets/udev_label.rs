// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The filesystem label in udev's record of a block device
//! (`/run/udev/data/b<major>:<minor>`), which the hidden-volume check reads to
//! warn about any label on the hidden volume. Whoever made a filesystem chose
//! its label, and udev writes it into the record as `ID_FS_LABEL_ENC`, with
//! `\xNN` for each byte its encoding does not keep.
//!
//! The input is a record. The target checks that:
//!
//! - reading it never panics and never finds an empty label;
//! - where the record has an `ID_FS_LABEL_ENC` line, the label is what the
//!   first one decodes to;
//! - a label from the input, written in front of the record as udev writes
//!   it (the encoding `nails_fuzz::systemd::encode_devnode_name` models),
//!   reads back unchanged, whatever the rest of the record says.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_base::filesystem::udev::{decode, filesystem_label};
use nails_fuzz::systemd::encode_devnode_name;

fuzz_target!(|data: &[u8]| {
    let record = String::from_utf8_lossy(data);
    let label = filesystem_label(&record);
    assert_ne!(label.as_deref(), Some(""), "{record:?}");
    if let Some(value) = record
        .lines()
        .find_map(|line| line.strip_prefix("E:ID_FS_LABEL_ENC="))
    {
        let decoded = decode(value);
        assert_eq!(
            label,
            (!decoded.is_empty()).then_some(decoded),
            "{record:?}"
        );
    }

    let chosen = record.lines().next().unwrap_or_default().to_string();
    let written = format!(
        "E:ID_FS_LABEL_ENC={}\n{record}",
        encode_devnode_name(&chosen)
    );
    assert_eq!(
        filesystem_label(&written),
        (!chosen.is_empty()).then_some(chosen),
        "{written:?}"
    );
});
