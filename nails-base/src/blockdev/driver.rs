// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Which driver a block device belongs to, by its major number.
//!
//! A driver that keeps a major number of its own registers it under its name,
//! and the kernel lists every such number in `/proc/devices`, below "Block
//! devices:": `43 nbd`, `230 zvol`, `252 zram`. A driver without one takes
//! its numbers from a range the kernel shares between drivers, listed as
//! `259 blkext`, so that number names no driver.

use crate::Filesystem;
use std::collections::BTreeMap;
use std::path::Path;

/// Where the kernel lists the major numbers its drivers registered.
pub const PROC_DEVICES: &str = "/proc/devices";

/// What [`PROC_DEVICES`] lists for the range of numbers the kernel shares
/// between drivers.
pub const SHARED_RANGE: &str = "blkext";

/// The block drivers the kernel lists in [`PROC_DEVICES`], by major number.
/// `None` when the file cannot be read.
pub fn block_majors<F: Filesystem>(fs: &F) -> Option<BTreeMap<u32, String>> {
    fs.read_file_content(Path::new(PROC_DEVICES))
        .ok()
        .map(|text| parse_block_majors(&text))
}

/// The lines below "Block devices:" in the text of [`PROC_DEVICES`], each a
/// major number and the name of the driver that registered it.
pub fn parse_block_majors(text: &str) -> BTreeMap<u32, String> {
    let mut majors = BTreeMap::new();
    let mut block = false;
    for line in text.lines().map(str::trim) {
        if let Some(section) = line.strip_suffix(':') {
            block = section == "Block devices";
            continue;
        }
        let Some((major, driver)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if let (true, Ok(major)) = (block, major.parse()) {
            majors.insert(major, driver.trim().to_string());
        }
    }
    majors
}

/// The major number of a `major:minor` device number.
pub fn major_of(dev: &str) -> Option<u32> {
    dev.trim().split_once(':')?.0.parse().ok()
}
