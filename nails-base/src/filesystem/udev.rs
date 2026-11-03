// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What udev knows of a block device: its record in `/run/udev/data`, and
//! the label links it makes in `/dev/disk/by-label`.
//!
//! udev keeps a record of each device it handled in
//! `/run/udev/data/b<major>:<minor>`, which every user may read: one line per
//! fact, `E:<KEY>=<value>` for a property. A filesystem's label is the
//! property `ID_FS_LABEL_ENC`, written as libblkid's `blkid_encode_string()`
//! writes it: every byte that is not an ASCII letter or digit, one of
//! `#+-.:=@_` or part of a valid character of more than one byte becomes
//! `\xNN`, the backslash too, so the value keeps every byte of the label.
//! `ID_FS_LABEL` holds the label with such bytes replaced and is read only
//! from a record without the first.
//!
//! A record names the label of exactly its device. A `/dev/disk/by-label`
//! link, named by the label in the same encoding, points at one of all the
//! devices that carry that label, so of two filesystems with one label only
//! one has a link. The links serve only for a device udev keeps no record of.
//!
//! The record of a partition also holds what libblkid read of its entry in
//! the partition table, `ID_PART_ENTRY_*` ([`partition_entry`]): which table,
//! the type, the attribute flags, the number and where it starts.

use std::path::Path;

#[cfg(test)]
mod tests;

/// The value of the property `key` in `record`, udev's record of a device:
/// what follows `E:<key>=` on the first such line.
pub fn property<'a>(record: &'a str, key: &str) -> Option<&'a str> {
    record.lines().find_map(|line| {
        line.strip_prefix("E:")?
            .strip_prefix(key)?
            .strip_prefix('=')
    })
}

/// The filesystem label in `record`, udev's record of a device: the decoded
/// `ID_FS_LABEL_ENC`, or else `ID_FS_LABEL`. `None` for no label, and for an
/// empty one.
pub fn filesystem_label(record: &str) -> Option<String> {
    property(record, "ID_FS_LABEL_ENC")
        .map(decode)
        .or_else(|| property(record, "ID_FS_LABEL").map(str::to_string))
        .filter(|label| !label.is_empty())
}

/// What udev's record of a partition says of its entry in the partition
/// table, as libblkid read it when the device appeared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionEntry {
    /// The kind of table, `gpt` or `dos` (`ID_PART_ENTRY_SCHEME`).
    pub scheme: String,
    /// The type: a GPT type GUID, which libblkid writes in lower case, or an
    /// MBR type byte such as `0x83` (`ID_PART_ENTRY_TYPE`).
    pub type_id: String,
    /// The attribute flags of a GPT entry, the boot flag of an MBR one
    /// (`ID_PART_ENTRY_FLAGS`, in hexadecimal): 0 when the record has none,
    /// as libblkid writes the property only for flags that are set; `None`
    /// when the record holds a value that is no number.
    pub flags: Option<u64>,
    /// The entry's number in the table (`ID_PART_ENTRY_NUMBER`).
    pub number: Option<u32>,
    /// Where the partition starts, in 512-byte sectors
    /// (`ID_PART_ENTRY_OFFSET`).
    pub offset: Option<u64>,
}

/// The partition entry in `record`, udev's record of a device; `None` for a
/// record that names no table or no type, as a whole disk's does.
pub fn partition_entry(record: &str) -> Option<PartitionEntry> {
    let value = |key: &str| {
        property(record, key)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };
    let flags = match value("ID_PART_ENTRY_FLAGS") {
        None => Some(0),
        Some(text) => text
            .strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .and_then(|hex| u64::from_str_radix(hex, 16).ok()),
    };
    Some(PartitionEntry {
        scheme: value("ID_PART_ENTRY_SCHEME")?.to_string(),
        type_id: value("ID_PART_ENTRY_TYPE")?.to_string(),
        flags,
        number: value("ID_PART_ENTRY_NUMBER").and_then(|n| n.parse().ok()),
        offset: value("ID_PART_ENTRY_OFFSET").and_then(|n| n.parse().ok()),
    })
}

/// `value` with each `\xNN` udev wrote turned back into its byte. A
/// backslash that starts no such escape stays as it is, and bytes that are
/// no valid UTF-8 read as U+FFFD.
pub fn decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let escaped = (bytes[at] == b'\\' && bytes.get(at + 1) == Some(&b'x'))
            .then(|| bytes.get(at + 2..at + 4).and_then(hex_byte))
            .flatten();
        match escaped {
            Some(byte) => {
                decoded.push(byte);
                at += 4;
            }
            None => {
                decoded.push(bytes[at]);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// The byte two hex digits spell.
fn hex_byte(digits: &[u8]) -> Option<u8> {
    let value = |digit: u8| char::from(digit).to_digit(16);
    match digits {
        [high, low] => u8::try_from(value(*high)? * 16 + value(*low)?).ok(),
        _ => None,
    }
}

/// The label of the filesystem mounted from `source` whose mount shows the
/// device number `dev` (`major:minor`): from udev's record in `records` of
/// the device `dev`, which is the one the kernel mounted, or else of the
/// block device `source` names, as a btrfs mount shows a number of its own
/// and a node renamed since may lead to another device; without a record,
/// from the link to `source` in `links`. Reading it opens no device: the
/// device node is only looked up.
pub(crate) fn label_of(source: &Path, dev: &str, records: &Path, links: &Path) -> Option<String> {
    let mut numbers = vec![dev.to_string()];
    numbers.extend(node_number(source).filter(|number| number != dev));
    for number in numbers {
        if let Ok(record) = std::fs::read(records.join(format!("b{number}"))) {
            return filesystem_label(&String::from_utf8_lossy(&record));
        }
    }
    linked_label(source, links)
}

/// `major:minor` of the block device `path` names, its links followed.
fn node_number(path: &Path) -> Option<String> {
    let stat = rustix::fs::stat(path).ok()?;
    let block = rustix::fs::FileType::from_raw_mode(stat.st_mode).is_block_device();
    block.then(|| {
        format!(
            "{}:{}",
            rustix::fs::major(stat.st_rdev),
            rustix::fs::minor(stat.st_rdev)
        )
    })
}

/// The label whose link in `links` resolves to the device `source` names.
///
/// The source is resolved to its device node first, because a label link and
/// a `/dev/mapper` source both point at the underlying `/dev/dm-N`.
fn linked_label(source: &Path, links: &Path) -> Option<String> {
    let device = source.canonicalize().ok()?;
    std::fs::read_dir(links)
        .ok()?
        .flatten()
        .find(|entry| entry.path().canonicalize().ok().as_deref() == Some(device.as_path()))
        .and_then(|entry| entry.file_name().to_str().map(decode))
}
