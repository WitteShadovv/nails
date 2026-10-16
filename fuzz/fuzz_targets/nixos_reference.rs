// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The check that a decoy's `/etc/nixos` names nothing of the hidden
//! environment: the line scanner that follows Nix's attribute sets, strings
//! and comments, the markers matched in each line, and the names of the
//! storage below the hidden volume read from udev's database.
//!
//! The hidden volume is the documented layout: the LUKS2 mapping `data` on
//! the partition sdb2, mounted at `/mnt/data`. The input is the partition's
//! udev record, a NUL and the text of `configuration.nix`; without a NUL the
//! whole input is that text and the record is a typical one. The target
//! checks that:
//!
//! - every reference lies in the file: its line exists, holds its text, and
//!   no line is reported twice;
//! - matching ignores ASCII case, as documented: the text with the case of
//!   every ASCII letter swapped gives the same lines, kinds and texts;
//! - the scan reads forward only: the first lines of the file give the
//!   references the whole file gives for them.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_base::{Filesystem, MockFilesystem};
use nails_platform::nixos::config::{BaseConfigReference, ReferenceKind, verify_base_config_clean};
use std::path::Path;

const FILE: &str = "/etc/nixos/configuration.nix";
const DM0: &str = "/sys/devices/virtual/block/dm-0";
const SDB2: &str =
    "/sys/devices/pci0000:00/0000:00:17.0/ata2/host1/target1:0:0/1:0:0:0/block/sdb/sdb2";
const LUKS: &str = "CRYPT-LUKS2-7d2c9e14e8a14b3c9f6b0e1a2d3c4b5a-data";

/// udev's record of the partition when the input brings none.
const PARTITION_RECORD: &str = "\
S:disk/by-id/ata-QEMU_HARDDISK_QM00002-part2
S:disk/by-path/pci-0000:00:17.0-ata-2-part2
S:disk/by-partlabel/vault
S:disk/by-partuuid/4f1b0a7d-02
S:disk/by-uuid/7d2c9e14-e8a1-4b3c-9f6b-0e1a2d3c4b5a
S:disk/by-label/My\\x20Vault
E:ID_FS_UUID=7d2c9e14-e8a1-4b3c-9f6b-0e1a2d3c4b5a
E:ID_FS_LABEL=My_Vault
E:ID_FS_LABEL_ENC=My\\x20Vault
E:ID_FS_TYPE=crypto_LUKS
E:ID_PART_ENTRY_NAME=vault
E:ID_PART_ENTRY_UUID=4f1b0a7d-02
";

/// udev's record of the mapping.
const MAPPING_RECORD: &str = "\
S:mapper/data
S:disk/by-id/dm-name-data
S:disk/by-id/dm-uuid-CRYPT-LUKS2-7d2c9e14e8a14b3c9f6b0e1a2d3c4b5a-data
S:disk/by-uuid/0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7b
S:disk/by-label/secrets
E:ID_FS_UUID=0b6e2a51-93c4-4d7e-8f1a-2c3d4e5f6a7b
E:ID_FS_LABEL=secrets
E:ID_FS_LABEL_ENC=secrets
";

fuzz_target!(|data: &[u8]| {
    let (record, text) = match data.iter().position(|&b| b == 0) {
        Some(at) => (
            String::from_utf8_lossy(&data[..at]).into_owned(),
            String::from_utf8_lossy(&data[at + 1..]).into_owned(),
        ),
        None => (
            PARTITION_RECORD.to_string(),
            String::from_utf8_lossy(data).into_owned(),
        ),
    };

    let found = scan(&record, &text);
    let lines: Vec<&str> = text.split('\n').collect();
    let mut previous = 0;
    for reference in &found {
        assert!(reference.line > previous, "{found:?}");
        previous = reference.line;
        let line = lines
            .get(reference.line - 1)
            .expect("the reported line exists");
        assert!(
            !reference.text.is_empty() && line.contains(&reference.text),
            "{reference:?}"
        );
    }

    let swapped = scan(&record, &swap_ascii_case(&text));
    assert_eq!(found.len(), swapped.len(), "{found:?} {swapped:?}");
    for (a, b) in found.iter().zip(&swapped) {
        assert_eq!((a.line, a.kind), (b.line, b.kind));
        assert!(a.text.eq_ignore_ascii_case(&b.text), "{a:?} {b:?}");
    }

    if let Some(cut) = text
        .match_indices('\n')
        .nth(lines.len() / 2)
        .map(|(at, _)| at)
    {
        let head: Vec<(usize, ReferenceKind, String)> = scan(&record, &text[..cut])
            .into_iter()
            .map(|r| (r.line, r.kind, r.text))
            .collect();
        let kept = text[..cut].split('\n').count();
        let expected: Vec<(usize, ReferenceKind, String)> = found
            .into_iter()
            .filter(|r| r.line <= kept)
            .map(|r| (r.line, r.kind, r.text))
            .collect();
        assert_eq!(head, expected);
    }
});

/// The references the check reports for `text`, with `record` as the
/// partition's udev record.
fn scan(record: &str, text: &str) -> Vec<BaseConfigReference> {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(
        "/proc/self/mountinfo",
        "36 35 254:0 / /mnt/data rw,relatime shared:1 - ext4 /dev/mapper/data rw\n",
    );
    device(&fs, DM0, "254:0", "DEVNAME=dm-0\nDEVTYPE=disk");
    fs.mock_set_file_content(&format!("{DM0}/dm/name"), "data\n");
    fs.mock_set_file_content(&format!("{DM0}/dm/uuid"), &format!("{LUKS}\n"));
    device(
        &fs,
        SDB2,
        "8:18",
        "DEVNAME=sdb2\nDEVTYPE=partition\nPARTN=2\nPARTNAME=vault\nPARTUUID=4f1b0a7d-02",
    );
    fs.mock_set_file_content(&format!("{SDB2}/partition"), "2\n");
    links(&fs, &format!("{DM0}/slaves"), &[SDB2]);
    links(&fs, &format!("{SDB2}/holders"), &[DM0]);
    fs.mock_set_file_content("/run/udev/data/b254:0", MAPPING_RECORD);
    fs.mock_set_file_content("/run/udev/data/b8:18", record);
    fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[Path::new(FILE)]);
    fs.mock_set_file_content(FILE, text);
    verify_base_config_clean(&fs, Path::new("/mnt/data"))
        .expect("the scan reads through the mock")
        .references
}

/// A block device's sysfs directory, linked from `/sys/dev/block`.
fn device(fs: &MockFilesystem, dir: &str, dev: &str, uevent: &str) {
    fs.mock_set_file_content(&format!("{dir}/dev"), &format!("{dev}\n"));
    fs.mock_set_file_content(&format!("{dir}/uevent"), &format!("{uevent}\n"));
    fs.create_symlink(Path::new(dir), &Path::new("/sys/dev/block").join(dev))
        .expect("link the device");
}

/// A sysfs directory of links (`slaves/`, `holders/`) to device directories.
fn links(fs: &MockFilesystem, dir: &str, targets: &[&str]) {
    let mut entries = Vec::new();
    for target in targets {
        let link = Path::new(dir).join(Path::new(target).file_name().expect("a device name"));
        fs.create_symlink(Path::new(target), &link)
            .expect("link the device");
        entries.push(link);
    }
    fs.mock_set_directory_contents(Path::new(dir), entries);
}

/// `text` with every ASCII letter in the other case.
fn swap_ascii_case(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'a'..='z' => c.to_ascii_uppercase(),
            'A'..='Z' => c.to_ascii_lowercase(),
            _ => c,
        })
        .collect()
}
