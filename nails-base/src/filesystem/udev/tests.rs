// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! udev's records and label links, on records written as udev writes them
//! and on temporary directories in place of `/run/udev/data` and
//! `/dev/disk/by-label`.

use super::*;
use std::fs;
use std::os::unix::fs::symlink;

/// The record udev keeps of a LUKS mapping with an ext4 filesystem inside,
/// with `label` as libblkid encodes and makes it safe.
fn record(encoded: &str, safe: &str) -> String {
    format!(
        "S:disk/by-id/dm-name-data\n\
         S:disk/by-label/{encoded}\n\
         S:mapper/data\n\
         I:17952636\n\
         E:DM_NAME=data\n\
         E:ID_FS_UUID=00000000-0000-4000-8000-000000000001\n\
         E:ID_FS_TYPE=ext4\n\
         E:ID_FS_USAGE=filesystem\n\
         E:ID_FS_LABEL={safe}\n\
         E:ID_FS_LABEL_ENC={encoded}\n\
         G:systemd\n\
         Q:systemd\n\
         V:1\n"
    )
}

/// `blkid_encode_string()`: a valid character of more than one byte stays,
/// and so do ASCII letters, digits and `#+-.:=@_`; every other byte, the
/// backslash included, becomes `\xNN`.
fn encode(label: &str) -> String {
    let mut encoded = String::new();
    for c in label.chars() {
        let code = u32::from(c);
        let valid = !(0xfdd0..=0xfdef).contains(&code) && code & 0xfffe != 0xfffe;
        if (c.len_utf8() > 1 && valid) || c.is_ascii_alphanumeric() || "#+-.:=@_".contains(c) {
            encoded.push(c);
        } else {
            let mut buf = [0; 4];
            for byte in c.encode_utf8(&mut buf).bytes() {
                encoded.push_str(&format!("\\x{byte:02x}"));
            }
        }
    }
    encoded
}

// ------------------------------------------------------------------------
// The label in a record
// ------------------------------------------------------------------------

#[test]
fn the_label_is_read_from_its_encoded_property() {
    assert_eq!(
        filesystem_label(&record("data", "data")).as_deref(),
        Some("data")
    );
    // libblkid's safe form replaces the space; the encoded one keeps it.
    assert_eq!(
        filesystem_label(&record("family\\x20photos", "family_photos")).as_deref(),
        Some("family photos")
    );
    assert_eq!(
        filesystem_label(&record("Fotos\\x20M\u{e4}rz", "Fotos_M\u{e4}rz")).as_deref(),
        Some("Fotos M\u{e4}rz")
    );
}

#[test]
fn the_safe_property_serves_a_record_without_the_encoded_one() {
    let record = "E:ID_FS_TYPE=ext4\nE:ID_FS_LABEL=backup\n";
    assert_eq!(filesystem_label(record).as_deref(), Some("backup"));
}

#[test]
fn no_label_and_an_empty_one_are_none() {
    let unlabelled = "S:disk/by-uuid/5c1e\nE:ID_FS_TYPE=ext4\nE:ID_FS_USAGE=filesystem\n";
    assert_eq!(filesystem_label(unlabelled), None);
    assert_eq!(
        filesystem_label("E:ID_FS_LABEL_ENC=\nE:ID_FS_LABEL=\n"),
        None
    );
    assert_eq!(filesystem_label(""), None);
}

#[test]
fn only_the_label_properties_themselves_count() {
    // A link line, a longer key and a property of another kind name no label.
    let record = "S:disk/by-label/data\n\
                  E:ID_FS_LABEL_ENCODED=other\n\
                  E:ID_PART_ENTRY_NAME=data\n\
                  X:ID_FS_LABEL_ENC=data\n";
    assert_eq!(filesystem_label(record), None);
}

// ------------------------------------------------------------------------
// The escapes
// ------------------------------------------------------------------------

#[test]
fn every_escape_turns_back_into_its_byte() {
    assert_eq!(decode("a\\x5cb"), "a\\b", "a backslash");
    assert_eq!(decode("\\x2fsrv\\x2fx"), "/srv/x");
    assert_eq!(decode("A\\x5C\\x2F"), "A\\/", "upper-case digits");
    assert_eq!(decode("caf\\xc3\\xa9"), "caf\u{e9}", "a character in bytes");
    assert_eq!(decode("plain"), "plain");
}

#[test]
fn a_backslash_that_starts_no_escape_stays() {
    for value in [
        "\\", "a\\", "\\x", "\\x4", "\\xzz", "\\x+f", "\\y41", "\\x\\x41",
    ] {
        let expected = value.replace("\\x41", "A");
        assert_eq!(decode(value), expected, "{value}");
    }
}

#[test]
fn bytes_that_are_no_text_read_as_replacement_characters() {
    assert_eq!(decode("\\xff\\xfe"), "\u{fffd}\u{fffd}");
    assert_eq!(decode("ok\\xc3"), "ok\u{fffd}");
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Whatever a label holds, udev's encoding of it reads back as it.
        #[test]
        fn an_encoded_label_reads_back_unchanged(label in "\\PC{0,24}") {
            prop_assert_eq!(decode(&encode(&label)), label.clone());
            let read = filesystem_label(&record(&encode(&label), "safe"));
            prop_assert_eq!(read, (!label.is_empty()).then_some(label));
        }

        /// Any value decodes without a panic, and one without a backslash
        /// as it is.
        #[test]
        fn any_value_decodes(value in "\\PC{0,40}") {
            let decoded = decode(&value);
            if !value.contains('\\') {
                prop_assert_eq!(decoded, value);
            }
        }
    }
}

// ------------------------------------------------------------------------
// Where the label of a mount comes from
// ------------------------------------------------------------------------

/// Stand-ins for `/run/udev/data` and `/dev/disk/by-label`, and a device
/// node in a scratch `/dev`, a regular file that `stat` takes for no device.
struct Udev {
    _scratch: tempfile::TempDir,
    records: std::path::PathBuf,
    links: std::path::PathBuf,
    node: std::path::PathBuf,
}

impl Udev {
    fn new() -> Self {
        let scratch = tempfile::tempdir().unwrap();
        let records = scratch.path().join("data");
        let links = scratch.path().join("by-label");
        let node = scratch.path().join("dm-7");
        fs::create_dir(&records).unwrap();
        fs::create_dir(&links).unwrap();
        fs::write(&node, "").unwrap();
        Self {
            _scratch: scratch,
            records,
            links,
            node,
        }
    }

    fn record(&self, dev: &str, text: &str) -> &Self {
        fs::write(self.records.join(format!("b{dev}")), text).unwrap();
        self
    }

    fn link(&self, name: &str) -> &Self {
        symlink(&self.node, self.links.join(name)).unwrap();
        self
    }

    fn label(&self, dev: &str) -> Option<String> {
        label_of(&self.node, dev, &self.records, &self.links)
    }
}

#[test]
fn the_record_of_the_mounts_device_gives_the_label() {
    let udev = Udev::new();
    udev.record("254:7", &record("family\\x20photos", "family_photos"))
        .record("254:8", &record("other", "other"));
    assert_eq!(udev.label("254:7").as_deref(), Some("family photos"));
}

#[test]
fn a_record_without_a_label_is_believed_over_a_link() {
    let udev = Udev::new();
    udev.record("254:7", "E:ID_FS_TYPE=ext4\n").link("data");
    assert_eq!(udev.label("254:7"), None);
}

#[test]
fn without_a_record_the_link_to_the_device_gives_the_label() {
    let udev = Udev::new();
    udev.link("family\\x20photos");
    assert_eq!(udev.label("254:7").as_deref(), Some("family photos"));
}

#[test]
fn a_link_to_another_device_gives_no_label() {
    let udev = Udev::new();
    let other = udev.node.with_file_name("dm-8");
    fs::write(&other, "").unwrap();
    symlink(&other, udev.links.join("data")).unwrap();
    assert_eq!(udev.label("254:7"), None);
    // Nor does a missing directory of links, or a source that is no path.
    let gone = udev.links.with_file_name("absent");
    assert_eq!(label_of(&udev.node, "254:7", &udev.records, &gone), None);
    assert_eq!(
        label_of(Path::new("tmpfs"), "0:40", &udev.records, &udev.links),
        None
    );
}

#[test]
fn only_a_block_device_node_has_a_number_of_its_own() {
    let udev = Udev::new();
    assert_eq!(node_number(&udev.node), None, "a regular file");
    assert_eq!(node_number(&udev.records), None, "a directory");
    assert_eq!(node_number(&udev.node.with_file_name("absent")), None);
}
