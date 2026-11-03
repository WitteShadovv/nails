// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reading the LUKS2 JSON metadata straight from the device.
//!
//! `cryptsetup luksDump` prints the persistent flags and the tokens of a LUKS2
//! header; this module reads the same fields from the on-disk format without
//! spawning cryptsetup. A LUKS2 device starts with a 4096-byte binary header
//! (magic `LUKS\xba\xbe`, big-endian version 2, big-endian `hdr_size` at offset
//! 8) followed by the JSON area, which runs to `hdr_size` and is NUL-padded. The
//! JSON's `config.flags` holds persistent activation flags such as
//! `allow-discards`, and `tokens.<n>.type` names the unlock method a token
//! serves (`systemd-tpm2`, `systemd-fido2`, ...).
//!
//! [`probe_header`] reads the start of the device below a LUKS mapping
//! read-only, without changing its access time, and says what it holds: a
//! LUKS1 or LUKS2 header with its uuid, nothing a LUKS header starts with,
//! as for a volume opened with a detached header (and then whether a LUKS2
//! secondary header survived), or nothing it could read.

use crate::forensic::RawSource;
use crate::forensic::layout::luks2_secondary_at;
use std::path::Path;

/// The LUKS magic at offset 0 of the primary header.
const LUKS_MAGIC: &[u8; 6] = b"LUKS\xba\xbe";
/// Size of the binary header that precedes the JSON area.
const BINARY_HEADER_LEN: usize = 4096;
/// The largest `hdr_size` the format allows (binary header plus 4 MiB JSON).
const MAX_HEADER_LEN: u64 = 4 * 1024 * 1024;

/// The fields of a LUKS2 header the backend check reports on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Luks2Metadata {
    /// Persistent activation flags (`config.flags`), e.g. `allow-discards`.
    pub flags: Vec<String>,
    /// Token types (`tokens.*.type`), sorted.
    pub token_types: Vec<String>,
}

/// Parse a LUKS2 header from the start of a device. `None` when the bytes are
/// not a LUKS2 header (a LUKS1 header, a detached-header device that starts
/// with ciphertext, or a truncated read) or the JSON area is malformed.
pub fn parse_luks2_header(bytes: &[u8]) -> Option<Luks2Metadata> {
    let header_len = luks2_header_len(bytes)?;
    let area = bytes.get(BINARY_HEADER_LEN..header_len)?;
    let json_len = area.iter().position(|&b| b == 0).unwrap_or(area.len());
    let json: serde_json::Value = serde_json::from_slice(&area[..json_len]).ok()?;

    let flags = json
        .pointer("/config/flags")
        .and_then(serde_json::Value::as_array)
        .map(|flags| {
            flags
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let mut token_types: Vec<String> = json
        .get("tokens")
        .and_then(serde_json::Value::as_object)
        .map(|tokens| {
            tokens
                .values()
                .filter_map(|token| token.get("type").and_then(serde_json::Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    token_types.sort();
    Some(Luks2Metadata { flags, token_types })
}

/// The total header length (`hdr_size`) of a LUKS2 binary header, validated.
fn luks2_header_len(bytes: &[u8]) -> Option<usize> {
    if bytes.get(..6)? != LUKS_MAGIC {
        return None;
    }
    let version = u16::from_be_bytes(bytes.get(6..8)?.try_into().ok()?);
    if version != 2 {
        return None;
    }
    let hdr_size = u64::from_be_bytes(bytes.get(8..16)?.try_into().ok()?);
    if hdr_size <= BINARY_HEADER_LEN as u64 || hdr_size > MAX_HEADER_LEN {
        return None;
    }
    usize::try_from(hdr_size).ok()
}

/// Where the uuid of a LUKS1 or LUKS2 binary header lies: 40 bytes of text,
/// NUL-padded.
const UUID_FIELD: std::ops::Range<usize> = 168..208;

/// What the start of the device below a LUKS mapping holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderProbe {
    /// A LUKS header of `version`, with its `uuid` and, for a LUKS2 header
    /// whose JSON area parses, its metadata.
    Attached {
        /// 1 or 2 (or whatever the header says).
        version: u16,
        /// The uuid the header names, as written (`8-4-4-4-12` hex digits).
        uuid: String,
        /// The LUKS2 flags and tokens.
        meta: Option<Luks2Metadata>,
    },
    /// No LUKS header, as on a device opened with a detached header: the
    /// offset of a LUKS2 secondary header the device still holds, if any.
    Detached {
        /// Where the secondary header lies, in bytes into the device.
        secondary_at: Option<u64>,
    },
    /// The device could not be opened or read (a missing node, no root).
    Unreadable,
}

/// Read what the start of `device` holds, read-only and without changing
/// its access time.
pub fn probe_header(device: &Path) -> HeaderProbe {
    let Ok(source) = RawSource::open(device) else {
        return HeaderProbe::Unreadable;
    };
    let mut head = vec![0u8; BINARY_HEADER_LEN];
    let Ok(read) = source.read_at(&mut head, 0) else {
        return HeaderProbe::Unreadable;
    };
    head.truncate(read);
    if head.starts_with(LUKS_MAGIC) && head.len() >= UUID_FIELD.end {
        let uuid = String::from_utf8_lossy(&head[UUID_FIELD])
            .trim_end_matches('\0')
            .to_string();
        return HeaderProbe::Attached {
            version: u16::from_be_bytes([head[6], head[7]]),
            uuid,
            meta: luks2_header_len(&head).and_then(|len| {
                let mut header = vec![0u8; len];
                let read = source.read_at(&mut header, 0).ok()?;
                parse_luks2_header(&header[..read])
            }),
        };
    }
    match luks2_secondary_at(&source, 0) {
        Ok(secondary_at) => HeaderProbe::Detached { secondary_at },
        Err(_) => HeaderProbe::Unreadable,
    }
}

/// Whether the header uuid `header` is the volume uuid cryptsetup wrote
/// into the device-mapper uuid `dm_uuid` (`CRYPT-LUKS2-<hex>-<name>`, the
/// uuid without its dashes). A device-mapper uuid that names none matches
/// any header.
pub fn same_volume(header: &str, dm_uuid: &str) -> bool {
    let Some(named) = volume_uuid_of(dm_uuid) else {
        return true;
    };
    let digits: String = header.chars().filter(|c| *c != '-').collect();
    digits.eq_ignore_ascii_case(named)
}

/// The volume uuid a device-mapper uuid names, without its dashes: the
/// `<hex>` of `CRYPT-<TYPE>-<hex>-<name>`. cryptsetup writes one for a
/// volume that has a uuid (a LUKS volume, and the integrity layer below a
/// LUKS2 volume with authenticated encryption) and none for a volume
/// without one (`CRYPT-TCRYPT-<name>`, and `CRYPT-SUBDEV-<name>_<n>` for
/// the further cipher layers below it).
pub fn volume_uuid_of(dm_uuid: &str) -> Option<&str> {
    dm_uuid
        .trim()
        .strip_prefix("CRYPT-")
        .and_then(|rest| rest.split_once('-'))
        .and_then(|(_, rest)| rest.split_once('-'))
        .map(|(hex, _)| hex)
        .filter(|hex| !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Whether the `SUBDEV` mapping whose device-mapper uuid is `dm_uuid` is the
/// integrity layer of a LUKS2 volume with authenticated encryption, which
/// cryptsetup 2.8 and later name `CRYPT-SUBDEV-<uuid>-<name>_dif` (earlier
/// versions `CRYPT-INTEGRITY-…`): its uuid names a whole volume uuid, 32 hex
/// digits, which the further cipher layers of a TCRYPT volume never carry.
pub fn names_a_volume(dm_uuid: &str) -> bool {
    volume_uuid_of(dm_uuid).is_some_and(|hex| hex.len() == 32)
}

/// The uuid every test header carries, which the device-mapper uuid
/// `CRYPT-LUKS2-0123456789abcdef0123456789abcdef-<name>` names.
#[cfg(test)]
pub(crate) const TEST_UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";

/// Build a LUKS2 header image with the given JSON metadata and the uuid
/// [`TEST_UUID`] (test support).
#[cfg(test)]
pub(crate) fn header_image(json: &str, hdr_size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; hdr_size];
    bytes[..6].copy_from_slice(LUKS_MAGIC);
    bytes[6..8].copy_from_slice(&2u16.to_be_bytes());
    bytes[8..16].copy_from_slice(&(hdr_size as u64).to_be_bytes());
    bytes[UUID_FIELD.start..UUID_FIELD.start + TEST_UUID.len()]
        .copy_from_slice(TEST_UUID.as_bytes());
    bytes[BINARY_HEADER_LEN..BINARY_HEADER_LEN + json.len()].copy_from_slice(json.as_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    const JSON: &str = r#"{"keyslots":{"0":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["0"]},"1":{"type":"systemd-fido2"}},"segments":{},"digests":{},"config":{"json_size":"12288","keyslots_size":"16744448","flags":["allow-discards","no-read-workqueue"]}}"#;

    #[test]
    fn parses_flags_and_tokens() {
        let meta = parse_luks2_header(&header_image(JSON, 16384)).unwrap();
        assert_eq!(meta.flags, vec!["allow-discards", "no-read-workqueue"]);
        assert_eq!(meta.token_types, vec!["systemd-fido2", "systemd-tpm2"]);
    }

    #[test]
    fn a_plain_header_has_no_flags_or_tokens() {
        let meta =
            parse_luks2_header(&header_image(r#"{"tokens":{},"config":{}}"#, 16384)).unwrap();
        assert_eq!(meta, Luks2Metadata::default());
    }

    #[test]
    fn rejects_non_luks2_bytes() {
        assert!(parse_luks2_header(&[0u8; 16384]).is_none());
        let mut luks1 = header_image("{}", 16384);
        luks1[6..8].copy_from_slice(&1u16.to_be_bytes());
        assert!(parse_luks2_header(&luks1).is_none());
        // Truncated: hdr_size claims more than was read.
        assert!(parse_luks2_header(&header_image(JSON, 16384)[..8192]).is_none());
        let mut huge = header_image("{}", 16384);
        huge[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(parse_luks2_header(&huge).is_none());
        assert!(parse_luks2_header(&header_image("{not json", 16384)).is_none());
    }

    #[test]
    fn parses_a_header_written_by_cryptsetup() {
        // The first 16 KiB of a 20 MiB image formatted with `cryptsetup
        // luksFormat --type luks2` (dummy passphrase, pbkdf2) and given a
        // `systemd-tpm2` token with `cryptsetup token import`.
        let image = include_bytes!("fixtures/luks2-tpm2-token.hdr");
        let meta = parse_luks2_header(image).unwrap();
        assert!(meta.flags.is_empty(), "{meta:?}");
        assert_eq!(meta.token_types, vec!["systemd-tpm2"]);
    }

    #[test]
    fn probes_an_attached_luks2_header_from_a_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let device = dir.path().join("sdb2");
        let mut image = header_image(JSON, 16384);
        image.extend(std::iter::repeat_n(0xAAu8, 65536));
        std::fs::write(&device, &image).unwrap();
        let HeaderProbe::Attached {
            version,
            uuid,
            meta,
        } = probe_header(&device)
        else {
            panic!("{:?}", probe_header(&device));
        };
        assert_eq!((version, uuid.as_str()), (2, TEST_UUID));
        assert!(meta.unwrap().flags.contains(&"allow-discards".to_string()));
        assert_eq!(
            probe_header(&dir.path().join("missing")),
            HeaderProbe::Unreadable
        );
    }

    #[test]
    fn probes_an_attached_luks1_header_with_no_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let device = dir.path().join("sdb2");
        let mut image = header_image("{}", 16384);
        image[6..8].copy_from_slice(&1u16.to_be_bytes());
        std::fs::write(&device, &image).unwrap();
        assert_eq!(
            probe_header(&device),
            HeaderProbe::Attached {
                version: 1,
                uuid: TEST_UUID.to_string(),
                meta: None,
            }
        );
    }

    #[test]
    fn ciphertext_at_the_start_is_a_detached_header_and_a_secondary_one_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let device = dir.path().join("sdb2");
        let mut image = vec![0x5Au8; 65536];
        std::fs::write(&device, &image).unwrap();
        assert_eq!(
            probe_header(&device),
            HeaderProbe::Detached { secondary_at: None }
        );
        image[0x4000..0x4006].copy_from_slice(b"SKUL\xba\xbe");
        std::fs::write(&device, &image).unwrap();
        assert_eq!(
            probe_header(&device),
            HeaderProbe::Detached {
                secondary_at: Some(0x4000)
            }
        );
    }

    #[test]
    fn a_header_is_the_volumes_when_the_mappings_uuid_names_its_uuid() {
        let dm = "CRYPT-LUKS2-0123456789abcdef0123456789abcdef-data";
        assert!(same_volume(TEST_UUID, dm));
        assert!(same_volume(&TEST_UUID.to_uppercase(), dm));
        assert!(!same_volume("ffffffff-89ab-cdef-0123-456789abcdef", dm));
        assert!(!same_volume("", dm));
        // A name with dashes of its own.
        assert!(same_volume(
            TEST_UUID,
            "CRYPT-LUKS1-0123456789abcdef0123456789abcdef-my-data"
        ));
        // A device-mapper uuid that names no volume uuid matches any.
        for dm in ["", "CRYPT-LUKS2-", "CRYPT-LUKS2-data", "LVM-x-y"] {
            assert!(same_volume("ffffffff", dm), "{dm}");
        }
    }

    #[test]
    fn the_integrity_layer_of_a_luks2_volume_names_its_uuid_and_a_cascade_layer_none() {
        let hex = TEST_UUID.replace('-', "");
        let hex = hex.as_str();
        assert_eq!(
            volume_uuid_of(&format!("CRYPT-LUKS2-{hex}-data")),
            Some(hex)
        );
        assert!(names_a_volume(&format!("CRYPT-SUBDEV-{hex}-data_dif")));
        assert!(names_a_volume(&format!("CRYPT-INTEGRITY-{hex}-data_dif\n")));
        // The further cipher layers of a TCRYPT volume, which has no uuid,
        // even of one whose name starts with hex digits and a dash.
        for dm in [
            "CRYPT-SUBDEV-outer_1",
            "CRYPT-SUBDEV-abc-def_1",
            "CRYPT-TCRYPT-outer",
            "",
        ] {
            assert!(!names_a_volume(dm), "{dm}");
        }
    }
}
