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

use std::io::Read;
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

/// Read and parse the LUKS2 header at the start of `device`. Any read error
/// (missing node, no permission) yields `None`.
pub fn read_luks2_header(device: &Path) -> Option<Luks2Metadata> {
    let mut file = std::fs::File::open(device).ok()?;
    let mut bytes = vec![0u8; BINARY_HEADER_LEN];
    file.read_exact(&mut bytes).ok()?;
    let header_len = luks2_header_len(&bytes)?;
    bytes.resize(header_len, 0);
    file.read_exact(&mut bytes[BINARY_HEADER_LEN..]).ok()?;
    parse_luks2_header(&bytes)
}

/// Build a LUKS2 header image with the given JSON metadata (test support).
#[cfg(test)]
pub(crate) fn header_image(json: &str, hdr_size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; hdr_size];
    bytes[..6].copy_from_slice(LUKS_MAGIC);
    bytes[6..8].copy_from_slice(&2u16.to_be_bytes());
    bytes[8..16].copy_from_slice(&(hdr_size as u64).to_be_bytes());
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
    fn reads_a_header_from_a_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let device = dir.path().join("sdb2");
        let mut image = header_image(JSON, 16384);
        image.extend(std::iter::repeat_n(0xAAu8, 65536));
        std::fs::write(&device, &image).unwrap();
        let meta = read_luks2_header(&device).unwrap();
        assert!(meta.flags.contains(&"allow-discards".to_string()));
        assert!(read_luks2_header(&dir.path().join("missing")).is_none());
    }
}
