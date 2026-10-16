// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Words that give hidden storage away in a name.
//!
//! A mount path, a device-mapper name or a filesystem label outlives the
//! session: it stays in the leftover mount-point directory, in generated
//! systemd unit names, in `/dev/disk/by-label` and in journal lines. Every
//! place that judges or picks such a name uses this one list, so they all
//! agree on what reads as hidden storage.

/// Words that hint at hidden storage. One shared list so the mount path, the
/// device-mapper name and the filesystem label are all judged the same way.
///
/// A match is a leak, not a failure: the name survives in the leftover
/// mount-point directory, in generated systemd `.mount`/`.device` unit names, in
/// `/dev/disk/by-label` and in kernel and sudo journal lines, where anyone who
/// reads them learns that hidden storage exists. Matching is case-insensitive
/// and on substrings, so `veracrypt-hidden`, `MyNailsVol` and `decoy0` all hit.
pub const SUSPICIOUS_STORAGE_TOKENS: &[&str] = &["hidden", "nails", "veracrypt", "tcrypt", "decoy"];

/// The first [`SUSPICIOUS_STORAGE_TOKENS`] entry contained in `name`, if any.
pub fn suspicious_token(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    SUSPICIOUS_STORAGE_TOKENS
        .iter()
        .copied()
        .find(|token| lower.contains(token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspicious_token_is_case_insensitive_substring() {
        assert_eq!(suspicious_token("MyVeraCryptVol"), Some("veracrypt"));
        assert_eq!(suspicious_token("DECOY0"), Some("decoy"));
        assert_eq!(suspicious_token("nails-store"), Some("nails"));
        assert_eq!(suspicious_token("data"), None);
    }

    #[test]
    fn neutral_names_pass() {
        for name in [
            "data",
            "/mnt/data",
            "backup",
            "sdb2",
            "luks-0f3c",
            "Photos 2024",
        ] {
            assert_eq!(suspicious_token(name), None, "{name}");
        }
    }

    #[test]
    fn the_first_listed_token_wins() {
        // "hidden" comes before "veracrypt" in the list, wherever it sits in
        // the name.
        assert_eq!(suspicious_token("veracrypt-hidden"), Some("hidden"));
        assert_eq!(suspicious_token("TCRYPT_decoy"), Some("tcrypt"));
    }
}
