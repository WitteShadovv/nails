// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `/etc/crypttab`: the encrypted volumes a system's boot opens.
//!
//! `systemd-cryptsetup-generator` turns every line into a
//! `systemd-cryptsetup@<name>.service` that opens the volume as
//! `/dev/mapper/<name>`. A line is `name device [key [options]]`, fields
//! separated by white space; a line with fewer than two fields is ignored,
//! as systemd ignores it, and fields past the fourth are dropped.

use std::path::PathBuf;

/// One crypttab line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrypttabEntry {
    /// The volume name: the device opens as `/dev/mapper/<name>`.
    pub name: String,
    /// The encrypted device or file: a path, or `UUID=`/`PARTUUID=`/`LABEL=`/
    /// `PARTLABEL=`.
    pub source: String,
    /// The key file; `None` when the field is missing, `none` or `-`, where
    /// the boot asks for a passphrase (or finds a key in
    /// `/etc/cryptsetup-keys.d`).
    pub key: Option<String>,
    /// The options (`luks`, `tcrypt`, `discard`, `noauto`, `swap`, …).
    pub options: Vec<String>,
}

impl CrypttabEntry {
    /// Whether an option is present.
    pub fn has_option(&self, name: &str) -> bool {
        self.options.iter().any(|o| o == name)
    }

    /// The value of a `key=value` option (`header=`, `keyfile-offset=`, …).
    pub fn option_value(&self, key: &str) -> Option<&str> {
        self.options
            .iter()
            .find_map(|o| o.strip_prefix(key).and_then(|rest| rest.strip_prefix('=')))
    }

    /// A TrueCrypt or VeraCrypt volume: an option that makes
    /// `systemd-cryptsetup` open the device as one. That is `tcrypt`,
    /// `tcrypt-hidden` (or its alias `tcrypthidden`), `tcrypt-system`, a
    /// `tcrypt-keyfile=`, or `tcrypt-veracrypt` (or its alias `veracrypt`).
    /// Such an option counts wherever it stands, even before a `luks` or
    /// `plain` that systemd would let win.
    pub fn is_tcrypt(&self) -> bool {
        self.options.iter().any(|option| {
            matches!(option.as_str(), "tcrypt" | "tcrypt-system")
                || option.starts_with("tcrypt-keyfile=")
        }) || self.is_tcrypt_hidden()
            || self.is_veracrypt()
    }

    /// The hidden volume of a TrueCrypt or VeraCrypt container:
    /// `tcrypt-hidden` or its alias `tcrypthidden`.
    pub fn is_tcrypt_hidden(&self) -> bool {
        self.has_option("tcrypt-hidden") || self.has_option("tcrypthidden")
    }

    /// A VeraCrypt volume: `tcrypt-veracrypt` or its alias `veracrypt`.
    pub fn is_veracrypt(&self) -> bool {
        self.has_option("tcrypt-veracrypt") || self.has_option("veracrypt")
    }

    /// The block device the source names, as a `/dev` path (`UUID=x` as
    /// `/dev/disk/by-uuid/x`). `None` for a file or an unknown spec.
    pub fn device(&self) -> Option<PathBuf> {
        crate::fstab::spec_device(&self.source)
    }
}

/// Parse crypttab text. Comments, blank lines and lines with fewer than two
/// fields are skipped.
pub fn parse_crypttab(text: &str) -> Vec<CrypttabEntry> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?.to_string();
            let source = fields.next()?.to_string();
            let key = fields
                .next()
                .filter(|key| !matches!(*key, "none" | "-"))
                .map(str::to_string);
            let options = fields
                .next()
                .map(|options| options.split(',').map(str::to_string).collect())
                .unwrap_or_default();
            Some(CrypttabEntry {
                name,
                source,
                key,
                options,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn a_typical_crypttab_is_parsed() {
        let entries = parse_crypttab(
            "# <name> <device> <key> <options>\n\
             cryptroot UUID=0a1b2c3d-0000-4000-8000-000000000001 none luks,discard\n\
             \n\
             \t# an indented comment\n\
             cryptswap /dev/disk/by-partuuid/7f-02 /dev/urandom swap,cipher=aes-xts-plain64,size=512\n\
             backup PARTUUID=7f-03 /etc/keys/backup.key luks,noauto,nofail\n\
             vault /dev/sdb - tcrypt-hidden\n\
             data LABEL=data\n",
        );
        assert_eq!(entries.len(), 5);

        assert_eq!(entries[0].name, "cryptroot");
        assert_eq!(entries[0].key, None, "none asks for a passphrase");
        assert_eq!(entries[0].options, vec!["luks", "discard"]);
        assert!(entries[0].has_option("discard"));
        assert_eq!(
            entries[0].device(),
            Some(PathBuf::from(
                "/dev/disk/by-uuid/0a1b2c3d-0000-4000-8000-000000000001"
            ))
        );

        assert_eq!(entries[1].key.as_deref(), Some("/dev/urandom"));
        assert!(entries[1].has_option("swap"));
        assert_eq!(entries[1].option_value("size"), Some("512"));
        assert_eq!(entries[1].option_value("cipher"), Some("aes-xts-plain64"));

        assert_eq!(entries[2].key.as_deref(), Some("/etc/keys/backup.key"));
        assert!(entries[2].has_option("noauto"));
        assert_eq!(
            entries[2].device().as_deref(),
            Some(Path::new("/dev/disk/by-partuuid/7f-03"))
        );

        assert_eq!(entries[3].key, None, "- asks for a passphrase");
        assert!(entries[3].is_tcrypt());
        assert!(entries[3].is_tcrypt_hidden());
        assert!(!entries[3].is_veracrypt());
        assert_eq!(entries[3].device().as_deref(), Some(Path::new("/dev/sdb")));

        // Only the two mandatory fields.
        assert_eq!(entries[4].key, None);
        assert!(entries[4].options.is_empty());
        assert_eq!(
            entries[4].device().as_deref(),
            Some(Path::new("/dev/disk/by-label/data"))
        );
    }

    #[test]
    fn malformed_lines_are_skipped_and_extra_fields_dropped() {
        let entries = parse_crypttab(
            "lonely\n\
             ok /dev/vdb none luks extra fields\n\
             #commented /dev/vdc none luks\n",
        );
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "ok");
        assert_eq!(entries[0].options, vec!["luks"]);
    }

    #[test]
    fn veracrypt_and_truecrypt_options_are_told_apart() {
        let entry = |options: &str| CrypttabEntry {
            name: "x".into(),
            source: "/dev/vdb".into(),
            key: None,
            options: options.split(',').map(str::to_string).collect(),
        };
        assert!(entry("tcrypt").is_tcrypt());
        assert!(entry("tcrypt-system").is_tcrypt());
        assert!(entry("tcrypt-veracrypt").is_veracrypt());
        assert!(entry("tcrypt-veracrypt").is_tcrypt());
        assert!(entry("veracrypt").is_veracrypt());
        assert!(entry("veracrypt").is_tcrypt());
        assert!(!entry("luks,discard").is_tcrypt());
        assert!(!entry("tcrypt").is_tcrypt_hidden());

        // systemd's alias for tcrypt-hidden opens the hidden volume too.
        for hidden in [
            "tcrypt-hidden",
            "tcrypthidden",
            "discard,tcrypthidden,veracrypt",
        ] {
            assert!(entry(hidden).is_tcrypt(), "{hidden}");
            assert!(entry(hidden).is_tcrypt_hidden(), "{hidden}");
        }
        assert!(!entry("tcrypthidden").is_veracrypt());

        // A TrueCrypt key file selects the type on its own; a PIM does not.
        let keyfile = entry("tcrypt-keyfile=/etc/keys/vault.key");
        assert!(keyfile.is_tcrypt());
        assert!(!keyfile.is_tcrypt_hidden());
        assert!(!entry("veracrypt-pim=485").is_tcrypt());
        assert!(!entry("keyfile-offset=4096,keyfile-size=64").is_tcrypt());
    }

    #[test]
    fn a_file_or_an_unknown_spec_names_no_device() {
        let entries = parse_crypttab("box /home/alice/box.img none tcrypt\nodd ID=1 none\n");
        assert_eq!(entries[0].device(), None);
        assert_eq!(entries[0].source, "/home/alice/box.img");
        assert_eq!(entries[1].device(), None);
    }
}
