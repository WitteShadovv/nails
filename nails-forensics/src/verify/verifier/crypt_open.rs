// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `cryptsetup open` options that open a volume of the decoy's
//! `/etc/crypttab` as `systemd-cryptsetup` opens it at boot, for the line of
//! a mapping that is not open here. systemd v260 reads the line so, as v245
//! did. What the line opens the volume with that has no option here, such as
//! a key file or a token, is named instead, as it needs parameters of its
//! own.

use nails_base::crypttab::CrypttabEntry;
use nails_base::fstab::spec_device;
use nails_base::next_step::shell_word;
use std::ffi::OsStr;

/// The cipher, key size in bits and passphrase hash systemd-cryptsetup opens
/// a plain volume with where its line gives none. cryptsetup's own defaults
/// are older or newer ones, so a plain open names all three.
const PLAIN_DEFAULTS: [(&str, &str, &str); 3] = [
    ("cipher", "--cipher", "aes-cbc-essiv:sha256"),
    ("size", "--key-size", "256"),
    ("hash", "--hash", "ripemd160"),
];

/// The plain options systemd-cryptsetup reads with no default: from where
/// the encrypted data starts, the sector its IVs count from, and the sector
/// size.
const PLAIN_LAYOUT: [(&str, &str); 3] = [
    ("offset", "--offset"),
    ("skip", "--skip"),
    ("sector-size", "--sector-size"),
];

/// The kind of volume systemd-cryptsetup opens a line as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Luks,
    Plain,
    Tcrypt,
    Bitlk,
}

/// How to open a volume of the decoy's crypttab with `cryptsetup open`.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Opening {
    /// The options before the source, each followed by a space.
    pub(super) options: String,
    /// What the line also opens the volume with that no option here carries
    /// over, as the line gives it.
    pub(super) left_out: Vec<String>,
}

/// The options that open `volume` as systemd-cryptsetup does, `here` giving
/// where a device or file the line names lies on this machine, shell-quoted:
/// a detached header and a TrueCrypt key file are read from there. One that
/// `here` cannot place is left out.
pub(super) fn opening(volume: &CrypttabEntry, here: impl Fn(&str) -> Option<String>) -> Opening {
    let kind = kind(volume);
    let mut options: Vec<String> = Vec::new();
    let mut left_out: Vec<String> = volume
        .key
        .iter()
        .map(|key| format!("the key file {key}"))
        .collect();
    match kind {
        Kind::Luks => {}
        Kind::Plain => options = plain(volume),
        Kind::Tcrypt => options = tcrypt(volume),
        Kind::Bitlk => options.push("--type bitlk".to_string()),
    }
    for option in &volume.options {
        // The file an option names, and the option that reads it here.
        let file = if let Some(header) = option.strip_prefix("header=") {
            let carried = matches!(kind, Kind::Luks | Kind::Tcrypt) && is_header_path(header);
            Some((carried.then_some(header), "--header"))
        } else if let Some(key_file) = option.strip_prefix("tcrypt-keyfile=") {
            // systemd hands these to cryptsetup as --key-file does, and drops
            // a relative one.
            if kind != Kind::Tcrypt || !key_file.starts_with('/') {
                continue;
            }
            Some((Some(key_file), "--key-file"))
        } else {
            None
        };
        match file {
            Some((Some(file), flag)) => match here(file) {
                Some(at) => options.push(format!("{flag} {at}")),
                None => left_out.push(option.clone()),
            },
            Some((None, _)) => left_out.push(option.clone()),
            None if needs_its_own(option) => left_out.push(option.clone()),
            None => {}
        }
    }
    Opening {
        options: options.iter().map(|option| format!("{option} ")).collect(),
        left_out,
    }
}

/// The options of a plain volume: the parameters of its line, systemd's
/// defaults for those it gives none.
fn plain(volume: &CrypttabEntry) -> Vec<String> {
    let mut options = vec!["--type plain".to_string()];
    for (key, option, default) in PLAIN_DEFAULTS {
        let value = volume.option_value(key).unwrap_or(default);
        options.push(format!("{option} {}", word(value)));
    }
    for (key, option) in PLAIN_LAYOUT {
        if let Some(value) = volume.option_value(key) {
            options.push(format!("{option} {}", word(value)));
        }
    }
    options
}

/// The options of a TrueCrypt or VeraCrypt volume: which header it opens
/// and its PIM. cryptsetup looks for a VeraCrypt volume by itself.
fn tcrypt(volume: &CrypttabEntry) -> Vec<String> {
    let mut options = vec!["--type tcrypt".to_string()];
    if volume.is_tcrypt_hidden() {
        options.push("--tcrypt-hidden".to_string());
    }
    if volume.has_option("tcrypt-system") {
        options.push("--tcrypt-system".to_string());
    }
    if let Some(pim) = volume.option_value("veracrypt-pim") {
        options.push(format!("--veracrypt-pim {}", word(pim)));
    }
    options
}

/// The kind of volume systemd-cryptsetup opens `volume` as: it reads the
/// options in order and the last one that names a kind wins. A detached
/// header makes the volume LUKS, unless TrueCrypt is named before it, and a
/// line that names no kind is opened as LUKS alone.
fn kind(volume: &CrypttabEntry) -> Kind {
    volume
        .options
        .iter()
        .fold(None, |kind, option| {
            let named = match option.as_str() {
                "luks" => Kind::Luks,
                "bitlk" => Kind::Bitlk,
                "plain" | "swap" | "tmp" => Kind::Plain,
                "tcrypt" | "tcrypt-hidden" | "tcrypthidden" | "tcrypt-system"
                | "tcrypt-veracrypt" | "veracrypt" => Kind::Tcrypt,
                other if other.starts_with("tmp=") => Kind::Plain,
                other if other.starts_with("tcrypt-keyfile=") => Kind::Tcrypt,
                other if other.starts_with("key-slot=") || other.starts_with("keyslot=") => {
                    Kind::Luks
                }
                other if other.starts_with("header=") => match kind {
                    Some(Kind::Tcrypt) => Kind::Tcrypt,
                    _ => Kind::Luks,
                },
                _ => return kind,
            };
            Some(named)
        })
        .unwrap_or(Kind::Luks)
}

/// Whether a `header=` value is a path alone, as systemd reads it: absolute,
/// and not followed by `:` and the device that holds the file (a `/dev` path
/// or an fstab device spec), which systemd mounts to read the header.
fn is_header_path(header: &str) -> bool {
    header.starts_with('/')
        && header
            .rsplit_once(':')
            .is_none_or(|(_, device)| !(device.starts_with('/') || spec_device(device).is_some()))
}

/// Whether `option` changes how systemd-cryptsetup unlocks the volume with
/// no `cryptsetup open` option that does the same here: where in a key file
/// the key lies, and a PKCS#11, FIDO2 or TPM2 token. A TPM2 measurement
/// changes nothing that opens the volume.
fn needs_its_own(option: &str) -> bool {
    [
        "keyfile-offset=",
        "keyfile-size=",
        "pkcs11-uri=",
        "fido2-",
        "tpm2-",
    ]
    .iter()
    .any(|prefix| option.starts_with(prefix))
        && !option.starts_with("tpm2-measure-")
}

fn word(value: &str) -> String {
    shell_word(OsStr::new(value))
}
