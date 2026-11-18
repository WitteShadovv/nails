// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The name PID 1 gives the mount unit of a mount point, as systemd's
//! `unit_name_from_path()` makes it (src/basic/unit-name.c, the same in
//! systemd 255 and 260): the path simplified, every byte of it escaped as
//! `unit_name_path_escape()` escapes it, whatever the byte, and a name of 256
//! characters or more shortened as `unit_name_hash_long()` shortens it, with
//! the SipHash-2-4 of the whole name and its terminating NUL under systemd's
//! fixed key. The names were checked against PID 1's own units on systemd
//! 255 and 260 (the tests below and the e2e check of the unit names).

use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// systemd's `UNIT_NAME_MAX`: a unit name is shorter.
const UNIT_NAME_MAX: usize = 256;

/// systemd's `LONG_UNIT_NAME_HASH_KEY`.
const LONG_HASH_KEY: [u8; 16] = [
    0xec, 0xf2, 0x37, 0xfb, 0x58, 0x32, 0x4a, 0x32, 0x84, 0x9f, 0x06, 0x9b, 0x0d, 0x21, 0xeb, 0x9a,
];

/// The suffix of a mount unit.
const SUFFIX: &str = ".mount";

/// The name of the mount unit PID 1 makes for a mount at `path`
/// (`/run/my-disk` is `run-my\x2ddisk.mount`): every byte that is not an
/// ASCII letter, a digit, `:`, `_` or `.` (a `.` only after the first) as
/// `\xNN`, valid UTF-8 or not, and a name that would have 256 characters or
/// more cut to 232 and given `_` and 16 hex digits of its hash before the
/// suffix.
pub fn mount_unit(path: &Path) -> String {
    let parts: Vec<&[u8]> = path
        .as_os_str()
        .as_bytes()
        .split(|&b| b == b'/')
        .filter(|part| !part.is_empty() && *part != b".")
        .collect();
    let mut name = String::new();
    if parts.is_empty() {
        name.push('-');
    }
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            name.push('-');
        }
        for (at, &byte) in part.iter().enumerate() {
            match byte {
                b'.' if index == 0 && at == 0 => name.push_str("\\x2e"),
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b':' | b'_' | b'.' => {
                    name.push(char::from(byte));
                }
                other => name.push_str(&format!("\\x{other:02x}")),
            }
        }
    }
    name.push_str(SUFFIX);
    if name.len() < UNIT_NAME_MAX {
        return name;
    }
    hash_long(&name)
}

/// `unit_name_hash_long()` for a name of [`UNIT_NAME_MAX`] characters or
/// more that ends in [`SUFFIX`]: its first characters, `_`, the hash's eight
/// bytes in little-endian order as hex, and the suffix, 255 characters in
/// all.
fn hash_long(name: &str) -> String {
    let mut hashed = name.as_bytes().to_vec();
    hashed.push(0);
    let hash = siphash24(&hashed, &LONG_HASH_KEY).to_le_bytes();
    let keep = UNIT_NAME_MAX - 1 - (SUFFIX.len() - 1) - 2 * hash.len() - 2;
    // The escaped name is ASCII, so any cut is at a character.
    let mut short = name[..keep].to_string();
    short.push('_');
    for byte in hash {
        short.push_str(&format!("{byte:02x}"));
    }
    short.push_str(SUFFIX);
    short
}

/// SipHash-2-4 of `data` under `key`, as systemd's `siphash24()`.
fn siphash24(data: &[u8], key: &[u8; 16]) -> u64 {
    let word = |bytes: &[u8]| {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(bytes);
        u64::from_le_bytes(buf)
    };
    let (k0, k1) = (word(&key[..8]), word(&key[8..]));
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    let round = |v: &mut [u64; 4]| {
        v[0] = v[0].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(13) ^ v[0];
        v[0] = v[0].rotate_left(32);
        v[2] = v[2].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(16) ^ v[2];
        v[0] = v[0].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(21) ^ v[0];
        v[2] = v[2].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(17) ^ v[2];
        v[2] = v[2].rotate_left(32);
    };
    let compress = |v: &mut [u64; 4], m: u64| {
        v[3] ^= m;
        round(v);
        round(v);
        v[0] ^= m;
    };
    let (chunks, rest) = data.as_chunks::<8>();
    for chunk in chunks {
        compress(&mut v, u64::from_le_bytes(*chunk));
    }
    let mut last = [0u8; 8];
    last[..rest.len()].copy_from_slice(rest);
    // The length's low byte, as SipHash defines the last block.
    last[7] = data.len().to_le_bytes()[0];
    compress(&mut v, u64::from_le_bytes(last));
    v[2] ^= 0xff;
    for _ in 0..4 {
        round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

#[cfg(test)]
#[path = "unit_name_tests.rs"]
mod tests;
