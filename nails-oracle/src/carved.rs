// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Keys for the objects bulk_extractor's carving scanners (the `*_carved`
//! recorders) reconstruct, so that an object subtracts across the three images
//! exactly when its content does.
//!
//! A carved object is named by the byte offset it was found at, which says
//! where it sits, not what it is, so it is keyed by its content instead. A
//! carved login record (`utmp_carved`) is parsed and keyed by the fields it
//! records with its time and session left out, like plaso's reading of a live
//! login file: the boot and getty records a plain reboot writes subtract
//! against the ones the control cycle wrote, and a record of another user,
//! host, terminal or process range does not, whether it sits in a live login
//! file or in free space. Any other carved object is keyed by the content hash
//! bulk_extractor records for it. [`recorder`] says which recorder gets which.
//!
//! The same key reads the records of a restored login file
//! ([`login_record_keys`]): on a filesystem that compresses, bulk_extractor
//! carves none of the records a compressed extent holds, so the control
//! image's login files, read whole, say which records the control cycle wrote
//! (see [`crate::model::Scans::control_login_records`]).

use crate::plaso::pid_range;
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Component, Path, PathBuf};

/// How the scan reads one bulk_extractor feature file, by its feature type
/// (the file stem).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorder {
    /// A value recorder (`email`, `url`, `domain`, ...): each line's feature
    /// column is the value.
    Values,
    /// `utmp_carved`: each line names a carved 384-byte login record, keyed by
    /// the fields it records ([`utmp_record_key`]).
    LoginRecords,
    /// Another carving scanner: each line's carved object is keyed by the
    /// content hash in its context column ([`carved_hash`]).
    CarvedObjects,
    /// Left out of the verdict. `sqlite_carved` reconstructs whole databases,
    /// and on the oracle's decoy images the Nix store database changes on every
    /// boot, so `after` holds live and stale, partly overwritten copies of it
    /// whose bytes no clean boot reproduces: keyed by hash they never subtract,
    /// and a carved database has no record layout this scan parses. A database
    /// the session leaves is still seen by its path and digest when it is a
    /// live file, the live Nix store database by its rows (see
    /// [`crate::nix_db`]), and any database by the value recorders (its URLs,
    /// e-mail addresses and domains) wherever it sits; the verdict names the
    /// rest as unseen ([`SKIPPED_CARVERS`]). `duplicates` lists blocks that
    /// repeat by their offsets, which say where data sits, not what it is.
    Skipped,
}

/// The carvers whose objects the verdict leaves out (see
/// [`Recorder::Skipped`]): what they reconstruct is a class of trace the
/// verdict cannot see, so it names them.
pub const SKIPPED_CARVERS: [&str; 1] = ["sqlite_carved"];

/// The feature type of bulk_extractor's carved login records.
pub const UTMP_CARVED: &str = "utmp_carved";

/// The way the scan reads the feature file of `feature_type`.
pub fn recorder(feature_type: &str) -> Recorder {
    match feature_type {
        UTMP_CARVED => Recorder::LoginRecords,
        "duplicates" => Recorder::Skipped,
        skipped if SKIPPED_CARVERS.contains(&skipped) => Recorder::Skipped,
        other if other.ends_with("_carved") => Recorder::CarvedObjects,
        _ => Recorder::Values,
    }
}

/// The content hash bulk_extractor records in a carved object's context
/// column (`<hashdigest type='sha1'>…</hashdigest>`) as `sha1:<hex>`, or
/// `None` when the column carries none.
pub fn carved_hash(context: &str) -> Option<String> {
    let open = "<hashdigest type='";
    let start = context.find(open)? + open.len();
    let rest = &context[start..];
    let (kind, rest) = rest.split_once("'>")?;
    let (digest, _) = rest.split_once("</hashdigest>")?;
    let valid = !kind.is_empty()
        && kind.bytes().all(|b| b.is_ascii_alphanumeric())
        && !digest.is_empty()
        && digest.bytes().all(|b| b.is_ascii_hexdigit());
    valid.then(|| format!("{kind}:{}", digest.to_ascii_lowercase()))
}

/// The name bulk_extractor gives an object whose bytes it already saved
/// under another name; the context still carries the hash of those bytes.
pub const CACHED: &str = "<CACHED>";

/// Whether a carved-object line's context describes a zip member
/// (`<zipinfo>...`) rather than a saved file.
pub fn is_zip_member_info(context: &str) -> bool {
    context.starts_with("<zipinfo>")
}

/// The place of the zip member a saved file's line names in its first
/// column, the forensic path bulk_extractor writes: `1304739840-ZIP-0` names
/// the member at `1304739840`, and a member found in decompressed data has a
/// path of its own, so `512-GZIP-80-ZIP-0` names the member at `512-GZIP-80`.
/// `None` when the column names no zip member.
pub fn zip_member_offset(column: &str) -> Option<&str> {
    let (place, index) = column.rsplit_once("-ZIP-")?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let path = place.starts_with(|c: char| c.is_ascii_digit())
        && place
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase() || b == b'-');
    (path && digits(index)).then_some(place)
}

/// The carved object's file under the recorder's output directory, from the
/// feature column of its line (`utmp_carved/000/123utmp`), or `None` when the
/// column is not a plain relative path inside that directory.
pub fn carved_object_path(dir: &Path, feature: &str) -> Option<PathBuf> {
    let relative = Path::new(feature);
    let plain = relative
        .components()
        .all(|component| matches!(component, Component::Normal(_)));
    (plain && !feature.is_empty()).then(|| dir.join(relative))
}

/// The size of one glibc `struct utmp` record on x86_64 Linux, the size
/// bulk_extractor's utmp carver writes each record at.
pub const UTMP_RECORD_SIZE: usize = 384;

/// The names of the `ut_type` values.
const UT_TYPES: [&str; 10] = [
    "EMPTY",
    "RUN_LVL",
    "BOOT_TIME",
    "NEW_TIME",
    "OLD_TIME",
    "INIT_PROCESS",
    "LOGIN_PROCESS",
    "USER_PROCESS",
    "DEAD_PROCESS",
    "ACCOUNTING",
];

/// Key one carved login record on what it records: its type, process range
/// ([`pid_range`]), terminal, id, user, host, exit status and address. Its
/// session id and time are left out: a fresh boot gives them new values, and
/// keyed by them no boot record would ever subtract. Returns `None` for a
/// buffer that is not one record. Pure, so it is unit-tested directly.
pub fn utmp_record_key(record: &[u8]) -> Option<String> {
    if record.len() != UTMP_RECORD_SIZE {
        return None;
    }
    let i16_at = |at: usize| i16::from_le_bytes([record[at], record[at + 1]]);
    let i32_at = |at: usize| {
        i32::from_le_bytes([record[at], record[at + 1], record[at + 2], record[at + 3]])
    };
    let text = |from: usize, to: usize| {
        let raw = &record[from..to];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).into_owned()
    };
    let ut_type = i16_at(0);
    let kind = usize::try_from(ut_type)
        .ok()
        .and_then(|k| UT_TYPES.get(k))
        .map_or_else(|| ut_type.to_string(), |name| (*name).to_string());
    Some(format!(
        "type={kind} pid={} line={} id={} user={} host={} exit={}/{} addr={}",
        pid_range(i64::from(i32_at(4))),
        text(8, 40),
        text(40, 44),
        text(44, 76),
        text(76, 332),
        i16_at(332),
        i16_at(334),
        utmp_address(&record[348..364]),
    ))
}

/// Whether the restored file at the absolute on-image `path` is one a decoy
/// keeps login records in, as glibc writes them: `wtmp` or `btmp`, or a
/// rotation of one (`wtmp.1`, `wtmp-20261029`), in whatever directory the
/// restored tree holds it. A compressed rotation (`wtmp.1.gz`) is not: its
/// bytes are no records.
pub fn is_login_record_file(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    ["wtmp", "btmp"]
        .iter()
        .any(|base| match name.strip_prefix(base) {
            Some("") => true,
            Some(rest) => rest
                .strip_prefix(['.', '-'])
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())),
            None => false,
        })
}

/// The key ([`utmp_record_key`]) of every whole login record in `data`, the
/// contents of a login record file. A partial record at its end, which a torn
/// write can leave, is no record and adds none.
pub fn login_record_keys(data: &[u8]) -> BTreeSet<String> {
    let (records, _torn) = data.as_chunks::<UTMP_RECORD_SIZE>();
    records
        .iter()
        .filter_map(|record| utmp_record_key(record))
        .collect()
}

/// A login record's address (`ut_addr_v6`): IPv4 when only its first four
/// bytes are set, as glibc stores one, IPv6 otherwise.
fn utmp_address(bytes: &[u8]) -> String {
    let mut v6 = [0_u8; 16];
    v6.copy_from_slice(bytes);
    if v6[4..].iter().all(|&b| b == 0) {
        Ipv4Addr::new(v6[0], v6[1], v6[2], v6[3]).to_string()
    } else {
        Ipv6Addr::from(v6).to_string()
    }
}

#[cfg(test)]
#[path = "carved_tests.rs"]
mod tests;
