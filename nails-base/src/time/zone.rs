// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The zone a time is shown in, and how the local zone is found.
//!
//! The local zone is looked for in these files and in no other, as NAILS
//! looked for it before, less the OpenWrt `/etc/config/system` it once also
//! tried:
//!
//! 1. `TZ` unset (or not UTF-8), or `TZ=localtime`: `/etc/localtime`.
//! 2. `TZ` empty: UTC.
//! 3. `TZ=:name`: the zone file `name`, an absolute path or relative to the
//!    first of `/usr/share/zoneinfo`, `/share/zoneinfo`, `/etc/zoneinfo` and
//!    `/usr/share/lib/zoneinfo` that opens it.
//! 4. Any other `TZ`: that zone file if one opens, else the POSIX rule it
//!    holds (see [`super::posix`]).
//! 5. When that gives no zone: the zone named by where `/etc/localtime` links
//!    (below `/usr/share/zoneinfo/` or `/etc/zoneinfo/`), else by
//!    `/etc/timezone`, read from `/usr/share/zoneinfo/<name>`: the name is
//!    put after that directory as it stands, so a name that starts with `/`
//!    names no file.
//! 6. Else UTC.
//!
//! No directory is listed and no zone database is searched: a zone file is
//! read only when `TZ`, `/etc/localtime` or `/etc/timezone` names it. The
//! zone is looked for once per process, the first time a time is shown in it,
//! so a command that shows no local time reads none of these files.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::Timestamp;
use super::civil::{Civil, write_offset};
use super::tzif::Extras;

/// A time zone: a fixed offset, a POSIX rule or a zone file's transitions,
/// or the local zone, found when a time is first shown in it.
#[derive(Debug, Clone)]
pub struct Zone(Rules);

#[derive(Debug, Clone)]
enum Rules {
    Known(Known),
    Local,
}

/// The rules of a zone that is known.
#[derive(Debug, Clone)]
struct Known {
    /// The offsets, as jiff reads them.
    tz: jiff::tz::TimeZone,
    /// The POSIX rule that holds after the last transition: a zone file's
    /// footer, or the rule of a POSIX zone.
    rule: Option<jiff::tz::TimeZone>,
    /// What a zone file says beyond that (see [`super::tzif`]).
    extras: Extras,
}

/// The seconds of 400 Gregorian years, after which weekdays and leap years
/// repeat.
const CYCLE: i64 = 146_097 * 86_400;

impl Known {
    fn new(tz: jiff::tz::TimeZone) -> Self {
        Self {
            tz,
            rule: None,
            extras: Extras::default(),
        }
    }

    /// The offset at Unix time `unix`.
    ///
    /// A zone file's transitions are compared with the instant in their leap
    /// time. From the last transition on (or with none) the POSIX rule holds
    /// at the instant itself; it repeats every 400 years, so outside the years
    /// jiff reaches (-9999 to 9999) the rule is read at the same day and time
    /// of a year 400 years nearer. Any other zone keeps its offset there.
    fn offset_at(&self, unix: i64) -> i32 {
        let min = jiff::Timestamp::MIN.as_second();
        let max = jiff::Timestamp::MAX.as_second();
        let last = self.extras.last_transition;
        let leap = self.extras.leap_time(unix);
        let at = match (&self.rule, last) {
            (_, Some(last)) if leap < last => return offset(&self.tz, leap.clamp(min, max)),
            (Some(rule), _) => return offset(rule, into_range(unix, min, max)),
            // No rule: the last transition's offset, or the zone's only one.
            (None, Some(last)) => unix.max(last),
            (None, None) => unix,
        };
        offset(&self.tz, at.clamp(min, max))
    }
}

/// The offset `tz` gives at `second`, which is within jiff's range.
fn offset(tz: &jiff::tz::TimeZone, second: i64) -> i32 {
    // The callers keep `second` within jiff's range, so the conversion holds.
    let at = jiff::Timestamp::from_second(second).unwrap_or(jiff::Timestamp::UNIX_EPOCH);
    tz.to_offset(at).seconds()
}

/// `unix` moved by whole 400-year cycles into `min..=max` when outside it.
fn into_range(unix: i64, min: i64, max: i64) -> i64 {
    // The cycles to move by, rounded up; the distance is positive.
    let cycles = |distance: i64| (distance + CYCLE - 1) / CYCLE;
    if unix > max {
        unix - cycles(unix - max) * CYCLE
    } else if unix < min {
        unix + cycles(min - unix) * CYCLE
    } else {
        unix
    }
}

impl Zone {
    /// UTC.
    pub fn utc() -> Self {
        Self(Rules::Known(Known::new(jiff::tz::TimeZone::UTC)))
    }

    /// A fixed offset of `seconds` east of UTC, or `None` beyond ±25:59:59.
    pub fn fixed(seconds: i32) -> Option<Self> {
        let offset = jiff::tz::Offset::from_seconds(seconds).ok()?;
        Some(Self(Rules::Known(Known::new(jiff::tz::TimeZone::fixed(
            offset,
        )))))
    }

    /// The zone of a POSIX TZ string as `TZ` may hold it, or `None`.
    pub fn posix(rule: &str) -> Option<Self> {
        // Blanks around the rule are no part of it.
        let rule = rule.trim_matches(|c: char| c.is_ascii_whitespace());
        if !super::posix::accepted(rule) {
            return None;
        }
        let tz = jiff::tz::TimeZone::posix(rule).ok()?;
        Some(Self(Rules::Known(Known {
            rule: Some(tz.clone()),
            ..Known::new(tz)
        })))
    }

    /// The zone of a TZif file's bytes (RFC 8536), or `None` when they are no
    /// valid one or their footer gives an offset of 24 hours or more, which
    /// NAILS has never taken from a footer.
    pub fn tzif(bytes: &[u8]) -> Option<Self> {
        let bytes = super::tzif::framed(bytes);
        let tz = jiff::tz::TimeZone::tzif("localtime", &bytes).ok()?;
        let extras = super::tzif::read(&bytes)?;
        if extras
            .footer
            .as_deref()
            .is_some_and(super::posix::offset_of_a_day)
        {
            return None;
        }
        let rule = extras
            .footer
            .as_deref()
            .and_then(|footer| jiff::tz::TimeZone::posix(footer).ok());
        Some(Self(Rules::Known(Known { tz, rule, extras })))
    }

    /// The local zone of this process (see the module documentation). It is
    /// looked for the first time a time is shown in it, not before: taking
    /// this zone reads no file.
    pub fn local() -> &'static Self {
        static LOCAL: Zone = Zone(Rules::Local);
        &LOCAL
    }

    /// The rules behind this zone, looking for the local zone's the first
    /// time they are needed.
    fn rules(&self) -> &Known {
        static LOCAL: OnceLock<Known> = OnceLock::new();
        match &self.0 {
            Rules::Known(known) => known,
            Rules::Local => LOCAL.get_or_init(|| {
                match Self::find(std::env::var("TZ").ok().as_deref(), &SystemFiles).0 {
                    Rules::Known(known) => known,
                    // `find` gives known rules only.
                    Rules::Local => Known::new(jiff::tz::TimeZone::UTC),
                }
            }),
        }
    }

    /// The local zone for the `TZ` value `tz`, reading through `files`.
    pub(crate) fn find(tz: Option<&str>, files: &dyn ZoneFiles) -> Self {
        from_tz(tz, files)
            .or_else(|| linked_zone(files))
            .unwrap_or_else(Self::utc)
    }

    /// The offset from UTC in seconds at `instant`.
    ///
    /// The offset is taken at the second `instant` falls in, in every year a
    /// timestamp covers: a zone's POSIX rule holds in every year after its
    /// last transition.
    pub fn offset_at(&self, instant: Timestamp) -> i32 {
        self.rules().offset_at(instant.unix_seconds())
    }

    /// `instant` in this zone with its offset, as `status` shows a time:
    /// `2026-10-14 21:41:59 +02:00`. The fraction of the second is left out,
    /// and the offset is rounded to the minute.
    pub fn stamp(&self, instant: Timestamp) -> String {
        let offset = self.offset_at(instant);
        let civil = Civil::from_unix(instant.unix_seconds() + i64::from(offset));
        let mut out = String::with_capacity(26);
        civil.write_date(&mut out);
        out.push(' ');
        civil.write_time(&mut out);
        out.push(' ');
        write_offset(&mut out, offset);
        out
    }

    /// The time of day of `instant` in this zone, `HH:MM:SS`.
    pub fn clock(&self, instant: Timestamp) -> String {
        let offset = self.offset_at(instant);
        let civil = Civil::from_unix(instant.unix_seconds() + i64::from(offset));
        let mut out = String::with_capacity(8);
        civil.write_time(&mut out);
        out
    }
}

/// How a zone file was read.
#[derive(Debug)]
pub(crate) enum ZoneFile {
    /// It did not open: missing, unreachable, or not allowed.
    NotOpened,
    /// It opened but could not be read through, as a directory.
    Unreadable,
    /// Its bytes.
    Read(Vec<u8>),
}

/// The reads the local zone is looked for with, so a test can stand in for
/// the files of the machine.
pub(crate) trait ZoneFiles {
    /// Open `path` (following links) and read it.
    fn read(&self, path: &Path) -> ZoneFile;
    /// Where the link at `path` points.
    fn read_link(&self, path: &Path) -> Option<PathBuf>;
}

/// The machine's own files.
struct SystemFiles;

impl ZoneFiles for SystemFiles {
    fn read(&self, path: &Path) -> ZoneFile {
        let Ok(mut file) = std::fs::File::open(path) else {
            return ZoneFile::NotOpened;
        };
        let mut bytes = Vec::new();
        match file.read_to_end(&mut bytes) {
            Ok(_) => ZoneFile::Read(bytes),
            Err(_) => ZoneFile::Unreadable,
        }
    }

    fn read_link(&self, path: &Path) -> Option<PathBuf> {
        std::fs::read_link(path).ok()
    }
}

const LOCALTIME: &str = "/etc/localtime";

/// The directories a relative zone name in `TZ` is looked for in, in order.
const ZONE_DIRECTORIES: [&str; 4] = [
    "/usr/share/zoneinfo",
    "/share/zoneinfo",
    "/etc/zoneinfo",
    "/usr/share/lib/zoneinfo",
];

/// The zone `TZ` gives (steps 1 to 4), or `None` to fall back.
fn from_tz(tz: Option<&str>, files: &dyn ZoneFiles) -> Option<Zone> {
    let Some(tz) = tz else {
        return from_file(files.read(Path::new(LOCALTIME)));
    };
    if tz.is_empty() {
        return Some(Zone::utc());
    }
    if tz == "localtime" {
        return from_file(files.read(Path::new(LOCALTIME)));
    }
    if let Some(name) = tz.strip_prefix(':') {
        return from_file(find_zone_file(name, files));
    }
    match find_zone_file(tz, files) {
        ZoneFile::NotOpened => Zone::posix(tz),
        opened => from_file(opened),
    }
}

/// The zone file `name`: the path itself when absolute, else the first of
/// [`ZONE_DIRECTORIES`] it opens in. A file that opens but cannot be read
/// ends the search.
fn find_zone_file(name: &str, files: &dyn ZoneFiles) -> ZoneFile {
    let path = Path::new(name);
    if path.is_absolute() {
        return files.read(path);
    }
    for directory in ZONE_DIRECTORIES {
        match files.read(&Path::new(directory).join(path)) {
            ZoneFile::NotOpened => continue,
            opened => return opened,
        }
    }
    ZoneFile::NotOpened
}

fn from_file(file: ZoneFile) -> Option<Zone> {
    match file {
        ZoneFile::Read(bytes) => Zone::tzif(&bytes),
        ZoneFile::NotOpened | ZoneFile::Unreadable => None,
    }
}

/// Step 5: the zone named by `/etc/localtime`'s link or by `/etc/timezone`.
fn linked_zone(files: &dyn ZoneFiles) -> Option<Zone> {
    let name = linked_name(files).or_else(|| timezone_file_name(files))?;
    // The name follows the directory as it stands, as it always has: a name
    // that starts with `/` makes a path with `//` that names no zone file,
    // where joining paths would read the file the name gives.
    from_file(files.read(Path::new(&format!("/usr/share/zoneinfo/{name}"))))
}

/// The zone name in `/etc/localtime`'s link: what follows
/// `/usr/share/zoneinfo/` or `/etc/zoneinfo/`, absolute or one level up.
fn linked_name(files: &dyn ZoneFiles) -> Option<String> {
    const PREFIXES: [&str; 4] = [
        "/usr/share/zoneinfo/",
        "../usr/share/zoneinfo/",
        "/etc/zoneinfo/",
        "../etc/zoneinfo/",
    ];
    let target = files
        .read_link(Path::new(LOCALTIME))?
        .into_os_string()
        .into_string()
        .ok()?;
    PREFIXES
        .iter()
        .find_map(|prefix| target.strip_prefix(prefix))
        .map(str::to_string)
}

/// The zone name `/etc/timezone` holds, without trailing blanks.
fn timezone_file_name(files: &dyn ZoneFiles) -> Option<String> {
    let ZoneFile::Read(bytes) = files.read(Path::new("/etc/timezone")) else {
        return None;
    };
    let text = String::from_utf8(bytes).ok()?;
    Some(text.trim_end().to_string())
}
