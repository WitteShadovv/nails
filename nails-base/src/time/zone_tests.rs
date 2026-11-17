// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Zones: the times shown in them, and which files finding the local zone
//! reads in each case.

use super::Timestamp;
use super::zone::{Zone, ZoneFile, ZoneFiles};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A TZif version 2 file (RFC 8536), as `nails-cli/tests/time_strings.rs`
/// writes one.
fn tzif(types: &[(i32, bool, &str)], transitions: &[(i64, u8)], footer: &str) -> Vec<u8> {
    fn header(out: &mut Vec<u8>, counts: [u32; 6]) {
        out.extend_from_slice(b"TZif2");
        out.extend_from_slice(&[0; 15]);
        for count in counts {
            out.extend_from_slice(&count.to_be_bytes());
        }
    }
    let mut out = Vec::new();
    header(&mut out, [0, 0, 0, 0, 1, 4]);
    out.extend_from_slice(&0i32.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(b"UTC\0");
    let mut chars = Vec::new();
    let mut index = Vec::new();
    for (_, _, name) in types {
        index.push(u8::try_from(chars.len()).unwrap());
        chars.extend_from_slice(name.as_bytes());
        chars.push(0);
    }
    let count = |n: usize| u32::try_from(n).unwrap();
    header(
        &mut out,
        [
            0,
            0,
            0,
            count(transitions.len()),
            count(types.len()),
            count(chars.len()),
        ],
    );
    for (at, _) in transitions {
        out.extend_from_slice(&at.to_be_bytes());
    }
    for (_, kind) in transitions {
        out.push(*kind);
    }
    for ((offset, dst, _), at) in types.iter().zip(&index) {
        out.extend_from_slice(&offset.to_be_bytes());
        out.push(u8::from(*dst));
        out.push(*at);
    }
    out.extend_from_slice(&chars);
    out.push(b'\n');
    out.extend_from_slice(footer.as_bytes());
    out.push(b'\n');
    out
}

/// A fixed zone `name` of `offset` seconds, as a TZif file.
fn fixed_file(offset: i32, name: &str, footer: &str) -> Vec<u8> {
    tzif(&[(offset, false, name)], &[], footer)
}

fn berlin() -> Vec<u8> {
    tzif(
        &[(3600, false, "CET"), (7200, true, "CEST")],
        &[(1_774_746_000, 1), (1_792_890_000, 0)],
        "CET-1CEST,M3.5.0,M10.5.0/3",
    )
}

/// Files that stand in for the machine's, recording every path read or
/// whose link is read.
#[derive(Default)]
struct Files {
    files: HashMap<PathBuf, ZoneFileKind>,
    links: HashMap<PathBuf, PathBuf>,
    reads: RefCell<Vec<String>>,
}

#[derive(Clone)]
enum ZoneFileKind {
    Bytes(Vec<u8>),
    Directory,
}

impl Files {
    fn file(mut self, path: &str, bytes: Vec<u8>) -> Self {
        self.files
            .insert(PathBuf::from(path), ZoneFileKind::Bytes(bytes));
        self
    }

    fn directory(mut self, path: &str) -> Self {
        self.files
            .insert(PathBuf::from(path), ZoneFileKind::Directory);
        self
    }

    fn link(mut self, path: &str, target: &str) -> Self {
        self.links
            .insert(PathBuf::from(path), PathBuf::from(target));
        self
    }

    fn reads(&self) -> Vec<String> {
        self.reads.borrow().clone()
    }
}

impl ZoneFiles for Files {
    fn read(&self, path: &Path) -> ZoneFile {
        self.reads.borrow_mut().push(path.display().to_string());
        match self.files.get(path) {
            Some(ZoneFileKind::Bytes(bytes)) => ZoneFile::Read(bytes.clone()),
            Some(ZoneFileKind::Directory) => ZoneFile::Unreadable,
            None => ZoneFile::NotOpened,
        }
    }

    fn read_link(&self, path: &Path) -> Option<PathBuf> {
        self.reads
            .borrow_mut()
            .push(format!("link {}", path.display()));
        self.links.get(path).cloned()
    }
}

/// 2026-03-29T01:00:00Z, the first second of summer time in Berlin.
fn summer() -> Timestamp {
    Timestamp::from_unix_seconds(1_774_746_000).unwrap()
}

fn shown(zone: &Zone) -> String {
    zone.stamp(summer())
}

/// A machine whose `/etc/localtime` is Berlin's zone file, linked as Debian
/// links it.
fn debian() -> Files {
    Files::default()
        .file("/etc/localtime", berlin())
        .link("/etc/localtime", "/usr/share/zoneinfo/Europe/Berlin")
        .file("/usr/share/zoneinfo/Europe/Berlin", berlin())
        .file("/etc/timezone", b"Europe/Berlin\n".to_vec())
}

#[test]
fn without_tz_only_etc_localtime_is_read() {
    let files = debian();
    assert_eq!(
        shown(&Zone::find(None, &files)),
        "2026-03-29 03:00:00 +02:00"
    );
    assert_eq!(files.reads(), ["/etc/localtime"]);

    let files = debian();
    let zone = Zone::find(Some("localtime"), &files);
    assert_eq!(shown(&zone), "2026-03-29 03:00:00 +02:00");
    assert_eq!(files.reads(), ["/etc/localtime"]);
}

#[test]
fn an_empty_tz_is_utc_and_reads_nothing() {
    let files = debian();
    assert_eq!(
        shown(&Zone::find(Some(""), &files)),
        "2026-03-29 01:00:00 +00:00"
    );
    assert!(files.reads().is_empty());
}

#[test]
fn a_tz_rule_reads_no_file_but_the_zone_directories_it_is_looked_for_in() {
    let files = debian();
    let zone = Zone::find(Some("<+05>-5"), &files);
    assert_eq!(shown(&zone), "2026-03-29 06:00:00 +05:00");
    assert_eq!(
        files.reads(),
        [
            "/usr/share/zoneinfo/<+05>-5",
            "/share/zoneinfo/<+05>-5",
            "/etc/zoneinfo/<+05>-5",
            "/usr/share/lib/zoneinfo/<+05>-5",
        ]
    );
}

#[test]
fn a_tz_zone_name_reads_its_file_from_the_first_directory_that_has_it() {
    let files = Files::default()
        .file("/etc/zoneinfo/Europe/Berlin", berlin())
        .file(
            "/usr/share/lib/zoneinfo/Europe/Berlin",
            fixed_file(0, "UTC", "UTC0"),
        );
    let zone = Zone::find(Some("Europe/Berlin"), &files);
    assert_eq!(shown(&zone), "2026-03-29 03:00:00 +02:00");
    assert_eq!(
        files.reads(),
        [
            "/usr/share/zoneinfo/Europe/Berlin",
            "/share/zoneinfo/Europe/Berlin",
            "/etc/zoneinfo/Europe/Berlin",
        ]
    );

    // With a colon, the same.
    let files = debian();
    let zone = Zone::find(Some(":Europe/Berlin"), &files);
    assert_eq!(shown(&zone), "2026-03-29 03:00:00 +02:00");
    assert_eq!(files.reads(), ["/usr/share/zoneinfo/Europe/Berlin"]);
}

#[test]
fn an_absolute_tz_path_is_read_as_it_stands() {
    let files = Files::default().file("/srv/zone", fixed_file(-3 * 3600, "XXT", "XXT3"));
    let zone = Zone::find(Some(":/srv/zone"), &files);
    assert_eq!(shown(&zone), "2026-03-28 22:00:00 -03:00");
    assert_eq!(files.reads(), ["/srv/zone"]);
    let zone = Zone::find(Some("/srv/zone"), &files);
    assert_eq!(shown(&zone), "2026-03-28 22:00:00 -03:00");
}

/// The reads of the fallback (step 5) on the [`debian`] machine.
const FALLBACK: [&str; 2] = ["link /etc/localtime", "/usr/share/zoneinfo/Europe/Berlin"];

#[test]
fn a_tz_naming_nothing_falls_back_to_the_zone_etc_localtime_links_to() {
    for tz in ["Nowhere/Zone", "XST5XDT", " ", "UTC", "<+02>-2 extra"] {
        let files = debian();
        let zone = Zone::find(Some(tz), &files);
        assert_eq!(shown(&zone), "2026-03-29 03:00:00 +02:00", "TZ={tz:?}");
        let reads = files.reads();
        assert_eq!(reads.len(), 6, "{reads:?}");
        assert_eq!(reads[4..], FALLBACK, "TZ={tz:?}");
    }
    // A colon form is never read as a rule: no file, then the fallback.
    let files = debian();
    let zone = Zone::find(Some(":UTC0"), &files);
    assert_eq!(shown(&zone), "2026-03-29 03:00:00 +02:00");
    assert_eq!(files.reads()[4..], FALLBACK);
}

#[test]
fn a_zone_file_that_opens_but_does_not_read_ends_the_search() {
    // A directory under the first zone directory: no further directory, no
    // rule, the fallback.
    let files = debian().directory("/usr/share/zoneinfo/Europe");
    let zone = Zone::find(Some("Europe"), &files);
    assert_eq!(shown(&zone), "2026-03-29 03:00:00 +02:00");
    let mut expected = vec!["/usr/share/zoneinfo/Europe".to_string()];
    expected.extend(FALLBACK.map(String::from));
    assert_eq!(files.reads(), expected);

    // A file that is no TZif file: likewise.
    let files = debian().file("/usr/share/zoneinfo/UTC0", b"not a zone".to_vec());
    let zone = Zone::find(Some("UTC0"), &files);
    assert_eq!(shown(&zone), "2026-03-29 03:00:00 +02:00");
}

#[test]
fn a_missing_or_broken_etc_localtime_falls_back_and_then_to_utc() {
    // Missing, no link, but /etc/timezone names the zone.
    let files = Files::default()
        .file("/usr/share/zoneinfo/Europe/Berlin", berlin())
        .file("/etc/timezone", b"Europe/Berlin \n".to_vec());
    let zone = Zone::find(None, &files);
    assert_eq!(shown(&zone), "2026-03-29 03:00:00 +02:00");
    assert_eq!(
        files.reads(),
        [
            "/etc/localtime",
            "link /etc/localtime",
            "/etc/timezone",
            "/usr/share/zoneinfo/Europe/Berlin",
        ]
    );

    // A broken link to a zone that is not there: UTC.
    let files = Files::default().link("/etc/localtime", "/usr/share/zoneinfo/Mars/Olympus");
    let zone = Zone::find(None, &files);
    assert_eq!(shown(&zone), "2026-03-29 01:00:00 +00:00");
    assert_eq!(
        files.reads(),
        [
            "/etc/localtime",
            "link /etc/localtime",
            "/usr/share/zoneinfo/Mars/Olympus",
        ]
    );

    // A link NixOS writes, relative, names the zone below /etc/zoneinfo, which
    // is still read from /usr/share/zoneinfo.
    let files = Files::default()
        .link("/etc/localtime", "../etc/zoneinfo/Europe/Berlin")
        .file("/usr/share/zoneinfo/Europe/Berlin", berlin());
    assert_eq!(
        shown(&Zone::find(None, &files)),
        "2026-03-29 03:00:00 +02:00"
    );

    // A link elsewhere names nothing; /etc/timezone is read next, and an
    // empty name opens no zone.
    let files = Files::default()
        .link("/etc/localtime", "/opt/zones/Berlin")
        .file("/etc/timezone", b"\n".to_vec())
        .directory("/usr/share/zoneinfo/");
    assert_eq!(
        shown(&Zone::find(None, &files)),
        "2026-03-29 01:00:00 +00:00"
    );
    assert_eq!(
        files.reads(),
        [
            "/etc/localtime",
            "link /etc/localtime",
            "/etc/timezone",
            "/usr/share/zoneinfo/",
        ]
    );

    // Nothing at all: UTC, after looking where the zone could be named.
    let files = Files::default();
    assert_eq!(
        shown(&Zone::find(None, &files)),
        "2026-03-29 01:00:00 +00:00"
    );
    assert_eq!(
        files.reads(),
        ["/etc/localtime", "link /etc/localtime", "/etc/timezone"]
    );

    // /etc/timezone that is not UTF-8 names nothing.
    let files = Files::default().file("/etc/timezone", vec![0xff, 0xfe]);
    assert_eq!(
        shown(&Zone::find(None, &files)),
        "2026-03-29 01:00:00 +00:00"
    );
}

#[test]
fn a_corrupt_etc_localtime_is_no_zone() {
    for bytes in [
        Vec::new(),
        b"TZif".to_vec(),
        b"not a zone file at all".to_vec(),
        berlin()[..60].to_vec(),
    ] {
        let files = Files::default().file("/etc/localtime", bytes);
        assert_eq!(
            shown(&Zone::find(None, &files)),
            "2026-03-29 01:00:00 +00:00"
        );
    }
}

#[test]
fn a_posix_rule_is_taken_as_tz_may_hold_it() {
    let accepted = [
        ("UTC0", "2026-03-29 01:00:00 +00:00"),
        ("GMT0", "2026-03-29 01:00:00 +00:00"),
        ("XST-3", "2026-03-29 04:00:00 +03:00"),
        (" XST-3 ", "2026-03-29 04:00:00 +03:00"),
        ("XST+3", "2026-03-28 22:00:00 -03:00"),
        ("<+0130>-1:30", "2026-03-29 02:30:00 +01:30"),
        ("<-0530>5:30", "2026-03-28 19:30:00 -05:30"),
        ("XST-23:59:59", "2026-03-30 00:59:59 +24:00"),
        ("ABCDEFG-1", "2026-03-29 02:00:00 +01:00"),
        ("CET-1CEST,M3.5.0,M10.5.0/3", "2026-03-29 03:00:00 +02:00"),
        ("XST5XDT,M3.2.0,M11.1.0", "2026-03-28 21:00:00 -04:00"),
        ("XST5XDT4,J60,J300", "2026-03-28 21:00:00 -04:00"),
        ("XST5XDT,60/2,300/2", "2026-03-28 21:00:00 -04:00"),
        ("XST5XDT,59/24,300/0:30:59", "2026-03-28 21:00:00 -04:00"),
        ("XST5XDT,M3.2.0/2,M11.1.0/2", "2026-03-28 21:00:00 -04:00"),
    ];
    for (rule, at) in accepted {
        let zone = Zone::posix(rule).unwrap_or_else(|| panic!("{rule:?} refused"));
        assert_eq!(shown(&zone), at, "{rule:?}");
    }
    let refused = [
        "",
        "UTC",
        "XST",
        "XS-3",
        "ABCDEFGH-3",
        "<AB>-3",
        "<A_B>-3",
        "<+03-3",
        "XST-24",
        "XST-25",
        "XST-1:60",
        "XST-1:00:60",
        "XST-",
        "XST5XDT",
        "XST5XDT,",
        "XST5XDT,M3.2.0",
        "XST5XDT,M3.2.0,",
        "XST5XDT,M13.2.0,M11.1.0",
        "XST5XDT,M3.6.0,M11.1.0",
        "XST5XDT,M3.0.0,M11.1.0",
        "XST5XDT,M3.2.7,M11.1.0",
        "XST5XDT,J0,J300",
        "XST5XDT,J366,J300",
        "XST5XDT,366,300",
        "XST5XDT,M3.2.0/25,M11.1.0",
        "XST5XDT,M3.2.0/-1,M11.1.0",
        "XST5XDT,M3.2.0/+1,M11.1.0",
        "XST5XDT,M3.2.0/1:60,M11.1.0",
        "XST+5XDT+4,M3.2.0/-1,M11.1.0/26",
        "XST5XDT,M3.2.0,M11.1.0,",
        "XST5XDT,M3.2.0,M11.1.0x",
        "XST-3x",
        "XST-99999999999",
        "XST5XDT,M300.2.0,M11.1.0",
        "XST5XDT,J70000,J300",
    ];
    for rule in refused {
        assert!(Zone::posix(rule).is_none(), "{rule:?} taken");
    }
}

#[test]
fn a_fixed_zone_and_utc_show_their_offset() {
    let at = summer();
    assert_eq!(Zone::utc().stamp(at), "2026-03-29 01:00:00 +00:00");
    assert_eq!(
        Zone::fixed(-1).unwrap().stamp(at),
        "2026-03-29 00:59:59 -00:00"
    );
    assert_eq!(
        Zone::fixed(29).unwrap().stamp(at),
        "2026-03-29 01:00:29 +00:00"
    );
    assert_eq!(
        Zone::fixed(30).unwrap().stamp(at),
        "2026-03-29 01:00:30 +00:01"
    );
    assert_eq!(
        Zone::fixed(-30).unwrap().stamp(at),
        "2026-03-29 00:59:30 -00:01"
    );
    assert_eq!(Zone::fixed(2 * 3600).unwrap().clock(at), "03:00:00");
    assert!(Zone::fixed(26 * 3600).is_none());
}

#[test]
fn a_time_past_the_years_a_zone_reaches_takes_the_offset_at_their_end() {
    let zone = tzif_zone();
    let max = Timestamp::MAX;
    assert_eq!(zone.stamp(max), "+262143-01-01 00:59:59 +01:00");
    assert_eq!(Zone::utc().stamp(max), "+262142-12-31 23:59:59 +00:00");
    let min = Timestamp::MIN;
    assert_eq!(
        Zone::fixed(-3600).unwrap().stamp(min),
        "-262144-12-31 23:00:00 -01:00"
    );
    assert_eq!(
        zone.clock(Timestamp::from_unix_seconds(253_402_300_800).unwrap()),
        "01:00:00"
    );
}

fn tzif_zone() -> Zone {
    Zone::tzif(&berlin()).unwrap()
}

#[test]
fn the_local_zone_is_one_and_shows_a_time() {
    let first: *const Zone = Zone::local();
    let second: *const Zone = Zone::local();
    assert_eq!(first, second);
    // Whatever zone the machine running the test has, a stamp keeps its form.
    let stamp = Zone::local().stamp(summer());
    let shape: String = stamp
        .chars()
        .map(|c| if c.is_ascii_digit() { '9' } else { c })
        .collect();
    assert!(
        shape == "9999-99-99 99:99:99 +99:99" || shape == "9999-99-99 99:99:99 -99:99",
        "{stamp}"
    );
    assert_eq!(stamp[11..19], Zone::local().clock(summer()));
}
