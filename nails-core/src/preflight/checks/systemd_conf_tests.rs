// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The systemd configuration reader: the syntax of one file, and the main file
//! and drop-ins of a configuration on a real filesystem in a temporary root.

use super::*;
use crate::RealFilesystem;
use std::fs;

fn write(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn values(root: &Path, key: &str) -> Vec<String> {
    section_assignments(&RealFilesystem, root, "journald.conf", "Journal")
        .into_iter()
        .filter(|a| a.key == key)
        .map(|a| a.value)
        .collect()
}

fn parse(text: &str) -> (Vec<(String, String)>, bool) {
    let mut out = Vec::new();
    let ok = parse_section(text, "Journal", &mut out).is_ok();
    (out.into_iter().map(|a| (a.key, a.value)).collect(), ok)
}

fn pair(key: &str, value: &str) -> (String, String) {
    (key.to_string(), value.to_string())
}

/// systemd drops a byte order mark from the first line that starts with
/// one, which need not be the first line, and tells a comment before it
/// does. Found by the `systemd_conf` fuzz target with a mark at the start
/// of a later line, which NAILS kept.
#[test]
fn a_byte_order_mark_goes_where_systemd_drops_it() {
    // On a later line the mark goes, so the header counts.
    assert_eq!(
        parse("# a comment\n\u{feff}[Journal]\nStorage=volatile\n"),
        (vec![pair("Storage", "volatile")], true)
    );
    // Only the first mark goes.
    assert_eq!(
        parse("\u{feff}[Journal]\n\u{feff}Storage=none\nStorage=volatile\n"),
        (
            vec![pair("\u{feff}Storage", "none"), pair("Storage", "volatile")],
            true
        )
    );
    // A mark before `#` leaves no comment but a key systemd does not know.
    assert_eq!(
        parse("[Journal]\n\u{feff}#Storage=none\n"),
        (vec![pair("#Storage", "none")], true)
    );
}

/// systemd refuses a section name with a control character, a quote or a
/// backslash, and stops reading there as at a header without its `]`.
/// Found by the `systemd_conf` fuzz target with a DEL in the name, after
/// which NAILS read on into the drop-ins.
#[test]
fn a_section_name_systemd_refuses_stops_the_reading() {
    for header in [
        "[Log\u{7f}in]",
        "[Lo\tgin]",
        "[\"Journal\"]",
        "['Journal']",
        "[Jour\\nal]",
    ] {
        let text = format!("[Journal]\nStorage=volatile\n{header}\n[Journal]\nStorage=none\n");
        assert_eq!(
            parse(&text),
            (vec![pair("Storage", "volatile")], false),
            "{header}"
        );
    }
}

/// systemd ends a line at a carriage return or a NUL too. Found by the
/// `systemd_conf` fuzz target: the CR after `[` stayed inside the line,
/// which then read as the header of another section, so the assignments
/// after it counted, where systemd stops at the malformed header `[`.
#[test]
fn a_carriage_return_or_a_nul_ends_a_line() {
    assert_eq!(parse("[\rJournal]\nStorage=persistent\n"), (vec![], false));
    assert_eq!(
        parse("[Journal]\rStorage=volatile\r"),
        (vec![pair("Storage", "volatile")], true)
    );
    assert_eq!(
        parse("[Journal]\r\n\rStorage=none\n\rStorage=auto"),
        (vec![pair("Storage", "none"), pair("Storage", "auto")], true)
    );
    assert_eq!(
        parse("[Journal]\0Storage=volatile\0\0Storage=none"),
        (
            vec![pair("Storage", "volatile"), pair("Storage", "none")],
            true
        )
    );
    // A continued line goes on past a lone CR as past a newline.
    assert_eq!(
        parse("[Journal]\rStorage=vola\\\rtile"),
        (vec![pair("Storage", "vola tile")], true)
    );
}

/// A run of line ends ends a single line only while no kind repeats in it
/// and no NUL has come first: `\r\n` ends one line, while `\n\n`, and a NUL
/// followed by another end, end two, the second of them empty.
#[test]
fn a_line_end_that_repeats_or_follows_a_nul_ends_another_line() {
    assert_eq!(read_lines("a\r\nb"), ["a", "b"]);
    assert_eq!(read_lines("a\n\nb"), ["a", "", "b"]);
    assert_eq!(read_lines("a\0\nb"), ["a", "", "b"]);
}

#[test]
fn only_the_named_section_counts() {
    let (out, ok) = parse(
        "Storage=persistent\n[Other]\nStorage=persistent\n[Journal]\nStorage=volatile\n[X-Foo]\nStorage=auto\n",
    );
    assert!(ok);
    assert_eq!(out, vec![pair("Storage", "volatile")]);
}

#[test]
fn keys_and_sections_are_case_sensitive() {
    let (out, _) = parse("[journal]\nStorage=a\n[Journal]\nstorage=b\nStorage=c\n");
    assert_eq!(out, vec![pair("storage", "b"), pair("Storage", "c")]);
}

#[test]
fn comments_whitespace_and_quoting_follow_systemd() {
    let text = "\u{feff}[Journal]\n  # Storage=persistent\n\t; Storage=none\n  Storage = \"volatile\"  \nSystemMaxUse=1G # trailing\nno equals sign\n=novalue\n";
    let (out, ok) = parse(text);
    assert!(ok);
    assert_eq!(
        out,
        vec![
            pair("Storage", "\"volatile\""),
            pair("SystemMaxUse", "1G # trailing"),
        ]
    );
}

#[test]
fn continuation_lines_join_and_skip_comments() {
    let (out, _) = parse("[Journal]\nKey=a \\\n# comment\n  b\nEsc=x\\\\\nNext=y\nTail=z\\");
    assert_eq!(
        out,
        vec![
            pair("Key", "a    b"),
            pair("Esc", "x\\\\"),
            pair("Next", "y"),
            pair("Tail", "z"),
        ]
    );
}

#[test]
fn malformed_header_stops_the_file() {
    let (out, ok) = parse("[Journal]\nStorage=volatile\n[Journal\nStorage=persistent\n");
    assert!(!ok);
    assert_eq!(out, vec![pair("Storage", "volatile")]);
}

#[test]
fn missing_config_yields_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(config_files(&RealFilesystem, tmp.path(), "journald.conf").is_empty());
    assert!(!config_present(
        &RealFilesystem,
        tmp.path(),
        "journald.conf"
    ));
}

#[test]
fn main_file_is_the_first_found_only() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(
        root,
        "usr/lib/systemd/journald.conf",
        "[Journal]\nStorage=persistent\n",
    );
    assert_eq!(values(root, "Storage"), vec!["persistent"]);
    assert!(config_present(&RealFilesystem, root, "journald.conf"));

    write(
        root,
        "etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\n",
    );
    assert_eq!(values(root, "Storage"), vec!["volatile"]);
}

#[test]
fn drop_in_overrides_main_file() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(
        root,
        "etc/systemd/journald.conf",
        "[Journal]\nStorage=persistent\n",
    );
    write(
        root,
        "usr/lib/systemd/journald.conf.d/50-volatile.conf",
        "[Journal]\nStorage=volatile\n",
    );
    let all = section_assignments(&RealFilesystem, root, "journald.conf", "Journal");
    assert_eq!(last_value(&all, "Storage"), Some("volatile"));
}

#[test]
fn etc_drop_in_shadows_same_named_lower_ones() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(
        root,
        "usr/lib/systemd/journald.conf.d/50-x.conf",
        "[Journal]\nStorage=persistent\nCompress=no\n",
    );
    write(
        root,
        "run/systemd/journald.conf.d/50-x.conf",
        "[Journal]\nStorage=auto\n",
    );
    write(
        root,
        "etc/systemd/journald.conf.d/50-x.conf",
        "[Journal]\nStorage=volatile\n",
    );
    assert_eq!(values(root, "Storage"), vec!["volatile"]);
    assert!(
        values(root, "Compress").is_empty(),
        "the shadowed file is not read at all"
    );
}

#[test]
fn drop_ins_are_ordered_by_file_name_across_directories() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(
        root,
        "etc/systemd/journald.conf.d/10-a.conf",
        "[Journal]\nStorage=persistent\n",
    );
    write(
        root,
        "usr/lib/systemd/journald.conf.d/90-z.conf",
        "[Journal]\nStorage=volatile\n",
    );
    write(
        root,
        "run/systemd/journald.conf.d/50-m.conf",
        "[Journal]\nStorage=none\n",
    );
    // Hidden files, other suffixes and directories are not drop-ins.
    write(
        root,
        "etc/systemd/journald.conf.d/99-off.conf.disabled",
        "[Journal]\nStorage=auto\n",
    );
    write(
        root,
        "etc/systemd/journald.conf.d/.99-hidden.conf",
        "[Journal]\nStorage=auto\n",
    );
    fs::create_dir_all(root.join("etc/systemd/journald.conf.d/99-dir.conf")).unwrap();
    assert_eq!(
        values(root, "Storage"),
        vec!["persistent", "none", "volatile"]
    );
}

#[test]
fn last_assignment_wins_within_and_across_files() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(
        root,
        "etc/systemd/journald.conf",
        "[Journal]\nStorage=volatile\nStorage=persistent\n",
    );
    write(
        root,
        "etc/systemd/journald.conf.d/10-a.conf",
        "[Journal]\nStorage=none\nStorage=volatile\n",
    );
    let all = section_assignments(&RealFilesystem, root, "journald.conf", "Journal");
    assert_eq!(last_value(&all, "Storage"), Some("volatile"));
    assert_eq!(last_value(&all, "Missing"), None);
}

#[test]
fn malformed_header_skips_the_remaining_files() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(
        root,
        "etc/systemd/journald.conf.d/10-a.conf",
        "[Journal]\nStorage=volatile\n[Broken\n",
    );
    write(
        root,
        "etc/systemd/journald.conf.d/20-b.conf",
        "[Journal]\nStorage=persistent\n",
    );
    assert_eq!(values(root, "Storage"), vec!["volatile"]);
}

/// systemd skips a comment whatever its bytes, so a comment that is not
/// valid UTF-8 (a Latin-1 byte) does not hide the rest of the file. A
/// whole-file UTF-8 read rejects the file outright and would miss the
/// `Storage=persistent` below such a comment, reading a persistent decoy
/// journal as volatile.
#[test]
fn a_latin1_comment_does_not_hide_a_later_assignment() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // 0xFC is 'ü' in Latin-1 and never a valid UTF-8 byte.
    let mut bytes = b"[Journal]\n# Gr".to_vec();
    bytes.push(0xFC);
    bytes.extend_from_slice(b"n\nStorage=persistent\n");
    let path = root.join("etc/systemd/journald.conf");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, &bytes).unwrap();

    // The whole-file UTF-8 read rejects it with InvalidData...
    assert_eq!(
        RealFilesystem
            .read_file_content(&path)
            .unwrap_err()
            .io_kind(),
        Some(std::io::ErrorKind::InvalidData)
    );
    // ...but the config read keeps the valid lines, so the assignment below
    // the Latin-1 comment is seen.
    assert_eq!(
        last_value(
            &section_assignments(&RealFilesystem, root, "journald.conf", "Journal"),
            "Storage"
        ),
        Some("persistent")
    );
}

/// The decode puts one U+FFFF, which systemd refuses as it refuses the
/// bytes, in place of each sequence that is not UTF-8, and changes
/// nothing else: the line ends, comments and continuations stay as
/// systemd reads them.
#[test]
fn decode_config_bytes_marks_each_sequence_that_is_not_utf8() {
    assert_eq!(
        decode_config_bytes(b"[Journal]\r\nKey=a\xFF\xFEb\\\0# \xC3\n\xE2\x82x\xE2\x82\xAC"),
        "[Journal]\r\nKey=a\u{ffff}\u{ffff}b\\\0# \u{ffff}\n\u{ffff}x\u{20ac}"
    );
    // Valid UTF-8 comes through unchanged.
    let text = "\u{feff}[Journal]\nStorage=auto # Grün\r\n\n";
    assert_eq!(decode_config_bytes(text.as_bytes()), text);
}

/// systemd stops reading at a line that is not valid UTF-8, unless it is a
/// comment, as at a malformed section header: the assignments before it
/// count, the line and the rest of the file do not. NAILS used to drop
/// the line and read on, so a `Storage=volatile` journald never reads
/// counted.
#[test]
fn a_line_that_is_not_utf8_stops_the_reading() {
    let read = |bytes: &[u8]| {
        let mut out = Vec::new();
        let result = parse_section(&decode_config_bytes(bytes), "Journal", &mut out);
        let pairs: Vec<_> = out.into_iter().map(|a| (a.key, a.value)).collect();
        (pairs, result)
    };
    let stopped = Err(RefusedLine::NotUtf8);
    // A Latin-1 'ö' and 'ß' in a value: systemd has no trailing comments.
    assert_eq!(
        read(b"[Journal]\nStorage=persistent\nSystemMaxUse=200M # Gr\xF6\xDFe\nStorage=volatile\n"),
        (vec![pair("Storage", "persistent")], stopped)
    );
    // A lone invalid byte on a line of its own.
    assert_eq!(
        read(b"[Journal]\nStorage=persistent\n\xFF\nCompress=no\n"),
        (vec![pair("Storage", "persistent")], stopped)
    );
    // In another section too: systemd tests every line.
    assert_eq!(
        read(b"[Journal]\nStorage=persistent\n[Other]\nKey=\xFC\n[Journal]\nStorage=none\n"),
        (vec![pair("Storage", "persistent")], stopped)
    );
    // A continued line is not applied when a later part of it is bad,
    // nor when that part ends the file.
    assert_eq!(
        read(b"[Journal]\nStorage=persistent\nStorage=vol\\\natile\xFF\nStorage=none\n"),
        (vec![pair("Storage", "persistent")], stopped)
    );
    assert_eq!(
        read(b"[Journal]\nStorage=persistent\nStorage=none\xFF\\"),
        (vec![pair("Storage", "persistent")], stopped)
    );
    // A comment is skipped whatever its bytes, inside a continuation too.
    assert_eq!(
        read(b"[Journal]\n  # Gr\xFCn\n;\xFF\nStorage=vola\\\n# \xFC\ntile\n"),
        (vec![pair("Storage", "vola tile")], Ok(()))
    );
}

/// systemd's UTF-8 test refuses the noncharacters as well, which Rust's
/// UTF-8 allows, so a line holding one stops the reading even in a file
/// that is valid UTF-8; a comment holding one is still skipped.
#[test]
fn a_noncharacter_stops_the_reading() {
    for c in [
        '\u{fdd0}',
        '\u{fdef}',
        '\u{fffe}',
        '\u{ffff}',
        '\u{1fffe}',
        '\u{10ffff}',
    ] {
        let text = format!("[Journal]\nStorage=persistent\n#{c}\nKey=x{c}\nStorage=none\n");
        assert_eq!(
            parse(&text),
            (vec![pair("Storage", "persistent")], false),
            "{c:?}"
        );
    }
    // Their neighbours are plain characters.
    for c in ['\u{fdcf}', '\u{fdf0}', '\u{fffd}', '\u{1fffd}'] {
        let text = format!("[Journal]\nKey=x{c}\n");
        assert_eq!(
            parse(&text),
            (vec![pair("Key", &format!("x{c}"))], true),
            "{c:?}"
        );
    }
}

/// A line that is not UTF-8 skips every later file, as a malformed header
/// does: journald never reads a drop-in's `Storage=volatile` behind a
/// Latin-1 value in the main file.
#[test]
fn a_line_that_is_not_utf8_skips_the_remaining_files() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let main = root.join("etc/systemd/journald.conf");
    fs::create_dir_all(main.parent().unwrap()).unwrap();
    fs::write(
        &main,
        b"[Journal]\nStorage=persistent\nSystemMaxUse=200M # Gr\xF6\xDFe\nStorage=auto\n",
    )
    .unwrap();
    write(
        root,
        "etc/systemd/journald.conf.d/50-volatile.conf",
        "[Journal]\nStorage=volatile\n",
    );
    assert_eq!(values(root, "Storage"), vec!["persistent"]);
}

/// The UTF-8 byte fallback opens the decoy with `O_NOATIME`, exactly as the
/// normal whole-file read does, so a decoy `journald.conf` that only parses
/// through the fallback (it holds a non-UTF-8 byte) is still read without
/// stamping its access time. Drop the flag and the read leaves an atime
/// trail on the decoy — the trace this read path exists to avoid. Skips
/// unless the filesystem records a read's atime (`noatime` would prove
/// nothing); the test owns the file, so the kernel grants `O_NOATIME`
/// rather than refusing it.
#[test]
fn the_byte_fallback_reads_the_decoy_without_touching_its_atime() {
    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, SystemTime};

    let atime = |p: &Path| {
        let meta = fs::metadata(p).unwrap();
        (meta.atime(), meta.atime_nsec())
    };
    // Backdate the atime well behind the mtime so even a relatime mount
    // would update it on the next plain read.
    let backdate = |p: &Path| {
        let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        fs::File::open(p)
            .unwrap()
            .set_times(fs::FileTimes::new().set_accessed(old))
            .unwrap();
    };

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    // A control read proves this filesystem records atime at all.
    let probe = root.join("probe");
    fs::write(&probe, b"probe").unwrap();
    backdate(&probe);
    let probe_before = atime(&probe);
    let _ = fs::read(&probe).unwrap();
    if atime(&probe) == probe_before {
        eprintln!("skipping: the temp filesystem does not record atime updates");
        return;
    }

    // 0xFC is never a valid UTF-8 byte, so the whole-file read rejects the
    // file and read_config_text falls back to read_config_bytes_noatime.
    let path = root.join("etc/systemd/journald.conf");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut bytes = b"[Journal]\n# ".to_vec();
    bytes.push(0xFC);
    bytes.extend_from_slice(b"\nStorage=persistent\n");
    fs::write(&path, &bytes).unwrap();
    assert_eq!(
        RealFilesystem
            .read_file_content(&path)
            .unwrap_err()
            .io_kind(),
        Some(std::io::ErrorKind::InvalidData),
        "the decoy must reach the byte fallback"
    );

    backdate(&path);
    let before = atime(&path);
    let text = read_config_text(&RealFilesystem, &path).expect("the byte fallback reads the decoy");
    assert!(text.contains("Storage=persistent"), "{text}");
    assert_eq!(
        atime(&path),
        before,
        "the byte fallback must open the decoy with O_NOATIME"
    );
}

/// Only a file the filesystem read as invalid UTF-8 is read again, byte by
/// byte, from the disk. Any other failure is the filesystem's answer: a
/// configuration file that the in-memory test double does not hold reads
/// as missing even where the disk has a file at that path, so a check run
/// against the double never reads the host's own configuration.
#[test]
fn only_invalid_utf8_sends_the_read_to_the_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("journald.conf");
    fs::write(&path, "[Journal]\nStorage=persistent\n").unwrap();

    assert_eq!(read_config_text(&crate::MockFilesystem::new(), &path), None);
    assert_eq!(
        read_config_text(&RealFilesystem, &path).as_deref(),
        Some("[Journal]\nStorage=persistent\n")
    );
}
