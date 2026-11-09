// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the fstab lines systemd reads as entries. What systemd 255
//! (glibc) and 260 (libmount) make of each line here was checked with their
//! `systemd-fstab-generator`.

use super::*;
use crate::session::fstab::{FstabEntry, parse_fstab};
use std::path::Path;

/// The one reason `entry_lines` gives for `line`, refused as line 1.
fn why(line: &[u8]) -> Unlike {
    match entry_lines(line) {
        Err((1, why)) => why,
        other => panic!("{:?}: {other:?}", String::from_utf8_lossy(line)),
    }
}

#[test]
fn blank_lines_comments_and_lines_of_one_field_are_no_entries() {
    // glibc gives a line of one field no mount point, which systemd skips,
    // and libmount does not read one. A vertical tab is no separator for
    // either, so the line that NAILS would read as /dev/vdb1 mounted at
    // /mnt/data/x has one field too.
    let text = b"# a comment\n\n \t \n  # an indented one\n\r\n#\x0b/dev/vdb1 /srv/x\n/dev/vdb1\n\
                 /dev/vdb1\x0b/mnt/data/x\n/dev/vdb1 /srv/x ext4 defaults 0 2\n";
    assert_eq!(
        entry_lines(text),
        Ok(vec![b"/dev/vdb1 /srv/x ext4 defaults 0 2".as_slice()])
    );
}

#[test]
fn lines_systemd_reads_as_nails_does_are_entries() {
    let lines: [&[u8]; 14] = [
        // NixOS escapes a space and a tab, in the options too.
        b"/dev/disk/by-label/My\\040Data /mnt/My\\040Disk ext4 \
          x-systemd.requires-mounts-for=/a\\040b,nofail 0 2",
        b"/dev/vdb1\t/srv/tab\text4\tx-a=b\\011c,noauto\t0\t2",
        // A newline, a backslash, a space before a digit.
        b"/dev/vdb1 /srv/nl\\012x ext4 defaults 0 2",
        b"/dev/vdb1 /srv/a\\134b ext4 defaults 0 2",
        b"/dev/vdb1 /srv/d\\0400 ext4 defaults 0 2",
        // A backslash that starts no escape all of them keep, as udev writes
        // a space in a label's link, and in the options before a letter, a
        // short run of digits or nothing.
        b"/dev/disk/by-label/My\\x20Data /srv/raw\\b ext4 defaults 0 2",
        b"/dev/vdb1 /srv/end\\ ext4 username=DOM\\user,a\\0,noauto\\ 0 0",
        // A carriage return after the pass number, which libmount drops and
        // glibc's reading of the number skips; whitespace and bytes that are
        // no UTF-8 after the fields, which NAILS does not read.
        b"/dev/vdb1 /srv/crlf ext4 noauto 0 0\r",
        b"/dev/vdb1 /srv/vt ext4 defaults 0 2\x0b",
        b"/dev/vdb1 /srv/c ext4 defaults 0 2 # caf\xe9 \xc2\xa0",
        // Three fields, and two: libmount does not read the two, glibc reads
        // them as NAILS does.
        b"tmpfs /srv/t tmpfs",
        b"/dev/vdb1 /srv/two",
        // A line of the longest glibc reads whole.
        b"/dev/vdb1 /srv/long ext4 noauto,x-a=b",
        // A number that is a device, not the start of a mount table's line.
        b"10.0.0.1:/export /srv/nfs nfs4 defaults 0 0",
    ];
    let longest = [
        lines[12],
        b"b".repeat(LONGEST_LINE - lines[12].len()).as_slice(),
    ]
    .concat();
    let mut text: Vec<u8> = Vec::new();
    for line in lines
        .iter()
        .take(12)
        .chain(&[longest.as_slice()])
        .chain(&lines[13..])
    {
        text.extend_from_slice(line);
        text.push(b'\n');
    }
    let read = entry_lines(&text).unwrap();
    assert_eq!(read.len(), 14);
    assert_eq!(read[12].len(), LONGEST_LINE);
    // NAILS reads each as glibc does, one entry a line, and as libmount does
    // where libmount reads it at all: libmount skips the line of two fields
    // and the one whose pass number runs into a vertical tab.
    let entries: Vec<FstabEntry> = read
        .iter()
        .map(|line| {
            let mut entries = parse_fstab(&String::from_utf8_lossy(line));
            assert_eq!(entries.len(), 1, "{}", String::from_utf8_lossy(line));
            entries.remove(0)
        })
        .collect();
    assert_eq!(entries[0].spec, "/dev/disk/by-label/My Data");
    assert_eq!(entries[0].file, Path::new("/mnt/My Disk"));
    assert_eq!(entries[2].file, Path::new("/srv/nl\nx"));
    assert_eq!(entries[3].file, Path::new("/srv/a\\b"));
    assert_eq!(entries[4].file, Path::new("/srv/d 0"));
    assert_eq!(entries[5].spec, "/dev/disk/by-label/My\\x20Data");
    assert_eq!(entries[5].file, Path::new("/srv/raw\\b"));
    assert_eq!(entries[6].file, Path::new("/srv/end\\"));
    assert_eq!(
        entries[6].options,
        ["username=DOM\\user", "a\\0", "noauto\\"]
    );
    assert_eq!(entries[7].options, ["noauto"]);
    assert_eq!(entries[9].file, Path::new("/srv/c"));
    assert_eq!(entries[11].vfstype, "auto");
}

#[test]
fn whitespace_that_systemd_does_not_split_at_is_refused() {
    use Field::{Device, MountPoint, Options, Type};
    // A no-break space and a vertical tab in a mount point: NAILS would
    // decide /mnt/data/a, of type `b`, and the hidden systemd mounts
    // /mnt/data/a b.
    assert_eq!(
        why("/dev/vdb1 /mnt/data/a\u{a0}b ext4 defaults 0 2".as_bytes()),
        Unlike::Holds(MountPoint, '\u{a0}')
    );
    assert_eq!(
        why(b"/dev/vdb1 /srv/a\x0bb ext4 defaults 0 2"),
        Unlike::Holds(MountPoint, '\x0b')
    );
    // Before a `#`: a comment to NAILS, a tmpfs to systemd.
    assert_eq!(
        why(b"\x0b#x /mnt/data/vt tmpfs defaults 0 0"),
        Unlike::Holds(Device, '\x0b')
    );
    assert_eq!(
        why("\u{a0}# /dev/vdb1 /srv/x ext4 defaults 0 0".as_bytes()),
        Unlike::Holds(Device, '\u{a0}')
    );
    // A carriage return that ends the type or the options, which glibc
    // keeps there: `noauto\r` is no `noauto` to systemd 258.
    assert_eq!(
        why(b"/dev/vdb1 /srv/x ext4 noauto\r"),
        Unlike::Holds(Options, '\r')
    );
    assert_eq!(why(b"tmpfs /srv/x tmpfs\r"), Unlike::Holds(Type, '\r'));
    assert_eq!(why(b"/dev/vdb1 /srv/x\r"), Unlike::Holds(MountPoint, '\r'));
    // A NUL, where glibc ends the line.
    assert_eq!(
        why(b"/dev/vdb1 /srv/a\0b ext4 defaults,noauto 0 0"),
        Unlike::Holds(MountPoint, '\0')
    );
    assert_eq!(
        why(b"/dev/vdb1 /srv/x ext4 defaults\0,noauto 0 0"),
        Unlike::Holds(Options, '\0')
    );
}

#[test]
fn escapes_that_glibc_and_libmount_read_differently_are_refused() {
    use Field::{Device, MountPoint, Options, Type};
    let escape = |field, escape: &str| Unlike::Escape(field, escape.to_string());
    for (line, unlike) in [
        // An escape glibc leaves as it is and libmount undoes.
        (
            b"/dev/vdb1 /mnt/data/caf\\303\\251 ext4 defaults 0 2".as_slice(),
            escape(MountPoint, "\\303"),
        ),
        (
            b"/dev/vdb1 /mnt/dat\\141/x ext4 defaults 0 2",
            escape(MountPoint, "\\141"),
        ),
        (
            b"/dev/disk/by-label/caf\\351 /srv/x ext4 defaults 0 2",
            escape(Device, "\\351"),
        ),
        // One above a byte, which libmount wraps round to a NUL.
        (
            b"/dev/vdb1 /mnt/data/x\\400 ext4 defaults 0 2",
            escape(MountPoint, "\\400"),
        ),
        // A doubled backslash, which glibc undoes and libmount does not.
        (
            b"/dev/vdb1 /srv/a\\\\b ext4 defaults 0 2",
            escape(MountPoint, "\\\\"),
        ),
        // In the options: a comma libmount undoes, a NUL that ends them for
        // it, and a backslash before a comma, at which systemd does not split
        // the options, written or undone.
        (
            b"/dev/vdb1 /srv/x ext4 noauto,x\\054x-systemd.wanted-by=multi-user.target 0 0",
            escape(Options, "\\054"),
        ),
        (
            b"/dev/vdb1 /srv/x ext4 defaults\\000,noauto 0 0",
            escape(Options, "\\000"),
        ),
        (
            b"/dev/vdb1 /srv/x ext4 defaults\\,noauto 0 0",
            escape(Options, "\\,"),
        ),
        (
            b"/dev/vdb1 /srv/x ext4 defaults\\134,noauto 0 0",
            escape(Options, "\\134"),
        ),
        (
            b"/dev/vdb1 /srv/x ext4 x-systemd.automoun\\164 0 0",
            escape(Options, "\\164"),
        ),
        // Any backslash in the type.
        (
            b"/dev/vdb1 /srv/x tmpf\\163 defaults 0 0",
            escape(Type, "\\163"),
        ),
        (b"/dev/vdb1 /srv/x ext\\4 defaults 0 0", escape(Type, "\\4")),
    ] {
        assert_eq!(why(line), unlike, "{}", String::from_utf8_lossy(line));
    }
}

#[test]
fn fields_that_are_not_text_are_refused() {
    use Field::{Device, MountPoint, Options, Type};
    for (line, field) in [
        (b"/dev/vdb\xe9 /srv/x ext4 defaults 0 2".as_slice(), Device),
        (b"/dev/vdb1 /mnt/data/caf\xe9 ext4 defaults 0 2", MountPoint),
        (b"/dev/vdb1 /srv/x ext\xe9 defaults 0 2", Type),
        (b"/dev/vdb1 /srv/x ext4 defaults,caf\xe9 0 2", Options),
    ] {
        assert_eq!(why(line), Unlike::NotText(field));
    }
}

#[test]
fn a_line_longer_than_glibc_reads_is_refused() {
    // glibc would read the options without their last `noauto`.
    let line = [
        b"/dev/vdb1 /srv/long ext4 x-a=".as_slice(),
        &b"b".repeat(LONGEST_LINE),
        b",noauto 0 0",
    ]
    .concat();
    assert_eq!(why(&line), Unlike::TooLong);
    // A comment of any length is none.
    let comment = [b"# ".as_slice(), &b"c".repeat(LONGEST_LINE)].concat();
    assert_eq!(entry_lines(&comment), Ok(vec![]));
}

#[test]
fn a_line_that_begins_as_another_table_does_is_refused() {
    // As the first line, libmount would read the file as /proc/swaps, and the
    // next line as a swap on /dev/vdb1, or as a mount table, and the line as
    // a mount of /dev/vdb2 at /srv/x.
    for line in [
        b"Filename\t/srv/x ext4".as_slice(),
        b"  Filename\tType\tSize\tUsed\tPriority",
        b"1 2 3:4 / /srv/x rw - ext4 /dev/vdb2 rw",
        b"\t1\x0b2 /srv/x",
        b"+1 -2",
        b"1-2 /srv/x ext4 defaults 0 0",
    ] {
        assert_eq!(
            why(line),
            Unlike::OtherTable,
            "{}",
            String::from_utf8_lossy(line)
        );
    }
    // Not so: one number, a number that is part of a word, a comment.
    let text = b"12 /srv/x ext4\n1x 2 /srv/y\n# 1 2\n10.0.0.1:/x /srv/z nfs4\n";
    assert_eq!(entry_lines(text).map(|lines| lines.len()), Ok(3));
}

#[test]
fn the_first_line_systemd_may_read_otherwise_is_named_by_its_number() {
    let text = b"# fstab\n/dev/vdb1 /srv/x ext4 defaults 0 2\n/dev/vdb2 /srv/a\\\\b ext4 \
                 defaults 0 2\n/dev/vdb3 /srv/y\r\n";
    assert_eq!(
        entry_lines(text),
        Err((3, Unlike::Escape(Field::MountPoint, "\\\\".to_string())))
    );
}

#[test]
fn each_reason_says_what_systemd_reads_otherwise() {
    use Field::{Device, MountPoint, Options, Type};
    for (unlike, text) in [
        (
            Unlike::OtherTable,
            "begins as a line of a mount table or of the list of swaps does, and systemd from \
             259 on reads a file that begins with such a line as that table",
        ),
        (
            Unlike::TooLong,
            "is longer than the 4095 bytes of a line that systemd up to 258 reads",
        ),
        (Unlike::NotText(Type), "has a type that is not UTF-8 text"),
        (
            Unlike::Holds(MountPoint, '\u{a0}'),
            "has U+00A0 in its mount point, which NAILS takes for a separator and systemd does \
             not",
        ),
        (
            Unlike::Holds(Device, '\0'),
            "has a NUL in its device, where systemd up to 258 ends the line",
        ),
        (
            Unlike::Escape(Options, "\\054".to_string()),
            "has `\\054` in its options, which systemd may read otherwise than NAILS",
        ),
    ] {
        assert_eq!(unlike.to_string(), text);
    }
}
