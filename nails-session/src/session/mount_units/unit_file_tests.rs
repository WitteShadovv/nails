// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for reading a unit file.

use super::*;

fn assignments(text: &[u8]) -> Vec<(String, String, String)> {
    parse(text).expect("a unit file systemd loads").assignments
}

fn triple(section: &str, key: &str, value: &str) -> (String, String, String) {
    (section.to_string(), key.to_string(), value.to_string())
}

#[test]
fn a_mount_unit_reads_as_its_assignments_in_order() {
    let unit = parse(
        b"# A NixOS systemd.mounts unit\n\
          [Unit]\n\
          Description=Scratch space\n\
          Before=local-fs.target\n\
          \n\
          [Mount]\n\
          What = /dev/disk/by-id/virtio-scratch \n\
          Where=/srv/scratch\n\
          Type=ext4\n\
          Options=noatime,x-systemd.after=a.service\n\
          [Install]\n\
          WantedBy=local-fs.target\n",
    )
    .unwrap();
    assert_eq!(
        unit.last("Mount", "What"),
        Some("/dev/disk/by-id/virtio-scratch")
    );
    assert_eq!(unit.last("Mount", "Type"), Some("ext4"));
    assert_eq!(
        unit.last("Mount", "Options"),
        Some("noatime,x-systemd.after=a.service")
    );
    assert_eq!(unit.last("Unit", "What"), None);
    assert_eq!(unit.assignments.len(), 7);
}

#[test]
fn the_last_assignment_counts_and_an_empty_one_resets() {
    let unit = parse(b"[Mount]\nType=ext4\nType=tmpfs\n[Swap]\nOptions=a\nOptions=\n").unwrap();
    assert_eq!(unit.last("Mount", "Type"), Some("tmpfs"));
    assert_eq!(unit.last("Swap", "Options"), None);
    let words: Vec<&str> = unit.values("Mount", "Type").collect();
    assert_eq!(words, ["ext4", "tmpfs"]);
}

#[test]
fn comments_continuations_and_line_ends_are_read_as_systemd_reads_them() {
    // A comment inside a continuation is skipped, and the continuation goes
    // on; the backslash becomes a space.
    assert_eq!(
        assignments(b"[Unit]\nRequires=a.service \\\n# not here\n  b.service\n"),
        [triple("Unit", "Requires", "a.service    b.service")]
    );
    // An escaped backslash ends no line.
    assert_eq!(
        assignments(b"[Mount]\nWhat=/x\\\\\nType=ext4\n"),
        [
            triple("Mount", "What", "/x\\\\"),
            triple("Mount", "Type", "ext4")
        ]
    );
    // CR LF ends one line, LF LF two, a NUL one at once; a continuation left
    // at the end of the file is read.
    assert_eq!(
        assignments(b"[Mount]\r\nType=ext4\n\n\0What=/dev/vdb\x00Options=ro\\"),
        [
            triple("Mount", "Type", "ext4"),
            triple("Mount", "What", "/dev/vdb"),
            triple("Mount", "Options", "ro"),
        ]
    );
    // `;` comments too, and a comment's bytes need not be UTF-8.
    assert_eq!(
        assignments(b"; \xff\xfe Latin-1\n  # \xe9t\xe9\n[Mount]\nType=vfat\n"),
        [triple("Mount", "Type", "vfat")]
    );
    // One byte order mark goes, from the first line that starts with one.
    assert_eq!(
        assignments(b"\xef\xbb\xbf[Mount]\n\xef\xbb\xbfType=ext4\n"),
        [triple("Mount", "\u{feff}Type", "ext4")]
    );
    // Outside a section, without `=`, and with nothing before it: skipped.
    assert_eq!(
        assignments(b"What=/dev/sda\n[Mount]\nnonsense\n=x\nType=ext4\n[X-Own]\nType=nfs\n"),
        [
            triple("Mount", "Type", "ext4"),
            triple("X-Own", "Type", "nfs")
        ]
    );
}

#[test]
fn a_unit_file_systemd_refuses_is_refused() {
    for (text, why) in [
        (&b"[Mount\nWhat=/dev/sda\n"[..], Refused::MalformedHeader),
        (b"[Mo\"unt]\n", Refused::MalformedHeader),
        (b"[Mo\\unt]\n", Refused::MalformedHeader),
        (b"[Mo\x01unt]\n", Refused::MalformedHeader),
        (b"[]\n", Refused::MalformedHeader),
        (b"[Mo*unt]\n", Refused::MalformedHeader),
        (b"[Mount]\nWhat=/dev/\xff\n", Refused::NotUtf8),
        (b"[Mount]\nWhat=/dev/\xef\xbf\xbf\n", Refused::NotUtf8),
        (b"[Mount]\nWhat=\\\n\xfe\n", Refused::NotUtf8),
    ] {
        assert_eq!(parse(text), Err(why), "{:?}", String::from_utf8_lossy(text));
    }
    let long = [b"[Mount]\nWhat=".as_slice(), &vec![b'a'; LONG_LINE_MAX]].concat();
    assert_eq!(parse(&long), Err(Refused::TooLong));
    let continued = [
        b"[Mount]\nWhat=".as_slice(),
        &vec![b'a'; LONG_LINE_MAX / 2],
        b"\\\n",
        &vec![b'b'; LONG_LINE_MAX / 2],
    ]
    .concat();
    assert_eq!(parse(&continued), Err(Refused::TooLong));
}

#[test]
fn only_the_escape_of_a_percent_sign_is_resolved() {
    assert_eq!(
        without_specifiers("/dev/sdb1").as_deref(),
        Some("/dev/sdb1")
    );
    assert_eq!(without_specifiers("50%%").as_deref(), Some("50%"));
    assert_eq!(without_specifiers("/srv/%H"), None);
    assert_eq!(without_specifiers("%"), None);
}
