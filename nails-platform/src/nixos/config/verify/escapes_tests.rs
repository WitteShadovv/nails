// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the string escapes of a line.

use super::super::scan::Scanner;
use super::*;

/// Each line of `text` with the escapes of its strings decoded, as the
/// scanner finds them.
fn decoded(text: &str) -> Vec<String> {
    let mut scanner = Scanner::default();
    text.split('\n')
        .map(|line| {
            scanner.line(line.as_bytes());
            let escapes = scanner.escapes();
            String::from_utf8_lossy(&Decoded::of(line.as_bytes(), &escapes).text).into_owned()
        })
        .collect()
}

/// Every escape form reads as `nix-instantiate --eval` of Nix 2.35 gives
/// it: in a `"…"` string a backslash before `n`, `r` or `t` is the control
/// character and before any other byte that byte; in a `''…''` string
/// `'''`, `''$` and `''\` escape and a lone backslash is itself.
#[test]
fn each_escape_reads_as_nix_evaluates_it() {
    for (text, read) in [
        ("x = \"a\\nb\";", "x = \"a\nb\";"),
        ("x = \"a\\rb\";", "x = \"a\rb\";"),
        ("x = \"a\\tb\";", "x = \"a\tb\";"),
        ("x = \"a\\\"b\";", "x = \"a\"b\";"),
        ("x = \"a\\\\b\";", "x = \"a\\b\";"),
        ("x = \"a\\${b}\";", "x = \"a${b}\";"),
        ("x = \"@v\\ault\";", "x = \"@vault\";"),
        ("x = \"2\\58\";", "x = \"258\";"),
        ("x = \"\\@vault\";", "x = \"@vault\";"),
        ("x = \"vg\\x2droot\";", "x = \"vgx2droot\";"),
        ("x = \"\\U\";", "x = \"u\";"),
        ("x = \"$${x}\";", "x = \"$${x}\";"),
        ("x = ''a'''b'';", "x = ''a''b'';"),
        ("x = ''a''${b}'';", "x = ''a${b}'';"),
        ("x = ''a''\\nb'';", "x = ''a\nb'';"),
        ("x = ''a''\\tb'';", "x = ''a\tb'';"),
        ("x = ''a''\\rb'';", "x = ''a\rb'';"),
        ("x = ''@v''\\ault'';", "x = ''@vault'';"),
        ("x = ''a\\b'';", "x = ''a\\b'';"),
        ("x = ''a\\nb'';", "x = ''a\\nb'';"),
        ("x = ''a''\\'b'';", "x = ''a'b'';"),
        ("x = ''$${x}'';", "x = ''$${x}'';"),
        // An attribute name in quotes is a string too, and a string in a
        // comment is read as in code.
        (
            "luks.devices.\"d\\ata\" = { };",
            "luks.devices.\"data\" = { };",
        ),
        ("# x = \"/mnt/d\\ata\";", "# x = \"/mnt/data\";"),
        // Outside a string a backslash is no escape.
        ("# mnt-my\\x2ddata.mount", "# mnt-my\\x2ddata.mount"),
    ] {
        assert_eq!(decoded(text), [read], "{text}");
    }
    // A backslash at the end of a line, in either kind of string, is the
    // newline after it, and the string goes on.
    assert_eq!(decoded("x = \"a\\\nb\";"), ["x = \"a\n", "b\";"]);
    assert_eq!(decoded("x = ''a''\\\nb'';"), ["x = ''a\n", "b'';"]);
}

/// A range of the decoded line maps back to the bytes of the line that
/// stand for it, and a range of the line to the decoded bytes.
#[test]
fn ranges_map_between_the_line_and_its_decoded_text() {
    let line = b"x = \"@v\\ault\" ''a'''b'';";
    let mut scanner = Scanner::default();
    scanner.line(line);
    let decoded = Decoded::of(line, &scanner.escapes());
    assert_eq!(decoded.text, b"x = \"@vault\" ''a''b'';");
    // `@vault` is 5..11 decoded and 5..12 in the line.
    assert_eq!(decoded.raw(&(5..11)), 5..12);
    assert_eq!(decoded.decoded(&(5..12)), 5..11);
    // The escaped `a` alone stands for both bytes of `\a`.
    assert_eq!(decoded.raw(&(7..8)), 7..9);
    assert_eq!(decoded.decoded(&(8..9)), 7..8);
    // `'''` gives two bytes, each standing for all three.
    assert_eq!(decoded.raw(&(16..17)), 17..20);
    assert_eq!(decoded.raw(&(16..18)), 17..20);
    // An empty range and the end of the line.
    assert_eq!(decoded.raw(&(22..22)), 24..24);
    assert_eq!(decoded.decoded(&(24..24)), 22..22);
}

/// fstab's octal escapes read as libmount decodes them: three octal digits
/// after a backslash give one byte, cut to eight bits, and any other
/// backslash stays with the bytes after it read on.
#[test]
fn fstab_escapes_read_as_libmount_decodes_them() {
    let read = |text: &[u8]| Decoded::of(text, &fstab(text)).text;
    assert_eq!(read(b"/mnt/d\\141ta"), b"/mnt/data");
    assert_eq!(read(b"a\\040b\\011c\\134d"), b"a b\tc\\d");
    assert_eq!(read(b"\\101"), b"a");
    assert_eq!(read(b"\\\\141"), b"\\a");
    assert_eq!(read(b"\\777"), [0xff]);
    assert_eq!(read(b"\\0141"), b"\x0c1");
    for kept in [&b"\\14"[..], b"\\18a", b"\\x61", b"a\\"] {
        assert_eq!(read(kept), kept, "{kept:?}");
    }
    let decoded = Decoded::of(b"d\\141ta", &fstab(b"d\\141ta"));
    assert_eq!(decoded.raw(&(1..2)), 1..5);
    assert_eq!(decoded.raw(&(0..4)), 0..7);
}
