// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

/// unattended-upgrades' own configuration file, as each release installs it
/// in `/etc/apt/apt.conf.d` (the package's data/50unattended-upgrades.Debian
/// of 2.12, .Ubuntu of 2.9.1+nmu4ubuntu1 and of 2.12ubuntu9), unchanged.
const DEBIAN_13: &[u8] = include_bytes!("fixtures/apt/debian-13-50unattended-upgrades");
const UBUNTU_24_04: &[u8] = include_bytes!("fixtures/apt/ubuntu-24.04-50unattended-upgrades");
const UBUNTU_26_04: &[u8] = include_bytes!("fixtures/apt/ubuntu-26.04-50unattended-upgrades");
/// What the package's debconf question writes when the answer is yes.
const AUTO_UPGRADES: &[u8] = include_bytes!("fixtures/apt/20auto-upgrades");
/// apt's own `01autoremove` (debian/apt.conf.autoremove of apt 2.7.14 to
/// 3.2.1), nested blocks and `#` comments.
const AUTOREMOVE: &[u8] = include_bytes!("fixtures/apt/01autoremove");

/// The setting unattended-upgrades' shutdown helper reads.
const KEY: &[&str] = &["Unattended-Upgrade", "InstallOnShutdown"];

fn statements(text: &str) -> Vec<Statement> {
    parse(text.as_bytes()).unwrap().statements
}

fn set(item: &str, value: &str, line: usize) -> Statement {
    Statement::Set {
        item: item.as_bytes().to_vec(),
        value: value.as_bytes().to_vec(),
        line,
    }
}

fn refused(text: &str) -> SyntaxError {
    parse(text.as_bytes()).unwrap_err()
}

/// The values the file gives the key, in order.
fn key_values(text: &[u8]) -> Vec<Vec<u8>> {
    parse(text)
        .unwrap()
        .statements
        .into_iter()
        .filter_map(|statement| match statement {
            Statement::Set { item, value, .. } if names(&item, KEY, false) => Some(value),
            _ => None,
        })
        .collect()
}

#[test]
fn the_stock_files_parse_and_leave_the_setting_alone() {
    for (name, text) in [
        ("debian-13", DEBIAN_13),
        ("ubuntu-24.04", UBUNTU_24_04),
        ("ubuntu-26.04", UBUNTU_26_04),
    ] {
        let parsed = parse(text).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(parsed.open_blocks, 0, "{name}");
        assert!(!parsed.in_comment, "{name}");
        assert!(!parsed.statements.is_empty(), "{name}");
        // The line is there, commented out.
        assert!(
            String::from_utf8_lossy(text).contains("//Unattended-Upgrade::InstallOnShutdown"),
            "{name}"
        );
        assert!(key_values(text).is_empty(), "{name}");
    }
}

#[test]
fn the_debian_file_lists_its_origins_in_its_block() {
    let parsed = parse(DEBIAN_13).unwrap();
    assert!(parsed.statements.contains(&set(
        "Unattended-Upgrade::Origins-Pattern::",
        "origin=Debian,codename=${distro_codename},label=Debian-Security",
        32
    )));
}

#[test]
fn auto_upgrades_turns_the_daily_run_on() {
    assert_eq!(
        statements(std::str::from_utf8(AUTO_UPGRADES).unwrap()),
        [
            set("APT::Periodic::Update-Package-Lists", "1", 1),
            set("APT::Periodic::Unattended-Upgrade", "1", 2),
        ]
    );
}

#[test]
fn autoremove_reads_its_nested_lists_past_its_hash_comments() {
    let parsed = parse(AUTOREMOVE).unwrap();
    assert_eq!(parsed.open_blocks, 0);
    let kernels: Vec<_> = parsed
        .statements
        .iter()
        .filter_map(|statement| match statement {
            Statement::Set { item, value, .. } if item == b"APT::VersionedKernelPackages::" => {
                Some(String::from_utf8_lossy(value).into_owned())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        kernels,
        [
            "linux-.*",
            "kfreebsd-.*",
            "gnumach-.*",
            ".*-modules",
            ".*-kernel"
        ]
    );
}

#[test]
fn the_setting_reads_in_each_form_apt_takes() {
    for text in [
        "Unattended-Upgrade::InstallOnShutdown \"true\";",
        "Unattended-Upgrade::InstallOnShutdown true;",
        "Unattended-Upgrade { InstallOnShutdown \"true\"; };",
        "Unattended-Upgrade {\n  InstallOnShutdown \"true\";\n};",
        "unattended-upgrade::installonshutdown \"true\";",
        "\"Unattended-Upgrade::InstallOnShutdown\" \"true\";",
        "Unattended-Upgrade::\"InstallOnShutdown\" \"true\";",
        "Unattended-Upgrade::InstallOnShutdow%6e \"true\";",
        "\tUnattended-Upgrade::InstallOnShutdown\t\"true\";",
        "Unattended-Upgrade::InstallOnShutdown\n\"true\";",
        "Unattended-Upgrade::InstallOnShutdown \"true\";\r\n",
        "Unattended-Upgrade::InstallOnShutdown \"tr\"\"ue\";",
        "Unattended-Upgrade::InstallOnShutdown \"true\" { };",
        "/* off */ Unattended-Upgrade::InstallOnShutdown \"true\"; /* still",
        // A statement over several lines: its `;` alone on the next one, and
        // its value on a line of its own between empty ones.
        "Unattended-Upgrade::InstallOnShutdown \"true\"\n;",
        "Unattended-Upgrade::InstallOnShutdown\n\n\"true\"\n\n;",
        // A block that closes with no `;` before it.
        "Foo {\n}\nUnattended-Upgrade::InstallOnShutdown \"true\";",
        // A statement that starts after another's `;` and ends on the next
        // line, the white space before it stripped.
        "Foo \"x\";   Unattended-Upgrade::InstallOnShutdown\n\"true\";",
        // A `/*` inside a quoted string opens no comment, the one after it
        // does; an empty comment closes where it opens.
        "Foo \"/*\" /* c */; Unattended-Upgrade::InstallOnShutdown \"true\";",
        "Foo \"x\"; /**/ Unattended-Upgrade::InstallOnShutdown \"true\";",
    ] {
        assert_eq!(key_values(text.as_bytes()), [b"true".to_vec()], "{text:?}");
    }
}

#[test]
fn comments_hide_the_setting() {
    for text in [
        "// Unattended-Upgrade::InstallOnShutdown \"true\";",
        "# Unattended-Upgrade::InstallOnShutdown \"true\";",
        "/* Unattended-Upgrade::InstallOnShutdown \"true\"; */",
        "/*\nUnattended-Upgrade::InstallOnShutdown \"true\";\n*/",
        "Foo \"x\"; // Unattended-Upgrade::InstallOnShutdown \"true\";",
        "Foo \"x\"; # Unattended-Upgrade::InstallOnShutdown \"true\";",
        // A `#` after a quoted one starts a comment all the same.
        "Foo \"a # b\"; # Unattended-Upgrade::InstallOnShutdown \"true\";",
        // `/*/` opens a comment and does not close it.
        "/*/ Unattended-Upgrade::InstallOnShutdown \"true\"; */",
    ] {
        assert!(key_values(text.as_bytes()).is_empty(), "{text:?}");
    }
}

#[test]
fn comment_marks_inside_a_quoted_string_are_text() {
    assert_eq!(
        statements("Acquire::http::Proxy \"http://proxy:3128\"; // a comment"),
        [set("Acquire::http::Proxy", "http://proxy:3128", 1)]
    );
    assert_eq!(
        statements("Foo \"a # b /* c */\";"),
        [set("Foo", "a # b /* c */", 1)]
    );
}

#[test]
fn a_comment_that_opens_on_a_line_closes_on_a_later_one() {
    let parsed = parse(b"/* one\ntwo\nthree */ Foo \"x\";\nBar \"y\";").unwrap();
    assert_eq!(parsed.statements, [set("Foo", "x", 3), set("Bar", "y", 4)]);
    assert!(!parsed.in_comment);
    let open = parse(b"Foo \"x\";\n/* never closed").unwrap();
    assert!(open.in_comment);
}

#[test]
fn values_of_several_quoted_strings_join_with_one_space() {
    assert_eq!(statements("Foo \"a\"  \"b\";"), [set("Foo", "a b", 1)]);
    // White space after the last string counts too: a vertical tab that a
    // comment kept from the end of its line.
    assert_eq!(statements("Foo \"a\"\x0b// c\n;"), [set("Foo", "a ", 2)]);
}

#[test]
fn a_word_keeps_its_brackets_and_decodes_its_escapes_as_apt_does() {
    // A `[...]` holds white space; a `%` and two hex digits are one byte,
    // anything shorter stays as it is.
    assert_eq!(statements("Foo[a b] \"x\";"), [set("Foo[a b]", "x", 1)]);
    assert_eq!(statements("Foo %41%4;"), [set("Foo", "A%4", 1)]);
    assert_eq!(statements("Foo bar%4;"), [set("Foo", "bar%4", 1)]);
}

#[test]
fn directives_are_read_at_the_top_level() {
    assert_eq!(
        statements("#clear Unattended-Upgrade;\n#include \"/etc/x\";"),
        [
            Statement::Clear {
                name: b"Unattended-Upgrade".to_vec(),
                line: 1
            },
            Statement::Include { line: 2 },
        ]
    );
    assert_eq!(
        statements("#x-apt-configure-index \"/usr/share/doc/apt/examples/configure-index\";"),
        [Statement::ConfigureIndex { line: 1 }]
    );
}

#[test]
fn a_block_left_open_is_no_error_to_apt() {
    let parsed = parse(b"Unattended-Upgrade {\n InstallOnShutdown \"true\";").unwrap();
    assert_eq!(parsed.open_blocks, 1);
    assert_eq!(
        parsed.statements,
        [set("Unattended-Upgrade::InstallOnShutdown", "true", 2)]
    );
}

#[test]
fn what_apt_refuses_is_refused_on_its_line() {
    for (text, line, reason) in [
        ("Foo \"x\"", 1, "Extra junk at end of file"),
        ("Foo \"x\";\nBar \"y\"\n", 3, "Extra junk at end of file"),
        ("{ Foo \"x\"; };", 1, "Block starts with no name."),
        ("Foo \"x\" y;", 1, "Extra junk after value"),
        ("Foo bar baz;", 1, "Extra junk after value"),
        (
            "Foo { #clear Bar; };",
            1,
            "Directives can only be done at the top level",
        ),
        // A `#` that starts no directive starts a comment, unless it is
        // quoted.
        ("\"#bogus\" Foo;", 1, "Unsupported directive"),
        ("#clearly Foo;", 1, "Unsupported directive"),
        (
            "#clear;",
            1,
            "clear directive requires an option tree as argument",
        ),
        ("Foo[x \"y\";", 1, "Malformed tag"),
        // A quote left open at the line's end.
        ("Foo \"abc\n;", 2, "Extra junk after value"),
    ] {
        assert_eq!(
            refused(text),
            SyntaxError {
                line,
                reason,
                by_apt: true
            },
            "{text:?}"
        );
    }
}

#[test]
fn a_line_nails_does_not_read_is_refused_but_not_as_apts_refusal() {
    // apt reads a line in pieces and can join the next line to it, so a
    // line past MAX_LINE bytes is not read; one of MAX_LINE bytes is.
    let long = format!("// {}\nFoo \"x\";", "x".repeat(MAX_LINE - 2));
    let error = refused(&long);
    assert_eq!((error.line, error.by_apt), (1, false), "{error:?}");
    assert!(error.reason.contains(&MAX_LINE.to_string()), "{error:?}");
    let longest = format!(
        "// {}\nUnattended-Upgrade::InstallOnShutdown \"true\";",
        "x".repeat(MAX_LINE - 3)
    );
    assert_eq!(key_values(longest.as_bytes()), [b"true".to_vec()]);
    // apt stops reading a line at a NUL byte.
    let error = refused("Foo \"x\";\nBar \"y\0\";");
    assert_eq!(
        error,
        SyntaxError {
            line: 2,
            reason: "a NUL byte",
            by_apt: false
        }
    );
}

#[test]
fn tags_split_as_apt_looks_them_up() {
    let split = |name: &str| {
        tags(name.as_bytes()).map(|tags| {
            tags.iter()
                .map(|tag| String::from_utf8_lossy(tag).into_owned())
                .collect::<Vec<_>>()
        })
    };
    assert_eq!(
        split("Unattended-Upgrade::InstallOnShutdown").unwrap(),
        ["Unattended-Upgrade", "InstallOnShutdown"]
    );
    assert_eq!(split("Dir").unwrap(), ["Dir"]);
    // A `::` right after another belongs to the next tag.
    assert_eq!(split("a::::b").unwrap(), ["a", "::b"]);
    assert_eq!(split("a:::b").unwrap(), ["a", ":b"]);
    // An empty tag is a list item, which no lookup finds.
    assert_eq!(split("APT::NeverAutoRemove::"), None);
    assert_eq!(split("::a"), None);
    assert_eq!(split(""), None);
    // apt reads the name up to its first NUL.
    assert_eq!(
        tags(b"Unattended-Upgrade::InstallOnShutdown\0junk")
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn names_ignore_ascii_case_and_cover_the_items_below() {
    assert!(names(b"unattended-upgrade::INSTALLONSHUTDOWN", KEY, false));
    assert!(!names(b"Unattended-Upgrade", KEY, false));
    assert!(names(b"Unattended-Upgrade", KEY, true));
    assert!(names(b"unattended-UPGRADE::installonshutdown", KEY, true));
    assert!(!names(
        b"Unattended-Upgrade::InstallOnShutdown::x",
        KEY,
        true
    ));
    assert!(!names(
        b"Unattended-Upgrades::InstallOnShutdown",
        KEY,
        false
    ));
    assert!(!names(b"Unattended-Upgrade::", KEY, true));
}

#[test]
fn parts_are_read_by_the_names_apt_reads() {
    for name in [
        "50unattended-upgrades",
        "20auto-upgrades",
        "01autoremove",
        "99local.conf",
        "a.b.conf",
        "a:b",
        "A_b-C",
        "conf",
    ] {
        assert_eq!(part_name(name.as_bytes()), PartName::Read, "{name}");
    }
    for name in [
        ".hidden",
        "50unattended-upgrades.dpkg-old",
        "50unattended-upgrades.dpkg-dist",
        "50unattended-upgrades.ucf-dist",
        "x.bak",
        "x.disabled",
        "x.save",
        "x~",
        "x.",
        "x.conf.",
        "x y",
        "x.CONF",
        "x.cfg",
        "",
        // A byte beyond ASCII changes nothing where another rule skips the
        // name.
        ".caf\u{e9}",
        "caf\u{e9}.bak",
        "x.c\u{f6}nf",
        "caf\u{e9}.",
        "caf\u{e9}~",
    ] {
        assert_eq!(part_name(name.as_bytes()), PartName::Skipped, "{name:?}");
    }
}

#[test]
fn a_part_name_beyond_ascii_is_left_to_the_locale() {
    // apt's isalpha() takes 0xe9 for a letter in ISO-8859-1 and so reads
    // `99caf\xe9`, which it skips in the C locale and in a UTF-8 one; the two
    // bytes of UTF-8's `ü` are letters in ISO-8859-2 (`Ă` and `ź`).
    for name in [
        b"99caf\xe9".as_slice(),
        "99\u{fc}ber".as_bytes(),
        b"\xff.conf",
        b"a\x80b",
    ] {
        assert_eq!(part_name(name), PartName::ByLocale, "{name:?}");
    }
}

#[test]
fn a_value_beyond_ascii_is_left_to_the_locale() {
    // strcasecmp() lowercases 0xdd to `i` in tr_TR.ISO-8859-9, where
    // `W\xddTH` is apt's `with`; the reader knows no word with such a byte.
    for value in [b"W\xddTH".as_slice(), b"\xe9", b"tru\xe9", b"1\xe9"] {
        assert!(value_by_locale(value), "{value:?}");
        assert!(string_to_bool(value, true), "{value:?}");
        assert!(!string_to_bool(value, false), "{value:?}");
    }
    // ASCII, or a byte beyond it only after the NUL at which apt stops
    // comparing.
    for value in [
        b"true".as_slice(),
        b"WITH",
        b"",
        b"0x1",
        b"true\0\xe9",
        b"\0\xdd",
    ] {
        assert!(!value_by_locale(value), "{value:?}");
    }
}

#[test]
fn booleans_read_as_apt_reads_them() {
    for (value, read) in [
        ("1", true),
        ("0", false),
        ("true", true),
        ("TRUE", true),
        ("yes", true),
        ("on", true),
        ("enable", true),
        ("with", true),
        ("false", false),
        ("No", false),
        ("off", false),
        ("disable", false),
        ("without", false),
        // strtol() in base 0, kept in an int.
        ("0x1", true),
        ("0X1", true),
        ("01", true),
        ("00", false),
        ("+1", true),
        ("-0", false),
        (" 1", true),
        ("4294967297", true),
        ("4294967296", false),
        // A long that strtol() takes as LONG_MIN is 0 in an int.
        ("-99999999999999999999", false),
        // 4294967297 in octal.
        ("040000000001", true),
        (" 0x1", true),
        // A word compares up to the first NUL.
        ("true\0x", true),
        ("OFF\0x", false),
    ] {
        assert_eq!(string_to_bool(value.as_bytes(), !read), read, "{value:?}");
    }
    // What apt does not know is the default.
    for value in [
        "",
        "2",
        "-1",
        "1 ",
        "  ",
        "0x",
        "08",
        "ture",
        "99999999999999999999",
        "y",
        // strtol() stops at a NUL, so it never reads such a value whole,
        // and no word is empty or a number.
        "1\0x",
        "0\0",
        "\0x",
        "\0",
    ] {
        assert!(string_to_bool(value.as_bytes(), true), "{value:?}");
        assert!(!string_to_bool(value.as_bytes(), false), "{value:?}");
    }
}
