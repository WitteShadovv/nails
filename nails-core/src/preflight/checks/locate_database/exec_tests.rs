// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

fn command(program: &str, args: &[&str]) -> ExecCommand {
    ExecCommand {
        program: program.as_bytes().to_vec(),
        args: args.iter().map(|arg| arg.as_bytes().to_vec()).collect(),
    }
}

fn one(value: &str) -> ExecCommand {
    let mut commands = exec_commands(value).unwrap_or_else(|e| panic!("{value}: {e}"));
    assert_eq!(commands.len(), 1, "{value}: {commands:?}");
    commands.remove(0)
}

fn refused(value: &str) -> String {
    match exec_commands(value) {
        Err(ExecError::Refused(why)) => why,
        other => panic!("{value}: {other:?}"),
    }
}

fn unknown(value: &str) -> String {
    match exec_commands(value) {
        Err(ExecError::Unknown(why)) => why,
        other => panic!("{value}: {other:?}"),
    }
}

#[test]
fn a_plain_command_splits_at_blanks() {
    assert_eq!(
        one("/usr/sbin/updatedb.plocate"),
        command("/usr/sbin/updatedb.plocate", &[])
    );
    assert_eq!(
        one("/usr/bin/updatedb  -e\t/mnt   --prunefs=ext4"),
        command("/usr/bin/updatedb", &["-e", "/mnt", "--prunefs=ext4"])
    );
    assert_eq!(exec_commands("   ").unwrap(), []);
}

#[test]
fn nixos_quotes_every_argument_and_doubles_percent_and_dollar() {
    // escapeSystemdExecArgs: each argument JSON-quoted, % as %%, $ as $$.
    let value = "\"/nix/store/aaaa-plocate-1.1.25/bin/updatedb\" \"--output\" \
                 \"/var/cache/locatedb\" \"--prunepaths\" \"/tmp /mnt/100%% /a$$b\" \
                 \"--prunenames\" \"\\\"q\\\" \\\\b\"";
    assert_eq!(
        one(value),
        command(
            "/nix/store/aaaa-plocate-1.1.25/bin/updatedb",
            &[
                "--output",
                "/var/cache/locatedb",
                "--prunepaths",
                "/tmp /mnt/100% /a$b",
                "--prunenames",
                "\"q\" \\b",
            ]
        )
    );
}

#[test]
fn quotes_may_start_inside_a_word_and_both_kinds_unescape() {
    assert_eq!(
        one("/bin/updatedb -e'/a b'\"/c\" '\\x41\\n'"),
        command("/bin/updatedb", &["-e/a b/c", "A\n"])
    );
}

#[test]
fn escapes_read_as_systemd_reads_them() {
    let cmd = one(r"/u \a\b\f\n\r\t\v\\\'\s\x7e\101\u00e9\U0001F600");
    assert_eq!(cmd.args.len(), 1);
    assert_eq!(
        cmd.args[0],
        [
            &[
                0x07, 0x08, 0x0c, b'\n', b'\r', b'\t', 0x0b, b'\\', b'\'', b' ', b'~', b'A'
            ][..],
            "\u{e9}\u{1f600}".as_bytes()
        ]
        .concat()
    );
    // A byte escape is the byte, UTF-8 or not, and \u encodes a surrogate
    // as systemd's utf8_encode_unichar() does.
    assert_eq!(one(r"/u \xff").args[0], [0xff]);
    assert_eq!(one(r"/u \377").args[0], [0xff]);
    assert_eq!(one(r"/u \ud800").args[0], [0xed, 0xa0, 0x80]);
    assert_eq!(one(r"/u ߿").args[0], [0xdf, 0xbf]);
    // \u and \U below 0x80 are one byte, an even one included.
    assert_eq!(one(r"/u \u0041\U0000004a").args[0], b"AJ");
}

#[test]
fn an_escape_systemd_does_not_know_stays_as_it_is() {
    // systemd reads such a word again with EXTRACT_UNESCAPE_RELAX: the
    // backslash and the character after it stay, the rest reads as usual.
    for kept in [
        r"\q",
        r"\x0",
        r"\x00",
        r"\000",
        r"\400",
        r"\08",
        r"\u0000",
        r"\u12",
        r"\U0000d800",
        r"\U0000fffe",
        r"\U00110000",
    ] {
        assert_eq!(
            one(&format!("/u {kept}")).args[0],
            kept.as_bytes(),
            "{kept}"
        );
    }
    assert_eq!(one(r"/u \q\n").args[0], b"\\q\n");
    assert_eq!(one(r"/u 'a\qb'").args[0], b"a\\qb");
    // A backslash that ends the value outside quotes stays too.
    assert_eq!(one("/u a\\").args[0], b"a\\");
}

#[test]
fn what_systemd_refuses() {
    for value in [
        "/u 'open",
        "/u \"open",
        "/u 'a\\",
        "/u a\0b",
        "/u a\\\0b",
        "/u 'a\\\0b'",
        "@/u",
    ] {
        refused(value);
    }
}

#[test]
fn specifiers_and_variables_are_not_guessed() {
    assert_eq!(one("/u 100%%").args[0], b"100%");
    assert!(unknown("/u %n").contains("specifier"));
    assert!(unknown("/u 50%").contains("specifier"));
    assert!(unknown("/u%i").contains("specifier"));
    assert!(unknown("/u $PRUNE").contains("environment variable"));
    assert!(unknown("/u ${PRUNE}").contains("environment variable"));
    assert!(unknown("/u a$").contains("environment variable"));
    // `:` keeps every `$`.
    assert_eq!(
        one(":/u $PRUNE $$").args,
        [b"$PRUNE".to_vec(), b"$$".to_vec()]
    );
}

#[test]
fn the_prefixes_come_off_and_at_takes_argv0() {
    assert_eq!(one("-/u -e /mnt").program, b"/u");
    assert_eq!(one("+/u").program, b"/u");
    assert_eq!(one("!!/u").program, b"/u");
    assert_eq!(one("-!/u").program, b"/u");
    assert_eq!(
        one("@/usr/bin/updatedb updatedb -e /mnt"),
        command("/usr/bin/updatedb", &["-e", "/mnt"])
    );
    assert_eq!(one("-@:/u name $X").args, [b"$X".to_vec()]);
    // Each prefix counts once: a second one is part of the program.
    assert_eq!(one("--/u").program, b"-/u");
    assert_eq!(one("+!/u").program, b"!/u");
    assert_eq!(one("@@/u a b"), command("@/u", &["b"]));
    assert_eq!(one("::/u x").program, b":/u");
}

#[test]
fn a_lone_semicolon_separates_commands() {
    assert_eq!(
        exec_commands("/a -e /x ; /b ;").unwrap(),
        [command("/a", &["-e", "/x"]), command("/b", &[])]
    );
    // `\;` is a `;` word; a `;` inside a word is part of it.
    assert_eq!(
        exec_commands("; /a \\; x;y").unwrap(),
        [command("/a", &[";", "x;y"])]
    );
    // An escaped `;` inside a word is no escape systemd knows: it keeps its
    // backslash.
    assert_eq!(one("/a\\;"), command("/a\\;", &[]));
}

#[test]
fn the_program_is_an_updatedb_by_its_file_name() {
    for program in [
        "updatedb",
        "/usr/bin/updatedb",
        "/usr/sbin/updatedb.plocate",
        "updatedb.plocat",
        "updatedb.find-utils_2.x",
        "/nix/store/x-plocate-1.1.25/bin/updatedb",
    ] {
        assert!(is_updatedb(program.as_bytes()), "{program}");
    }
    for program in [
        "/usr/bin/plocate",
        "/bin/sh",
        "updatedbx",
        "/updatedb/x",
        "",
        "updatedb.",
        // The whole script of `sh -c`, which is no program's name.
        "updatedb.plocate --prunepaths tmp",
        "updatedb.plocate\t-e x",
        "updatedb.plocate;true",
    ] {
        assert!(!is_updatedb(program.as_bytes()), "{program}");
    }
}

#[test]
fn errors_read_as_their_reason() {
    assert_eq!(ExecError::Refused("x".to_string()).to_string(), "x");
    assert_eq!(ExecError::Unknown("y".to_string()).to_string(), "y");
}
