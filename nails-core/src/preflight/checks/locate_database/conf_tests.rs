// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::preflight::checks::locate_database::tests::{ARCH, DEBIAN, FEDORA, UBUNTU};

fn entries(list: &[Vec<u8>]) -> Vec<&str> {
    list.iter()
        .map(|entry| std::str::from_utf8(entry).unwrap())
        .collect()
}

fn error(text: &[u8]) -> ConfError {
    parse_updatedb_conf(text).expect_err("updatedb refuses it")
}

#[test]
fn the_distributions_files_read_as_updatedb_reads_them() {
    let debian = parse_updatedb_conf(DEBIAN.as_bytes()).unwrap();
    assert_eq!(debian.prune_bind_mounts, Some(true));
    assert_eq!(
        entries(&debian.prunepaths),
        [
            "/tmp",
            "/var/spool",
            "/media",
            "/var/lib/os-prober",
            "/var/lib/ceph",
            "/home/.ecryptfs",
            "/var/lib/schroot"
        ]
    );
    // Debian ships PRUNENAMES commented out.
    assert!(debian.prunenames.is_empty());
    assert!(entries(&debian.prunefs).contains(&"tmpfs"));
    assert!(!entries(&debian.prunefs).contains(&"ext4"));

    let ubuntu = parse_updatedb_conf(UBUNTU.as_bytes()).unwrap();
    assert_eq!(ubuntu.prunepaths, debian.prunepaths);
    assert!(entries(&ubuntu.prunefs).contains(&"redfs"));

    let fedora = parse_updatedb_conf(FEDORA.as_bytes()).unwrap();
    assert_eq!(fedora.prune_bind_mounts, None);
    assert_eq!(
        entries(&fedora.prunepaths),
        [
            "/tmp",
            "/media",
            "/dev",
            "/sys",
            "/proc",
            "/run",
            "/var/cache",
            "/var/spool"
        ]
    );

    let arch = parse_updatedb_conf(ARCH.as_bytes()).unwrap();
    assert_eq!(entries(&arch.prunenames), [".git", ".hg", ".svn"]);
    assert!(entries(&arch.prunepaths).contains(&"/mnt"));
    assert!(entries(&arch.prunepaths).contains(&"/media"));
}

#[test]
fn blanks_comments_and_empty_lines_are_skipped() {
    let conf = parse_updatedb_conf(
        b"\n# a comment\n  \t\r\n\x0bPRUNEPATHS\t=\x0c\"/a\t/b  /c\" # after\n\
          PRUNENAMES = \"\"\n# last, without a newline",
    )
    .unwrap();
    assert_eq!(entries(&conf.prunepaths), ["/a", "/b", "/c"]);
    assert!(conf.prunenames.is_empty());
    assert_eq!(parse_updatedb_conf(b"").unwrap(), UpdatedbConf::default());
}

#[test]
fn a_hash_inside_quotes_is_part_of_the_value() {
    let conf = parse_updatedb_conf(b"PRUNEPATHS = \"/a#b /c\"").unwrap();
    assert_eq!(entries(&conf.prunepaths), ["/a#b", "/c"]);
}

#[test]
fn a_nul_ends_the_value_as_the_c_string_does() {
    let conf = parse_updatedb_conf(b"PRUNEPATHS = \"/a /b\0/c\"\n").unwrap();
    assert_eq!(entries(&conf.prunepaths), ["/a", "/b"]);
    let conf = parse_updatedb_conf(b"PRUNE_BIND_MOUNTS = \"yes\0junk\"\n").unwrap();
    assert_eq!(conf.prune_bind_mounts, Some(true));
}

#[test]
fn prune_bind_mounts_takes_the_four_spellings() {
    for (value, flag) in [("0", false), ("no", false), ("1", true), ("yes", true)] {
        let conf = parse_updatedb_conf(format!("PRUNE_BIND_MOUNTS=\"{value}\"").as_bytes());
        assert_eq!(conf.unwrap().prune_bind_mounts, Some(flag), "{value}");
    }
    for value in ["YES", "true", "", " yes"] {
        let refused = error(format!("PRUNE_BIND_MOUNTS=\"{value}\"").as_bytes());
        assert_eq!(
            refused.kind,
            ConfErrorKind::InvalidBool(value.as_bytes().to_vec()),
            "{value}"
        );
    }
}

#[test]
fn every_refusal_names_its_line() {
    let cases: &[(&[u8], u32, ConfErrorKind)] = &[
        (
            b"\nprunepaths = \"/mnt\"\n",
            2,
            ConfErrorKind::UnknownVariable(b"prunepaths".to_vec()),
        ),
        (
            b"PRUNEPATHS = \"/a\"\nPRUNEPATHS = \"/b\"\n",
            2,
            ConfErrorKind::AlreadyDefined(Variable::PrunePaths),
        ),
        (b"= \"/a\"\n", 1, ConfErrorKind::VariableExpected),
        (b"\"/a\"\n", 1, ConfErrorKind::VariableExpected),
        (b"\0PRUNEFS = \"x\"\n", 1, ConfErrorKind::VariableExpected),
        (b"1PRUNEFS = \"x\"\n", 1, ConfErrorKind::VariableExpected),
        (b"PRUNEFS \"x\"\n", 1, ConfErrorKind::EqualsExpected),
        (b"PRUNEFS\n= \"x\"\n", 1, ConfErrorKind::EqualsExpected),
        (b"PRUNEFS = x\n", 1, ConfErrorKind::QuotedValueExpected),
        (b"PRUNEFS =\n", 1, ConfErrorKind::QuotedValueExpected),
        (
            b"\n\nPRUNEFS = \"x\n\"\n",
            3,
            ConfErrorKind::MissingClosingQuote,
        ),
        (b"PRUNEFS = \"x", 1, ConfErrorKind::MissingClosingQuote),
        (b"PRUNEFS = \"x\" y\n", 1, ConfErrorKind::DataAfterValue),
        (b"PRUNEFS = \"x\" \"y\"\n", 1, ConfErrorKind::DataAfterValue),
    ];
    for (text, line, kind) in cases {
        let refused = error(text);
        assert_eq!(
            (refused.line, &refused.kind),
            (*line, kind),
            "{:?}",
            String::from_utf8_lossy(text)
        );
        assert!(
            refused.to_string().contains(&format!("line {line}")),
            "{refused}"
        );
    }
}

#[test]
fn a_name_runs_over_letters_digits_and_underscores() {
    // `PRUNEFS2` is one name, and not PRUNEFS.
    assert_eq!(
        error(b"PRUNEFS2 = \"x\"").kind,
        ConfErrorKind::UnknownVariable(b"PRUNEFS2".to_vec())
    );
    // A byte above ASCII is no letter in the C locale.
    assert_eq!(
        error("PRUNEFS\u{e9} = \"x\"".as_bytes()).kind,
        ConfErrorKind::EqualsExpected
    );
}

#[test]
fn the_variables_have_their_names() {
    for (variable, name) in [
        (Variable::PruneBindMounts, "PRUNE_BIND_MOUNTS"),
        (Variable::PruneFs, "PRUNEFS"),
        (Variable::PruneNames, "PRUNENAMES"),
        (Variable::PrunePaths, "PRUNEPATHS"),
    ] {
        assert_eq!(variable.name(), name);
        let twice = format!("{name} = \"1\"\n{name} = \"1\"\n");
        assert!(error(twice.as_bytes()).to_string().contains(name));
    }
}

#[test]
fn each_refusal_reads_as_a_sentence() {
    for (text, words) in [
        (&b"X = \"1\""[..], "sets X, which updatedb does not know"),
        (b"=", "does not start with a variable name"),
        (b"PRUNEFS", "has no = after the variable name"),
        (b"PRUNEFS =", "has no quoted value after the ="),
        (b"PRUNEFS = \"", "is not closed"),
        (b"PRUNE_BIND_MOUNTS = \"2\"", "none of 0, no, 1 and yes"),
        (b"PRUNEFS = \"\" =", "goes on after its quoted value"),
    ] {
        let message = error(text).to_string();
        assert!(message.contains(words), "{message}");
    }
}
