// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::MockFilesystem;
use std::path::{Path, PathBuf};

/// Fedora 44's `/etc/sysconfig/firewalld`, as its firewalld package installs
/// it.
const FEDORA_SYSCONFIG: &str = include_str!("../fixtures/fedora-44-firewalld.sysconfig");

fn vars(text: &str) -> Variables {
    file_variables(text.as_bytes()).unwrap_or_else(|why| panic!("{text:?}: {why}"))
}

fn one(text: &str, name: &str) -> Option<String> {
    vars(text).get(name).cloned()
}

#[test]
fn fedora_sets_firewalld_args_empty() {
    assert_eq!(one(FEDORA_SYSCONFIG, "FIREWALLD_ARGS"), Some(String::new()));
    assert_eq!(vars(FEDORA_SYSCONFIG).len(), 1);
}

#[test]
fn values_read_as_systemd_reads_them() {
    for (text, value) in [
        ("A=--log-target=syslog\n", "--log-target=syslog"),
        (
            "A=\"--log-target=syslog --debug\"\n",
            "--log-target=syslog --debug",
        ),
        ("A='--log-target=syslog'\n", "--log-target=syslog"),
        // Blanks around the name and before the value go, and those after
        // a plain value.
        ("  A =   x y  \n", "x y"),
        ("A=x\t\n", "x"),
        // A quoted value keeps its blanks, and parts join.
        ("A=\" x \"\n", " x "),
        ("A='a'\"b\"\n", "ab"),
        ("A='a' b\n", "ab"),
        // A backslash escapes the next character, and one at the end of a
        // line goes on with the next.
        ("A=a\\ \n", "a "),
        ("A=a\\\nb\n", "ab"),
        // In double quotes it stays unless it escapes one of \" \\ ` $.
        ("A=\"q\\\"\\$x\\d\"\n", "q\"$x\\d"),
        ("A=\"a\\\nb\"\n", "ab"),
        // In single quotes nothing is escaped, and a newline stays.
        ("A='a\\b\nc'\n", "a\\b\nc"),
        // The last assignment counts.
        ("A=1\nA=2\n", "2"),
        // A file need not end with a newline, nor a quote with its partner.
        ("A=1", "1"),
        ("A=\"open", "open"),
        ("A=", ""),
    ] {
        assert_eq!(one(text, "A").as_deref(), Some(value), "{text:?}");
    }
}

#[test]
fn comments_and_lines_systemd_drops_set_nothing() {
    for text in [
        "# A=1\n",
        "; A=1\n",
        "  # A=1\n",
        // A line without `=` sets nothing.
        "A\n",
        // A name systemd refuses, as `export A`, is dropped.
        "export A=1\n",
        "1A=1\n",
        "A-B=1\n",
        // Nothing after a NUL byte is read.
        "\0A=1\n",
    ] {
        assert_eq!(one(text, "A"), None, "{text:?}");
    }
    // A comment that ends in a backslash does not swallow the next line,
    // as from systemd 254.
    assert_eq!(one("# x \\\nA=1\n", "A").as_deref(), Some("1"));
    // A tab and a newline are kept in a value, and so is any other control
    // character: systemd 254's env_value_is_valid() judges only UTF-8 and
    // length. A later assignment of the variable wins.
    assert_eq!(one("A=\"a\tb\nc\"\n", "A").as_deref(), Some("a\tb\nc"));
    assert_eq!(
        one("A=--log-target=syslog\nA=\"a\u{1}b\"\n", "A").as_deref(),
        Some("a\u{1}b")
    );
}

#[test]
fn a_file_that_is_not_utf8_cannot_be_read() {
    assert_eq!(
        file_variables(b"A=\xff\n"),
        Err("the file is not UTF-8".to_string())
    );
}

/// A decoy that holds `files`, each with its text.
fn decoy(files: &[(&str, &str)]) -> MockFilesystem {
    let fs = MockFilesystem::new();
    for (path, text) in files {
        fs.mock_add_file(path, text);
    }
    fs
}

fn assignments(text: &str) -> Vec<Assignment> {
    let mut out = Vec::new();
    super::super::super::super::systemd_conf::parse_section(text, "Service", &mut out).unwrap();
    out
}

fn environment_of(fs: &MockFilesystem, service: &str) -> Result<Environment, String> {
    let hidden: Vec<PathBuf> = Vec::new();
    let files = DecoyFiles::new(fs, Path::new("/"), &hidden);
    environment(&files, &assignments(service))
}

#[test]
fn files_override_environment_lines_in_their_order() {
    let fs = decoy(&[
        ("/etc/sysconfig/firewalld", FEDORA_SYSCONFIG),
        (
            "/etc/sysconfig/more",
            "FIREWALLD_ARGS=--log-target=syslog\nB=2\n",
        ),
    ]);
    let found = environment_of(
        &fs,
        "[Service]\nEnvironment=FIREWALLD_ARGS=--debug \"B=x y\" C=3 not-one\n\
         EnvironmentFile=-/etc/sysconfig/firewalld\n",
    )
    .unwrap();
    assert_eq!(found.variables["FIREWALLD_ARGS"], "");
    assert_eq!(found.variables["B"], "x y");
    assert_eq!(found.variables["C"], "3");
    assert!(!found.variables.contains_key("not-one"));
    assert_eq!(found.files, ["/etc/sysconfig/firewalld"]);

    let found = environment_of(
        &fs,
        "[Service]\nEnvironmentFile=-/etc/sysconfig/firewalld\nEnvironmentFile=/etc/sysconfig/more\n",
    )
    .unwrap();
    assert_eq!(found.variables["FIREWALLD_ARGS"], "--log-target=syslog");
    assert_eq!(found.variables["B"], "2");
    assert_eq!(
        found.files,
        ["/etc/sysconfig/firewalld", "/etc/sysconfig/more"]
    );

    // An empty assignment drops the lines before it.
    let found = environment_of(
        &fs,
        "[Service]\nEnvironment=A=1\nEnvironmentFile=/etc/sysconfig/more\nEnvironment=\n\
         EnvironmentFile=\n",
    )
    .unwrap();
    assert!(found.variables.is_empty(), "{found:?}");
    assert!(found.files.is_empty(), "{found:?}");
}

#[test]
fn a_missing_optional_file_sets_nothing_and_unset_environment_takes_away() {
    let fs = decoy(&[("/etc/default/x", "A=1\nB=2\n")]);
    let found = environment_of(
        &fs,
        "[Service]\nEnvironmentFile=-/etc/sysconfig/firewalld\nEnvironmentFile=/etc/default/x\n\
         UnsetEnvironment=A B=2\n",
    )
    .unwrap();
    assert!(found.variables.is_empty(), "{found:?}");
    assert_eq!(found.files, ["/etc/default/x"]);
    // systemd ignores a name that is not absolute, and one that is not
    // normalized, with a `..` in it, whether `-` lets it be missing or not.
    for line in [
        "EnvironmentFile=etc/default/x",
        "EnvironmentFile=/etc/../etc/default/x",
        "EnvironmentFile=-/etc/default/../default/x",
        "EnvironmentFile=/etc/default/x/..",
    ] {
        let found = environment_of(&fs, &format!("[Service]\n{line}\n")).unwrap();
        assert!(found.files.is_empty(), "{line}: {found:?}");
        assert!(found.variables.is_empty(), "{line}: {found:?}");
    }
}

#[test]
fn unset_environment_reads_its_words_as_systemd_does() {
    let fs = decoy(&[("/etc/default/x", "A=1\nB=2\nC=3\n")]);
    let with = |unset: &str| {
        environment_of(
            &fs,
            &format!("[Service]\nEnvironmentFile=/etc/default/x\nUnsetEnvironment={unset}\n"),
        )
    };
    // A quoted name is unquoted, as `extract_first_word()` does.
    let found = with("\"A\" 'B'").unwrap();
    assert_eq!(found.variables.keys().collect::<Vec<_>>(), ["C"]);
    // An assignment takes the variable away only while it holds that value.
    let found = with("B=9 C=3").unwrap();
    assert_eq!(found.variables.keys().collect::<Vec<_>>(), ["A", "B"]);
    // A word that is neither a name nor an assignment takes nothing away.
    let found = with("1A -").unwrap();
    assert_eq!(found.variables.len(), 3, "{found:?}");
    // What NAILS does not read as systemd does is unknown.
    for (unset, why) in [
        (
            "\\x41",
            "NAILS cannot read its UnsetEnvironment=\\x41 (it holds a backslash, whose escape \
             NAILS does not read)",
        ),
        (
            "%n",
            "NAILS cannot read its UnsetEnvironment=%n (it uses a specifier that NAILS does not \
             expand)",
        ),
        (
            "\"A",
            "NAILS cannot read its UnsetEnvironment=\"A (a quote without its partner)",
        ),
    ] {
        assert_eq!(with(unset), Err(why.to_string()), "{unset}");
    }
}

#[test]
fn what_nails_cannot_read_of_the_environment_is_unknown() {
    let fs = decoy(&[]);
    for (service, why) in [
        (
            "[Service]\nEnvironmentFile=/etc/sysconfig/firewalld\n",
            "its EnvironmentFile=/etc/sysconfig/firewalld does not exist, so the service does \
             not start until it does",
        ),
        (
            "[Service]\nEnvironmentFile=-/etc/sysconfig/*\n",
            "NAILS does not expand the specifier or wildcard of its \
             EnvironmentFile=-/etc/sysconfig/*",
        ),
        (
            "[Service]\nEnvironmentFile=/etc/%N\n",
            "NAILS does not expand the specifier or wildcard of its EnvironmentFile=/etc/%N",
        ),
        (
            "[Service]\nEnvironmentFile=/etc/default/\\x\n",
            "NAILS does not expand the specifier or wildcard of its \
             EnvironmentFile=/etc/default/\\x",
        ),
        (
            "[Service]\nEnvironment=A=\\x41\n",
            "NAILS cannot read its Environment=A=\\x41 (it holds a backslash, whose escape NAILS \
             does not read)",
        ),
        (
            "[Service]\nEnvironment=A=%n\n",
            "NAILS cannot read its Environment=A=%n (it uses a specifier that NAILS does not \
             expand)",
        ),
    ] {
        assert_eq!(
            environment_of(&fs, service),
            Err(why.to_string()),
            "{service}"
        );
    }
    // A file of text that is not UTF-8.
    let fs = decoy(&[]);
    fs.mock_set_file_bytes("/etc/default/x", b"A=\xff\n");
    assert_eq!(
        environment_of(&fs, "[Service]\nEnvironmentFile=/etc/default/x\n"),
        Err("/etc/default/x is not UTF-8".to_string())
    );
}
