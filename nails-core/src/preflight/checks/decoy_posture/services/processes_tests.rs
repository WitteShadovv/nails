// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

fn words(line: &str) -> Vec<Vec<u8>> {
    line.split_whitespace()
        .map(|word| word.as_bytes().to_vec())
        .collect()
}

const PROGRAMS: &[&str] = &["tuned", "tuned-ppd", "firewalld", "abrtd"];

#[test]
fn a_python_command_line_runs_the_first_word_after_the_interpreters_options() {
    for (line, script) in [
        ("/usr/bin/python3 -Es /usr/sbin/tuned -l", "/usr/sbin/tuned"),
        ("python3 /usr/sbin/tuned", "/usr/sbin/tuned"),
        (
            "python3 -X dev -W error /usr/bin/firewalld",
            "/usr/bin/firewalld",
        ),
        (
            "python3 -Xdev -sWerror /usr/bin/firewalld",
            "/usr/bin/firewalld",
        ),
        ("python3 -EX dev tuned", "tuned"),
        ("python3 --check-hash-based-pycs never x.py", "x.py"),
        ("python3 -I -- -odd-name", "-odd-name"),
    ] {
        assert_eq!(
            python_script(&words(line)),
            Some(script.as_bytes()),
            "{line}"
        );
    }
    for line in [
        "python3",
        "python3 -c import(tuned) /usr/sbin/tuned",
        "python3 -Ec x /usr/sbin/tuned",
        "python3 -m tuned",
        "python3 - /usr/sbin/tuned",
        "python3 -X",
    ] {
        assert_eq!(python_script(&words(line)), None, "{line}");
    }
}

#[test]
fn a_name_stands_for_its_program_or_the_one_nixos_wraps() {
    for (name, program) in [
        ("tuned", "tuned"),
        (".tuned-wrapped", "tuned"),
        (".tuned-ppd-wrap", "tuned-ppd"),
        (".tuned-ppd-wrapped", "tuned-ppd"),
        (".firewalld-wrap", "firewalld"),
        ("abrtd", "abrtd"),
    ] {
        assert_eq!(
            program_of(PROGRAMS, name.as_bytes()),
            Some(program),
            "{name}"
        );
    }
    for name in ["tuned-adm", "python3", ".tuned", "tuned-wrapped", ""] {
        assert_eq!(program_of(PROGRAMS, name.as_bytes()), None, "{name}");
    }
    for name in ["python", "python3", "python3.14", "platform-python"] {
        assert!(is_python(name), "{name}");
    }
    for name in ["python3-config", "pythonista", "py"] {
        assert!(!is_python(name), "{name}");
    }
    assert_eq!(
        own_args(
            "tuned",
            &words("/nix/store/a-python3/bin/python3.13 /nix/store/b-tuned/bin/.tuned-wrapped -l")
        ),
        Some(words("-l"))
    );
    assert_eq!(own_args("tuned", &words("/usr/bin/tuned-adm -l")), None);
}

#[test]
fn a_command_runs_a_daemon_only_as_its_program_or_its_python_script() {
    for (line, args) in [
        ("/usr/sbin/tuned -l -P", "-l -P"),
        ("tuned", ""),
        ("/usr/bin/python3 -Es /usr/sbin/tuned -P", "-P"),
        (
            "/usr/libexec/platform-python -Es /usr/sbin/tuned -l -P",
            "-l -P",
        ),
        ("/nix/store/b-tuned/bin/.tuned-wrapped -l", "-l"),
    ] {
        assert_eq!(own_args("tuned", &words(line)), Some(words(args)), "{line}");
    }
    // A program that runs tuned in turn may take its output into a file of
    // its own, as logsave and script do.
    for line in [
        "/usr/sbin/logsave -a /var/log/tuned/tuned.log /usr/sbin/tuned -P",
        "/usr/bin/script -q -a /var/log/tuned/typescript -c /usr/sbin/tuned",
        "/usr/bin/nice /usr/sbin/tuned -l",
        "/usr/bin/env python3 /usr/sbin/tuned",
        "/usr/bin/python3 /usr/local/bin/run /usr/sbin/tuned",
        "/usr/bin/python3 -m tuned",
    ] {
        assert_eq!(own_args("tuned", &words(line)), None, "{line}");
    }
    // Whether a unit runs abrtd at all is read from any of its words.
    assert!(runs_anywhere(
        "abrtd",
        &words("/usr/bin/nice /usr/sbin/abrtd -d -s")
    ));
    assert!(!runs_anywhere("abrtd", &words("/bin/true")));
}
