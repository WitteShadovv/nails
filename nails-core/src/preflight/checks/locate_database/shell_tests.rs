// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

/// The arguments of each updatedb `text` runs.
fn runs(text: &str) -> Vec<Vec<String>> {
    updatedb_runs(text.as_bytes())
        .into_iter()
        .map(|run| {
            let command = run.unwrap_or_else(|why| panic!("{text:?}: {why}"));
            assert!(is_updatedb(&command.program), "{command:?}");
            command
                .args
                .into_iter()
                .map(|arg| String::from_utf8(arg).unwrap())
                .collect()
        })
        .collect()
}

/// Why NAILS cannot tell what a command of `text` runs.
fn unknown(text: &str) -> String {
    updatedb_runs(text.as_bytes())
        .into_iter()
        .find_map(Result::err)
        .unwrap_or_else(|| panic!("{text:?}: every command is known"))
}

fn nothing(text: &str) {
    let found = updatedb_runs(text.as_bytes());
    assert!(found.is_empty(), "{text:?}: {found:?}");
}

#[test]
fn a_plain_command_and_its_arguments() {
    assert_eq!(runs("updatedb"), [Vec::<String>::new()]);
    assert_eq!(
        runs("/usr/bin/updatedb --config-file /etc/updatedb-extra.conf -o /var/lib/x.db"),
        [[
            "--config-file",
            "/etc/updatedb-extra.conf",
            "-o",
            "/var/lib/x.db"
        ]]
    );
    assert_eq!(runs("  updatedb\t-e   /mnt  "), [["-e", "/mnt"]]);
}

#[test]
fn whatever_runs_it_the_first_updatedb_word_is_the_program() {
    for text in [
        "nice -n 19 updatedb -U /home",
        "ionice -c3 nice updatedb -U /home",
        "flock --nonblock /run/x.lock updatedb.plocate -U /home",
        "exec sudo /usr/sbin/updatedb -U /home",
        "X=1 Y=2 updatedb -U /home",
    ] {
        assert_eq!(runs(text), [["-U", "/home"]], "{text}");
    }
}

#[test]
fn commands_split_at_the_operators_and_braces() {
    assert_eq!(
        runs("cd / && updatedb -e /a; updatedb -e /b || true | cat & (updatedb -e /c)"),
        [["-e", "/a"], ["-e", "/b"], ["-e", "/c"]]
    );
    assert_eq!(
        runs("test -x /usr/sbin/anacron || { cd / && updatedb -e /d; }"),
        [["-e", "/d"]]
    );
    assert_eq!(
        runs("updatedb -e /a\nupdatedb -e /b\n"),
        [["-e", "/a"], ["-e", "/b"]]
    );
}

#[test]
fn quotes_and_escapes_give_the_words_the_shell_passes() {
    assert_eq!(
        runs("updatedb -e '/a b' --prunefs=\"ext4\""),
        [["-e", "/a b", "--prunefs=ext4"]]
    );
    assert_eq!(runs("updatedb -e /a\\ b"), [["-e", "/a b"]]);
    assert_eq!(runs("updatedb \\\n  -e /a"), [["-e", "/a"]]);
    assert_eq!(runs("'/usr/bin/updatedb' -e /a"), [["-e", "/a"]]);
}

#[test]
fn redirections_are_no_arguments() {
    for text in [
        "updatedb -e /a >/dev/null 2>&1",
        "updatedb -e /a > /dev/null 2> /tmp/err",
        "updatedb -e /a &>/dev/null",
        "updatedb </dev/null -e /a >&-",
        "updatedb -e /a >>/var/log/x",
    ] {
        assert_eq!(runs(text), [["-e", "/a"]], "{text}");
    }
}

#[test]
fn comments_and_questions_run_nothing() {
    nothing("# updatedb --prunepaths /tmp");
    nothing("true # updatedb");
    nothing("test -x /usr/sbin/updatedb.plocate || exit 0");
    nothing("[ -x /usr/sbin/updatedb.plocate ] || exit 0");
    nothing("[[ -x /usr/bin/updatedb ]]");
    nothing("command -v updatedb >/dev/null");
    nothing("which updatedb; type updatedb; echo updatedb; printf updatedb");
    nothing("run-parts --report /etc/cron.daily");
    nothing("");
    // A `#` inside a word is no comment.
    assert_eq!(runs("updatedb -e /a#b"), [["-e", "/a#b"]]);
}

#[test]
fn what_only_running_the_shell_tells_is_unknown() {
    for text in [
        "updatedb $OPTIONS",
        "updatedb -e \"$DIR\"",
        "updatedb -e `cat /etc/x`",
        "updatedb -e $(cat /etc/x)",
        "updatedb -e /mnt/*",
        "updatedb -e /mnt/[ab]",
        "updatedb -e ~/x",
        "UPDATEDB=/usr/sbin/updatedb.plocate",
        "UPDATEDB=\"/usr/bin/updatedb\"; OPTS='--prunepaths /tmp'; $UPDATEDB $OPTS",
        "sh -c 'updatedb --prunepaths /tmp'",
        "X=`updatedb.plocate`",
    ] {
        unknown(text);
    }
}

#[test]
fn a_command_substitution_runs_its_command() {
    // `$(` ends the word and `)` the command, so what runs inside is read.
    assert_eq!(runs("X=$(updatedb.plocate)"), [Vec::<String>::new()]);
    assert_eq!(runs("echo $(updatedb -e /a)"), [["-e", "/a"]]);
}

#[test]
fn text_the_shell_refuses_is_unknown() {
    for text in [
        "updatedb -e '/a",
        "updatedb -e \"/a",
        "updatedb -e /a \\",
        "updatedb > ",
        "updatedb <<EOF",
    ] {
        assert!(unknown(text).contains("cannot split"), "{text}");
    }
}

#[test]
fn a_lone_bracket_is_no_glob() {
    // `[` alone is the test command; with a `]` in the same word it globs.
    nothing("[ -x /usr/bin/updatedb ]");
    unknown("updatedb -e /a[b]");
    assert_eq!(runs("updatedb -e /a[b"), [["-e", "/a[b"]]);
}

#[test]
fn a_quoted_name_is_no_assignment() {
    // The shell runs a word whose name or `=` is quoted as a command.
    assert_eq!(runs("'A=/usr/bin/updatedb' -e /a"), [["-e", "/a"]]);
    assert_eq!(runs("A\\=/usr/bin/updatedb -e /a"), [["-e", "/a"]]);
    assert!(unknown("A=/usr/bin/updatedb").contains("in a variable"));
    assert!(unknown("A=\"/usr/bin/updatedb\" B=1").contains("in a variable"));
}

#[test]
fn an_updatedb_named_before_the_program_is_unknown() {
    // `sh -c` runs its script with the next word as its name.
    assert!(
        unknown("sh -c 'updatedb --prunepaths /tmp' updatedb").contains("a word before"),
        "the script runs another updatedb"
    );
    // After the program, a word naming updatedb is one of its arguments.
    assert_eq!(
        runs("updatedb --config-file /etc/updatedb.conf"),
        [["--config-file", "/etc/updatedb.conf"]]
    );
}

#[test]
fn each_command_is_told_apart() {
    let found = updatedb_runs(b"updatedb -e /a; updatedb $X; echo updatedb");
    assert_eq!(found.len(), 2, "{found:?}");
    assert_eq!(
        found[0],
        Ok(ExecCommand {
            program: b"updatedb".to_vec(),
            args: vec![b"-e".to_vec(), b"/a".to_vec()],
        })
    );
    assert!(found[1].is_err(), "{found:?}");
}

#[test]
fn what_ends_a_word_and_what_does_not() {
    // A redirection right after a word ends it; only unquoted digits name a
    // descriptor.
    assert_eq!(runs("updatedb -e /a>/dev/null"), [["-e", "/a"]]);
    assert_eq!(runs("updatedb -e '2'>/dev/null"), [["-e", "2"]]);
    // A `~` or `]` inside a word expands nothing.
    assert_eq!(runs("updatedb -e /a~b /a]b"), [["-e", "/a~b", "/a]b"]]);
    // Quoted braces are words.
    assert_eq!(runs("updatedb '{' \"}\""), [["{", "}"]]);
    // A word that starts with `=` is no assignment.
    assert_eq!(runs("=x updatedb -e /a"), [["-e", "/a"]]);
    // `-V` after updatedb is its option, not a question.
    assert_eq!(runs("updatedb -V"), [["-V"]]);
}

#[test]
fn keywords_in_front_of_a_command_leave_it_the_same() {
    assert_eq!(
        runs("if [ -x /usr/bin/updatedb ]; then updatedb -e /a; fi"),
        [["-e", "/a"]]
    );
    assert_eq!(
        runs("while ! updatedb -e /b; do sleep 1; done"),
        [["-e", "/b"]]
    );
    // A quoted `[` is still the test command.
    nothing("'[' -x /usr/bin/updatedb ']'");
}

#[test]
fn what_makes_a_word_an_assignment_or_a_question() {
    // A name of letters, digits and `_` that starts with no digit.
    assert!(unknown("A_B=/usr/bin/updatedb").contains("in a variable"));
    assert_eq!(runs("A-B=/usr/bin/updatedb -e /a"), [["-e", "/a"]]);
    assert_eq!(runs("1A=/usr/bin/updatedb -e /a"), [["-e", "/a"]]);
    // `command` asks only with -v or -V.
    assert_eq!(runs("command updatedb -e /a"), [["-e", "/a"]]);
    // A brace group's first command is a command of its own.
    nothing("{ [ -x /usr/bin/updatedb ]; }");
    // A redirection after a separator starts the next command.
    assert_eq!(
        runs("updatedb -e /a;>/dev/null updatedb -e /b"),
        [["-e", "/a"], ["-e", "/b"]]
    );
    // `&>` sends both outputs to a file, and the command goes on.
    assert_eq!(
        runs("updatedb -e /a &>/dev/null -e /b"),
        [["-e", "/a", "-e", "/b"]]
    );
}
