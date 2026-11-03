// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the way a zsh starts makes it read and turn on: its command line,
//! and an `/etc/zshenv` that turns `RCS` on again for a zsh started with
//! `-f`.

use super::*;

/// A zsh started as `zsh -f`, which is no login shell.
const BARE: Start = Start {
    login: Some(false),
    rcs: false,
    global_rcs: true,
};

/// The command line of `words`.
fn line(words: &[&str]) -> CommandLine {
    CommandLine::of(
        &words
            .iter()
            .map(|word| word.to_string())
            .collect::<Vec<_>>(),
    )
}

#[test]
fn a_zshenv_that_may_turn_rcs_on_again_makes_a_zsh_f_read_on() {
    // zsh 5.9.2 started with -f reads ~/.zshrc after each of these in
    // /etc/zshenv: they turn RCS on again.
    for zshenv in [
        "setopt rcs",
        "set -o rcs",
        "unsetopt no_rcs",
        "options[rcs]=on",
        "set +o norcs",
        "[[ -o interactive ]] && setopt rcs",
        "set +f",
        "unsetopt -f",
        "emulate -R zsh",
        "setopt {r,x}cs",
        "source /etc/zshenv.local",
        // Another zsh without -f, or a flag or a name an expansion makes.
        "[[ -z $INNER ]] && INNER=1 exec zsh -i",
        "x=f; set +$x",
        "set +${:-f}",
        "set +$(print f)",
        "setopt $o",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/etc/zshenv", &format!("{zshenv}\n"));
        seed(&fs, "/etc/zshenv.local", "setopt rcs\n");
        seed(&fs, "/home/alice/.zshrc", "setopt share_history\n");
        let found = scan(&fs, BARE);
        assert!(found.reopened, "{zshenv}: {found:?}");
        assert_eq!(
            on(&fs, BARE),
            ["/home/alice/.zshrc names SHARE_HISTORY"],
            "{zshenv}"
        );
    }
    // One that names neither reads /etc/zshenv alone.
    let fs = MockFilesystem::new();
    seed(&fs, "/etc/zshenv", "export EDITOR=vi\n");
    seed(&fs, "/home/alice/.zshrc", "setopt share_history\n");
    assert_eq!(scan(&fs, BARE), Scan::default());
    // A zsh started with -d reads /etc's other files once one turns
    // GLOBAL_RCS on again.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshenv", "setopt global_rcs\n");
    seed(&fs, "/etc/zshrc", "setopt share_history\n");
    let start = Start {
        global_rcs: false,
        ..UNKNOWN
    };
    assert_eq!(on(&fs, start), ["/etc/zshrc names SHARE_HISTORY"]);
}

#[test]
fn an_option_the_command_line_turns_on_counts() {
    // zsh 5.9.1 runs each with SHARE_HISTORY on.
    for words in [
        &["zsh", "-o", "sharehistory"][..],
        &["zsh", "-f", "-o", "sharehistory"],
        &["zsh", "-f", "-oshare_history"],
        &["zsh", "--share-history"],
        &["zsh", "-f", "--share_history"],
        &["zsh", "-fo", "sharehistory"],
        &["zsh", "-fxo", "sharehistory"],
        &["zsh", "-fxoshare_history"],
        &["zsh", "--no-rcs", "-o", "SHARE_HISTORY"],
        &["zsh", "--no-share-history", "-o", "sharehistory"],
    ] {
        assert_eq!(
            line(words).writes(),
            [Write {
                what: "its command line turns on SHARE_HISTORY".to_string(),
                entered: true,
                option: false,
            }],
            "{words:?}"
        );
    }
    // Turned off by the last word that names it, or another option.
    for words in [
        &["zsh", "-o", "sharehistory", "+o", "sharehistory"][..],
        &["zsh", "--share-history", "+-share-history"],
        &["zsh", "-o", "histignoredups"],
        &["zsh", "-f"],
        &["-zsh"],
    ] {
        let line = line(words);
        assert_eq!(line.writes(), Vec::new(), "{words:?}");
        assert_eq!(line.doubts, Vec::<String>::new(), "{words:?}");
    }
    // One that emulates sh or ksh reads their startup files, and an `-o`
    // that names nothing is a doubt.
    for (words, doubt) in [
        (&["sh", "-i"][..], "sh"),
        (&["-ksh"], "-ksh"),
        (&["/bin/rsh"], "/bin/rsh"),
        (&["zsh", "--emulate", "sh"], "--emulate"),
        (&["zsh", "--emulate=ksh"], "--emulate=ksh"),
    ] {
        assert_eq!(
            line(words).doubts,
            [format!(
                "it cannot tell what a zsh started with `{doubt}` on its command line reads, as \
                 zsh then emulates sh or ksh and reads their startup files"
            )],
            "{words:?}"
        );
    }
    assert_eq!(
        line(&["zsh", "-o"]).doubts,
        ["it cannot tell what `-o` on its command line turns on"]
    );
    assert_eq!(
        line(&["zsh", "--emulate", "zsh"]).doubts,
        Vec::<String>::new()
    );
    // GLOB_SUBST makes a glob qualifier in a value run.
    assert_eq!(
        line(&["zsh", "-o", "globsubst"]).doubts,
        [
            "it cannot tell what code zsh runs from the values it expands as patterns, as its \
             command line turns GLOB_SUBST on, which makes a glob qualifier in a value run"
        ]
    );
}
