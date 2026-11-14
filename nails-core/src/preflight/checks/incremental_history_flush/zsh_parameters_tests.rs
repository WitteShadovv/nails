// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the builtins that set or take away a parameter do, as zsh reads
//! their words: the `typeset` family's options past a number, a word where
//! the options may stand or a name that an expansion, brace expansion or a
//! glob may make, the patterns of `unset -m`, and the attributes of a
//! parameter whose value the check follows.

use super::*;

/// What zsh's startup files hold with `zshenv` as `.zshenv` and `rc` as
/// `.zshrc`.
fn found(zshenv: &str, rc: &str) -> Scan {
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshenv", zshenv);
    seed(&fs, "/home/alice/.zshrc", rc);
    scan(&fs, UNKNOWN)
}

/// The doubt of `command` whose word `word` an expansion, brace expansion
/// or a glob may make any of its options, in `~/.zshrc`.
fn unread(command: &str, word: &str) -> String {
    format!(
        "it cannot tell what `{command}` in /home/alice/.zshrc does, as zsh may expand `{word}` \
         into any of its options"
    )
}

#[test]
fn a_typeset_option_past_a_number_is_read_as_zsh_reads_it() {
    // zsh 5.9 to 5.9.2 take the word after a letter that takes a number as
    // that number and read the options on past it, so each of these sets
    // the parameters the pattern matches: histchars, after which the line
    // that starts with `#` runs, HOME, FPATH and TTY.
    for line in [
        "typeset -L 3 -m 'histchar?=!^%'",
        "declare -Z 3 -m 'histchar?=!^%'",
        "zmodload zsh/param/private; private -L 3 -m 'histchar?=!^%'",
        "typeset -L 2 -m 'HOM?=h2'",
        "typeset -L 2 -m 'FPAT?=zf'",
        "typeset -L 3 -m 'T?Y=.zl'",
        "typeset -Lt 3 -m 'HOM?=h2'",
        "typeset -L3 -m 'HOM?=h2'",
        "typeset -i 16 -E 2 -m 'HOM?=h2'",
    ] {
        let found = found("", &format!("{line}\n#x; setopt share_history\n"));
        assert!(
            found.doubts.iter().any(|doubt| doubt.ends_with(
                "in /home/alice/.zshrc sets, as with -m zsh sets each one a pattern of it matches"
            )),
            "{line}: {found:?}"
        );
    }
    // A tie past a number: zsh 5.9 to 5.9.2 read the files in `~/h2x`.
    let found_tie = found("typeset -Z 3 -T ZDOTDIR zd\nzd=(h2x)\n", "");
    assert_eq!(
        found_tie.doubts,
        [
            "it cannot follow the value of `ZDOTDIR`, which `typeset -Z 3 -T ZDOTDIR zd` in \
          /home/alice/.zshenv ties to another name, by which zsh sets it too"
        ]
    );
    // `private` takes no number after `-p`, so the options end there, and
    // `local`, `export`, `readonly`, `integer` and `float` refuse `-m`.
    for line in [
        "zmodload zsh/param/private; private -p 3 -m 'HOM?=/x'",
        "local -L 3 -m 'HOM?=/x'",
        "typeset -L 3 x=1",
    ] {
        assert_eq!(found("", &format!("{line}\n")), Scan::default(), "{line}");
    }
}

#[test]
fn an_option_an_expansion_may_make_of_any_typeset_is_a_doubt() {
    // zsh 5.9 to 5.9.2 expand each word before the builtin reads its
    // options: with `o=m`, `private -$o 'HOM?=/x'` sets HOME.
    for (line, word) in [
        ("private -$o 'HOM?=/x'", "-$o"),
        ("local -$o x", "-$o"),
        ("export $o x", "$o"),
        ("integer {-m,x} y", "{-m,x}"),
        ("float \"-$o\" x", "-$o"),
        ("readonly $o x", "$o"),
        ("declare -$o 'T?Y=/x'", "-$o"),
        ("typeset -L $n -m x", "$n"),
        ("typeset -L 3 $o x", "$o"),
    ] {
        let found = found("", &format!("o=m\n{line}\n"));
        let (command, _) = line.split_once(' ').unwrap();
        let words = line.replace(['\'', '"'], "");
        assert!(
            found.doubts.contains(&unread(&words, word)),
            "{line}: {found:?} {command}"
        );
    }
}

#[test]
fn a_name_an_expansion_brace_expansion_or_a_glob_makes_is_a_doubt() {
    // zsh 5.9 to 5.9.2 set ZDOTDIR with each of these, or take it away.
    for line in [
        "typeset {ZDOT,}DIR=/home/alice/zd",
        "export {ZDOT,}DIR=/home/alice/zd",
        "typeset -g {ZDOT,}DIR=/home/alice/zd",
    ] {
        let found = found(&format!("{line}\n"), "");
        assert!(
            found
                .doubts
                .iter()
                .any(|doubt| doubt.contains("{ZDOT,}DIR=/home/alice/zd`")),
            "{line}: {found:?}"
        );
    }
    for (zshenv, doubt) in [
        (
            "typeset -g -- {ZDOT,}DIR=/home/alice/zd",
            "it cannot tell which parameter `typeset {ZDOT,}DIR=/home/alice/zd` in \
             /home/alice/.zshenv sets",
        ),
        (
            "ZDOTDIR=~/.zd; unset {ZDOT,}DIR",
            "it cannot tell which parameter `unset {ZDOT,}DIR` in /home/alice/.zshenv takes \
             away",
        ),
        (
            "read -r {ZDOT,}DIR < ~/.dir",
            "it cannot tell which parameter `read {ZDOT,}DIR` in /home/alice/.zshenv sets",
        ),
        (
            "print -rv{ZDOT,ZDOT}DIR /home/alice/zd",
            "it cannot tell which parameter `print -rv{ZDOT,ZDOT}DIR` in /home/alice/.zshenv \
             sets",
        ),
        // A word that may give none moves the name to another place.
        (
            "getopts $none a ${n}DIR",
            "it cannot tell which parameter `getopts ${n}DIR` in /home/alice/.zshenv sets",
        ),
    ] {
        let found = found(&format!("{zshenv}\n"), "");
        assert!(
            found.doubts.contains(&doubt.to_string()),
            "{zshenv}: {found:?}"
        );
    }
    // A glob in a value makes no name, and a word that gives the name's place
    // no other word moves none.
    for rc in [
        "typeset x=*.c\n",
        "getopts $spec opt\n",
        "getopts ab opt $x $y\n",
    ] {
        assert_eq!(found("", rc), Scan::default(), "{rc}");
    }
}

#[test]
fn an_unset_that_may_take_away_a_parameter_the_check_reads_is_a_doubt() {
    // zsh 5.9 to 5.9.2 take ZDOTDIR away with each and read the user's
    // files in the home.
    for (line, doubt) in [
        (
            "unset -m 'ZDOTDI?'",
            "it cannot tell which parameters `unset -m ZDOTDI?` in /home/alice/.zshenv takes \
             away, as its pattern may match one the check reads",
        ),
        (
            "unset -m '(ZDOTDIR|x)'",
            "it cannot tell which parameters `unset -m (ZDOTDIR|x)` in /home/alice/.zshenv \
             takes away, as its pattern may match one the check reads",
        ),
        (
            "unset -vm '*'",
            "it cannot tell which parameters `unset -m *` in /home/alice/.zshenv takes away, as \
             its pattern may match one the check reads",
        ),
        (
            "unset -m ZDOT*",
            "it cannot tell which parameters `unset -m ZDOT*` in /home/alice/.zshenv takes away, \
             as its pattern may match one the check reads",
        ),
        (
            "unset -m $p",
            "it cannot tell what `unset -m $p` in /home/alice/.zshenv does, as zsh may expand \
             `$p` into any of its options",
        ),
        (
            "unset -m -- $p",
            "it cannot tell which parameters `unset -m $p` in /home/alice/.zshenv takes away, as \
             its pattern may match one the check reads",
        ),
        (
            "unset $n",
            "it cannot tell what `unset $n` in /home/alice/.zshenv does, as zsh may expand `$n` \
             into any of its options",
        ),
        (
            "unset -- $n",
            "it cannot tell which parameter `unset $n` in /home/alice/.zshenv takes away",
        ),
        (
            "unset -$o ZDOTDI?",
            "it cannot tell what `unset -$o ZDOTDI?` in /home/alice/.zshenv does, as zsh may \
             expand `-$o` into any of its options",
        ),
        // A `]` a backslash keeps in a class, as zsh's tokenizer does.
        (
            "unset -m 'ZDOTDI[\\]R]'",
            "it cannot tell which parameters `unset -m ZDOTDI[\\]R]` in /home/alice/.zshenv \
             takes away, as its pattern may match one the check reads",
        ),
        (
            "unset -m '[\\]Z]DOTDIR'",
            "it cannot tell which parameters `unset -m [\\]Z]DOTDIR` in /home/alice/.zshenv \
             takes away, as its pattern may match one the check reads",
        ),
    ] {
        let found = found(&format!("ZDOTDIR=~/.zd\n{line}\n"), "");
        assert!(
            found.doubts.contains(&doubt.to_string()),
            "{line}: {found:?}"
        );
    }
    // A pattern that matches none the check reads, functions and names as
    // written are none.
    for line in [
        "unset -m 'POWERLEVEL9K_*'",
        "unset -m '(POWERLEVEL9K_*|DEFAULT_USER)~POWERLEVEL9K_GITSTATUS_DIR'",
        "unset -fm 'ZDOT*'",
        "unset -f $n",
        "unset x 'y[1]'",
    ] {
        assert_eq!(found("", &format!("{line}\n")), Scan::default(), "{line}");
    }
}

#[test]
fn a_builtin_whose_option_an_expansion_may_make_is_a_doubt() {
    // zsh 5.9.2 sets ZDOTDIR with each, as it reads the options of a
    // builtin after it expands its words: `print -vZDOTDIR`, `printf -v
    // ZDOTDIR`, `zstyle -s`.
    for (line, word) in [
        ("f=-vZDOT; print ${f}DIR /home/alice/zd", "${f}DIR"),
        (
            "print {-vZDOT,-vZDOT}DIR /home/alice/zd",
            "{-vZDOT,-vZDOT}DIR",
        ),
        ("f=-v; n=ZDOT; printf $f ${n}DIR /home/alice/zd", "$f"),
        ("print -f %s $x", "$x"),
        ("zstyle $o :x y ZDOTDIR", "$o"),
        ("zmodload zsh/datetime; strftime $o x 0", "$o"),
    ] {
        let found = found(&format!("{line}\n"), "");
        let (_, rest) = line.rsplit_once("; ").unwrap_or(("", line));
        let (command, _) = rest.split_once(' ').unwrap();
        let doubt = format!(
            "it cannot tell which parameter `{command} {word}` in /home/alice/.zshenv sets"
        );
        assert!(found.doubts.contains(&doubt), "{line}: {found:?}");
    }
    // Past `--`, or a word that starts otherwise, the options end.
    for rc in [
        "print -r -- $x\n",
        "print -rn -- \"$x\"\n",
        "printf '%s\\n' \"$x\"\n",
        "print -P '%F{red}x%f'\n",
        "print hello $USER\n",
        "print -fv x\n",
    ] {
        assert_eq!(found("", rc), Scan::default(), "{rc}");
    }
}

#[test]
fn an_attribute_of_a_parameter_whose_value_the_check_follows_is_a_doubt() {
    // zsh 5.9 to 5.9.2 expand ZDOTDIR in lower case after `typeset -l`, and
    // keep the first value after `readonly`, which ends the file at the next
    // assignment.
    for (zshenv, name, command) in [
        (
            "ZDOTDIR=$HOME/ZD\ntypeset -l ZDOTDIR\n. $ZDOTDIR/rc",
            "ZDOTDIR",
            "typeset -l ZDOTDIR",
        ),
        (
            "ZDOTDIR=~/.zd\nreadonly ZDOTDIR\nZDOTDIR=~/.ze",
            "ZDOTDIR",
            "readonly ZDOTDIR",
        ),
        (
            "typeset -u XDG_CONFIG_HOME",
            "XDG_CONFIG_HOME",
            "typeset -u XDG_CONFIG_HOME",
        ),
        (
            "typeset -L 12 NIX_PROFILES",
            "NIX_PROFILES",
            "typeset -L 12 NIX_PROFILES",
        ),
        ("typeset -gr fpath", "fpath", "typeset -gr fpath"),
    ] {
        let found = found(&format!("{zshenv}\n"), "");
        let doubt = format!(
            "it cannot follow the value of `{name}` that `{command}` in /home/alice/.zshenv \
             gives an attribute, which may change what zsh expands it to or keep a later \
             assignment from setting it"
        );
        assert!(found.doubts.contains(&doubt), "{zshenv}: {found:?}");
    }
    // Uniqueness, export and scope change neither.
    for zshenv in [
        "typeset -U fpath",
        "typeset -gaU fpath",
        "export ZDOTDIR=~/.zd",
        "typeset -gx XDG_CONFIG_HOME",
    ] {
        let found = found(&format!("{zshenv}\n"), "");
        assert!(
            !found
                .doubts
                .iter()
                .any(|doubt| doubt.contains("gives an attribute")),
            "{zshenv}: {found:?}"
        );
    }
}
