// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The list of the commands the check knows to be harmless, each read by
//! its name and every word ([`super`]).

use super::{Verdict, command, option, parameter};
use crate::preflight::checks::incremental_history_flush::zsh::lexer::Word;

fn words(text: &str) -> Vec<Word> {
    text.split_whitespace()
        .map(|text| Word {
            text: text.to_string(),
            expands: text.contains('$'),
            ..Word::default()
        })
        .collect()
}

fn verdict(line: &str) -> Verdict {
    let mut all = words(line);
    let name = all.remove(0);
    command(&name.text, &all, super::How::default())
}

#[test]
fn the_list_holds_the_harmless_forms_of_the_builtins_alone() {
    for line in [
        ": x",
        "true",
        "print -r -- $x",
        "print -n x",
        "echo $x",
        "printf %s x",
        "setopt hist_ignore_dups NO_BEEP",
        "unsetopt zle",
        "set -o vi",
        "set -A arr a b",
        "set -- a b",
        "emulate -L zsh",
        "emulate sh -c x",
        "typeset -gx A=1",
        "local -a x",
        "unset x",
        "eval x",
        "autoload -Uz compinit",
        "bindkey -e",
        "bindkey -v",
        "bindkey -L",
        "zle -l",
        "fc -l",
        "fc -lnr -20",
        "fc -AI",
        "fc -W",
        "fc -R",
        "history",
        "history -p",
        "typeset --fu f",
        "export PATH=$PATH",
        "kill -l",
        "hash -d src=/src",
        "hash -r",
        "zstyle :x y z",
        "zstyle -e :x y z",
        "zstyle -t :x y",
        "functions -c a b",
        "trap x INT",
    ] {
        assert_eq!(verdict(line), Verdict::Known, "{line}");
    }
    for line in [
        "print -z exit",
        "print -s x",
        "print $o x",
        "printf -v x y",
        "printf $o",
        "setopt $o",
        "setopt -m 'x*'",
        "setopt no_such_option",
        "set -e",
        "set -o csh_junkie_loops",
        "emulate csh",
        "emulate -o cshjunkieloops zsh",
        "typeset $o x",
        "unset -f x",
        "eval $x",
        "bindkey w beginning-of-history",
        "bindkey -s x y",
        "bindkey -A emacs main",
        "zle -N w",
        "zle .accept-line",
        "fc -e - x",
        "fc -s",
        "fc",
        "r",
        "kill -HUP $$",
        "kill 1234",
        "hash sudo=/x",
        "zstyle -s :x y name",
        "functions -M f",
        "trap $x INT",
        "read x",
        "vared x",
        "zmodload zsh/zpty",
        "disable print",
        "unfunction f",
        "unalias a",
        "ttyctl -f",
        "echoti smkx",
        "sched +1 x",
        "zcompile x",
        "/usr/bin/stty eof ^M",
        "coproc x",
    ] {
        assert!(
            matches!(verdict(line), Verdict::Unknown(_)),
            "{line}: {:?}",
            verdict(line)
        );
    }
    for line in [
        "stty eof ^M",
        "sh -c x",
        "perl -e x",
        "my-function x",
        "zpty x y",
    ] {
        assert_eq!(verdict(line), Verdict::Named, "{line}");
    }
}

#[test]
fn a_function_named_like_a_typed_command_may_run_its_own_program() {
    let how = super::How {
        function: Some("sudo"),
        ..super::How::default()
    };
    assert_eq!(command("sudo", &words("$@"), how), Verdict::Known);
    assert_eq!(command("sudo", &[], how), Verdict::Known);
    let outside = super::How {
        outside: true,
        ..how
    };
    assert_eq!(command("sudo", &words("$@"), outside), Verdict::Known);
    assert_eq!(command("sudo", &words("-E $@"), how), Verdict::Named);
    assert!(matches!(
        command("sudo", &words("-E $@"), outside),
        Verdict::Unknown(_)
    ));
}

#[test]
fn every_option_but_csh_s_loops_is_on_the_list() {
    for name in [
        "share_history",
        "NO_HUP",
        "noBeep",
        "promptsubst",
        "nomatch",
        "nonomatch",
        "errexit",
        "NO_ERR_EXIT",
    ] {
        assert_eq!(option(name), None, "{name}");
    }
    for name in ["csh_junkie_loops", "NOCSHJUNKIELOOPS", "noexist"] {
        assert!(option(name).is_some(), "{name}");
    }
}

#[test]
fn a_parameter_of_zsh_s_own_is_on_the_list_where_it_steers_nothing_the_check_reads() {
    for name in [
        "HISTFILE", "PATH", "my_var", "ZDOTDIR", "PS1", "TMOUT", "BUFFER",
    ] {
        assert_eq!(parameter(name, false), None, "{name}");
    }
    for name in [
        "histchars",
        "STTY",
        "POSTEDIT",
        "KEYBOARD_HACK",
        "commands",
        "UID",
    ] {
        assert!(parameter(name, false).is_some(), "{name}");
    }
    for name in ["HISTNO", "BUFFER", "LBUFFER", "CURSOR", "MARK"] {
        assert!(parameter(name, true).is_some(), "{name}");
    }
}
