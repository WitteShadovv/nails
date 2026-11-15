// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The startup code the check reads keeps to the list of the commands it
//! knows to be harmless ([`super::super::known`]): any other command, where
//! zsh may run it, is a doubt ([`super::super::reached`]).

use super::*;

/// The doubts of `rc` as `~/.zshrc`, beside the files `more` holds, every
/// doubt among them.
fn doubts(rc: &str, more: &[(&str, &str)]) -> Vec<String> {
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", rc);
    for (path, text) in more {
        seed(&fs, path, text);
    }
    scan_all(&fs, UNKNOWN).doubts
}

/// Whether `rc` as `~/.zshrc` runs a command the list does not hold where
/// zsh may run it.
fn unlisted(rc: &str) -> bool {
    doubts(rc, &[]).iter().any(|doubt| super::unlisted(doubt))
}

#[test]
fn every_false_pass_of_the_last_verify_is_a_doubt() {
    // zsh 5.9 to 5.9.2 wrote the typed lines with each: a widget that sets
    // HISTNO runs a history line, an alias of kill signals the shell, the
    // code a shell is given starts a job that signals it, a program leaves a
    // process that does, a key typed runs a history widget, and `stty eof`
    // makes a key typed end the shell.
    for rc in [
        "my-accept() { [[ $BUFFER == *two* ]] && HISTNO=1; zle .accept-line }\n\
         zle -N accept-line my-accept\n",
        "my-accept() { [[ $BUFFER == *two* ]] && (( HISTNO = 1 )); zle .accept-line }\n\
         zle -N accept-line my-accept\n",
        "zle-line-init() { [[ $armed == 1 ]] && { HISTNO=1; zle .accept-line }; armed=1 }\n\
         zle -N zle-line-init\n",
        "zle-line-finish() { [[ $BUFFER == *two* ]] && HISTNO=1 }\nzle -N zle-line-finish\n",
        "f() { HISTNO=1 }\nmy-accept() { [[ $BUFFER == *two* ]] && f; zle .accept-line }\n\
         zle -N accept-line my-accept\n",
        "my-si() { [[ $KEYS == w ]] && { HISTNO=1; zle .accept-line; return }; zle .self-insert }\n\
         zle -N self-insert my-si\n",
        "bindkey w beginning-of-history\n",
        "alias k=kill\n( repeat 1500000 :; k -HUP $$ ) &!\n",
        "alias kh='kill -HUP'\n( repeat 1500000 :; kh $$ ) &!\n",
        "alias k=kill\npreexec() { [[ $1 == *two* ]] && k -HUP $$ }\n",
        "alias kh='kill -HUP'\npreexec() { [[ $1 == *two* ]] && kh $$ }\n",
        "alias k=kill\nprecmd() { [[ $armed == 1 ]] && k -HUP $$; armed=1 }\n",
        "alias k=kill\nzle-line-init() { [[ $armed == 1 ]] && k -HUP $$; armed=1 }\n\
         zle -N zle-line-init\n",
        "sh -o errexit -c '(sleep 3; kill -HUP $PPID) >/dev/null 2>&1 &'\n",
        "bash -O extglob -c '(sleep 3; kill -HUP $PPID) >/dev/null 2>&1 &'\n",
        "bash --rcfile /dev/null -c '(sleep 3; kill -HUP $PPID) >/dev/null 2>&1 &'\n",
        "bash -c -o errexit '(sleep 3; kill -HUP $PPID) >/dev/null 2>&1 &'\n",
        "bash -c 'coproc { sleep 3; kill -HUP $PPID; }'\n",
        "alias s=sh\ns -c '(sleep 3; kill -HUP $PPID) >/dev/null 2>&1 &'\n",
        "alias b=bash\nb -c '(sleep 3; kill -HUP $PPID) >/dev/null 2>&1 &'\n",
        "sh <<'EOF'\n(sleep 3; kill -HUP $PPID) >/dev/null 2>&1 &\nEOF\n",
        "sh -s <<< '(sleep 3; kill -HUP $PPID) >/dev/null 2>&1 &'\n",
        "env sh -c '(sleep 3; kill -HUP $PPID) >/dev/null 2>&1 &'\n",
        "nice sh -c '(sleep 3; kill -HUP $PPID) >/dev/null 2>&1 &'\n",
        "timeout 20 sh -c \"(sleep 3; kill -HUP $$) >/dev/null 2>&1 &\"\n",
        "env setsid -f sh -c \"sleep 3; kill -HUP $$\" >/dev/null 2>&1\n",
        "perl -e '$p = getppid(); exit if fork; sleep 3; kill \"HUP\", $p' >/dev/null 2>&1\n",
        "~/.local/bin/later\n",
        "stty eof '^M'\n",
    ] {
        assert!(unlisted(rc), "{rc}");
    }
}

#[test]
fn what_the_list_holds_passes() {
    // What most startup files hold but completion, a prompt's code and an
    // outside program: none of it may end the shell, run another line than
    // the one typed or change the terminal.
    for rc in [
        "",
        "HISTFILE=~/.zsh_history\nHISTSIZE=10000\nSAVEHIST=10000\n",
        "export PATH=$HOME/bin:$PATH\nexport EDITOR=vim LANG=C.UTF-8\npath+=(~/.cargo/bin)\n",
        "setopt hist_ignore_dups hist_ignore_space extended_history auto_cd\n\
         unsetopt beep\nset -o vi\n",
        "bindkey -e\n",
        "bindkey -v\nKEYTIMEOUT=1\n",
        "alias ll='ls -l'\nalias gs='git status'\n",
        "mkcd() { mkdir -p \"$1\" && cd \"$1\" }\n",
        "zstyle ':completion:*' menu select\n",
        "PS1='%n@%m %~ %# '\nRPROMPT='%T'\n",
        "typeset -U path\ntypeset -gx PAGER=less\nlocal_var=1\nunset local_var\n",
        "precmd() { print -Pn '\\e]0;%~\\a' }\n",
        "[[ -f ~/.zshrc.local ]] && source ~/.zshrc.local\n",
        "for o in hist_ignore_dups auto_pushd; do setopt $o; done\n",
        "emulate -L zsh\ncd ~\n",
        "fc -l -10\nhistory\n",
        "f() { print -r -- hi }\nf\n",
        "if [[ -o interactive ]]; then print -r -- welcome; fi\n",
    ] {
        assert_eq!(doubts(rc, &[]), Vec::<String>::new(), "{rc}");
    }
}

#[test]
fn a_name_runs_the_function_the_files_certainly_define_before_it_runs() {
    // Defined before it at the top level of the same reading of its file,
    // or of a file that sources that one: zsh stops a file at an error or a
    // `return` before both. An alias stands for a name with no quote in it
    // past a reserved word too, and a function for any.
    for (rc, more) in [
        ("f() { : }\nf\n", &[][..]),
        ("function f { : }\nf x\n", &[][..]),
        (
            "f() { : }\nsource ~/.f.zsh\n",
            &[("/home/alice/.f.zsh", "f\n")][..],
        ),
        ("helper() { : }\nprecmd() { helper }\n", &[][..]),
        ("f() { : }\ng() { f }\ng\n", &[][..]),
        ("alias e=echo\ne hi\n", &[][..]),
        ("alias q=:\nq x\n", &[][..]),
        ("alias q=:\nnocorrect q\n! q\n", &[][..]),
        ("f() { : }\nnoglob f\n\\f\n'f'\n", &[][..]),
        ("[[ -n $x ]] || true\nf() { : }\nf\n", &[][..]),
    ] {
        assert_eq!(doubts(rc, more), Vec::<String>::new(), "{rc}");
    }
    // Defined after it, where it may not be, or in another file: zsh runs
    // an outside program of that name then, as zsh 5.9 to 5.9.2 did where an
    // error stopped the file of the definition before it (a glob that
    // matches nothing). An alias whose value ends with a command that takes
    // the words it is used with otherwise hands them to it.
    for (rc, more) in [
        ("f\nf() { : }\n", &[][..]),
        ("precmd() { helper }\nhelper() { : }\n", &[][..]),
        (
            "precmd() { helper }\n: ~/no-such-*\nhelper() { : }\n",
            &[][..],
        ),
        (
            "source ~/.f.zsh\nf\n",
            &[("/home/alice/.f.zsh", "f() { : }\n")][..],
        ),
        (
            "source ~/.f.zsh\nf\n",
            &[("/home/alice/.f.zsh", ": ~/no-such-*\nf() { : }\n")][..],
        ),
        ("f\n", &[("/home/alice/.zshenv", "f() { : }\n")][..]),
        ("eval 'f() { : }'\nf\n", &[][..]),
        ("eval ': ~/no-such-*; f() { : }'\nf\n", &[][..]),
        ("f() { : } &\nf\n", &[][..]),
        ("f() { : } | :\nf\n", &[][..]),
        ("alias q=:\n\\q\n", &[][..]),
        ("alias q=:\n'q'\n", &[][..]),
        ("alias q=:\nnoglob q\n", &[][..]),
        ("alias q=:\n- q\n", &[][..]),
        // A copy of a function zsh does not have defines none, and the stock
        // add-zsh-hook returns before it autoloads at a hook off its list.
        ("functions -c nosuch f\nf\n", &[][..]),
        (
            "autoload -Uz add-zsh-hook\nadd-zsh-hook prexec f\nf\n",
            &[][..],
        ),
        ("trap ':' INT\nTRAPINT\n", &[][..]),
        ("if [[ -n $x ]]; then f() { : }; fi\nf\n", &[][..]),
        ("[[ -n $x ]] && f() { : }\nf\n", &[][..]),
        ("( f() { : } )\nf\n", &[][..]),
        ("a() { b }\na\nb() { : }\n", &[][..]),
        ("precmd() { helper }\nreturn\nhelper() { : }\n", &[][..]),
        (
            "[[ -n $x ]] && source ~/.f.zsh\nf\n",
            &[("/home/alice/.f.zsh", "f() { : }\n")][..],
        ),
        (
            "source ~/.f.zsh\nf\n",
            &[("/home/alice/.f.zsh", "return\nf() { : }\n")][..],
        ),
        ("alias p=print\np -z exit\n", &[][..]),
        ("alias h=history\nh -P\n", &[][..]),
        ("alias hd=hash\nhd sudo=/tmp/x\n", &[][..]),
        ("x=$(f() { : })\nf\n", &[][..]),
        ("my-tool init\n", &[][..]),
    ] {
        let found = doubts(rc, more);
        assert!(
            found.iter().any(|doubt| super::unlisted(doubt)),
            "{rc}: {found:?}"
        );
    }
}

#[test]
fn a_parameter_the_line_editor_or_the_history_reads_is_a_doubt() {
    for rc in [
        "export STTY\n(( STTY = 0 ))\n",
        "let STTY=0\n",
        "(( histchars = 33 ))\n",
        "(( FPATH = 1 ))\n",
        "(( n = 1, TRY_BLOCK_ERROR = 0 ))\n",
        "w() { HISTNO=1 }\nprecmd() { w }\n",
        "precmd() { (( HISTNO = 1 )) }\n",
        "precmd() { for HISTNO in 1; do :; done }\n",
        "precmd() { : ${HISTNO::=1} }\n",
        "precmd() { local CURSOR=0 }\n",
        "precmd() { BUFFER=exit }\n",
        "histchars='e^#'\n",
        "STTY='eof ^M'\n",
        "POSTEDIT=$'\\e[?1l'\n",
        "zle_bracketed_paste=(x y)\n",
        "commands[sudo]=/tmp/x\n",
        "KEYBOARD_HACK=x\n",
    ] {
        assert!(unlisted(rc), "{rc}");
    }
    // Out of a function no widget runs, so the line editor's are the user's
    // own there; arithmetic may set the user's own and the harmless ones.
    assert!(!unlisted("HISTNO=1\nCURSOR=0\n"));
    assert!(!unlisted(
        "(( n = 1, SAVEHIST = 100, OPTIND = 1 ))\n(( EUID == 0 )) && print root\n"
    ));
}

#[test]
fn an_option_is_on_the_list_by_its_name_but_csh_s_loops() {
    // zsh 5.9 to 5.9.2 end as the typed `false` fails with ERR_EXIT on, and
    // write no history file then; with CSH_JUNKIE_LOOPS they read a loop's
    // body to an `end`, and a name that is no option is none they read.
    for rc in [
        "setopt err_exit\n",
        "set -o errexit\n",
        "options[errexit]=on\n",
        "emulate zsh -o errexit\n",
        "setopt no_beep auto_cd\n",
    ] {
        assert!(!unlisted(rc), "{rc}");
    }
    for rc in [
        "setopt csh_junkie_loops\n",
        "unsetopt no_csh_junkie_loops\n",
        "options[cshjunkieloops]=on\n",
        "options[$o]=on\n",
        "setopt no_such_option\n",
        "set -e\n",
    ] {
        assert!(unlisted(rc), "{rc}");
    }
    let argv =
        |words: &[&str]| -> Vec<String> { words.iter().map(|word| (*word).to_string()).collect() };
    for words in [
        &["zsh", "-o", "cshjunkieloops"][..],
        &["-zsh", "--csh-junkie-loops"],
    ] {
        assert!(
            !CommandLine::of(&argv(words)).doubts.is_empty(),
            "{words:?}"
        );
    }
    for words in [
        &["zsh"][..],
        &["zsh", "-f"],
        &["-zsh"],
        &["zsh", "-e"],
        &["zsh", "-t"],
    ] {
        assert!(CommandLine::of(&argv(words)).doubts.is_empty(), "{words:?}");
    }
}

#[test]
fn a_key_binding_a_widget_or_a_terminal_setting_is_a_doubt() {
    for rc in [
        "bindkey '^[[A' up-line-or-search\n",
        "bindkey -s '^o' 'lfcd\\n'\n",
        "bindkey -A viins main\n",
        "w() { : }\nzle -N w\n",
        "autoload -Uz add-zle-hook-widget\nw() { : }\nadd-zle-hook-widget line-init w\n",
        "ttyctl -f\n",
        "echoti smkx\n",
        "stty -ixon\n",
        "zmodload zsh/terminfo\n",
        "print -z exit\n",
        "read -r x\n",
        "kill -HUP $$\n",
        "exec zsh\n",
        "command ls\n",
        "coproc cat\n",
        "sched +1 :\n",
        "unalias run-help\n",
        "disable print\n",
    ] {
        assert!(unlisted(rc), "{rc}");
    }
}

#[test]
fn a_command_in_a_function_zsh_never_runs_is_none() {
    // A helper the operator may type is no hook: zsh never runs it as the
    // files run or a line is typed.
    for rc in [
        "up() { git pull && make }\n",
        "alias ll='ls -l'\n",
        "f() { stty sane }\n",
    ] {
        assert!(!unlisted(rc), "{rc}");
    }
    // As a hook, run from one, or named like the command a NAILS command is
    // typed with, it is a doubt.
    for rc in [
        "precmd() { git status --short }\n",
        "f() { stty sane }\nprecmd() { f }\n",
        "f() { stty sane }\nf\n",
        "sudo() { /usr/bin/sudo -E \"$@\" }\n",
        "alias sudo='sudo -E'\n",
        "TRAPHUP() { stty sane }\n",
    ] {
        assert!(unlisted(rc), "{rc}");
    }
    // One that runs the program of its own name with the words it is given
    // hands it what typing it would.
    for rc in ["sudo() { command sudo \"$@\" }\n", "alias sudo=sudo\n"] {
        assert!(!unlisted(rc), "{rc}");
    }
}
