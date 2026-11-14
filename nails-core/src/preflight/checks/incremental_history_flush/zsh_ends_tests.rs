// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What may make a zsh end by itself, writing its history file as it ends,
//! before activation kills it: a hook that exits or signals the shell, and a
//! `TMOUT` above 0; and what a command substitution in a hook writes, from
//! the subshell it runs in.

use super::*;

/// Whether the check warns for `fs`.
fn warns(fs: &MockFilesystem) -> bool {
    scan(fs, UNKNOWN) != Scan::default()
}

#[test]
fn a_hook_that_may_end_the_shell_is_a_doubt() {
    // zsh 5.9 to 5.9.2 write the history file as these end the shell, the
    // line just typed in it, once a command is entered.
    for rc in [
        "preexec() { exit }\n",
        "preexec() { bye }\n",
        "precmd() { logout }\n",
        "q() { exit }\npreexec_functions+=(q)\n",
        "preexec() { kill -HUP $$ }\n",
        "preexec() { builtin kill -s HUP $$ }\n",
        "preexec() { /bin/kill -HUP $$ }\n",
        "preexec() { kill 0 }\n",
        "preexec() { kill -HUP $pid }\n",
        "preexec() { pkill -HUP -t pts/0 }\n",
        "preexec() { : $(kill -HUP $$) }\n",
        "preexec() { : $(exit) }\n",
        "precmd() { b=$(cd /nowhere 2>/dev/null || exit 1) }\n",
        "preexec() { ( exit ) }\n",
        "preexec() { exit | cat }\n",
        "preexec() { { exit } & }\n",
        "TRAPZERR() { exit }\npreexec() { false }\n",
        "trap 'exit' ZERR\npreexec() { false }\n",
        "trap 'return' INT\n",
        "TRAPINT() { exit }\n",
        "preexec() { exec zsh }\n",
        "preexec() { exec -a zsh zsh }\n",
        "alias q=exit\npreexec() { q }\n",
        "sudo() { exit }\n",
        "command_not_found_handler() { exit }\n",
        "w() { exit }\nzle -N w\nbindkey '^X' w\n",
        "zmodload zsh/sched\nsched +60 exit\n",
        "zshaddhistory() { [[ $1 == *nails* ]] && exit }\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        let found = scan(&fs, UNKNOWN);
        assert!(
            found
                .doubts
                .iter()
                .any(|doubt| doubt.contains("as it ends by itself")),
            "{rc}: {found:?}"
        );
    }
    // What ends no shell, or runs where no hook runs it, is none: zsh 5.9 to
    // 5.9.2 write nothing with these.
    for rc in [
        "q() { exit }\n",
        "setopt err_exit\npreexec() { false }\n",
        "preexec() { : $(return 1) }\n",
        "preexec() { : $(exec /bin/true) }\n",
        "preexec() { kill -HUP 1234 }\n",
        "preexec() { kill %1 }\n",
        "preexec() { kill -l }\n",
        "TRAPINT() { return 1 }\n",
        "precmd() { [[ -n $x ]] || return }\n",
        "preexec() { exec 2>/dev/null }\n",
        "[[ -o interactive ]] || exit\n",
        "[[ -x /usr/bin/fish ]] && exec fish\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
}

#[test]
fn a_tmout_above_0_is_a_doubt() {
    // zsh 5.9 to 5.9.2 end once a prompt has waited for the seconds TMOUT
    // holds, writing the history file as they end, the lines typed so far
    // in it.
    for rc in [
        "TMOUT=3\n",
        "export TMOUT=900\n",
        "readonly TMOUT=900\n",
        "typeset -i TMOUT=900\n",
        "TMOUT=$t\n",
        "TMOUT+=1\n",
        "(( TMOUT = 900 ))\n",
        ": ${TMOUT:=900}\n",
        "read TMOUT < ~/.tmout\n",
        "TMOUT=900\nTRAPALRM() { zle reset-prompt }\n",
        "precmd() { TMOUT=60 }\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert!(warns(&fs), "{rc}");
    }
    // 0 or nothing, and one declared or taken away, are none.
    for rc in [
        "TMOUT=0\n",
        "TMOUT=\n",
        "export TMOUT\n",
        "unset TMOUT\n",
        "print -r -- $TMOUT ${TMOUT:-0}\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
    // One the shell's environment holds is a doubt above 0.
    let fs = MockFilesystem::new();
    let tmout = |value: &str| {
        let install = Install::of(&fs, None, Some(&[("TMOUT".to_string(), value.to_string())]));
        zsh(&fs, &[PathBuf::from(HOME)], NOT_LOGIN, &install)
    };
    assert_eq!(
        tmout("900").doubts,
        [
            "it cannot tell whether zsh writes the history file as it ends by itself, as the \
             shell's environment sets TMOUT to `900`, after which zsh ends once a prompt has \
             waited that many seconds, and writes the file as it ends (`env -u TMOUT zsh -f` \
             starts one without it)"
        ]
    );
    assert_eq!(tmout("0"), Scan::default());
}

#[test]
fn what_a_command_substitution_writes_counts_as_the_hook_s() {
    // zsh 5.9.2 writes the line to the file each of these names, or appends
    // the history to HISTFILE, from the subshell of the substitution.
    for rc in [
        "preexec() { x=$(print -r -- $1 > $f) }\n",
        "preexec() { : $(print -u3 -r -- \"$1\") }\n",
        "preexec() { : \"$(print -r -- $1 >> ~/.log)\" }\n",
        "precmd() { : $(fc -AI) }\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert!(warns(&fs), "{rc}");
    }
    // In quotes zsh expands nothing in, it is text: none.
    for rc in [
        "print -r -- '$(print -r -- $1 > $f)'\n",
        ": ${x::='$(print -r -- $1 > $f)'}\n",
        "preexec() { print -r -- '$(cat > $f)' }\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
}
