// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The line a widget gives zsh to run: what its code sets the line editor's
//! line to, and the widgets of zsh's own it runs that put other text in it.

use super::*;

/// What the check finds of `rc` as `~/.zshrc`.
fn found(rc: &str) -> Scan {
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", rc);
    scan(&fs, UNKNOWN)
}

#[test]
fn a_line_a_widget_sets_that_may_end_the_shell_is_a_doubt() {
    // zsh 5.9 to 5.9.2 run the line the widget sets as the second line is
    // entered, end, and write the first.
    for rc in [
        "my-accept() { [[ $BUFFER == *two* ]] && BUFFER=exit; zle .accept-line }\n\
         zle -N accept-line my-accept\n",
        "my-accept() { [[ $BUFFER == *two* ]] && { LBUFFER=exit; RBUFFER= }; zle .accept-line }\n\
         zle -N accept-line my-accept\n",
        "my-accept() { [[ $BUFFER == *two* ]] && BUFFER=bye; zle .accept-line }\n\
         zle -N accept-line my-accept\n",
        "my-accept() { [[ $BUFFER == *two* ]] && BUFFER='kill -HUP $$'; zle .accept-line }\n\
         zle -N accept-line my-accept\n",
        "my-enter() { [[ $BUFFER == *two* ]] && BUFFER=exit; zle .accept-line }\n\
         zle -N my-enter\nbindkey '^M' my-enter\n",
        "zle-line-init() { [[ $armed == 1 ]] && { BUFFER=exit; zle .accept-line }; armed=1 }\n\
         zle -N zle-line-init\n",
        "c=exit\nzle-line-init() { [[ $armed == 1 ]] && { BUFFER=$c; zle .accept-line }; armed=1 }\n\
         zle -N zle-line-init\n",
        "zle-line-finish() { [[ $BUFFER == *two* ]] && BUFFER=exit }\nzle -N zle-line-finish\n",
        // Other ways to set the line, a line zsh expands history in, and a
        // widget that puts other text in it.
        "w() { BUFFER+=x }\nzle -N w\n",
        "w() { BUFFER[1,-1]=exit }\nzle -N w\n",
        "w() { read BUFFER < ~/.next }\nzle -N w\n",
        "w() { print -v BUFFER exit }\nzle -N w\n",
        "w() { : ${BUFFER::=exit} }\nzle -N w\n",
        "w() { BUFFER='!1'; zle .accept-line }\nzle -N w\n",
        "w() { zle .beginning-of-history; zle .accept-line }\nzle -N accept-line w\n",
        "w() { BUFFER='print exit'; CURSOR=0; zle .kill-word; zle .accept-line }\nzle -N w\n",
        "w() { BUFFER=exi; zle expand-or-complete; zle .accept-line }\nzle -N w\n",
        "u() { zle .yank }\nw() { u; zle .accept-line }\nzle -N w\n",
        "zle -A up-history self-insert\n",
        "zle-line-init() { zle vi-cmd-mode }\nzle -N zle-line-init\n",
        "zle-line-init() { zle -K vicmd }\nzle -N zle-line-init\n",
        "zle-line-init() { zle -U $'!1\\n' }\nzle -N zle-line-init\n",
        "zle-line-init() { zle -U '!1\n' }\nzle -N zle-line-init\n",
        "precmd() { print -z '!1' }\n",
        "bindkey -s '^X' '!1^M'\n",
    ] {
        assert_ne!(found(rc), Scan::default(), "{rc}");
    }
}

#[test]
fn a_widget_that_keeps_the_line_it_runs_or_runs_a_known_one_is_none() {
    // zsh 5.9 to 5.9.2 write nothing with these.
    for rc in [
        "my-accept() { zle .accept-line }\nzle -N accept-line my-accept\n",
        "ctrl-z() { BUFFER=fg; zle .accept-line }\nzle -N ctrl-z\nbindkey '^Z' ctrl-z\n",
        "f() { zle complete-word }\nzle -N zle-line-finish f\n",
        "f() { zle reset-prompt; zle -R }\nzle -N f\n",
        "f() { zle my-other }\nmy-other() { : }\nzle -N my-other\nzle -N f\n",
        "BUFFER=exit\n",
        "zle -A run-help logit\n",
        "zle -A .self-insert self-insert\n",
        "zle-line-init() { zle -K viins; zle .vi-insert }\nzle -N zle-line-init\n",
        "precmd() { print -z 'ls -l' }\n",
    ] {
        assert_eq!(found(rc), Scan::default(), "{rc}");
    }
}
