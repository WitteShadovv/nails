// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A builtin's name that runs an outside program: after `command`, after
//! `disable`, and of a module zsh does not load as the name is first run.

use super::*;

#[test]
fn a_builtin_s_name_that_runs_an_outside_program_gets_the_line() {
    // zsh 5.9 to 5.9.2 hand the typed line to ~/bin/print, first in PATH,
    // which appends it to a file, in each.
    for rc in [
        "preexec() { command print -r -- \"$1\" }\n",
        "preexec() { command -p print -r -- \"$1\" }\n",
        "disable print\npreexec() { print -r -- \"$1\" }\n",
        "disable -m 'p[r]int'\npreexec() { print -r -- \"$1\" }\n",
        "disable -m 'pr*'\npreexec() { print -r -- \"$1\" }\n",
        "disable $b\npreexec() { print -r -- \"$1\" }\n",
        "preexec() { disable print; print -r -- \"$1\" }\n",
        "preexec() { strftime -s t %s \"$1\" }\n",
        "preexec() { stat \"$1\" }\n",
        "sudo() { command sudo logit \"$@\" }\n",
        "sudo() { command print -r -- \"$@\" }\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        let found = scan(&fs, UNKNOWN);
        assert!(!found.doubts.is_empty(), "{rc}: {found:?}");
    }
    // The builtin itself, one disable leaves alone (an alias, a function of
    // the name), `command -v`, and a wrapper that runs the program of its own
    // name with its words, as it would run without the function, are none.
    for rc in [
        "preexec() { builtin print -r -- \"$1\" }\n",
        "disable -a print\npreexec() { print -r -- \"$1\" }\n",
        "disable -f print\npreexec() { print -r -- \"$1\" }\n",
        "disable -r select\npreexec() { print -r -- \"$1\" }\n",
        "disable echo\npreexec() { print -r -- \"$1\" }\n",
        "preexec() { command -v print >/dev/null && print -r -- \"$1\" }\n",
        "sudo() { command sudo \"$@\" }\n",
        "man() { command man \"$@\" }\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
}
