// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What zsh writes or turns on as it runs that no word of the startup files
//! names as one of the three options: an `fc` that writes the history file.

use super::*;

#[test]
fn an_fc_that_writes_the_history_file_counts_as_a_write() {
    // zsh 5.9.2 writes each command line to HISTFILE from these hooks, with
    // none of the three options on.
    for (rc, shown) in [
        ("precmd() { fc -AI }\n", "fc -AI"),
        ("precmd() { fc -W }\n", "fc -W"),
        ("preexec() { fc -AI }\n", "fc -AI"),
        ("h() { fc -A -I }\nprecmd_functions+=(h)\n", "fc -A -I"),
        ("zshaddhistory() { fc -IA; return 0 }\n", "fc -IA"),
        ("TRAPDEBUG() { builtin fc -WI }\n", "fc -WI"),
        ("periodic() { \\fc -P }\n", "fc -P"),
        ("eval 'precmd() { fc -AI }'\n", "fc -AI"),
        (
            "if true; then precmd() { 'fc' -AI ~/.zsh_history; }; fi\n",
            "fc -AI",
        ),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(
            on(&fs, UNKNOWN),
            [format!("/home/alice/.zshrc names `{shown}`")],
            "{rc}"
        );
        assert_eq!(scan(&fs, UNKNOWN).doubts, Vec::<String>::new(), "{rc}");
    }
    // One whose words it cannot read, or that a line holds beyond the code
    // the check reads, is a doubt.
    let beyond = "it cannot follow an `fc` that a line of /home/alice/.zshrc may run, which \
                  can write the history file";
    for (rc, doubt) in [
        (
            "precmd() { fc $flags }\n",
            "it cannot tell whether `fc $flags` in /home/alice/.zshrc writes the history file",
        ),
        (
            "precmd() { fc -l $n }\n",
            "it cannot tell whether `fc -l $n` in /home/alice/.zshrc writes the history file",
        ),
        ("alias save='fc -AI'\nprecmd() { save }\n", beyond),
        ("sched +60 fc -W\n", beyond),
        ("precmd() { print -r -- fc -AI }\n", beyond),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        let found = scan(&fs, UNKNOWN);
        assert_eq!(found.writes, Vec::new(), "{rc}");
        assert_eq!(found.doubts, [doubt], "{rc}");
    }
    // One that reads or lists the history writes nothing.
    for rc in [
        "fc -R\n",
        "alias h='fc -l 1'\n",
        "fc -l -10\n",
        "fc-list : family\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
}
