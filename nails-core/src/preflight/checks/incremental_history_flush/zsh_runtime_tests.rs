// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What zsh writes or turns on as it runs that no word of the startup files
//! names as one of the three options: an `fc` that writes the history file,
//! a name that brace expansion makes, one that an expansion makes, and code
//! that a glob qualifier runs.

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

#[test]
fn a_name_that_brace_expansion_makes_counts() {
    // Each names SHARE_HISTORY once zsh has expanded its words, which counts
    // as on, as any mention does; zsh 5.9.1 runs the first five with it on.
    for line in [
        "setopt {share,inc_append}_history",
        "set -o {share,incappend}history",
        "setopt share_histor{y,x}",
        "setopt braceccl; setopt sharehistor{y}",
        "setopt share_histor{x..y}",
        "for o in {share,inc_append}_history; do setopt $o; done",
        "opts=(no_{share,inc_append}_history); for o in $opts; do setopt $o; done",
        "alias s='setopt {share,inc_append}_history'",
        // An option's name after `-o` in a word of flags.
        "set -oshare_history",
        "set -xoshare_history",
        "emulate zsh -o share_history",
        "emulate zsh -c 'setopt share_history'",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{line}\n"));
        assert!(
            on(&fs, UNKNOWN).contains(&"/home/alice/.zshrc names SHARE_HISTORY".to_string()),
            "{line}: {:?}",
            scan(&fs, UNKNOWN)
        );
    }
}

#[test]
fn an_option_whose_name_an_expansion_makes_is_a_doubt() {
    let doubt =
        |what: &str| format!("it cannot tell which options `{what}` in /home/alice/.zshrc sets");
    let emulate =
        |what: &str| format!("it cannot tell what `emulate {what}` in /home/alice/.zshrc turns on");
    let parameter =
        |what: &str| format!("it cannot tell which parameter `{what}` in /home/alice/.zshrc sets");
    for (line, expected) in [
        ("options[$o]=on", doubt("options[$o]=on")),
        ("options[${(j::)a}]=on", doubt("options[${(j::)a}]=on")),
        ("options[${o}y]=on", doubt("options[${o}y]=on")),
        ("typeset -g \"options[$o]=on\"", doubt("options[$o]=on")),
        ("options=($k on)", doubt("options=(... $k ...)")),
        ("read -A options < ~/.opts", doubt("options")),
        ("set -A options $k on", doubt("options")),
        ("emulate zsh -o $o", emulate("-o $o")),
        ("emulate zsh $flags", emulate("$flags")),
        ("emulate zsh -c \"$code\"", emulate("-c $code")),
        ("typeset -g \"$name=on\"", parameter("typeset $name=on")),
        ("print -v \"$name\" on", parameter("print $name")),
        ("read -r \"$name\" <<< on", parameter("read $name")),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{line}\n"));
        let found = scan(&fs, UNKNOWN);
        assert!(found.doubts.contains(&expected), "{line}: {found:?}");
    }
}

#[test]
fn a_glob_qualifier_that_runs_code_is_a_doubt() {
    let doubt = |word: &str| {
        format!(
            "it cannot follow the code that a glob qualifier in `{word}` in /home/alice/.zshrc runs"
        )
    };
    for (line, word) in [
        (
            "x=(~/.z*(Ne:'setopt sha''re_history':))",
            "~/.z*(Ne:'setopt sha''re_history':)",
        ),
        ("print ~/.z*(e'setopt x')", "~/.z*(e'setopt x')"),
        ("for f in ~/.z*(+func); do :; done", "~/.z*(+func)"),
        ("ls *(#qe{true})", "*(#qe{true})"),
        ("y=$(print *(N.e:'true':))", "y=$(print *(N.e:'true':))"),
        ("cat < ~/.z*(e:'true':)", "~/.z*(e:'true':)"),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{line}\n"));
        let found = scan(&fs, UNKNOWN);
        assert!(found.doubts.contains(&doubt(word)), "{line}: {found:?}");
    }
    // Arithmetic, and a pattern's alternatives or qualifiers without code,
    // are no such qualifier, and a common matcher's braces name no option.
    for line in [
        "zstyle ':completion:*' matcher-list 'm:{a-zA-Z}={A-Za-z}' 'r:|[._-]=* r:|=*'",
        "HISTSIZE=$((SAVEHIST+1000))",
        "x=$(( (a+b) * 2 ))",
        "for f in ~/.zsh/(aliases|functions).zsh; do :; done",
        "print -l ~/.z*(N.om[1,3])",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{line}\n"));
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{line}");
    }
}
