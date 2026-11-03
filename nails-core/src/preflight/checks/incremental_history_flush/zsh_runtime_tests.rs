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
            "if true; then precmd() { 'fc' -AI ~/.zsh_lines; }; fi\n",
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
        ("precmd() { print -r -- fc -AI }\n", beyond),
        (
            "zle -N fc-widget; bindkey '^X' fc-widget; print fc -W\n",
            beyond,
        ),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        let found = scan(&fs, UNKNOWN);
        assert_eq!(found.writes, Vec::new(), "{rc}");
        assert_eq!(found.doubts, [doubt], "{rc}");
    }
    // One that reads or lists the history writes nothing.
    for rc in ["fc -R\n", "fc -l -10\n", "fc-list : family\n"] {
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
        "(( ${+commands[git]} )) && print git",
        "for (( i = 0; i < ${+x}; i++ )) { : }",
        "x=$(( (a+b) * 2 ))",
        "for f in ~/.zsh/(aliases|functions).zsh; do :; done",
        "print -l ~/.z*(N.om[1,3])",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{line}\n"));
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{line}");
    }
}

#[test]
fn emulate_r_ksh_turns_share_history_on() {
    // zsh 5.9.1: `-R` resets every option to the mode's defaults, and ksh's
    // hold SHARE_HISTORY; sh's, csh's and zsh's hold none of the three, and a
    // plain `emulate ksh` changes no history option.
    let turned = "/home/alice/.zshrc runs `emulate -R ksh`, whose reset to ksh's defaults turns \
                  on SHARE_HISTORY";
    for rc in [
        "emulate -R ksh\n",
        "emulate -LR ksh\n",
        "emulate -R -L ksh\n",
        "emulate -R ksh -c :\n",
        "f() { emulate -LR ksh }\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(on(&fs, UNKNOWN), [turned], "{rc}");
    }
    for rc in [
        "emulate ksh\n",
        "emulate -R sh\n",
        "emulate -R csh\n",
        "emulate -LR zsh\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
    // One whose mode an expansion makes is a doubt.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", "emulate -R $mode\n");
    assert_eq!(
        scan(&fs, UNKNOWN).doubts,
        ["it cannot tell what `emulate $mode` in /home/alice/.zshrc turns on"]
    );
}

#[test]
fn a_hook_that_writes_the_line_itself_counts_as_a_write() {
    // zsh 5.9.1 writes each command line to ~/.zsh_history from the first
    // two, with no fc and none of the three options.
    let redirects = |target: &str| format!("/home/alice/.zshrc redirects output to `{target}`");
    for (rc, what) in [
        (
            "preexec() { print -r -- \"$1\" >> ~/.zsh_history }\n",
            redirects("~/.zsh_history"),
        ),
        (
            "zshaddhistory() { print -r -- ${1%%$'\\n'} >>| ~/.zsh_history }\n",
            redirects("~/.zsh_history"),
        ),
        (
            "h() { print -r -- $1 >> $HISTFILE }\nadd-zsh-hook preexec h\n",
            redirects("$HISTFILE"),
        ),
        (
            "print -r -- x >> ${HISTFILE:-~/.zsh_history}\n",
            redirects("${HISTFILE:-~/.zsh_history}"),
        ),
        (
            "TRAPDEBUG() { print -r -- $ZSH_DEBUG_CMD >> ~/.histfile }\n",
            redirects("~/.histfile"),
        ),
        (
            "preexec() { print -r -- $1 | tee -a ~/.zsh_history }\n",
            "/home/alice/.zshrc names `~/.zsh_history` in `preexec`".to_string(),
        ),
        (
            "log() { print -r -- $1 | tee -a ~/.zsh_history }\npreexec_functions+=(log)\n",
            "/home/alice/.zshrc names `~/.zsh_history` in `log`".to_string(),
        ),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert!(
            on(&fs, UNKNOWN).contains(&what),
            "{rc}: {:?}",
            scan(&fs, UNKNOWN)
        );
    }
    // A target an expansion makes, in a hook, is a doubt.
    let elsewhere = |function: &str, target: &str| {
        format!(
            "it cannot tell where the output that `{function}` in /home/alice/.zshrc redirects \
             to `{target}` goes, which may be the history file"
        )
    };
    for (rc, doubt) in [
        (
            "preexec() { print -r -- $1 >> $log }\n",
            elsewhere("preexec", "$log"),
        ),
        (
            "w() { print -r -- $BUFFER >> \"$file\" }\nzle -N accept-line w\n",
            elsewhere("w", "$file"),
        ),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN).doubts, [doubt], "{rc}");
    }
    // Outside a hook, to another file, or read, it is neither.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "f() { print x >> $log }\nprint x >> ~/.cache/log\ncat < ~/.zsh_history\n",
    );
    assert_eq!(scan(&fs, UNKNOWN), Scan::default());
}

#[test]
fn a_parameter_set_by_a_name_an_expansion_makes_is_a_doubt() {
    // zsh 5.9.2 runs each with SHARE_HISTORY on, or with TTY or ZDOTDIR set
    // to what a part of the name holds.
    let parameter =
        |what: &str| format!("it cannot tell which parameter `{what}` in /home/alice/.zshrc sets");
    for (rc, what) in [
        (
            "n='options[share'; m='history]'; : ${(P)${:-$n$m}::=on}\n",
            ": ${(P)${:-$n$m}::=on}",
        ),
        (
            "n=TTY; : ${(P)n::=~/.zsh_history}\n",
            ": ${(P)n::=~/.zsh_history}",
        ),
        ("(( ${(P)n::=1} ))\n", "(( ${(P)n::=1} ))"),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        let found = scan(&fs, UNKNOWN);
        let what = what.trim_start_matches(": ");
        assert!(found.doubts.contains(&parameter(what)), "{rc}: {found:?}");
    }
    for (rc, what) in [
        ("zstyle -s :x y ${:-TT}Y\n", "zstyle ${:-TT}Y"),
        ("zstyle -g $name\n", "zstyle $name"),
        ("getopts a $name\n", "getopts $name"),
        ("strftime -s $name %s 0\n", "strftime $name"),
        ("vared $name\n", "vared $name"),
        ("zparseopts -A $name a\n", "zparseopts $name"),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN).doubts, [parameter(what)], "{rc}");
    }
    // One that reads a parameter by the name another holds sets none, and
    // a name the words give as written is read as before.
    for rc in [
        ": ${(P)n}\n",
        "x=${(P)n:-default}\n",
        "zstyle -s ':completion:*' format fmt\n",
        "getopts ab opt \"$@\"\n",
        "zstyle ':completion:*' list-colors ${(s.:.)LS_COLORS}\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
    // A line that holds one beyond what the walk read is a doubt too.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", "cat <<EOF\n${(P)n::=on}\nEOF\n");
    assert!(
        scan(&fs, UNKNOWN).doubts.contains(
            &"it cannot tell which parameter a line of /home/alice/.zshrc may set by the name \
              another one holds"
                .to_string()
        ),
        "{:?}",
        scan(&fs, UNKNOWN)
    );
}

#[test]
fn a_function_s_body_set_by_its_name_is_read_as_its_code() {
    // zsh 5.9.2 writes each command line to HISTFILE with the first two.
    for (rc, write) in [
        (
            "functions[preexec]='print -r -- \"$1\" >> ~/.zsh_history'\n",
            "/home/alice/.zshrc redirects output to `~/.zsh_history`",
        ),
        (
            "functions[precmd]='fc -AI'\n",
            "/home/alice/.zshrc names `fc -AI`",
        ),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert!(
            on(&fs, UNKNOWN).contains(&write.to_string()),
            "{rc}: {:?}",
            scan(&fs, UNKNOWN)
        );
    }
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "functions[preexec]='print -r -- \"$1\" >> $log'\n",
    );
    assert_eq!(
        scan(&fs, UNKNOWN).doubts,
        [
            "it cannot tell where the output that `preexec` in /home/alice/.zshrc redirects to \
             `$log` goes, which may be the history file"
        ]
    );
    // A body or a name an expansion makes, and the arrays that hold bodies or
    // alias values beside names, are doubts.
    for (rc, doubt) in [
        (
            "functions[precmd]=$code\n",
            "it cannot tell what code `functions[precmd]=$code` in /home/alice/.zshrc gives a \
             function",
        ),
        (
            "functions[$name]='print x'\n",
            "it cannot tell what code `functions[$name]=print x` in /home/alice/.zshrc gives a \
             function",
        ),
        (
            "functions+=(preexec 'print x')\n",
            "it cannot tell what code `functions=(...)` in /home/alice/.zshrc gives",
        ),
        (
            "aliases+=(so setopt)\n",
            "it cannot tell what code `aliases=(...)` in /home/alice/.zshrc gives",
        ),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert!(
            scan(&fs, UNKNOWN).doubts.contains(&doubt.to_string()),
            "{rc}: {:?}",
            scan(&fs, UNKNOWN)
        );
    }
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", "functions[greet]='print hi'\n");
    assert_eq!(scan(&fs, UNKNOWN), Scan::default());
}
