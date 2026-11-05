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
        "x=$(( (EUID+UID) * 2 ))",
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
        "emulate -LR zsh\n",
        "emulate -R zsh\nemulate -R r\n",
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
fn a_hook_s_output_to_the_terminal_through_tty_is_no_doubt_until_a_file_sets_tty() {
    // zsh 5.9.2 sets TTY to its terminal's name as it starts, whatever its
    // environment holds, and writes nothing to HISTFILE for these.
    for rc in [
        "precmd() { print -Pn '\\e]0;%~\\a' > $TTY }\n",
        "precmd() { print -Pn x >\"$TTY\" }\n",
        "precmd() { print -Pn x >> ${TTY} }\n",
        "preexec() { print -rn -- $1 &> $TTY }\n",
        "precmd() { print -n x 2>$TTY }\nexport GPG_TTY=$TTY\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
    // A file that may set TTY, any of them, makes it the doubt it is for any
    // other target an expansion makes: zsh 5.9.2 writes each command line to
    // HISTFILE with the first one.
    let doubt = |set: &str| {
        format!(
            "it cannot tell where the output that `preexec` in /home/alice/.zshrc redirects to \
             `$TTY` goes, as {set} may set TTY to name the history file"
        )
    };
    let hook = "preexec() { print -r -- $1 >> $TTY }\n";
    for set in [
        "TTY=~/.zsh_history",
        "typeset -g TTY=~/.zsh_history",
        "f() { local TTY }",
        "read -r TTY < ~/.ttyname",
        ": ${TTY::=~/.zsh_history}",
        "TTY+=x",
        "for TTY in ~/.zsh_history; do :; done",
        "print -v TTY ~/.zsh_history",
        "zstyle -s :x y TTY",
        "unset TTY",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{hook}{set}\n"));
        assert_eq!(
            scan(&fs, UNKNOWN).doubts,
            [doubt("/home/alice/.zshrc")],
            "{set}"
        );
    }
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", hook);
    seed(&fs, "/home/alice/.zshenv", "TTY=~/.zsh_history\n");
    assert_eq!(scan(&fs, UNKNOWN).doubts, [doubt("/home/alice/.zshenv")]);
    // Any other target is read as before.
    let elsewhere = |target: &str| {
        format!(
            "it cannot tell where the output that `preexec` in /home/alice/.zshrc redirects to \
             `{target}` goes, which may be the history file"
        )
    };
    for target in ["$TTY/x", "${TTY:-/dev/tty}", "$TTYx", "${TTY}x", "$TTY$x"] {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("preexec() {{ print -r -- $1 >> {target} }}\n"),
        );
        assert_eq!(scan(&fs, UNKNOWN).doubts, [elsewhere(target)], "{target}");
    }
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

#[test]
fn a_function_a_hook_runs_counts_as_a_hook() {
    // zsh 5.9.2 writes each command line to HISTFILE with each of these: the
    // hook hands the line to a function that writes it to a file whose name
    // an expansion makes.
    let doubt = |function: &str, target: &str| {
        format!(
            "it cannot tell where the output that `{function}` in /home/alice/.zshrc redirects \
             to `{target}` goes, which may be the history file"
        )
    };
    for (rc, function) in [
        (
            "log=$HISTFILE\nw() { print -r -- \"$1\" >> $log }\npreexec() { w \"$1\" }\n",
            "w",
        ),
        (
            "w() { print -r -- \"$1\" >> $log }\nv() { w \"$1\" }\npreexec_functions+=(v)\n",
            "w",
        ),
        (
            "w() { print -r -- \"$ZSH_DEBUG_CMD\" >> $log }\ntrap 'w' DEBUG\n",
            "w",
        ),
        (
            "w() { print -r -- \"$1\" >> $log }\npreexec() { eval 'w \"$1\"' }\n",
            "w",
        ),
        (
            "w() { print -r -- \"$1\" >> $log }\npreexec() { : $(w \"$1\") }\n",
            "w",
        ),
        (
            "preexec() { eval 'print -r -- \"$1\" >> $log' }\n",
            "preexec",
        ),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN).doubts, [doubt(function, "$log")], "{rc}");
    }
    // One that no hook runs is no hook.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "w() { print -r -- \"$1\" >> $log }\nf() { w x }\nf\n",
    );
    assert_eq!(scan(&fs, UNKNOWN), Scan::default());
}

/// Whether a scan of `fs` for a zsh that may be a login shell finds what
/// writes the history file, or a doubt: anything but a pass.
fn warns(fs: &MockFilesystem) -> bool {
    scan(fs, UNKNOWN) != Scan::default()
}

#[test]
fn a_name_is_read_as_zsh_reads_a_word_before_it_names_a_parameter() {
    // zsh 5.9.2 sets TTY with each of these, as it takes quotes and
    // backslashes off a word, joins a line that ends in a backslash with the
    // next, decodes `$'...'` and reads an option's argument after its
    // letters, and a hook's output to $TTY then goes to the history file.
    let hook = "preexec() { print -r -- \"$1\" >> $TTY }\n";
    for set in [
        "x='\n#'; TTY=$HOME/.zsh_history",
        "T\\\nTY=$HOME/.zsh_history",
        "read T''TY <<< $HOME/.zsh_history",
        "typeset -g T''TY=$HOME/.zsh_history",
        "print -v T\\TY $HOME/.zsh_history",
        "export \"T\"TY=$HOME/.zsh_history",
        "print -vTTY $HOME/.zsh_history",
        "zstyle :x y ~/.zsh_history; zstyle -s :x y 'TTY'",
        ": ${TTY[1,-1]::=$HOME/.zsh_history}",
        "print -v $'\\x54'TY $HOME/.zsh_history",
        "print -v $'\\124'TY $HOME/.zsh_history",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{set}\n{hook}"));
        assert!(warns(&fs), "{set}");
    }
    // A name an expansion makes, for the builtins that set one by a name,
    // and what names it as an option's argument.
    for set in [
        "printf -vTTY %s $HOME/.zsh_history",
        "n=T; zformat -f ${n}TY \"%s\" s:$HOME/.zsh_history",
        "n=T; print -z $HOME/.zsh_history; getln ${n}TY",
        "n=T; zpty -r w ${n}TY",
        "n=T; syswrite -c ${n}TY x",
        "n=T; stat -A ${n}TY /",
        "x=options; y=history; set -A $x share$y on",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{set}\n{hook}"));
        assert!(warns(&fs), "{set}");
    }
    // A comment, a read and a name of which TTY is a part set none.
    for rc in [
        "# write to TTY in a hook\n",
        "print $TTY ${TTY} ${#TTY} ${TTY:-x}\n",
        "GPG_TTY=$TTY; MYTTY=1; TTYS=2\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{rc}{hook}"));
        assert!(!warns(&fs), "{rc}");
    }
}

#[test]
fn the_forms_of_a_file_hold_what_zsh_reads_its_words_as() {
    let forms = backstop::Forms::of(
        "print -v T\\TY x\nT\\\nTY=1\nx=$'\\x54\\u0054\\U00000059'=\n# TTY=1\n",
    );
    assert_eq!(forms.writes("TTY"), 3);
    // A line a backslash joins to a comment line holds no more code.
    let forms = backstop::Forms::of("x=a\\\n  #; source ~/.zsh/history.zsh\n");
    assert_eq!(forms.uses("source"), 0);
    assert_eq!(backstop::named("x=a\\\n  #; source ~/x\n").sources, 0);
    // A line that starts with `#` inside a quote is code once it closes.
    assert_eq!(backstop::Forms::of("x='\n#'; TTY=1\n").writes("TTY"), 1);
}

#[test]
fn a_hook_made_in_any_form_zsh_runs_one_is_read_as_one() {
    // zsh 5.9.2 runs `myhook` after each command with each of these, and it
    // writes each command line to HISTFILE.
    let body = "f=$HISTFILE\nmyhook() { print -r -- ${history[$((HISTCMD-1))]} >> $f }\n";
    for made in [
        "functions -c myhook precmd",
        "precmd_functions[1]=myhook",
        "set -A precmd_functions myhook",
        "read -A precmd_functions <<< myhook",
        "zle -C zle-line-finish .complete-word myhook",
        "zle -N w myhook; zle -A w zle-line-finish",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{body}{made}\n"));
        assert!(warns(&fs), "{made}");
    }
    // These count too, as the check reads each form a hook may take alike.
    for made in [
        "precmd_functions+=myhook",
        "print -v precmd_functions myhook",
        "pre''cmd_functions+=(myhook)",
        "zle -F 0 myhook",
        "zle -C w .complete-word f; zle -A w zle-line-init",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{body}{made}\n"));
        assert!(warns(&fs), "{made}");
    }
    // A completion widget of another name runs as a key bound to it is
    // pressed, which may be one a line is typed with (Space), as a `zle -N`
    // widget's function does: its function is a hook too.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        &format!("{body}zle -C mycomp .complete-word myhook\n"),
    );
    assert!(warns(&fs));
    // Declared, or taken away, an array of hooks makes none.
    for rc in [
        "typeset -ga precmd_functions\n",
        "unset precmd_functions\n",
        "(( ${precmd_functions[(I)x]} )) && print hooked\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
}

#[test]
fn what_a_hook_runs_from_its_own_file_or_one_it_sources_is_a_hook_s() {
    // zsh 5.9.2 writes each command line as it is entered with each.
    let write = "print -r -- \"$1\" >> $f\n";
    for (rc, file) in [
        (
            "f=$HISTFILE\nfpath=(~/zfn $fpath)\nautoload -Uz preexec\n",
            "/home/alice/zfn/preexec",
        ),
        (
            "f=$HISTFILE\nfpath=(~/zfn $fpath)\nautoload -Uz myhook\npreexec_functions+=(myhook)\n",
            "/home/alice/zfn/myhook",
        ),
        (
            "f=$HISTFILE\nautoload -Uz ~/zfn/preexec\n",
            "/home/alice/zfn/preexec",
        ),
        (
            "f=$HISTFILE\npreexec() { . ~/hookbody }\n",
            "/home/alice/hookbody",
        ),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        seed(&fs, file, write);
        assert!(warns(&fs), "{rc}");
        // The same file read outside a hook writes once, as zsh starts.
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", "f=$HISTFILE\n. ~/hookbody\n");
        seed(&fs, "/home/alice/hookbody", write);
        assert!(!warns(&fs), "{rc}");
    }
}

#[test]
fn a_command_a_hook_runs_that_may_write_a_file_an_expansion_names_is_a_doubt() {
    // zsh 5.9.2 writes each command line to HISTFILE with each.
    for rc in [
        "f=$HISTFILE\npreexec() { print -r -- \"$1\" | tee -a $f >/dev/null }\n",
        "f=$HISTFILE\npreexec() { command tee -a \"$f\" <<< \"$1\" >/dev/null }\n",
        "f=$HISTFILE\nalias w='print -r -- \"$1\" >> $f'\npreexec() { w }\n",
        "f=$HISTFILE\nalias -g LOG='>> $f'\npreexec() { print -r -- \"$1\" LOG }\n",
        "f=$HISTFILE\ncommand_not_found_handler() { print -r -- \"$*\" >> $f; return 127 }\n",
        "f=$HISTFILE\nexec 3>>$f\npreexec() { print -r -u3 -- \"$1\" }\n",
        "f=$HISTFILE\ncoproc tee -a $f >/dev/null\npreexec() { print -p -r -- \"$1\" }\n",
        "zmodload zsh/mapfile\nf=$HISTFILE\npreexec() { mapfile[$f]+=\"$1\" }\n",
        "preexec() { fc -p -a ~/.zlog; print -sr -- \"$1\" }\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert!(warns(&fs), "{rc}");
    }
    // These count too: an element of mapfile set otherwise writes its file,
    // and an `fc -p` pushes a list zsh writes to its file as it pops it.
    for rc in [
        "zmodload zsh/mapfile\nf=$HISTFILE\npreexec() { : ${mapfile[$f]::=$1} }\n",
        "zmodload zsh/mapfile\npreexec() { print -v 'mapfile[~/.zsh_history]' \"$1\" }\n",
        "zshaddhistory() { fc -pa ~/.zlog }\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert!(warns(&fs), "{rc}");
    }
    // A builtin that writes no file, a function the files define, and a
    // command outside a hook are none.
    for rc in [
        "preexec() { print -n \"\\e]0;$1\\a\" }\n",
        "title() { print -n \"$1\" }\npreexec() { title \"$1\" }\n",
        "f() { tee -a $log }\n",
        "precmd() { [[ -n $VIRTUAL_ENV ]] && psvar[1]=${VIRTUAL_ENV:t} }\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
}

#[test]
fn a_function_named_like_a_builtin_is_a_hook() {
    // The hooks `add-zle-hook-widget` makes run `zstyle` and `zle` as each
    // line is entered, once zsh/zle is loaded, and zsh 5.9.2 writes it to
    // HISTFILE with each then.
    for rc in [
        "zstyle() { print -r -- \"$BUFFER\" >> $log; builtin zstyle ':x' y z }\n",
        "zle() { print -r -- \"$BUFFER\" >> $log; builtin zle -R }\n",
    ] {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("log=~/.zsh_history\n{rc}"),
        );
        assert!(warns(&fs), "{rc}");
        // Named otherwise, it runs only where it is called.
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshrc",
            &rc.replace("zstyle() {", "mystyle() {")
                .replace("zle() {", "myzle() {"),
        );
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
}

#[test]
fn a_name_a_builtin_takes_attached_to_its_flag_or_after_others_counts() {
    // zsh 5.9.2 sets TTY with each to the history file, which the hook then
    // appends each command line to.
    let hook = "preexec() { print -r -- \"$1\" >> $TTY }\n";
    for set in [
        "n=T; print -v${n}TY -- ~/.zsh_history",
        "n=T; print -rv ${n}TY -- ~/.zsh_history",
        "n=T; print -nrv ${n}TY -- ~/.zsh_history",
        "n=T; print -v\"${n}TY\" -- ~/.zsh_history",
        "zmodload zsh/datetime; n=T; strftime -s${n}TY ~/.zsh_history 0",
        "zmodload zsh/attr; n=T; zgetattr ~/.t user.t ${n}TY",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{hook}{set}\n"));
        assert!(!scan(&fs, UNKNOWN).doubts.is_empty(), "{set}");
    }
    // zsh 5.9.2 turns SHARE_HISTORY on with each.
    let named = "n='options[share'; m='history]'; ";
    for set in [
        "print -v$n$m on",
        "print -rv $n$m on",
        "print -nrv $n$m on",
        "print -Rv $n$m on",
        "zmodload zsh/datetime; strftime -s$n$m on 0",
        "zmodload zsh/datetime; strftime -rs$n$m %s 0",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{named}{set}\n"));
        assert!(!scan(&fs, UNKNOWN).doubts.is_empty(), "{set}");
    }
    // These count too, as the check reads the names they may set.
    for set in [
        "zlistattr ~/.t ${n}TY",
        "zmodload zsh/system; syserror -e ${n}TY",
        "print -$flags $n x",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{hook}{set}\n"));
        assert!(!scan(&fs, UNKNOWN).doubts.is_empty(), "{set}");
    }
    // A name as written is no doubt; `-f` takes the `v` after it as its
    // format, and printf takes `-v` as a word of its own only.
    for set in [
        "print -rv out -- x",
        "print -vout x",
        "print -fv $x",
        "printf -vx %s $y",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{set}\n"));
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{set}");
    }
}

#[test]
fn an_alias_given_by_the_parameters_that_hold_them_is_a_doubt() {
    // zsh 5.9.2 runs `fc -W` from precmd with each, which writes the history
    // file.
    for (define, used) in [
        ("alias h=f\naliases[h]+='c -W'", "h"),
        ("alias h=f\naliases[h]+=c", "h -W"),
        ("aliases[h]=f\naliases[h]+=c", "h -W"),
        (": ${aliases[h]::=fc -l}", "h -W"),
        (": ${aliases[h]:=fc -l}", "h -W"),
        ("print -v 'aliases[h]' 'fc -l'", "h -W"),
        ("print -rv 'aliases[h]' 'fc -l'", "h -W"),
        ("printf -v 'aliases[h]' %s 'fc -l'", "h -W"),
        ("read 'aliases[h]' <<< 'fc -l'", "h -W"),
        ("set -A aliases h 'fc -l'", "h -W"),
        ("zstyle :x y 'fc -l'; zstyle -s :x y 'aliases[h]'", "h -W"),
        ("alias -g X=f\ngaliases[X]+='c -W'", "X"),
    ] {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("{define}\nprecmd() {{ {used} }}\n"),
        );
        assert!(warns(&fs), "{define}");
    }
    // The same for a function's body, and a disabled alias, which `enable`
    // makes zsh expand.
    for rc in [
        "c=fc\nprint -v 'functions[precmd]' \"$c -AI\"\n",
        "dis_aliases[h]='fc -W'\nenable -a h\nprecmd() { h }\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert!(warns(&fs), "{rc}");
    }
    // An alias given by its element as written is read as one, and reading
    // the parameters, or a file named like them, gives none.
    for rc in [
        "aliases[h]='fc -l'\n",
        "print -rl -- ${(k)aliases} ${(k)functions}\n",
        "source ~/.zsh/aliases.zsh\nsource ~/.zsh/functions.zsh\n",
        "zstyle ':completion:*:functions' ignored-patterns '_*'\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
}

#[test]
fn a_hook_s_write_to_a_file_that_may_be_the_history_file_is_a_doubt() {
    // zsh 5.9.2 appends each command line to HISTFILE with each.
    for rc in [
        "preexec() { print -r -- \"$1\" >> ~/.zsh_h[i]story }\n",
        "HISTFILE=~/.zlog\npreexec() { print -r -- \"$1\" >> ~/.zlog }\n",
        "HISTFILE=~/.zlog\npreexec() { history -p -a ~/.zlog; print -sr -- \"$1\" }\n",
        "preexec() { print -r -- \"$1\" >> ~/.zl }\n",
        "zmodload zsh/system\nsysopen -a -w -u fd ~/.zl\npreexec() { print -u $fd -r -- \"$1\" }\n",
        "exec 3>>~/.zl\npreexec() { print -u3 -r -- \"$1\" }\n",
        "exec >>~/.zl\npreexec() { print -r -- \"$1\" }\n",
        "preexec() { print -r -- \"$1\" | tee -a ~/.zl >/dev/null }\n",
        "preexec() { tee -a ~/.zl <<< \"$1\" >/dev/null }\n",
        "preexec() { LINE=$1 logger }\n",
        "alias -g /dev/null=~/.zl\npreexec() { print -r -- \"$1\" > /dev/null }\n",
        "alias -g T='| tee -a ~/.zl'\npreexec() { print -r -- \"$1\" T }\n",
        "alias -g T='| tee zl'\npreexec() { print -r -- \"$1\" T }\n",
        "alias -g S='| sort -o ~/.zl'\npreexec() { print -r -- \"$1\" S }\n",
        "log() { print -r -- \"$1\" }\npreexec() { log \"$1\" | tee -a ~/.zl }\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert!(warns(&fs), "{rc}");
    }
    // A device, a descriptor the shell has open, and a command fed what
    // writes nothing of the command line are none.
    for rc in [
        "preexec() { print -r -- \"$1\" >/dev/null 2>&1 }\n",
        "precmd() { print -Pn '\\e]0;%~\\a' > /dev/tty }\n",
        "precmd() { print -n x >&2 }\n",
        "exec 2>/dev/null\n",
        "precmd() { git branch 2>/dev/null | grep -q main }\n",
        "alias -g G='| grep'\nalias -g L='| less'\nalias -g H='| head -n 20'\n",
        "alias -g J='| jq .'\nalias -g C='| xclip -selection clipboard'\n",
        "print -r -- start >> ~/.zl\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
}

#[test]
fn a_widget_s_function_and_completion_a_hook_runs_are_read_as_a_hook_s() {
    // zsh 5.9.2 writes each command line to HISTFILE with each.
    let body = "f=$HISTFILE\nw() { print -r -- \"$BUFFER\" >> $f }\n";
    for made in [
        "zle -C myw .complete-word w\nautoload -Uz add-zle-hook-widget\nadd-zle-hook-widget line-finish myw",
        "autoload -Uz add-zle-hook-widget\nnoop() { : }\nadd-zle-hook-widget line-finish noop\nzstyle zle-line-finish widgets 0:noop 1:myw\nzle -C myw .complete-word w",
        "autoload -Uz add-zle-hook-widget\nnoop() { : }\nadd-zle-hook-widget line-finish noop\nazhw:zle-line-finish() { w }",
        "zle -T tc w",
        "lf() { zle myw }\nzle -N zle-line-finish lf\nzle -C myw .complete-word w",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{body}{made}\n"));
        assert!(warns(&fs), "{made}");
    }
    // A hook that completes a word runs completion functions the check does
    // not read, and so does a key typed in a line bound to completion.
    for rc in [
        "lf() { zle complete-word }\nzle -N zle-line-finish lf\n",
        "lf() { zle -- complete-word }\nzle -N zle-line-finish lf\n",
        "autoload -Uz add-zle-hook-widget\nadd-zle-hook-widget line-finish complete-word\n",
        "zle -A complete-word accept-line\n",
        "bindkey ' ' complete-word\n",
        "bindkey '^m' expand-or-complete\n",
        "bindkey -M main a _x\n",
        "bindkey -s '^M' '^I^J'\n",
        "bindkey -s ' ' ' \\t'\n",
        "zstyle -e zle-line-init widgets 'reply=(1:x)'\n",
        // An arrow, an Alt key that moves by a word and any other key after
        // `^X` or an escape but those zsh's own completion functions bind:
        // zsh 5.9.2 writes the line as the Left arrow is pressed with the
        // first and a completer that appends $BUFFER to HISTFILE.
        "bindkey '^[[D' complete-word\n",
        "bindkey '^[f' expand-or-complete\n",
        "bindkey '^X^Z' _my-widget\n",
        "bindkey '^[x' menu-complete\n",
        "bindkey '^[[Z' reverse-menu-complete\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert!(warns(&fs), "{rc}");
    }
    // Tab, `^D`, the keys zsh's own completion functions bind, and a widget
    // that does not complete, are none.
    for rc in [
        "bindkey '^I' complete-word\n",
        "bindkey '^D' delete-char-or-list\n",
        "bindkey '^Xh' _complete_help\n",
        "bindkey '\\e/' _history-complete-older\n",
        "bindkey '^[[D' backward-char\n",
        "precmd() { zle && zle reset-prompt }\n",
        "bindkey -s '^o' 'lfcd^M'\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
}

#[test]
fn completion_bound_to_a_range_of_keys_or_past_a_word_zsh_may_drop_is_a_doubt() {
    // zsh 5.9.2 binds every key of a range with `-R`, binds past `-L`, an
    // `-M` glued to its keymap, `--` and `-` as it does without them, and
    // drops `${k[1]}` and `$e` when they are empty: with compinit's
    // completer a function that appends $BUFFER to HISTFILE, it runs it as
    // the keys of a typed line are pressed with each, and writes each part
    // of the line as a space is typed with all but the ranges of letters and
    // of all keys, whose keys complete in place of typing.
    let doubt = |shown: &str| {
        format!(
            "it cannot tell what the completion functions that `{shown}` in \
             /home/alice/.zshrc runs as a line is typed write"
        )
    };
    for (rc, shown) in [
        (
            "bindkey -R ' - ' complete-word",
            "bindkey -R  -  complete-word",
        ),
        (
            "bindkey -M main -R ' - ' complete-word",
            "bindkey -R  -  complete-word",
        ),
        (
            "bindkey -RM main ' !' complete-word",
            "bindkey -R  ! complete-word",
        ),
        (
            "bindkey -R 'a-z' complete-word",
            "bindkey -R a-z complete-word",
        ),
        (
            "bindkey -R '^@-~' expand-or-complete",
            "bindkey -R ^@-~ expand-or-complete",
        ),
        ("bindkey -L ' ' complete-word", "bindkey   complete-word"),
        (
            "bindkey -Mmain ' ' complete-word",
            "bindkey   complete-word",
        ),
        ("bindkey -- ' ' complete-word", "bindkey   complete-word"),
        ("bindkey - ' ' complete-word", "bindkey   complete-word"),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{rc}\n"));
        assert_eq!(scan(&fs, UNKNOWN).doubts, [doubt(shown)], "{rc}");
    }
    // Past an element outside quotes, which zsh drops when it is empty, the
    // check cannot tell keys from widgets; an expansion it may make several
    // words of, or options of, may hold any, and zsh 5.9.2 binds Space with
    // the brace expansion and the range `"$o"` makes.
    for (rc, doubt) in [
        (
            "bindkey -- ${k[1]} ' ' complete-word",
            "it cannot tell which keys `bindkey ${k[1]}   complete-word` in /home/alice/.zshrc \
             binds `complete-word`, which completes a word, to, as `${k[1]}` before it may \
             expand to no word",
        ),
        (
            "bindkey ${k[1]} ' ' complete-word",
            "it cannot tell what `bindkey ${k[1]}   complete-word` in /home/alice/.zshrc binds, \
             as `${k[1]}` may expand to its options",
        ),
        (
            "bindkey -- $e ' ' complete-word",
            "it cannot tell which keys `bindkey $e   complete-word` in /home/alice/.zshrc binds \
             to which widgets, as `$e` may expand to no word or to several, a widget that \
             completes a word among them",
        ),
        (
            "bindkey $k\"\" x",
            "it cannot tell which keys `bindkey $k x` in /home/alice/.zshrc binds to which \
             widgets, as `$k` may expand to no word or to several, a widget that completes a \
             word among them",
        ),
        (
            "bindkey \"$@\"",
            "it cannot tell which keys `bindkey $@` in /home/alice/.zshrc binds to which \
             widgets, as `$@` may expand to no word or to several, a widget that completes a \
             word among them",
        ),
        (
            "bindkey ${=k}",
            "it cannot tell which keys `bindkey ${=k}` in /home/alice/.zshrc binds to which \
             widgets, as `${=k}` may expand to no word or to several, a widget that completes \
             a word among them",
        ),
        (
            "bindkey -$o ' ' complete-word",
            "it cannot tell what `bindkey -$o   complete-word` in /home/alice/.zshrc binds, as \
             an expansion makes its options `-$o`",
        ),
        (
            "bindkey {' ',complete-word}",
            "it cannot tell which keys `bindkey { ,complete-word}` in /home/alice/.zshrc binds \
             to which widgets, as `{ ,complete-word}` may expand to no word or to several, a \
             widget that completes a word among them",
        ),
        (
            "o=-R\nbindkey \"$o\" ' - ' complete-word",
            "it cannot tell what `bindkey $o  -  complete-word` in /home/alice/.zshrc binds, as \
             `$o` may expand to its options",
        ),
        (
            "o=-R\nbindkey -M main \"$o\" ' - ' complete-word",
            "it cannot tell what `bindkey -M main $o  -  complete-word` in /home/alice/.zshrc \
             binds, as `$o` may expand to its options",
        ),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{rc}\n"));
        assert_eq!(scan(&fs, UNKNOWN).doubts, [doubt], "{rc}");
    }
    // SH_WORD_SPLIT or KSH_ARRAYS may make several words of such an element.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "setopt sh_word_split\nbindkey $k[1] up-line-or-search\n",
    );
    assert_eq!(
        scan(&fs, UNKNOWN).doubts,
        [
            "it cannot tell which keys `bindkey $k[1] up-line-or-search` in /home/alice/.zshrc \
             binds to which widgets, as /home/alice/.zshrc may turn SH_WORD_SPLIT or KSH_ARRAYS \
             on, with which `$k[1]` may expand to several words, a widget that completes a word \
             among them"
        ]
    );
    // A terminal's keys, quoted or an element outside quotes, a widget that
    // does not complete, a list and a keymap of its own are none.
    for rc in [
        "bindkey \"$terminfo[kcuu1]\" up-line-or-search\n",
        "bindkey $terminfo[kcuu1] up-line-or-search\n",
        "typeset -A key\nbindkey ${key[Up]} up-line-or-beginning-search\n",
        "typeset -A key\nbindkey -- \"${key[Home]}\" beginning-of-line\n",
        "bindkey $'\\e[A' up-line-or-search\n",
        "bindkey '^[[A' up-line-or-search\nbindkey -M vicmd '?' history-incremental-search-backward\n",
        "bindkey -R 'a-z' self-insert\n",
        "bindkey -l\nbindkey -L\nbindkey -lL main\n",
        "bindkey -M menuselect '^M' .accept-line\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
}

#[test]
fn a_redirection_with_no_command_runs_what_nullcmd_names() {
    // zsh 5.9.2 runs `cat`, NULLCMD's default, for a redirection alone, and
    // `more`, READNULLCMD's, for an input alone, a function the files define
    // by that name among them: with each the hook appends each command line
    // to ~/.zl, the history file.
    for (name, redirection) in [("cat", ">/dev/null"), ("more", "</dev/null")] {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!(
                "HISTFILE=~/.zl\n{name}() {{ fc -ln -1 >> ~/.zl }}\npreexec() {{ {redirection} }}\n"
            ),
        );
        assert_eq!(
            scan(&fs, UNKNOWN).doubts,
            [format!(
                "it cannot tell whether `~/.zl`, which `{name}` in /home/alice/.zshrc redirects \
                 output to, is the history file (a file HISTFILE names, or a link to it)"
            )],
            "{name}"
        );
    }
    // With none of those names defined, it runs no code of the files.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "preexec() { >/dev/null }\nprecmd() { </dev/null }\n",
    );
    assert_eq!(scan(&fs, UNKNOWN), Scan::default());
}

#[test]
fn a_hook_s_write_to_a_descriptor_the_shell_keeps_open_is_a_doubt() {
    // zsh 5.9.2 writes each command line to the history file with each:
    // `zsystem flock -f` keeps a descriptor open on it, and a socket or a
    // descriptor above 2 goes to whatever the shell has open there.
    for rc in [
        "zmodload zsh/system\nzsystem flock -f fd ~/.zsh_history\npreexec() { print -u $fd -r -- \"$1\" }\n",
        "zmodload zsh/system\nzsystem flock -t 1 -f fd ~/.zl\n",
        "zmodload zsh/net/socket\nzsocket -d 6 ~/s\npreexec() { print -u 6 -r -- \"$1\" }\n",
        "zmodload zsh/net/tcp\nztcp localhost 7000\n",
        "preexec() { print -u 7 -r -- \"$1\" }\n",
        "preexec() { print -ru7 -- \"$1\" }\n",
        "preexec() { print -r -u $fd -- \"$1\" }\n",
        "preexec() { print -r -- \"$1\" >&7 }\n",
        "preexec() { print -r -- \"$1\" 1>&11 }\n",
        "preexec() { print -r -- \"$1\" >> /dev/fd/11 }\n",
        "preexec() { print -r -- \"$1\" > /proc/self/fd/9 }\n",
        "exec >&3\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert!(warns(&fs), "{rc}");
    }
    // Standard output and error, and an unlock, are none.
    for rc in [
        "preexec() { print -u2 -r -- \"$1\" }\n",
        "preexec() { print -r -u 1 -- \"$1\" }\n",
        "preexec() { print -r -- \"$1\" >&2 }\n",
        "preexec() { print -r -- \"$1\" > /dev/fd/2 }\n",
        "exec 2>&1\n",
        "zmodload zsh/system\nzsystem flock -u 5\n",
        "print -u 7 start\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
}

#[test]
fn a_parameter_zsh_runs_or_loads_code_from_is_a_doubt() {
    // zsh 5.9.2 expands the message after `?` in each element of MAILPATH
    // before a prompt, a command substitution in it too, and loads a module
    // of a directory module_path names, whose code it then runs.
    for rc in [
        "MAILPATH=~/mbox'?$(fc -l -1 >> $f)'\n",
        "mailpath=(~/mbox'?$(x)')\n",
        "export MAILPATH\n",
        "NULLCMD=w\n",
        "READNULLCMD=w\n",
        "module_path=(~/zm $module_path)\nzmodload evil\n",
        "MODULE_PATH=~/zm\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert!(warns(&fs), "{rc}");
    }
    // Reading them, and MAIL, which names a file alone, are none.
    for rc in [
        "print -r -- $MAILPATH $module_path\n",
        "MAIL=/var/mail/alice\nMAILCHECK=60\n",
        "zmodload zsh/complist\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
}

#[test]
fn a_function_defined_by_each_of_its_names_or_one_zsh_expands_is_read_by_each() {
    // zsh 5.9.2 defines `preexec` with each, by a second name, by brace
    // expansion, by a name an expansion makes and by a glob that a file in
    // the directory it runs in matches, so each command line goes to the
    // history file.
    let write = "{ print -r -- \"$1\" >> $f }";
    for definition in [
        format!("function x preexec {write}"),
        format!("x preexec () {write}"),
        format!("function x preexec () {write}"),
        format!("function x preexec\n{write}"),
        format!("function {{preexec,x}} {write}"),
        format!("n=preexec\nfunction $n {write}"),
        format!("n=preexec\n$n() {write}"),
        format!("function ${{:-preexec}} {write}"),
        format!("function preexe[c] {write}"),
        format!("x() {write}\nfunctions -c x preexe[c]"),
        "function ${:-TRAPDEBUG} { print -r -- \"$ZSH_DEBUG_CMD\" >> $f }".to_string(),
        "function x precmd { fc -AI }".to_string(),
    ] {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("f=$HISTFILE\n{definition}\n"),
        );
        assert!(warns(&fs), "{definition}");
    }
    // Names that are no hook's, and an expanded name whose code writes
    // nothing, are none.
    for definition in [
        format!("function x y {write}"),
        format!("x y () {write}"),
        "n=preexec\nfunction $n { print -Pn '%~' }".to_string(),
        "function { setopt localoptions; : }".to_string(),
    ] {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("f=$HISTFILE\n{definition}\n"),
        );
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{definition}");
    }
}

#[test]
fn a_hook_made_by_a_word_zsh_expands_into_others_is_a_doubt() {
    // zsh 5.9.2 makes `w` a hook with each, by brace expansion.
    for made in [
        "autoload -Uz add-zsh-hook\nadd-zsh-hook {preexec,w}",
        "preexec_functions=({w,w})",
        "precmd_functions+=(w{,})",
        "set -A preexec_functions {w,w}",
        "zle -N {zle-line-finish,w}",
        "zle -N zle-line-finish w{,}",
    ] {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("f=$HISTFILE\nw() {{ print -r -- \"$1$BUFFER\" >> $f }}\n{made}\n"),
        );
        assert!(warns(&fs), "{made}");
    }
}

#[test]
fn a_global_alias_the_code_uses_is_a_doubt() {
    // zsh 5.9.2 puts a global alias's value in place of each word that is its
    // name as it reads the code: each of these makes `preexec` a function or a
    // hook, sets TTY or writes each command line to the history file.
    for rc in [
        "alias -g X=preexec\nfunction X { print -r -- \"$1\" >> $f }\n",
        "alias -g X=preexec\nfunction x X { print -r -- \"$1\" >> $f }\n",
        "alias -g X=preexec_functions\nw() { print -r -- \"$1\" >> $f }\nset -A X w\n",
        "alias -g X=TTY\nread X <<< ~/.zsh_history\npreexec() { print -r -- \"$1\" >> $TTY }\n",
        "alias -g S='| sort -o .zl .zl -'\npreexec() { print -r -- \"$1\" S }\n",
        "alias -g S='| sort --output=.zl -'\npreexec() { print -r -- \"$1\" S }\n",
        "galiases[S]='| sort -o .zl'\npreexec() { print -r -- \"$1\" S }\n",
        "alias -g G='| grep'\npreexec() { print -r -- \"$1\" G -q x }\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("f=$HISTFILE\n{rc}"));
        assert!(warns(&fs), "{rc}");
    }
    // One the files define but do not use, as for typing, is none; one
    // written twice alike counts once, so the second is a use.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "alias -g G='| grep'\nalias -g G='| grep'\n",
    );
    assert!(warns(&fs));
    for rc in [
        "alias -g G='| grep'\n",
        "alias -g ...='../..'\nalias -g NUL='> /dev/null 2>&1'\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
}

/// The doubt a global alias whose uses the check cannot count is, as `text`
/// in the file at `place` defines it.
fn uncountable(text: &str, place: &str) -> String {
    format!(
        "it cannot tell what code the global alias `{text}` in {place} runs, as zsh puts its \
         value in place of each token that is its name, which the check cannot count where the \
         name holds an operator, a brace or a blank, or is empty"
    )
}

/// The doubt a hook's output to the device `target` is where the file at
/// `place` defines the global alias `text`.
fn under_alias(hook: &str, target: &str, text: &str, place: &str) -> String {
    format!(
        "it cannot tell where the output that `{hook}` in /home/alice/.zshrc redirects to \
         `{target}` goes, as {place} defines the global alias `{text}`, which zsh may put in \
         place of a word or an operator of it"
    )
}

#[test]
fn a_global_alias_named_like_an_operator_or_a_brace_is_a_doubt_wherever_it_stands() {
    // zsh 5.9.2 looks a global alias up for each token it reads, and splits
    // an operator off a word with no blank beside it, as it does the `}` that
    // ends a word: with each of these it puts the alias's value in place of
    // the `>`, `>>`, `&>`, `;` or `}` of the hook and appends each command
    // line to ~/.zl, the history file, before it runs it.
    for (text, hook, target) in [
        (">=>>~/.zl;:", "{ print -r -- $1>$TTY }", Some("$TTY")),
        (">>=>>~/.zl;:", "{ print -r -- $1>>$TTY }", Some("$TTY")),
        (
            ">=>>~/.zl;:",
            "{ print -r -- \"$1\" -->$TTY }",
            Some("$TTY"),
        ),
        (">=>>~/.zl;:", "{ print -r -- $1>${TTY} }", Some("${TTY}")),
        (
            ">=>>~/.zl;:",
            "{ print -Pn -- \"\\e]0;$1\\a\"-->$TTY }",
            Some("$TTY"),
        ),
        (
            ">=>>~/.zl;:",
            "{ print -r -- $1>/dev/null }",
            Some("/dev/null"),
        ),
        (
            ">=>>~/.zl;:",
            "{ print -r -- $1>/dev/tty }",
            Some("/dev/tty"),
        ),
        (
            ">>=>>~/.zl;:",
            "{ print -r -- $1>>/dev/null }",
            Some("/dev/null"),
        ),
        (
            "&>=>>~/.zl;:",
            "{ print -r -- $1&>/dev/null }",
            Some("/dev/null"),
        ),
        (";=>>~/.zl;", "{ print -r -- $1; }", None),
        ("}=>>~/.zl; }", "{ print -r -- $1}", None),
    ] {
        let (name, value) = text.split_once('=').expect("a definition");
        let alias = format!("alias -g '{name}'='{value}'\n");
        let hooked = format!("HISTFILE=~/.zl\npreexec() {hook}\n");
        // Defined in ~/.zshrc above the hook, and in ~/.zshenv.
        for file in ["/home/alice/.zshrc", "/home/alice/.zshenv"] {
            let fs = MockFilesystem::new();
            if file == "/home/alice/.zshrc" {
                seed(&fs, file, &format!("{alias}{hooked}"));
            } else {
                seed(&fs, file, &alias);
                seed(&fs, "/home/alice/.zshrc", &hooked);
            }
            let doubts = scan(&fs, UNKNOWN).doubts;
            assert!(
                doubts.contains(&uncountable(text, file)),
                "{text} {hook}: {doubts:?}"
            );
            if let Some(target) = target {
                assert!(
                    doubts.contains(&under_alias("preexec", target, text, file)),
                    "{text} {hook}: {doubts:?}"
                );
            }
        }
    }
    // An empty name, which the check could not read, is such a doubt too.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", "galiases[]='>> ~/.zl'\n");
    assert!(
        scan(&fs, UNKNOWN)
            .doubts
            .contains(&uncountable("galiases[]=>> ~/.zl", "/home/alice/.zshrc")),
        "{:?}",
        scan(&fs, UNKNOWN)
    );
}

#[test]
fn a_hook_s_output_to_a_device_is_a_doubt_where_a_file_defines_any_global_alias() {
    // zsh may put a global alias's value in place of any token of the
    // redirection as it reads it, so with one of any name, used or not, the
    // check takes no target for a device.
    for (rc, hook, target, text) in [
        (
            "alias -g G='| grep'\nprecmd() { print -Pn '\\e]0;%~\\a' > $TTY }\n",
            "precmd",
            "$TTY",
            "G=| grep",
        ),
        (
            "alias -g ...='../..'\npreexec() { print -r -- $1 >/dev/null 2>&1 }\n",
            "preexec",
            "/dev/null",
            "...=../..",
        ),
        (
            "galiases[L]='| less'\nprecmd() { print -n x > /dev/tty }\n",
            "precmd",
            "/dev/tty",
            "galiases[L]=| less",
        ),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(
            scan(&fs, UNKNOWN).doubts,
            [under_alias(hook, target, text, "/home/alice/.zshrc")],
            "{rc}"
        );
    }
    // One an `exec` keeps open, and a global alias in another file.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshenv", "alias -g G='| grep'\n");
    seed(&fs, "/home/alice/.zshrc", "exec 2>/dev/null\n");
    assert_eq!(
        scan(&fs, UNKNOWN).doubts,
        [
            "it cannot tell where the output that `exec` in /home/alice/.zshrc redirects to \
          `/dev/null` goes, as /home/alice/.zshenv defines the global alias `G=| grep`, which \
          zsh may put in place of a word or an operator of it"
        ]
    );
    // Without one, each is none.
    for rc in [
        "precmd() { print -Pn '\\e]0;%~\\a' > $TTY }\n",
        "preexec() { print -r -- $1 >/dev/null 2>&1 }\n",
        "exec 2>/dev/null\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
}

#[test]
fn an_alias_word_an_expansion_makes_is_a_doubt() {
    // zsh 5.9.2 takes `$g` for `-g` here and makes `>` a global alias, which
    // then writes each command line to ~/.zl; a function that hands its
    // words to `alias` may do the same.
    for (rc, word) in [
        (
            "g=-g\nalias $g '>'='>>~/.zl;:'\npreexec() { print -r -- $1>$TTY }\n",
            "$g",
        ),
        ("ga() { alias -g \"$@\" }\nga '>=>>~/.zl;:'\n", "$@"),
        ("alias -$x '>=>>~/.zl;:'\n", "-$x"),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        let doubts = scan(&fs, UNKNOWN).doubts;
        assert!(
            doubts.iter().any(|doubt| {
                doubt.starts_with("it cannot tell which aliases `alias ")
                && doubt.ends_with(&format!(
                    "` in /home/alice/.zshrc defines, as an expansion, brace expansion or a glob \
                     may make `{word}` other words, which may be a flag that makes them global"
                ))
            }),
            "{rc}: {doubts:?}"
        );
    }
}

#[test]
fn arithmetic_that_may_set_a_name_the_check_cannot_read_is_a_doubt() {
    // zsh 5.9.2 sets TTY to `5` with each, as it reads `${n}TY` in arithmetic
    // after it expands `${n}`, and the value of a parameter that holds no
    // number as arithmetic too; the hook's output to $TTY then goes to
    // `./5`, a link to the history file. FPATH, _compdir, ZDOTDIR and HOME
    // set so make it load a compinit, read startup files elsewhere.
    for set in [
        "n=T\n(( ${n}TY = 5 ))",
        "n=T\nlet ${n}TY=5",
        "n=T\n: $(( ${n}TY = 5 ))",
        "n=T\na=(1)\n: ${a[${n}TY=5]}",
        "n=T\nprintf '%d' ${n}TY=5 >/dev/null",
        "n=T\n[[ ${n}TY=5 -eq 5 ]]",
        "n=T\nfor (( ${n}TY = 5; 0; )) { : }",
        "n=T\nrepeat $(( ${n}TY = 5, 0 )) :",
        "n=T\ninteger v\nv=${n}TY=5",
        "m=$(printf '%s%s=5' T TY)\n(( m ))",
        "m=$(printf '%s%s=5' T TY)\nSAVEHIST=m",
        "m=$x\nprint -r -- ${s: m}",
        "m=$x\nprint -r -- ${(l:m:)s}",
        "m=$x\nprint -r -- *([m])",
        "m=$x\na=(1)\na[m]=2",
        "m=$x\nshift m",
        "m=$x\ninteger m",
        "m=$x\ntypeset -i m",
        "m=$x\n(( a ? (m = 1) : m ))",
        "m=$x\n(( m++ ))",
        "m=$x\nunset 'a[m]'",
        "unset SAVEHIST\n(( SAVEHIST ))",
        "m=$x\na=([m]=1)",
        "m=$x\na+=([m]=1)",
        "m=$x\nprint -r -- ${${(z)s}[m]}",
        "m=$x\nprint -r -- ${s/(#b)(a)/${match[m]}}",
        "m=$x\ncase 1 in ($((m))) ;; esac",
        "m=$x\n(( sin(m) ))",
        "f() { local -h SECONDS=$1; (( SECONDS )) }",
        "m=$x\nf() { local -A k }\nk=(1)\nk[m]=2",
        "m=$x\ntypeset -A k\nunset k\nk[m]=2",
        "f() { local -i n=$1; }",
    ] {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("{set}\npreexec() {{ print -r -- \"$1\" >> $TTY }}\n"),
        );
        assert!(warns(&fs), "{set}");
    }
    for zshenv in ["n=Z\n(( ${n}DOTDIR = 5 ))\n", "n=H\n(( ${n}OME = 5 ))\n"] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshenv", zshenv);
        assert!(warns(&fs), "{zshenv}");
    }
    // Numbers, counts and tests, the parameters zsh keeps a number in, one an
    // expression assigns before it reads it, an array whose keys are strings,
    // and a function's own integer are none.
    for rc in [
        "(( $+commands[fzf] )) && print fzf\n",
        "HISTSIZE=10000\nSAVEHIST=$HISTSIZE\nKEYTIMEOUT=1\n",
        "for (( i = 0; i < 3; i++ )) { : }\n",
        "(( EUID == 0 )) && print root\n",
        "[[ $#x -gt 0 ]] && [[ $SHLVL -eq 1 ]]\n",
        "typeset -A key\nkey[Home]=${terminfo[khome]}\n[[ -n ${key[Home]} ]]\n",
        "f() { local -i n; }\n",
        "printf '%s\\n' \"$x\"\n",
        "print -r -- ${history[$((HISTCMD-1))]}\n",
        "(( ${precmd_functions[(I)x]} )) && print hooked\n",
        "(( bits = 1 << 2 ))\n",
        "print -r -- ${s:-n} ${s:h}\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
}

#[test]
fn a_file_the_code_may_make_before_zsh_reads_it_is_a_doubt() {
    // zsh 5.9.2 sources a file that its startup code makes first, which is
    // not there as the check reads the files, and turns SHARE_HISTORY on.
    for rc in [
        "cp ~/.src ~/.gen\n. ~/.gen\n",
        "ln -sf ~/.src ~/.gen\n[[ -f ~/.gen ]] && . ~/.gen\n",
        "cat ~/.src > ~/.gen\nsource ~/.gen\n",
        "tee ~/{.gen,.x} < ~/.src >/dev/null\n. ~/.gen\n",
        "f=~/.g\ncp ~/.src ${f}en\n. ~/.gen\n",
        "f=~/.gen\nmk() { print -r -- 'setopt share_history' > $f }\nmk\n. ~/.gen\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        seed(&fs, "/home/alice/.src", "setopt share_history\n");
        assert!(warns(&fs), "{rc}");
    }
    // One of the files zsh reads itself, made by one before it.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshenv", "cp ~/.src ~/.zshrc\n");
    seed(&fs, "/home/alice/.src", "setopt share_history\n");
    assert!(warns(&fs));
    // A file a test asks about before it is sourced, which nothing makes, a
    // write after zsh reads the file and one to a path that cannot be it
    // are none.
    for rc in [
        "[[ -f ~/.zshrc.local ]] && source ~/.zshrc.local\n",
        "if test -r ~/.fzf.zsh; then . ~/.fzf.zsh; fi\n",
        "[ -f ~/.p10k.zsh ] && . ~/.p10k.zsh\nprint x >> $HOME/.log\n",
        "ssh-agent -s > $HOME/.ssh/agent-env\n[[ -f ~/.x ]] && . ~/.x\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, NOT_LOGIN), Scan::default(), "{rc}");
    }
}

#[test]
fn a_hook_that_may_hand_the_command_line_to_a_program_in_its_environment_is_a_doubt() {
    // zsh 5.9.2 gives `logit` the exported LINE, which it appends to the
    // history file, with each.
    for rc in [
        "export LINE\npreexec() { LINE=$1; ~/bin/logit }\n",
        "preexec() { export LINE=$1; ~/bin/logit }\n",
        "preexec() { typeset -gx LINE=$1; ~/bin/logit }\n",
        "preexec() { read LINE <<< $1; logit }\n",
        "setopt allexport\npreexec() { local LINE=$1; logit }\n",
        "preexec() { LINE=$1 }\nprecmd() { logit }\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert!(warns(&fs), "{rc}");
    }
    // One local to the hook, or a hook that runs no program but builtins
    // and functions the files define, is none.
    for rc in [
        "preexec() { local LINE=$1; logit }\n",
        "preexec() { LINE=$1; print -Pn '\\e]0;%~\\a' }\n",
        "w() { : }\npreexec() { LINE=$1; w }\n",
        "preexec() { start=$SECONDS }\nprecmd() { notify-send done }\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{rc}");
    }
}

#[test]
fn a_file_the_code_may_write_before_zsh_reads_it_is_a_doubt() {
    // zsh 5.9.2 sources the line the code appends to the file first, which
    // the check does not see in the file as it reads it.
    for rc in [
        "cat ~/.src >> ~/.zshrc.local\n. ~/.zshrc.local\n",
        "cp ~/.src ~/.zshrc.local\n. ~/.zshrc.local\n",
        "f=~/.zshrc.local\nprint -r -- \"$(<~/.src)\" >> $f\n. ~/.zshrc.local\n",
        "f=~/.zshrc.local\nlog() { cat ~/.src >> $f }\nlog\n. ~/.zshrc.local\n",
        "zcompile ~/.zshrc.local.zwc ~/.src\n. ~/.zshrc.local\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        seed(&fs, "/home/alice/.zshrc.local", ":\n");
        seed(&fs, "/home/alice/.src", "setopt share_history\n");
        assert!(warns(&fs), "{rc}");
    }
    // A write after zsh reads it, or to another file, and a `touch`, which
    // writes nothing in it, are none.
    for rc in [
        ". ~/.zshrc.local\nprint x >> ~/.zshrc.local\n",
        "print x >> ~/.cache/log\n. ~/.zshrc.local\n",
        "touch $HISTFILE\n. ~/.zshrc.local\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        seed(&fs, "/home/alice/.zshrc.local", ":\n");
        assert_eq!(scan(&fs, NOT_LOGIN), Scan::default(), "{rc}");
    }
}
