// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What may make zsh read the files' code or a builtin's words otherwise
//! than as they are written: the options that change how zsh reads code,
//! the words that brace expansion or a glob may make flags or names of, and
//! the options of the builtins the check reads, as zsh reads them.

use super::*;

/// What `rc`, the user's `.zshrc`, sets.
fn read(rc: &str) -> Scan {
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", rc);
    scan(&fs, UNKNOWN)
}

/// Whether the check warns on `rc`, the user's `.zshrc`.
fn warns(rc: &str) -> bool {
    let found = read(rc);
    !found.doubts.is_empty() || !found.writes.is_empty()
}

#[test]
fn a_histchars_set_makes_the_files_comment_lines_a_doubt() {
    // zsh 5.9.2 starts a comment only at histchars' third character: with
    // each of these the line after it runs, and zsh writes each command line
    // to the history file in the extended form SHARE_HISTORY writes.
    let doubt = |place: &str| {
        format!(
            "it cannot tell which lines of the files zsh runs, as {place} sets histchars, whose \
             third character starts a comment in place of `#`"
        )
    };
    for set in [
        "histchars='!^'",
        "HISTCHARS='!^%'",
        "typeset histchars='!^'",
        "histchars=",
        ": ${histchars::=!^}",
    ] {
        assert_eq!(
            read(&format!("{set}\n# x; setopt share_history\n")).doubts,
            [doubt("/home/alice/.zshrc")],
            "{set}"
        );
    }
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshenv", "histchars='!^'\n");
    seed(&fs, "/home/alice/.zshrc", "# x; setopt share_history\n");
    assert_eq!(scan(&fs, UNKNOWN).doubts, [doubt("/home/alice/.zshenv")]);
    // A comment is none where nothing sets it.
    assert_eq!(read("# x; setopt share_history\n"), Scan::default());
}

#[test]
fn quotes_zsh_may_read_otherwise_are_a_doubt() {
    // zsh 5.9.2 reads `''` in a quoted string as a quote with RC_QUOTES, so
    // that this `eval` defines preexec, which appends each command line to
    // ~/.zl before it runs; without the option it prints a string.
    let eval = "eval 'print '\\''a'';preexec() { print -r -- $1 >>~/.zl };''b'\\'\n";
    let doubt = "it cannot read the quotes of the files as zsh may, as /home/alice/.zshrc may turn \
                 RC_QUOTES or CSH_JUNKIE_QUOTES on, which change what a quote holds";
    for set in [
        "setopt rcquotes",
        "setopt RC_QUOTES",
        "setopt cshjunkiequotes",
        "emulate csh",
        "emulate -R csh",
    ] {
        assert!(
            read(&format!("HISTFILE=~/.zl\n{set}\n{eval}"))
                .doubts
                .contains(&doubt.to_string()),
            "{set}"
        );
    }
    assert_eq!(read(&format!("HISTFILE=~/.zl\n{eval}")), Scan::default());
}

#[test]
fn a_close_brace_after_words_is_a_doubt_where_braces_may_be_ignored() {
    // zsh 5.9.2 reads the `}` after `:` as a word of it with each of these,
    // so that preexec runs the print line after it, which appends each
    // command line to ~/.zl before it runs.
    let doubt = "it cannot tell where the code that `: }` in /home/alice/.zshrc ends with its `}` \
                 ends, as /home/alice/.zshrc may turn IGNORE_BRACES or IGNORE_CLOSE_BRACES on, \
                 with which that `}` is a word of the command";
    for set in [
        "setopt ignore_close_braces",
        "setopt ignorebraces",
        "setopt nobraceexpand",
        "unsetopt brace_expand",
        "set -I",
        "emulate sh",
        "emulate -L sh",
        "emulate bash",
    ] {
        let rc =
            format!("HISTFILE=~/.zl\n{set}\npreexec() {{ : }}\nprint -r -- \"$1\" >>~/.zl\n}}\n");
        assert!(
            read(&rc).doubts.contains(&doubt.to_string()),
            "{set}: {:?}",
            read(&rc)
        );
    }
    // Where no file names them a `}` closes after words, and where one
    // does, one in a command's place closes as in zsh's default.
    for rc in [
        "HISTFILE=~/.zl\npreexec() { : }\n",
        "HISTFILE=~/.zl\nsetopt ignorebraces\npreexec() { :; }\nprecmd() {\n  :\n}\n",
        "emulate ksh\npreexec() { : }\n",
    ] {
        assert_eq!(read(rc), Scan::default(), "{rc}");
    }
}

#[test]
fn a_function_an_alias_may_rename_is_a_doubt_where_alias_func_def_may_be_on() {
    // zsh 5.9.2 defines preexec or zshaddhistory with each of these, which
    // appends each command line to ~/.zl before it runs.
    let doubt = "it cannot tell which function `foo ()` in /home/alice/.zshrc defines, as \
                 /home/alice/.zshrc may turn ALIAS_FUNC_DEF on, with which zsh puts the value of \
                 the alias `foo` in place of its name";
    for (set, alias) in [
        ("setopt aliasfuncdef", "alias foo=preexec"),
        ("setopt ALIAS_FUNC_DEF", "alias foo='bar preexec'"),
        ("setopt aliasfuncdef", "alias foo=zshaddhistory"),
        ("emulate ksh", "aliases[foo]=preexec"),
    ] {
        let rc = format!("HISTFILE=~/.zl\n{set}\n{alias}\nfoo() {{ print -r -- $1 >>~/.zl; }}\n");
        assert!(
            read(&rc).doubts.contains(&doubt.to_string()),
            "{set} {alias}: {:?}",
            read(&rc)
        );
    }
    // Without the option zsh refuses such a definition, and one no alias
    // names or made with `function` takes no alias's value.
    for rc in [
        "alias foo=preexec\nfoo() { print -r -- $1 >>~/.zl; }\n",
        "setopt aliasfuncdef\nalias bar=preexec\nfoo() { print -r -- $1 >>~/.zl; }\n",
        "setopt aliasfuncdef\nalias foo=preexec\nfunction foo { print -r -- $1 >>~/.zl; }\n",
    ] {
        assert_eq!(read(rc), Scan::default(), "{rc}");
    }
}

#[test]
fn prompt_vars_turns_prompt_subst_on() {
    // zsh 5.9.2 runs the prompt's command substitution with each, as
    // PROMPT_VARS is its other name for PROMPT_SUBST.
    for set in [
        "setopt promptvars",
        "setopt PROMPT_VARS",
        "set -o prompt_vars",
        "options[promptvars]=on",
    ] {
        let found = read(&format!("{set}\nPS1='$(fc -ln -1 >>~/.zl)%# '\n"));
        assert_eq!(
            found.doubts,
            [
                "it cannot follow the code that `PS1=$(fc -ln -1 >>~/.zl)%# ` in \
                 /home/alice/.zshrc runs as zsh shows the prompt, as PROMPT_SUBST may be on"
            ],
            "{set}"
        );
    }
    assert!(read("PS1='$(fc -ln -1 >>~/.zl)%# '\n").doubts.is_empty());
}

#[test]
fn a_word_brace_expansion_or_a_glob_may_make_a_flag_or_a_name_of_is_a_doubt() {
    // zsh 5.9.2 expands each word before the builtin reads it, and with each
    // of these, with a file the glob matches where it runs for `-[g]` and the
    // `setopt` globs, made `>` a global alias, `h` an alias of fc a hook gives
    // `-AI`, an alias named `do`, SHARE_HISTORY on, a copy of a function to
    // preexec, a widget it runs as each line is entered or one bound to Space,
    // ran `fc -AI` or set the widgets style add-zle-hook-widget runs, and
    // wrote each command line to the history file.
    let write = "print -r -- $1$BUFFER >>~/.zl";
    for rc in [
        "alias {-g,-g} '>'='>>~/.zl;:'\npreexec() { print -r -- $1>$TTY }\n".to_string(),
        "alias {-,-}g '>'='>>~/.zl;:'\npreexec() { print -r -- $1>/dev/null }\n".to_string(),
        "alias -[g] '>'='>>~/.zl;:'\npreexec() { print -r -- $1>$TTY }\n".to_string(),
        "alias {h,h}='fc -l'\nprecmd() { h -AI }\n".to_string(),
        "alias h{,}='fc -l'\nprecmd() { h -AI }\n".to_string(),
        "alias {do,do}='do fc -ln -1 >>~/.zl;'\npreexec() { for x in 1; do :; done }\n".to_string(),
        "setopt {-m,'*hare*'}\n".to_string(),
        "setopt s[h]are_history\n".to_string(),
        "setopt shar?_history\n".to_string(),
        "set {-o,share_history}\n".to_string(),
        format!("logger() {{ {write} }}\nfunctions {{-c,logger}} preexec\n"),
        format!("w() {{ {write} }}\nzle {{-N,zle-line-finish}} w\n"),
        format!("_w() {{ {write} }}\nzle {{-C,w}} complete-word _w\nbindkey ' ' w\n"),
        "precmd() { fc {-AI,-AI} }\n".to_string(),
        "zstyle -- zle-line-finish {widgets,x} 0:complete-word\n".to_string(),
    ] {
        assert!(warns(&rc), "{rc}: {:?}", read(&rc));
    }
    // A first word of `zstyle` and a `trap`'s code that brace expansion may
    // make others of are doubts by the same rule.
    for rc in [
        "zstyle {--,zle-line-finish} widgets 0:complete-word\n",
        "trap {'fc -AI',:} DEBUG\n",
    ] {
        assert!(warns(rc), "{rc}: {:?}", read(rc));
    }
    // The same words quoted, which zsh does not expand, or as written.
    for rc in [
        "alias h='fc -l'\n",
        "setopt hist_ignore_dups\n",
        "logger() { : }\nfunctions -c logger mylogger\n",
        "zle -N zle-line-finish w\nw() { : }\n",
        "zstyle ':completion:*' menu select\n",
    ] {
        assert_eq!(read(rc), Scan::default(), "{rc}");
    }
}

#[test]
fn a_zstyle_s_definition_past_a_dash_is_read() {
    // zsh 5.9.2 takes a first word `-` or one that starts with `--` for a
    // definition of the style past it, as the stock add-zle-hook-widget
    // writes its own, and with each runs complete-word as each line is
    // entered, whose completer then appends the line to the history file.
    for flag in ["--", "-", "--x"] {
        let rc = format!("zstyle {flag} zle-line-finish widgets 0:complete-word 1:d\n");
        assert_eq!(
            read(&rc).doubts,
            [format!(
                "it cannot tell which widgets `zstyle {flag} zle-line-finish widgets \
                 0:complete-word 1:d` in /home/alice/.zshrc makes add-zle-hook-widget run as \
                 each line is entered"
            )],
            "{flag}"
        );
    }
    // Any other flag lists, looks up or deletes styles.
    for rc in [
        "zstyle -L\n",
        "zstyle -d zle-line-finish widgets\n",
        "zstyle -s zle-line-finish widgets w\n",
    ] {
        assert_eq!(read(rc), Scan::default(), "{rc}");
    }
}

#[test]
fn zle_s_options_are_read_as_zsh_reads_them() {
    // zsh 5.9.2 runs complete-word with each of these flags, which pick no
    // operation of zle, as each line is entered, and makes w the function of
    // zle-line-finish with `-aN` and `--N`: each writes each command line to
    // the history file, with a completer that appends $BUFFER to it.
    for flags in ["-w", "-m", "-a", "-c", "-g", "-r", "-L", "-wL", "--w"] {
        let rc = format!("f() {{ zle {flags} complete-word }}\nzle -N zle-line-finish f\n");
        assert!(warns(&rc), "{rc}");
    }
    for flags in ["-aN", "--N", "-N --", "-wN"] {
        let rc = format!("w() {{ print -r -- $BUFFER >>~/.zl }}\nzle {flags} zle-line-finish w\n");
        assert!(warns(&rc), "{rc}: {:?}", read(&rc));
    }
    // A widget that does not complete, a flag zle does not take, and one
    // that makes no widget.
    for rc in [
        "f() { zle -w reset-prompt }\nzle -N zle-line-finish f\n",
        "zle -X complete-word\n",
        "zle -l\nzle -R\n",
    ] {
        assert_eq!(read(rc), Scan::default(), "{rc}");
    }
}

#[test]
fn a_copy_of_a_stock_function_under_another_name_is_a_doubt() {
    // zsh 5.9.2 makes f a hook through each copy, and f then appends each
    // command line to ~/.zl before it runs.
    for (rc, from, to) in [
        (
            "autoload -Uz add-zsh-hook\nfunctions -c add-zsh-hook azh\nf() { print -r -- $1 \
             >>~/.zl; }\nazh preexec f\n",
            "add-zsh-hook",
            "azh",
        ),
        (
            "autoload -Uz add-zle-hook-widget\nfunctions -c add-zle-hook-widget azw\n",
            "add-zle-hook-widget",
            "azw",
        ),
    ] {
        assert!(
            read(rc).doubts.contains(&format!(
                "it cannot follow what `{to}` does in place of `{from}`, which `functions -c` in \
                 /home/alice/.zshrc copies it from and whose work the check reads by its name"
            )),
            "{rc}: {:?}",
            read(rc)
        );
    }
}

#[test]
fn command_s_and_exec_s_options_are_read_as_zsh_reads_them() {
    // zsh 5.9.2 drops `command`'s `-p` and, with POSIX_BUILTINS, runs the
    // builtin alias, which makes `>` a global alias that writes each command
    // line to ~/.zl with the first. Past `exec`'s options, and where an
    // expansion or brace expansion makes the command's name, it may run it
    // too.
    for rc in [
        "setopt posixbuiltins\ncommand -p alias -g '>'='>>~/.zl;:'\npreexec() { print -r -- \
         $1>$TTY }\n",
        "setopt posixbuiltins\ncommand -p -- alias -g '>'='>>~/.zl;:'\n",
        "exec -a myzsh -l alias -g '>'='>>~/.zl;:'\n",
        "ali$s -g '>'='>>~/.zl;:'\n",
        "{command,-p} alias -g '>'='>>~/.zl;:'\n",
    ] {
        assert!(warns(rc), "{rc}");
    }
    // With `-v` it prints what each word is and runs nothing.
    assert_eq!(
        read("command -v alias -g '>'='>>~/.zl;:'\n"),
        Scan::default()
    );
}

#[test]
fn a_command_whose_words_all_vanish_runs_what_nullcmd_names() {
    // zsh 5.9.2 runs `cat` or `more` for a redirection whose command's words
    // all expand to none: with each the hook appends each command line to
    // ~/.zl, the history file.
    for (name, hook) in [
        ("cat", "/no/such*(N) >/dev/null"),
        ("more", "/no/such*(N) </dev/null"),
        ("cat", "$empty >/dev/null"),
    ] {
        let rc =
            format!("HISTFILE=~/.zl\n{name}() {{ fc -ln -1 >> ~/.zl }}\npreexec() {{ {hook} }}\n");
        assert!(
            read(&rc).doubts.contains(&format!(
                "it cannot tell whether `~/.zl`, which `{name}` in /home/alice/.zshrc redirects \
                 output to, is the history file (a file HISTFILE names, or a link to it)"
            )),
            "{hook}: {:?}",
            read(&rc)
        );
    }
    // A word that stays leaves a command, and an assignment alone runs none.
    for hook in ["print x >/dev/null", "x=1 >/dev/null"] {
        let rc = format!("cat() {{ fc -ln -1 >> ~/.zl }}\npreexec() {{ {hook} }}\n");
        assert_eq!(read(&rc), Scan::default(), "{hook}");
    }
}

#[test]
fn a_global_alias_named_with_any_operator_character_or_a_blank_is_a_doubt() {
    // zsh splits a word at each of these, and at a blank, so the check
    // cannot count where it expands such an alias.
    for name in ["<", "|", "&", "(", ")", "{", "}", ";", ">", "a b", "x>y"] {
        let text = format!("{name}=x");
        let rc = format!("alias -g '{name}'=x\n");
        assert!(
            read(&rc).doubts.contains(&format!(
                "it cannot tell what code the global alias `{text}` in /home/alice/.zshrc runs, \
                 as zsh puts its value in place of each token that is its name, which the check \
                 cannot count where the name holds an operator, a brace or a blank, or is empty"
            )),
            "{name}: {:?}",
            read(&rc)
        );
    }
}

#[test]
fn emulate_s_mode_is_read_by_its_first_letter() {
    // zsh 5.9.2 picks the mode by its first letter past one `r`, and turns
    // SHARE_HISTORY on with each of these.
    for (rc, written) in [
        ("emulate -R rksh\n", "rksh"),
        ("emulate -R korn\n", "korn"),
        ("emulate -R k\n", "k"),
        ("emulate -R ksh93\n", "ksh93"),
        ("emulate -LR rksh\n", "rksh"),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(
            on(&fs, UNKNOWN),
            [format!(
                "/home/alice/.zshrc runs `emulate -R {written}`, whose reset to ksh's defaults \
                 turns on SHARE_HISTORY"
            )],
            "{rc}"
        );
    }
    // A word brace expansion or a glob may make the flags or the mode of, as
    // zsh 5.9.2 makes `-R ksh` of `{-R,ksh}`, is a doubt.
    for (rc, word) in [
        ("emulate {-R,ksh}\n", "{-R,ksh}"),
        ("emulate -{R,R} ksh\n", "-{R,R}"),
        ("emulate -R [k]sh\n", "[k]sh"),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert!(
            scan(&fs, UNKNOWN).doubts.contains(&format!(
                "it cannot tell what `emulate {word}` in /home/alice/.zshrc turns on"
            )),
            "{rc}: {:?}",
            scan(&fs, UNKNOWN)
        );
    }
}

#[test]
fn a_builtin_s_words_handed_on_may_make_a_widget_or_its_style() {
    // One that hands its words on may make a widget or set the style
    // add-zle-hook-widget reads (`myzle -N zle-line-finish w`).
    for (rc, doubt) in [
        (
            "myzle() { builtin zle \"$@\" }\n",
            "it cannot tell what `zle $@` in /home/alice/.zshrc does, as zsh may expand `$@` \
             into its options",
        ),
        (
            "mystyle() { builtin zstyle \"$@\" }\n",
            "it cannot tell which widgets `zstyle $@` in /home/alice/.zshrc makes \
             add-zle-hook-widget run as each line is entered",
        ),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan(&fs, UNKNOWN).doubts, [doubt], "{rc}");
    }
}
