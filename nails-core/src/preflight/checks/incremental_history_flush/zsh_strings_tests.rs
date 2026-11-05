// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The code that zsh runs from a string the startup files hold: an alias's
//! value, a trap's, a `sched`'s, a `zstyle -e`'s and a prompt's, and what
//! expands a parameter's value again.

use super::*;

/// What a doubt about the alias `text` in `.zshrc` says.
fn alias(text: &str) -> String {
    format!("it cannot tell what the alias `{text}` in /home/alice/.zshrc runs where it is used")
}

/// What `rc`, as `.zshrc`, makes the check find.
fn read(rc: &str) -> Scan {
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", rc);
    scan(&fs, UNKNOWN)
}

/// What the warning names of `rc`, as `.zshrc`.
fn named(rc: &str) -> Vec<String> {
    read(rc)
        .writes
        .into_iter()
        .map(|write| write.what)
        .collect()
}

#[test]
fn an_alias_s_value_is_read_as_code_or_a_doubt() {
    // A value with nothing it cannot read is read as code.
    for (rc, write) in [
        (
            "alias s='setopt share_history; true'\n",
            "/home/alice/.zshrc names SHARE_HISTORY",
        ),
        (
            "alias save='fc -AI; true'\nprecmd() { save }\n",
            "/home/alice/.zshrc names `fc -AI`",
        ),
        (
            "aliases[save]='fc -W; :'\n",
            "/home/alice/.zshrc names `fc -W`",
        ),
    ] {
        assert_eq!(named(rc), [write], "{rc}");
        assert_eq!(read(rc).doubts, Vec::<String>::new(), "{rc}");
    }
    // One with an expansion, or that hands the words it is used with to a
    // command that reads them as options, code, names or paths, or that ends
    // with a blank, is a doubt.
    for (rc, text) in [
        ("alias x='$a $b'\n", "x=$a $b"),
        ("alias x=\"$cmd -AI\"\n", "x=$cmd -AI"),
        ("alias so=setopt\nso $o\n", "so=setopt"),
        ("alias s='setopt share_history'\n", "s=setopt share_history"),
        ("alias b='builtin '\n", "b=builtin "),
        ("aliases[x]='$a $b'\n", "aliases[x]=$a $b"),
    ] {
        let found = read(rc);
        assert!(found.doubts.contains(&alias(text)), "{rc}: {found:?}");
    }
    // An alias of a plain command is neither.
    assert_eq!(read("alias ll='ls -l'\nalias g=git\n"), Scan::default());
}

/// What a doubt about the alias `text` in `.zshrc` for an `fc` that writes
/// nothing, which the files use, says.
fn fc_alias(text: &str) -> String {
    format!(
        "it cannot tell what the alias `{text}` in /home/alice/.zshrc runs where it is used, as \
         zsh hands the fc it stands for the words after it"
    )
}

#[test]
fn an_alias_for_an_fc_that_writes_nothing_is_no_doubt_until_it_is_used() {
    // zsh 5.9.2 writes nothing to HISTFILE for these, typed or not.
    for rc in [
        "alias h='fc -l'\n",
        "alias h='fc -l 1'\n",
        "alias -- hist='fc -lnr -20'\n",
        "alias -r h='fc -li'\n",
        "alias r='fc -e -'\n",
        "alias h='builtin fc -l'\n",
        "aliases[h]='fc -l'\n",
        "alias ll='ls -l' h='fc -l'\n",
    ] {
        assert_eq!(read(rc), Scan::default(), "{rc}");
    }
    // Used in the files, it hands the fc the words after it: zsh 5.9.2 runs
    // `fc -l -W` from the first two after each command, which writes HISTFILE.
    for (rc, text) in [
        ("alias h='fc -l'\nprecmd() { h -W }\n", "h=fc -l"),
        ("alias h='fc -l'\nfunctions[precmd]='h -AI'\n", "h=fc -l"),
        ("alias h='fc -l'\neval 'precmd() { h -W }'\n", "h=fc -l"),
        ("alias h='fc -l'\nh\n", "h=fc -l"),
        ("alias h='fc -l' hh=h\n", "h=fc -l"),
        (
            "aliases[h]='fc -l'\nprecmd() { h -W }\n",
            "aliases[h]=fc -l",
        ),
        // A name that stands in a line for anything else counts too.
        (
            "alias h='fc -l'\nbindkey '^h' backward-delete-char\n",
            "h=fc -l",
        ),
    ] {
        let found = read(rc);
        assert!(found.doubts.contains(&fc_alias(text)), "{rc}: {found:?}");
    }
    // Used in another file it reads, too.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "alias h='fc -l'\nsource ~/.zsh/hooks.zsh\n",
    );
    seed(&fs, "/home/alice/.zsh/hooks.zsh", "precmd() { h -W }\n");
    assert_eq!(scan(&fs, UNKNOWN).doubts, [fc_alias("h=fc -l")]);
    // Any other value is read as before: a flag that writes, a word an
    // expansion makes, a blank at its end, a global or suffix alias.
    for (rc, text) in [
        ("alias h='fc -W'\n", "h=fc -W"),
        ("alias h='fc -lA'\n", "h=fc -lA"),
        ("alias h='fc -l -I -P'\n", "h=fc -l -I -P"),
        ("alias h=\"fc '-W'\"\n", "h=fc '-W'"),
        ("alias h='fc -l '\n", "h=fc -l "),
        ("alias -g h='fc -l'\n", "h=fc -l"),
        ("alias -s h='fc -l'\n", "h=fc -l"),
        ("galiases[h]='fc -l'\n", "galiases[h]=fc -l"),
        ("alias h='fc -l > ~/out'\n", "h=fc -l > ~/out"),
    ] {
        let found = read(rc);
        assert!(
            found.doubts.contains(&alias(text)) || !found.writes.is_empty(),
            "{rc}: {found:?}"
        );
    }
    assert!(!read("alias h=\"fc -l $n\"\n").doubts.is_empty());
}

#[test]
fn a_trap_s_or_a_sched_s_code_is_read_as_code_or_a_doubt() {
    for (rc, write) in [
        ("trap 'fc -AI' DEBUG\n", "/home/alice/.zshrc names `fc -AI`"),
        (
            "trap -- 'setopt share_history' USR1\n",
            "/home/alice/.zshrc names SHARE_HISTORY",
        ),
        ("sched +60 fc -W\n", "/home/alice/.zshrc names `fc -W`"),
        (
            "sched -o 10:00 'fc -AI'\n",
            "/home/alice/.zshrc names `fc -AI`",
        ),
    ] {
        assert_eq!(named(rc), [write], "{rc}");
        assert_eq!(read(rc).doubts, Vec::<String>::new(), "{rc}");
    }
    for (rc, doubt) in [
        (
            "trap \"$code\" DEBUG\n",
            "it cannot tell what code `trap $code` in /home/alice/.zshrc runs",
        ),
        (
            "trap '$a $b' DEBUG\n",
            "it cannot tell what code `trap $a $b` in /home/alice/.zshrc runs",
        ),
        (
            "sched +60 $cmd -W\n",
            "it cannot tell what command `sched ... $cmd -W` in /home/alice/.zshrc runs",
        ),
    ] {
        assert_eq!(read(rc).doubts, [doubt], "{rc}");
    }
    assert_eq!(
        read("trap - DEBUG\ntrap '' INT\nsched -1\n"),
        Scan::default()
    );
}

#[test]
fn a_zstyle_e_s_code_is_read_as_code_or_a_doubt() {
    assert_eq!(
        named("zstyle -e ':completion:*' hosts 'reply=(a b); fc -AI'\n"),
        ["/home/alice/.zshrc names `fc -AI`"]
    );
    assert_eq!(
        read("zstyle -e ':vcs_info:*' x \"$code\"\n").doubts,
        ["it cannot tell what code `zstyle -e ... $code` in /home/alice/.zshrc runs"]
    );
    assert_eq!(
        read("zstyle ':completion:*' menu select\n"),
        Scan::default()
    );
}

#[test]
fn a_prompt_s_code_is_a_doubt_where_prompt_subst_may_be_on() {
    let doubt = |text: &str| {
        format!(
            "it cannot follow the code that `{text}` in /home/alice/.zshrc runs as zsh shows the \
             prompt, as PROMPT_SUBST may be on"
        )
    };
    for (rc, text) in [
        (
            "setopt prompt_subst\nPS1='$(git_branch)%# '\n",
            "PS1=$(git_branch)%# ",
        ),
        ("setopt promptsubst\nRPROMPT=\"$x\"\n", "RPROMPT=$x"),
        ("PROMPT='${o::=x}'\nemulate ksh -c :\n", "PROMPT=${o::=x}"),
        ("unsetopt prompt_subst\nRPS1='`date`'\n", "RPS1=`date`"),
        (
            "setopt prompt_subst\nprint -P '$(git_branch)'\n",
            "print -P $(git_branch)",
        ),
    ] {
        let found = read(rc);
        assert!(found.doubts.contains(&doubt(text)), "{rc}: {found:?}");
    }
    // Without PROMPT_SUBST a prompt shows its code as text, and `$ ` is no
    // expansion.
    assert_eq!(
        read("PS1='$(git_branch)%# '\n").doubts,
        Vec::<String>::new()
    );
    assert_eq!(
        read("setopt prompt_subst\nPS1='%n@%m $ '\n").doubts,
        Vec::<String>::new()
    );
}

#[test]
fn what_expands_a_parameter_s_value_again_is_a_doubt() {
    let doubt = |text: &str| {
        format!(
            "it cannot follow the code that `{text}` in /home/alice/.zshrc may run, as it \
             expands a parameter's value again"
        )
    };
    for (rc, text) in [
        ("print ${(e)x}\n", "${(e)x}"),
        ("y=${(e)x}\n", "y=${(e)x}"),
        ("print ${(%%)x}\n", "${(%%)x}"),
        ("for f in ${~pattern}; do :; done\n", "${~pattern}"),
        ("print $~x\n", "$~x"),
    ] {
        let found = read(rc);
        assert!(found.doubts.contains(&doubt(text)), "{rc}: {found:?}");
    }
    assert_eq!(
        read("setopt globsubst\n").doubts,
        [
            "it cannot tell what code zsh runs from the values it expands as patterns, as \
             /home/alice/.zshrc names GLOB_SUBST, which makes a glob qualifier in a value run"
        ]
    );
    // Flags that do not expand the value again are no doubt, nor is one `%`,
    // which expands only a prompt's escapes.
    assert_eq!(
        read("print ${(j:,:)x} ${(@)x} ${=x} ${(s: :)x} ${(%):-%~}\n"),
        Scan::default()
    );
}

#[test]
fn an_fc_alias_used_where_a_line_that_starts_with_a_hash_or_a_backslash_hides_it_is_a_doubt() {
    // zsh 5.9.2 expands the alias in each and runs `fc -l -W`, which writes
    // HISTFILE after each command.
    for (rc, text) in [
        ("alias h='fc -l'\nprecmd() { x='\n#'; h -W }\n", "h=fc -l"),
        ("alias hh='fc -l'\nprecmd() { h\\\nh -W }\n", "hh=fc -l"),
    ] {
        assert_eq!(read(rc).doubts, [fc_alias(text)], "{rc}");
    }
}

#[test]
fn a_prompt_set_in_any_form_holds_code_where_prompt_subst_may_be_on() {
    // zsh 5.9.2 runs the code each sets at each prompt with PROMPT_SUBST on,
    // which writes the line before to HISTFILE.
    let code = "'$(print -r -- ${history[$((HISTCMD-1))]} >> $f)%# '";
    for set in [
        format!("print -v PS1 {code}"),
        format!(": ${{PS1::={code}}}"),
        format!("prompt={code}"),
        format!("PROMPT_EOL_MARK={code}"),
        format!("read -r PS1 <<< {code}"),
        format!("print -vPS1 {code}"),
    ] {
        let rc = format!("setopt prompt_subst\nf=$HISTFILE\n{set}\n");
        let found = read(&rc);
        assert!(!found.doubts.is_empty(), "{set}: {found:?}");
        // Without PROMPT_SUBST, the doubt holds only where a command line
        // turns it on.
        let found = read(&format!("f=$HISTFILE\n{set}\n"));
        assert!(
            found.doubts.is_empty() && !found.prompts.is_empty(),
            "{set}"
        );
    }
    // promptinit's `prompt`, a prompt taken away or declared, and a read of
    // one, are none.
    for rc in [
        "prompt suse\n",
        "unset RPS1 RPROMPT\n",
        "typeset PS1\n",
        "print -r -- $PS1 ${prompt}\n",
    ] {
        assert_eq!(read(rc), Scan::default(), "{rc}");
    }
}

#[test]
fn an_alias_for_a_command_whose_words_the_check_reads_is_a_doubt() {
    // compinit's dump file, prompt's theme and the hooks of add-zsh-hook
    // are in the words they are given, which an alias hands on.
    for (rc, text) in [
        ("alias ci=compinit\n", "ci=compinit"),
        ("alias p=prompt\n", "p=prompt"),
        ("alias azh=add-zsh-hook\n", "azh=add-zsh-hook"),
        ("alias z=zle\n", "z=zle"),
        ("alias bk=bindkey\n", "bk=bindkey"),
        ("alias fmt=zformat\n", "fmt=zformat"),
    ] {
        assert_eq!(read(rc).doubts, [alias(text)], "{rc}");
    }
}

#[test]
fn an_alias_named_like_a_reserved_word_is_a_doubt() {
    // zsh 5.9.2 expands an alias before it reads a reserved word: with each
    // of these the hook appends each command line to ~/.zl, the history
    // file, where the reserved word starts a command in it.
    let reserved = |text: &str, word: &str| {
        format!(
            "it cannot tell what the alias `{text}` in /home/alice/.zshrc runs where it is used, \
             as zsh expands it in place of the reserved word `{word}` wherever that starts a \
             command"
        )
    };
    let write = "fc -ln -1 >>~/.zl;";
    for (rc, text, word) in [
        (
            format!("alias '{{'='{{ {write}'\npreexec() {{ :; }}\n"),
            format!("{{={{ {write}"),
            "{",
        ),
        (
            format!("alias do='do {write}'\npreexec() {{ for x in 1; do :; done }}\n"),
            format!("do=do {write}"),
            "do",
        ),
        (
            format!("alias then='then {write}'\npreexec() {{ if true; then :; fi }}\n"),
            format!("then=then {write}"),
            "then",
        ),
        (
            format!("alias fi='{write} fi'\npreexec() {{ if true; then :; fi }}\n"),
            format!("fi={write} fi"),
            "fi",
        ),
        (
            format!("alias '}}'='{write} }}'\npreexec() {{ :\n}}\n"),
            format!("}}={write} }}"),
            "}",
        ),
        (
            format!("aliases[end]='{write} end'\npreexec() {{ foreach x (1) : ; end }}\n"),
            format!("aliases[end]={write} end"),
            "end",
        ),
    ] {
        assert!(
            read(&rc).doubts.contains(&reserved(&text, word)),
            "{rc}: {:?}",
            read(&rc)
        );
    }
    // One named like a precommand runs where a hook runs that precommand, as
    // a function of its name would: zsh 5.9.2 appends each command line to
    // ~/.zl with each, and runs `cd -` alone with the last.
    for (rc, name) in [
        (
            format!("alias '!'='{write} :'\npreexec() {{ ! false }}\n"),
            "!",
        ),
        (
            format!("alias -- -='{write} cd -'\npreexec() {{ - : }}\n"),
            "-",
        ),
        (
            format!("alias time='{write} :'\npreexec() {{ time : }}\n"),
            "time",
        ),
    ] {
        assert!(
            read(&rc).doubts.contains(&format!(
                "it cannot tell whether `~/.zl`, which `{name}` in /home/alice/.zshrc redirects \
                 output to, is the history file (a file HISTFILE names, or a link to it)"
            )),
            "{rc}: {:?}",
            read(&rc)
        );
    }
    assert_eq!(
        read("alias -- -='cd -'\npreexec() { - : }\n"),
        Scan::default()
    );
    // A global alias of such a name is counted where a word is its name, and
    // an alias named like a builtin runs as a hook where the builtin does.
    assert_eq!(read("alias -g if=x\n"), Scan::default());
    assert_ne!(
        read("alias print='print -r -- $1 >>~/.zl; print'\npreexec() { print }\n"),
        Scan::default()
    );
}

#[test]
fn what_a_sched_a_zstyle_e_or_a_bindkey_s_runs_is_a_hook_s() {
    // zsh 5.9.2 writes each command line to HISTFILE with each: what sched
    // runs at its time, a style's code as vcs_info looks it up at each
    // prompt, and the line a key types.
    for rc in [
        "zmodload zsh/sched\nf=$HISTFILE\nw() { print -r -- ${history[$((HISTCMD-1))]} >> $f; \
         sched +1 w }\nsched +1 w\n",
        "f=$HISTFILE\nautoload -Uz vcs_info\nzstyle -e ':vcs_info:*' enable \
         'print -r -- ${history[$((HISTCMD-1))]} >> $f; reply=(git)'\nprecmd() { vcs_info }\n",
        "bindkey -s '^M' '^Jfc -AI^J'\n",
        "f=$HISTFILE\nw() { print -r -- ${history[$((HISTCMD-1))]} >> $f }\nbindkey -s '^M' '^J w^J'\n",
    ] {
        assert_ne!(read(rc), Scan::default(), "{rc}");
    }
    // Keys that type a line the check reads whole, and a binding of a key
    // to a widget, are none.
    for rc in [
        "bindkey -s '^o' 'lfcd\\n'\nlfcd() { cd ~/x }\n",
        "bindkey '^[[A' up-line-or-search\n",
    ] {
        assert_eq!(read(rc), Scan::default(), "{rc}");
    }
    // A string with an escape key or a number, or an expansion, is a doubt.
    for rc in [
        "bindkey -s '^o' '^[xaccept-line^M'\n",
        "bindkey -s '^o' '\\033[A'\n",
        "bindkey -s '^o' \"$cmd\"\n",
    ] {
        assert!(!read(rc).doubts.is_empty(), "{rc}");
    }
}

#[test]
fn keys_that_edit_the_line_or_a_name_glued_to_a_key_in_a_bindkey_s_count() {
    // zsh 5.9.2 runs `setopt sharehistory` or `fc -AI` with each, as Ctrl-A
    // moves to the start and Backspace erases, uses the alias `h` and sets
    // TTY with the last two, which a key glued to the word hides.
    for rc in [
        "bindkey -e\nbindkey -s '^M' '^Jhistory^Asetopt share^J'\n",
        "bindkey -e\nbindkey -s '^M' '^Jsetopt sharehistorx^Hy^J'\n",
        "bindkey -e\nbindkey -s '^M' '^Jfc -IX ^H^H^HAI^J'\n",
        "bindkey -e\nalias h='fc -l'\nbindkey -s '^M' '^Jh -W^J'\n",
        "bindkey -e\npreexec() { print -r -- \"$1\" >> $TTY }\n\
         bindkey -s '^M' '^JTTY=~/.zsh_history^J'\n",
        // A string bound in another keymap, where keys are commands.
        "bindkey -M vicmd -s Q 'x^M'\n",
        "bindkey -a -s Q 'x^M'\n",
        // A brace expansion, which zsh 5.9.2 makes two words of here: `q`
        // then types the line that defines the hook.
        "bindkey -s {q,'preexec() { print -r -- $1 >>~/.zl }^M'}\n",
    ] {
        assert_ne!(read(rc), Scan::default(), "{rc}");
    }
    // A key a line is typed with bound to a widget, unbound, a widget made
    // or a keymap linked may change what a string's keys type.
    for more in [
        "bindkey jk vi-cmd-mode",
        "bindkey -r a",
        "bindkey -s xx 'y'",
        "zle -N self-insert f\nf() { zle .self-insert }",
        "bindkey -A vicmd main",
    ] {
        let rc = format!("bindkey -s '^o' 'lfcd^M'\n{more}\n");
        assert_ne!(read(&rc), Scan::default(), "{rc}");
    }
    for rc in [
        "bindkey -s '^o' 'lfcd^M'\nbindkey '^R' history-incremental-search-backward\n",
        "bindkey -s '^o' 'lfcd^M'\nbindkey a self-insert\n",
    ] {
        assert_eq!(read(rc), Scan::default(), "{rc}");
    }
}

#[test]
fn what_print_z_puts_in_the_line_is_read_as_a_hook_s_code() {
    // zsh 5.9.2 edits the line `print -z` gives next, which a widget may
    // accept (`zle-line-init() { zle accept-line }`).
    for rc in [
        "print -z 'setopt sharehistory'\n",
        "print -z -- \"$cmd\"\n",
        "print -z 'fc -AI'\n",
        "alias h='fc -l'\nprint -z 'h -W'\n",
        "print -z 'x\\ny'\n",
    ] {
        assert_ne!(read(rc), Scan::default(), "{rc}");
    }
    assert_eq!(read("print -z 'ls -l'\n"), Scan::default());
    assert_eq!(read("print -rz -- 'cd ~/src'\n"), Scan::default());
}

#[test]
fn an_alias_whose_value_leaves_a_definition_or_a_structure_open_is_a_doubt() {
    // zsh 5.9.2 reads an alias's value with the words where it is used: with
    // each of these it defines preexec, which appends each command line to
    // ~/.zl before it runs.
    for (rc, text) in [
        (
            "alias f=function\nf preexec { print -r -- $1 >>~/.zl }\n",
            "f=function",
        ),
        (
            "alias f='function preexec'\nf { print -r -- $1 >>~/.zl }\n",
            "f=function preexec",
        ),
        (
            "alias b='{'\npreexec() b print -r -- $1 >>~/.zl; }\n",
            "b={",
        ),
    ] {
        assert!(
            read(rc).doubts.contains(&alias(text)),
            "{rc}: {:?}",
            read(rc)
        );
    }
    // One that closes what it opens is read as code.
    for rc in [
        "alias x='if true; then :; fi'\n",
        "alias -g G='| grep'\n",
        "alias x='for i in 1; do :; done'\n",
    ] {
        assert_eq!(read(rc), Scan::default(), "{rc}");
    }
}
