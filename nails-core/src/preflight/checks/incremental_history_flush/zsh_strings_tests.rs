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
