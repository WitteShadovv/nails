// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The elements of `fpath` the check cannot follow even where it knows
//! where `fpath` starts: an empty one, which zsh reads as the directory it
//! runs in, and one that `SH_WORD_SPLIT` or `KSH_ARRAYS` may change.

use super::*;

/// What a typed Nix zsh whose `fpath` the check knows finds with `rc` as
/// `.zshrc`, and the stock `compinit` and `promptinit` in its own directory.
fn known_with(rc: &str) -> Scan {
    let fs = MockFilesystem::new();
    nix_zsh(
        &fs,
        &[OWN],
        &["compinit", "compaudit", "compdump", "promptinit"],
    );
    seed(&fs, "/home/alice/.zshrc", rc);
    scan_with(&fs, UNKNOWN, &install(&fs, &[]))
}

#[test]
fn an_empty_element_of_fpath_is_the_directory_zsh_runs_in() {
    // zsh 5.9.2 loads ./compinit with each, in the home a terminal starts it
    // in, in place of its own.
    for setter in [
        "FPATH+=:",
        "fpath[1,0]=",
        "fpath+=",
        "fpath[1]=''",
        "FPATH=:$FPATH",
        "FPATH=$FPATH:",
        "FPATH=",
        "fpath+=('')",
        "fpath[2,1]=",
    ] {
        let found = known_with(&format!("{setter}\nautoload -Uz compinit && compinit\n"));
        assert!(warned(&found), "{setter}");
    }
    // An element that names a directory is followed.
    assert_eq!(
        known_with("fpath=(~/zfn $fpath)\nautoload -Uz compinit && compinit\n"),
        Scan::default()
    );
}

#[test]
fn an_element_of_fpath_word_splitting_may_change_is_one_the_check_cannot_follow() {
    // zsh 5.9.2 splits `$fpath` at the `/` of IFS with SH_WORD_SPLIT on, into
    // directories that it looks in from where it runs, and makes `$fpath[1]`
    // the first element and `[1]` with KSH_ARRAYS on: it loads a compinit the
    // check does not read with each.
    for setup in [
        "setopt sh_word_split\nIFS=/\nfpath=($fpath)\n",
        "emulate sh -c 'IFS=/; fpath=($fpath)'\n",
        "set -y\nIFS=/\nfpath=(${fpath})\n",
        "fpath=(~/zfn $fpath)\nsetopt ksh_arrays\nfpath=($fpath[1] $fpath)\n",
    ] {
        let found = known_with(&format!("{setup}autoload -Uz compinit && compinit\n"));
        assert!(warned(&found), "{setup}");
    }
    // The check reads an element that an expansion gives as one it cannot
    // follow wherever a file read may turn either on, before or after it:
    // a function the files run may turn it on before the line runs.
    for setup in [
        "setopt shwordsplit\nfor d in ~/a; do fpath=($d $fpath); done\n",
        "fpath=($fpath)\nemulate ksh\n",
        "options[shwordsplit]=on\nfpath=($fpath)\n",
    ] {
        let found = known_with(&format!("{setup}autoload -Uz compinit && compinit\n"));
        assert!(warned(&found), "{setup}");
    }
    // IFS alone splits nothing, and zsh's own mode turns neither on.
    for setup in [
        "IFS=/\nfpath=($fpath)\n",
        "emulate -L zsh\nfpath=($fpath)\n",
        "fpath=(~/zfn $fpath)\nfpath=($fpath[1] $fpath)\n",
    ] {
        let found = known_with(&format!("{setup}autoload -Uz compinit && compinit\n"));
        assert_eq!(found, Scan::default(), "{setup}");
    }
    // NixOS's loop over the profiles, `$p` among its elements.
    let fs = MockFilesystem::new();
    nixos(&fs);
    seed(&fs, "/home/alice/.zshrc", "setopt shwordsplit\n");
    assert!(warned(&scan_with(&fs, UNKNOWN, &install(&fs, &SESSION))));
}

#[test]
fn a_theme_prompt_runs_from_a_hook_runs_as_a_hook() {
    // zsh 5.9.2 runs the theme each time the hook runs, which appends each
    // command line to the history file.
    let theme = "fc -ln -1 >> $f\n";
    for hook in [
        "precmd() { prompt w }",
        "preexec() { prompt w }",
        "precmd_functions+=(pw)\npw() { prompt w }",
        "pw() { prompt w }\nautoload -Uz add-zsh-hook\nadd-zsh-hook precmd pw",
        "precmd() { prompt restore }",
    ] {
        let fs = MockFilesystem::new();
        nix_zsh(
            &fs,
            &[OWN],
            &["promptinit", "add-zsh-hook", "add-zle-hook-widget"],
        );
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!(
                "fpath=(~/zpt $fpath)\nautoload -Uz promptinit\npromptinit\nf=$HISTFILE\n{hook}\n"
            ),
        );
        seed(&fs, "/home/alice/zpt/prompt_w_setup", theme);
        seed(&fs, "/home/alice/zpt/prompt_default_setup", theme);
        assert!(
            warned(&scan_with(&fs, UNKNOWN, &install(&fs, &[]))),
            "{hook}"
        );
    }
    // Run once at the top, the theme writes no command line.
    let fs = MockFilesystem::new();
    nix_zsh(
        &fs,
        &[OWN],
        &["promptinit", "add-zsh-hook", "add-zle-hook-widget"],
    );
    seed(
        &fs,
        "/home/alice/.zshrc",
        "fpath=(~/zpt $fpath)\nautoload -Uz promptinit\npromptinit\nf=$HISTFILE\nprompt w\n",
    );
    seed(&fs, "/home/alice/zpt/prompt_w_setup", theme);
    assert_eq!(scan_with(&fs, UNKNOWN, &install(&fs, &[])), Scan::default());
}

#[test]
fn a_completion_function_bound_to_keys_is_a_hook() {
    // zsh 5.9.2 runs `_foo` at each Space typed with each, which appends what
    // is typed to the history file.
    for bind in [
        "compdef -k _foo complete-word ' '",
        "compdef -K _foo sp complete-word ' '",
    ] {
        let fs = MockFilesystem::new();
        nix_zsh(&fs, &[OWN], &["compinit", "compaudit", "compdump"]);
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!(
                "f=$HISTFILE\nfpath=(~/zfn $fpath)\nautoload -Uz compinit && compinit\n{bind}\n"
            ),
        );
        seed(
            &fs,
            "/home/alice/zfn/_foo",
            "#autoload\nprint -r -- \"$BUFFER\" >> $f\n",
        );
        assert!(
            warned(&scan_with(&fs, UNKNOWN, &install(&fs, &[]))),
            "{bind}"
        );
    }
}

#[test]
fn an_expansion_of_fpath_that_joins_its_elements_is_one_the_check_cannot_follow() {
    // zsh 5.9.2 joins fpath into one element with each, a directory whose
    // name holds a blank or a `:` that it loads compinit from in place of its
    // own, or a function the files autoload.
    for setup in [
        "fpath=(~/a $fpath)\nfpath=(\"$fpath\")\n",
        "fpath=(~/a $fpath)\nfpath=(\"${fpath}\")\n",
        "fpath=(~/a $fpath)\nfpath=(\"${fpath[*]}\")\n",
        "fpath=(~/a $fpath)\nfpath=(\"${fpath[2,-1]}\")\n",
        "fpath=(~/a $fpath)\nfpath=(\"${(u)fpath}\")\n",
        "fpath=(~/a $fpath)\nfpath=($FPATH)\n",
        "fpath=(~/a $fpath)\nfpath=(${FPATH})\n",
        "fpath=(~/a $fpath)\nfpath+=\"$fpath\"\n",
        "fpath=(~/a $fpath)\nfpath[1]=$fpath\n",
        "fpath=(~/a $fpath)\nfpath+=$FPATH\n",
        "fpath=(~/a $fpath)\nFPATH=$fpath\n",
        "fpath=(~/a $fpath)\nFPATH=(x)\n",
        "fpath=('$fpath' $fpath)\n",
        "fpath=(\\$fpath $fpath)\n",
        "fpath=(~/a:b $fpath)\n",
    ] {
        let found = known_with(&format!("{setup}autoload -Uz compinit && compinit -D\n"));
        assert!(warned(&found), "{setup}");
    }
    // Its elements as they are, in quotes too where `@` keeps them apart, and
    // FPATH as a part of FPATH's value, are what fpath holds.
    for setup in [
        "fpath=(~/zfn \"${fpath[@]}\")\n",
        "fpath=(~/zfn \"${(@)fpath}\")\n",
        "fpath=(~/zfn ${fpath[@]})\n",
        "fpath=(~/zfn ${(u)fpath})\n",
        "fpath=(~/zfn \"${fpath[1]}\")\n",
        "FPATH=~/zfn:$FPATH\n",
        "FPATH=\"$HOME/zfn:$FPATH\"\n",
    ] {
        let found = known_with(&format!("{setup}autoload -Uz compinit && compinit -D\n"));
        assert_eq!(found, Scan::default(), "{setup}");
    }
}

#[test]
fn a_function_s_file_the_code_may_make_before_zsh_loads_it_is_a_doubt() {
    // zsh 5.9.2 loads the compinit the code copies into the directory in
    // front of fpath first, by a path an expansion makes, in place of its
    // own.
    for setup in [
        "d=~/zfn\nn=compinit\ncp ~/.src $d/$n\n",
        "cp ~/.src ~/zfn/comp${x:-init}\n",
        "cp ~/.src ~/zfn/compinit\n",
    ] {
        let rc = format!("{setup}fpath=(~/zfn $fpath)\nautoload -Uz compinit && compinit\n");
        assert!(warned(&known_with(&rc)), "{setup}");
    }
    // A write to another name is none.
    let rc = "cp ~/.src ~/zfn/other\nfpath=(~/zfn $fpath)\nautoload -Uz compinit && compinit\n";
    assert_eq!(known_with(rc), Scan::default());
}
