// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What zsh may run as you complete a word: wherever zsh may load a
//! `compinit`, a doubt; without one, `compctl` and bash's `complete`, and
//! the function a completion widget runs, which is a hook.

use super::*;

/// The `.zshrc` lines that run the stock `compinit`.
const COMPINIT: &str = "autoload -Uz compinit && compinit -D\n";

/// What a typed Nix zsh with zsh's own `compinit` and `promptinit` in its
/// own directory finds with `rc` as `.zshrc`, and `fs` with what a test
/// seeds besides.
fn found_with(fs: &MockFilesystem, rc: &str) -> Scan {
    nix_zsh(fs, &[OWN], &["compinit", "promptinit"]);
    seed(fs, "/home/alice/.zshrc", rc);
    scan_with(fs, UNKNOWN, &install(fs, &[]))
}

/// What [`found_with`] finds in a filesystem of its own.
fn found(rc: &str) -> Scan {
    found_with(&MockFilesystem::new(), rc)
}

#[test]
fn compinit_is_a_doubt_whatever_the_files_hold_beside_it() {
    // zsh 5.9 to 5.9.2's own completion functions run code that programs
    // print (`_comp_locale`, `_npm`), parse from their help (`_arguments --`
    // for `tar`) and take from the styles, parameters and files they read,
    // so the check doubts compinit itself, with what the files set for it or
    // not.
    for line in [
        "",
        "zstyle ':completion:*' menu select",
        "zstyle ':completion:*' completer _w",
        "zstyle ':completion:*' command 'print -r -- \"$BUFFER\" >> ~/.zl; ps'",
        "_comp_options+=(globdots)",
        "fpath=(~/zc $fpath)",
        "bindkey ' ' complete-word",
    ] {
        assert_eq!(
            found(&format!("{COMPINIT}{line}\n")).doubts,
            [COMPINIT_DOUBT],
            "{line}"
        );
    }
}

#[test]
fn what_only_zsh_s_completion_system_runs_is_none_without_compinit() {
    // Without compinit, zsh runs none of zsh's own completion functions as
    // you complete a word: zsh 5.9.2 runs none of these, and its builtin
    // completion runs no code of the files.
    for line in [
        "zstyle ':completion:*' menu 'select=1+x'",
        "zstyle ':completion:*' command 'print -r -- \"$BUFFER\" >> ~/.zl; ps'",
        "zstyle ':completion:*' completer _w",
        "typeset -gA _comps; _comps[print]=_w",
        "_patch_args=( '--zz=[x]:y:{print -r -- $BUFFER >> ~/.zl}' )",
        "bindkey ' ' complete-word",
        "bindkey '^[[D' complete-word",
        "zle -A complete-word accept-line",
    ] {
        assert_eq!(found(&format!("{line}\n")), Scan::default(), "{line}");
    }
    // The function a completion widget runs is a hook, compinit or not.
    let rc = "_w() { print -r -- \"$BUFFER\" >> ~/.zl }\nzle -C w complete-word _w\n";
    assert!(warned(&found(rc)));
}

#[test]
fn compctl_and_complete_are_a_doubt_with_compinit_or_without() {
    // zsh 5.9.2 runs `w2` as Tab completes a word of `print` with compctl's
    // completion, which needs no compinit, and `_w` with bashcompinit's.
    for line in [
        "compctl -K w2 print",
        "complete -F _w print",
        "complete -C logger print",
    ] {
        assert_eq!(
            found(&format!("{line}\n")).doubts,
            [format!(
                "it cannot tell what `{line}` in /home/alice/.zshrc makes zsh run as you \
                 complete a word"
            )],
            "{line}"
        );
        assert!(warned(&found(&format!("{COMPINIT}{line}\n"))), "{line}");
    }
}

#[test]
fn a_compiled_digest_an_element_of_fpath_names_is_a_doubt() {
    // zsh 5.9.2 loads the functions in `~/zc.zwc` from the digest itself
    // (`fpath=(~/zc.zwc $fpath)`), `promptinit` among them, whose code the
    // check cannot read.
    let promptinit = "autoload -Uz promptinit && promptinit\n";
    for setter in [
        "fpath=(~/zc.zwc $fpath)",
        "FPATH=~/zc.zwc:$FPATH",
        "fpath=(~/.zwc $fpath)",
    ] {
        let fs = MockFilesystem::new();
        let digest = if setter.contains("/.zwc") {
            "/home/alice/.zwc"
        } else {
            "/home/alice/zc.zwc"
        };
        fs.mock_set_file_bytes(digest, b"\x07\x06\x05\x04zwc");
        let got = found_with(&fs, &format!("{setter}\n{promptinit}"));
        assert!(
            got.doubts.contains(&format!(
                "it cannot read the compiled code in {digest} that zsh may run"
            )),
            "{setter}: {got:?}"
        );
    }
    // One that is not there is none.
    assert_eq!(
        found(&format!("fpath=(~/zc.zwc $fpath)\n{promptinit}")),
        Scan::default()
    );
}
