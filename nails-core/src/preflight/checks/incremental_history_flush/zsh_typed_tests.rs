// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What zsh runs with the line the operator types a NAILS command in: a
//! function or a regular alias named like the command that starts it
//! (`sudo`, `nails`), read as a hook's code, and a global alias named like a
//! word of it (`activate`, `--yes`), which counts as used.

use super::*;
use crate::preflight::checks::incremental_history_flush::{TYPED_COMMANDS, TYPED_WORDS};

/// What zsh's startup files hold with `rc` as `.zshrc`.
fn found(rc: &str) -> Scan {
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", rc);
    scan(&fs, UNKNOWN)
}

/// Whether `found` is anything but a pass.
fn warned(found: &Scan) -> bool {
    !found.writes.is_empty() || !found.doubts.is_empty()
}

/// A function that appends what it is run with to `~/.zl`.
const LOGIT: &str = "logit() { print -r -- \"${history[$HISTCMD]}\" >>~/.zl }\n";

#[test]
fn a_function_named_like_the_command_typed_is_a_hook() {
    // zsh 5.9.2 runs each in place of the command as `sudo print -r --
    // marker-one` (or the line of its name) is entered, which appends the
    // line to `~/.zl`.
    for name in TYPED_COMMANDS {
        let rc = format!("{name}() {{ print -r -- \"{name} $*\" >>~/.zl }}\n");
        assert_eq!(
            found(&rc).doubts,
            [format!(
                "it cannot tell whether `~/.zl`, which `{name}` in /home/alice/.zshrc redirects \
                 output to, is the history file (a file HISTFILE names, or a link to it)"
            )],
            "{rc}"
        );
    }
    // Any way a file defines one by that name, or by the path of `nails`
    // the guide has you type, which zsh runs as `/mnt/data/nails check` is
    // entered.
    for rc in [
        "/mnt/data/nails() { print -r -- \"nails $*\" >>~/.zl }\n",
        "function ./nails { print -r -- \"nails $*\" >>~/.zl }\n",
        "'sudo'() { print -r -- \"sudo $*\" >>~/.zl }\n",
        "\\sudo() { print -r -- \"sudo $*\" >>~/.zl }\n",
        "s\"u\"do() { print -r -- \"sudo $*\" >>~/.zl }\n",
        "function sudo { print -r -- \"sudo $*\" >>~/.zl }\n",
        "function w s\\udo { print -r -- \"sudo $*\" >>~/.zl }\n",
        "functions[sudo]='print -r -- \"sudo $*\" >>~/.zl'\n",
        "eval 'sudo() { print -r -- \"sudo $*\" >>~/.zl }'\n",
        "autoload ~/zfn/sudo\n",
        "logit() { print -r -- \"$*\" >>~/.zl }\nfunctions -c logit sudo\n",
        "sudo() { logit \"$@\" }\nlogit() { print -r -- \"$*\" >>~/.zl }\n",
        // One that holds a backslash or a quote past those zsh takes off may
        // be read otherwise than zsh does.
        "'s\\udo'() { print -r -- \"sudo $*\" >>~/.zl }\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        seed(
            &fs,
            "/home/alice/zfn/sudo",
            "print -r -- \"sudo $*\" >>~/.zl\n",
        );
        assert!(warned(&scan(&fs, UNKNOWN)), "{rc}");
    }
    // A wrapper that writes nothing, and a function of another name, pass.
    for rc in [
        "sudo() { command sudo \"$@\" }\n",
        "nails() { command nails \"$@\" }\n",
        "sudoedit() { print -r -- \"$*\" >>~/.zl }\n",
        "sudo_logit() { print -r -- \"$*\" >>~/.zl }\n",
    ] {
        assert_eq!(found(rc), Scan::default(), "{rc}");
    }
}

#[test]
fn a_regular_alias_named_like_the_command_typed_is_a_hook_s_code() {
    // zsh 5.9.2 runs `logit` with each as the line is entered.
    for alias in [
        "alias sudo='logit; sudo'",
        "alias 'sudo=logit; sudo'",
        "alias \\sudo='logit; sudo'",
        "alias -- sudo='logit; sudo'",
        "aliases[sudo]='logit; sudo'",
        "alias nails='logit; nails'",
        "alias /mnt/data/nails='logit; /mnt/data/nails'",
        "alias doas='logit; doas'",
        "alias su='logit; su'",
        "eval \"alias run0='logit; run0'\"",
    ] {
        let got = found(&format!("{LOGIT}{alias}\n"));
        assert!(warned(&got), "{alias}");
    }
    // One that runs nothing that writes passes.
    for alias in ["alias sudo='nocorrect sudo'", "alias nails='command nails'"] {
        assert_eq!(
            found(&format!("{LOGIT}{alias}\n")),
            Scan::default(),
            "{alias}"
        );
    }
}

#[test]
fn a_global_alias_named_like_a_word_of_a_nails_command_counts_as_used() {
    // zsh 5.9.2 puts each in place of that word of `sudo nails activate
    // --yes` as it is entered, and runs `logit`.
    for name in TYPED_COMMANDS
        .iter()
        .chain(&TYPED_WORDS)
        .chain(&["/mnt/data/nails"])
    {
        let alias = format!("alias -g -- {name}='{name}; logit'");
        let got = found(&format!("{LOGIT}{alias}\n"));
        assert_eq!(
            got.doubts,
            [format!(
                "it cannot tell what the global alias `{name}={name}; logit` in \
                 /home/alice/.zshrc runs as you enter a NAILS command, as zsh puts its value in \
                 place of a word of that line named like it (`sudo`, `activate`, `--yes`)"
            )],
            "{alias}"
        );
    }
    // By the parameter that holds them, with quotes or a backslash zsh takes
    // off, and one whose name holds one past those.
    for alias in [
        "galiases[status]='status; logit'",
        "alias -g 'deactivate'='deactivate; logit'",
        "alias -g e\\mergency='emergency; logit'",
        "alias -g 'su\\do'='sudo; logit'",
        "alias -g \"che'ck\"='check; logit'",
    ] {
        assert!(warned(&found(&format!("{LOGIT}{alias}\n"))), "{alias}");
    }
    // One of another name that no file uses passes, as before.
    for alias in ["alias -g G='| grep'", "alias -g activates='x'"] {
        assert_eq!(
            found(&format!("{LOGIT}{alias}\n")),
            Scan::default(),
            "{alias}"
        );
    }
}
