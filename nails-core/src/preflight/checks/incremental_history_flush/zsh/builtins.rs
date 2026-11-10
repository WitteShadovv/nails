// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The functions zsh runs by their name as hooks, and its builtins: which
//! ones run a function the files define as a hook, and which write no file
//! their words name; the names zsh runs code by as the operator types a
//! NAILS command or a line is at hand; and the options `fc` and `history`
//! take, as zsh reads them.

use super::super::{TYPED_COMMANDS, TYPED_WORDS};

/// The functions zsh runs as hooks by their name, as commands are entered or
/// end (`preexec`, `precmd`), as a line goes into the history
/// (`zshaddhistory`), as the directory changes, time passes or the shell
/// ends, or as a command typed is not found. A `TRAP...` function is run as
/// its signal comes, `TRAPDEBUG` before each command.
pub(super) const HOOKS: &[&str] = &[
    "precmd",
    "preexec",
    "zshaddhistory",
    "chpwd",
    "periodic",
    "zshexit",
    "zsh_directory_name",
    "command_not_found_handler",
];

/// The builtins of zsh 5.9 and of the modules it ships. A function named
/// like one runs wherever code runs that builtin, as zsh's own code does as
/// each line is entered (the hooks `add-zle-hook-widget` makes run `zstyle`
/// and `zle`), so it counts as a hook.
const BUILTINS: &str = "\
    . : [ alias autoload bg bindkey break builtin bye cap cd chdir chgrp chmod \
    chown clone command compadd comparguments compcall compctl compdescribe \
    compfiles compgroups compquote compset comptags comptry compvalues continue \
    declare dirs disable disown echo echotc echoti emulate enable eval exec \
    exit export false fc fg float functions getcap getln getopts hash history \
    integer jobs kill let limit ln local log logout mkdir mv noglob \
    pcre_compile pcre_match pcre_study popd print printf private pushd pushln \
    pwd r read readonly rehash return rm rmdir sched set setcap setopt shift \
    source stat strftime suspend sync syserror sysopen sysread sysseek syswrite \
    test times trap true ttyctl type typeset ulimit umask unalias unfunction \
    unhash unlimit unset unsetopt vared wait whence where which zcompile \
    zcurses zdelattr zf_chgrp zf_chmod zf_chown zf_ln zf_mkdir zf_mv zf_rm \
    zf_rmdir zf_sync zformat zftp zgdbmpath zgetattr zle zlistattr zmodload \
    zparseopts zprof zpty zregexparse zselect zsetattr zsocket zstat zstyle \
    zsystem ztcp ztie zuntie";

/// The builtins of [`BUILTINS`] that may write a file their words name, or
/// run code or a command their words give.
const WRITERS: &str = "\
    . builtin chgrp chmod chown clone command eval exec fc history ln mkdir mv \
    noglob r rm rmdir sched setcap source sync sysopen sysread syswrite trap \
    zcompile zdelattr zf_chgrp zf_chmod zf_chown zf_ln zf_mkdir zf_mv zf_rm \
    zf_rmdir zf_sync zftp zpty zsetattr zsystem ztie zuntie";

/// Whether `name` is one of the builtins of zsh 5.9 and of its modules
/// ([`BUILTINS`]).
pub(super) fn builtin(name: &str) -> bool {
    BUILTINS.split_whitespace().any(|builtin| builtin == name)
}

/// Whether a function or a regular alias named `name` runs with the line
/// the operator types a NAILS command in: one named like the command that
/// starts it ([`TYPED_COMMANDS`]: `sudo`, `nails`), or like the path of
/// `nails` the operator guide has the operator type (`/mnt/data/nails`, any
/// that ends in `/nails`), which zsh runs in that command's place
/// (`sudo() { ... }`, `alias sudo='logit; sudo'`), so it counts as a hook.
pub(super) fn typed(name: &str) -> bool {
    TYPED_COMMANDS.contains(&name) || name.ends_with("/nails")
}

/// Whether zsh runs a function or a regular alias named `name` with the
/// line being typed at hand: `run-help` and `which-command`, which the
/// widgets of those names run as a command named as the key ran them, with
/// the line's first word as their argument and the whole line on the buffer
/// stack (`read -z` reads it back), and which zsh 5.9 to 5.9.2 bind to Alt-h,
/// Alt-H and Alt-? in its emacs keymap; `.run-help` and `.which-command`, as
/// a key bound to them by those names runs; `man`, which zsh's own alias
/// `run-help` stands for, and which zsh's own `run-help` runs for a command
/// it has no help file for (`ls`) with the line still on the buffer stack;
/// and a `run-help-...` helper, which zsh's own `run-help` runs with the
/// line's words. `whence`, which zsh's own alias `which-command` stands for,
/// is a builtin ([`builtin`]).
pub(super) fn line_command(name: &str) -> bool {
    matches!(
        name,
        "run-help" | "which-command" | ".run-help" | ".which-command" | "man"
    ) || name.starts_with("run-help-")
}

/// Whether a global alias named `name` may run as the widgets `run-help`
/// and `which-command` run a command with the line at hand: one named like
/// that command ([`line_command`]), or like `whence`, which zsh's own alias
/// `which-command` stands for.
pub(super) fn line_word(name: &str) -> bool {
    line_command(name) || name == "whence"
}

/// Whether a global alias named `name` runs as the operator enters a NAILS
/// command: one named like a word of it ([`typed`], [`TYPED_WORDS`]: `sudo`,
/// `/mnt/data/nails`, `activate`, `--yes`), which zsh puts in place of that
/// word, or one whose name holds a backslash or a quote, which the check may
/// read otherwise than zsh does.
pub(super) fn typed_word(name: &str) -> bool {
    typed(name) || TYPED_WORDS.contains(&name) || name.contains(['\\', '\'', '"'])
}

/// Whether `command` is a builtin that writes no file its words name and
/// runs no code or command they give (`print`, `zstyle`, `[[`).
pub(super) fn quiet(command: &str) -> bool {
    command == "[["
        || command == "]]"
        || (builtin(command) && !WRITERS.split_whitespace().any(|writer| writer == command))
}

/// The letters `fc` and `history` (`command`) take as options in zsh 5.9
/// to 5.9.2 (Src/builtin.c): with any other among its options, zsh runs
/// neither (`bad option`).
fn fc_options(command: &str) -> &'static str {
    if command == "history" {
        "adDEfiLmnpPrt"
    } else {
        "aAdDeEfiIlLmnpPrRstW"
    }
}

/// The letters of the options of an `fc` or a `history` (`command`) of
/// `words`, each one as written, its quotes taken off, and whether an
/// expansion, brace expansion or a glob may make other words of it, read as
/// zsh reads a builtin's options (Src/builtin.c): each word that starts with
/// `-` holds them, up to the first that does not, is `-` or `--`, or has a
/// digit past its `-` (`-10`), and `-e` and `-t` take the rest of their word
/// or the word after it, past which zsh reads on (`fc -t %F -AI`); none
/// where one of them is none the command takes, as zsh then runs nothing;
/// with how many words they took. `None` where one of those words may be
/// made by an expansion.
pub(super) fn fc_letters<S: AsRef<str>>(
    command: &str,
    words: impl IntoIterator<Item = (S, bool)>,
) -> Option<(String, usize)> {
    let mut letters = String::new();
    let mut taken = 0;
    let mut argument = false;
    for (word, computed) in words {
        if computed {
            return None;
        }
        if !std::mem::take(&mut argument) {
            let Some(rest) = word.as_ref().strip_prefix('-') else {
                break;
            };
            let rest = rest.strip_prefix('-').unwrap_or(rest);
            if rest.is_empty() || rest.starts_with(|c: char| c.is_ascii_digit()) {
                break;
            }
            for (at, letter) in rest.char_indices() {
                letters.push(letter);
                if matches!(letter, 'e' | 't') {
                    argument = at + 1 == rest.len();
                    break;
                }
            }
        }
        taken += 1;
    }
    if !letters
        .chars()
        .all(|letter| fc_options(command).contains(letter))
    {
        letters.clear();
    }
    Some((letters, taken))
}
