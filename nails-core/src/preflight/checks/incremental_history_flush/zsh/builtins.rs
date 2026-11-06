// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The functions zsh runs by their name as hooks, and its builtins: which
//! ones run a function the files define as a hook, and which write no file
//! their words name; and the names zsh runs code by as the operator types a
//! NAILS command.

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
