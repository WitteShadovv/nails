// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The parameters the list of the commands the check knows to be harmless
//! lets the files set ([`super`]): one of the user's own, which no part of zsh
//! reads; one of zsh's own the check knows to steer nothing it reads
//! ([`HARMLESS_PARAMETERS`]) or reads itself ([`READ_PARAMETERS`]); and, out
//! of a function, one of the line editor's ([`ZLE_PARAMETERS`]), which zsh
//! keeps only as a widget runs.

/// The parameters of zsh's line editor (zsh/zle), which it reads as a widget
/// runs and back once it returns: the line and the cursor, the history line
/// shown (`HISTNO`), the region, the kill ring and what the keys typed. A
/// function a widget runs that sets one may change the line zsh runs as the
/// line is accepted, a history line in place of the one typed among them.
pub(in super::super) const ZLE_PARAMETERS: &[&str] = &[
    "BUFFER",
    "BUFFERLINES",
    "CONTEXT",
    "CURSOR",
    "CUTBUFFER",
    "HISTNO",
    "ISEARCHMATCH_ACTIVE",
    "ISEARCHMATCH_START",
    "ISEARCHMATCH_END",
    "KEYMAP",
    "KEYS",
    "KEYS_QUEUED_COUNT",
    "killring",
    "LASTABORTEDSEARCH",
    "LASTSEARCH",
    "LASTWIDGET",
    "LBUFFER",
    "MARK",
    "NUMERIC",
    "PENDING",
    "PREBUFFER",
    "PREDISPLAY",
    "POSTDISPLAY",
    "RBUFFER",
    "REGION_ACTIVE",
    "region_highlight",
    "SUFFIX_ACTIVE",
    "SUFFIX_START",
    "SUFFIX_END",
    "UNDO_CHANGE_NO",
    "UNDO_LIMIT_NO",
    "WIDGET",
    "WIDGETFUNC",
    "WIDGETSTYLE",
    "YANK_ACTIVE",
    "YANK_START",
    "YANK_END",
    "ZLE_RECURSIVE",
    "ZLE_STATE",
];

/// The parameters zsh 5.9 to 5.9.2 and the modules they ship set or read
/// (zshparam(1), zshmodules(1)), beside the line editor's
/// ([`ZLE_PARAMETERS`]). One of them that neither [`HARMLESS_PARAMETERS`]
/// holds nor the reader reads itself ([`READ_PARAMETERS`]) is a doubt where
/// the files set it: zsh may read it in a way the check does not
/// (`histchars`, which picks the characters zsh expands history by, `STTY`,
/// `POSTEDIT` and `zle_bracketed_paste`, which zsh writes to the terminal or
/// runs `stty` with, `KEYBOARD_HACK`, which cuts a typed line, `commands`,
/// which maps a command's name to a program).
pub(in super::super) const OWN_PARAMETERS: &str = "\
    ARGC argv status pipestatus _ CPUTYPE EGID EUID ERRNO FUNCNEST GID HISTCMD HOST LINENO \
    LOGNAME MACHTYPE OLDPWD OPTARG OPTIND OSTYPE PPID PWD RANDOM SECONDS SHLVL signals \
    TRY_BLOCK_ERROR TRY_BLOCK_INTERRUPT TTY TTYIDLE UID USERNAME VENDOR zsh_eval_context \
    ZSH_EVAL_CONTEXT ZSH_ARGZERO ZSH_EXECUTION_STRING ZSH_NAME ZSH_PATCHLEVEL \
    zsh_scheduled_events ZSH_SCRIPT ZSH_SUBSHELL ZSH_VERSION ARGV0 BAUD cdpath CDPATH COLUMNS \
    CORRECT_IGNORE CORRECT_IGNORE_FILE DIRSTACKSIZE ENV FCEDIT fignore FIGNORE fpath FPATH \
    histchars HISTCHARS HISTFILE HISTORY_IGNORE HISTSIZE HOME IFS KEYBOARD_HACK KEYTIMEOUT LANG \
    LC_ALL LC_COLLATE LC_CTYPE LC_MESSAGES LC_NUMERIC LC_TIME LINES LISTMAX MAIL MAILCHECK \
    mailpath MAILPATH manpath MANPATH match mbegin mend MATCH MBEGIN MEND module_path \
    MODULE_PATH NULLCMD path PATH POSTEDIT PROMPT PROMPT2 PROMPT3 PROMPT4 prompt \
    PROMPT_EOL_MARK PS1 PS2 PS3 PS4 psvar PSVAR READNULLCMD REPORTMEMORY REPORTTIME REPLY reply \
    RPROMPT RPS1 RPROMPT2 RPS2 SAVEHIST SPROMPT STTY TERM TERMINFO TERMINFO_DIRS TIMEFMT TMOUT \
    TMPPREFIX TMPSUFFIX WORDCHARS ZBEEP ZDOTDIR zle_bracketed_paste zle_highlight \
    ZLE_LINE_ABORTED ZLE_REMOVE_SUFFIX_CHARS ZLE_SPACE_SUFFIX_CHARS ZLE_RPROMPT_INDENT PERIOD \
    LOGCHECK WATCH watch WATCHFMT MENUSCROLL MENUSELECT MENUMODE LISTPROMPT ZLS_COLORS \
    ZLS_COLOURS aliases builtins commands dirstack dis_aliases dis_builtins dis_functions \
    dis_functions_source dis_galiases dis_patchars dis_reswords dis_saliases funcfiletrace \
    funcsourcetrace funcstack functions functions_source functrace galiases history \
    historywords jobdirs jobstates jobtexts modules nameddirs options parameters patchars \
    reswords saliases userdirs usergroups keymaps widgets termcap terminfo errnos sysparams \
    EPOCHSECONDS EPOCHREALTIME epochtime langinfo mapfile SRANDOM ZFTP_TMOUT ZFTP_HOST \
    ZFTP_PORT ZFTP_IP ZFTP_SYSTEM ZFTP_TYPE ZFTP_USER ZFTP_ACCOUNT ZFTP_PWD ZFTP_CODE \
    ZFTP_REPLY ZFTP_PREFS ZFTP_VERBOSE ZCURSES_COLORS ZCURSES_COLOR_PAIRS zcurses_attrs \
    zcurses_colors zcurses_keycodes zcurses_windows compstate words CURRENT PREFIX SUFFIX \
    IPREFIX ISUFFIX QIPREFIX QISUFFIX";

/// The parameters of zsh's own ([`OWN_PARAMETERS`]) the check knows to steer
/// nothing it reads: where and how much history zsh keeps and which lines it
/// leaves out (not when it writes them), the paths zsh finds commands,
/// directories and manual pages in, the locale, the terminal's name and where
/// its description is, the host's name, how the line editor shows the line
/// and parts words, how much completion lists, the time a report shows, the
/// names of temporary files, the editor `fc -e` runs (no `fc -e` is on the
/// list), the mail file zsh says has new mail, the values the prompts' `%v`
/// shows, what a command found or matched, the size of the terminal, the
/// depth of nested functions, the logins zsh reports, the directories it
/// was in, and the values zsh keeps of its shell level, the time and the
/// random numbers it gives.
pub(in super::super) const HARMLESS_PARAMETERS: &[&str] = &[
    "HISTFILE",
    "HISTSIZE",
    "SAVEHIST",
    "HISTORY_IGNORE",
    "PATH",
    "path",
    "CDPATH",
    "cdpath",
    "MANPATH",
    "manpath",
    "FIGNORE",
    "fignore",
    "LANG",
    "LC_ALL",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_NUMERIC",
    "LC_TIME",
    "TERM",
    "TERMINFO",
    "TERMINFO_DIRS",
    "HOST",
    "WORDCHARS",
    "KEYTIMEOUT",
    "zle_highlight",
    "ZLE_RPROMPT_INDENT",
    "ZLE_REMOVE_SUFFIX_CHARS",
    "ZLE_SPACE_SUFFIX_CHARS",
    "LISTMAX",
    "LISTPROMPT",
    "MENUSELECT",
    "ZLS_COLORS",
    "ZLS_COLOURS",
    "TIMEFMT",
    "TMPPREFIX",
    "TMPSUFFIX",
    "CORRECT_IGNORE",
    "CORRECT_IGNORE_FILE",
    "FCEDIT",
    "MAIL",
    "MAILCHECK",
    "psvar",
    "PSVAR",
    "REPLY",
    "reply",
    "match",
    "mbegin",
    "mend",
    "MATCH",
    "MBEGIN",
    "MEND",
    "OPTARG",
    "OPTIND",
    "LINES",
    "COLUMNS",
    "FUNCNEST",
    "WATCH",
    "watch",
    "WATCHFMT",
    "OLDPWD",
    "PWD",
    "SHLVL",
    "SECONDS",
    "RANDOM",
    "IFS",
    "dirstack",
    "nameddirs",
];

/// The parameters of zsh's own whose effect the reader reads itself where
/// the files set them: where the user's files and the functions the files
/// autoload are, what NixOS's `set-environment` writes `NIX_PROFILES` with,
/// the prompts, those zsh reads as arithmetic each time it uses them
/// (`TMOUT`), the arrays of hook functions, the aliases and functions zsh
/// keeps in parameters, the options (each one's name read as `setopt`
/// reads it), the files `mapfile` writes, the mail messages, the commands
/// zsh runs for a redirection with none, where it loads modules from, its
/// version and the name it gives every program it runs. Of these the
/// reader's own rules decide what is a doubt.
pub(in super::super) const READ_PARAMETERS: &[&str] = &[
    "ZDOTDIR",
    "XDG_CONFIG_HOME",
    "HOME",
    "fpath",
    "FPATH",
    "NIX_PROFILES",
    "PS1",
    "PROMPT",
    "prompt",
    "RPS1",
    "RPROMPT",
    "PS2",
    "PROMPT2",
    "RPS2",
    "RPROMPT2",
    "PS3",
    "PROMPT3",
    "PS4",
    "PROMPT4",
    "SPROMPT",
    "PROMPT_EOL_MARK",
    "TMOUT",
    "PERIOD",
    "BAUD",
    "REPORTTIME",
    "REPORTMEMORY",
    "DIRSTACKSIZE",
    "MENUSCROLL",
    "LOGCHECK",
    "ZFTP_TMOUT",
    "aliases",
    "galiases",
    "saliases",
    "dis_aliases",
    "dis_galiases",
    "dis_saliases",
    "functions",
    "dis_functions",
    "options",
    "mapfile",
    "MAILPATH",
    "mailpath",
    "NULLCMD",
    "READNULLCMD",
    "module_path",
    "MODULE_PATH",
    "ZSH_VERSION",
    "ARGV0",
];

/// Why an assignment in arithmetic of the parameter `name` is none the list
/// holds (`(( STTY = 0 ))`, `let FPATH=1`): as for [`parameter`], and for one
/// of zsh's own the check reads itself too, as the reader follows none it
/// assigns there; `None` for the user's own and the harmless ones.
pub(in super::super) fn arithmetic_parameter(name: &str) -> Option<String> {
    let own = OWN_PARAMETERS.split_whitespace().any(|own| own == name);
    if !own || HARMLESS_PARAMETERS.contains(&name) {
        return None;
    }
    Some(parameter(name, false).unwrap_or_else(|| {
        format!(
            "`{name}` is one of zsh's own parameters, which the check follows only where a file \
             assigns it outside arithmetic"
        )
    }))
}

/// Why setting the parameter `name` is none the list holds, in a function's
/// code where `in_function`; `None` where it is ([the module](self)).
pub(in super::super) fn parameter(name: &str, in_function: bool) -> Option<String> {
    if in_function && ZLE_PARAMETERS.contains(&name) {
        return Some(format!(
            "`{name}` is a parameter of the line editor, which a widget that sets it may make \
             run another line than the one typed"
        ));
    }
    let own = OWN_PARAMETERS.split_whitespace().any(|own| own == name);
    if !own || HARMLESS_PARAMETERS.contains(&name) || READ_PARAMETERS.contains(&name) {
        return None;
    }
    Some(match name {
        "histchars" | "HISTCHARS" => format!(
            "`{name}` picks the characters zsh expands history by, with which a typed line may \
             run another"
        ),
        "STTY" | "POSTEDIT" | "zle_bracketed_paste" | "ZBEEP" => format!(
            "zsh writes `{name}` to the terminal or runs `stty` with it, which may change what a \
             key typed does"
        ),
        "KEYBOARD_HACK" => {
            format!("`{name}` makes zsh drop a character a typed line ends with")
        }
        "commands" => format!("`{name}` maps a command's name to the program zsh runs for it"),
        _ => format!("`{name}` is a parameter of zsh's own whose effect the check does not read"),
    })
}
