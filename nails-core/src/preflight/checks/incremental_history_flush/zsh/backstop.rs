// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a startup file's lines name, counted without the lexer and
//! wherever it stands: the options that write each command line to the
//! history file, `source`, a `.` with a word after it, `eval`, an alias that
//! stands for `.`, and the `ZDOTDIR` settings. The walk counts the same as it
//! reads them as code it follows, and what the lines name beyond that is what
//! it did not follow: an option named there counts as on, and the rest is a
//! doubt.
//!
//! Only a line whose first character that is not a blank is `#` is left out,
//! so an option a comment at the end of a line names counts as on too, and a
//! `source` or `eval` anywhere else than in a command the walk follows, as in
//! a string, an `echo`, an alias or a here-document, is a doubt.

use super::walk::option;

/// What the lines of a file name, outside the lines that are a comment.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Named {
    /// Each of [`super::OPTIONS`], in any spelling and in its `no` form too.
    pub(super) options: [usize; 3],
    /// `source`, a `.` with a word after it, and a `.` an alias stands for.
    pub(super) sources: usize,
    /// `eval`.
    pub(super) evals: usize,
    /// `ZDOTDIR` where it is not read ([`zdotdir_writes`]).
    pub(super) zdotdirs: usize,
}

/// The names of zsh's options (zsh 5.9), as zsh compares them: in lower
/// case, without `_`.
const ZSH_OPTIONS: &str = "\
    aliases aliasfuncdef allexport alwayslastprompt alwaystoend appendcreate appendhistory \
    autocd autocontinue autolist automenu autonamedirs autoparamkeys autoparamslash autopushd \
    autoremoveslash autoresume badpattern banghist bareglobqual bashautolist bashrematch beep \
    bgnice braceccl braceexpand bsdecho caseglob casematch casepaths cbases cdablevars \
    cdsilent chasedots chaselinks checkjobs checkrunningjobs clobber clobberempty \
    combiningchars completealiases completeinword continueonerror correct correctall \
    cprecedences cshjunkiehistory cshjunkieloops cshjunkiequotes cshnullcmd cshnullglob \
    debugbeforecmd dotglob dvorak emacs equals errexit errreturn evallineno exec extendedglob \
    extendedhistory flowcontrol forcefloat functionargzero glob globalexport globalrcs \
    globassign globcomplete globdots globstarshort globsubst hashall hashcmds hashdirs \
    hashexecutablesonly hashlistall histallowclobber histappend histbeep histexpand \
    histexpiredupsfirst histfcntllock histfindnodups histignorealldups histignoredups \
    histignorespace histlexwords histnofunctions histnostore histreduceblanks histsavebycopy \
    histsavenodups histsubstpattern histverify hup ignorebraces ignoreclosebraces ignoreeof \
    incappendhistory incappendhistorytime interactive interactivecomments ksharrays \
    kshautoload kshglob kshoptionprint kshtypeset kshzerosubscript listambiguous listbeep \
    listpacked listrowsfirst listtypes localloops localoptions localpatterns localtraps log \
    login longlistjobs magicequalsubst mailwarn mailwarning markdirs menucomplete monitor \
    multibyte multifuncdef multios nomatch notify nullglob numericglobsort octalzeroes onecmd \
    overstrike pathdirs pathscript physical pipefail posixaliases posixargzero posixbuiltins \
    posixcd posixidentifiers posixjobs posixstrings posixtraps printeightbit printexitvalue \
    privileged promptbang promptcr promptpercent promptsp promptsubst promptvars \
    pushdignoredups pushdminus pushdsilent pushdtohome rcexpandparam rcquotes rcs recexact \
    rematchpcre restricted rmstarsilent rmstarwait sharehistory shfileexpansion shglob \
    shinstdin shnullcmd shoptionletters shortloops shortrepeat shwordsplit singlecommand \
    singlelinezle sourcetrace stdin sunkeyboardhack trackall transientrprompt trapsasync \
    typesetsilent typesettounset unset verbose vi warncreateglobal warnnestedvar xtrace zle";

/// Whether zsh knows `name` as an option, in any spelling and either form.
fn zsh_option(name: &str) -> bool {
    let name: String = name
        .trim_matches(['\'', '"'])
        .chars()
        .filter(|c| *c != '_')
        .collect::<String>()
        .to_lowercase();
    let known = |name: &str| ZSH_OPTIONS.split_whitespace().any(|option| option == name);
    known(&name) || name.strip_prefix("no").is_some_and(known)
}

/// The words of `line` in each piece of it where a command can start.
fn pieces(line: &str) -> impl Iterator<Item = Vec<&str>> {
    line.split([';', '&', '|', '(', ')', '{', '}', '`'])
        .map(|piece| piece.split_whitespace().collect())
}

/// What in zsh code `text`, from the file at `place`, keeps a last `unsetopt`
/// from settling the doubts before it, as a clause of the warning: what may
/// redefine `unsetopt`, `setopt` or `builtin`, or any word as a global alias;
/// a trap, a hook or a plugin manager's deferred loading, which may set an
/// option again after it; `err_return` or `err_exit`; and what may stop the
/// file before it.
pub(super) fn blocker(text: &str, place: &str) -> Option<String> {
    for line in text.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        if redefines(line) {
            return Some(format!(
                "an alias or function in {place} can change what the line runs"
            ));
        }
        if hooks(line) {
            return Some(format!(
                "a hook or plugin manager in {place} can set it again after the line runs"
            ));
        }
        if errs(line) {
            return Some(format!(
                "{place} can turn on err_return or err_exit, which may stop zsh before the line runs"
            ));
        }
        if stops(line) {
            return Some(format!(
                "{place} holds what may stop it before the line runs"
            ));
        }
    }
    None
}

/// Whether `line` may redefine `unsetopt`, `setopt` or `builtin` (an alias,
/// a function, `disable`, `aliases[...]`, `functions[...]`) or define a global
/// alias.
fn redefines(line: &str) -> bool {
    let part = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-');
    ["disable", "aliases", "galiases", "saliases", "functions"]
        .iter()
        .any(|word| whole_words(line, word) > 0)
        || ["unsetopt", "setopt", "builtin"].iter().any(|name| {
            line.match_indices(name).any(|(at, found)| {
                let before = &line[..at];
                let after = line[at + found.len()..].trim_start();
                !before.chars().next_back().is_some_and(part)
                    && (after.starts_with('=')
                        || after.starts_with('(')
                        || before.trim_end().ends_with("function"))
            })
        })
        || pieces(line).any(|words| {
            words.windows(2).any(|pair| {
                pair[0] == "alias" && pair[1].starts_with(['-', '+']) && pair[1].contains('g')
            })
        })
}

/// Whether `line` may define a trap or a hook, or load a plugin later, as
/// zinit's `wait` does: any word of them.
fn hooks(line: &str) -> bool {
    [
        "trap",
        "precmd",
        "preexec",
        "chpwd",
        "periodic",
        "sched",
        "zshexit",
        "zshaddhistory",
        "add-zsh-hook",
        "add-zle-hook-widget",
        "zle",
        "zsh-defer",
        "zinit",
        "zi",
        "zplugin",
    ]
    .iter()
    .any(|word| whole_words(line, word) > 0)
        || line.contains("zle-")
        || line
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .any(|word| {
                word.strip_prefix("TRAP").is_some_and(|signal| {
                    !signal.is_empty()
                        && signal
                            .chars()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                }) || word
                    .strip_suffix("_functions")
                    .is_some_and(|name| !name.is_empty())
            })
}

/// Whether `line` may turn on `err_return` or `err_exit`: either named in any
/// spelling, or `set -e`.
fn errs(line: &str) -> bool {
    line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|word| {
            let word: String = word
                .chars()
                .filter(|c| *c != '_')
                .collect::<String>()
                .to_lowercase();
            let word = word.strip_prefix("no").unwrap_or(&word);
            matches!(word, "errexit" | "errreturn")
        })
        || pieces(line).any(|words| {
            words.windows(2).any(|pair| {
                pair[0] == "set"
                    && pair[1].starts_with('-')
                    && !pair[1].starts_with("--")
                    && pair[1][1..].contains('e')
            })
        })
}

/// Whether `line` holds what zsh may stop a file at: `${name:?...}` or
/// `${name?...}`, a read-only or a numeric variable, arithmetic in which a
/// division appears, and `set -o` with a name zsh does not know.
fn stops(line: &str) -> bool {
    let within = |open: &str, close: &str| {
        line.match_indices(open).any(|(at, _)| {
            line[at..]
                .split(close)
                .next()
                .is_some_and(|inside| inside.contains(['/', '%']))
        })
    };
    line.match_indices("${").any(|(at, _)| {
        line[at..]
            .split('}')
            .next()
            .is_some_and(|inside| inside.contains('?'))
    }) || ["readonly", "integer", "float"]
        .iter()
        .any(|word| whole_words(line, word) > 0)
        || within("((", "))")
        || within("$[", "]")
        || (whole_words(line, "let") > 0 && line.contains(['/', '%']))
        || pieces(line).any(|words| {
            words.windows(2).any(|pair| {
                matches!(pair[0], "typeset" | "declare" | "local" | "export")
                    && pair[1].starts_with(['-', '+'])
                    && pair[1].contains(['r', 'i', 'E', 'F'])
            }) || words.windows(3).any(|three| {
                three[0] == "set" && matches!(three[1], "-o" | "+o") && !zsh_option(three[2])
            })
        })
}

/// What the lines of zsh code `text` name.
pub(super) fn named(text: &str) -> Named {
    let mut named = Named::default();
    for line in text.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        for (at, _) in options(line) {
            named.options[at] += 1;
        }
        named.sources += whole_words(line, "source") + dot_words(line) + alias_dots(line);
        named.evals += whole_words(line, "eval");
        named.zdotdirs += zdotdir_writes(line);
    }
    named
}

/// How often `word` stands in `line` as a word of its own: with no letter,
/// digit, `_`, `.`, `/` or `-` beside it.
fn whole_words(line: &str, word: &str) -> usize {
    let part = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-');
    line.match_indices(word)
        .filter(|&(at, found)| {
            !line[..at].chars().next_back().is_some_and(part)
                && !line[at + found.len()..].chars().next().is_some_and(part)
        })
        .count()
}

/// How often a `.` stands in `line` as a word of its own, quotes and a
/// backslash around it taken off, with another word after it, as in
/// `. file`; not before an option or a `]]` (`find . -name`, `[[ -d . ]]`).
fn dot_words(line: &str) -> usize {
    line.split([';', '&', '|', '(', ')', '{', '}', '`'])
        .map(|piece| {
            let words: Vec<&str> = piece
                .split_whitespace()
                .map(|word| word.trim_matches(['\'', '"', '\\']))
                .collect();
            words
                .windows(2)
                .filter(|pair| {
                    pair[0] == "." && !pair[1].starts_with('-') && !matches!(pair[1], "]]" | "]")
                })
                .count()
        })
        .sum()
}

/// How often an alias in `line` stands for `.`, past the precommands before
/// it, its quotes and backslashes taken off (`alias s=.`, `alias s='. f'`,
/// `alias s='builtin .'`, `alias s=\.`, `aliases[s]=.`).
fn alias_dots(line: &str) -> usize {
    if whole_words(line, "alias") == 0 && !line.contains("aliases[") {
        return 0;
    }
    line.match_indices('=')
        .filter(|&(at, _)| {
            let value = line[at + 1..].replace(['\'', '"', '\\'], " ");
            value
                .split_whitespace()
                .find(|word| {
                    !matches!(
                        *word,
                        "builtin" | "command" | "noglob" | "nocorrect" | "exec" | "-"
                    )
                })
                .is_some_and(|word| word == "." || word.starts_with(".;"))
        })
        .count()
}

/// The options that `text` names, by their place in [`super::OPTIONS`], in
/// any word of it and either form.
pub(super) fn options(text: &str) -> impl Iterator<Item = (usize, bool)> + '_ {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter_map(option)
}

/// How often `text` names `ZDOTDIR` otherwise than to read it: anywhere but
/// after `$` or `${` (with a `#`, `+`, `=`, `~` or `^` between), and in
/// `${ZDOTDIR=...}`, `${ZDOTDIR:=...}` or `${ZDOTDIR::=...}`.
pub(super) fn zdotdir_writes(text: &str) -> usize {
    let name = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices("ZDOTDIR")
        .filter(|&(at, found)| {
            let before = &text[..at];
            let after = &text[at + found.len()..];
            if before.chars().next_back().is_some_and(name)
                || after.chars().next().is_some_and(name)
            {
                return false;
            }
            let before = before.trim_end_matches(['#', '+', '=', '~', '^']);
            let braced = before.ends_with("${");
            let read = braced || before.ends_with('$');
            !read
                || (braced
                    && (after.starts_with('=')
                        || after.starts_with(":=")
                        || after.starts_with("::=")))
        })
        .count()
}
