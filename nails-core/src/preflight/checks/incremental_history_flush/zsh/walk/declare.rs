// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the builtins of the `typeset` family (`typeset`, `declare`, `local`,
//! `export`, `readonly`, `integer`, `float` and `private`) and `unset` set or
//! take away, as the walk reads them. Their options, and those of
//! `functions`, which marks functions to be autoloaded as they may
//! ([`super::autoload`]), are read as zsh reads a builtin's options
//! (Src/builtin.c, `execbuiltin`): [`options`]. What the walk cannot read
//! exactly is a doubt: a word where the options may stand that an expansion,
//! brace expansion or a glob may make any of, a parameter's name such a word
//! may make, the patterns of `-m`, which may match a parameter the check
//! reads ([`super::patterns`]), a tie of one whose value it reads, and an
//! attribute given to one whose value it follows.

use super::super::arith::READ_AS_NUMBER;
use super::super::lexer::{Word, is_name};
use super::command::{ALIAS_PARAMETERS, assigned, is_assignment};
use super::hooks::hook_array;
use super::patterns::may_match;
use super::strings::{PROMPTS, brace_list};
use super::{Event, Frame, HOOKS, Walker};

/// The parameters a rule of the check reads, by their value or by their
/// being set, beside the prompts, the arrays of hook functions, the
/// parameters that hold aliases and those zsh reads as arithmetic each time
/// it uses them ([`READ_AS_NUMBER`]): where the user's files are, where the
/// functions the files autoload are and what NixOS's `set-environment` writes
/// `NIX_PROFILES` with, what starts a comment, what zsh runs or loads as code,
/// the options, the functions' code, the files `mapfile` writes, and what
/// picks the program a multi-call coreutils runs.
const READ: &[&str] = &[
    "ZDOTDIR",
    "XDG_CONFIG_HOME",
    "HOME",
    "fpath",
    "FPATH",
    "NIX_PROFILES",
    "USER",
    "XDG_STATE_HOME",
    "ZSH_VERSION",
    "histchars",
    "HISTCHARS",
    "MAILPATH",
    "mailpath",
    "NULLCMD",
    "READNULLCMD",
    "module_path",
    "MODULE_PATH",
    "options",
    "functions",
    "dis_functions",
    "mapfile",
    "ARGV0",
];

/// The parameters whose value the check follows as a path or a list of them:
/// an attribute that changes what zsh expands one to (`-l`, `-L 3`, `-a`,
/// which makes a scalar an empty array), what it holds (`-i`) or whether a
/// later assignment sets it (`-r`) is a doubt.
const FOLLOWED: &[&str] = &[
    "ZDOTDIR",
    "XDG_CONFIG_HOME",
    "NIX_PROFILES",
    "fpath",
    "FPATH",
];

/// The letters of the options of the `typeset` family that give such an
/// attribute ([`FOLLOWED`]), and `a`, which gives one to all but `fpath`,
/// already an array.
const ATTRIBUTES: &str = "AEFLRZilru";

/// Whether the check reads the value of the parameter `name` where the files
/// set it, so that a tie (`typeset -T`) by which zsh sets it by another name
/// is a doubt: one zsh reads as arithmetic each time it uses it (`TMOUT`),
/// `ZDOTDIR`, `XDG_CONFIG_HOME`, `NIX_PROFILES`, `fpath` and an array of hook
/// functions. zsh ties none of its special parameters (`PS1`, `HOME`) to
/// another.
fn tie_read(name: &str) -> bool {
    READ_AS_NUMBER.contains(&name)
        || matches!(
            name,
            "ZDOTDIR" | "XDG_CONFIG_HOME" | "NIX_PROFILES" | "fpath" | "FPATH"
        )
        || hook_array(name)
}

/// Whether the pattern `pattern` of `unset -m` may match a parameter the
/// check reads ([`READ`]).
fn matches_read(pattern: &str) -> bool {
    READ.iter()
        .chain(PROMPTS)
        .chain(ALIAS_PARAMETERS)
        .chain(READ_AS_NUMBER.iter())
        .any(|name| may_match(pattern, name))
        || HOOKS
            .iter()
            .any(|hook| may_match(pattern, &format!("{hook}_functions")))
}

/// The letters of the options of `command`, a builtin of the `typeset`
/// family, that take a number, in the rest of their word or as the word
/// after it (`typeset -L 3`), as each lists its options: `readonly` and
/// `private` give `p` none; `functions` and `unset` have none.
fn numbered(command: &str) -> &'static str {
    match command {
        "readonly" | "private" => "EFLRZi",
        "functions" | "unset" => "",
        _ => "EFLRZip",
    }
}

/// The options of a builtin, as zsh reads them ([`options`]).
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Options<'a> {
    /// Each letter, and whether a word that starts with `-`, rather than
    /// `+`, gives it.
    pub(super) letters: Vec<(char, bool)>,
    /// Where the words past the options start.
    pub(super) names: usize,
    /// A word where the options may stand that an expansion, brace expansion
    /// or a glob may make any options of, or none (`-$o`, `$o`, `{-m,x}`),
    /// where the check stops reading them.
    pub(super) unread: Option<&'a Word>,
    /// An option that takes an argument has none, so that zsh runs nothing
    /// (`functions -x`).
    pub(super) fails: bool,
}

impl Options<'_> {
    /// Whether the options hold `letter`, of either sign.
    pub(super) fn has(&self, letter: char) -> bool {
        self.letters.iter().any(|&(known, _)| known == letter)
    }

    /// Whether a word that starts with `-` gives `letter`.
    pub(super) fn on(&self, letter: char) -> bool {
        self.letters
            .iter()
            .any(|&(known, minus)| minus && known == letter)
    }
}

/// Whether the first character of `word` may be one an expansion, brace
/// expansion or a glob gives it (`$o`, `"$o"`, `{-m,x}`, `*`, a file's
/// name), which may be a `-` or a `+`, so that it may be options; brace
/// expansion of lists only whose words start otherwise (`{ZDOT,}DIR`) gives
/// none.
pub(super) fn starts_computed(word: &Word) -> bool {
    (word.expands && word.text.starts_with(['$', '`']))
        || (word.bare
            && word.text.starts_with(['$', '`', '{', '*', '?', '[', '('])
            && !(word.text.starts_with('{') && brace_list(word).is_some()))
}

/// The options among `args`, the words after `command` (a builtin of the
/// `typeset` family, `functions` or `unset`), as zsh reads a builtin's
/// options: each word that starts with `-`, or with `+` but for `unset`,
/// holds options, up to the first word that does not, an assignment among
/// them, or that is a sign and a digit (`-2`, a name); `-`, `+` and `--` end
/// them and are dropped, and `--fu` reads as `-fu`. An option that takes an
/// argument takes the rest of its word, or the word after it, and zsh reads
/// no more letters of its word then: `functions -x` any word, and with none
/// after it zsh runs nothing; a [`numbered`] one a number, the word after it
/// only where that starts with a digit, and the options go on past it
/// (`typeset -fLt 3 -u` drops the `t`, `typeset -L 3 -m` holds `m`). Where an
/// expansion, brace expansion or a glob may make a word where they may stand,
/// or the word after a letter that takes one, which may be any options, the
/// check reads no further ([`Options::unread`]).
pub(super) fn options<'a>(command: &str, args: &'a [Word]) -> Options<'a> {
    let plus = command != "unset";
    let numbered = numbered(command);
    let takes = if command == "functions" { "x" } else { "" };
    let digit = |text: &str| text.starts_with(|c: char| c.is_ascii_digit());
    let mut options = Options::default();
    let mut at = 0;
    'words: while let Some(word) = args.get(at) {
        // An assignment to a name as written (`LINE=$1`) is no option, and
        // ends them.
        if is_assignment(&word.text) {
            break;
        }
        if starts_computed(word) {
            options.unread = Some(word);
            break;
        }
        let rest = match word.text.strip_prefix('-') {
            Some(rest) => rest,
            None => match word.text.strip_prefix('+').filter(|_| plus) {
                Some(rest) => rest,
                None => break,
            },
        };
        if digit(rest) {
            break;
        }
        if word.expands || word.bare {
            options.unread = Some(word);
            break;
        }
        at += 1;
        if rest.is_empty() || rest == "-" {
            break;
        }
        let minus = word.text.starts_with('-');
        let letters = rest.strip_prefix('-').unwrap_or(rest);
        for (index, letter) in letters.char_indices() {
            options.letters.push((letter, minus));
            let tail = &letters[index + letter.len_utf8()..];
            if takes.contains(letter) {
                // Its argument: the rest of the word, or the word after it.
                if tail.is_empty() {
                    match args.get(at) {
                        None => options.fails = true,
                        Some(next) if next.expands || next.bare => {
                            options.unread = Some(next);
                            break 'words;
                        }
                        Some(_) => at += 1,
                    }
                }
                continue 'words;
            }
            if numbered.contains(letter) {
                if digit(tail) {
                    continue 'words;
                }
                if let Some(next) = args.get(at) {
                    if starts_computed(next) {
                        options.unread = Some(next);
                        break 'words;
                    }
                    if digit(&next.text) {
                        at += 1;
                        continue 'words;
                    }
                }
            }
        }
    }
    options.names = at;
    options
}

/// The doubt of `command` of `args`, in the file at `place`, whose word
/// `word` stands where its options may and an expansion, brace expansion or
/// a glob may make any options of ([`Options::unread`]).
pub(super) fn unread_doubt(command: &str, args: &[Word], word: &Word, place: &str) -> String {
    let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
    format!(
        "it cannot tell what `{command} {}` in {place} does, as zsh may expand `{}` into any of \
         its options",
        words.join(" "),
        word.text
    )
}

/// Whether `word`, a word after a builtin of the `typeset` family past its
/// options, names the parameter it sets by what an expansion, brace
/// expansion or a glob makes (`"$name=on"`, `${prefix}x`, `{ZDOT,}DIR=x`),
/// which may be any.
fn computed_target(word: &Word) -> bool {
    let target = word
        .text
        .split_once('=')
        .map_or(word.text.as_str(), |(target, _)| target);
    !word.text.starts_with(['-', '+'])
        && (target.contains(['$', '`']) || (word.bare && !is_name(assigned(target))))
}

impl Walker<'_> {
    /// The events of a builtin of the `typeset` family (`command`) of `args`
    /// ([`options`]). A word where its options may stand that an expansion,
    /// brace expansion or a glob may make any options of is a doubt, and so
    /// is a parameter's name such a word makes, the `-m` of `typeset`,
    /// `declare` and `private`, with which zsh reads each word as a pattern
    /// and sets or changes every parameter it matches (`typeset -m
    /// 'HOM?=/x'`, `typeset -L 3 -m 'T?Y'`), a tie (`typeset -T TMOUT tmout`)
    /// of one whose value the check reads ([`tie_read`]), as zsh then sets it
    /// by the other name too (`tmout=(...)`), and an attribute
    /// ([`ATTRIBUTES`], `readonly`, `integer` and `float` among them, and
    /// `-a` but on `fpath`) of one whose value it follows ([`FOLLOWED`]):
    /// `typeset -l ZDOTDIR`, `typeset -a XDG_CONFIG_HOME`. `local`,
    /// `readonly`, `export`, `integer` and `float` take no `-m`. Each other
    /// word is an assignment or a declaration.
    pub(super) fn declare(&mut self, command: &str, args: &[Word], unconditional: bool) {
        let options = options(command, args);
        let words = || {
            args.iter()
                .map(|arg| arg.text.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        };
        if let Some(word) = options.unread {
            let doubt = unread_doubt(command, args, word, self.place);
            self.events.push(Event::Doubt(doubt));
        }
        if matches!(command, "typeset" | "declare" | "private") && options.has('m') {
            self.events.push(Event::Doubt(format!(
                "it cannot tell which parameters `{command} {}` in {} sets, as with -m zsh sets \
                 each one a pattern of it matches",
                words(),
                self.place
            )));
        }
        let attributes = matches!(command, "readonly" | "integer" | "float")
            || ATTRIBUTES.chars().any(|letter| options.on(letter));
        let array = options.on('a');
        // The names, past the word the check stops reading the options at.
        let names = (options.names + usize::from(options.unread.is_some())).min(args.len());
        for arg in &args[names..] {
            let target = arg
                .text
                .split_once('=')
                .map_or(arg.text.as_str(), |(target, _)| target);
            let name = assigned(target);
            if computed_target(arg) {
                self.events.push(Event::Doubt(format!(
                    "it cannot tell which parameter `{command} {}` in {} sets",
                    arg.text, self.place
                )));
            } else if options.on('T') && tie_read(name) {
                self.events.push(Event::Doubt(format!(
                    "it cannot follow the value of `{}`, which `{command} {}` in {} ties to \
                     another name, by which zsh sets it too",
                    arg.text,
                    words(),
                    self.place
                )));
            } else if FOLLOWED.contains(&name) && (attributes || (array && name != "fpath")) {
                self.events.push(Event::Doubt(format!(
                    "it cannot follow the value of `{name}` that `{command} {}` in {} gives an \
                     attribute, which may change what zsh expands it to or keep a later \
                     assignment from setting it",
                    words(),
                    self.place
                )));
            }
        }
        // In a function, an anonymous one among them, without `-g`, a name
        // declared as it is is the function's own and empty there, as
        // `${XDG_CONFIG_HOME:-...}` then tells.
        let in_function = self.function().is_some()
            || self.frames.iter().any(|open| open.frame == Frame::Function);
        let local = in_function && command != "export" && !options.has('g');
        for arg in args {
            // A hook's array or a prompt declared as it is.
            if hook_array(&arg.text) {
                self.hooks += 1;
            }
            if PROMPTS.contains(&arg.text.as_str()) {
                self.prompts += 1;
            }
            self.assignment(arg, unconditional);
            let name = match arg.text.as_str() {
                "ZDOTDIR" => "ZDOTDIR",
                "XDG_CONFIG_HOME" => "XDG_CONFIG_HOME",
                _ => continue,
            };
            if local {
                self.events.push(Event::Assign {
                    name,
                    value: Some(Word::default()),
                    unconditional: false,
                    first: false,
                });
            }
        }
    }

    /// The events of an `unset` of `args` ([`options`]), which runs
    /// `unconditional` or not: what it takes away holds no code (a prompt, a
    /// hook's array), and `XDG_CONFIG_HOME` taken away is its default after
    /// it. A word where its options may stand that an expansion, brace
    /// expansion or a glob may make any options of is a doubt, and so is, but
    /// with `-f`, which takes functions away, a name such a word may make, and
    /// a pattern of `-m` that such a word makes or that may match a parameter
    /// the check reads ([`matches_read`]), whose value may then be another
    /// than the one the check follows.
    pub(super) fn unset(&mut self, args: &[Word], unconditional: bool) {
        for arg in args {
            self.prompts += usize::from(PROMPTS.contains(&arg.text.as_str()));
            self.hooks += usize::from(hook_array(&arg.text));
            self.mention(&arg.text);
        }
        let options = options("unset", args);
        // With `-f` it takes functions away, whatever its other words.
        if options.has('f') {
            return;
        }
        if let Some(word) = options.unread {
            let doubt = unread_doubt("unset", args, word, self.place);
            self.events.push(Event::Doubt(doubt));
            return;
        }
        for arg in &args[options.names..] {
            let computed = arg.expands || arg.bare || arg.text.contains(['$', '`']);
            if options.has('m') && (computed || matches_read(&arg.text)) {
                self.events.push(Event::Doubt(format!(
                    "it cannot tell which parameters `unset -m {}` in {} takes away, as its \
                     pattern may match one the check reads",
                    arg.text, self.place
                )));
            } else if computed {
                self.events.push(Event::Doubt(format!(
                    "it cannot tell which parameter `unset {}` in {} takes away",
                    arg.text, self.place
                )));
            } else if !options.has('m') && arg.text == "XDG_CONFIG_HOME" {
                self.xdg_config_homes += 1;
                self.events.push(Event::Assign {
                    name: "XDG_CONFIG_HOME",
                    value: None,
                    unconditional,
                    first: !self.ran,
                });
            }
        }
    }
}
