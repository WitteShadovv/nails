// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a startup file's lines name, counted without the lexer and
//! wherever it stands: the options that write each command line to the
//! history file, `source`, a `.` with a word after it, `eval`, an alias that
//! stands for `.`, `autoload`, an `fc` that may write the history file, and
//! the `ZDOTDIR` and `fpath` settings. The walk counts the same as it reads
//! them as code it follows, and what the lines name beyond that is what it
//! did not follow: an option named there counts as on, an `fpath` setting
//! adds a directory the check cannot follow, and the rest is a doubt.
//!
//! Only a line whose first character that is not a blank is `#` is left out,
//! so an option a comment at the end of a line names counts as on too, and a
//! `source` or `eval` anywhere else than in a command the walk follows, as in
//! a string, an `echo`, an alias or a here-document, is a doubt.
//!
//! The lines are read in each form zsh may read their words in ([`Forms`]):
//! as written, with each backslash-newline joined, and each of those with the
//! quotes and backslashes taken off and `$'...'` decoded, as zsh takes them
//! off a word before it uses it as a name (`print -v T\TY`), and the words
//! of the code as the lexer reads them, which a line that starts with `#`
//! inside a quote does not hide. What the most of them name counts.

use super::lexer::{Token, lex};
use super::walk::{HOOKS, PROMPTS, option};

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
    /// `autoload`.
    pub(super) autoloads: usize,
    /// `fpath` and `FPATH` where they are not read ([`fpath_writes`]).
    pub(super) fpaths: usize,
    /// `fc` with a flag that writes the history file, or an expansion
    /// ([`fc_writes`]).
    pub(super) fcs: usize,
    /// `NIX_PROFILES` where it is not read ([`nix_profiles_writes`]).
    pub(super) nix_profiles: usize,
    /// A parameter assigned by the name another one holds
    /// ([`indirect_assignments`]).
    pub(super) indirects: usize,
    /// An array of hook functions (`precmd_functions`) where it is not read
    /// ([`hook_writes`]).
    pub(super) hooks: usize,
    /// A prompt (`PS1`, `PROMPT`, ...) where it is not read
    /// ([`prompt_writes`]).
    pub(super) prompts: usize,
    /// A parameter that holds aliases (`aliases`, `galiases`) where it is
    /// not read ([`alias_writes`]).
    pub(super) alias_params: usize,
    /// `functions` or `dis_functions` where it is not read ([`writes`]).
    pub(super) function_params: usize,
    /// `((` and `$[`, which start arithmetic.
    pub(super) arith: usize,
}

impl Named {
    /// The most of `self` and `other`, field by field.
    fn most(self, other: Self) -> Self {
        let mut options = self.options;
        for (at, count) in other.options.iter().enumerate() {
            options[at] = options[at].max(*count);
        }
        Self {
            options,
            sources: self.sources.max(other.sources),
            evals: self.evals.max(other.evals),
            zdotdirs: self.zdotdirs.max(other.zdotdirs),
            autoloads: self.autoloads.max(other.autoloads),
            fpaths: self.fpaths.max(other.fpaths),
            fcs: self.fcs.max(other.fcs),
            nix_profiles: self.nix_profiles.max(other.nix_profiles),
            indirects: self.indirects.max(other.indirects),
            hooks: self.hooks.max(other.hooks),
            prompts: self.prompts.max(other.prompts),
            alias_params: self.alias_params.max(other.alias_params),
            function_params: self.function_params.max(other.function_params),
            arith: self.arith.max(other.arith),
        }
    }

    /// What `piece`, a line of code or a word of it (`word`), names. A word
    /// that is nothing but `aliases` or `functions` is an array's element or
    /// the builtin `functions`, which the walk reads.
    fn add(&mut self, piece: &str, word: bool) {
        for (at, _) in options(piece) {
            self.options[at] += 1;
        }
        self.sources += whole_words(piece, "source") + dot_words(piece) + alias_dots(piece);
        self.evals += whole_words(piece, "eval");
        self.zdotdirs += zdotdir_writes(piece);
        self.autoloads += whole_words(piece, "autoload");
        self.fpaths += fpath_writes(piece);
        self.fcs += fc_writes(piece);
        self.nix_profiles += nix_profiles_writes(piece);
        self.indirects += indirect_assignments(piece);
        self.hooks += hook_writes(piece);
        self.prompts += prompt_writes(piece);
        self.arith += piece.matches("((").count() + piece.matches("$[").count();
        let alone = matches!(
            piece,
            "functions"
                | "dis_functions"
                | "aliases"
                | "galiases"
                | "saliases"
                | "dis_aliases"
                | "dis_galiases"
                | "dis_saliases"
        );
        if !(word && alone) {
            self.alias_params += alias_writes(piece);
            self.function_params += function_writes(piece);
        }
    }
}

/// What the lines of zsh code `text` name, in the form of them that names
/// the most of each ([`Forms`]).
pub(super) fn named(text: &str) -> Named {
    let forms = Forms::of(text);
    let mut most = Named::default();
    for form in &forms.texts {
        let mut named = Named::default();
        for line in code_lines(form) {
            named.add(line, false);
        }
        most = most.most(named);
    }
    let mut named = Named::default();
    for word in &forms.words {
        named.add(word, true);
    }
    most.most(named)
}

/// The lines of `text` that are no comment: whose first character that is
/// not a blank is not `#`.
fn code_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
}

/// The forms of a file's text in which the check looks for the names its
/// lines hold, as zsh may read them: the text as written; with each
/// backslash-newline joined, as zsh joins the lines; each of those with each
/// `$'...'` decoded and every quote and backslash taken off, as zsh takes
/// them off a word before it uses it as a name (`print -v T\TY`); and the
/// words of its code as the lexer reads them, quotes taken off and lines
/// joined, which a line that starts with `#` inside a quote does not hide.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Forms {
    texts: Vec<String>,
    words: Vec<String>,
}

impl Forms {
    /// The forms of `text`.
    pub(super) fn of(text: &str) -> Self {
        let mut texts = vec![text.to_string()];
        // Joined, a line may run on into what was a comment line, which a
        // `#` that starts a word then starts.
        let joined = without_comments(&text.replace("\\\n", ""));
        if joined != text {
            texts.push(joined);
        }
        for form in texts.clone() {
            let bare = unquoted(&form);
            if !texts.contains(&bare) {
                texts.push(bare);
            }
        }
        let words = lex(text)
            .0
            .into_iter()
            .flat_map(|token| match token {
                Token::Word(word) => vec![word.text],
                Token::Array(name, items) => {
                    let mut words = vec![format!("{name}=(")];
                    words.extend(items.into_iter().map(|item| item.text));
                    words
                }
                Token::Text(text) | Token::Arithmetic(text) => vec![text],
                _ => Vec::new(),
            })
            .map(|word| unquoted(&word))
            .collect();
        Self { texts, words }
    }

    /// The most that `count` finds in the lines of a form that are no
    /// comment, or in the words of the code.
    pub(super) fn most(&self, count: impl Fn(&str) -> usize) -> usize {
        let lines = self
            .texts
            .iter()
            .map(|form| code_lines(form).map(&count).sum::<usize>());
        let words = self.words.iter().map(|word| count(word)).sum::<usize>();
        lines
            .chain(std::iter::once(words))
            .max()
            .unwrap_or_default()
    }

    /// How often the forms name the variable `name` otherwise than to read
    /// it, at the most ([`writes`]).
    pub(super) fn writes(&self, name: &str) -> usize {
        self.most(|line| writes(line, name))
    }

    /// How often `name` stands in the forms as a word of its own
    /// ([`whole_words`]), at the most.
    pub(super) fn uses(&self, name: &str) -> usize {
        self.most(|line| whole_words(line, name))
    }

    /// What the forms may change what a later command runs with, as the
    /// warning names each: an alias, by `alias` with a value or the
    /// parameters that hold them ([`alias_writes`]); a `disable`, after
    /// which a name may be another command; a `trap`; a variable of the
    /// dynamic loader (`LD_PRELOAD`), which may make a program print other
    /// code; and `ARGV0`, which picks the program a multi-call coreutils runs.
    pub(super) fn shadows(&self) -> Vec<&'static str> {
        let mut found = Vec::new();
        if self.most(|line| alias_writes(line) + alias_definitions(line)) > 0 {
            found.push("defines an alias");
        }
        if self.uses("disable") > 0 {
            found.push("names `disable`");
        }
        if self.uses("trap") > 0 {
            found.push("names `trap`");
        }
        if self.most(loader_writes) > 0 {
            found.push("sets a variable of the dynamic loader (`LD_...`)");
        }
        if self.writes("ARGV0") > 0 {
            found.push("sets ARGV0, the name zsh gives every program it runs");
        }
        found
    }

    /// Whether the forms may make zsh export every parameter set: they name
    /// `ALL_EXPORT`, in either form, or run a `set` with a word of flags that
    /// holds `a` (`set -a`).
    pub(super) fn all_export(&self) -> bool {
        self.texts.iter().any(|form| {
            names_any(form, &["allexport"])
                || code_lines(form).any(|line| {
                    whole_words(line, "set") > 0
                        && line.split_whitespace().any(|word| {
                            word.len() > 1 && word.starts_with(['-', '+']) && word.contains('a')
                        })
                })
        })
    }

    /// Whether the forms may hide what a special parameter is: a
    /// `typeset`, a `local` or the like with a flag word that holds `h`
    /// (`local -h SECONDS`), after which it holds what is assigned to it.
    pub(super) fn hides_specials(&self) -> bool {
        self.texts.iter().any(|form| {
            code_lines(form).any(|line| {
                [
                    "typeset", "declare", "local", "private", "export", "readonly", "integer",
                    "float",
                ]
                .iter()
                .any(|command| whole_words(line, command) > 0)
                    && line.split_whitespace().any(|word| {
                        word.len() > 1
                            && word.starts_with(['-', '+'])
                            && word[1..].chars().all(|c| c.is_ascii_alphanumeric())
                            && word.contains('h')
                    })
            })
        })
    }

    /// Whether the forms may turn `SH_WORD_SPLIT` or `KSH_ARRAYS` on, which
    /// split what an expansion gives an array or keep its first element:
    /// they name either, in either form ([`names_any`]), run an `emulate` of
    /// another mode than zsh's ([`emulates_other`]), or a `set`, `setopt` or
    /// `unsetopt` with a word of flags that holds `y`, `SH_WORD_SPLIT`'s
    /// letter.
    pub(super) fn word_split(&self) -> bool {
        self.texts.iter().any(|form| {
            names_any(form, &["shwordsplit", "ksharrays"])
                || emulates_other(form)
                || code_lines(form).any(|line| {
                    ["set", "setopt", "unsetopt"]
                        .iter()
                        .any(|command| whole_words(line, command) > 0)
                        && line.split_whitespace().any(|word| {
                            word.len() > 1
                                && word.starts_with(['-', '+'])
                                && word[1..].chars().all(|c| c.is_ascii_alphanumeric())
                                && word.contains('y')
                        })
                })
        })
    }
}

/// How often `line` defines an alias with the `alias` builtin: the word
/// `alias` of its own, with an `=` after it.
fn alias_definitions(line: &str) -> usize {
    let part = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-');
    line.match_indices("alias")
        .filter(|&(at, found)| {
            !line[..at].chars().next_back().is_some_and(part)
                && !line[at + found.len()..].chars().next().is_some_and(part)
                && line[at + found.len()..].contains('=')
        })
        .count()
}

/// How often `line` sets a variable of the dynamic loader, whose name starts
/// with `LD_` (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`), otherwise than
/// to read it ([`is_write`]).
fn loader_writes(line: &str) -> usize {
    let part = |c: char| c.is_ascii_alphanumeric() || c == '_';
    line.match_indices("LD_")
        .filter(|&(at, _)| {
            let len = line[at..]
                .find(|c: char| !part(c))
                .unwrap_or(line.len() - at);
            // The name, not one that ends with it (`OLD_PATH`).
            !line[..at].chars().next_back().is_some_and(part) && is_write(line, at, len)
        })
        .count()
}

/// Whether `text`, zsh code, runs an `emulate` of another mode than zsh's,
/// which may turn `SH_WORD_SPLIT` or `KSH_ARRAYS` on: past its flags (and
/// the option after `-o` or `+o`), its first word is not `zsh`. One with no
/// word after it shows the mode and changes none.
fn emulates_other(text: &str) -> bool {
    code_lines(text).any(|line| {
        let part = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-');
        line.match_indices("emulate").any(|(at, found)| {
            if line[..at].chars().next_back().is_some_and(part)
                || line[at + found.len()..].chars().next().is_some_and(part)
            {
                return false;
            }
            let rest = line[at + found.len()..]
                .split([';', '&', '|', '(', ')', '`'])
                .next()
                .unwrap_or_default();
            let mut words = rest.split_whitespace();
            while let Some(word) = words.next() {
                if matches!(word, "-o" | "+o") {
                    words.next();
                } else if !word.starts_with(['-', '+']) {
                    return word != "zsh";
                }
            }
            false
        })
    })
}

/// `text` with what each of its lines holds from a `#` that starts a word
/// on taken out, as zsh reads a comment.
fn without_comments(text: &str) -> String {
    text.split_inclusive('\n')
        .map(|line| {
            let mut previous: Option<char> = None;
            for (at, c) in line.char_indices() {
                if c == '#'
                    && previous.is_none_or(|p| {
                        p.is_whitespace() || matches!(p, ';' | '&' | '|' | '(' | ')')
                    })
                {
                    let end = if line.ends_with('\n') { "\n" } else { "" };
                    return format!("{}{end}", &line[..at]);
                }
                previous = Some(c);
            }
            line.to_string()
        })
        .collect()
}

/// `text` with each `$'...'` decoded, its escapes as zsh reads them
/// (`$'\x54'` is `T`), and then every quote and backslash taken off.
fn unquoted(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'\'') {
            chars.next();
            while let Some(c) = chars.next() {
                match c {
                    '\'' => break,
                    '\\' => out.extend(ansi_escape(&mut chars)),
                    c => out.push(c),
                }
            }
            continue;
        }
        if !matches!(c, '\'' | '"' | '\\') {
            out.push(c);
        }
    }
    out
}

/// The character the escape after a backslash in `$'...'` stands for, read
/// from `chars`: a number in hex after `x`, `u` or `U`, or in octal; the
/// character itself for any other, as zsh reads them (`\T` is `T`); `None`
/// at the end of the text.
fn ansi_escape(chars: &mut std::iter::Peekable<std::str::Chars>) -> Option<char> {
    let c = chars.next()?;
    let number = |chars: &mut std::iter::Peekable<std::str::Chars>, radix: u32, most: usize| {
        let mut digits = String::new();
        while digits.len() < most
            && let Some(digit) = chars.next_if(|digit| digit.is_digit(radix))
        {
            digits.push(digit);
        }
        u32::from_str_radix(&digits, radix)
            .ok()
            .and_then(char::from_u32)
    };
    match c {
        'x' => number(chars, 16, 2).or(Some('x')),
        'u' => number(chars, 16, 4).or(Some('u')),
        'U' => number(chars, 16, 8).or(Some('U')),
        '0'..='7' => {
            let mut digits = c.to_string();
            while digits.len() < 3
                && let Some(digit) = chars.next_if(|digit| digit.is_digit(8))
            {
                digits.push(digit);
            }
            u32::from_str_radix(&digits, 8)
                .ok()
                .and_then(char::from_u32)
        }
        'n' => Some('\n'),
        't' => Some('\t'),
        other => Some(other),
    }
}

/// The flags of `fc` that write the history file: `-A` appends to it, `-W`
/// writes it, `-P` writes the list it pops, and `-p` pushes a list that zsh
/// writes to its file as it pops it, which `-a` makes it do as the function
/// it runs in returns.
pub(super) const FC_WRITES: [char; 4] = ['A', 'W', 'P', 'p'];

/// Whether `word`, a word of an `fc` command with its quotes taken off, is
/// one of its flags: a `-` and a letter (`-AI`), not a number (`-10`).
pub(super) fn is_fc_flag(word: &str) -> bool {
    word.strip_prefix('-')
        .is_some_and(|flags| flags.starts_with(|c: char| c.is_ascii_alphabetic()))
}

/// How often an `fc`, or a `history`, which takes its flags, stands in
/// `line` as a word of its own with a flag after it that writes the history
/// file ([`FC_WRITES`]), or an expansion that may be one, before its options
/// end or the command does.
fn fc_writes(line: &str) -> usize {
    let part = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-');
    ["fc", "history"]
        .iter()
        .flat_map(|command| line.match_indices(command))
        .filter(|&(at, found)| {
            let rest = &line[at + found.len()..];
            let before = line[..at].chars().next_back();
            if before.is_some_and(part) || rest.chars().next().is_some_and(part) {
                return false;
            }
            // `history` as a command, not the parameter (`${history[1]}`).
            if found == "history"
                && (!before.is_none_or(|c| c.is_whitespace() || ";&|(`".contains(c))
                    || !rest.starts_with(char::is_whitespace))
            {
                return false;
            }
            let command = rest
                .split([';', '&', '|', '(', ')', '`', '}'])
                .next()
                .unwrap_or_default();
            for word in command.split_whitespace() {
                let word = word.replace(['\'', '"', '\\'], "");
                if word.contains('$') {
                    return true;
                }
                if !is_fc_flag(&word) {
                    return false;
                }
                if word.contains(FC_WRITES) {
                    return true;
                }
            }
            false
        })
        .count()
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
/// either form: in each word of it as brace expansion may make it
/// ([`braces`]), each part between characters that are no letter, digit or
/// `_`, and, after a `-` or `+`, what follows an `o` in the part, as
/// `set -oshare_history` takes it. A word that brace expansion makes too
/// much of names every option.
pub(super) fn options(text: &str) -> Vec<(usize, bool)> {
    let mut found = Vec::new();
    for chunk in text.split_whitespace() {
        match braces(chunk) {
            Some(words) => {
                for word in words {
                    named_in(&word, &option, &mut found);
                }
            }
            None => found.extend((0..super::OPTIONS.len()).map(|at| (at, true))),
        }
    }
    found
}

/// Whether `text`, zsh code, may turn `RCS` or `GLOBAL_RCS` on again, which
/// make a zsh started with `-f` or `-d` read the startup files it skips: a
/// word that names one of them, in either form and as [`options`] reads
/// words; a `set`, `setopt` or `unsetopt` with a word of flags that holds `f`
/// or `d`, the letters of `NO_RCS` and `NO_GLOBAL_RCS` (`set +f`); and an
/// `emulate`, as `emulate -R` sets every option as zsh starts with it. A line
/// that is a comment is left out.
pub(super) fn names_rcs(text: &str) -> bool {
    names_any(text, &["rcs", "globalrcs"])
        || text
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .any(|line| {
                let flags = ["set", "setopt", "unsetopt"]
                    .iter()
                    .any(|command| whole_words(line, command) > 0)
                    && line.split_whitespace().any(|word| {
                        let word = word.trim_matches(['\'', '"', '\\']);
                        word.len() > 1
                            && word.starts_with(['-', '+'])
                            && word[1..].starts_with(|c: char| c.is_ascii_alphabetic())
                            && word.contains(['f', 'd'])
                    });
                // A computed flag or name (`set +$x`), and an `exec`, which
                // may start another zsh without `-f`.
                let computed = ["set", "setopt", "unsetopt"].iter().any(|command| {
                    line.match_indices(command).any(|(at, _)| {
                        whole_words(&line[at..], command) > 0 && line[at..].contains(['$', '`'])
                    })
                });
                flags
                    || computed
                    || whole_words(line, "emulate") > 0
                    || whole_words(line, "exec") > 0
            })
}

/// Whether `text`, a word of zsh code, names a history file: `$HISTFILE` or
/// an expansion of it, or a path whose last part holds `hist` in any case
/// (`~/.zsh_history`, `~/.histfile`, `of=$HOME/.zhistory`).
pub(super) fn history_path(text: &str) -> bool {
    let last = text.rsplit(['/', '=']).next().unwrap_or(text);
    text.contains("$HISTFILE")
        || text.contains("${HISTFILE")
        || last.to_lowercase().contains("hist")
}

/// Whether `text`, zsh code, names one of the options `wanted` (as zsh
/// compares names: lower case, without `_`), in either form and as
/// [`options`] reads words, outside a line that is a comment.
pub(super) fn names_any(text: &str, wanted: &[&str]) -> bool {
    let named = |word: &str| {
        let name: String = word
            .chars()
            .filter(|c| *c != '_')
            .collect::<String>()
            .to_lowercase();
        let name = name.strip_prefix("no").unwrap_or(&name);
        wanted.contains(&name).then_some(())
    };
    text.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .any(|line| {
            line.split_whitespace().any(|chunk| match braces(chunk) {
                Some(words) => words.iter().any(|word| {
                    let mut found = Vec::new();
                    named_in(word, &named, &mut found);
                    !found.is_empty()
                }),
                None => true,
            })
        })
}

/// Whether `text`, zsh code, may turn `PROMPT_SUBST` on, which makes zsh run
/// what a prompt holds as it shows it: it names the option, or runs an
/// `emulate`, as sh's and ksh's emulation turn it on.
pub(super) fn names_prompt_subst(text: &str) -> bool {
    names_any(text, &["promptsubst"])
        || text
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .any(|line| whole_words(line, "emulate") > 0)
}

/// Whether `text`, a word of zsh code, expands a parameter's value again,
/// which may run code or set a parameter (`${options[...]::=on}`): with the
/// `(e)` flag, with `(%%)`, which expands it in full as a prompt, or as a
/// pattern (`${~name}`, `$~name`), where a glob qualifier in the value runs
/// code. One `%` only expands a prompt's escapes (`${(%):-%~}`).
pub(super) fn reexpands(text: &str) -> bool {
    text.contains("${~")
        || text.contains("$~")
        || text.match_indices("${(").any(|(at, found)| {
            let flags = &text[at + found.len()..];
            flags
                .split(')')
                .next()
                .is_some_and(|flags| flags.contains('e') || flags.matches('%').count() > 1)
        })
}

/// Add what the parts of `word` name, as `named` reads a part, to `found`
/// ([`options`]).
fn named_in<T>(word: &str, named: &impl Fn(&str) -> Option<T>, found: &mut Vec<T>) {
    let mut start = None;
    for (at, c) in word
        .char_indices()
        .chain(std::iter::once((word.len(), ' ')))
    {
        let part = c.is_ascii_alphanumeric() || c == '_';
        match start {
            None if part => start = Some(at),
            Some(from) if !part => {
                let piece = &word[from..at];
                if let Some(hit) = named(piece) {
                    found.push(hit);
                } else if word[..from].ends_with(['-', '+']) {
                    // Flags, an `o` among them, and the option's name after it.
                    found.extend(
                        piece
                            .match_indices('o')
                            .find_map(|(o, _)| named(&piece[o + 1..])),
                    );
                }
                start = None;
            }
            _ => {}
        }
    }
}

/// The most words that brace expansion is followed into for one word of
/// code; one that makes more names every option ([`options`]).
const BRACE_LIMIT: usize = 1024;

/// What stands for the `{` and the `}` of a group that brace expansion
/// leaves as written, so that it is not expanded again.
const KEPT: (char, char) = ('\u{1}', '\u{2}');

/// The words that brace expansion may make of `word`, a word of zsh code as
/// written, as far as they may name an option, and more: each alternative of
/// a `{a,b}` list, and of a `{x..y}` range and, as `BRACE_CCL` makes it, of
/// a `{abc}` group (its ranges too, as in `{a-z}`) each character that an
/// option's name may hold ([`NAME_CHARS`]), beside the group as written.
/// `None` when that makes more than [`BRACE_LIMIT`].
pub(super) fn braces(word: &str) -> Option<Vec<String>> {
    let mut done = Vec::new();
    let mut todo = vec![word.to_string()];
    while let Some(word) = todo.pop() {
        match group(&word) {
            None => done.push(word),
            Some((open, close)) => {
                for alternative in alternatives(&word[open + 1..close]) {
                    todo.push(format!(
                        "{}{alternative}{}",
                        &word[..open],
                        &word[close + 1..]
                    ));
                }
            }
        }
        if done.len() + todo.len() > BRACE_LIMIT {
            return None;
        }
    }
    Some(done)
}

/// Where the first group that brace expansion expands in `word` opens and
/// closes: a `{` with its `}`, past a parameter's expansion (`${...}`).
fn group(word: &str) -> Option<(usize, usize)> {
    let bytes = word.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'$' && bytes.get(at + 1) == Some(&b'{') {
            at = closing(bytes, at + 1).map_or(at + 2, |close| close + 1);
        } else if bytes[at] == b'{' {
            match closing(bytes, at) {
                Some(close) => return Some((at, close)),
                None => at += 1,
            }
        } else {
            at += 1;
        }
    }
    None
}

/// The `}` that closes the `{` at `open` in `bytes`, nested ones counted.
fn closing(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (at, &byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
    }
    None
}

/// The characters of the names of [`super::OPTIONS`] and of their `no`
/// form, in either case, and the `_` that zsh skips in a name: no other
/// character a group of brace expansion stands for can make a word name one.
const NAME_CHARS: &str = "incapedhstorymINCAPEDHSTORYM_";

/// What a group of brace expansion, `content` between its braces, may stand
/// for ([`braces`]).
fn alternatives(content: &str) -> Vec<String> {
    let mut parts = vec![String::new()];
    let mut depth = 0usize;
    for c in content.chars() {
        match c {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(String::new());
                continue;
            }
            _ => {}
        }
        parts.last_mut().expect("a part").push(c);
    }
    if parts.len() > 1 {
        return parts;
    }
    let mut alternatives = vec![format!("{}{content}{}", KEPT.0, KEPT.1)];
    let mut add = |from: char, to: char| {
        for c in from.min(to)..=from.max(to) {
            if NAME_CHARS.contains(c) && !alternatives.iter().any(|known| *known == c.to_string()) {
                alternatives.push(c.to_string());
            }
        }
    };
    // A range, `{a..e}` or `{1..9..2}`; one of numbers makes digits, which
    // no option's name holds.
    if let Some((from, to)) = content.split_once("..") {
        let to = to.split("..").next().unwrap_or_default();
        let one = |text: &str| {
            let mut chars = text.chars();
            chars.next().filter(|_| chars.next().is_none())
        };
        if let (Some(from), Some(to)) = (one(from), one(to)) {
            add(from, to);
            return alternatives;
        }
        if from.parse::<i64>().is_ok() && to.parse::<i64>().is_ok() {
            alternatives.push("0".to_string());
            return alternatives;
        }
    }
    let chars: Vec<char> = content.chars().collect();
    let mut at = 0;
    while at < chars.len() {
        if at + 2 < chars.len() && chars[at + 1] == '-' {
            add(chars[at], chars[at + 2]);
            at += 3;
        } else {
            add(chars[at], chars[at]);
            at += 1;
        }
    }
    alternatives
}

/// Whether `text`, a word of zsh code as written, holds a glob qualifier
/// that runs code as zsh expands the word: `e` and a delimiter around the
/// code (`*(e:'...':)`, `*(#qe'...')`), or `+` and a command (`*(+func)`).
/// What `$(( ))` holds is arithmetic, not a glob.
pub(super) fn qualifier_code(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut at = 0;
    while at < chars.len() {
        if chars[at] == '$' && chars.get(at + 1) == Some(&'(') && chars.get(at + 2) == Some(&'(') {
            // Arithmetic: past its `))`.
            let mut depth = 0usize;
            at += 1;
            while at < chars.len() {
                match chars[at] {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                at += 1;
            }
        } else if chars[at] == '(' && (at == 0 || chars[at - 1] != '$') {
            let rest = &chars[at + 1..];
            for (i, &c) in rest.iter().enumerate() {
                let next = rest.get(i + 1).copied();
                let code = match (c, next) {
                    ('e', Some(open)) if open.is_ascii_punctuation() && open != ')' => {
                        let close = match open {
                            '(' => ')',
                            '[' => ']',
                            '{' => '}',
                            '<' => '>',
                            other => other,
                        };
                        rest[i + 2..].contains(&close)
                    }
                    ('+', Some(name)) => name.is_ascii_alphabetic() || matches!(name, '_' | '{'),
                    _ => false,
                };
                if code {
                    return true;
                }
            }
        }
        at += 1;
    }
    false
}

/// How often `text` names `ZDOTDIR` otherwise than to read it ([`writes`]).
pub(super) fn zdotdir_writes(text: &str) -> usize {
    writes(text, "ZDOTDIR")
}

/// How often `text` names `NIX_PROFILES` otherwise than to read it
/// ([`writes`]).
pub(super) fn nix_profiles_writes(text: &str) -> usize {
    writes(text, "NIX_PROFILES")
}

/// How often `text` names one of the arrays of the functions zsh runs as
/// hooks (`precmd_functions`) otherwise than to read it ([`writes`]).
pub(super) fn hook_writes(text: &str) -> usize {
    HOOKS
        .iter()
        .map(|hook| writes(text, &format!("{hook}_functions")))
        .sum()
}

/// How often `text` names a parameter whose value zsh shows as a prompt
/// otherwise than to read it ([`writes`]); `prompt`, which also names the
/// function `promptinit` defines (`prompt suse`), only where no word of its
/// own names it, as in `prompt=...` or `${prompt::=...}`, and not in a
/// widget's name (`reset-prompt`).
pub(super) fn prompt_writes(text: &str) -> usize {
    let word_end = |c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')');
    let bare = |at: usize, len: usize| {
        text[..at].chars().next_back().is_none_or(word_end)
            && text[at + len..].chars().next().is_none_or(word_end)
    };
    PROMPTS
        .iter()
        .filter(|name| **name != "prompt")
        .map(|name| writes(text, name))
        .sum::<usize>()
        + text
            .match_indices("prompt")
            .filter(|&(at, found)| {
                // Not in a widget's name (`zle reset-prompt`).
                let widget = text[..at].ends_with('-') || text[at + found.len()..].starts_with('-');
                is_write(text, at, found.len()) && !bare(at, found.len()) && !widget
            })
            .count()
}

/// How often `text`, zsh code, assigns a parameter whose name another one's
/// value gives: a `${(P)...}`, the `P` among other flags too, with an `=` in
/// it (`${(P)name::=value}`, `${(P)name=value}`), which can set any
/// parameter, the `options` an option is turned on in among them.
pub(super) fn indirect_assignments(text: &str) -> usize {
    let bytes = text.as_bytes();
    text.match_indices("${(")
        .filter(|&(at, found)| {
            let rest = &text[at + found.len()..];
            let Some((flags, _)) = rest.split_once(')') else {
                return true;
            };
            if !flags.contains('P') {
                return false;
            }
            // What the braces hold past the flags, nested ones counted; one
            // that does not close runs to the end of the text.
            let end = closing(bytes, at + 1).unwrap_or(text.len());
            let inner = text.get(at + found.len() + flags.len() + 1..end);
            inner.is_none_or(|inner| inner.contains('='))
        })
        .count()
}

/// How often `text` names a parameter that holds aliases (`aliases`,
/// `galiases`, `saliases` and their `dis_` forms) otherwise than to read it
/// ([`parameter_writes`]).
pub(super) fn alias_writes(text: &str) -> usize {
    ["aliases", "galiases", "saliases"]
        .iter()
        .map(|name| parameter_writes(text, name) + parameter_writes(text, &format!("dis_{name}")))
        .sum()
}

/// How often `text` names `functions` or `dis_functions`, which hold the
/// functions' bodies, otherwise than to read it ([`parameter_writes`]).
pub(super) fn function_writes(text: &str) -> usize {
    parameter_writes(text, "functions") + parameter_writes(text, "dis_functions")
}

/// How often `text` names the parameter `name`, a word that paths, patterns
/// and styles hold too (`~/.zsh/aliases.zsh`, `site-functions`,
/// `':completion:*:functions'`), otherwise than to read it ([`writes`]): as
/// a word of its own, after a blank, a quote, a `;`, a `&`, a `{` (of
/// `${name::=...}`) or the letters of an option (`-vname`), and before a
/// blank, a quote, a subscript, an `=`, a `+`, a `;`, a `}` or a `)`.
fn parameter_writes(text: &str, name: &str) -> usize {
    text.match_indices(name)
        .filter(|&(at, found)| {
            let before = text[..at].chars().next_back();
            let after = text[at + found.len()..].chars().next();
            before.is_none_or(|c| {
                c.is_whitespace() || c.is_ascii_alphabetic() || "'\";&{\\".contains(c)
            }) && after.is_none_or(|c| c.is_whitespace() || "'\"[=+;})".contains(c))
                && is_write(text, at, found.len())
        })
        .count()
}

/// How often `text` names `fpath` or `FPATH` otherwise than to read it
/// ([`writes`]).
pub(super) fn fpath_writes(text: &str) -> usize {
    writes(text, "fpath") + writes(text, "FPATH")
}

/// How often `text` names the variable `name` otherwise than to read it
/// ([`is_write`]).
fn writes(text: &str, name: &str) -> usize {
    text.match_indices(name)
        .filter(|&(at, found)| is_write(text, at, found.len()))
        .count()
}

/// Whether `text` names a variable otherwise than to read it where the
/// `len` bytes at `at` name it: anywhere but after `$` or `${` (with flags,
/// as in `${(@)name}`, or a `#`, `+`, `=`, `~` or `^` between), and in
/// `${name=...}`, `${name:=...}` or `${name::=...}`, an element's too
/// (`${name[1]::=...}`); also as the argument of an option, after its letters
/// (`print -vTTY`).
fn is_write(text: &str, at: usize, len: usize) -> bool {
    let part = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let modifiers = ['#', '+', '=', '~', '^'];
    let before = &text[..at];
    let after = &text[at + len..];
    if after.chars().next().is_some_and(part) {
        return false;
    }
    if before.chars().next_back().is_some_and(part) {
        // An option's letters and their argument in one word.
        let flags = before.trim_end_matches(|c: char| c.is_ascii_alphabetic());
        return flags.len() < before.len()
            && flags.strip_suffix(['-', '+']).is_some_and(|start| {
                !start
                    .chars()
                    .next_back()
                    .is_some_and(|c| part(c) || c == '-' || c == '+')
            });
    }
    let mut before = before.trim_end_matches(modifiers);
    if let Some(flagged) = before.strip_suffix(')')
        && let Some(open) = flagged.rfind("${(")
        && !flagged[open + 3..].contains(['}', '$', '\n'])
    {
        before = flagged[..open + 2].trim_end_matches(modifiers);
    }
    let braced = before.ends_with("${");
    let read = braced || before.ends_with('$');
    // Past an element's subscript, nested brackets counted.
    let mut after = after;
    if braced && after.starts_with('[') {
        let mut depth = 0usize;
        for (at, c) in after.char_indices() {
            match c {
                '[' => depth += 1,
                ']' => {
                    depth -= 1;
                    if depth == 0 {
                        after = &after[at + 1..];
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    !read
        || (braced
            && (after.starts_with('=') || after.starts_with(":=") || after.starts_with("::=")))
}

/// The keys of the elements of `name` that `text` sets
/// (`mapfile[~/.zsh_history]=...`, `${mapfile[$f]::=...}`,
/// `print -v 'mapfile[f]'`), as written.
pub(super) fn set_elements(text: &str, name: &str) -> Vec<String> {
    text.match_indices(name)
        .filter(|&(at, found)| is_write(text, at, found.len()))
        .filter_map(|(at, found)| {
            let key = text[at + found.len()..].strip_prefix('[')?;
            let mut depth = 1usize;
            for (end, c) in key.char_indices() {
                match c {
                    '[' => depth += 1,
                    ']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(key[..end].to_string());
                        }
                    }
                    _ => {}
                }
            }
            Some(key.to_string())
        })
        .collect()
}
