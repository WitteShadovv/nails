// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The code that zsh runs from a string a startup file holds: an alias's
//! value as it is used, a trap's, a `sched`'s, a `zstyle -e`'s and a
//! prompt's when `PROMPT_SUBST` is on (the keys a `bindkey -s` types are
//! read in [`super::keys`]). A string
//! the walk can read whole is read as an `eval`'s words are; one with an
//! expansion in it, which may make any code, is a doubt. What runs as zsh
//! looks a style up, at a time or as keys are pressed counts as a hook's, and
//! an alias's value as the code of a function of its name, where it is used.

use super::super::backstop::{FC_WRITES, KEPT, braces, history_path, is_fc_flag};
use super::super::lexer::{Token, Word, lex};
use super::{Event, Walker, walk_text_in};

/// The commands that take the words after them as options, code, names or
/// paths, so that an alias whose value ends with one hands them the words it
/// is used with (`alias so=setopt`, then `so $o`).
const OPEN: &[&str] = &[
    "setopt",
    "unsetopt",
    "set",
    "emulate",
    "source",
    ".",
    "eval",
    "autoload",
    "functions",
    "typeset",
    "declare",
    "local",
    "readonly",
    "export",
    "integer",
    "float",
    "unset",
    "fc",
    "trap",
    "sched",
    "zstyle",
    "print",
    "printf",
    "read",
    "alias",
    "zmodload",
    "builtin",
    "command",
    "exec",
    "noglob",
    "nocorrect",
    "-",
    "time",
    "prompt",
    "add-zsh-hook",
    "add-zle-hook-widget",
    "zle",
    "bindkey",
    "getopts",
    "vared",
    "zparseopts",
    "zformat",
    "getln",
    "zpty",
    "sysopen",
    "syswrite",
    "sysread",
    "zselect",
    "zstat",
    "stat",
    "strftime",
    "pcre_match",
    "zregexparse",
    "zsystem",
    "ztie",
    "zcurses",
    "private",
    "coproc",
];

/// zsh's reserved words that the walk reads as the structure of the code:
/// zsh expands an alias of such a name before it reads the word as one,
/// wherever the word starts a command (`alias '{'=...` in a function's body,
/// `alias do=...` in a loop), which the walk takes for no command it runs.
/// The precommands among the reserved words (`!`, `nocorrect`, `time`) and
/// `-` it reads as calls where they stand ([`super::command`]).
const RESERVED: &[&str] = &[
    "{", "}", "case", "coproc", "do", "done", "elif", "else", "end", "esac", "fi", "for",
    "foreach", "function", "if", "repeat", "select", "then", "until", "while",
];

/// The name of the alias that `text` defines: `name` of `name=value`, or of
/// `aliases[name]=value`; `None` for a suffix or global alias, which zsh
/// expands elsewhere than as a command's name, and for a name that holds
/// what zsh may expand, brace expansion's `{`, `,` and `}` among it.
fn alias_name(text: &str) -> Option<&str> {
    let expands = ['$', '`', '\\', '\'', '"', '[', ']', '*', '?', '{', ',', '}'];
    alias_target(text).filter(|name| !name.is_empty() && !name.contains(expands))
}

/// The name as written of the alias that `text` defines, `name` of
/// `name=value` or of `aliases[name]=value` ([`alias_name`]).
fn alias_target(text: &str) -> Option<&str> {
    let (target, _) = text.split_once('=')?;
    match target.strip_prefix("aliases[") {
        Some(rest) => rest.strip_suffix(']'),
        None if target.contains('[') => None,
        None => Some(target),
    }
}

/// The words brace expansion makes of `word`, outside quotes, where each of
/// its groups is a list (`{jpg,png}`) and none of those words starts with `-`
/// or `+`, which may be a flag: `None` for a word with no such group, or any
/// other group (a range, a `BRACE_CCL` one), a glob or an expansion, which
/// may make other words.
pub(super) fn brace_list(word: &Word) -> Option<Vec<String>> {
    if !word.bare
        || word.expands
        || word.text.contains([
            '*', '?', '[', ']', '(', ')', '|', '<', '>', '^', '#', '~', '$', '`',
        ])
    {
        return None;
    }
    let words = braces(&word.text)?;
    let kept = |text: &String| text.contains([KEPT.0, KEPT.1]);
    (words.len() > 1
        && !words
            .iter()
            .any(|text| kept(text) || text.starts_with(['-', '+'])))
    .then_some(words)
}

/// The parameters whose value zsh shows as a prompt, which `PROMPT_SUBST`
/// makes it expand, a command substitution and an assignment in an
/// expansion among it, as it shows them.
pub(in super::super) const PROMPTS: &[&str] = &[
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
];

/// Whether `word`, a string of zsh code as the lexer gives it, holds an
/// expansion, which may make any code: a backquote, or a `$` before a name,
/// a `{`, a `(` or a special parameter, wherever quotes put it (not the `$`
/// of `PS1='$ '`).
pub(super) fn computed(word: &Word) -> bool {
    let mut chars = word.text.chars().peekable();
    word.expands
        || std::iter::from_fn(|| chars.next().map(|c| (c, chars.peek().copied()))).any(
            |(c, next)| {
                c == '`'
                    || (c == '$'
                        && next.is_some_and(|next| {
                            next.is_ascii_alphanumeric() || "_{([#?!*@$-".contains(next)
                        }))
            },
        )
}

/// Whether `text`, a value zsh takes from its environment as it is, holds
/// an expansion ([`computed`]), which zsh runs as it shows it as a prompt
/// where `PROMPT_SUBST` is on.
pub(in super::super) fn expands(text: &str) -> bool {
    computed(&Word {
        text: text.to_string(),
        ..Word::default()
    })
}

/// Whether `command`, the last command of an alias's value as written, is
/// an `fc` that writes nothing: `fc`, past the precommands that run it, with
/// words that hold no expansion and no flag that writes the history file
/// ([`FC_WRITES`]: `-A`, `-W`, `-P`), as `fc -l` or `fc -lnr -20` lists it.
fn listing_fc(command: &str) -> bool {
    let (tokens, flaws) = lex(command);
    let mut words = Vec::new();
    for token in tokens {
        match token {
            Token::Word(word) if !word.expands => words.push(word.text),
            _ => return false,
        }
    }
    let mut words = words
        .iter()
        .skip_while(|word| matches!(word.as_str(), "builtin" | "noglob" | "nocorrect" | "-"));
    flaws.is_empty()
        && words.next().is_some_and(|word| word == "fc")
        && words.all(|word| !is_fc_flag(word) || !word.contains(FC_WRITES))
}

impl Walker<'_> {
    /// The events of an `alias` of `args`: what each value runs, read as an
    /// `eval`'s words, where the walk can read it whole. One with an
    /// expansion is a doubt, and so is one that ends with a command that
    /// takes the words the alias is used with as code, options, names or
    /// paths ([`OPEN`]), or with a blank, after which zsh expands the next
    /// word as an alias too. An `fc` that writes nothing is no doubt in the
    /// value of an alias zsh expands only as a command's name
    /// ([`Event::FcAlias`]). A word an expansion makes that is no definition
    /// as written is a doubt too, and so is any word brace expansion or a
    /// glob may make other words of (`{-g,-g}`, `{-,-}g`): it may be a flag
    /// (`-g`) that makes the aliases after it global, or definitions. So is a
    /// regular alias named like a reserved word ([`RESERVED`]), which runs
    /// wherever that word starts a command.
    pub(super) fn alias(&mut self, args: &[Word], unconditional: bool) {
        // `-g` and `-s` make an alias zsh expands elsewhere than as a
        // command's name; `-r` is the default, and `--` ends the flags.
        let mut regular = true;
        let mut global = false;
        let mut suffix = false;
        let mut flags = true;
        // A list zsh brace-expands into words that can be no flag
        // (`alias -s {jpg,png}=feh`) stands for those words.
        let mut words = Vec::new();
        for arg in args {
            self.mention(&arg.text);
            match brace_list(arg) {
                Some(listed) => words.extend(listed.into_iter().map(|text| Word {
                    text,
                    expands: false,
                    quoted: arg.quoted,
                    bare: false,
                })),
                None => words.push(arg.clone()),
            }
        }
        for arg in &words {
            if (!arg.text.contains('=') && computed(arg)) || arg.bare {
                let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
                self.events.push(Event::Doubt(format!(
                    "it cannot tell which aliases `alias {}` in {} defines, as an expansion, \
                     brace expansion or a glob may make `{}` other words, which may be a flag \
                     that makes them global",
                    words.join(" "),
                    self.place,
                    arg.text
                )));
                continue;
            }
            if flags && arg.text.starts_with(['-', '+']) && !arg.text.contains('=') {
                flags = arg.text != "--";
                regular &= matches!(arg.text.as_str(), "--" | "-r");
                global |= arg.text.contains('g');
                suffix |= arg.text.contains('s');
                continue;
            }
            flags = false;
            if let Some((_, value)) = arg.text.split_once('=') {
                let global = global && !suffix;
                self.alias_value(&arg.text, value, arg, unconditional, (regular, global));
            }
        }
    }

    /// The events of the value `value` an alias is given by the word `word`,
    /// as [`Walker::alias`] reads it; of `kind`, `regular` when zsh expands
    /// the alias only as a command's name, and `global` when it expands it as
    /// any word.
    pub(super) fn alias_value(
        &mut self,
        text: &str,
        value: &str,
        word: &Word,
        unconditional: bool,
        kind: (bool, bool),
    ) {
        let (regular, global) = kind;
        let doubt = |place: &str| {
            Event::Doubt(format!(
                "it cannot tell what the alias `{text}` in {place} runs where it is used"
            ))
        };
        if computed(word) {
            self.events.push(doubt(self.place));
            return;
        }
        let name = alias_name(text);
        if let Some(reserved) = alias_target(text).filter(|name| regular && RESERVED.contains(name))
        {
            self.events.push(Event::Doubt(format!(
                "it cannot tell what the alias `{text}` in {} runs where it is used, as zsh \
                 expands it in place of the reserved word `{reserved}` wherever that starts a \
                 command",
                self.place
            )));
        }
        // A regular alias's value runs where its name is used, as a function
        // of that name would; a global alias's where a word is its name, which
        // the check counts where the files are read ([`Event::GlobalAlias`]);
        // a suffix alias's, or one whose name the check cannot read, anywhere,
        // as a hook.
        let outer = match name.filter(|_| regular) {
            Some(name) => {
                self.events.push(Event::Define(name.to_string()));
                self.events.push(Event::RegularAlias(name.to_string()));
                name.to_string()
            }
            None => {
                let outer = format!("alias {text}");
                if global {
                    // The word it stands for, past `galiases[`.
                    let (target, _) = text.split_once('=').unwrap_or((text, ""));
                    let named = target
                        .split_once('[')
                        .and_then(|(_, key)| key.strip_suffix(']'))
                        .unwrap_or(target);
                    self.events.push(Event::GlobalAlias {
                        name: named.to_string(),
                        text: text.to_string(),
                    });
                } else {
                    self.events.push(Event::Hook(outer.clone()));
                }
                outer
            }
        };
        if !regular && history_path(value) {
            // A global alias for the history file (`alias -g /dev/tty=...`)
            // stands for it in a redirection.
            self.events.push(Event::Fc(format!("alias {text}")));
        }
        self.nested_in(value, unconditional, Some(outer));
        // zsh reads the value with the words where it is used, so one that
        // leaves a function's definition or a structure open (`function`,
        // `function preexec`, `{`) makes them its body or part of it.
        let walked = walk_text_in(value, self.place, None);
        if walked.confused || walked.unfinished {
            self.events.push(doubt(self.place));
        }
        // The command the words the alias is used with go to: its value's
        // last, past its assignments and precommands.
        let last = value
            .rsplit([';', '&', '|', '(', ')', '{', '}', '\n'])
            .next()
            .unwrap_or_default();
        let command = last.split_whitespace().find(|word| {
            !word.contains('=')
                && !matches!(
                    *word,
                    "builtin" | "command" | "noglob" | "nocorrect" | "exec" | "-" | "time"
                )
        });
        if value.ends_with(char::is_whitespace) {
            self.events.push(doubt(self.place));
        } else if let Some(name) = name.filter(|_| regular && listing_fc(last)) {
            // It hands its words to an `fc` that writes nothing as written,
            // but may write once used with more (`h -W`).
            self.events.push(Event::FcAlias {
                name: name.to_string(),
                text: text.to_string(),
            });
        } else if command.is_none_or(|command| OPEN.contains(&command)) {
            self.events.push(doubt(self.place));
        }
    }

    /// The events of a `trap` of `args`: the code it runs as the signal or
    /// the hook comes (`trap 'fc -AI' DEBUG`), read as an `eval`'s words,
    /// where the walk can read it whole; with an expansion, a doubt.
    pub(super) fn trap(&mut self, args: &[Word], unconditional: bool) {
        let mut args = args.iter().peekable();
        args.next_if(|arg| arg.text == "--");
        if let Some(code) = args.next() {
            if computed(code) || code.bare {
                self.events.push(Event::Doubt(format!(
                    "it cannot tell what code `trap {}` in {} runs",
                    code.text, self.place
                )));
            } else if code.text != "-" {
                // zsh runs it as it would the TRAP... function of its signal.
                let signal = args
                    .peek()
                    .map(|signal| signal.text.as_str())
                    .filter(|signal| signal.chars().all(|c| c.is_ascii_alphanumeric()))
                    .unwrap_or_default();
                let outer = format!("TRAP{signal}");
                // As a `TRAP...` function of its signal is defined.
                self.events.push(Event::Define(outer.clone()));
                self.nested_in(&code.text, unconditional, Some(outer));
            }
        }
        for arg in args {
            self.mention(&arg.text);
        }
    }

    /// The events of a `sched` of `args`: the command it runs at its time
    /// (`sched +60 fc -W`), read as an `eval`'s words, where the walk can
    /// read them whole; with an expansion, a doubt.
    pub(super) fn sched(&mut self, args: &[Word], unconditional: bool) {
        let mut args = args.iter().peekable();
        args.next_if(|arg| arg.text == "-o");
        // The time, or the number of an item to take away (`-2`).
        match args.next() {
            Some(time) if time.text.starts_with('-') => return,
            Some(time) if computed(time) => {}
            Some(_) => {}
            None => return,
        }
        let command: Vec<&Word> = args.collect();
        if command.iter().any(|word| computed(word) || word.bare) {
            let words: Vec<&str> = command.iter().map(|word| word.text.as_str()).collect();
            self.events.push(Event::Doubt(format!(
                "it cannot tell what command `sched ... {}` in {} runs",
                words.join(" "),
                self.place
            )));
            return;
        }
        let words: Vec<&str> = command.iter().map(|word| word.text.as_str()).collect();
        let code = words.join(" ");
        self.hooked(&code, unconditional, format!("sched {code}"));
    }

    /// The events of zsh code `text` that zsh runs later as a hook would,
    /// at a time, as a style is looked up or as keys are pressed, read as the
    /// code of a hook named `hook`.
    pub(super) fn hooked(&mut self, text: &str, unconditional: bool, hook: String) {
        self.events.push(Event::Hook(hook.clone()));
        self.nested_in(text, unconditional, Some(hook));
    }

    /// The events of a `zstyle` of `args`: with `-e`, the code each string
    /// after the pattern and the style is, which zsh runs as it looks the
    /// style up, read as an `eval`'s words where the walk can read it whole;
    /// with an expansion, a doubt. Any other `zstyle` sets data, whose words
    /// count for the options they name.
    pub(super) fn zstyle(&mut self, args: &[Word], unconditional: bool) {
        // The style the stock add-zle-hook-widget runs the widgets of as each
        // line is entered, or one an expansion names, which may be it. zsh
        // takes a first word `-e`, `-` or one that starts with `--` for a
        // definition past it (zutil.c's bin_zstyle), as the stock
        // add-zle-hook-widget writes `zstyle -- "$hook" widgets ...`, and any
        // other flag for none; one an expansion, brace expansion or a glob may
        // make may be any of them.
        let at = match args.first() {
            Some(first) if computed(first) || first.bare => Some(0),
            Some(flag) if flag.text == "-e" || flag.text == "-" || flag.text.starts_with("--") => {
                Some(2)
            }
            Some(flag) if flag.text.starts_with('-') => None,
            _ => Some(1),
        };
        let style = at.and_then(|at| args.get(at));
        if style.is_some_and(|style| style.text == "widgets" || computed(style) || style.bare) {
            let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
            self.events.push(Event::Doubt(format!(
                "it cannot tell which widgets `zstyle {}` in {} makes add-zle-hook-widget run \
                 as each line is entered",
                words.join(" "),
                self.place
            )));
        }
        if args.first().is_none_or(|flag| flag.text != "-e") {
            for arg in args {
                self.mention(&arg.text);
            }
            return;
        }
        for (at, arg) in args.iter().enumerate().skip(1) {
            if at < 3 {
                self.mention(&arg.text);
            } else if computed(arg) || arg.bare {
                self.events.push(Event::Doubt(format!(
                    "it cannot tell what code `zstyle -e ... {}` in {} runs",
                    arg.text, self.place
                )));
            } else {
                let hook = format!("zstyle -e {}", arg.text);
                self.hooked(&arg.text, unconditional, hook);
            }
        }
    }

    /// Note a prompt that zsh expands as it shows it when `PROMPT_SUBST` is
    /// on, `text` as written, when it holds an expansion or a command
    /// substitution: what that runs, an `fc` or an assignment to `options`
    /// among it, the check cannot follow ([`Event::Prompt`]).
    pub(super) fn prompt(&mut self, text: &str, value: &Word) {
        if computed(value) {
            self.events.push(Event::Prompt(format!(
                "it cannot follow the code that `{text}` in {} runs as zsh shows the prompt, as \
                 PROMPT_SUBST may be on",
                self.place
            )));
        }
    }
}
