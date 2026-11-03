// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What one simple command of a startup file does, as the walk reads it: the
//! options a `setopt`, `unsetopt` or `set -o` turns on or off, the files a
//! `source` or `.` reads, what an `eval` of words the walk can read runs, the
//! `ZDOTDIR` and `XDG_CONFIG_HOME` an assignment sets, the directories one
//! adds to `fpath`, the functions an `autoload` marks, and the options any
//! other word names.

use super::super::OH_MY_ZSH;
use super::super::backstop::{
    self, FC_WRITES, is_fc_flag, qualifier_code, reexpands, zdotdir_writes,
};
use super::super::lexer::{Word, is_name};
use super::strings::PROMPTS;
use super::{Event, Frame, Walker, mentioned, walk_text};

/// The precommand words that run the word after them as the command.
const PRECOMMANDS: &[&str] = &[
    "builtin",
    "command",
    "noglob",
    "nocorrect",
    "exec",
    "-",
    "time",
    "!",
];

/// Whether `text` assigns a variable (`name=...`, `name+=...`,
/// `name[key]=...`), not a word with an `=` in it (`${=c}`, `$=c`).
fn is_assignment(text: &str) -> bool {
    text.split_once('=')
        .is_some_and(|(target, _)| is_name(assigned(target)))
}

/// The name of the variable that the target of an assignment, `target`,
/// sets (`name`, `name+`, `name[key]`).
fn assigned(target: &str) -> &str {
    let name = target.strip_suffix('+').unwrap_or(target);
    name.split_once('[').map_or(name, |(name, _)| name)
}

/// Whether `text` stands for what `fpath` or `FPATH` holds, or some of it:
/// `$fpath`, `${fpath[@]}`, `${(@)fpath}`, `${fpath[1]}`, `${fpath:#pat}`;
/// not a directory made from it (`${fpath[1]}/sub`, `${fpath/a/b}`).
fn holds_fpath(text: &str) -> bool {
    let Some(rest) = text.strip_prefix('$') else {
        return false;
    };
    let (inner, braced) = match rest.strip_prefix('{') {
        Some(braced) => match braced.strip_suffix('}') {
            Some(inner) if !inner.contains(['{', '}', '$']) => (inner, true),
            _ => return false,
        },
        None => (rest, false),
    };
    let inner = match inner.strip_prefix('(') {
        Some(flagged) if braced => match flagged.split_once(')') {
            Some((_, name)) => name,
            None => return false,
        },
        _ => inner,
    };
    let end = inner
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(inner.len());
    let (name, after) = inner.split_at(end);
    let subscript =
        after.starts_with('[') && after.ends_with(']') && !after[1..after.len() - 1].contains(']');
    matches!(name, "fpath" | "FPATH")
        && (after.is_empty() || subscript || (braced && after.starts_with(":#")))
}

/// Whether `text`, a word of zsh code, may set an option by a name the check
/// cannot read: the `options` parameter as a whole, which a `read -A`, a
/// `set -A` or a `zparseopts` can fill, or an element of it whose key an
/// expansion makes (`options[$o]`, `options[${o}y]`).
fn computed_options(text: &str) -> bool {
    if text == "options" {
        return true;
    }
    text.match_indices("options[").any(|(at, found)| {
        let before = text[..at].chars().next_back();
        let key = &text[at + found.len()..];
        let key = key.split(']').next().unwrap_or(key);
        !before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') && key.contains(['$', '`'])
    })
}

/// Whether `text`, a word after `typeset` or the like, `print -v`, `printf -v`
/// or `read`, names the parameter it sets by an expansion (`"$name=on"`,
/// `${prefix}x`), which may be one of the `options` parameter.
fn computed_target(text: &str) -> bool {
    !text.starts_with(['-', '+'])
        && text
            .split_once('=')
            .map_or(text, |(target, _)| target)
            .contains(['$', '`'])
}

/// Whether `args`, the words after `functions`, `typeset` or the like
/// (`command`), mark the functions they name to be autoloaded: `functions`
/// with `-u` or `-U`, `typeset` with `-f` and one of those.
fn marks_autoload(command: &str, args: &[Word]) -> bool {
    let flags: String = args
        .iter()
        .take_while(|arg| arg.text.starts_with('-') && arg.text != "--")
        .map(|arg| arg.text.as_str())
        .collect();
    let autoload = flags.contains(['u', 'U']);
    match command {
        "functions" => autoload,
        _ => autoload && flags.contains('f'),
    }
}

impl Walker<'_> {
    /// The items of the innermost loop over `var`, when the check can list
    /// them.
    pub(super) fn loop_items(&self, var: &str) -> Option<&[String]> {
        self.frames
            .iter()
            .rev()
            .find_map(|open| match &open.frame {
                Frame::Loop {
                    var: Some(name),
                    items,
                    ..
                } if name == var => Some(items.as_deref()),
                _ => None,
            })?
    }

    /// The list `words` stands for in a `for` header, when the check can list
    /// it: literal words, or one array the file assigned literally.
    pub(super) fn list(&self, words: &[Word]) -> Option<Vec<String>> {
        if let [word] = words
            && word.expands
        {
            let name = word
                .text
                .trim_start_matches('$')
                .trim_start_matches('{')
                .trim_end_matches('}')
                .trim_end_matches("[@]")
                .trim_end_matches("[*]");
            return self.arrays.get(name).cloned();
        }
        words
            .iter()
            .map(|word| (!word.expands).then(|| word.text.clone()))
            .collect()
    }

    /// The name of the variable `word` expands to, when it is nothing but
    /// one (`$opt`, `${opt}`).
    pub(super) fn variable(word: &Word) -> Option<&str> {
        let text = word.text.strip_prefix('$')?;
        let name = text
            .strip_prefix('{')
            .and_then(|text| text.strip_suffix('}'))
            .unwrap_or(text);
        is_name(name).then_some(name)
    }

    /// The event of `word`, an element added to `fpath`, unless it stands
    /// for what `fpath` holds already ([`holds_fpath`]); a loop's variable
    /// stands for each item the check can list.
    pub(super) fn fpath_dir(&mut self, word: &Word, first: bool) {
        if holds_fpath(&word.text) {
            return;
        }
        if let Some(items) = Self::variable(word).and_then(|var| self.loop_items(var)) {
            let dirs: Vec<Event> = items
                .iter()
                .map(|text| Event::Fpath {
                    dir: Some(Word {
                        text: text.clone(),
                        expands: false,
                    }),
                    first,
                })
                .collect();
            self.events.extend(dirs);
            return;
        }
        self.events.push(Event::Fpath {
            dir: Some(word.clone()),
            first,
        });
    }

    /// The events of `items` assigned to `fpath` as an array, or appended to
    /// it (`append`): those before what `fpath` held (`$fpath`), or all
    /// where it held nothing they keep, come first ([`Event::Fpath`]).
    pub(super) fn fpath_items(&mut self, items: &[Word], append: bool) {
        let held = items.iter().position(|item| holds_fpath(&item.text));
        for (at, item) in items.iter().enumerate() {
            let first = !append && held.is_none_or(|held| at < held);
            self.fpath_dir(item, first);
        }
    }

    /// The events of an `autoload`, or of the like (`command`), of `args`:
    /// each function it marks, by name or by the path of its file. Which
    /// functions it marks is a doubt with `-m` (patterns), `-w` (compiled
    /// files), or `-X` without a name (the function it runs in).
    pub(super) fn autoload(&mut self, command: &str, args: &[Word]) {
        let mut flags = String::new();
        let mut names = Vec::new();
        let mut options = true;
        for arg in args {
            self.mention(&arg.text);
            if options && !arg.expands && arg.text.len() > 1 && arg.text.starts_with(['-', '+']) {
                if arg.text == "--" {
                    options = false;
                } else {
                    flags.push_str(&arg.text);
                }
                continue;
            }
            options = false;
            names.push(arg.clone());
        }
        if flags.contains(['m', 'w']) || (names.is_empty() && flags.contains('X')) {
            let words: Vec<&str> = std::iter::once(command)
                .chain(args.iter().map(|arg| arg.text.as_str()))
                .collect();
            self.events.push(Event::Doubt(format!(
                "it cannot tell which functions `{}` in {} loads",
                words.join(" "),
                self.place
            )));
            return;
        }
        self.events.extend(names.into_iter().map(Event::Autoload));
    }

    /// The events of zsh code `text` that a command of the file runs, read as
    /// the file's own: an `eval`'s words, an `emulate -c`'s code. What it
    /// sets counts as unconditional only when the command is and the walk
    /// followed the code's structure.
    pub(super) fn nested(&mut self, text: &str, unconditional: bool) {
        let nested = walk_text(text, self.place);
        self.sources += nested.sources;
        self.evals += nested.evals;
        self.zdotdirs += nested.zdotdirs;
        self.autoloads += nested.autoloads;
        self.fpaths += nested.fpaths;
        self.fcs += nested.fcs;
        self.may_stop |= nested.may_stop;
        let uncertain = !unconditional || nested.confused;
        for mut event in nested.events {
            if uncertain
                && let Event::Set { unconditional, .. }
                | Event::Source { unconditional, .. }
                | Event::Assign { unconditional, .. } = &mut event
            {
                *unconditional = false;
            }
            self.events.push(event);
        }
    }

    /// The events of an `emulate` of `args`: the options its `-o` and `+o`
    /// set, and the code its `-c` runs. An expansion among its words, which
    /// may be such an option or code, is a doubt.
    pub(super) fn emulate(&mut self, args: &[Word], unconditional: bool) {
        let place = self.place;
        let doubt = |what: &str| {
            Event::Doubt(format!(
                "it cannot tell what `emulate {what}` in {place} turns on"
            ))
        };
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            if arg.expands {
                self.events.push(doubt(&arg.text));
                continue;
            }
            match arg.text.as_str() {
                "-o" | "+o" => match args.next() {
                    Some(name) if name.expands => {
                        let what = format!("{} {}", arg.text, name.text);
                        self.events.push(doubt(&what));
                    }
                    Some(name) => self.set(&name.text, arg.text == "-o", unconditional),
                    None => {}
                },
                "-c" => match args.next() {
                    Some(code) if code.expands => {
                        let what = format!("-c {}", code.text);
                        self.events.push(doubt(&what));
                    }
                    Some(code) => self.nested(&code.text, unconditional),
                    None => {}
                },
                _ => self.mention(&arg.text),
            }
        }
    }

    /// The events of an `fc` of `args`. One that writes the history file, by
    /// a flag ([`FC_WRITES`]: `fc -AI`, `fc -W`), does so whenever it runs,
    /// as it does after every command from a hook (`precmd`, `preexec`,
    /// `zshaddhistory`, `TRAPDEBUG`), the way bash's `history -a` does from
    /// `PROMPT_COMMAND`. One whose words hold an expansion, which may be such
    /// a flag, is a doubt.
    pub(super) fn fc(&mut self, args: &[Word]) {
        let mut flags = Vec::new();
        for arg in args {
            if arg.expands {
                self.fcs += 1;
                let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
                self.events.push(Event::Doubt(format!(
                    "it cannot tell whether `fc {}` in {} writes the history file",
                    words.join(" "),
                    self.place
                )));
                return;
            }
            if !is_fc_flag(&arg.text) {
                break;
            }
            flags.push(arg.text.as_str());
        }
        if flags.iter().any(|flag| flag.contains(FC_WRITES)) {
            self.fcs += 1;
            self.events
                .push(Event::Fc(format!("fc {}", flags.join(" "))));
        }
    }

    /// The events of a `setopt`-like command turning the options `word`
    /// names on (`on`), as brace expansion may make the word
    /// ([`backstop::options`]); none when it names others.
    pub(super) fn set(&mut self, word: &str, on: bool, unconditional: bool) {
        for (option, named_on) in backstop::options(word) {
            self.events.push(Event::Set {
                option,
                on: on == named_on,
                unconditional,
            });
        }
    }

    /// Note every option `text` names as a mention.
    pub(super) fn mention_options(&mut self, text: &str) {
        let found = mentioned(text);
        self.events.extend(found.into_iter().map(Event::Mention));
    }

    /// Note a doubt when `text`, a word of the file's code, holds a glob
    /// qualifier that runs code ([`qualifier_code`]), or expands a
    /// parameter's value again ([`reexpands`]).
    pub(super) fn qualifier(&mut self, text: &str) {
        if qualifier_code(text) {
            self.events.push(Event::Doubt(format!(
                "it cannot follow the code that a glob qualifier in `{text}` in {} runs",
                self.place
            )));
        }
        self.reexpansion(text);
    }

    /// Note a doubt when `text` expands a parameter's value again
    /// ([`reexpands`]), which may run code.
    pub(super) fn reexpansion(&mut self, text: &str) {
        if reexpands(text) {
            self.events.push(Event::Doubt(format!(
                "it cannot follow the code that `{text}` in {} may run, as it expands a \
                 parameter's value again",
                self.place
            )));
        }
    }

    /// Note what a word of the file's code names: its options, an option it
    /// may set by a name the check cannot read ([`computed_options`]), code a
    /// glob qualifier in it runs, and a `ZDOTDIR` it may set otherwise than
    /// by an assignment the walk reads (`${ZDOTDIR:=...}`, `ZDOTDIR+=...`);
    /// all but the options are doubts.
    pub(super) fn mention(&mut self, text: &str) {
        self.qualifier(text);
        if computed_options(text) {
            self.events.push(Event::Doubt(format!(
                "it cannot tell which options `{text}` in {} sets",
                self.place
            )));
        }
        self.mention_arithmetic(text);
    }

    /// Note what an arithmetic command, `text`, names: its options, and a
    /// `ZDOTDIR` it may set ([`Walker::mention`]); no glob is expanded in
    /// it, and what `${+name}` tests sets nothing.
    pub(super) fn mention_arithmetic(&mut self, text: &str) {
        self.mention_options(text);
        self.reexpansion(text);
        if ["ZDOTDIR=", "ZDOTDIR:=", "ZDOTDIR::=", "ZDOTDIR+="]
            .iter()
            .any(|form| text.contains(form))
        {
            self.zdotdirs += zdotdir_writes(text);
            self.events.push(Event::Doubt(format!(
                "it cannot follow where `{text}` in {} sets ZDOTDIR",
                self.place
            )));
        }
    }

    /// The events of one simple command, `words`, which ran `after` a
    /// condition (`&&`, `||`) or not, and in a pipeline or the background or
    /// not.
    pub(super) fn command(&mut self, words: Vec<Word>, after_condition: bool, piped: bool) {
        let unconditional = self.certain(after_condition, piped);
        let mut words = words.into_iter().peekable();
        // Assignments before the command word.
        while let Some(word) = words.next_if(|word| is_assignment(&word.text)) {
            self.assignment(&word, unconditional);
        }
        while words
            .next_if(|word| PRECOMMANDS.contains(&word.text.as_str()))
            .is_some()
        {}
        let Some(command) = words.next() else {
            return;
        };
        let args: Vec<Word> = words.collect();
        self.qualifier(&command.text);
        for arg in &args {
            self.qualifier(&arg.text);
        }
        if command.expands && command.text.starts_with(['$', '`']) {
            // `$c`, `${:-source}`, `$(print source)`: any command, a
            // `source` among them.
            self.events.push(Event::Doubt(format!(
                "it cannot tell what command `{}` in {} runs",
                command.text, self.place
            )));
            for arg in &args {
                self.mention(&arg.text);
            }
            return;
        }
        match command.text.as_str() {
            "setopt" | "unsetopt" => {
                let on = command.text == "setopt";
                for arg in &args {
                    if let Some(items) = Self::variable(arg).and_then(|var| self.loop_items(var)) {
                        let items = items.to_vec();
                        for item in items {
                            self.set(&item, on, unconditional);
                        }
                    } else if arg.expands || arg.text.starts_with(['-', '+']) {
                        self.events.push(Event::Doubt(format!(
                            "it cannot tell which options `{} {}` in {} turns on",
                            command.text, arg.text, self.place
                        )));
                    } else {
                        self.set(&arg.text, on, unconditional);
                    }
                }
            }
            "set" => {
                let mut args = args.iter();
                while let Some(arg) = args.next() {
                    if matches!(arg.text.as_str(), "-o" | "+o")
                        && let Some(name) = args.next()
                    {
                        if name.expands {
                            self.events.push(Event::Doubt(format!(
                                "it cannot tell which options `set {} {}` in {} turns on",
                                arg.text, name.text, self.place
                            )));
                        } else {
                            self.set(&name.text, arg.text == "-o", unconditional);
                        }
                    } else {
                        self.mention(&arg.text);
                    }
                }
            }
            "source" | "." => {
                self.sources += 1;
                let mut args = args.into_iter();
                match args.next() {
                    Some(path) if path.text.ends_with(OH_MY_ZSH) => {
                        self.events.push(Event::OhMyZsh);
                    }
                    Some(path) => {
                        self.mention(&path.text);
                        self.events.push(Event::Source {
                            path,
                            unconditional,
                        });
                    }
                    None => self.events.push(Event::Doubt(format!(
                        "it cannot tell what `{}` in {} reads",
                        command.text, self.place
                    ))),
                }
                for arg in args {
                    self.mention(&arg.text);
                }
            }
            "eval" if args.iter().all(|arg| !arg.expands) => {
                // Its words are code the walk reads as zsh would run them,
                // past the `--` that may end its options.
                let skip = usize::from(args.first().is_some_and(|arg| arg.text == "--"));
                let text: Vec<&str> = args[skip..].iter().map(|arg| arg.text.as_str()).collect();
                self.evals += 1;
                self.nested(&text.join(" "), unconditional);
            }
            "emulate" => self.emulate(&args, unconditional),
            "alias" => self.alias(&args, unconditional),
            "trap" => self.trap(&args, unconditional),
            "sched" => self.sched(&args, unconditional),
            "zstyle" => self.zstyle(&args, unconditional),
            "print" | "printf" | "read" => {
                let mut target = command.text == "read";
                // `print -P` expands its words as a prompt.
                let mut prompt = false;
                let mut options = true;
                for arg in &args {
                    if target && arg.expands && computed_target(&arg.text) {
                        self.events.push(Event::Doubt(format!(
                            "it cannot tell which parameter `{} {}` in {} sets",
                            command.text, arg.text, self.place
                        )));
                    }
                    let flag = options && arg.text.starts_with('-') && arg.text.len() > 1;
                    options &= flag && arg.text != "--";
                    prompt |= flag && command.text == "print" && arg.text.contains('P');
                    if prompt && !flag {
                        let text = format!("print -P {}", arg.text);
                        self.prompt(&text, arg);
                    }
                    // `-v` names the parameter `print` and `printf` set.
                    target = command.text == "read" || arg.text == "-v";
                    self.mention(&arg.text);
                }
            }
            "return" | "exit" => self.may_stop = true,
            "fc" => self.fc(&args),
            "autoload" => {
                self.autoloads += 1;
                self.autoload(&command.text, &args);
            }
            "functions" | "typeset" | "declare" | "local"
                if marks_autoload(&command.text, &args) =>
            {
                self.autoload(&command.text, &args);
            }
            "export" | "typeset" | "declare" | "local" | "readonly" | "integer" | "float" => {
                for arg in &args {
                    if computed_target(&arg.text) {
                        self.events.push(Event::Doubt(format!(
                            "it cannot tell which parameter `{} {}` in {} sets",
                            command.text, arg.text, self.place
                        )));
                    }
                    self.assignment(arg, unconditional);
                }
            }
            _ => {
                self.mention(&command.text);
                for arg in &args {
                    self.mention(&arg.text);
                }
            }
        }
    }

    /// The events of `word` when it assigns `ZDOTDIR`, `XDG_CONFIG_HOME`,
    /// `fpath` or `FPATH`, and its mentions.
    pub(super) fn assignment(&mut self, word: &Word, unconditional: bool) {
        if self.fpath_assignment(word) {
            return;
        }
        if let Some((target, value)) = word.text.split_once('=') {
            let name = assigned(target);
            if matches!(name, "aliases" | "galiases" | "saliases") && target.contains('[') {
                // An alias, by the parameter that holds them.
                self.mention(&word.text);
                self.alias_value(&word.text, value, word, unconditional);
                return;
            }
            if PROMPTS.contains(&name) {
                let value = Word {
                    text: value.to_string(),
                    expands: word.expands,
                };
                self.prompt(&word.text, &value);
            }
        }
        let name = match word.text.split_once('=') {
            Some(("ZDOTDIR", _)) => "ZDOTDIR",
            Some(("XDG_CONFIG_HOME", _)) => "XDG_CONFIG_HOME",
            _ => {
                if word.text == "ZDOTDIR" {
                    // Exported or declared as it is.
                    self.zdotdirs += 1;
                }
                self.mention(&word.text);
                return;
            }
        };
        self.zdotdirs += zdotdir_writes(&word.text);
        self.mention_options(&word.text);
        let value = word.text[name.len() + 1..].to_string();
        self.events.push(Event::Assign {
            name,
            value: Word {
                text: value,
                expands: word.expands,
            },
            unconditional,
        });
    }

    /// The events of `word` when it sets `fpath` (`fpath+=dir`,
    /// `fpath[1,0]=dir`) or `FPATH`, whose directories a `:` parts, or
    /// declares one as it is (`typeset -U fpath`); whether it does.
    fn fpath_assignment(&mut self, word: &Word) -> bool {
        let (target, value) = match word.text.split_once('=') {
            Some((target, value)) => (target, Some(value)),
            None => (word.text.as_str(), None),
        };
        let name = assigned(target);
        if !matches!(name, "fpath" | "FPATH") {
            return false;
        }
        self.fpaths += 1;
        self.mention(&word.text);
        let parts: Vec<&str> = match value {
            Some(value) if name == "FPATH" => value.split(':').collect(),
            Some(value) => vec![value],
            None => Vec::new(),
        };
        let items: Vec<Word> = parts
            .into_iter()
            .filter(|part| !part.is_empty())
            .map(|part| Word {
                text: part.to_string(),
                expands: part.contains(['$', '`']),
            })
            .collect();
        // `fpath+=dir` appends; `fpath[1,0]=dir` and `fpath[1]=dir` put it
        // in front, and any other element is somewhere after the front.
        let subscript = target.split_once('[').map(|(_, key)| key);
        let append = target.ends_with('+')
            || subscript.is_some_and(|key| !(key.starts_with("1]") || key.starts_with("1,")));
        self.fpath_items(&items, append);
        true
    }
}
