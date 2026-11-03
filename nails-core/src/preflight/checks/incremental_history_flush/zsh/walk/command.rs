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
    self, FC_WRITES, history_path, is_fc_flag, qualifier_code, reexpands, zdotdir_writes,
};
use super::super::lexer::{Word, is_name};
use super::strings::PROMPTS;
use super::{Event, Frame, Walker, mentioned, walk_text_in};

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

/// The code of each command substitution in `text` as written, a word of
/// zsh code: what `$(...)`, a backquote pair or a process substitution
/// (`<(...)`, `>(...)`, `=(...)`) holds, past the quotes and parentheses in
/// it, to the end of `text` when it does not close. Arithmetic (`$((`) holds
/// none of its own.
fn substitutions(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut found = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        let opens = match chars[at] {
            '`' => Some(at + 1),
            '$' | '<' | '>' | '=' if chars.get(at + 1) == Some(&'(') => {
                (chars.get(at + 2) != Some(&'(')).then_some(at + 2)
            }
            _ => None,
        };
        let Some(start) = opens else {
            at += 1;
            continue;
        };
        let mut end = start;
        let mut depth = 0usize;
        let mut quote: Option<char> = None;
        while end < chars.len() {
            let c = chars[end];
            match (quote, c) {
                (_, '\\') => end += 1,
                (Some(open), c) if c == open => quote = None,
                (Some(_), _) => {}
                (None, '\'' | '"') => quote = Some(c),
                (None, '`') if chars[at] == '`' => break,
                (None, '(') if chars[at] != '`' => depth += 1,
                (None, ')') if chars[at] != '`' => {
                    if depth == 0 {
                        break;
                    }
                    depth -= 1;
                }
                _ => {}
            }
            end += 1;
        }
        let end = end.min(chars.len());
        found.push(chars[start..end].iter().collect());
        at = end + 1;
    }
    found
}

/// Where among `args`, the words after the builtin `command`, an expansion
/// makes the name of a parameter it sets: `getopts`'s second word, the
/// parameter `zstyle -s`, `-a`, `-b` or `-g` sets, a `strftime -s`'s, and any
/// word of `vared`, `zparseopts`, `sysread`, `zstat`, `zselect`,
/// `pcre_match`, `zregexparse` and `zsystem`, which take such names among
/// their options. `None` when none does.
fn names_parameter(command: &str, args: &[Word]) -> Option<usize> {
    let computed = |word: &Word| word.expands || word.text.contains(['$', '`']);
    match command {
        "getopts" => args.get(1).filter(|word| computed(word)).map(|_| 1),
        "zstyle" => {
            let flag = args.first()?.text.as_str();
            let at = match flag {
                "-s" | "-a" | "-b" => 3,
                "-g" => 1,
                _ => return None,
            };
            args.get(at).filter(|word| computed(word)).map(|_| at)
        }
        "strftime" => args
            .iter()
            .position(|word| word.text == "-s")
            .map(|at| at + 1)
            .filter(|&at| args.get(at).is_some_and(computed)),
        "vared" | "zparseopts" | "sysread" | "zstat" | "zselect" | "pcre_match" | "zregexparse"
        | "zsystem" => args.iter().position(computed),
        _ => None,
    }
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

    /// The events of the `fpath` assignment NixOS's `/etc/zshenv` makes in
    /// its loop over the profiles, `fpath=($p/share/zsh/site-functions
    /// $p/share/zsh/$ZSH_VERSION/functions $p/share/zsh/vendor-completions
    /// $fpath)`, when `items` are those and the loop is that one: each of
    /// the three directories under every profile, in front of the others
    /// ([`Event::ProfileFpath`]). Whether they are.
    pub(super) fn profiles_fpath(&mut self, items: &[Word]) -> bool {
        const RESTS: [&str; 3] = [
            "/share/zsh/site-functions",
            "/share/zsh/$ZSH_VERSION/functions",
            "/share/zsh/vendor-completions",
        ];
        let in_loop = self
            .frames
            .last()
            .is_some_and(|open| matches!(open.frame, Frame::Loop { profiles: true, .. }));
        let texts: Vec<&str> = items.iter().map(|item| item.text.as_str()).collect();
        let written: Vec<String> = RESTS.iter().map(|rest| format!("$p{rest}")).collect();
        let exact = texts.len() == 4
            && texts[..3]
                .iter()
                .zip(&written)
                .all(|(text, written)| text == written)
            && texts[3] == "$fpath"
            && items[..3].iter().all(|item| item.expands);
        if !in_loop || !exact || !self.pending.words.is_empty() {
            return false;
        }
        for (rest, written) in RESTS.iter().zip(written) {
            self.events.push(Event::ProfileFpath {
                written,
                rest: (*rest).to_string(),
                first: true,
            });
        }
        true
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
        // Without `-U` zsh expands aliases in the function's code as it
        // loads it.
        let unaliased = args
            .iter()
            .any(|arg| !arg.expands && arg.text.starts_with('-') && arg.text.contains('U'));
        if !unaliased {
            self.events.extend(
                names
                    .iter()
                    .filter(|name| !name.expands)
                    .map(|name| Event::Expanding(name.text.clone())),
            );
        }
        self.events.extend(names.into_iter().map(Event::Autoload));
    }

    /// The events of zsh code `text` that a command of the file runs, read as
    /// the file's own: an `eval`'s words, an `emulate -c`'s code. What it
    /// sets counts as unconditional only when the command is and the walk
    /// followed the code's structure.
    pub(super) fn nested(&mut self, text: &str, unconditional: bool) {
        let outer = self.function();
        self.nested_in(text, unconditional, outer);
    }

    /// The events of zsh code `text` that a command of the file runs as the
    /// function `outer` would, when in one ([`Walker::nested`]): a trap's
    /// code runs as a `TRAP...` function does.
    pub(super) fn nested_in(&mut self, text: &str, unconditional: bool, outer: Option<String>) {
        let nested = walk_text_in(text, self.place, outer);
        self.sources += nested.sources;
        self.evals += nested.evals;
        self.zdotdirs += nested.zdotdirs;
        self.autoloads += nested.autoloads;
        self.fpaths += nested.fpaths;
        self.fcs += nested.fcs;
        self.nix_profiles += nested.nix_profiles;
        self.indirects += nested.indirects;
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
        // `-R` resets every option to the mode's defaults, and ksh's turns
        // SHARE_HISTORY on (zsh 5.9.1: `emulate -R ksh`, not `emulate ksh`).
        let mut reset = false;
        let mut mode = None;
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            if arg.expands {
                self.events.push(doubt(&arg.text));
                continue;
            }
            if mode.is_none() {
                if let Some(flags) = arg.text.strip_prefix('-')
                    && !flags.is_empty()
                    && flags.chars().all(|c| c.is_ascii_alphabetic())
                    && !matches!(flags, "o" | "c")
                {
                    reset |= flags.contains('R');
                    continue;
                }
                if !arg.text.starts_with(['-', '+']) {
                    mode = Some(arg.text.clone());
                }
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
        if reset && mode.as_deref() == Some("ksh") {
            self.events.push(Event::Turns {
                option: 1,
                what: format!(
                    "{} runs `emulate -R ksh`, whose reset to ksh's defaults turns on",
                    self.place
                ),
            });
        }
    }

    /// The events of an `add-zsh-hook` or a `zle -N` of `args`: the function
    /// it makes a hook, which zsh runs as commands are entered or end, or as
    /// a key is pressed ([`Event::Hook`]); one an expansion names is a doubt.
    pub(super) fn hook(&mut self, command: &str, args: &[Word]) {
        for arg in args {
            self.mention(&arg.text);
        }
        let words: Vec<&Word> = args
            .iter()
            .filter(|arg| !arg.text.starts_with('-'))
            .collect();
        let function = match command {
            // `add-zsh-hook hook function`, `add-zle-hook-widget hook widget`.
            "add-zsh-hook" | "add-zle-hook-widget" => words.get(1),
            // `zle -N widget [function]`.
            _ if args.first().is_some_and(|flag| flag.text == "-N") => {
                words.get(1).or(words.first())
            }
            _ => None,
        };
        match function {
            Some(function) if function.expands => self.events.push(Event::Doubt(format!(
                "it cannot tell which function `{command} ... {}` in {} makes a hook",
                function.text, self.place
            ))),
            Some(function) => {
                self.events.push(Event::Hook(function.text.clone()));
                // `add-zsh-hook` and `add-zle-hook-widget` autoload the
                // function they add, which zsh then loads from `fpath`
                // unless the files define it.
                let adds = !args
                    .iter()
                    .any(|arg| arg.text.starts_with('-') && arg.text.contains(['d', 'D', 'L']));
                if command != "zle" && adds {
                    self.events.push(Event::Autoload((*function).clone()));
                }
            }
            None => {}
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

    /// The commands that the command substitutions in `text`, a word of the
    /// file's code or a here-document's body, run by name ([`Event::Call`]):
    /// in a subshell, but a function they run there can write the history
    /// file all the same.
    pub(super) fn substituted(&mut self, text: &str) {
        for code in substitutions(text) {
            let nested = walk_text_in(&code, self.place, self.function());
            self.events.extend(
                nested
                    .events
                    .into_iter()
                    .filter(|event| matches!(event, Event::Call { .. })),
            );
        }
    }

    /// Note a doubt for each assignment in `text`, a word of the file's
    /// code, to a parameter whose name another one holds
    /// ([`backstop::indirect_assignments`]): it can set any parameter.
    pub(super) fn indirect(&mut self, text: &str) {
        let found = backstop::indirect_assignments(text);
        if found > 0 {
            self.indirects += found;
            self.events.push(Event::Doubt(format!(
                "it cannot tell which parameter `{text}` in {} sets",
                self.place
            )));
        }
    }

    /// Note what an arithmetic command, `text`, names: its options, and a
    /// `ZDOTDIR` it may set ([`Walker::mention`]); no glob is expanded in
    /// it, and what `${+name}` tests sets nothing.
    pub(super) fn mention_arithmetic(&mut self, text: &str) {
        self.mention_options(text);
        self.reexpansion(text);
        self.indirect(text);
        self.substituted(text);
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
        if !words.is_empty() {
            self.counted();
        }
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
        let function = self.function();
        for arg in &args {
            self.qualifier(&arg.text);
            // A command in a function that names the history file may write
            // it, as `tee -a ~/.zsh_history` does, should the function be a
            // hook; the words of a `setopt` name options, no file.
            if let Some(function) = &function
                && history_path(&arg.text)
                && !matches!(command.text.as_str(), "setopt" | "unsetopt")
            {
                self.events.push(Event::Names {
                    word: arg.text.clone(),
                    function: function.clone(),
                });
            }
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
        if let Some(at) = names_parameter(&command.text, &args) {
            self.events.push(Event::Doubt(format!(
                "it cannot tell which parameter `{} {}` in {} sets",
                command.text, args[at].text, self.place
            )));
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
                // The values `-A` assigns an array, and the positional
                // parameters after `--`, set no option.
                let mut values = false;
                while let Some(arg) = args.next() {
                    if arg.expands && !values {
                        self.events.push(Event::Doubt(format!(
                            "it cannot tell which options `set {}` in {} turns on",
                            arg.text, self.place
                        )));
                    }
                    values |= matches!(arg.text.as_str(), "--" | "-A" | "+A");
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
            "add-zsh-hook" | "add-zle-hook-widget" | "zle" => self.hook(&command.text, &args),
            "trap" => self.trap(&args, unconditional),
            "sched" => self.sched(&args, unconditional),
            "zstyle" => self.zstyle(&args, unconditional),
            "print" | "printf" | "read" => self.print(&command.text, &args),
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
                if !command.expands {
                    self.events.push(Event::Call {
                        name: command.text.clone(),
                        args: args.clone(),
                        function: function.clone(),
                    });
                }
            }
        }
    }

    /// The events of a `print`, `printf` or `read` (`command`) of `args`:
    /// the parameter `read` and `-v` set, when an expansion makes its name, is
    /// a doubt, and what `print -P` expands as a prompt counts as a prompt.
    fn print(&mut self, command: &str, args: &[Word]) {
        let mut target = command == "read";
        // `print -P` expands its words as a prompt.
        let mut prompt = false;
        let mut options = true;
        for arg in args {
            if target && arg.expands && computed_target(&arg.text) {
                self.events.push(Event::Doubt(format!(
                    "it cannot tell which parameter `{command} {}` in {} sets",
                    arg.text, self.place
                )));
            }
            let flag = options && arg.text.starts_with('-') && arg.text.len() > 1;
            options &= flag && arg.text != "--";
            prompt |= flag && command == "print" && arg.text.contains('P');
            if prompt && !flag {
                let text = format!("print -P {}", arg.text);
                self.prompt(&text, arg);
            }
            // `-v` names the parameter `print` and `printf` set.
            target = command == "read" || arg.text == "-v";
            self.mention(&arg.text);
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
                let regular = name == "aliases";
                self.alias_value(&word.text, value, word, unconditional, regular);
                return;
            }
            if matches!(name, "functions" | "dis_functions") && target.contains('[') {
                // A function, by the parameter that holds them, whose body
                // is the value.
                self.mention(&word.text);
                self.function_value(target, value, word);
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
            Some(("NIX_PROFILES", _)) => {
                self.nix_profiles += 1;
                "NIX_PROFILES"
            }
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

    /// The events of the body `value` that the word `word` gives the
    /// function its `target` names (`functions[precmd]=...`), read as that
    /// function's body where the walk can read it whole; with an expansion,
    /// or for a name an expansion makes, a doubt.
    fn function_value(&mut self, target: &str, value: &str, word: &Word) {
        let name = target
            .split_once('[')
            .and_then(|(_, key)| key.strip_suffix(']'))
            .filter(|name| is_name(&name.replace(['-', '.', ':'], "_")));
        match name {
            // Its `$` stands in the body, as in any function's, unless the
            // word expands it as it assigns it.
            Some(name) if !word.expands => {
                let code = format!("{name}() {{\n{value}\n}}");
                self.nested(&code, false);
            }
            _ => self.events.push(Event::Doubt(format!(
                "it cannot tell what code `{}` in {} gives a function",
                word.text, self.place
            ))),
        }
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
