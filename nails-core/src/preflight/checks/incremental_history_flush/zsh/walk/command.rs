// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What one simple command of a startup file does, as the walk reads it, past
//! its precommands and their options: the options a `setopt`, `unsetopt` or
//! `set -o` turns on or off ([`super::options`]), the files a `source` or `.`
//! reads, what an `eval` of words the walk can read runs, the
//! `ZDOTDIR` and `XDG_CONFIG_HOME` an assignment sets, the directories one
//! adds to `fpath`, the functions an `autoload` or the like marks
//! ([`super::autoload`]), and the options any other word names.

use super::super::OH_MY_ZSH;
use super::super::arith::READ_AS_NUMBER;
use super::super::backstop::{
    self, FC_WRITES, history_path, qualifier_code, reexpands, xdg_config_home_writes,
    zdotdir_writes,
};
use super::super::builtins::fc_letters;
use super::super::lexer::{Word, is_name};
use super::hooks::hook_array;
use super::names::{names_parameter, targets};
use super::strings::PROMPTS;
use super::{Event, Frame, Input, Walker, mentioned, walk_text_in};

/// The parameters that hold the aliases zsh expands, or disabled ones that
/// `enable -a` makes it expand (zsh/parameter).
pub(super) const ALIAS_PARAMETERS: &[&str] = &[
    "aliases",
    "galiases",
    "saliases",
    "dis_aliases",
    "dis_galiases",
    "dis_saliases",
];

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

/// How the command after its precommands runs ([`Walker::precommands`]).
#[derive(Debug, Default)]
struct Run {
    /// In the shell's place (`exec`).
    exec: bool,
}

/// Whether zsh can expand `value`, an assignment's value as written, with
/// no error that stops the file it is in: it names no parameter but `HOME`
/// and those `${...:-...}` gives a default for (`${XDG_CONFIG_HOME:-...}`),
/// which the check resolves, and runs no command.
fn cannot_fail(value: &str) -> bool {
    let mut rest = value.to_string();
    for safe in [
        "${XDG_CONFIG_HOME:-$HOME/.config}",
        "${XDG_CONFIG_HOME:-${HOME}/.config}",
        "${XDG_CONFIG_HOME:-~/.config}",
        "${ZDOTDIR:-$HOME}",
        "${ZDOTDIR:-${HOME}}",
        "${ZDOTDIR:-~}",
        "${HOME}",
        "$HOME",
    ] {
        rest = rest.replace(safe, "");
    }
    !rest.contains(['$', '`'])
}

/// Whether `text` assigns a variable (`name=...`, `name+=...`,
/// `name[key]=...`), not a word with an `=` in it (`${=c}`, `$=c`).
pub(super) fn is_assignment(text: &str) -> bool {
    text.split_once('=')
        .is_some_and(|(target, _)| is_name(assigned(target)))
}

/// The name of the variable that the target of an assignment, `target`,
/// sets (`name`, `name+`, `name[key]`).
pub(super) fn assigned(target: &str) -> &str {
    let name = target.strip_suffix('+').unwrap_or(target);
    name.split_once('[').map_or(name, |(name, _)| name)
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

/// The code of each command substitution in `text` as written, a word of
/// zsh code: what `$(...)`, a backquote pair or a process substitution
/// (`<(...)`, `>(...)`, `=(...)`) holds, past the quotes and parentheses in
/// it, to the end of `text` when it does not close. Arithmetic (`$((`) holds
/// none of its own, and neither do single quotes or `$'...'` in a `${...}`,
/// which the lexer keeps as written (`${PS1::='$(x)'}`); elsewhere it took
/// the quotes off.
fn substitutions(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut found = Vec::new();
    let mut at = 0;
    // How deep in `${...}` the scan is, and the quote it is in there: `'`,
    // `"`, or `$` for `$'...'`, in which a backslash keeps a `'` too.
    let mut braces = 0usize;
    let mut quote: Option<char> = None;
    while at < chars.len() {
        let next = chars.get(at + 1).copied();
        if braces > 0 {
            let skip = match (quote, chars[at]) {
                (Some('\'' | '$'), '\'') | (Some('"'), '"') => {
                    quote = None;
                    1
                }
                (Some('$'), '\\') | (Some('"') | None, '\\') => 2,
                (Some('\'' | '$'), _) => 1,
                (None, '$') if next == Some('\'') => {
                    quote = Some('$');
                    2
                }
                (None, '\'' | '"') => {
                    quote = Some(chars[at]);
                    1
                }
                (None, '}') => {
                    braces -= 1;
                    1
                }
                _ => 0,
            };
            if skip > 0 {
                at += skip;
                continue;
            }
        }
        if chars[at] == '$' && next == Some('{') && quote.is_none() {
            braces += 1;
            at += 2;
            continue;
        }
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

    /// The events of zsh code `text` that a command of the file runs, read as
    /// the file's own: an `eval`'s words, an `emulate -c`'s code. What it
    /// sets counts as unconditional only when the command is and the walk
    /// followed the code's structure.
    pub(super) fn nested(&mut self, text: &str, unconditional: bool) {
        let outer = self.function();
        let top = self.top && !self.frames.iter().any(|open| open.frame == Frame::Function);
        self.nested_in(text, unconditional, outer, top);
    }

    /// The events of zsh code `text` that a command of the file runs as the
    /// function `outer` would, when in one ([`Walker::nested`]), where zsh is
    /// at its top level as it runs it (`top`): a trap's code runs as a
    /// `TRAP...` function does. What code that runs as a function sets, which
    /// it may do later or in its own scope, is no certain setting where it
    /// stands, and no setting comes first in the file after a command that
    /// ran ([`Event::Assign`]).
    pub(super) fn nested_in(
        &mut self,
        text: &str,
        unconditional: bool,
        outer: Option<String>,
        top: bool,
    ) {
        let later = outer.is_some();
        let nested = walk_text_in(text, self.place, outer, top);
        self.sources += nested.sources;
        self.evals += nested.evals;
        self.zdotdirs += nested.zdotdirs;
        self.xdg_config_homes += nested.xdg_config_homes;
        self.autoloads += nested.autoloads;
        self.fpaths += nested.fpaths;
        self.fcs += nested.fcs;
        self.nix_profiles += nested.nix_profiles;
        self.indirects += nested.indirects;
        self.alias_params += nested.alias_params;
        self.function_params += nested.function_params;
        self.tmouts += nested.tmouts;
        self.may_stop |= nested.may_stop;
        let uncertain = !unconditional || nested.confused || later;
        for mut event in nested.events {
            if uncertain
                && let Event::Set { unconditional, .. }
                | Event::Source { unconditional, .. }
                | Event::Assign { unconditional, .. } = &mut event
            {
                *unconditional = false;
            }
            if (self.ran || later)
                && let Event::Assign { first, .. } = &mut event
            {
                *first = false;
            }
            self.events.push(event);
        }
        self.ran |= nested.ran;
    }

    /// The events of an `fc` or a `history` (`command`, which takes the
    /// flags of `fc -l`) of `args`, its options read as zsh reads them
    /// ([`fc_letters`]). One that writes the history file, by a flag
    /// ([`FC_WRITES`]: `fc -AI`, `fc -W`, `history -p -a`, `fc -t %F -AI`),
    /// does so whenever it runs, as it does after every command from a hook
    /// (`precmd`, `preexec`, `zshaddhistory`, `TRAPDEBUG`), the way bash's
    /// `history -a` does from `PROMPT_COMMAND`. One whose options or their
    /// arguments hold an expansion, or a word brace expansion or a glob may
    /// make other words of (`fc {-AI,-AI}`), which may be such a flag, is a
    /// doubt.
    pub(super) fn fc(&mut self, command: &str, args: &[Word]) {
        let words = args
            .iter()
            .map(|arg| (arg.text.as_str(), arg.expands || arg.bare));
        match fc_letters(command, words) {
            None => {
                self.fcs += 1;
                let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
                self.events.push(Event::Doubt(format!(
                    "it cannot tell whether `{command} {}` in {} writes the history file",
                    words.join(" "),
                    self.place
                )));
            }
            Some((letters, taken)) if letters.contains(FC_WRITES) => {
                self.fcs += 1;
                let flags: Vec<&str> = args[..taken].iter().map(|arg| arg.text.as_str()).collect();
                self.events
                    .push(Event::Fc(format!("{command} {}", flags.join(" "))));
            }
            Some(_) => {}
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
        if text.contains("${") {
            // `${mapfile[file]::=...}`.
            self.mapfile(text);
        }
        if computed_options(text) {
            self.events.push(Event::Doubt(format!(
                "it cannot tell which options `{text}` in {} sets",
                self.place
            )));
        }
        self.mention_arithmetic(text);
    }

    /// What the command substitutions in `text`, a word of the file's code
    /// or a here-document's body, write and run: in a subshell, whose
    /// settings zsh drops, but a write there writes a file all the same (an
    /// `fc`, a redirection, one to a descriptor the shell has open, a word
    /// that names the history file in a function), a function they run there
    /// can write the history file, and a signal reaches the shell's process
    /// ([`Event::Ends`]). In a word zsh expands nothing in (`'$(x)'`,
    /// [`Walker::mention_word`]), only the commands, as before: it is text.
    pub(super) fn substituted(&mut self, text: &str) {
        for code in substitutions(text) {
            let nested = walk_text_in(&code, self.place, self.function(), false);
            let literal = self.literal;
            self.events
                .extend(nested.events.into_iter().filter(|event| match event {
                    Event::Call { .. } => true,
                    Event::Redirect { .. }
                    | Event::Fc(_)
                    | Event::HookDoubt { .. }
                    | Event::Names { .. }
                    | Event::Ends { signal: true, .. } => !literal,
                    _ => false,
                }));
        }
    }

    /// Note what `word`, a word of the file's code, names
    /// ([`Walker::mention`]), where a command substitution in one zsh
    /// expands nothing in (`'$(x)'`) is text ([`Walker::substituted`]).
    pub(super) fn mention_word(&mut self, word: &Word) {
        let was = std::mem::replace(&mut self.literal, !word.expands);
        self.mention(&word.text);
        self.literal = was;
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

    /// Read the precommands that start `words`, a command's words past its
    /// assignments, and their options, as zsh does (Src/exec.c): `command`'s
    /// `-p`, `-v` and `-V`, and a `--` after them, where a word with any other
    /// letter is the command, and `exec`'s `-c`, `-l` and `-a`, which takes
    /// the rest of its word or the next word, up to a `--`. zsh expands an
    /// alias named like a precommand that is no builtin in its place (`alias
    /// -- -=...`), as the code of a function of that name the command runs.
    /// `None` when zsh runs no command: a `command -v` or `-V`, which prints
    /// what its words are, and an `exec` with a flag it does not know; else
    /// how the command runs ([`Run`]).
    fn precommands(
        &mut self,
        words: &mut std::iter::Peekable<std::vec::IntoIter<Word>>,
    ) -> Option<Run> {
        let plain = |word: &Word| !word.expands && !word.bare && word.text.len() > 1;
        let mut run = Run::default();
        while let Some(word) = words.next_if(|word| PRECOMMANDS.contains(&word.text.as_str())) {
            match word.text.as_str() {
                "-" | "nocorrect" | "time" | "!" => self.events.push(Event::Call {
                    name: word.text,
                    args: Vec::new(),
                    function: self.function(),
                    input: Input::None,
                }),
                "command" => {
                    let mut whence = false;
                    while let Some(flags) = words.next_if(|word| {
                        plain(word)
                            && word.text.strip_prefix('-').is_some_and(|flags| {
                                flags.chars().all(|c| matches!(c, 'p' | 'v' | 'V'))
                            })
                    }) {
                        whence |= flags.text.contains(['v', 'V']);
                    }
                    if whence {
                        return None;
                    }
                    words.next_if(|word| word.text == "--");
                }
                "exec" => {
                    run.exec = true;
                    while let Some(flags) =
                        words.next_if(|word| plain(word) && word.text.starts_with('-'))
                    {
                        if flags.text == "--" {
                            break;
                        }
                        let letters = &flags.text[1..];
                        let (before, argv0) = letters
                            .split_once('a')
                            .map_or((letters, None), |(before, rest)| (before, Some(rest)));
                        if !before.chars().all(|c| matches!(c, 'c' | 'l')) {
                            return None;
                        }
                        if argv0 == Some("") {
                            words.next();
                        }
                    }
                }
                _ => {}
            }
        }
        Some(run)
    }

    /// The events of one simple command, `words`, which ran `after` a
    /// condition (`&&`, `||`) or not, in a pipeline or the background or
    /// not, and reads `input`.
    pub(super) fn command(
        &mut self,
        words: Vec<Word>,
        after_condition: bool,
        piped: bool,
        mut input: Input,
    ) {
        let unconditional = self.certain(after_condition, piped);
        if !words.is_empty() {
            self.counted();
        }
        let mut words = words.into_iter().peekable();
        // Assignments before the command word, which put what they assign in
        // its environment. zsh keeps what they set only for that command
        // (and after a special builtin where POSIX_BUILTINS is on), so with a
        // command after them they may set a parameter, and need not.
        let mut assignments = Vec::new();
        while let Some(word) = words.next_if(|word| is_assignment(&word.text)) {
            if word.expands {
                input = Input::Computed;
            }
            assignments.push(word);
        }
        let lasting = unconditional && words.peek().is_none();
        for word in &assignments {
            self.assignment(word, lasting);
        }
        let Some(run) = self.precommands(&mut words) else {
            // `command -v`, which prints what its words are.
            for word in words {
                self.mention_word(&word);
            }
            return;
        };
        let Some(command) = words.next() else {
            self.computed_assignments(&assignments);
            return;
        };
        let args: Vec<Word> = words.collect();
        self.ends(&command.text, &args, run.exec);
        self.qualifier(&command.text);
        let function = self.function();
        self.words(&command, &args, function.as_ref());
        if (command.expands || command.bare) && !matches!(command.text.as_str(), "[[" | "[") {
            // `$c`, `${:-source}`, `$(print source)`, `ali$s`, `{-p,alias}`:
            // any command, a `source` or an `alias -g` among them.
            self.events.push(Event::Doubt(format!(
                "it cannot tell what command `{}` in {} runs",
                command.text, self.place
            )));
            for arg in &args {
                self.mention_word(arg);
            }
            return;
        }
        if command.text == "functions"
            && let Some(word) = args.iter().find(|arg| arg.bare)
        {
            // `functions {-c,logger} preexec`.
            self.events.push(Event::Doubt(format!(
                "it cannot tell what `functions` in {} does with `{}`, which zsh may expand \
                 into its flags or into names",
                self.place, word.text
            )));
        }
        self.parameters(&command, &args);
        self.command_arithmetic(&command.text, &args);
        self.tested(&command.text, &args);
        self.computed_sets(&command.text, &args);
        // `functions` as a command prints, copies or marks functions.
        self.function_params += usize::from(command.text == "functions");
        match command.text.as_str() {
            "setopt" | "unsetopt" => self.setopt(&command.text, &args, unconditional),
            "set" => self.set_builtin(&args, unconditional),
            "source" | "." => self.source(&command.text, args, unconditional, function),
            "eval" if args.iter().all(|arg| !arg.expands && !arg.bare) => {
                // Its words are code the walk reads as zsh would run them,
                // past the `--` that may end its options.
                let skip = usize::from(args.first().is_some_and(|arg| arg.text == "--"));
                let text: Vec<&str> = args[skip..].iter().map(|arg| arg.text.as_str()).collect();
                self.evals += 1;
                self.nested(&text.join(" "), unconditional);
            }
            "coproc" => {
                let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
                self.events.push(Event::Doubt(format!(
                    "it cannot tell what the coprocess that `coproc {}` in {} starts writes, which \
                     a hook may feed each command line",
                    words.join(" "),
                    self.place
                )));
            }
            "functions"
                if args
                    .iter()
                    .any(|arg| arg.text.starts_with('-') && arg.text.contains('c')) =>
            {
                self.copy_function(&args);
            }
            "bindkey" => self.bindkey(&args, unconditional),
            "unset" => self.unset(&args, unconditional),
            "emulate" => self.emulate(&args, unconditional),
            "alias" => self.alias(&args, unconditional),
            "add-zsh-hook" | "add-zle-hook-widget" => self.hook(&command.text, &args),
            "zle" => self.zle(&args),
            "trap" => self.trap(&args, unconditional),
            "sched" => self.sched(&args, unconditional),
            "zstyle" => self.zstyle(&args, unconditional),
            "print" => {
                self.print_descriptor(&args);
                self.print_line(&args);
                self.print(&args);
            }
            "return" | "exit" | "bye" | "logout" => self.may_stop = true,
            // `history` takes the flags of `fc`, as `fc -l` does.
            "fc" | "history" => self.fc(&command.text, &args),
            "sysopen" => self.sysopen(&args),
            "zsystem" => self.zsystem(&args),
            "zsocket" | "ztcp" => self.connection(&command.text, &args),
            "autoload" => {
                self.autoloads += 1;
                self.autoload(&command.text, &args);
            }
            // `functions -u`, `typeset -fu` and the like mark functions to be
            // autoloaded ([`super::autoload`]); the others declare parameters
            // or print functions.
            "functions" | "typeset" | "declare" | "readonly"
                if self.marked(&command.text, &args) => {}
            "export" | "typeset" | "declare" | "local" | "readonly" | "integer" | "float"
            | "private" => {
                self.declared(&command.text, &args);
                self.declare(&command.text, &args, unconditional);
            }
            _ => {
                self.mention_word(&command);
                for arg in &args {
                    self.mention_word(arg);
                }
                if !command.expands {
                    self.events.push(Event::Call {
                        name: command.text.clone(),
                        args: args.clone(),
                        function: function.clone(),
                        input,
                    });
                }
            }
        }
    }

    /// Note what the words `args` of `command`, in the function `function`
    /// when in one, name: code a glob qualifier runs, the elements of
    /// `mapfile` they set, and, in a function, the history file, which a
    /// command that writes it by its name (`tee -a ~/.zsh_history`) writes
    /// should the function be a hook; the words of a `setopt` name options,
    /// no file.
    fn words(&mut self, command: &Word, args: &[Word], function: Option<&String>) {
        for arg in args {
            self.qualifier(&arg.text);
            self.mapfile(&arg.text);
            if let Some(function) = function
                && history_path(&arg.text)
                && !matches!(command.text.as_str(), "setopt" | "unsetopt")
            {
                self.events.push(Event::Names {
                    word: arg.text.clone(),
                    function: function.clone(),
                });
            }
        }
    }

    /// Note the parameters `command` sets by a name among `args`: a doubt
    /// when an expansion makes the name ([`names_parameter`]), and a prompt,
    /// an array of hook functions, an alias or a function set to a value the
    /// check cannot read ([`targets`]).
    fn parameters(&mut self, command: &Word, args: &[Word]) {
        if let Some(word) = names_parameter(&command.text, args) {
            self.events.push(Event::Doubt(format!(
                "it cannot tell which parameter `{} {}` in {} sets",
                command.text, word.text, self.place
            )));
        }
        // A prompt, an array of hook functions, an alias or a function that
        // a builtin sets by its name, to a value the check cannot read.
        for target in targets(&command.text, args) {
            let name = assigned(&target.text);
            if ALIAS_PARAMETERS.contains(&name) {
                self.alias_params += 1;
                self.events.push(Event::Doubt(format!(
                    "it cannot tell what alias `{} {}` in {} gives, which zsh then expands",
                    command.text, target.text, self.place
                )));
            }
            if matches!(name, "functions" | "dis_functions") {
                self.function_params += 1;
                self.events.push(Event::Doubt(format!(
                    "it cannot tell what code `{} {}` in {} gives a function",
                    command.text, target.text, self.place
                )));
            }
            if PROMPTS.contains(&target.text.as_str()) {
                self.events.push(Event::Prompt(format!(
                    "it cannot follow the code that `{} {}` in {} gives the prompt, which zsh \
                     runs as it shows it, as PROMPT_SUBST may be on",
                    command.text, target.text, self.place
                )));
            }
            if hook_array(&target.text) {
                self.events.push(Event::Doubt(format!(
                    "it cannot tell which functions `{} {}` in {} makes hooks",
                    command.text, target.text, self.place
                )));
            }
        }
    }

    /// The events of a `source` or a `.` (`command`) of `args`, in the
    /// function `function` when in one.
    fn source(
        &mut self,
        command: &str,
        args: Vec<Word>,
        unconditional: bool,
        function: Option<String>,
    ) {
        self.sources += 1;
        let mut args = args.into_iter();
        match args.next() {
            Some(path) if path.text.ends_with(OH_MY_ZSH) => {
                self.events.push(Event::OhMyZsh);
            }
            Some(path) => {
                self.mention_word(&path);
                self.events.push(Event::Source {
                    path,
                    unconditional,
                    function,
                });
            }
            None => self.events.push(Event::Doubt(format!(
                "it cannot tell what `{command}` in {} reads",
                self.place
            ))),
        }
        for arg in args {
            self.mention_word(&arg);
        }
    }

    /// The events of a `print` of `args`: what `print -P` expands as a
    /// prompt counts as a prompt. The parameter `-v` sets is a target
    /// ([`targets`]).
    fn print(&mut self, args: &[Word]) {
        // `print -P` expands its words as a prompt.
        let mut prompt = false;
        let mut options = true;
        for arg in args {
            let flag = options && arg.text.starts_with('-') && arg.text.len() > 1;
            options &= flag && arg.text != "--";
            prompt |= flag && arg.text.contains('P');
            if prompt && !flag {
                let text = format!("print -P {}", arg.text);
                self.prompt(&text, arg);
            }
            self.mention_word(arg);
        }
    }

    /// The events of `word` when it assigns `ZDOTDIR`, `XDG_CONFIG_HOME`,
    /// `fpath` or `FPATH`, and its mentions.
    pub(super) fn assignment(&mut self, word: &Word, unconditional: bool) {
        self.assignment_arithmetic(word);
        // Its value, which zsh reads as arithmetic each time it uses it, the
        // walk judges ([`Event::Arith`]); declared without one, it keeps its
        // value.
        let target = word
            .text
            .split_once('=')
            .map_or(word.text.as_str(), |(target, _)| target);
        if READ_AS_NUMBER.contains(&assigned(target)) && !target.contains('[') {
            self.numbers += 1;
        }
        if assigned(target) == "TMOUT" {
            self.tmout(word);
        }
        if self.fpath_assignment(word) {
            return;
        }
        self.mapfile(&word.text);
        if let Some((target, value)) = word.text.split_once('=') {
            let name = assigned(target);
            if hook_array(name) {
                // `precmd_functions[1]=name`, `precmd_functions+=name`.
                self.hooks += 1;
                let value = Word {
                    text: value.to_string(),
                    expands: word.expands,
                    quoted: false,
                    bare: word.bare,
                };
                self.hook_value(&value);
            }
            if ALIAS_PARAMETERS.contains(&name) {
                // An alias, by the parameter that holds them: one added to
                // (`aliases[h]+=c`), or disabled, the check cannot read.
                self.alias_params += 1;
                self.mention_word(word);
                if target.contains('[') && !target.ends_with('+') && !name.starts_with("dis_") {
                    let kind = (name == "aliases", name == "galiases");
                    self.alias_value(&word.text, value, word, unconditional, kind);
                } else {
                    self.events.push(Event::Doubt(format!(
                        "it cannot tell what alias `{}` in {} gives, which zsh then expands",
                        word.text, self.place
                    )));
                }
                return;
            }
            if matches!(name, "functions" | "dis_functions") {
                // A function, by the parameter that holds them, whose body
                // is the value.
                self.function_params += 1;
                self.mention_word(word);
                self.function_value(target, value, word);
                return;
            }
            if PROMPTS.contains(&name) {
                self.prompts += 1;
                let value = Word {
                    text: value.to_string(),
                    expands: word.expands,
                    quoted: false,
                    bare: word.bare,
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
                // Exported or declared as it is.
                match word.text.as_str() {
                    "ZDOTDIR" => self.zdotdirs += 1,
                    "XDG_CONFIG_HOME" => self.xdg_config_homes += 1,
                    _ => {}
                }
                self.mention_word(word);
                return;
            }
        };
        self.zdotdirs += zdotdir_writes(&word.text);
        self.xdg_config_homes += xdg_config_home_writes(&word.text);
        self.mention_options(&word.text);
        let value = word.text[name.len() + 1..].to_string();
        let first = !self.ran && cannot_fail(&value);
        self.events.push(Event::Assign {
            name,
            value: Some(Word {
                text: value,
                expands: word.expands,
                quoted: false,
                bare: word.bare,
            }),
            unconditional,
            first,
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

    /// Note each element of `mapfile` that `text`, a word of the file's code,
    /// sets, which writes the file its key names (zsh/mapfile), as a
    /// redirection to it ([`Event::Redirect`]).
    fn mapfile(&mut self, text: &str) {
        for key in backstop::set_elements(text, "mapfile") {
            self.events.push(Event::Redirect {
                computed: key.contains(['$', '`']),
                function: self.function(),
                target: key,
                kept: false,
            });
        }
    }
}
