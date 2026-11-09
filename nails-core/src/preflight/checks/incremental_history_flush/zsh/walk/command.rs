// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What one simple command of a startup file does, as the walk reads it, past
//! its precommands and their options: the options a `setopt`, `unsetopt` or
//! `set -o` turns on or off ([`super::options`]), the files a `source` or `.`
//! reads, what an `eval` of words the walk can read runs, the
//! `ZDOTDIR` and `XDG_CONFIG_HOME` an assignment sets, the directories one
//! adds to `fpath`, the functions an `autoload` marks, and the options any
//! other word names.

use super::super::OH_MY_ZSH;
use super::super::arith::READ_AS_NUMBER;
use super::super::backstop::{
    self, FC_WRITES, history_path, is_fc_flag, qualifier_code, reexpands, zdotdir_writes,
};
use super::super::lexer::{Word, is_name};
use super::hooks::hook_array;
use super::names::{computed, names_parameter, targets};
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
        // With `-d`, zsh looks for a function it cannot find at the path
        // given in fpath, by its name.
        if flags.contains('d') {
            let bases: Vec<Word> = names
                .iter()
                .filter_map(|name| {
                    let (_, base) = name.text.rsplit_once('/')?;
                    Some(Word {
                        text: base.to_string(),
                        expands: name.expands,
                        quoted: false,
                        bare: name.bare,
                    })
                })
                .collect();
            names.extend(bases);
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
        self.alias_params += nested.alias_params;
        self.function_params += nested.function_params;
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

    /// The events of an `fc` or a `history` (`command`, which takes the
    /// flags of `fc -l`) of `args`. One that writes the history file, by a
    /// flag ([`FC_WRITES`]: `fc -AI`, `fc -W`, `history -p -a`), does so
    /// whenever it runs, as it does after every command from a hook
    /// (`precmd`, `preexec`, `zshaddhistory`, `TRAPDEBUG`), the way bash's
    /// `history -a` does from `PROMPT_COMMAND`. One whose flags hold an
    /// expansion, or a word brace expansion or a glob may make other words
    /// of (`fc {-AI,-AI}`), which may be such a flag, is a doubt.
    pub(super) fn fc(&mut self, command: &str, args: &[Word]) {
        let mut flags = Vec::new();
        for arg in args {
            if arg.expands || arg.bare {
                self.fcs += 1;
                let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
                self.events.push(Event::Doubt(format!(
                    "it cannot tell whether `{command} {}` in {} writes the history file",
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
                .push(Event::Fc(format!("{command} {}", flags.join(" "))));
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

    /// Read the precommands that start `words`, a command's words past its
    /// assignments, and their options, as zsh does (Src/exec.c): `command`'s
    /// `-p`, `-v` and `-V`, and a `--` after them, where a word with any other
    /// letter is the command, and `exec`'s `-c`, `-l` and `-a`, which takes
    /// the rest of its word or the next word, up to a `--`. zsh expands an
    /// alias named like a precommand that is no builtin in its place (`alias
    /// -- -=...`), as the code of a function of that name the command runs.
    /// `false` when zsh runs no command: a `command -v` or `-V`, which prints
    /// what its words are, and an `exec` with a flag it does not know.
    fn precommands(&mut self, words: &mut std::iter::Peekable<std::vec::IntoIter<Word>>) -> bool {
        let plain = |word: &Word| !word.expands && !word.bare && word.text.len() > 1;
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
                        return false;
                    }
                    words.next_if(|word| word.text == "--");
                }
                "exec" => {
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
                            return false;
                        }
                        if argv0 == Some("") {
                            words.next();
                        }
                    }
                }
                _ => {}
            }
        }
        true
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
        // its environment.
        let mut assignments = Vec::new();
        while let Some(word) = words.next_if(|word| is_assignment(&word.text)) {
            if word.expands {
                input = Input::Computed;
            }
            self.assignment(&word, unconditional);
            assignments.push(word);
        }
        if !self.precommands(&mut words) {
            // `command -v`, which prints what its words are.
            for word in words {
                self.mention(&word.text);
            }
            return;
        }
        let Some(command) = words.next() else {
            self.computed_assignments(&assignments);
            return;
        };
        let args: Vec<Word> = words.collect();
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
                self.mention(&arg.text);
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
            "unset" => {
                // What it takes away holds no code: a prompt, a hook's array.
                for arg in &args {
                    self.prompts += usize::from(PROMPTS.contains(&arg.text.as_str()));
                    self.hooks += usize::from(hook_array(&arg.text));
                    self.mention(&arg.text);
                }
            }
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
            "return" | "exit" => self.may_stop = true,
            // `history` takes the flags of `fc`, as `fc -l` does.
            "fc" | "history" => self.fc(&command.text, &args),
            "sysopen" => self.sysopen(&args),
            "zsystem" => self.zsystem(&args),
            "zsocket" | "ztcp" => self.connection(&command.text, &args),
            "autoload" => {
                self.autoloads += 1;
                self.autoload(&command.text, &args);
            }
            "functions" | "typeset" | "declare" | "local"
                if marks_autoload(&command.text, &args) =>
            {
                self.autoload(&command.text, &args);
            }
            "export" | "typeset" | "declare" | "local" | "readonly" | "integer" | "float"
            | "private" => {
                self.declared(&command.text, &args);
                self.declare(&command.text, &args, unconditional);
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
                self.mention(&path.text);
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
            self.mention(&arg.text);
        }
    }

    /// The events of a `typeset` or the like (`command`) of `args`: a
    /// parameter whose name an expansion makes is a doubt, and so is a tie
    /// (`typeset -T TMOUT tmout`) of one whose value the check reads
    /// ([`tie_read`]), as zsh then sets it by the other name too
    /// (`tmout=(...)`); each word is an assignment or a declaration.
    fn declare(&mut self, command: &str, args: &[Word], unconditional: bool) {
        // zsh takes the options from the words up to the first that starts
        // with neither `-` nor `+`, or a `--`.
        let flags: Vec<&Word> = args
            .iter()
            .take_while(|arg| arg.text.starts_with(['-', '+']) && arg.text != "--")
            .collect();
        let ties = flags
            .iter()
            .any(|flag| flag.text.starts_with('-') && (flag.text.contains('T') || computed(flag)));
        if ties {
            for arg in &args[flags.len()..] {
                let name = assigned(arg.text.split_once('=').map_or(&arg.text, |(name, _)| name));
                if computed(arg) || tie_read(name) {
                    self.events.push(Event::Doubt(format!(
                        "it cannot follow the value of `{}`, which `{command} {}` in {} ties to \
                         another name, by which zsh sets it too",
                        arg.text,
                        args.iter()
                            .map(|arg| arg.text.as_str())
                            .collect::<Vec<_>>()
                            .join(" "),
                        self.place
                    )));
                }
            }
        }
        for arg in args {
            if computed_target(&arg.text) {
                self.events.push(Event::Doubt(format!(
                    "it cannot tell which parameter `{command} {}` in {} sets",
                    arg.text, self.place
                )));
            }
            // A hook's array or a prompt declared as it is.
            if hook_array(&arg.text) {
                self.hooks += 1;
            }
            if PROMPTS.contains(&arg.text.as_str()) {
                self.prompts += 1;
            }
            self.assignment(arg, unconditional);
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
            self.mention(&arg.text);
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
                self.mention(&word.text);
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
                self.mention(&word.text);
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
                quoted: false,
                bare: word.bare,
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
