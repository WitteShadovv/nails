// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The walk over a file's tokens that finds what its code does, in order:
//! the options a `setopt`, `unsetopt` or `set -o` turns on or off, and
//! whether that certainly runs at the top level; every other word that names
//! an option; what the check cannot follow; the files it sources; the
//! `ZDOTDIR` and `XDG_CONFIG_HOME` it sets; the directories it adds to
//! `fpath` and the functions it autoloads; and the code it holds in strings
//! that zsh runs ([`strings`]).

use super::OPTIONS;
use super::backstop;
use super::lexer::{End, Flaw, Token, Word, lex};
use std::collections::BTreeMap;

mod command;
mod event;
mod fpath;
mod hooks;
mod loops;
mod names;
mod strings;

pub(super) use super::builtins::HOOKS;
pub(super) use event::{Event, Input};
pub(super) use strings::PROMPTS;

/// The option that `word` names, by its place in [`OPTIONS`], and whether the
/// name turns it on (`false` for its `no` form); `None` for any other word.
pub(super) fn option(word: &str) -> Option<(usize, bool)> {
    let name: String = word
        .chars()
        .filter(|c| *c != '_')
        .collect::<String>()
        .to_lowercase();
    let find = |name: &str| OPTIONS.iter().position(|option| option.0 == name);
    find(&name)
        .map(|at| (at, true))
        .or_else(|| find(name.strip_prefix("no")?).map(|at| (at, false)))
}

/// The options that `text` names, in either form ([`backstop::options`]).
pub(super) fn mentioned(text: &str) -> Vec<usize> {
    backstop::options(text)
        .into_iter()
        .map(|(at, _)| at)
        .collect()
}

/// How a loop's body ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Closer {
    /// At `done`.
    Done,
    /// At `}`.
    Brace,
    /// At `end`, as `foreach`'s does.
    End,
}

/// A compound command the walk is inside of.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Frame {
    If,
    Case,
    /// A loop, with the items the check can list when it runs over a list it
    /// knows, and how its body ends; `profiles` when it runs over the words
    /// of `NIX_PROFILES`, as NixOS's `/etc/zshenv` does.
    Loop {
        var: Option<String>,
        items: Option<Vec<String>>,
        closer: Closer,
        profiles: bool,
    },
    Group,
    Subshell,
    Function,
}

impl Frame {
    /// Whether what this frame holds certainly runs, when the frame does.
    fn runs(&self) -> bool {
        match self {
            Self::Group => true,
            Self::Loop { items, .. } => items.as_ref().is_some_and(|items| !items.is_empty()),
            _ => false,
        }
    }
}

/// A frame the walk is inside of, as it was opened.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Open {
    frame: Frame,
    /// The name of the function whose body it is, for a function's.
    name: Option<String>,
    /// Whether the frame itself certainly runs where it stands: not after
    /// `&&` or `||` and not in a pipeline. One followed by `&` or `|` turns
    /// out not to when it closes.
    certain: bool,
    /// How many events the walk had found when it opened.
    start: usize,
    /// The arrays the walk knew when it opened.
    arrays: BTreeMap<String, Vec<String>>,
    /// In the condition of an `if`, `elif`, `while` or `until`, before its
    /// body.
    head: bool,
    /// Its body is one command or group, as in zsh's short forms, and ends
    /// with the line or the `;` after it.
    short: bool,
    /// A `case` that reads a pattern next.
    pattern: bool,
    /// How many commands its body holds that no inner frame holds.
    commands: usize,
    /// Whether a frame was opened inside it.
    nested: bool,
}

/// What the walk keeps of the command it is reading.
#[derive(Debug, Default)]
struct Pending {
    words: Vec<Word>,
    /// It runs after `&&` or `||`.
    after_condition: bool,
    /// It runs in a pipeline.
    piped: bool,
    /// The next word or `{` is a function's body.
    function_next: bool,
    /// It is a function's whole body, which does not run where it stands.
    body: bool,
    /// The name of the function whose body comes next.
    function_name: Option<String>,
    /// The commands of the pipeline it is in that run before it, each one's
    /// name and whether an expansion makes a word of it; `None` when one is
    /// no simple command the walk read (a group).
    feeders: Option<Vec<(String, bool)>>,
    /// It reads what an expansion makes: a here-string or a file an
    /// expansion names (`<<< "$1"`, `< $f`).
    fed: bool,
}

/// The walk over one file's tokens, which finds its [`Event`]s.
struct Walker<'a> {
    tokens: std::iter::Peekable<std::vec::IntoIter<Token>>,
    /// Where the file is, as the warning names it.
    place: &'a str,
    frames: Vec<Open>,
    /// The arrays the file assigns a literal list at its top level.
    arrays: BTreeMap<String, Vec<String>>,
    events: Vec<Event>,
    /// A `return` or `exit` was seen: the rest of the file may not run.
    may_stop: bool,
    /// The structure did not close as zsh's would.
    confused: bool,
    /// How many `source` and `.` commands it read.
    sources: usize,
    /// How many `eval`s it read whole.
    evals: usize,
    /// How often it read `ZDOTDIR` set ([`zdotdir_writes`]).
    zdotdirs: usize,
    /// How many `autoload` commands it read.
    autoloads: usize,
    /// How often it read `fpath` or `FPATH` set ([`backstop::fpath_writes`]).
    fpaths: usize,
    /// How many `fc` commands it read that write the history file or whose
    /// words it cannot read.
    fcs: usize,
    /// How often it read `NIX_PROFILES` set
    /// ([`backstop::nix_profiles_writes`]).
    nix_profiles: usize,
    /// How many assignments by a name another parameter holds it read
    /// ([`backstop::indirect_assignments`]).
    indirects: usize,
    /// How often it read an array of hook functions set or declared
    /// ([`backstop::hook_writes`]).
    hooks: usize,
    /// How often it read a prompt set ([`backstop::prompt_writes`]).
    prompts: usize,
    /// The function the code walked runs in, for code a command of a
    /// function runs from a string (`eval`, a trap's).
    outer: Option<String>,
    pending: Pending,
    /// Where the events of the commands of the line being read start, and
    /// of the line before it, whose here-documents' bodies come next.
    line_start: usize,
    bodies_start: usize,
    /// How often it read an alias set by the parameters that hold them
    /// ([`backstop::alias_writes`]), and a function by `functions`.
    alias_params: usize,
    function_params: usize,
}

impl Walker<'_> {
    /// Whether a command here certainly runs: in no frame that may not run,
    /// and not after `&&`, `||`, a `return` or an `exit`, in a pipeline or in
    /// the background.
    fn certain(&self, after_condition: bool, piped: bool) -> bool {
        !after_condition
            && !piped
            && !self.may_stop
            && self
                .frames
                .iter()
                .all(|open| open.certain && open.frame.runs())
    }

    /// Open `frame` where the command being read starts, in its condition
    /// (`head`) or not.
    fn open(&mut self, frame: Frame, head: bool) {
        let pattern = frame == Frame::Case;
        let name = if frame == Frame::Function {
            self.pending.function_name.take()
        } else {
            None
        };
        if let Some(outer) = self.frames.last_mut() {
            outer.nested = true;
        }
        self.frames.push(Open {
            name,
            frame,
            certain: !self.pending.after_condition && !self.pending.piped,
            start: self.events.len(),
            arrays: self.arrays.clone(),
            head,
            short: false,
            pattern,
            commands: 0,
            nested: false,
        });
    }

    /// Whether the frame that just closed may run elsewhere than in this
    /// shell, as the tokens after it tell, past its redirections: in the
    /// background or a pipeline (`} &`, `done | cat`), or before anything
    /// else than the end of a command or of the frame around it.
    fn runs_elsewhere(&self) -> bool {
        let mut ahead = self.tokens.clone();
        loop {
            match ahead.next() {
                Some(Token::Redirect { .. }) => {
                    ahead.next_if(|token| matches!(token, Token::Word(_)));
                }
                // The number of the descriptor a redirection takes (`2>&1`).
                Some(Token::Word(word))
                    if word.text.chars().all(|c| c.is_ascii_digit())
                        && matches!(ahead.peek(), Some(Token::Redirect { .. })) => {}
                Some(Token::Word(word))
                    if matches!(
                        word.text.as_str(),
                        "}" | "done" | "fi" | "esac" | "then" | "else" | "elif" | "do"
                    ) =>
                {
                    return false;
                }
                Some(Token::End(End::Line | End::Condition | End::Arm) | Token::Close) | None => {
                    return false;
                }
                Some(_) => return true,
            }
        }
    }

    /// Count a command of the innermost frame's body.
    pub(super) fn counted(&mut self) {
        if let Some(open) = self.frames.last_mut() {
            open.commands += 1;
        }
    }

    /// When `open`, the frame just closed, is NixOS's loop over the
    /// profiles, keep the directories it adds under each profile only when
    /// its body is the one `fpath` assignment NixOS writes there: any other
    /// body may change what `$p` holds, so the directories count as
    /// written, which the check cannot follow.
    fn profiles_closed(&mut self, open: &Open) {
        if !matches!(open.frame, Frame::Loop { profiles: true, .. })
            || (open.commands == 1 && !open.nested)
        {
            return;
        }
        for event in &mut self.events[open.start..] {
            if let Event::ProfileFpath { written, first, .. } = event {
                *event = Event::Fpath {
                    dir: Some(Word {
                        text: std::mem::take(written),
                        expands: true,
                    }),
                    first: *first,
                };
            }
        }
    }

    /// Pop the innermost frame if `close` closes it, and, when it may run
    /// elsewhere than in this shell, count none of what it held as certain
    /// and forget the arrays it assigned; note confusion if `close` does not
    /// close it.
    fn close(&mut self, close: fn(&Frame) -> bool) {
        if !self.frames.last().is_some_and(|open| close(&open.frame)) {
            self.confused = true;
            return;
        }
        let open = self.frames.pop().expect("the frame closed");
        self.profiles_closed(&open);
        if self.runs_elsewhere() {
            self.arrays = open.arrays;
            for event in &mut self.events[open.start..] {
                match event {
                    Event::Set { unconditional, .. }
                    | Event::Source { unconditional, .. }
                    | Event::Assign { unconditional, .. } => *unconditional = false,
                    _ => {}
                }
            }
        }
    }

    /// Whether the innermost frame is in its condition, before its body.
    fn in_head(&self) -> bool {
        self.frames.last().is_some_and(|open| open.head)
    }

    /// Whether the token next starts a body: a command or a group, not the
    /// `then` or `do` of the long forms.
    fn next_starts_body(&mut self) -> bool {
        matches!(self.tokens.peek(), Some(Token::Word(word)) if !matches!(word.text.as_str(), "then" | "do"))
    }

    /// Make the innermost frame's body one command or group, as in zsh's
    /// short forms (`if [[ ... ]] cmd`, `repeat 3 cmd`).
    fn short_body(&mut self) {
        if let Some(open) = self.frames.last_mut() {
            open.head = false;
            open.short = true;
        }
    }

    /// Close the frames whose short body just ended.
    fn end_short(&mut self) {
        while self.frames.last().is_some_and(|open| open.short) {
            self.frames.pop();
        }
    }

    /// Mark whether the innermost frame, when one of `frames`, is in its
    /// condition (`then`, `do`, `else`: not; `elif`: again).
    fn set_head(&mut self, head: bool, frames: fn(&Frame) -> bool) {
        if let Some(open) = self.frames.last_mut()
            && frames(&open.frame)
        {
            open.head = head;
        }
    }

    /// Finish the command being read, in a pipeline after it (`piped_after`)
    /// or not.
    fn finish(&mut self, piped_after: bool) {
        let words = std::mem::take(&mut self.pending.words);
        let after = self.pending.after_condition || self.pending.body;
        let piped = self.pending.piped || piped_after;
        // What the command reads: what the commands before it in its
        // pipeline write, or what an expansion makes.
        let input = if std::mem::take(&mut self.pending.fed) {
            Input::Computed
        } else if self.pending.piped {
            Input::Piped(self.pending.feeders.clone().unwrap_or_default())
        } else {
            Input::None
        };
        let feeder = Self::feeder(&words);
        self.command(words, after, piped, input);
        if !piped_after {
            self.pending.feeders = Some(Vec::new());
        } else if self.pending.piped {
            // A command in a pipeline after another: one more of them.
            match (self.pending.feeders.as_mut(), feeder) {
                (Some(feeders), Some(feeder)) => feeders.push(feeder),
                _ => self.pending.feeders = None,
            }
        } else {
            // The first command of a pipeline.
            self.pending.feeders = feeder.map(|feeder| vec![feeder]);
        }
        if std::mem::take(&mut self.pending.body) {
            self.pending.function_name = None;
        }
    }

    /// The name of the simple command `words` and whether an expansion makes
    /// one of its words, as what it writes feeds the commands after it in a
    /// pipeline; `None` for no simple command (a group's end).
    fn feeder(words: &[Word]) -> Option<(String, bool)> {
        let mut command = words
            .iter()
            .skip_while(|word| command::is_assignment(&word.text));
        let name = command.next()?;
        let expands = name.expands || words.iter().any(|word| word.expands);
        Some((name.text.clone(), expands))
    }

    /// The name of the function whose body the walk is in, when it is in
    /// one with a name.
    fn function(&self) -> Option<String> {
        if self.pending.body
            && let Some(name) = &self.pending.function_name
        {
            return Some(name.clone());
        }
        self.frames
            .iter()
            .rev()
            .find(|open| open.frame == Frame::Function)
            .and_then(|open| open.name.clone())
            .or_else(|| self.outer.clone())
    }

    /// Close the innermost frame with a `}`: a group, a function's body, a
    /// loop's, or zsh's `case word { ... }`.
    fn close_brace(&mut self) {
        self.end_short();
        self.close(|frame| {
            matches!(
                frame,
                Frame::Group
                    | Frame::Function
                    | Frame::Case
                    | Frame::Loop {
                        closer: Closer::Brace,
                        ..
                    }
            )
        });
    }

    /// The events of a word.
    fn word(&mut self, word: Word) {
        if !self.pending.words.is_empty() {
            if word.text == "}" {
                self.finish(false);
                self.close_brace();
                return;
            }
            let condition = word.text == "]]"
                && self
                    .pending
                    .words
                    .first()
                    .is_some_and(|first| first.text == "[[");
            self.pending.words.push(word);
            if condition && self.in_head() && self.next_starts_body() {
                // `if [[ ... ]] cmd`: the condition ends, the body starts.
                self.finish(false);
                self.short_body();
            }
            return;
        }
        let loop_frame = |closer| Frame::Loop {
            var: None,
            items: None,
            closer,
            profiles: false,
        };
        match word.text.as_str() {
            "if" => self.open(Frame::If, true),
            "case" => self.open(Frame::Case, false),
            "while" | "until" => self.open(loop_frame(Closer::Done), true),
            "repeat" => self.repeat(),
            "for" | "foreach" | "select" => {
                let (mut frame, short) = self.for_header(word.text == "foreach");
                if let Frame::Loop { profiles, .. } = &mut frame {
                    *profiles &= word.text == "for";
                }
                self.open(frame, false);
                if short {
                    self.short_body();
                }
            }
            "then" | "else" => self.set_head(false, |frame| *frame == Frame::If),
            "elif" => self.set_head(true, |frame| *frame == Frame::If),
            "do" => self.set_head(false, |frame| matches!(frame, Frame::Loop { .. })),
            "in" => {}
            "fi" => {
                self.end_short();
                self.close(|frame| *frame == Frame::If);
            }
            "esac" => {
                self.end_short();
                self.close(|frame| *frame == Frame::Case);
            }
            "done" => {
                self.end_short();
                self.close(|frame| {
                    matches!(
                        frame,
                        Frame::Loop {
                            closer: Closer::Done,
                            ..
                        }
                    )
                });
            }
            "end"
                if self.frames.last().is_some_and(|open| {
                    matches!(
                        open.frame,
                        Frame::Loop {
                            closer: Closer::End,
                            ..
                        }
                    )
                }) =>
            {
                self.frames.pop();
            }
            "{" => {
                let frame = if self.pending.function_next {
                    Frame::Function
                } else {
                    Frame::Group
                };
                self.pending.function_next = false;
                if self.in_head() {
                    self.short_body();
                }
                self.open(frame, false);
            }
            "}" => self.close_brace(),
            "function" => {
                if let Some(Token::Word(name)) = self.tokens.next() {
                    self.mention(&name.text);
                    self.events.push(Event::Define(name.text.clone()));
                    self.pending.function_name = Some(name.text);
                }
                if self.tokens.next_if_eq(&Token::Open).is_some() {
                    self.tokens.next_if_eq(&Token::Close);
                }
                self.pending.function_next = true;
            }
            _ if self.pending.function_next => {
                self.pending.function_next = false;
                self.pending.body = true;
                self.pending.words.push(word);
            }
            _ => self.pending.words.push(word),
        }
    }

    /// The events of an array's assignment, `name=(items)`, or of what
    /// appends to it, when `name` ends with `+`.
    fn array(&mut self, name: String, items: Vec<Word>) {
        for item in &items {
            self.mention(&item.text);
        }
        let (name, append) = match name.strip_suffix('+') {
            Some(name) => (name.to_string(), true),
            None => (name, false),
        };
        // The functions zsh runs as hooks (`precmd_functions+=(name)`).
        if let Some(hook) = name.strip_suffix("_functions")
            && HOOKS.contains(&hook)
        {
            self.hooks += 1;
            for item in &items {
                if item.expands {
                    self.events.push(Event::Doubt(format!(
                        "it cannot tell which function `{}` in {} makes a hook",
                        item.text, self.place
                    )));
                } else {
                    self.events.push(Event::Hook(item.text.clone()));
                }
            }
        }
        let functions = matches!(name.as_str(), "functions" | "dis_functions");
        let aliases = command::ALIAS_PARAMETERS.contains(&name.as_str());
        if functions || aliases {
            // Function bodies or alias values, each beside its name.
            self.function_params += usize::from(functions);
            self.alias_params += usize::from(aliases);
            self.events.push(Event::Doubt(format!(
                "it cannot tell what code `{name}=(...)` in {} gives",
                self.place
            )));
        }
        if name == "mapfile" {
            // zsh/mapfile writes each file its keys name.
            self.events.push(Event::Doubt(format!(
                "it cannot tell which files `mapfile=(...)` in {} writes",
                self.place
            )));
        }
        if name == "options"
            && let Some(item) = items.iter().find(|item| item.expands)
        {
            // An option whose name an expansion makes.
            self.events.push(Event::Doubt(format!(
                "it cannot tell which options `options=(... {} ...)` in {} sets",
                item.text, self.place
            )));
        }
        self.counted();
        if matches!(name.as_str(), "fpath" | "FPATH") {
            self.fpaths += 1;
            if append || name != "fpath" || !self.profiles_fpath(&items) {
                self.fpath_items(&items, append, true);
            }
        }
        let literal: Option<Vec<String>> = items
            .iter()
            .map(|item| (!item.expands).then(|| item.text.clone()))
            .collect();
        match literal {
            Some(literal)
                if self.pending.words.is_empty()
                    && self.certain(self.pending.after_condition, self.pending.piped) =>
            {
                if !append {
                    self.arrays.insert(name, literal);
                } else if let Some(known) = self.arrays.get_mut(&name) {
                    known.extend(literal);
                }
            }
            _ => {
                self.arrays.remove(&name);
            }
        }
    }

    /// The events of a token where a `case` reads a pattern: none but the
    /// names in it, up to the `)` after which a command starts, or the
    /// `esac` or `}` that closes the `case`.
    fn pattern_token(&mut self, token: Token) {
        match token {
            Token::Word(word) if matches!(word.text.as_str(), "esac" | "}") => {
                self.close(|frame| *frame == Frame::Case);
            }
            Token::Word(word) => self.mention(&word.text),
            Token::Close => {
                if let Some(open) = self.frames.last_mut() {
                    open.pattern = false;
                }
                self.pending = Pending {
                    feeders: Some(Vec::new()),
                    ..Pending::default()
                };
            }
            Token::Text(text) | Token::Arithmetic(text) => self.mention_options(&text),
            Token::Array(_, items) => {
                for item in items {
                    self.mention(&item.text);
                }
            }
            Token::Open | Token::End(_) | Token::Redirect { .. } => {}
        }
    }

    /// The events of the end of a command.
    fn end(&mut self, end: End) {
        self.finish(matches!(end, End::Pipe | End::Background));
        if end == End::Line {
            // The here-documents the line opens come next, as the input of
            // its commands.
            self.bodies_start = self.line_start;
            self.line_start = self.events.len();
        }
        match end {
            End::Line | End::Background => self.end_short(),
            End::Arm => {
                self.end_short();
                if let Some(open) = self.frames.last_mut()
                    && open.frame == Frame::Case
                {
                    open.pattern = true;
                }
            }
            End::Condition | End::Pipe => {}
        }
        self.pending.after_condition = end == End::Condition;
        self.pending.piped = end == End::Pipe;
    }

    /// The events of a `(`: a function's or an anonymous function's `()`, or
    /// a subshell.
    fn open_paren(&mut self) {
        let words = self.pending.words.len();
        if words <= 1 && self.tokens.peek() == Some(&Token::Close) {
            // `name()`: what follows is its body; `() { ... }`: an anonymous
            // function, which runs at once but can keep its options local
            // (`localoptions`, `emulate -L`).
            self.tokens.next();
            if let Some(name) = self.pending.words.pop() {
                self.mention(&name.text);
                self.events.push(Event::Define(name.text.clone()));
                self.pending.function_name = Some(name.text);
            }
            self.pending.function_next = true;
            return;
        }
        self.finish(false);
        self.open(Frame::Subshell, false);
    }

    /// Walk every token, finding the events in order.
    fn walk(mut self) -> Self {
        while let Some(token) = self.tokens.next() {
            if self.frames.last().is_some_and(|open| open.pattern) {
                self.pattern_token(token);
                continue;
            }
            match token {
                Token::Word(word) => self.word(word),
                Token::Array(name, items) => self.array(name, items),
                Token::Redirect { writes, dup } => {
                    // The redirection's target is no word of the command, but
                    // what a here-string or a file name says still counts.
                    if let Some(Token::Word(target)) =
                        self.tokens.next_if(|token| matches!(token, Token::Word(_)))
                    {
                        self.mention_options(&target.text);
                        self.qualifier(&target.text);
                        let computed = target.expands || target.text.contains(['$', '`']);
                        // `>&2`, `2>&1`, `>&-`: a descriptor, no file.
                        let descriptor = dup
                            && (target.text.chars().all(|c| c.is_ascii_digit())
                                || matches!(target.text.as_str(), "-" | "p"));
                        if !writes {
                            // What the command reads: `<<< "$1"`, `< $f`.
                            self.pending.fed |= computed;
                        } else if !descriptor {
                            // `exec 3>>file` keeps the descriptor open.
                            let kept = matches!(
                                self.pending.words.as_slice(),
                                [word] if word.text == "exec"
                            );
                            self.events.push(Event::Redirect {
                                computed,
                                function: self.function(),
                                target: target.text,
                                kept,
                            });
                        }
                    }
                }
                Token::Text(text) => {
                    self.mention_options(&text);
                    // A here-document's body is expanded as the command reads
                    // it, unless its delimiter is quoted, and is what the
                    // commands of the line that opens it read.
                    if text.contains(['$', '`']) {
                        let (from, to) = (self.bodies_start, self.line_start);
                        for event in &mut self.events[from..to] {
                            if let Event::Call { input, .. } = event {
                                *input = Input::Computed;
                            }
                        }
                    }
                    self.substituted(&text);
                }
                Token::Arithmetic(text) => {
                    // A command of its own, which sets no option; in a
                    // condition, its end (`if (( ... )) cmd`).
                    self.pending.function_next = false;
                    self.counted();
                    self.mention_arithmetic(&text);
                    if self.pending.words.is_empty() && self.in_head() && self.next_starts_body() {
                        self.short_body();
                    }
                }
                Token::Open => self.open_paren(),
                Token::Close => {
                    self.finish(false);
                    self.end_short();
                    self.close(|frame| *frame == Frame::Subshell);
                }
                Token::End(end) => self.end(end),
            }
        }
        self.finish(false);
        self.end_short();
        self.confused |= !self.frames.is_empty();
        self
    }
}

/// What the walk over zsh code found: its events, whether it lost track of
/// the structure, what it read that the lines may name ([`backstop`]), and
/// whether a `return` or `exit` may end the file early.
struct Walked {
    events: Vec<Event>,
    confused: bool,
    sources: usize,
    evals: usize,
    zdotdirs: usize,
    autoloads: usize,
    fpaths: usize,
    fcs: usize,
    nix_profiles: usize,
    indirects: usize,
    hooks: usize,
    prompts: usize,
    alias_params: usize,
    function_params: usize,
    may_stop: bool,
}

/// What a startup file's code does, as [`events`] reads it.
pub(super) struct Read {
    pub(super) events: Vec<Event>,
    /// The check lost track of its structure.
    pub(super) confused: bool,
    /// A `return` or `exit` may end it before its end.
    pub(super) may_stop: bool,
}

/// Walk zsh code `text` from the file at `place` that runs in the function
/// `outer`, when in one; what the lexer could not read is a doubt.
fn walk_text_in(text: &str, place: &str, outer: Option<String>) -> Walked {
    let (tokens, flaws) = lex(text);
    let walker = Walker {
        tokens: tokens.into_iter().peekable(),
        place,
        frames: Vec::new(),
        arrays: BTreeMap::new(),
        events: Vec::new(),
        may_stop: false,
        confused: false,
        sources: 0,
        evals: 0,
        zdotdirs: 0,
        autoloads: 0,
        fpaths: 0,
        fcs: 0,
        nix_profiles: 0,
        indirects: 0,
        hooks: 0,
        prompts: 0,
        outer,
        pending: Pending {
            feeders: Some(Vec::new()),
            ..Pending::default()
        },
        line_start: 0,
        bodies_start: 0,
        alias_params: 0,
        function_params: 0,
    }
    .walk();
    let mut events = walker.events;
    events.extend(flaws.into_iter().map(|flaw| {
        Event::Doubt(match flaw {
            Flaw::Unended(delimiter) => format!(
                "it cannot tell where the here-document that {place} opens with \
                 `<<{delimiter}` ends"
            ),
            Flaw::Unclosed(opener) => {
                format!("it cannot tell where the {opener} that {place} opens ends")
            }
            Flaw::Unfollowed(opener, what) => {
                format!("it cannot follow the {opener} that {place} opens, which holds {what}")
            }
        })
    }));
    Walked {
        events,
        confused: walker.confused,
        sources: walker.sources,
        evals: walker.evals,
        zdotdirs: walker.zdotdirs,
        autoloads: walker.autoloads,
        fpaths: walker.fpaths,
        fcs: walker.fcs,
        nix_profiles: walker.nix_profiles,
        indirects: walker.indirects,
        hooks: walker.hooks,
        prompts: walker.prompts,
        alias_params: walker.alias_params,
        function_params: walker.function_params,
        may_stop: walker.may_stop,
    }
}

/// What zsh code `text` from the file at `place` does, as the code of the
/// function `outer` when it runs as one (an autoloaded function's file, one a
/// function sources) ([`Read`]). What the lexer could not read is a doubt,
/// and so is a `source`, a `.`, an `eval`, an `autoload`, a `ZDOTDIR`
/// setting or an array of hook functions set that the file's lines hold
/// beyond those the walk read; an option they name beyond those the tokens
/// name counts as on, a prompt set beyond those the walk read holds code the
/// check cannot follow, and an `fpath` setting beyond those the walk read adds
/// a directory the check cannot follow ([`backstop`]).
pub(super) fn events(text: &str, place: &str, outer: Option<String>) -> Read {
    let (tokens, _) = lex(text);
    let mut read = [0; 3];
    for token in &tokens {
        let texts: Vec<&str> = match token {
            Token::Word(word) => vec![&word.text],
            Token::Array(name, items) => std::iter::once(name.as_str())
                .chain(items.iter().map(|item| item.text.as_str()))
                .collect(),
            Token::Text(text) | Token::Arithmetic(text) => vec![text],
            _ => Vec::new(),
        };
        for (at, _) in texts.into_iter().flat_map(backstop::options) {
            read[at] += 1;
        }
    }
    let walked = walk_text_in(text, place, outer);
    let mut events = walked.events;
    let named = backstop::named(text);
    for (at, (&lines, &tokens)) in named.options.iter().zip(&read).enumerate() {
        if lines > tokens {
            events.push(Event::Unread(at));
        }
    }
    if named.sources > walked.sources {
        events.push(Event::Doubt(format!(
            "it cannot follow a `source` or `.` that a line of {place} may run"
        )));
    }
    if named.evals > walked.evals {
        events.push(Event::Doubt(format!(
            "it cannot follow an `eval` that a line of {place} may run"
        )));
    }
    if named.zdotdirs > walked.zdotdirs {
        events.push(Event::Doubt(format!(
            "it cannot follow a ZDOTDIR that a line of {place} may set"
        )));
    }
    if named.autoloads > walked.autoloads {
        events.push(Event::Doubt(format!(
            "it cannot follow an `autoload` that a line of {place} may run"
        )));
    }
    if named.fpaths > walked.fpaths {
        events.push(Event::Fpath {
            dir: None,
            first: false,
        });
    }
    if named.fcs > walked.fcs {
        events.push(Event::Doubt(format!(
            "it cannot follow an `fc` that a line of {place} may run, which can write the \
             history file"
        )));
    }
    if named.nix_profiles > walked.nix_profiles {
        events.push(Event::ProfilesUnknown);
    }
    if named.indirects > walked.indirects {
        events.push(Event::Doubt(format!(
            "it cannot tell which parameter a line of {place} may set by the name another one \
             holds"
        )));
    }
    if named.hooks > walked.hooks {
        events.push(Event::Doubt(format!(
            "it cannot tell which functions a line of {place} may make hooks, which zsh runs as \
             each command is entered or ends"
        )));
    }
    if named.prompts > walked.prompts {
        events.push(Event::Prompt(format!(
            "it cannot follow a prompt that a line of {place} may set, whose code zsh runs as it \
             shows the prompt, as PROMPT_SUBST may be on"
        )));
    }
    if named.alias_params > walked.alias_params {
        events.push(Event::Doubt(format!(
            "it cannot tell what alias a line of {place} may give by the parameters that hold \
             them, which zsh then expands"
        )));
    }
    if named.function_params > walked.function_params {
        events.push(Event::Doubt(format!(
            "it cannot tell what code a line of {place} may give a function by `functions`"
        )));
    }
    Read {
        events,
        confused: walked.confused,
        may_stop: walked.may_stop,
    }
}
