// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The walk over a file's tokens that finds what its code does, in order:
//! the options a `setopt`, `unsetopt` or `set -o` turns on or off, and
//! whether that certainly runs at the top level; every other word that names
//! an option; what the check cannot follow; the files it sources; the
//! `ZDOTDIR` and `XDG_CONFIG_HOME` it sets; and the directories it adds to
//! `fpath` and the functions it autoloads.

use super::OPTIONS;
use super::backstop;
use super::lexer::{End, Flaw, Token, Word, is_name, lex};
use std::collections::BTreeMap;

mod command;

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

/// The options that `text` names without a `no` prefix, in any word of it.
pub(super) fn mentioned(text: &str) -> impl Iterator<Item = usize> + '_ {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter_map(option)
        .filter_map(|(at, on)| on.then_some(at))
}

/// What a file's code does, in order, as [`Walker`] finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Event {
    /// A `setopt` or the like turns an option on or off; `unconditional`
    /// when it certainly runs at the file's top level.
    Set {
        option: usize,
        on: bool,
        unconditional: bool,
    },
    /// A word names an option outside an understood `setopt`.
    Mention(usize),
    /// A line names an option where the walk read no code: in a comment, or
    /// in what a misread hid.
    Unread(usize),
    /// Something the check cannot follow, as the warning names it.
    Doubt(String),
    /// `source` or `.` of `path`.
    Source { path: Word, unconditional: bool },
    /// Oh My Zsh is loaded.
    OhMyZsh,
    /// `ZDOTDIR` or `XDG_CONFIG_HOME` is set.
    Assign {
        name: &'static str,
        value: Word,
        unconditional: bool,
    },
    /// A directory is added to `fpath`, where zsh looks for the functions it
    /// autoloads: the element as written, or `None` for what a line may add
    /// that the walk did not read.
    Fpath(Option<Word>),
    /// A function is marked to be autoloaded: its name, or the path of its
    /// file.
    Autoload(Word),
    /// An `fc` that writes the history file, as written (`fc -AI`).
    Fc(String),
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
    /// knows, and how its body ends.
    Loop {
        var: Option<String>,
        items: Option<Vec<String>>,
        closer: Closer,
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
    pending: Pending,
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
        self.frames.push(Open {
            frame,
            certain: !self.pending.after_condition && !self.pending.piped,
            start: self.events.len(),
            arrays: self.arrays.clone(),
            head,
            short: false,
            pattern,
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
                Some(Token::Redirect) => {
                    ahead.next_if(|token| matches!(token, Token::Word(_)));
                }
                // The number of the descriptor a redirection takes (`2>&1`).
                Some(Token::Word(word))
                    if word.text.chars().all(|c| c.is_ascii_digit())
                        && ahead.peek() == Some(&Token::Redirect) => {}
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

    /// The header of a `for`, `foreach` or `select` loop, read past its
    /// keyword: its variables and list, and how its body ends. Also whether
    /// the body is one command or group, as in zsh's short forms
    /// (`for x (a) cmd`).
    fn for_header(&mut self, foreach: bool) -> (Frame, bool) {
        let mut var = match self.tokens.next() {
            Some(Token::Word(word)) if is_name(&word.text) => Some(word.text),
            // `for (( ...; ...; ... ))`, over nothing the check can list.
            Some(Token::Arithmetic(text)) => {
                self.mention(&text);
                let (closer, short) = self.body_closer(foreach);
                let frame = Frame::Loop {
                    var: None,
                    items: None,
                    closer,
                };
                return (frame, short);
            }
            _ => {
                self.confused = true;
                None
            }
        };
        // More variables, as zsh takes them (`for key value in ...`).
        while self
            .tokens
            .next_if(|token| {
                matches!(token, Token::Word(word) if is_name(&word.text) && !matches!(word.text.as_str(), "in" | "do"))
            })
            .is_some()
        {
            var = None;
        }
        let mut list = Vec::new();
        let mut listed = false;
        match self.tokens.peek() {
            Some(Token::Word(word)) if word.text == "in" => {
                self.tokens.next();
                while let Some(Token::Word(word)) = self.tokens.next_if(
                    |token| matches!(token, Token::Word(word) if word.text != "do" && word.text != "{"),
                ) {
                    list.push(word);
                }
                listed = true;
            }
            Some(Token::Open) => {
                self.tokens.next();
                while let Some(Token::Word(word)) =
                    self.tokens.next_if(|token| matches!(token, Token::Word(_)))
                {
                    list.push(word);
                }
                listed = self.tokens.next_if_eq(&Token::Close).is_some();
            }
            _ => {}
        }
        for word in &list {
            let text = word.text.clone();
            self.mention(&text);
        }
        let items = if listed { self.list(&list) } else { None };
        let (closer, short) = self.body_closer(foreach);
        (Frame::Loop { var, items, closer }, short)
    }

    /// How the body of a loop whose header was read ends: `do ... done`,
    /// `{ ... }` or, for `foreach`, `... end`, past any line end, or with one
    /// command or group, as in zsh's short forms (then `true`).
    fn body_closer(&mut self, foreach: bool) -> (Closer, bool) {
        while self.tokens.next_if_eq(&Token::End(End::Line)).is_some() {}
        let (closer, short) = match self.tokens.peek() {
            Some(Token::Word(word)) if word.text == "do" => (Closer::Done, false),
            Some(Token::Word(word)) if word.text == "{" => (Closer::Brace, false),
            _ if foreach => (Closer::End, false),
            _ => (Closer::Done, true),
        };
        if !short && closer != Closer::End {
            self.tokens.next();
        }
        (closer, short)
    }

    /// Read `repeat`'s count and how its body ends.
    fn repeat(&mut self) {
        if let Some(Token::Word(count)) =
            self.tokens.next_if(|token| matches!(token, Token::Word(_)))
        {
            self.mention(&count.text);
        }
        let closer = match self.tokens.peek() {
            Some(Token::Word(word)) if word.text == "do" => Some(Closer::Done),
            Some(Token::Word(word)) if word.text == "{" => Some(Closer::Brace),
            _ => None,
        };
        if closer.is_some() {
            self.tokens.next();
        }
        self.open(
            Frame::Loop {
                var: None,
                items: None,
                closer: closer.unwrap_or(Closer::Done),
            },
            false,
        );
        if closer.is_none() {
            self.short_body();
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
        self.command(words, after, piped);
        self.pending.body = false;
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
        };
        match word.text.as_str() {
            "if" => self.open(Frame::If, true),
            "case" => self.open(Frame::Case, false),
            "while" | "until" => self.open(loop_frame(Closer::Done), true),
            "repeat" => self.repeat(),
            "for" | "foreach" | "select" => {
                let (frame, short) = self.for_header(word.text == "foreach");
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
        if matches!(name.as_str(), "fpath" | "FPATH") {
            self.fpaths += 1;
            for item in &items {
                self.fpath_dir(item);
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
                self.pending = Pending::default();
            }
            Token::Text(text) | Token::Arithmetic(text) => self.mention_options(&text),
            Token::Array(_, items) => {
                for item in items {
                    self.mention(&item.text);
                }
            }
            Token::Open | Token::End(_) | Token::Redirect => {}
        }
    }

    /// The events of the end of a command.
    fn end(&mut self, end: End) {
        self.finish(matches!(end, End::Pipe | End::Background));
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
                Token::Redirect => {
                    // The redirection's target is no word of the command, but
                    // what a here-string or a file name says still counts.
                    if let Some(Token::Word(target)) =
                        self.tokens.next_if(|token| matches!(token, Token::Word(_)))
                    {
                        self.mention_options(&target.text);
                    }
                }
                Token::Text(text) => self.mention_options(&text),
                Token::Arithmetic(text) => {
                    // A command of its own, which sets no option; in a
                    // condition, its end (`if (( ... )) cmd`).
                    self.pending.function_next = false;
                    self.mention(&text);
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
    may_stop: bool,
}

/// What a startup file's code does, as [`events`] reads it.
pub(super) struct Read {
    pub(super) events: Vec<Event>,
    /// The check lost track of its structure.
    pub(super) confused: bool,
}

/// Walk zsh code `text` from the file at `place`; what the lexer could not
/// read is a doubt.
fn walk_text(text: &str, place: &str) -> Walked {
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
        pending: Pending::default(),
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
        may_stop: walker.may_stop,
    }
}

/// What zsh code `text` from the file at `place` does ([`Read`]). What the
/// lexer could not read is a doubt, and so is a `source`, a `.`, an `eval`,
/// an `autoload` or a `ZDOTDIR` setting the file's lines hold beyond those
/// the walk read; an option they name beyond those the tokens name counts as
/// on, and an `fpath` setting beyond those the walk read adds a directory the
/// check cannot follow ([`backstop`]).
pub(super) fn events(text: &str, place: &str) -> Read {
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
    let walked = walk_text(text, place);
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
        events.push(Event::Fpath(None));
    }
    if named.fcs > walked.fcs {
        events.push(Event::Doubt(format!(
            "it cannot follow an `fc` that a line of {place} may run, which can write the \
             history file"
        )));
    }
    Read {
        events,
        confused: walked.confused,
    }
}
