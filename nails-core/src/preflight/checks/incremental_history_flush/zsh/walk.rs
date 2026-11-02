// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The walk over a file's tokens that finds what its code does, in order:
//! the options a `setopt`, `unsetopt` or `set -o` turns on or off, and
//! whether that certainly runs at the top level; every other word that names
//! an option; what the check cannot follow; the files it sources; and the
//! `ZDOTDIR` and `XDG_CONFIG_HOME` it sets.

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
}

/// A compound command the walk is inside of.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Frame {
    If,
    Case,
    /// A loop, with the items the check can list when it runs over a list it
    /// knows; it ends at `done`, or at `}` when `brace`.
    Loop {
        var: Option<String>,
        items: Option<Vec<String>>,
        brace: bool,
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
    /// How often it read `ZDOTDIR` set ([`zdotdir_writes`]).
    zdotdirs: usize,
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

    /// Open `frame` where a command can start, after a condition or in a
    /// pipeline or not.
    fn open(&mut self, frame: Frame, after_condition: bool, piped: bool) {
        self.frames.push(Open {
            frame,
            certain: !after_condition && !piped,
            start: self.events.len(),
            arrays: self.arrays.clone(),
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
                Some(Token::End(End::Line | End::Condition) | Token::Close) | None => {
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

    /// The header of a `for` loop, read past `for`: its variable and list.
    fn for_header(&mut self) -> Frame {
        let var = match self.tokens.next() {
            Some(Token::Word(word)) if is_name(&word.text) => Some(word.text),
            // `for (( ...; ...; ... ))`, over nothing the check can list.
            Some(Token::Arithmetic(text)) => {
                self.mention(&text);
                None
            }
            _ => {
                self.confused = true;
                None
            }
        };
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
        // The body: `do ... done` or `{ ... }`, past any line end.
        while self.tokens.next_if_eq(&Token::End(End::Line)).is_some() {}
        let brace = match self.tokens.next() {
            Some(Token::Word(word)) if word.text == "do" => false,
            Some(Token::Word(word)) if word.text == "{" => true,
            _ => {
                self.confused = true;
                false
            }
        };
        Frame::Loop { var, items, brace }
    }

    /// Walk every token, finding the events in order.
    fn walk(mut self) -> Self {
        let mut words: Vec<Word> = Vec::new();
        let mut after_condition = false;
        let mut piped = false;
        let mut function_next = false;
        // The command being read is a function's whole body, which does not
        // run where it stands.
        let mut body = false;
        while let Some(token) = self.tokens.next() {
            match token {
                Token::Word(word) if words.is_empty() => match word.text.as_str() {
                    "if" => self.open(Frame::If, after_condition, piped),
                    "case" => self.open(Frame::Case, after_condition, piped),
                    "while" | "until" | "select" | "repeat" => self.open(
                        Frame::Loop {
                            var: None,
                            items: None,
                            brace: false,
                        },
                        after_condition,
                        piped,
                    ),
                    "for" | "foreach" => {
                        let frame = self.for_header();
                        self.open(frame, after_condition, piped);
                    }
                    "then" | "else" | "elif" | "do" | "in" => {}
                    "fi" => self.close(|frame| *frame == Frame::If),
                    "esac" => self.close(|frame| *frame == Frame::Case),
                    "done" => self.close(|frame| matches!(frame, Frame::Loop { brace: false, .. })),
                    "{" => {
                        let frame = if function_next {
                            Frame::Function
                        } else {
                            Frame::Group
                        };
                        function_next = false;
                        self.open(frame, after_condition, piped);
                    }
                    "}" => self.close(|frame| {
                        matches!(
                            frame,
                            Frame::Group | Frame::Function | Frame::Loop { brace: true, .. }
                        )
                    }),
                    "function" => {
                        if let Some(Token::Word(name)) = self.tokens.next() {
                            self.mention(&name.text);
                        }
                        if self.tokens.next_if_eq(&Token::Open).is_some() {
                            self.tokens.next_if_eq(&Token::Close);
                        }
                        function_next = true;
                    }
                    _ if function_next => {
                        function_next = false;
                        body = true;
                        words.push(word);
                    }
                    _ => words.push(word),
                },
                Token::Word(word) if word.text == "}" => {
                    self.command(std::mem::take(&mut words), after_condition || body, piped);
                    body = false;
                    self.close(|frame| {
                        matches!(
                            frame,
                            Frame::Group | Frame::Function | Frame::Loop { brace: true, .. }
                        )
                    });
                }
                Token::Word(word) => words.push(word),
                Token::Array(name, items) => {
                    for item in &items {
                        self.mention(&item.text);
                    }
                    let literal: Option<Vec<String>> = items
                        .iter()
                        .map(|item| (!item.expands).then(|| item.text.clone()))
                        .collect();
                    match literal {
                        Some(literal)
                            if words.is_empty() && self.certain(after_condition, piped) =>
                        {
                            self.arrays.insert(name, literal);
                        }
                        _ => {
                            self.arrays.remove(&name);
                        }
                    }
                }
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
                    // A command of its own, which sets no option.
                    function_next = false;
                    self.mention(&text);
                }
                Token::Open | Token::Close
                    if self
                        .frames
                        .last()
                        .is_some_and(|open| open.frame == Frame::Case) => {}
                Token::Open if words.is_empty() && self.tokens.peek() == Some(&Token::Close) => {
                    // `() { ... }`: an anonymous function, which runs at once
                    // but can keep its options local (`localoptions`,
                    // `emulate -L`).
                    self.tokens.next();
                    function_next = true;
                }
                Token::Open if words.len() == 1 && self.tokens.peek() == Some(&Token::Close) => {
                    // `name()`: what follows is its body.
                    self.tokens.next();
                    let name = words.pop().expect("the function's name");
                    self.mention(&name.text);
                    function_next = true;
                }
                Token::Open => {
                    self.command(std::mem::take(&mut words), after_condition || body, piped);
                    body = false;
                    self.open(Frame::Subshell, after_condition, piped);
                }
                Token::Close => {
                    self.command(std::mem::take(&mut words), after_condition || body, piped);
                    body = false;
                    self.close(|frame| *frame == Frame::Subshell);
                }
                Token::End(end) => {
                    let pipe_after = matches!(end, End::Pipe | End::Background);
                    self.command(
                        std::mem::take(&mut words),
                        after_condition || body,
                        piped || pipe_after,
                    );
                    body = false;
                    after_condition = end == End::Condition;
                    piped = end == End::Pipe;
                }
            }
        }
        self.command(std::mem::take(&mut words), after_condition || body, piped);
        self.confused |= !self.frames.is_empty();
        self
    }
}

/// The events of zsh code `text` from the file at `place`, and whether the
/// check lost track of its structure, in which case none of its turn-offs
/// count. What the lexer could not read is a doubt, and so is a `source`, a
/// `.` or a `ZDOTDIR` setting the file's lines hold beyond those the walk
/// read; an option they name beyond those the tokens name counts as on
/// ([`backstop`]).
pub(super) fn events(text: &str, place: &str) -> (Vec<Event>, bool) {
    let (tokens, flaws) = lex(text);
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
    let walked = Walker {
        tokens: tokens.into_iter().peekable(),
        place,
        frames: Vec::new(),
        arrays: BTreeMap::new(),
        events: Vec::new(),
        may_stop: false,
        confused: false,
        sources: 0,
        zdotdirs: 0,
    }
    .walk();
    let mut events = walked.events;
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
    if named.zdotdirs > walked.zdotdirs {
        events.push(Event::Doubt(format!(
            "it cannot follow a ZDOTDIR that a line of {place} may set"
        )));
    }
    (events, walked.confused)
}
