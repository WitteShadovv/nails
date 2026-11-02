// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The tokens of zsh code: words with their quotes and escapes taken off and
//! their expansions kept as written, array assignments, and the places where
//! a command ends.

/// A word of zsh code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Word {
    /// Its text, quotes and escapes taken off; an expansion is kept as
    /// written.
    pub(super) text: String,
    /// Whether it holds an expansion: `$`, `${...}`, `$(...)` or a backquote.
    pub(super) expands: bool,
}

/// Where a command ends, and how.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum End {
    /// `;` or a newline.
    Line,
    /// `&&` or `||`: the next command may not run.
    Condition,
    /// `|`: the commands on both sides run in a pipeline.
    Pipe,
    /// `&`: the command before it runs in the background.
    Background,
}

/// A token of zsh code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Token {
    Word(Word),
    /// `NAME=(...)`: an array's name and its elements.
    Array(String, Vec<Word>),
    End(End),
    /// `(` and `)` outside a word.
    Open,
    Close,
    /// A redirection, whose target is the next word.
    Redirect,
}

/// Whether `text` is a shell variable's name.
pub(super) fn is_name(text: &str) -> bool {
    !text.is_empty()
        && !text.starts_with(|c: char| c.is_ascii_digit())
        && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Splits zsh code into [`Token`]s: comments dropped, a backslash before a
/// newline joining two lines, quotes and escapes taken off.
struct Lexer<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
    tokens: Vec<Token>,
    /// The word being read.
    word: Option<Word>,
}

impl Lexer<'_> {
    fn word(&mut self) -> &mut Word {
        self.word.get_or_insert_with(Word::default)
    }

    fn end_word(&mut self) {
        if let Some(word) = self.word.take() {
            self.tokens.push(Token::Word(word));
        }
    }

    /// Whether the next character ends a word: a blank, an operator or the
    /// end of the text.
    fn at_word_end(&mut self) -> bool {
        self.chars
            .peek()
            .is_none_or(|c| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')'))
    }

    /// Read `c` and what belongs to it into the current word.
    fn word_char(&mut self, c: char) {
        match c {
            '\\' => match self.chars.next() {
                Some('\n') | None => {}
                Some(escaped) => self.word().text.push(escaped),
            },
            '\'' => {
                self.word();
                for c in self.chars.by_ref() {
                    if c == '\'' {
                        break;
                    }
                    self.word.as_mut().expect("a word").text.push(c);
                }
            }
            '"' => {
                self.word();
                while let Some(c) = self.chars.next() {
                    match c {
                        '"' => break,
                        '\\' => match self.chars.next() {
                            Some('\n') | None => {}
                            Some(escaped) => self.word().text.push(escaped),
                        },
                        '$' | '`' => self.expansion(c),
                        c => self.word().text.push(c),
                    }
                }
            }
            '$' | '`' => self.expansion(c),
            '(' => {
                // A glob qualifier or the like, inside a word.
                self.word().text.push('(');
                self.balanced('(', ')');
            }
            c => self.word().text.push(c),
        }
    }

    /// Read an expansion that starts with `c` (`$` or a backquote) into the
    /// current word, as written.
    fn expansion(&mut self, c: char) {
        let word = self.word();
        word.expands = true;
        word.text.push(c);
        if c == '`' {
            while let Some(c) = self.chars.next() {
                self.word().text.push(c);
                match c {
                    '`' => break,
                    '\\' => {
                        if let Some(escaped) = self.chars.next() {
                            self.word().text.push(escaped);
                        }
                    }
                    _ => {}
                }
            }
            return;
        }
        match self.chars.peek().copied() {
            Some(open @ ('(' | '{')) => {
                self.chars.next();
                self.word().text.push(open);
                self.balanced(open, if open == '(' { ')' } else { '}' });
            }
            _ => {
                while let Some(c) = self.chars.next_if(|c| {
                    c.is_ascii_alphanumeric()
                        || matches!(c, '_' | '#' | '?' | '@' | '*' | '!' | '-')
                }) {
                    self.word().text.push(c);
                }
            }
        }
    }

    /// Read up to the `close` that matches an `open` already read, into the
    /// current word.
    fn balanced(&mut self, open: char, close: char) {
        let mut depth = 1;
        while let Some(c) = self.chars.next() {
            self.word().text.push(c);
            if c == '\\' {
                if let Some(escaped) = self.chars.next() {
                    self.word().text.push(escaped);
                }
            } else if c == open {
                depth += 1;
            } else if c == close {
                depth -= 1;
                if depth == 0 {
                    return;
                }
            }
        }
    }

    /// The elements of an array whose `(` was read, up to its `)`.
    fn array(&mut self) -> Vec<Word> {
        let mut items = Vec::new();
        while let Some(c) = self.chars.next() {
            match c {
                ')' => break,
                '#' if self.word.is_none() => self.comment(),
                c if c.is_whitespace() => {
                    if let Some(word) = self.word.take() {
                        items.push(word);
                    }
                }
                c => self.word_char(c),
            }
        }
        items.extend(self.word.take());
        items
    }

    /// Skip a comment, up to the newline that ends it.
    fn comment(&mut self) {
        while self.chars.next_if(|c| *c != '\n').is_some() {}
    }
}

/// The tokens of zsh code `text`.
pub(super) fn tokens(text: &str) -> Vec<Token> {
    let mut lexer = Lexer {
        chars: text.chars().peekable(),
        tokens: Vec::new(),
        word: None,
    };
    while let Some(c) = lexer.chars.next() {
        match c {
            '#' if lexer.word.is_none() => lexer.comment(),
            '\\' if lexer.chars.next_if_eq(&'\n').is_some() => {}
            '\n' | ';' => {
                lexer.end_word();
                lexer.tokens.push(Token::End(End::Line));
            }
            '&' => {
                lexer.end_word();
                let end = if lexer.chars.next_if_eq(&'&').is_some() {
                    End::Condition
                } else {
                    lexer.chars.next_if(|c| matches!(c, '|' | '!'));
                    End::Background
                };
                lexer.tokens.push(Token::End(end));
            }
            '|' => {
                lexer.end_word();
                let end = if lexer.chars.next_if_eq(&'|').is_some() {
                    End::Condition
                } else {
                    lexer.chars.next_if_eq(&'&');
                    End::Pipe
                };
                lexer.tokens.push(Token::End(end));
            }
            '(' => match lexer.word.take() {
                Some(word) if !word.expands && word.text.ends_with('=') => {
                    let name = word.text.trim_end_matches('=').to_string();
                    if is_name(&name) {
                        let items = lexer.array();
                        lexer.tokens.push(Token::Array(name, items));
                    } else {
                        lexer.word = Some(word);
                        lexer.word_char('(');
                    }
                }
                Some(word) if lexer.chars.peek() == Some(&')') => {
                    // `name()`: a function's definition.
                    lexer.tokens.push(Token::Word(word));
                    lexer.tokens.push(Token::Open);
                }
                Some(word) => {
                    lexer.word = Some(word);
                    lexer.word_char('(');
                }
                None => lexer.tokens.push(Token::Open),
            },
            ')' => {
                lexer.end_word();
                lexer.tokens.push(Token::Close);
            }
            '{' | '}' if lexer.word.is_none() && lexer.at_word_end() => {
                lexer.tokens.push(Token::Word(Word {
                    text: c.to_string(),
                    expands: false,
                }));
            }
            '<' | '>' => {
                lexer.end_word();
                while lexer
                    .chars
                    .next_if(|c| matches!(c, '<' | '>' | '&' | '|' | '!'))
                    .is_some()
                {}
                lexer.tokens.push(Token::Redirect);
            }
            c if c.is_whitespace() => lexer.end_word(),
            c => lexer.word_char(c),
        }
    }
    lexer.end_word();
    lexer.tokens
}
