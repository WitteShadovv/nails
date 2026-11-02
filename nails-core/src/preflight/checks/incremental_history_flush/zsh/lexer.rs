// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The tokens of zsh code: words with their quotes and escapes taken off and
//! their expansions kept as written, array assignments, arithmetic commands,
//! the places where a command ends, and the bodies of here-documents, which
//! are text, not code.

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
    /// The body of a here-document: text a command reads, not code.
    Text(String),
    /// The delimiter of a here-document whose body runs to the end of the
    /// text without the line that ends it, or that has none.
    Unended(String),
    /// What opens a quote, an expansion or another construct that runs to
    /// the end of the text without closing, as a message names it: all that
    /// follows it is in its word.
    Unclosed(String),
    /// What opens an expansion or a command substitution that holds what
    /// the lexer cannot read as zsh does, and what that is, as a message
    /// names them.
    Unfollowed(String, String),
    /// An arithmetic command, `(( ... ))`, as written: no `<<` in it opens
    /// a here-document.
    Arithmetic(String),
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
    /// The here-documents the line read so far opens, whose bodies start
    /// on the next line: each one's delimiter, and whether `<<-` lets its
    /// lines start with tabs.
    heredocs: Vec<(String, bool)>,
    /// What opens the construct that runs to the end of the text, once one
    /// does.
    unclosed: Option<String>,
    /// What opens the first expansion that holds what the lexer cannot read
    /// as zsh does, and what that is.
    unfollowed: Option<(String, String)>,
}

/// What a quoted or nested part of a word that [`Lexer::balanced`] reads is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Nest {
    /// The commands of `$(...)`, of a process substitution or of a subshell
    /// in one, which end at its `)`.
    Command,
    /// Parentheses that hold no commands, which end at their `)`: a glob
    /// qualifier's, or an arithmetic expression's, `((...))` or `$((...))`.
    Group,
    /// `${...}`, which ends at its `}`; `quoted` inside double quotes, where
    /// a `'` quotes nothing.
    Brace {
        quoted: bool,
    },
    Double,
    Single,
    /// `$'...'`, in which a backslash escapes the next character, so only a
    /// `'` without one ends it.
    Ansi,
    Back,
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
                let mut closed = false;
                for c in self.chars.by_ref() {
                    if c == '\'' {
                        closed = true;
                        break;
                    }
                    self.word.as_mut().expect("a word").text.push(c);
                }
                if !closed {
                    self.unclosed("`'`");
                }
            }
            '"' => {
                self.word();
                let mut closed = false;
                while let Some(c) = self.chars.next() {
                    match c {
                        '"' => {
                            closed = true;
                            break;
                        }
                        '\\' => match self.chars.next() {
                            Some('\n') | None => {}
                            Some(escaped) => self.word().text.push(escaped),
                        },
                        '$' | '`' => self.expansion(c, true),
                        c => self.word().text.push(c),
                    }
                }
                if !closed {
                    self.unclosed("`\"`");
                }
            }
            '$' | '`' => self.expansion(c, false),
            '(' => {
                // A glob qualifier or the like, inside a word.
                self.word().text.push('(');
                if !self.balanced(&[Nest::Group], "`(`") {
                    self.unclosed("`(`");
                }
            }
            c => self.word().text.push(c),
        }
    }

    /// Note that what `opener` opens holds `what`, which the lexer cannot
    /// read as zsh does.
    fn unfollowed(&mut self, opener: &str, what: &str) {
        self.unfollowed
            .get_or_insert_with(|| (opener.to_string(), what.to_string()));
    }

    /// Note that what `opener` opens runs to the end of the text, unless
    /// something that holds it does too.
    fn unclosed(&mut self, opener: &str) {
        self.unclosed.get_or_insert_with(|| opener.to_string());
    }

    /// Read an expansion that starts with `c` (`$` or a backquote) into the
    /// current word, as written; `quoted` inside double quotes.
    fn expansion(&mut self, c: char, quoted: bool) {
        let word = self.word();
        word.expands = true;
        word.text.push(c);
        if c == '`' {
            if !self.balanced(&[Nest::Back], "backquote") {
                self.unclosed("backquote");
            }
            return;
        }
        if !quoted && self.chars.next_if_eq(&'\'').is_some() {
            self.word().text.push('\'');
            if !self.balanced(&[Nest::Ansi], "`$'`") {
                self.unclosed("`$'`");
            }
            return;
        }
        match self.chars.peek().copied() {
            Some(open @ ('(' | '{')) => {
                self.chars.next();
                self.word().text.push(open);
                let (nests, opener): (&[Nest], _) = if open == '{' {
                    if self
                        .chars
                        .peek()
                        .is_some_and(|c| c.is_whitespace() || *c == '|')
                    {
                        self.unfollowed("`${`", "a command");
                    }
                    (&[Nest::Brace { quoted }], "`${`")
                } else if self.chars.next_if_eq(&'(').is_some() {
                    self.word().text.push('(');
                    (&[Nest::Group, Nest::Group], "`$((`")
                } else {
                    (&[Nest::Command], "`$(`")
                };
                if !self.balanced(nests, opener) {
                    self.unclosed(opener);
                }
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

    /// Read the rest of `nests`, whose openings were read, the innermost
    /// last, into the current word as written, up to what closes them: past
    /// what the quotes and the expansions nested in them hold, so a `)` or
    /// `}` in quotes closes nothing, and in a command substitution past its
    /// comments and here-documents too. What zsh reads otherwise than the
    /// lexer does, a `case` in a command substitution among it, is noted as
    /// unfollowed in what `opener` opens. Whether they close before the end
    /// of the text.
    fn balanced(&mut self, nests: &[Nest], opener: &str) -> bool {
        let mut stack = nests.to_vec();
        // In the commands of a command substitution: whether the next
        // character starts a word, the word being read while nothing but
        // letters, digits and `_` are in it, and the here-documents the line
        // read so far opens.
        let mut start = true;
        let mut bare = Some(String::new());
        let mut heredocs: Vec<(String, bool)> = Vec::new();
        while let Some(&inner) = stack.last() {
            let Some(c) = self.chars.next() else {
                return false;
            };
            self.word().text.push(c);
            if inner == Nest::Command {
                let boundary =
                    c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')' | '<' | '>');
                if boundary {
                    if bare.as_deref() == Some("case") {
                        // Its patterns end in a `)` that closes nothing.
                        self.unfollowed(opener, "a `case`");
                    }
                    bare = Some(String::new());
                } else if c.is_ascii_alphanumeric() || c == '_' {
                    if let Some(word) = bare.as_mut() {
                        word.push(c);
                    }
                } else {
                    bare = None;
                }
                let at_start = std::mem::replace(&mut start, boundary);
                match c {
                    '#' if at_start => {
                        // A comment, to the end of its line.
                        while let Some(c) = self.chars.next_if(|c| *c != '\n') {
                            self.word().text.push(c);
                        }
                        continue;
                    }
                    '\n' => {
                        if !self.heredoc_lines(std::mem::take(&mut heredocs)) {
                            return false;
                        }
                        continue;
                    }
                    '<' if self.chars.peek() == Some(&'<') => {
                        self.chars.next();
                        self.word().text.push('<');
                        if self.chars.next_if_eq(&'<').is_some() {
                            // A here-string: its word is the text.
                            self.word().text.push('<');
                        } else {
                            let tabs = self.chars.next_if_eq(&'-').is_some();
                            let delimiter = self.delimiter();
                            self.word().text.push_str(&delimiter);
                            if delimiter.is_empty() {
                                self.unfollowed(opener, "a here-document with no word to end it");
                            } else {
                                heredocs.push((delimiter, tabs));
                            }
                        }
                        continue;
                    }
                    '(' if at_start => {
                        // A subshell, or an arithmetic command, `((...))`.
                        if self.chars.next_if_eq(&'(').is_some() {
                            self.word().text.push('(');
                            stack.extend([Nest::Group, Nest::Group]);
                        } else {
                            stack.push(Nest::Command);
                            start = true;
                        }
                        continue;
                    }
                    _ => {}
                }
            }
            let quoted = matches!(inner, Nest::Brace { quoted: true });
            match (inner, c) {
                (Nest::Single | Nest::Ansi, '\'') | (Nest::Back, '`') | (Nest::Double, '"') => {
                    stack.pop();
                }
                (Nest::Single, _) => {}
                (_, '\\') => {
                    let escaped = self.chars.next();
                    self.word().text.extend(escaped);
                }
                (Nest::Back | Nest::Ansi, _) => {}
                (_, '`') => stack.push(Nest::Back),
                (_, '$') => {
                    if self.chars.next_if_eq(&'(').is_some() {
                        self.word().text.push('(');
                        if self.chars.next_if_eq(&'(').is_some() {
                            self.word().text.push('(');
                            stack.extend([Nest::Group, Nest::Group]);
                        } else {
                            stack.push(Nest::Command);
                            start = true;
                            bare = Some(String::new());
                        }
                    } else if self.chars.next_if_eq(&'{').is_some() {
                        self.word().text.push('{');
                        if self
                            .chars
                            .peek()
                            .is_some_and(|c| c.is_whitespace() || *c == '|')
                        {
                            self.unfollowed(opener, "a command");
                        }
                        stack.push(Nest::Brace {
                            quoted: quoted || inner == Nest::Double,
                        });
                    } else if !quoted
                        && inner != Nest::Double
                        && self.chars.next_if_eq(&'\'').is_some()
                    {
                        // `$'...'`; in double quotes a `$` and a `'`.
                        self.word().text.push('\'');
                        stack.push(Nest::Ansi);
                    }
                }
                (Nest::Double, _) => {}
                (_, '"') => stack.push(Nest::Double),
                (_, '\'') if !quoted => stack.push(Nest::Single),
                (Nest::Command | Nest::Group, '(') => stack.push(Nest::Group),
                (Nest::Command | Nest::Group, ')') | (Nest::Brace { .. }, '}') => {
                    stack.pop();
                }
                (Nest::Brace { .. }, '{') => stack.push(Nest::Brace { quoted }),
                _ => {}
            }
        }
        true
    }

    /// Read the bodies of `heredocs`, opened in a command substitution on the
    /// line just read, into the current word as written, each up to the line
    /// that holds only its delimiter. Whether they end before the end of the
    /// text.
    fn heredoc_lines(&mut self, heredocs: Vec<(String, bool)>) -> bool {
        for (delimiter, tabs) in heredocs {
            loop {
                let mut line = String::new();
                let mut ended = false;
                for c in self.chars.by_ref() {
                    if c == '\n' {
                        ended = true;
                        break;
                    }
                    line.push(c);
                }
                let word = self.word();
                word.text.push_str(&line);
                if ended {
                    word.text.push('\n');
                }
                let shown = if tabs {
                    line.trim_start_matches('\t')
                } else {
                    &line
                };
                if shown == delimiter {
                    break;
                }
                if !ended {
                    return false;
                }
            }
        }
        true
    }

    /// The elements of an array whose `(` was read, up to its `)`.
    fn array(&mut self) -> Vec<Word> {
        let mut items = Vec::new();
        let mut closed = false;
        while let Some(c) = self.chars.next() {
            match c {
                ')' => {
                    closed = true;
                    break;
                }
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
        if !closed {
            self.unclosed("`(`");
        }
        items
    }

    /// Read the delimiter of a here-document, after `<<` or `<<-`: a word,
    /// its quotes and escapes taken off.
    fn delimiter(&mut self) -> String {
        while self.chars.next_if(|c| *c == ' ' || *c == '\t').is_some() {}
        let mut delimiter = String::new();
        while let Some(c) = self.chars.next_if(|c| {
            !c.is_whitespace() && !matches!(c, ';' | '&' | '|' | '(' | ')' | '<' | '>')
        }) {
            if !matches!(c, '\'' | '"' | '\\') {
                delimiter.push(c);
            }
        }
        delimiter
    }

    /// Read the bodies of the here-documents the line just ended opened,
    /// each up to the line that holds only its delimiter; one that runs to
    /// the end of the text is [`Token::Unended`] too.
    fn heredoc_bodies(&mut self) {
        for (delimiter, tabs) in std::mem::take(&mut self.heredocs) {
            let mut body = String::new();
            let closed = loop {
                let mut line = String::new();
                let mut ended = false;
                for c in self.chars.by_ref() {
                    if c == '\n' {
                        ended = true;
                        break;
                    }
                    line.push(c);
                }
                let shown = if tabs {
                    line.trim_start_matches('\t')
                } else {
                    &line
                };
                if shown == delimiter {
                    break true;
                }
                body.push_str(&line);
                if !ended {
                    break false;
                }
                body.push('\n');
            };
            self.tokens.push(Token::Text(body));
            if !closed {
                self.tokens.push(Token::Unended(delimiter));
            }
        }
    }

    /// Read an arithmetic command whose first `(` was read and whose second
    /// is next, up to the `))` that closes it. `None`, with nothing read,
    /// when its parentheses do not close as one `))`, as those of two
    /// subshells, `((a); b)`, do.
    fn arithmetic(&mut self) -> Option<String> {
        let chars = self.chars.clone();
        let unclosed = self.unclosed.clone();
        let unfollowed = self.unfollowed.clone();
        self.chars.next();
        self.word = Some(Word {
            text: "((".to_string(),
            expands: true,
        });
        if self.balanced(&[Nest::Group], "`((`") && self.chars.next_if_eq(&')').is_some() {
            let mut text = self.word.take().expect("the arithmetic command").text;
            text.push(')');
            return Some(text);
        }
        self.word = None;
        self.chars = chars;
        self.unclosed = unclosed;
        self.unfollowed = unfollowed;
        None
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
        heredocs: Vec::new(),
        unclosed: None,
        unfollowed: None,
    };
    while let Some(c) = lexer.chars.next() {
        match c {
            '#' if lexer.word.is_none() => lexer.comment(),
            '\\' if lexer.chars.next_if_eq(&'\n').is_some() => {}
            '\n' => {
                lexer.end_word();
                lexer.tokens.push(Token::End(End::Line));
                lexer.heredoc_bodies();
            }
            ';' => {
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
                None => match lexer.chars.peek() {
                    Some('(') => match lexer.arithmetic() {
                        Some(text) => lexer.tokens.push(Token::Arithmetic(text)),
                        None => lexer.tokens.push(Token::Open),
                    },
                    _ => lexer.tokens.push(Token::Open),
                },
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
            '<' | '>' if lexer.chars.peek() == Some(&'(') => {
                // A process substitution, `<(...)` or `>(...)`: an expansion.
                lexer.chars.next();
                let word = lexer.word();
                word.expands = true;
                word.text.push(c);
                word.text.push('(');
                let opener = format!("`{c}(`");
                if !lexer.balanced(&[Nest::Command], &opener) {
                    lexer.unclosed(&opener);
                }
            }
            '<' if lexer.chars.peek() == Some(&'<') => {
                lexer.end_word();
                lexer.chars.next();
                if lexer.chars.next_if_eq(&'<').is_some() {
                    // A here-string: its word is the text.
                    lexer.tokens.push(Token::Redirect);
                } else {
                    let tabs = lexer.chars.next_if_eq(&'-').is_some();
                    let delimiter = lexer.delimiter();
                    if delimiter.is_empty() {
                        // No word to end it: zsh cannot read it either.
                        lexer.tokens.push(Token::Unended(delimiter));
                    } else {
                        lexer.heredocs.push((delimiter, tabs));
                    }
                }
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
    // A here-document opened on the last line, which has no body at all.
    for (delimiter, _) in std::mem::take(&mut lexer.heredocs) {
        lexer.tokens.push(Token::Unended(delimiter));
    }
    lexer
        .tokens
        .extend(lexer.unclosed.take().map(Token::Unclosed));
    lexer.tokens.extend(
        lexer
            .unfollowed
            .take()
            .map(|(opener, what)| Token::Unfollowed(opener, what)),
    );
    lexer.tokens
}
