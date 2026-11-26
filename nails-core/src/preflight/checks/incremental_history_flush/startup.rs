// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reading bash's startup files, and what they say about when it writes its
//! history.
//!
//! bash's files are read as a login shell and an interactive one read them,
//! together: `/etc/profile`, `/etc/bash.bashrc`, `/etc/bashrc`, then
//! `~/.bash_profile`, `~/.bash_login`, `~/.profile` and `~/.bashrc` in each
//! home the shell may run with. A line is read for the words a shell would
//! run, its comment dropped and its quotes taken off, and goes on in the next
//! one where what is left of it ends in a backslash. The reader
//! ([`uncommented`]) starts a comment at a `#` that starts a word, after a
//! space or a tab (bash's blanks) or an operator, in the file's code or a
//! command substitution's, and none in a quote, a backquote pair, a `${...}`,
//! arithmetic or a `(` it keeps open. A comment ends with its line, a
//! backslash at its end too. The reader's tests hold setups that bash 5.3
//! ran, and in those it drops only what bash read as a comment. Where it
//! cannot tell what bash reads, it keeps the text. Kept text can make the
//! check warn where bash runs nothing. It can also make the check pass where
//! bash runs the `PROMPT_COMMAND` assignment, as where bash reads the text as
//! a comment and the reader takes a quote in it for one that opens. A `case`
//! in a command substitution the reader may read otherwise than bash, which
//! can make the check pass too.

use std::path::{Path, PathBuf};

use crate::Filesystem;

/// The most of a startup file the check reads: 4 MiB, more than any startup
/// file holds.
const READ_LIMIT: u64 = 4 << 20;

/// A setting that makes a shell write each command line to its history file
/// as it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Write {
    /// The setting and where it is made, as the warning names them.
    pub what: String,
}

/// What the check read of a shell's startup files.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Scan {
    /// The settings found.
    pub writes: Vec<Write>,
    /// What the check could not follow, each as a clause of the warning
    /// (`it could not read ...`).
    pub doubts: Vec<String>,
}

/// The text of the startup file at `path`, read through `fs`: `Ok(None)` when
/// nothing is there, `Err` naming the file and why when something is there
/// that the check cannot read. Its type and size are looked up first, which
/// changes no access time, so no FIFO or device is opened.
pub(super) fn read<F: Filesystem>(fs: &F, path: &Path) -> Result<Option<String>, String> {
    let unread = |why: String| format!("{} ({why})", path.display());
    let failed = |error: crate::NailsError| {
        unread(
            error
                .io_kind()
                .map_or_else(|| error.to_string(), |kind| kind.to_string()),
        )
    };
    match fs.inode(path) {
        Ok(None) => return Ok(None),
        Ok(Some(_)) => {}
        Err(error) => return Err(failed(error)),
    }
    match fs.is_regular_file(path) {
        Ok(true) => {}
        Ok(false) => return Err(unread("not a regular file".to_string())),
        Err(error) => return Err(failed(error)),
    }
    match fs.file_size(path) {
        Ok(size) if size > READ_LIMIT => {
            return Err(unread(format!(
                "{size} bytes, more than a startup file holds"
            )));
        }
        Ok(_) => {}
        Err(error) => return Err(failed(error)),
    }
    fs.read_file_bytes(path)
        .map(|bytes| Some(String::from_utf8_lossy(&bytes).into_owned()))
        .map_err(failed)
}

/// What the reading of bash code is in ([`uncommented`]), as bash's reader
/// reads it: a construct it reads to its end before the word it stands in
/// goes on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Frame {
    /// The file's code, or a command substitution's or a process
    /// substitution's (`$(...)`, `<(...)`, `>(...)`), or the rest of a
    /// `((...)` that bash reads as a subshell (`((echo a); echo b)`), which
    /// bash parses as code, where a `#` that starts a word starts a comment;
    /// whether a `)` closes it, and how many `(` in it are open.
    Code { substitution: bool, depth: usize },
    /// The rest of a `$((...)` whose first `(` group a lone `)` closed
    /// (`$((echo a); echo b)`), a command substitution to bash, which reads
    /// it to its `)` as it reads that group, with quotes and no comment, and
    /// parses it as code only where it expands the word; how many `(` in it
    /// are open.
    Pair { depth: usize },
    /// `${...}`, to its `}`.
    Brace,
    /// Arithmetic: `$((...))` and `((...))` (a `command` of its own, after
    /// which a word starts), to the `))` that closes it, or `$[...]`, to its
    /// `]`; how many of the brackets it closes with are open in it.
    Arith {
        close: char,
        depth: usize,
        command: bool,
    },
    /// A backquote pair, to the next backquote no backslash escapes, in which
    /// nothing else opens.
    Backquote,
    /// `'...'`, where nothing is escaped.
    Single,
    /// `"..."`, where a backslash escapes the next character and `$(...)`,
    /// `${...}`, `$[...]` and a backquote pair open.
    Double,
    /// `$'...'`, where a backslash escapes the next character.
    Ansi,
}

/// The delimiter of a here-document that `chars` gives past its `<<`, and
/// whether its lines may start with tabs (`<<-`), as bash reads it: the next
/// word, past blanks, its quotes and backslashes taken off; `None` for a
/// here-string (`<<<`) or where no word follows.
fn delimiter(chars: &mut std::iter::Peekable<std::str::Chars>) -> Option<(String, bool)> {
    if chars.peek() == Some(&'<') {
        return None;
    }
    let tabs = chars.next_if_eq(&'-').is_some();
    while chars.next_if(|c| matches!(c, ' ' | '\t')).is_some() {}
    let mut word = String::new();
    let mut quote: Option<char> = None;
    while let Some(&c) = chars.peek() {
        match (quote, c) {
            (Some(open), c) if c == open => quote = None,
            (Some(_), c) => word.push(c),
            (None, '\'' | '"') => quote = Some(c),
            (None, '\\') => {
                chars.next();
                word.extend(chars.peek().copied());
            }
            (None, ' ' | '\t' | '\n' | ';' | '&' | '|' | '<' | '>' | '(' | ')') => break,
            (None, c) => word.push(c),
        }
        chars.next();
    }
    (!word.is_empty()).then_some((word, tabs))
}

/// `text`, bash code, with its comments dropped: a `#` that starts a word, at
/// a line's start or after a space, a tab or an operator (`;`, `&`, `|`, `(`,
/// `)`, not `<` or `>`), not escaped by a backslash, starts one in the file's
/// code and in a command substitution or a process substitution's, which
/// bash parses as code (`$(: # x)`), and none in a quote (`'...'`, `"..."`,
/// `$'...'`), a backquote pair, a `${...}` or arithmetic (`$((...))`,
/// `((...))`, `$[...]`), which bash reads to their end as part of a word
/// (`X=\`: #\``, `${X:- #}`). Its tests hold setups that bash 5.3 ran, and in
/// those the reader drops only what bash read as a comment. A `((` whose
/// first `(` group a lone `)` closes (`((echo a); echo b)`) bash reads as a
/// subshell that starts with that group: the reader reads the group as bash
/// first reads it, to its `)`, with quotes and no comment, and the rest as
/// code, where a comment starts. A `$((` whose first group a lone `)` closes
/// (`$((echo a); echo b)`) bash reads as a command substitution: it reads
/// the whole to its `)` with quotes and no comment, and parses it as code
/// only where it expands the word, so a `#` in it may start a comment or
/// none. Where the reader cannot tell what bash reads, it keeps the text: in
/// such a `$((...)`, in the first group of a `((`, where bash, running it as
/// code, may find a comment, after the `)` that ends such a subshell
/// (`((echo a); echo b)#`), in a `(` it keeps open, as an extended glob's or
/// a regular expression's group may be part of a word (`@(a| #b)`), and
/// after a `)` that closes nothing it saw open, as a `case` pattern's `)` may
/// end a `$(...)` or a `(` too soon for the reader. Kept text can make the
/// check warn where bash runs nothing. It can also make the check pass where
/// bash runs the `PROMPT_COMMAND` assignment: where bash reads the text as a
/// comment, a quote in it means nothing to bash, but the reader takes it for
/// one that opens, and may then start a comment inside a quote bash opened
/// (`(: #'` with `) ; X='); : #'; PROMPT_COMMAND=...` on the next line). A
/// `case` in a `$(...)` it may read otherwise than bash too, as a pattern's
/// `)` may end the `$(...)` for it. Where the `$(...)` stands in another
/// construct (a `"..."`, a `${...}`, a `$((...)` read as a command
/// substitution or an arithmetic command), a quote, a `}` or a `)` after the
/// pattern may then end that construct for the reader, and a `#` after it
/// may start a comment bash never starts
/// (`X="$(case x in x) echo "a #";; esac)"`,
/// `Y=${X:-$(case x in x) echo };; esac) #}`,
/// `(( $(case x in x) echo 1;; esac) # ))`).
/// A comment ends with its line, a backslash at its end too. bash keeps any
/// other white space in the word (a vertical tab, a no-break space), so a `#`
/// after one starts no comment. A here-document's body is text, in which no
/// `#` starts a comment and no quote opens one. bash reads a startup file and
/// what it sources as it reads a script, with comments whatever
/// `interactive_comments` holds.
fn uncommented(text: &str) -> String {
    let mut reader = BashReader {
        chars: text.chars().peekable(),
        kept: String::with_capacity(text.len()),
        frames: vec![Frame::Code {
            substitution: false,
            depth: 0,
        }],
        previous: None,
        bodies: Vec::new(),
    };
    while let Some(c) = reader.chars.next() {
        if !reader.read(c) {
            reader.kept.push(c);
            reader.previous = Some(c);
        }
    }
    reader.kept
}

/// The state of [`uncommented`]: the text left to read, what it keeps, what
/// it is in, the character before (where it is one that ends a word, the
/// next starts one), and the here-documents the line being read opened.
struct BashReader<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
    kept: String,
    frames: Vec<Frame>,
    previous: Option<char>,
    bodies: Vec<(String, bool)>,
}

impl BashReader<'_> {
    /// What it is in: the file's code at the bottom.
    fn frame(&self) -> Frame {
        *self.frames.last().expect("the file's code")
    }

    /// Read `c` and what it takes with it; `false` where `c` is to be kept as
    /// it is, as the character before the next.
    fn read(&mut self, c: char) -> bool {
        let frame = self.frame();
        // A backslash escapes the next character but in `'...'`.
        if c == '\\' && frame != Frame::Single {
            self.kept.push(c);
            if let Some(next) = self.chars.next() {
                self.kept.push(next);
            }
            self.previous = Some('\\');
            return true;
        }
        if c == '$' && self.dollar(frame) {
            return true;
        }
        match frame {
            Frame::Single | Frame::Ansi if c == '\'' => {
                self.frames.pop();
            }
            Frame::Backquote if c == '`' => {
                self.frames.pop();
            }
            Frame::Double => match c {
                '"' => {
                    self.frames.pop();
                }
                '`' => self.frames.push(Frame::Backquote),
                _ => {}
            },
            Frame::Brace => match c {
                '\'' => self.frames.push(Frame::Single),
                '"' => self.frames.push(Frame::Double),
                '`' => self.frames.push(Frame::Backquote),
                '}' => {
                    self.frames.pop();
                }
                _ => {}
            },
            Frame::Arith {
                close,
                depth,
                command,
            } => return self.arith(c, close, depth, command),
            Frame::Pair { depth } => return self.pair(c, depth),
            Frame::Single | Frame::Ansi | Frame::Backquote => {}
            Frame::Code {
                substitution,
                depth,
            } => return self.code(c, substitution, depth),
        }
        false
    }

    /// What `$` opens where expansions are read (not in `'...'`, `$'...'` or
    /// a backquote pair): `$(...)`, `$((...))`, `${...}`, `$[...]` and, but in
    /// `"..."`, `$'...'`; `false` where it opens none.
    fn dollar(&mut self, frame: Frame) -> bool {
        if matches!(frame, Frame::Single | Frame::Backquote | Frame::Ansi) {
            return false;
        }
        let arith = |close| Frame::Arith {
            close,
            depth: 0,
            command: false,
        };
        let (opened, shown) = match self.chars.peek() {
            Some('(') => {
                self.chars.next();
                if self.chars.next_if_eq(&'(').is_some() {
                    (arith(')'), "$((")
                } else {
                    let code = Frame::Code {
                        substitution: true,
                        depth: 0,
                    };
                    (code, "$(")
                }
            }
            Some('{') => {
                self.chars.next();
                (Frame::Brace, "${")
            }
            Some('[') => {
                self.chars.next();
                (arith(']'), "$[")
            }
            Some('\'') if frame != Frame::Double => {
                self.chars.next();
                (Frame::Ansi, "$'")
            }
            _ => return false,
        };
        self.kept.push_str(shown);
        self.frames.push(opened);
        self.previous = Some('(');
        true
    }

    /// Read `c` in arithmetic that closes with `close` and has `depth` of its
    /// brackets open in it, a `command` of its own or not.
    fn arith(&mut self, c: char, close: char, depth: usize, command: bool) -> bool {
        let open = if close == ')' { '(' } else { '[' };
        match c {
            '\'' => self.frames.push(Frame::Single),
            '"' => self.frames.push(Frame::Double),
            '`' => self.frames.push(Frame::Backquote),
            c if c == open || (c == close && depth > 0) => {
                let depth = if c == open { depth + 1 } else { depth - 1 };
                *self.frames.last_mut().expect("the arithmetic") = Frame::Arith {
                    close,
                    depth,
                    command,
                };
            }
            c if c == close => {
                self.frames.pop();
                self.kept.push(c);
                if close == ')' {
                    if let Some(next) = self.chars.next_if_eq(&')') {
                        self.kept.push(next);
                    } else if command {
                        // A lone `)` closes no arithmetic: bash reads the
                        // `((` as a subshell with a `(` group first, which
                        // the `)` closed (`((echo a); echo b)`), and the rest
                        // to its own `)` as code.
                        self.frames.push(Frame::Code {
                            substitution: true,
                            depth: 0,
                        });
                        self.previous = Some(')');
                        return true;
                    } else {
                        // Nor does it in a `$((`: bash reads the whole as a
                        // command substitution, to its own `)` as it read
                        // the group, with quotes and no comment, and as code
                        // only where it expands the word, so the reader
                        // starts no comment in it (`$((echo a); : #)`),
                        // unless a `case` in a `$(...)` in it ends it too
                        // soon (see `uncommented`).
                        self.frames.push(Frame::Pair { depth: 0 });
                        self.previous = Some(')');
                        return true;
                    }
                }
                // `$((1))#x` is one word, `((1)) #x` a comment.
                self.previous = Some(if command { ')' } else { 'x' });
                return true;
            }
            _ => {}
        }
        false
    }

    /// Read `c` in the rest of a `$((...)` that bash reads as a command
    /// substitution, with `depth` of its `(` open.
    fn pair(&mut self, c: char, depth: usize) -> bool {
        match c {
            '\'' => self.frames.push(Frame::Single),
            '"' => self.frames.push(Frame::Double),
            '`' => self.frames.push(Frame::Backquote),
            c if c == '(' || (c == ')' && depth > 0) => {
                let depth = if c == '(' { depth + 1 } else { depth - 1 };
                *self.frames.last_mut().expect("the pair") = Frame::Pair { depth };
            }
            ')' => {
                // The substitution is part of a word that goes on (`$(x)#y`).
                self.frames.pop();
                self.kept.push(c);
                self.previous = Some('x');
                return true;
            }
            _ => {}
        }
        false
    }

    /// Read `c` in code, the file's or a substitution's, with `depth` of its
    /// `(` open.
    fn code(&mut self, c: char, substitution: bool, depth: usize) -> bool {
        let word_start = self
            .previous
            .is_none_or(|p| matches!(p, '\n' | ' ' | '\t' | ';' | '&' | '|' | '(' | ')'));
        let set_depth = |frames: &mut Vec<Frame>, depth| {
            *frames.last_mut().expect("the code") = Frame::Code {
                substitution,
                depth,
            };
        };
        match c {
            '\'' => self.frames.push(Frame::Single),
            '"' => self.frames.push(Frame::Double),
            '`' => self.frames.push(Frame::Backquote),
            // In a `(` the reader keeps open, which may be an extended glob's
            // or a regular expression's group (`@(a| #b)`,
            // `[[ $x =~ ( #) ]]`) that bash reads as part of a word, a `#`
            // starts none: the text stays.
            '#' if word_start && depth == 0 => {
                while self.chars.next_if(|c| *c != '\n').is_some() {}
                return true;
            }
            '<' | '>' if self.chars.peek() == Some(&'(') => {
                // A process substitution.
                self.chars.next();
                self.kept.push(c);
                self.kept.push('(');
                self.frames.push(Frame::Code {
                    substitution: true,
                    depth: 0,
                });
                self.previous = Some('(');
                return true;
            }
            '(' if word_start && self.chars.peek() == Some(&'(') => {
                // An arithmetic command.
                self.chars.next();
                self.kept.push_str("((");
                self.frames.push(Frame::Arith {
                    close: ')',
                    depth: 0,
                    command: true,
                });
                self.previous = Some('(');
                return true;
            }
            '(' => set_depth(&mut self.frames, depth + 1),
            ')' if depth > 0 => set_depth(&mut self.frames, depth - 1),
            ')' => {
                // The substitution is part of a word that goes on (`$(x)#y`).
                // One that closes nothing the reader saw open may close a
                // substitution a `case` pattern's `)` ended too soon
                // (`$(case x in x) :;; esac)#y`): a `#` after it starts no
                // comment either.
                if substitution {
                    self.frames.pop();
                }
                self.kept.push(c);
                self.previous = Some('x');
                return true;
            }
            '<' if self.chars.peek() == Some(&'<') => {
                self.kept.push_str("<<");
                self.chars.next();
                let mut ahead = self.chars.clone();
                if let Some(body) = delimiter(&mut ahead) {
                    self.bodies.push(body);
                }
                self.previous = Some('<');
                return true;
            }
            '\n' if !self.bodies.is_empty() => {
                self.kept.push(c);
                self.here_documents();
                self.previous = Some('\n');
                return true;
            }
            _ => {}
        }
        false
    }

    /// The bodies of the here-documents the line opened, in order, each to
    /// the line that is its delimiter, kept as text.
    fn here_documents(&mut self) {
        for (word, tabs) in std::mem::take(&mut self.bodies) {
            loop {
                let mut line = String::new();
                while let Some(next) = self.chars.next_if(|c| *c != '\n') {
                    line.push(next);
                }
                let ended = self.chars.next().is_some();
                self.kept.push_str(&line);
                if ended {
                    self.kept.push('\n');
                }
                let shown = if tabs {
                    line.trim_start_matches('\t')
                } else {
                    line.as_str()
                };
                if shown == word || !ended {
                    break;
                }
            }
        }
    }
}

/// The words of a line of shell code, its comment dropped already
/// ([`uncommented`]) and its quotes, braces and backslashes taken off, split
/// at blanks and at `=`, with `;` standing for each place where a command can
/// end (`;`, `&`, `|`, parentheses and backquotes).
fn words(line: &str) -> Vec<String> {
    fn end(word: &mut String, words: &mut Vec<String>) {
        if !word.is_empty() {
            words.push(std::mem::take(word));
        }
    }
    let mut words = Vec::new();
    let mut word = String::new();
    for c in line.chars() {
        match c {
            '\'' | '"' | '\\' | '{' | '}' => {}
            ';' | '&' | '|' | '(' | ')' | '`' => {
                end(&mut word, &mut words);
                words.push(";".to_string());
            }
            c if c.is_whitespace() || c == '=' => end(&mut word, &mut words),
            c => word.push(c),
        }
    }
    end(&mut word, &mut words);
    words
}

/// The lines of bash code `text`, its comments dropped ([`uncommented`]),
/// each with the lines it goes on in: one that ends in a backslash goes on in
/// the next, as bash joins them; a comment ends with its line, as a backslash
/// in it escapes nothing.
fn joined_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut open: Option<String> = None;
    for line in uncommented(text).split('\n') {
        let mut joined = open.take().unwrap_or_default();
        joined.push_str(line);
        match joined.strip_suffix('\\') {
            Some(rest) if rest.len() + 1 == joined.len() => open = Some(rest.to_string()),
            _ => lines.push(joined),
        }
    }
    lines.extend(open);
    lines
}

/// The history command a bash startup file's `text` runs from
/// `PROMPT_COMMAND`: `history -a` or `history -w`, when the file names
/// `PROMPT_COMMAND` and runs one of them anywhere, its lines joined as bash
/// joins them ([`joined_lines`]).
fn prompt_command_writes(text: &str) -> Option<&'static str> {
    let mut prompt_command = false;
    let mut found = None;
    for line in joined_lines(text) {
        let line = line.as_str();
        prompt_command |= line.contains("PROMPT_COMMAND");
        let words = words(line);
        for pair in words.windows(2) {
            if pair[0] == "history"
                && let Some(flags) = pair[1].strip_prefix('-')
            {
                if flags.contains('a') {
                    found.get_or_insert("history -a");
                } else if flags.contains('w') {
                    found.get_or_insert("history -w");
                }
            }
        }
    }
    found.filter(|_| prompt_command)
}

/// What bash's startup files below `/etc` and in `homes` turn on, through
/// `fs`.
pub(super) fn bash<F: Filesystem>(fs: &F, homes: &[PathBuf]) -> Scan {
    let mut scan = Scan::default();
    let system = ["/etc/profile", "/etc/bash.bashrc", "/etc/bashrc"].map(PathBuf::from);
    let user = homes.iter().flat_map(|home| {
        [".bash_profile", ".bash_login", ".profile", ".bashrc"].map(|file| home.join(file))
    });
    for path in system.into_iter().chain(user) {
        match read(fs, &path) {
            Ok(Some(text)) => {
                if let Some(command) = prompt_command_writes(&text) {
                    scan.writes.push(Write {
                        what: format!("{} runs `{command}` from PROMPT_COMMAND", path.display()),
                    });
                }
            }
            Ok(None) => {}
            Err(why) => scan.doubts.push(format!("it could not read {why}")),
        }
    }
    scan
}
