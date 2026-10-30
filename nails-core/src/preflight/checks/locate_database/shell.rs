// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The updatedb commands a piece of shell runs, where that can be told
//! without running it.
//!
//! cron hands a job's command to `/bin/sh`, and the files of
//! `/etc/cron.daily` and its siblings are shell scripts. [`updatedb_runs`]
//! reads such text as a POSIX shell splits it, as far as that needs no
//! expansion:
//!
//! - the text falls into simple commands at newlines and at `;`, `&`, `|`,
//!   `(` and `)` outside quotes (so at `&&` and `||` too), and at a `{` or `}`
//!   that stands as a word of its own. A `#` that starts a word starts a
//!   comment, which runs to the end of the line;
//! - words are separated by blanks. `'…'` is taken as it is, `\` outside
//!   quotes takes the next character as it is, and a `\` before a newline
//!   joins the lines;
//! - a redirection (`>`, `>>`, `<`, `2>&1`, `&>`, …) and its target are no
//!   words of the command, and the `NAME=value` words a command starts with
//!   are its environment. The words `if`, `then`, `elif`, `else`, `while`,
//!   `until`, `do`, `!` and `time` in front of a command are left out too;
//! - in a simple command the first word whose file name is an updatedb's
//!   ([`super::exec::is_updatedb`]) is the program, whatever runs it (`nice`,
//!   `ionice`, `flock`, `sudo`, `exec`, …), and the words after it are its
//!   arguments. A command that only asks about a program (`test`, `[`, `[[`,
//!   `which`, `type`, `command -v`, `echo`, `printf`) runs none. `$(…)` ends
//!   a word and `)` a command, so the command inside is read as one too.
//!
//! The rest is expansion, which only running the shell would tell: a `$` or
//! `` ` `` (a variable, a backquoted command), a `"…"` that holds `$`, `` ` ``
//! or `\`, a glob, a `~` that starts a word or a here document. Where one of
//! them is the program or an argument of an updatedb, or where a command names
//! updatedb anywhere else (in a variable, inside a quoted command for
//! `sh -c`), that command is one NAILS cannot tell about: a variable is not
//! followed. Text NAILS cannot split into commands is one too.

use super::exec::{ExecCommand, is_updatedb, mentions_updatedb};

/// One word of a command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Word {
    /// The word as the shell passes it on, where it needs no expansion.
    text: Vec<u8>,
    /// Whether the shell expands something in it, so `text` is not what it
    /// passes on.
    expands: bool,
    /// Whether any of it was quoted or escaped: such a word is no keyword
    /// or redirection.
    quoted: bool,
    /// Whether an unquoted `[` is open in it, which a later `]` makes a
    /// glob.
    bracket: bool,
    /// How many bytes from its start no quote or backslash took.
    unquoted: usize,
}

/// The words a command can start with that leave it the same command.
const KEYWORDS: &[&[u8]] = &[
    b"if", b"then", b"elif", b"else", b"while", b"until", b"do", b"!", b"time",
];

/// Programs that only ask about another one, by its name or path.
const QUESTIONS: &[&[u8]] = &[b"test", b"[", b"[[", b"which", b"type", b"echo", b"printf"];

/// The simple commands of `text`, each as its words, or why they cannot be
/// told.
fn commands(text: &[u8]) -> Result<Vec<Vec<Word>>, String> {
    let mut out = Vec::new();
    let mut command: Vec<Word> = Vec::new();
    let mut word: Option<Word> = None;
    let mut redirect_target = false;
    let mut at = 0;
    // Ends the word being read; a word that is a redirection's target is
    // dropped.
    let end_word = |word: &mut Option<Word>, command: &mut Vec<Word>, target: &mut bool| {
        if let Some(done) = word.take() {
            if std::mem::take(target) {
                return;
            }
            command.push(done);
        }
    };
    while let Some(&byte) = text.get(at) {
        at += 1;
        match byte {
            b' ' | b'\t' | b'\r' => end_word(&mut word, &mut command, &mut redirect_target),
            b'\n' | b';' | b'&' | b'|' | b'(' | b')' => {
                if byte == b'&' && text.get(at) == Some(&b'>') {
                    // `&>file`: both outputs to a file, a redirection the
                    // `>` that follows reads.
                    end_word(&mut word, &mut command, &mut redirect_target);
                    continue;
                }
                end_word(&mut word, &mut command, &mut redirect_target);
                if redirect_target {
                    return Err("a redirection without its target".to_string());
                }
                out.push(std::mem::take(&mut command));
            }
            b'#' if word.is_none() => {
                while text.get(at).is_some_and(|&byte| byte != b'\n') {
                    at += 1;
                }
            }
            b'<' | b'>' => {
                // An fd number right before the operator belongs to it.
                if word
                    .as_ref()
                    .is_some_and(|w| !w.quoted && w.text.iter().all(u8::is_ascii_digit))
                {
                    word = None;
                } else {
                    end_word(&mut word, &mut command, &mut redirect_target);
                }
                if byte == b'<' && text.get(at) == Some(&b'<') {
                    return Err("a here document".to_string());
                }
                while text
                    .get(at)
                    .is_some_and(|&next| matches!(next, b'<' | b'>' | b'|'))
                {
                    at += 1;
                }
                if text.get(at) == Some(&b'&') {
                    // `2>&1`, `>&-`: a descriptor, which is a word too.
                    at += 1;
                }
                redirect_target = true;
            }
            b'\'' => {
                let w = word.get_or_insert_with(Word::default);
                w.quoted = true;
                loop {
                    match text.get(at) {
                        None => return Err("a quote without its partner".to_string()),
                        Some(b'\'') => {
                            at += 1;
                            break;
                        }
                        Some(&inner) => {
                            w.text.push(inner);
                            at += 1;
                        }
                    }
                }
            }
            b'"' => {
                let w = word.get_or_insert_with(Word::default);
                w.quoted = true;
                loop {
                    match text.get(at) {
                        None => return Err("a quote without its partner".to_string()),
                        Some(b'"') => {
                            at += 1;
                            break;
                        }
                        Some(&inner) => {
                            // The shell expands `$` and `` ` `` here, and
                            // `\` escapes some characters.
                            if matches!(inner, b'$' | b'`' | b'\\') {
                                w.expands = true;
                            }
                            w.text.push(inner);
                            at += 1;
                        }
                    }
                }
            }
            b'\\' => match text.get(at) {
                Some(b'\n') => at += 1,
                Some(&next) => {
                    let w = word.get_or_insert_with(Word::default);
                    w.quoted = true;
                    w.text.push(next);
                    at += 1;
                }
                None => return Err("a backslash at the end".to_string()),
            },
            _ => {
                let starts = word.is_none();
                let w = word.get_or_insert_with(Word::default);
                match byte {
                    b'$' | b'`' | b'*' | b'?' => w.expands = true,
                    b'~' if starts => w.expands = true,
                    // A `[` alone, the test command, is no glob.
                    b'[' => w.bracket = true,
                    b']' if w.bracket => w.expands = true,
                    _ => {}
                }
                if w.unquoted == w.text.len() {
                    w.unquoted += 1;
                }
                w.text.push(byte);
            }
        }
    }
    end_word(&mut word, &mut command, &mut redirect_target);
    if redirect_target {
        return Err("a redirection without its target".to_string());
    }
    out.push(command);
    Ok(out
        .into_iter()
        .flat_map(split_braces)
        .filter(|command| !command.is_empty())
        .collect())
}

/// `command` split at the words `{` and `}` that stand on their own, which
/// group commands and are no words of them.
fn split_braces(command: Vec<Word>) -> Vec<Vec<Word>> {
    let mut out = vec![Vec::new()];
    for word in command {
        if !word.quoted && !word.expands && matches!(word.text.as_slice(), b"{" | b"}") {
            out.push(Vec::new());
        } else if let Some(last) = out.last_mut() {
            last.push(word);
        }
    }
    out
}

/// Whether `word` is a `NAME=value` assignment: its name and `=` unquoted,
/// whatever of its value is quoted.
fn is_assignment(word: &Word) -> bool {
    match word.text.iter().position(|&byte| byte == b'=') {
        Some(eq) if eq > 0 && eq < word.unquoted => {
            let name = &word.text[..eq];
            !name[0].is_ascii_digit()
                && name
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        }
        _ => false,
    }
}

/// What one simple command runs of updatedb: nothing, an updatedb command,
/// or why NAILS cannot tell.
fn command_runs(words: &[Word]) -> Option<Result<ExecCommand, String>> {
    // The environment of the command, which a variable that names updatedb
    // may be part of: that is the mention below.
    let mut start = 0;
    while words.get(start).is_some_and(is_assignment) {
        start += 1;
    }
    while words
        .get(start)
        .is_some_and(|word| !word.quoted && KEYWORDS.contains(&word.text.as_slice()))
    {
        start += 1;
    }
    let argv = &words[start..];
    let asks = argv.first().is_some_and(|first| {
        !first.expands
            && (QUESTIONS.contains(&first.text.as_slice())
                || (first.text == b"command"
                    && argv
                        .get(1)
                        .is_some_and(|flag| matches!(flag.text.as_slice(), b"-v" | b"-V"))))
    });
    if asks {
        return None;
    }
    let Some(at) = argv
        .iter()
        .position(|word| !word.expands && is_updatedb(&word.text))
    else {
        return words
            .iter()
            .any(|word| mentions_updatedb(&word.text))
            .then(|| {
                Err(
                    "it names updatedb other than as a program it runs, in a variable or a \
                     quoted command"
                        .to_string(),
                )
            });
    };
    let (before, rest) = argv.split_at(at);
    let (program, args) = (&rest[0], &rest[1..]);
    // A word before it that names updatedb, as the script of
    // `sh -c '…' updatedb` does, may run another one.
    if before.iter().any(|word| mentions_updatedb(&word.text)) {
        return Some(Err(
            "a word before its updatedb names updatedb too, as a command a shell runs".to_string(),
        ));
    }
    if args.iter().any(|arg| arg.expands) {
        return Some(Err(
            "an argument of its updatedb is something the shell expands".to_string(),
        ));
    }
    Some(Ok(ExecCommand {
        program: program.text.clone(),
        args: args.iter().map(|arg| arg.text.clone()).collect(),
    }))
}

/// What `text`, a piece of shell, runs of updatedb (see the [module
/// docs](self)): each command that runs an updatedb, or that names one in a
/// way NAILS does not follow, with why. None when it names no updatedb, or
/// only asks about one.
pub fn updatedb_runs(text: &[u8]) -> Vec<Result<ExecCommand, String>> {
    if !mentions_updatedb(text) {
        return Vec::new();
    }
    match commands(text) {
        Ok(commands) => commands
            .iter()
            .filter_map(|command| command_runs(command))
            .collect(),
        Err(why) => vec![Err(format!("NAILS cannot split it into commands: {why}"))],
    }
}

#[cfg(test)]
#[path = "shell_tests.rs"]
mod tests;
