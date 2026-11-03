// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the startup code may make or change before zsh reads it, or hand to
//! the programs it runs. A file the check would read that is not there now,
//! the code may make first (`cp ~/.src ~/.gen; . ~/.gen`), so where a file
//! read names it beyond the `source` commands and the tests that name it,
//! that is a doubt; and a file the check reads, there or not, the code may
//! write before zsh reads it, so where a command that runs before that
//! writes to a path whose last part is its name, or one an expansion or a
//! brace expansion may make its name (`>> ~/.zshrc.local`, `>> $log`,
//! `cp ~/.src ${f}en`), that is a doubt too. A program that writes a file it
//! is not given the name of, the check does not see. A hook may give the
//! programs it runs the command line in their environment, once it sets a
//! parameter to what an expansion makes (`preexec() { LINE=$1; logger }`).

use super::{Forms, Reader, builtins};
use crate::Filesystem;
use std::path::Path;

/// The most names brace expansion is followed into for one word; a word
/// that makes more may name any file.
const NAMES_LIMIT: usize = 1024;

/// What stands for any characters in a name, as an expansion does.
const ANY: char = '\u{0}';

/// The names brace expansion makes of `text`: each alternative of a `{a,b}`
/// list, each character of a `{abc}` or `{a-c}` group, as `BRACE_CCL` makes
/// it, among them each of `chars`, and the group as written; `None` when it
/// makes more than [`NAMES_LIMIT`].
fn expansions(text: &str, chars: &str) -> Option<Vec<String>> {
    let mut done = Vec::new();
    let mut todo = vec![text.to_string()];
    while let Some(word) = todo.pop() {
        if done.len() + todo.len() > NAMES_LIMIT {
            return None;
        }
        let Some(open) = word.find('{') else {
            done.push(word);
            continue;
        };
        let mut depth = 0usize;
        let close = word[open..].char_indices().find_map(|(at, c)| {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(open + at);
                    }
                }
                _ => {}
            }
            None
        });
        let Some(close) = close else {
            done.push(word);
            continue;
        };
        let (before, inner, after) = (&word[..open], &word[open + 1..close], &word[close + 1..]);
        // The group as written, which no option may expand.
        todo.push(format!("{before}\u{1}{inner}\u{2}{after}"));
        let mut parts = vec![String::new()];
        let mut depth = 0usize;
        for c in inner.chars() {
            match c {
                '{' => depth += 1,
                '}' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    parts.push(String::new());
                    continue;
                }
                _ => {}
            }
            parts.last_mut().expect("a part").push(c);
        }
        if parts.len() == 1 {
            parts = inner
                .chars()
                .chain(chars.chars())
                .map(String::from)
                .collect();
        }
        for part in parts {
            todo.push(format!("{before}{part}{after}"));
        }
    }
    Some(done)
}

/// Whether `pattern`, a name where [`ANY`] stands for any characters,
/// matches `name`.
fn matches(pattern: &[char], name: &[char]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some((&ANY, rest)) => (0..=name.len()).any(|at| matches(rest, &name[at..])),
        Some((c, rest)) => name.first() == Some(c) && matches(rest, &name[1..]),
    }
}

/// `text`, a word as written, with each expansion in it, a parameter's, a
/// command's output, arithmetic or a `~`, as [`ANY`].
fn any_expansion(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut at = 0;
    while at < chars.len() {
        let c = chars[at];
        if c == '$' || c == '`' || (c == '~' && at == 0) {
            out.push(ANY);
            at += 1;
            if c == '`' {
                while at < chars.len() && chars[at] != '`' {
                    at += 1;
                }
                at += 1;
            } else if c == '$' && matches!(chars.get(at), Some('{' | '(')) {
                let (open, close) = if chars[at] == '{' {
                    ('{', '}')
                } else {
                    ('(', ')')
                };
                let mut depth = 0usize;
                while at < chars.len() {
                    if chars[at] == open {
                        depth += 1;
                    } else if chars[at] == close {
                        depth -= 1;
                        if depth == 0 {
                            at += 1;
                            break;
                        }
                    }
                    at += 1;
                }
            } else if c == '$' {
                while at < chars.len() && (chars[at].is_ascii_alphanumeric() || chars[at] == '_') {
                    at += 1;
                }
            }
        } else {
            out.push(c);
            at += 1;
        }
    }
    out
}

/// Whether `text`, the last part of a path as written, may name the file
/// `base`: as written, or as brace expansion makes it ([`expansions`]), and,
/// where `expanded`, with each expansion standing for any characters
/// ([`any_expansion`]). A glob makes no name of a file that is not there.
fn may_name(text: &str, base: &str, expanded: bool) -> bool {
    let text = if expanded {
        any_expansion(text)
    } else {
        text.to_string()
    };
    let name: Vec<char> = base.chars().collect();
    expansions(&text, base).is_none_or(|names| {
        names
            .iter()
            .any(|candidate| matches(&candidate.chars().collect::<Vec<_>>(), &name))
    })
}

/// The last part of the path `text` names: past its last `/`, or its last
/// `=` where it has none (`of=x`).
pub(super) fn last_part(text: &str) -> &str {
    match text.rsplit_once('/') {
        Some((_, last)) => last,
        None => text.rsplit('=').next().unwrap_or(text),
    }
}

/// How often `line`, a line of zsh code or a word of it, names the file
/// `base`: as the last part of a word's path ([`last_part`]), its quotes
/// taken off, or as what a brace expansion may make of it ([`may_name`]);
/// past a `/` alone where `by_path` (a function's file, whose name the code
/// uses alone too).
fn names_file(line: &str, base: &str, by_path: bool) -> usize {
    line.split(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')' | '<' | '>'))
        .filter(|word| {
            let word = word.replace(['\'', '"', '\\'], "");
            let last = last_part(&word);
            (!by_path || word.contains('/'))
                && (last == base || (last.contains('{') && may_name(last, base, false)))
        })
        .count()
}

/// The commands that make or write the files their words name.
const CREATES: &[&str] = &[
    "cp", "mv", "ln", "install", "tee", "dd", "rsync", "curl", "wget", "tar", "unzip", "zcompile",
    "zf_ln", "zf_mv", "mkfifo", "mknod",
];

/// Whether `command` makes or writes the files its words name.
pub(super) fn creates(command: &str) -> bool {
    CREATES.contains(&command.rsplit('/').next().unwrap_or(command))
}

impl<F: Filesystem> Reader<'_, F> {
    /// Note a doubt for each file the check would read that is not there
    /// now, as the code may make it before zsh reads it ([the module](self)):
    /// where a file read names it beyond the `source` commands and the tests
    /// that name it ([`Reader::known_files`]), a function's file only by a
    /// path; and for each file it reads, there or not, where a write to a
    /// path that may be its, or that of the compiled form zsh runs in its
    /// place (`.zwc`), runs before zsh reads it, at the top or in a function
    /// the top runs.
    pub(super) fn made(&mut self) {
        let mut files: Vec<(std::path::PathBuf, usize, bool)> = std::mem::take(&mut self.missing)
            .into_iter()
            .map(|(path, at)| (path, at, true))
            .chain(
                std::mem::take(&mut self.read_files)
                    .into_iter()
                    .map(|(path, at)| (path, at, false)),
            )
            .collect();
        files.sort();
        files.dedup_by(|a, b| a.0 == b.0 && a.2 == b.2);
        for (path, at, missing) in files {
            let Some(base) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let by_path = self.autoloads.iter().any(|name| name == base);
            let named = || -> usize {
                self.texts
                    .iter()
                    .map(|forms| forms.most(|line| names_file(line, base, by_path)))
                    .sum()
            };
            let known = || {
                self.known_files
                    .iter()
                    .filter(|known| last_part(known) == base)
                    .count()
            };
            // zsh runs the compiled form beside a file in its place.
            let compiled = format!("{base}.zwc");
            let why = if missing && named() > known() {
                Some("a file the check reads names it".to_string())
            } else {
                self.writes
                    .iter()
                    .find(|(last, _, order, function)| {
                        let before = match function {
                            None => *order < at,
                            Some(function) => self
                                .top_calls
                                .iter()
                                .any(|(name, call)| *call < at && self.reaches(name, function)),
                        };
                        before && (may_name(last, base, true) || may_name(last, &compiled, true))
                    })
                    .map(|(_, what, ..)| format!("{what} before zsh reads it"))
            };
            if let Some(why) = why {
                let now = if missing {
                    "which is not there now, "
                } else {
                    ""
                };
                self.doubt(format!(
                    "it cannot tell what {}, {now}holds as zsh reads it, as {why}, which may \
                     write it",
                    path.display()
                ));
            }
        }
    }

    /// Whether running the function or command `name` may run `function`:
    /// it is that one, or one it runs or autoloads runs it, as far as they
    /// go.
    fn reaches(&self, name: &str, function: &str) -> bool {
        let mut run = vec![name.to_string()];
        let mut at = 0;
        while let Some(caller) = run.get(at).cloned() {
            if caller == function {
                return true;
            }
            for (from, to) in self.edges.iter().chain(&self.autoloaded_by) {
                if *from == caller && !run.contains(to) {
                    run.push(to.clone());
                }
            }
            at += 1;
        }
        false
    }

    /// Note that the file at `path`, which the check would read, is not
    /// there now, or that the check reads it (`there`).
    pub(super) fn missing(&mut self, path: &Path, there: bool) {
        let entry = (path.to_path_buf(), self.order);
        if there {
            self.read_files.push(entry);
        } else {
            self.missing.push(entry);
        }
    }

    /// Note a write to the path `target`, as written, which the warning
    /// names as `what`, in the function `function` when in one
    /// ([`Reader::made`]).
    pub(super) fn makes(&mut self, target: &str, what: String, function: Option<String>) {
        let last = last_part(target).to_string();
        self.writes.push((last, what, self.order, function));
    }

    /// Note a doubt when a hook sets a parameter to what an expansion makes,
    /// which may be the command line (`LINE=$1`), while a hook runs a program
    /// that is no function, alias or builtin: zsh gives each program it runs
    /// the exported parameters in its environment, which the parameter is
    /// once a file exports it, every parameter is (`ALL_EXPORT`) or the
    /// shell's environment held it, and the program may write it to a file.
    /// One local to its function is none, unless every parameter is
    /// exported.
    pub(super) fn handed(&mut self, hooked: &[String]) {
        let all = self.texts.iter().any(Forms::all_export);
        let Some((function, name, _, place)) = self
            .computed
            .iter()
            .find(|(function, _, local, _)| Self::is_hook(function, hooked) && (!local || all))
            .cloned()
        else {
            return;
        };
        let program = self.edges.iter().find(|(caller, callee)| {
            Self::is_hook(caller, hooked)
                && !self.defined.contains(callee)
                && !self.autoloads.contains(callee)
                && !builtins::builtin(callee)
                && !matches!(callee.as_str(), "[[" | "]]")
        });
        if let Some((caller, callee)) = program {
            let doubt = format!(
                "it cannot tell what `{callee}` in `{caller}` writes, as `{function}` in {place} \
                 sets `{name}` to what an expansion makes, which zsh may give the programs a hook \
                 runs in their environment"
            );
            self.doubt(doubt);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{may_name, names_file};

    #[test]
    fn a_word_names_a_file_by_its_last_part_or_braces_that_make_it() {
        assert_eq!(
            names_file("cp ~/.src ~/.gen; . \"$HOME/.gen\"", ".gen", false),
            2
        );
        assert_eq!(names_file("x=~/.gen cat > .gen", ".gen", false), 2);
        assert_eq!(
            names_file("tee ~/{.gen,.x} ~/.g{e}n ~/.g?n * {", ".gen", false),
            2
        );
        assert_eq!(names_file("ln -s a ~/.genx ~/x.gen", ".gen", false), 0);
        assert_eq!(
            names_file("autoload -Uz compinit; compinit", "compinit", true),
            0
        );
        assert_eq!(names_file("cp x ~/zfn/compinit", "compinit", true), 1);
        assert!(may_name("{a,b}cd", "bcd", false));
        assert!(may_name(".g{e}n", ".gen", false));
        assert!(!may_name("x{ab}", "y", false));
        assert!(!may_name("{", ".gen", false));
        assert!(!may_name("{a,b}", ".gen", false));
        // With every expansion standing for any characters.
        assert!(may_name("${f}en", ".gen", true));
        assert!(may_name("$log", ".zlogin", true));
        assert!(!may_name("agent-env", ".zlogin", true));
        assert!(!may_name("${f}x", ".gen", true));
    }
}
