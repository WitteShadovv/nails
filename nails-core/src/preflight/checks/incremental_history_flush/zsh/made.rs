// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the startup code may make or change before zsh reads it, or hand to
//! the programs it runs. A file the check would read that is not there now,
//! the code may make first (`cp ~/.src ~/.gen; . ~/.gen`), so where a file
//! read names it beyond the `source` commands and the tests that name it,
//! that is a doubt, but for the code of a stock function, which makes none
//! before zsh reads it; and a file the check
//! reads, there or not, the code may write before zsh reads it, so where a
//! command that runs before that writes to a path whose last part is its
//! name (for a file a function's code reads, which a hook may read after
//! every command, any such command, and one whose path an expansion makes at
//! the top or in a function the top runs), or one an expansion or a brace expansion may make its name
//! (`>> ~/.zshrc.local`, `>> $log`, `cp ~/.src ${f}en`), that is a doubt
//! too. A program that writes a file it is not given the name of, the check
//! does not see. A hook may give the programs it runs the command line in
//! their environment, once it sets a parameter to what an expansion makes
//! (`preexec() { LINE=$1; logger }`).

use super::{Forms, Reader, builtins};
use crate::Filesystem;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
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
#[cfg(test)]
fn may_name(text: &str, base: &str, expanded: bool) -> bool {
    if expanded {
        names_of(&any_expansion(text), base)
    } else {
        names_of(text, base)
    }
}

/// Whether `text`, a name where [`ANY`] stands for any characters, may name
/// the file `base` as written or as brace expansion makes it
/// ([`expansions`]).
fn names_of(text: &str, base: &str) -> bool {
    let name: Vec<char> = base.chars().collect();
    expansions(text, base).is_none_or(|names| {
        names
            .iter()
            .any(|candidate| matches(&candidate.chars().collect::<Vec<_>>(), &name))
    })
}

/// Which of `bases`, each a file's name by its place, `text`, a name as
/// written, may name ([`names_of`]), with brace expansion followed once for
/// each length of name rather than for each name where it may: for a name
/// that holds no brace or comma, how many names it makes depends on how many
/// characters the name has alone, and each of them starts with what stands
/// before the first brace, where the text holds no [`ANY`].
fn names_among<'a>(text: &str, bases: impl Iterator<Item = (usize, &'a str)>) -> Vec<usize> {
    let exact = !text.contains(ANY);
    let start = text.split('{').next().unwrap_or_default();
    // By the length of a name, whether brace expansion makes more names of
    // the text than it follows.
    let mut beyond: HashMap<usize, bool> = HashMap::new();
    bases
        .filter(|(_, base)| {
            if !exact || base.contains(['{', '}', ',', ANY]) {
                return names_of(text, base);
            }
            let length = base.chars().count();
            let beyond = *beyond
                .entry(length)
                .or_insert_with(|| expansions(text, &"a".repeat(length)).is_none());
            beyond || (base.starts_with(start) && names_of(text, base))
        })
        .map(|(at, _)| at)
        .collect()
}

/// The last part of the path `text` names: past its last `/`, or its last
/// `=` where it has none (`of=x`).
pub(super) fn last_part(text: &str) -> &str {
    match text.rsplit_once('/') {
        Some((_, last)) => last,
        None => text.rsplit('=').next().unwrap_or(text),
    }
}

/// The words of `line`, a line of zsh code or a word of it, as [`named`]
/// reads them for the names of files.
fn file_words(line: &str) -> impl Iterator<Item = &str> {
    line.split(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')' | '<' | '>'))
}

/// `word` with its quotes and backslashes taken off.
fn bare(word: &str) -> Cow<'_, str> {
    if word.contains(['\'', '"', '\\']) {
        Cow::Owned(word.replace(['\'', '"', '\\'], ""))
    } else {
        Cow::Borrowed(word)
    }
}

/// How often `line`, a line of zsh code or a word of it, names the file
/// `base`, by a path alone where `by_path`, as [`named`] counts it for each
/// name at once.
#[cfg(test)]
fn names_file(line: &str, base: &str, by_path: bool) -> usize {
    file_words(line)
        .filter(|word| {
            let word = bare(word);
            let last = last_part(&word);
            (!by_path || word.contains('/'))
                && (last == base || (last.contains('{') && may_name(last, base, false)))
        })
        .count()
}

/// How often the files the check reads name each of `bases`, a file's name
/// and whether a word names it only past a `/` (a function's file, whose
/// name the code uses alone too): as the last part of a word's path
/// ([`last_part`]), its quotes taken off, or as what a brace expansion may
/// make of it ([`names_of`]), in the form of each file that names it most
/// ([`Forms::most`]), summed over the files. One pass over the forms counts
/// every name.
fn named(texts: &[&Forms], bases: &[(&str, bool)]) -> Vec<usize> {
    let mut total = vec![0; bases.len()];
    if bases.is_empty() {
        return total;
    }
    let index: HashMap<&str, usize> = bases
        .iter()
        .enumerate()
        .map(|(at, (base, _))| (*base, at))
        .collect();
    // The names a word without a `/` may name: those of no function's file.
    let unpathed: Vec<usize> = bases
        .iter()
        .enumerate()
        .filter(|(_, (_, by_path))| !by_path)
        .map(|(at, _)| at)
        .collect();
    // The names other than its own that a last part with a brace may make,
    // by that part, of a word without a `/` and of one with one.
    let mut braced: [HashMap<String, Vec<usize>>; 2] = Default::default();
    for forms in texts {
        let mut most: HashMap<usize, usize> = HashMap::new();
        forms.each(|pieces| {
            let mut counts: HashMap<usize, usize> = HashMap::new();
            for word in pieces.flat_map(file_words) {
                let path = word.contains('/');
                if !path && unpathed.is_empty() {
                    continue;
                }
                let word = bare(word);
                let last = last_part(&word);
                if path {
                    if let Some(at) = index.get(last) {
                        *counts.entry(*at).or_default() += 1;
                    }
                } else {
                    for at in unpathed.iter().filter(|at| bases[**at].0 == last) {
                        *counts.entry(*at).or_default() += 1;
                    }
                }
                if last.contains('{') {
                    let braced = &mut braced[usize::from(path)];
                    if !braced.contains_key(last) {
                        let wanted = bases
                            .iter()
                            .enumerate()
                            .filter(|(_, (base, by_path))| (path || !by_path) && *base != last)
                            .map(|(at, (base, _))| (at, *base));
                        braced.insert(last.to_string(), names_among(last, wanted));
                    }
                    for at in &braced[last] {
                        *counts.entry(*at).or_default() += 1;
                    }
                }
            }
            for (at, count) in counts {
                let best = most.entry(at).or_default();
                *best = (*best).max(count);
            }
        });
        for (at, count) in most {
            total[at] += count;
        }
    }
    total
}

/// Where in the files read a file that a function's code reads is read: as
/// the function runs, which may be after any command the files run, a hook's
/// included.
const IN_FUNCTION: usize = usize::MAX;

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
    /// where a file read, but for a stock function's code, names it beyond
    /// the `source` commands and the tests that name it
    /// ([`Reader::known_files`]), a function's file only by a path; and for
    /// each file it reads, there or not, where a write to a
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
        // A file read twice counts where zsh reads it last.
        files.sort_by(|a, b| (&a.0, a.2).cmp(&(&b.0, b.2)).then(b.1.cmp(&a.1)));
        files.dedup_by(|a, b| a.0 == b.0 && a.2 == b.2);
        let autoloads: HashSet<&str> = self.autoloads.iter().map(String::as_str).collect();
        let mut bases: Vec<(&str, bool)> = files
            .iter()
            .filter(|(.., missing)| *missing)
            .filter_map(|(path, ..)| path.file_name()?.to_str())
            .map(|base| (base, autoloads.contains(base)))
            .collect();
        bases.sort_unstable();
        bases.dedup();
        // The code of a stock function makes none of them first.
        let texts: Vec<&Forms> = self
            .texts
            .iter()
            .enumerate()
            .filter(|(at, _)| !self.stock_texts.contains(at))
            .map(|(_, forms)| forms)
            .collect();
        let named: HashMap<&str, usize> = bases
            .iter()
            .map(|(base, _)| *base)
            .zip(named(&texts, &bases))
            .collect();
        let mut known: HashMap<&str, usize> = HashMap::new();
        for file in &self.known_files {
            *known.entry(last_part(file)).or_default() += 1;
        }
        let first_calls = self.first_calls();
        // Each write's last part with each expansion as any characters, and
        // whether it holds none and no brace, so that it names one file.
        let writes: Vec<(String, bool, &String, usize, Option<&str>)> = self
            .writes
            .iter()
            .map(|(last, what, order, function)| {
                let expanded = any_expansion(last);
                let plain = !expanded.contains([ANY, '{']);
                (expanded, plain, what, *order, function.as_deref())
            })
            .collect();
        let mut doubts = Vec::new();
        for (path, at, missing) in &files {
            let Some(base) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            // zsh runs the compiled form beside a file in its place.
            let compiled = format!("{base}.zwc");
            let count = named.get(base).copied().unwrap_or_default();
            let why = if *missing && count > known.get(base).copied().unwrap_or_default() {
                Some("a file the check reads names it".to_string())
            } else {
                writes
                    .iter()
                    .find(|(expanded, plain, _, order, function)| {
                        // What a function's code reads, zsh reads as the
                        // function runs, which may be after any command the
                        // files run: a write to a path as written anywhere,
                        // and one an expansion makes at the top or in a
                        // function the top runs, counts. One a hook makes is a
                        // doubt of its own ([`super::runs`]).
                        let before = if *at == IN_FUNCTION {
                            *plain
                                || function
                                    .is_none_or(|function| first_calls.contains_key(function))
                        } else {
                            match function {
                                None => order < at,
                                Some(function) => {
                                    first_calls.get(function).is_some_and(|call| call < at)
                                }
                            }
                        };
                        before
                            && if *plain {
                                expanded == base || *expanded == compiled
                            } else {
                                names_of(expanded, base) || names_of(expanded, &compiled)
                            }
                    })
                    .map(|(_, _, what, ..)| format!("{what} before zsh reads it"))
            };
            if let Some(why) = why {
                let now = if *missing {
                    "which is not there now, "
                } else {
                    ""
                };
                doubts.push(format!(
                    "it cannot tell what {}, {now}holds as zsh reads it, as {why}, which may \
                     write it",
                    path.display()
                ));
            }
        }
        for doubt in doubts {
            self.doubt(doubt);
        }
    }

    /// For each function, the order of the first command at the top that may
    /// run it: one that runs it, or runs a function that runs it or that
    /// autoloads it, as far as the calls go.
    fn first_calls(&self) -> HashMap<&str, usize> {
        let mut callees: HashMap<&str, Vec<&str>> = HashMap::new();
        for (from, to) in self.edges.iter().chain(&self.autoloaded_by) {
            callees.entry(from).or_default().push(to);
        }
        let mut first: HashMap<&str, usize> = HashMap::new();
        for (name, call) in &self.top_calls {
            let mut run = vec![name.as_str()];
            let mut seen: HashSet<&str> = HashSet::from([name.as_str()]);
            while let Some(caller) = run.pop() {
                let at = first.entry(caller).or_insert(*call);
                *at = (*at).min(*call);
                for callee in callees.get(caller).into_iter().flatten() {
                    if seen.insert(callee) {
                        run.push(callee);
                    }
                }
            }
        }
        first
    }

    /// Note that the file at `path`, which the check would read, is not
    /// there now, or that the check reads it (`there`): where it reads it,
    /// or [`IN_FUNCTION`] for a file a function's code reads.
    pub(super) fn missing(&mut self, path: &Path, there: bool) {
        let at = if self.function_code {
            IN_FUNCTION
        } else {
            self.order
        };
        let entry = (path.to_path_buf(), at);
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
    use super::{Forms, may_name, named, names_among, names_file, names_of};

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

    #[test]
    fn the_names_counted_at_once_are_those_each_name_counts_alone() {
        let texts = [
            "cp ~/.src ~/.gen; . \"$HOME/.gen\"\n# . ~/.gen\n",
            "tee ~/{.gen,.x} ~/.g{e}n ~/.g?n * {\nprint 'a' > ~/zfn/compinit\n",
            "x=~/.gen cat > .gen \\\n  ~/.gen\n",
            "autoload -Uz compinit; compinit\ncp x ~/zfn/compinit ~/zfn/c{o,x}mpinit\n",
            "f() { : > $'\\x2e'gen; print ~/.ge{n} ~/{a}{b}{c}{d} }\n",
            "print \"~/.gen\n# ~/.gen\"\n",
            "",
        ];
        let forms: Vec<Forms> = texts.iter().map(|text| Forms::of(text)).collect();
        let refs: Vec<&Forms> = forms.iter().collect();
        let alone = |base: &str, by_path: bool| -> usize {
            forms
                .iter()
                .map(|forms| forms.most(|line| names_file(line, base, by_path)))
                .sum()
        };
        for bases in [
            &[
                (".gen", false),
                (".x", false),
                ("compinit", true),
                ("cxmpinit", true),
                ("{", false),
                (".g?n", false),
                ("abcd", false),
                ("missing", false),
            ][..],
            &[("compinit", false), (".gen", true)],
            &[],
        ] {
            let counted = named(&refs, bases);
            assert_eq!(counted.len(), bases.len());
            for (at, (base, by_path)) in bases.iter().enumerate() {
                assert_eq!(counted[at], alone(base, *by_path), "{base} {by_path}");
            }
        }
        assert_eq!(named(&refs, &[(".gen", false)]), [12]);
    }

    #[test]
    fn the_names_a_word_may_name_are_found_once_for_each_length() {
        let bases = [
            ".gen",
            "gen",
            ".zlogin",
            "compinit",
            "_git",
            "a,b",
            "x{y}",
            "{",
            "ab",
            "abcd",
            "abcdefghijklmnop",
            ".g",
        ];
        for text in [
            "${match[1]}:${match[3]:+$match[2]}:${match[3]:-$match[2]}:$match[4]}",
            "${tpre}${tsuf}",
            ".ge{n}",
            "{a,b}cd",
            "{a}{b}{c}{d}",
            "{a}{b}{c}",
            "x{a,{b,c}}",
            "{,}",
            "{",
            "}{a,b}",
            "\u{0}{a}",
            "_g{i}t",
            "comp{i,x}nit",
        ] {
            let alone: Vec<usize> = bases
                .iter()
                .enumerate()
                .filter(|(_, base)| names_of(text, base))
                .map(|(at, _)| at)
                .collect();
            let among = names_among(text, bases.iter().enumerate().map(|(at, base)| (at, *base)));
            assert_eq!(among, alone, "{text:?}");
        }
    }
}
