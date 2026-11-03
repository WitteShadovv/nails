// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The functions of zsh's own that the check knows by their code: the
//! stock `compinit` and `promptinit` and the ones they run, as zsh 5.9, 5.9.1
//! and 5.9.2 ship them. A file whose bytes are one of those is read for what
//! that code does ([`Stock`]); any other, a changed one too, is read as code
//! like any function the files autoload.
//!
//! What each does, as its code shows, is what the check counts for it:
//!
//! - `compinit` runs with `emulate -L zsh`, sources the dump file `compdump`
//!   writes (`-d` names it, else `${ZDOTDIR:-$HOME}/.zcompdump`), runs
//!   `compaudit` and `compdump`, autoloads `compinstall` without running it,
//!   and marks the completion functions it finds in `fpath`, the files whose
//!   names start with `_`, to be autoloaded, as the first line of each says
//!   (`#compdef`, `#autoload` and their words), when it finds no dump file it
//!   can use. zsh runs those only as completion runs, when a key bound to a
//!   completion widget is pressed (Tab), or when code runs them by name; the
//!   check reads one as a hook where a key typed in a line may run it
//!   (`compdef -k`, a widget's function), and doubts a key binding of a first
//!   line other than zsh's own ([`KEY_LINES`]). It names none of the three
//!   options and holds no `fc` that writes the history file.
//! - `compaudit` checks the owners and modes of the `fpath` directories and
//!   may put the directories under one that holds a `Base` directory at the
//!   end of `fpath`; `compdump` writes the dump file.
//! - `promptinit` autoloads `add-zsh-hook` and `add-zle-hook-widget`, and
//!   marks the prompt themes it finds in `fpath`, the `prompt_*_setup` files,
//!   to be autoloaded. It defines `prompt`, which runs the theme it names
//!   (`prompt suse` runs `prompt_suse_setup`) each time it runs, a hook's
//!   among them, may turn `PROMPT_SUBST` on as
//!   the theme asks, keeps code a theme gives it to run as the theme changes
//!   (`prompt_cleanup`), and keeps code to restore the prompt, which runs
//!   `prompt_default_setup` (`prompt restore`).
//! - `add-zsh-hook` and `add-zle-hook-widget` make the function they are
//!   given a hook, which the walk reads where they are run
//!   ([`super::walk::Event::Hook`]), or take one away.

use super::{Forms, Reader, Word, backstop, dump};
use crate::Filesystem;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// A function of zsh's own whose stock code the check knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stock {
    Compinit,
    Compaudit,
    Compdump,
    Promptinit,
    AddZshHook,
    AddZleHookWidget,
}

/// The stock functions: the name zsh autoloads each by, what it is, and the
/// SHA-256 of its file as a release ships it.
const STOCK: [(&str, Stock, &str); 8] = [
    // zsh 5.9.
    (
        "compinit",
        Stock::Compinit,
        "d1627311aec3129f3a35e2775fc93f1f0d7fb176fafaed2bb532a987f899a7f2", // pragma: allowlist secret
    ),
    // zsh 5.9.1 and 5.9.2.
    (
        "compinit",
        Stock::Compinit,
        "e784ec2f3089d12dbeb61b4f058df00d4cffbaab04b77ea342fbfeb1d1834501", // pragma: allowlist secret
    ),
    // zsh 5.9 to 5.9.2.
    (
        "compaudit",
        Stock::Compaudit,
        "d41820035eaa692eea358900f6d9f0882055191a15d1cffae654c0ac1e9b4d24", // pragma: allowlist secret
    ),
    // zsh 5.9 and 5.9.1.
    (
        "compdump",
        Stock::Compdump,
        "8678f63b995b86a0060b2a3ba7d8f868d09d47c86b410884960902af27eadbd2", // pragma: allowlist secret
    ),
    // zsh 5.9.2.
    (
        "compdump",
        Stock::Compdump,
        "474a41680c54eb1d75ed24259a9c2fdd9fcee972b2662451041ccab3dacbb40f", // pragma: allowlist secret
    ),
    // zsh 5.9 to 5.9.2.
    (
        "promptinit",
        Stock::Promptinit,
        "6cfb00c4be9b13b11e116b131d6650febc11a09a366e2a6cf929bf4f9b6c66f9", // pragma: allowlist secret
    ),
    (
        "add-zsh-hook",
        Stock::AddZshHook,
        "f0e9ac9dfe1b2367164d6674924b5297621881a4a325860942d72ec7f7281a8d", // pragma: allowlist secret
    ),
    (
        "add-zle-hook-widget",
        Stock::AddZleHookWidget,
        "0d00fe1f9ca24ab43d38d11e30ae2dcab64ecb375aad0c688d6c65a976f59d4e", // pragma: allowlist secret
    ),
];

/// The SHA-256 of `bytes`, in lower-case hex.
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The stock function the file of the function `name` holds, when its bytes
/// are that function's as a release ships them.
pub(super) fn known(name: &str, bytes: &[u8]) -> Option<Stock> {
    let digest = digest(bytes);
    let digest = digest.as_str();
    #[cfg(test)]
    if let Some(stock) = tests::known(name, digest) {
        return Some(stock);
    }
    STOCK
        .iter()
        .find(|(stock_name, _, stock_digest)| *stock_name == name && *stock_digest == digest)
        .map(|(_, stock, _)| *stock)
}

impl<F: Filesystem> Reader<'_, F> {
    /// Read the file at `path` of the function `name` the files autoload:
    /// for what its code does when it is a stock function of zsh's own
    /// ([`stock::known`]), else as code like any file.
    pub(super) fn function(&mut self, path: &Path, name: &str) {
        let Some(text) = self.text(path) else {
            return;
        };
        match known(name, text.as_bytes()) {
            Some(stock) => {
                // zsh expands the aliases the files define in its code as it
                // loads it unless the files autoload it with -U, so its words
                // count as uses of an alias then.
                if self.expanding.iter().any(|expanding| expanding == name) {
                    self.lines(&text, &path.to_string_lossy());
                }
                self.stock(stock);
            }
            // The file is the function's code.
            None => self.code_in(path, &text, false, Some(name.to_string())),
        }
    }

    /// Note what the stock function `stock` does ([`stock`]).
    fn stock(&mut self, stock: Stock) {
        match stock {
            Stock::Compinit => {
                self.compinit = true;
                for name in ["compaudit", "compdump"] {
                    self.autoload_name(name, Some("compinit"));
                }
            }
            Stock::Compaudit => self.compaudit = true,
            Stock::Promptinit => {
                self.promptinit = true;
                // A theme may ask for it.
                self.prompt_subst = true;
                for name in ["add-zsh-hook", "add-zle-hook-widget"] {
                    self.autoload_name(name, Some("promptinit"));
                }
            }
            Stock::Compdump | Stock::AddZshHook | Stock::AddZleHookWidget => {}
        }
    }

    /// Read the dump file at `path` that the stock `compinit` sources: for
    /// the completion functions it marks, when its lines are those `compdump`
    /// writes ([`dump::marks`]), else as code like any file.
    fn dump(&mut self, path: &Path) {
        if self.dumps.iter().any(|read| read == path) {
            return;
        }
        self.dumps.push(path.to_path_buf());
        let Some(text) = self.text(path) else {
            return;
        };
        match dump::marks(&text) {
            Some(marks) => {
                let place = path.to_string_lossy().into_owned();
                // Its quoted words are data; an alias zsh may expand is one
                // named like a command of its lines (`zle`, `autoload`).
                self.texts.push(Forms::of(&dump::commands(&text)));
                for (at, &count) in backstop::named(&text).options.iter().enumerate() {
                    if count > 0 {
                        self.options[at] = Some(format!("{place} names"));
                    }
                }
                for mark in marks {
                    if !self.dump_marks.contains(&mark) {
                        self.dump_marks.push(mark);
                    }
                }
            }
            // compinit sources it in its own code.
            None => self.code_in(path, &text, false, Some("compinit".to_string())),
        }
    }

    /// Whether the function `name` is one a stock function the files
    /// autoload marks to be autoloaded, which zsh runs only when it is run by
    /// name or as a hook: a completion function `compinit` or its dump file
    /// marks, `compinstall`, or a prompt theme `promptinit` marks
    /// (`prompt_suse_setup`).
    fn marks(&self, name: &str) -> bool {
        (self.compinit && (name.starts_with('_') || name == "compinstall"))
            || self.dump_marks.iter().any(|mark| mark == name)
            || (self.promptinit && name.starts_with("prompt_") && name.ends_with("_setup"))
    }

    /// Follow what the stock functions the files autoload read and run: the
    /// dump files `compinit` sources, the functions they mark that the files
    /// run by name or make hooks, and the prompt themes `prompt` runs.
    pub(super) fn marked(&mut self) {
        if self.compinit {
            self.dumps_of_compinit();
            self.first_lines();
        }
        for (name, args, place) in self.calls.clone() {
            if self.promptinit && name == "prompt" {
                // The code `prompt` keeps to restore the prompt, which a
                // theme runs (`prompt restore`), runs prompt_default_setup;
                // it runs the functions promptinit defines, which a file may
                // define in their place, as it runs, a hook among what runs it.
                self.autoload_name("prompt_default_setup", Some("prompt"));
                for helper in [
                    "prompt_default_setup",
                    "set_prompt",
                    "prompt_preview_safely",
                    "prompt_preview_theme",
                ] {
                    let edge = ("prompt".to_string(), helper.to_string());
                    if !self.edges.contains(&edge) {
                        self.edges.push(edge);
                    }
                }
                self.prompt(&args, &place);
            } else if self.promptinit
                && matches!(
                    name.as_str(),
                    "prompt_cleanup"
                        | "prompt_preview_safely"
                        | "prompt_preview_theme"
                        | "set_prompt"
                )
            {
                self.doubt(format!(
                    "it cannot follow the code that `{name}` in {place} runs, which promptinit \
                     defines"
                ));
            } else if self.compinit && name == "compdef" {
                self.compdef(&args, &place);
            } else if self.marks(&name) {
                self.autoload_name(&name, None);
            }
        }
        for hook in self.hooks.clone() {
            if self.marks(&hook) {
                self.autoload_name(&hook, None);
            }
        }
    }

    /// Note the function a call of `compdef`, which the stock `compinit`
    /// defines, with `args` in the file at `place` autoloads or binds to
    /// keys: with `-a`, `-k` or `-K` among its flags, the first word past
    /// them, which zsh then loads from `fpath` where the files or a key runs
    /// it; one an expansion names is a doubt. One bound to keys (`-k`, `-K`)
    /// is a hook, as a key typed in a line (Space) may be among them.
    fn compdef(&mut self, args: &[Word], place: &str) {
        let flags: Vec<&Word> = args
            .iter()
            .take_while(|arg| arg.text.starts_with('-') && arg.text != "--")
            .collect();
        if !flags
            .iter()
            .any(|flag| flag.expands || flag.text.contains(['a', 'k', 'K']))
        {
            return;
        }
        match args.get(flags.len()) {
            Some(function) if !function.expands && flags.iter().all(|flag| !flag.expands) => {
                self.autoload_name(&function.text, Some("compdef"));
                if flags.iter().any(|flag| flag.text.contains(['k', 'K']))
                    && !self.hooks.contains(&function.text)
                {
                    self.hooks.push(function.text.clone());
                }
            }
            _ => {
                let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
                self.doubt(format!(
                    "it cannot tell which function `compdef {}` in {place} autoloads",
                    words.join(" ")
                ));
            }
        }
    }

    /// Read the dump files the stock `compinit` sources: the one each call
    /// of it names with `-d`, and `.zcompdump` in each directory `ZDOTDIR`
    /// may have named as the files were read, the home among them, which it
    /// sources without one.
    fn dumps_of_compinit(&mut self) {
        let mut paths: Vec<PathBuf> = self
            .zdotdirs_seen
            .iter()
            .map(|dir| dir.join(".zcompdump"))
            .collect();
        if self.zdotdir_lost {
            self.doubt(
                "it cannot tell where the dump file that compinit sources is, as it cannot \
                 follow ZDOTDIR"
                    .to_string(),
            );
        }
        for (name, args, place) in self.calls.clone() {
            if name != "compinit" {
                continue;
            }
            // compinit reads its flags as long as they are -d, -D, -i, -u,
            // -C or -w; the word after a -d, unless it is another flag, names
            // the dump file.
            let mut args = args.iter().peekable();
            while let Some(arg) = args.next_if(|arg| {
                arg.expands || matches!(arg.text.as_str(), "-d" | "-D" | "-i" | "-u" | "-C" | "-w")
            }) {
                if arg.expands {
                    self.doubt(format!(
                        "it cannot tell which dump file `compinit {}` in {place} sources",
                        arg.text
                    ));
                    break;
                }
                if arg.text != "-d" {
                    continue;
                }
                let Some(file) =
                    args.next_if(|file| !matches!(file.text.as_str(), "-d" | "-f" | "-Q" | "-C"))
                else {
                    continue;
                };
                match self.resolve(file) {
                    Some(files) => paths.extend(files),
                    None => self.doubt(format!(
                        "it cannot follow the dump file that `compinit -d {}` in {place} \
                         sources",
                        file.text
                    )),
                }
            }
        }
        for path in paths {
            self.dump(&path);
        }
    }

    /// Note the prompt theme a call of `prompt` with `args` in the file at
    /// `place` runs, once the stock `promptinit` defines it: the one it names
    /// (`prompt suse`), or with `-h`, `-s` or `-p` the ones after it; none
    /// with `-c` or `-l`. One it picks itself (`random`, `-p` alone), or that
    /// an expansion names, is a doubt.
    fn prompt(&mut self, args: &[Word], place: &str) {
        let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
        let doubt = || {
            format!(
                "it cannot tell which prompt theme `prompt {}` in {place} runs",
                words.join(" ")
            )
        };
        let theme = |name: &str| {
            (!name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
            .then(|| format!("prompt_{name}_setup"))
        };
        if args.iter().any(|arg| arg.expands) {
            let doubt = doubt();
            self.doubt(doubt);
            return;
        }
        let themes: Vec<&str> = match words.first().copied() {
            None => Vec::new(),
            Some("random") => vec![""],
            Some(flag) if flag.starts_with('-') => match flag.chars().nth(1) {
                Some('c' | 'l') => Vec::new(),
                Some('h' | 's') => words.get(1).copied().into_iter().collect(),
                Some('p') if words.len() > 1 => words[1..].to_vec(),
                Some('p') => vec![""],
                _ => Vec::new(),
            },
            Some(name) => vec![name],
        };
        for name in themes {
            match theme(name) {
                Some(function) => {
                    // A theme runs as `prompt` does, a hook's among them.
                    let edge = ("prompt".to_string(), function.clone());
                    if !self.edges.contains(&edge) {
                        self.edges.push(edge);
                    }
                    self.autoload_name(&function, Some("prompt"));
                }
                None => {
                    let doubt = doubt();
                    self.doubt(doubt);
                }
            }
        }
    }

    /// Read the first line of each completion function in the `fpath`
    /// directories, which the stock `compinit` reads to mark them when it
    /// finds no dump file it can use: an `#autoload` with a word but `+X`
    /// (`-w`, which marks the functions of a compiled file, or the name of
    /// another function) marks what the check cannot follow, a doubt.
    fn first_lines(&mut self) {
        let dirs: Vec<PathBuf> = self
            .fpath
            .iter()
            .filter_map(|entry| entry.as_ref().ok().map(|(dir, _)| dir.clone()))
            .filter(|dir| !self.first_lines_read.contains(dir))
            .collect();
        for dir in dirs {
            self.first_lines_read.push(dir.clone());
            let Ok(entries) = self.fs.list_directory(&dir) else {
                continue;
            };
            for entry in entries {
                let Some(name) = entry.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if !name.starts_with('_') || name.ends_with('~') || name.ends_with(".zwc") {
                    continue;
                }
                let line = match first_line(self.fs, &entry) {
                    Ok(Some(line)) => line,
                    Ok(None) => continue,
                    Err(why) => {
                        self.doubt(format!("it could not read {} ({why})", entry.display()));
                        continue;
                    }
                };
                if !known_first_line(name, &line) {
                    self.doubt(format!(
                        "it cannot tell what the first line of {} makes compinit mark (`{line}`)",
                        entry.display()
                    ));
                }
            }
        }
    }

    /// Add to `fpath` what the stock `compaudit`, which `compinit` runs, may
    /// put at its end: the directories under each directory of it that holds
    /// a `Base` directory (two deep with `Base/Core`), as zsh's own completion
    /// functions are laid out when its build parts them. A `_compdir` named in
    /// a file read, which picks that directory, is a doubt.
    pub(super) fn audit(&mut self) {
        if !self.compaudit {
            return;
        }
        if let Some(place) = self.compdir.clone() {
            self.doubt(format!(
                "it cannot tell which directories compaudit, which compinit runs, puts in fpath, \
                 as {place} names _compdir"
            ));
            return;
        }
        let dirs: Vec<PathBuf> = self
            .fpath
            .iter()
            .filter_map(|entry| entry.as_ref().ok().map(|(dir, _)| dir.clone()))
            .filter(|dir| !self.audited.contains(dir))
            .collect();
        for dir in dirs {
            self.audited.push(dir.clone());
            let depth = if matches!(self.fs.is_directory(&dir.join("Base/Core")), Ok(true)) {
                2
            } else if matches!(self.fs.is_directory(&dir.join("Base")), Ok(true)) {
                1
            } else {
                continue;
            };
            let mut level = vec![dir.clone()];
            for _ in 0..depth {
                let mut next = Vec::new();
                for parent in level {
                    match self.fs.list_directory(&parent) {
                        Ok(entries) => next.extend(
                            entries
                                .into_iter()
                                .filter(|entry| matches!(self.fs.is_directory(entry), Ok(true))),
                        ),
                        Err(error) => self.doubt(format!(
                            "it could not read the directory {} that compaudit may put in fpath \
                             ({error})",
                            parent.display()
                        )),
                    }
                }
                level = next;
            }
            for sub in level {
                let entry = Ok((sub, false));
                if !self.fpath.contains(&entry) {
                    self.fpath.push(entry);
                }
            }
        }
    }
}

/// The first line of the file at `path`, as `read -r` reads it, when it is
/// a regular file; `None` for anything else; `Err` when the check cannot
/// read it or the line runs past the bytes it reads.
fn first_line<F: Filesystem>(fs: &F, path: &Path) -> Result<Option<String>, String> {
    const LINE_LIMIT: usize = 4096;
    let path = fs.canonicalize(path).map_err(|error| error.to_string())?;
    if !matches!(fs.is_regular_file(&path), Ok(true)) {
        return Ok(None);
    }
    let bytes = fs
        .read_file_range(&path, 0, LINE_LIMIT)
        .map_err(|error| error.to_string())?;
    match bytes.iter().position(|byte| *byte == b'\n') {
        Some(end) => Ok(Some(String::from_utf8_lossy(&bytes[..end]).into_owned())),
        None if bytes.len() < LINE_LIMIT => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
        None => Err(format!("its first line is longer than {LINE_LIMIT} bytes")),
    }
}

/// The completion functions of zsh 5.9 to 5.9.2 whose first line binds keys
/// to them, and that line, which binds keys a line is not typed with.
const KEY_LINES: [(&str, &str); 12] = [
    ("_read_comp", "#compdef -k complete-word \\C-x\\C-r"),
    ("_next_tags", "#compdef -k list-choices \\C-xn"),
    ("_most_recent_file", "#compdef -k complete-word \\C-xm"),
    (
        "_history_complete_word",
        "#compdef -K _history-complete-older complete-word \\e/ _history-complete-newer \
         complete-word \\e,",
    ),
    (
        "_expand_word",
        "#compdef -K _expand_word complete-word \\C-xe _list_expansions list-choices \\C-xd",
    ),
    (
        "_expand_alias",
        "#compdef -K _expand_alias complete-word \\C-xa",
    ),
    ("_correct_word", "#compdef -k complete-word \\C-xc"),
    ("_correct_filename", "#compdef -k complete-word \\C-xC"),
    ("_complete_tag", "#compdef -k complete-word \\C-xt"),
    ("_complete_help", "#compdef -k complete-word \\C-xh"),
    ("_complete_debug", "#compdef -k complete-word \\C-x?"),
    (
        "_bash_completions",
        "#compdef -K _bash_complete-word complete-word \\e~ _bash_list-choices list-choices ^X~",
    ),
];

/// Whether `line`, the first line of the completion function `name`, is
/// one whose marks the check knows, as the stock `compinit` reads it (its
/// words split at blanks): any but an `#autoload` with a word other than
/// `+X`, which loads the function at once without running it, and a
/// `#compdef` that binds keys (`-k`, `-K`) that is not one of zsh's own
/// ([`KEY_LINES`]), which may bind a key a line is typed with. compinit runs
/// `autoload -rUz` with the words of an `#autoload` line and the function's
/// name; a `#compdef` line names the commands and keys whose completion runs
/// the function.
fn known_first_line(name: &str, line: &str) -> bool {
    let mut words = line.split([' ', '\t']).filter(|word| !word.is_empty());
    match words.next() {
        Some("#autoload") => words.all(|word| word == "+X"),
        Some("#compdef") if words.any(|word| matches!(word, "-k" | "-K")) => KEY_LINES
            .iter()
            .any(|(stock, known)| *stock == name && *known == line),
        _ => true,
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::{Stock, digest};

    /// The text a test gives a stock function's file, which the check takes
    /// for the stock code of `name` in a test, as no test carries zsh's own.
    pub(in super::super) fn text(name: &str) -> String {
        format!("# The stock {name} of a test.\ntypeset -A _i_test\n")
    }

    /// The stock function `name` is in a test when `digest` is that of its
    /// [`text`].
    pub(super) fn known(name: &str, digest: &str) -> Option<Stock> {
        let stock = match name {
            "compinit" => Stock::Compinit,
            "compaudit" => Stock::Compaudit,
            "compdump" => Stock::Compdump,
            "promptinit" => Stock::Promptinit,
            "add-zsh-hook" => Stock::AddZshHook,
            "add-zle-hook-widget" => Stock::AddZleHookWidget,
            _ => return None,
        };
        (digest == super::digest(text(name).as_bytes())).then_some(stock)
    }

    #[test]
    fn a_stock_function_is_known_by_its_name_and_its_bytes_alone() {
        assert_eq!(
            super::known("compinit", text("compinit").as_bytes()),
            Some(Stock::Compinit)
        );
        // The same bytes under another name, or other bytes, are no stock
        // function.
        assert_eq!(super::known("compaudit", text("compinit").as_bytes()), None);
        assert_eq!(
            super::known("compinit", b"# The stock compinit of a test.\n"),
            None
        );
        assert_eq!(
            digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // pragma: allowlist secret
        );
    }

    /// Where the dev shell has zsh from the Nix store, its own functions are
    /// the ones the check knows.
    #[test]
    fn the_functions_of_the_zsh_of_the_dev_shell_are_known() {
        let Some(zsh) = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|dir| dir.join("zsh"))
            .find(|path| path.is_file())
            .and_then(|path| std::fs::canonicalize(path).ok())
        else {
            return;
        };
        let Some(version) = zsh
            .to_str()
            .and_then(|path| path.strip_prefix("/nix/store/"))
            .and_then(|path| path.strip_suffix("/bin/zsh"))
            .and_then(|name| name.split_once("-zsh-"))
            .map(|(_, version)| version.to_string())
        else {
            return;
        };
        let functions = zsh
            .parent()
            .and_then(std::path::Path::parent)
            .expect("the store path")
            .join("share/zsh")
            .join(&version)
            .join("functions");
        for name in [
            "compinit",
            "compaudit",
            "compdump",
            "promptinit",
            "add-zsh-hook",
            "add-zle-hook-widget",
        ] {
            let bytes = std::fs::read(functions.join(name)).expect("zsh's own function");
            assert!(
                super::STOCK
                    .iter()
                    .any(|(stock, _, known)| *stock == name && *known == digest(&bytes)),
                "{name} of zsh {version} is not among the stock functions"
            );
        }
    }
}
