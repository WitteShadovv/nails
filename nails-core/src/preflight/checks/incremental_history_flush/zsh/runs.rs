// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the code the files define does as zsh runs it, once every file is
//! read: where the redirections the files make write, what the functions
//! zsh runs as hooks write or may write, and where the aliases the files
//! define are used.

use super::{Forms, Reader, Word, backstop, builtins, walk};
use crate::Filesystem;

/// How a command a function runs may write what the shell's code gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Fed {
    /// An expansion makes a word it is given, which may name the history
    /// file (`tee -a $f`).
    Word,
    /// It reads what an expansion makes ([`walk::Input::Computed`]).
    Input,
    /// It reads what the commands before it in its pipeline write, each
    /// one's name and whether an expansion makes a word of it
    /// ([`walk::Input::Piped`]).
    Pipe(Vec<(String, bool)>),
}

/// Whether `target`, a redirection's target as written, is a device that
/// is no file: the terminal (`/dev/tty`), nothing (`/dev/null`), or standard
/// input, output or error (`/dev/stderr`, `/dev/fd/2`). `$TTY` is none: zsh
/// expands it to what the parameter holds, which the files may change by
/// ways the check cannot all read (a pattern, a name an expansion makes).
fn device(target: &str) -> bool {
    // Standard input, output and error: a descriptor above 2 may be any file
    // the shell has open (`zsystem flock`, `exec 3>>file`).
    let descriptor = |rest: Option<&str>| rest.is_some_and(|rest| matches!(rest, "0" | "1" | "2"));
    matches!(
        target,
        "/dev/null" | "/dev/tty" | "/dev/stdout" | "/dev/stderr" | "/dev/stdin"
    ) || descriptor(target.strip_prefix("/dev/fd/"))
        || descriptor(target.strip_prefix("/proc/self/fd/"))
}

/// Whether the check cannot count where zsh expands a global alias named
/// `name` by the words of the code ([`Forms::uses`]): zsh looks a global alias
/// up for every token it reads, an operator's too, and splits a token off a
/// word at an operator (`<`, `>`, `|`, `&`, `;`, `(`, `)`), at the `{` that
/// starts a command and at the `}` that ends a word, with no blank beside it,
/// so a name that holds one of them, or a blank, may stand where no word is
/// (`print -r -- $1>/dev/tty` uses an alias named `>`). An empty name is one
/// the check could not read.
fn uncountable(name: &str) -> bool {
    name.is_empty()
        || name.contains(['<', '>', '|', '&', ';', '(', ')', '{', '}'])
        || name.chars().any(char::is_whitespace)
}

impl<F: Filesystem> Reader<'_, F> {
    /// Note a redirection to `target`, as written, in the function `function`
    /// when in one, by the file at `place`: one to the history file by its
    /// name writes it; one to a device writes no file while no file defines
    /// a global alias ([`Reader::devices`]). One whose target an expansion
    /// makes (`computed`), `$TTY` among them, or that is any other file,
    /// which may be the history file (one `HISTFILE` names, a link to it), is
    /// a doubt where an `exec` keeps it open (`kept`), as a hook may write to
    /// the descriptor, and where a hook makes it.
    pub(super) fn redirect(
        &mut self,
        target: &str,
        function: Option<String>,
        computed: bool,
        kept: bool,
        place: &str,
    ) {
        if !device(target) {
            let what = format!("{place} redirects output to `{target}`");
            self.makes(target, what, function.clone());
        }
        if backstop::history_path(target) {
            let what = format!("{place} redirects output to `{target}`");
            if !self.fc.contains(&what) {
                self.fc.push(what);
            }
            return;
        }
        if device(target) {
            if kept || function.is_some() {
                self.devices.push((
                    function.filter(|_| !kept),
                    target.to_string(),
                    place.to_string(),
                ));
            }
            return;
        }
        if kept {
            self.doubt(format!(
                "it cannot tell where the descriptor that {place} keeps open to `{target}` goes, \
                 which may be the history file a hook writes each command line to"
            ));
        } else if let Some(function) = function {
            let doubt = if computed {
                format!(
                    "it cannot tell where the output that `{function}` in {place} redirects to \
                     `{target}` goes, which may be the history file"
                )
            } else {
                format!(
                    "it cannot tell whether `{target}`, which `{function}` in {place} redirects \
                     output to, is the history file (a file HISTFILE names, or a link to it)"
                )
            };
            self.in_functions.push((function, Err(doubt)));
        }
    }

    /// Whether a function named `function` is one zsh runs as a hook: by its
    /// name (`preexec`, `TRAPDEBUG`), as the dispatcher that the stock
    /// `add-zle-hook-widget` runs as each line is entered (`azhw:...`), as
    /// the files make it one or a hook runs it (`hooked`), as it is named
    /// like a builtin, which zsh's own code runs as each line is entered
    /// (`zstyle`, `zle`), like the command a NAILS command is typed with
    /// (`sudo`, `nails`), which runs with that line ([`builtins::typed`]), or
    /// like a command a widget runs with the line at hand (`run-help`,
    /// [`builtins::line_command`]).
    pub(super) fn is_hook(function: &str, hooked: &[String]) -> bool {
        walk::HOOKS.contains(&function)
            || builtins::builtin(function)
            || builtins::typed(function)
            || builtins::line_command(function)
            || function.starts_with("TRAP")
            || function.starts_with("azhw:")
            || hooked.iter().any(|hook| hook == function)
    }

    /// Note what runs as zsh runs: a redirection to a device where a file
    /// defines a global alias; an alias for an `fc` that writes nothing where
    /// a file uses it; keys that may type others or that `SH_WORD_SPLIT` may
    /// bind otherwise; what the functions zsh runs as hooks write or may
    /// write; and what may change NixOS's dircolors line
    /// ([`Reader::dircolors_doubts`]).
    pub(super) fn runs(&mut self) {
        // A redirection to a device writes no file, unless a file defines a
        // global alias: zsh may put its value in place of any token of the
        // redirection as it reads it, the `>` glued to a word in
        // `print -r -- $1>/dev/tty` among them.
        for (function, target, place) in std::mem::take(&mut self.devices) {
            let Some((_, text, at)) = self.global_alias_defs.first() else {
                continue;
            };
            let why = format!(
                "{at} defines the global alias `{text}`, which zsh may put in place of a word or \
                 an operator of it"
            );
            let doubt = format!(
                "it cannot tell where the output that {} in {place} redirects to `{target}` \
                 goes, as {why}",
                function
                    .as_ref()
                    .map_or_else(|| "`exec`".to_string(), |function| format!("`{function}`"))
            );
            match function {
                Some(function) => self.in_functions.push((function, Err(doubt))),
                None => self.doubt(doubt),
            }
        }
        // An alias for an fc that writes nothing hands it the words it is used
        // with: harmless while no file uses its name but where it is defined.
        let mut aliases = std::mem::take(&mut self.fc_aliases);
        aliases.sort();
        aliases.dedup();
        for (name, text, place) in &aliases {
            // Each definition names it as often as its own words do; one
            // written twice alike counts once, so the second is a use.
            let defined: usize = aliases
                .iter()
                .filter(|(other, ..)| other == name)
                .map(|(_, text, _)| Forms::of(text).uses(name))
                .sum();
            let named: usize = self
                .texts
                .iter()
                .map(|forms| forms.uses(name))
                .sum::<usize>();
            if named > defined {
                self.doubt(format!(
                    "it cannot tell what the alias `{text}` in {place} runs where it is used, as zsh \
                     hands the fc it stands for the words after it"
                ));
            }
        }
        self.global_alias_uses();
        // Keys a file binds or unbinds may make the keys a string types run
        // other widgets than the ones that type it.
        if let Some(rebound) = self.rebound.clone() {
            for (text, place) in std::mem::take(&mut self.typed_keys) {
                self.doubt(format!(
                    "it cannot tell what the keys that type `{}` in {place} run, as {rebound} \
                     binds a key a line is typed with or changes a widget or a keymap",
                    text.trim()
                ));
            }
        }
        // A word of a bindkey read as one word or none, which SH_WORD_SPLIT
        // or KSH_ARRAYS may make several of.
        if let Some(split) = self.word_split.clone() {
            for (bindkey, word, place) in std::mem::take(&mut self.keys_splits) {
                self.doubt(format!(
                    "it cannot tell which keys `{bindkey}` in {place} binds to what, as {split} \
                     may turn SH_WORD_SPLIT or KSH_ARRAYS on, with which `{word}` may expand to \
                     several words"
                ));
            }
        }
        // What a function holds counts where zsh runs it as a hook: by its name,
        // as the files make it one, as a hook runs it, or as it is named like a
        // builtin.
        let mut hooked = self.hooks.clone();
        loop {
            let before = hooked.len();
            for (caller, callee) in &self.edges {
                if Self::is_hook(caller, &hooked) && !Self::is_hook(callee, &hooked) {
                    hooked.push(callee.clone());
                }
            }
            if hooked.len() == before {
                break;
            }
        }
        self.handed(&hooked);
        for (function, found) in std::mem::take(&mut self.in_functions) {
            let hook = Self::is_hook(&function, &hooked);
            match found {
                Ok(write) if hook && !self.fc.contains(&write) => self.fc.push(write),
                Err(doubt) if hook => self.doubt(doubt),
                _ => {}
            }
        }
        // A command a hook runs with a word an expansion makes may write the
        // file that word names (`tee -a $f`), and one that reads what the
        // shell's code gives it may write that, the command line among it
        // (`print -r -- "$1" | tee -a file`), unless it is a function or an
        // alias the check reads, or a builtin that writes no file.
        for (function, command, place, fed) in std::mem::take(&mut self.computed_calls) {
            if !Self::is_hook(&function, &hooked)
                || self.defined.contains(&command)
                || self.autoloads.contains(&command)
                || (builtins::quiet(&command) && !self.outside(&command))
            {
                continue;
            }
            let what = match fed {
                Fed::Word => {
                    "as an expansion makes a word it is given, which may name the \
                              history file"
                }
                Fed::Pipe(feeders) if !self.carries(&feeders) => continue,
                Fed::Input | Fed::Pipe(_) => {
                    "as it reads what the shell gives it, which may \
                                             be the command line"
                }
            };
            self.doubt(format!(
                "it cannot tell what `{command}` in `{function}` in {place} writes, {what}"
            ));
        }
        self.dircolors_doubts();
    }

    /// Note a doubt for each global alias the files define whose name a word
    /// of the code they read holds beyond its definitions: zsh puts its value
    /// in place of that word as it reads the code, which may then run, set or
    /// define anything (`set -A X w`, `function X`, `read X`, `print -r -- "$1"
    /// X`). An alias defined twice alike counts once, so the second is a use.
    /// One named like a word of the NAILS commands the operator types
    /// ([`builtins::typed_word`]: `sudo`, `activate`, `--yes`) counts as used,
    /// as zsh puts its value in place of that word of the line, and so does
    /// one named like a command the widgets `run-help` and `which-command`
    /// run with the line at hand ([`builtins::line_word`]), or like a name
    /// the files make a hook, which `zle -A` gives the widget they run as.
    /// One whose uses the check cannot count ([`uncountable`]) is a doubt
    /// wherever it is defined.
    fn global_alias_uses(&mut self) {
        let mut definitions = std::mem::take(&mut self.global_alias_defs);
        definitions.sort();
        definitions.dedup();
        for (name, text, place) in &definitions {
            if builtins::typed_word(name) {
                self.doubt(format!(
                    "it cannot tell what the global alias `{text}` in {place} runs as you enter a \
                     NAILS command, as zsh puts its value in place of a word of that line named \
                     like it (`sudo`, `activate`, `--yes`)"
                ));
                continue;
            }
            if builtins::line_word(name) || self.hooks.contains(name) {
                self.doubt(format!(
                    "it cannot tell what the global alias `{text}` in {place} runs as a widget runs \
                     a command of its name with the line you type at hand (`run-help`, `man`)"
                ));
                continue;
            }
            if uncountable(name) {
                self.doubt(format!(
                    "it cannot tell what code the global alias `{text}` in {place} runs, as zsh \
                     puts its value in place of each token that is its name, which the check \
                     cannot count where the name holds an operator, a brace or a blank, or is \
                     empty"
                ));
                continue;
            }
            let defined: usize = definitions
                .iter()
                .filter(|(other, ..)| other == name)
                .map(|(_, text, _)| Forms::of(text).uses(name))
                .sum();
            let named: usize = self.texts.iter().map(|forms| forms.uses(name)).sum();
            if named > defined {
                self.doubt(format!(
                    "it cannot tell what the code that uses the global alias `{text}` in {place} \
                     runs, as zsh puts the alias's value in place of each word that is its name"
                ));
            }
        }
    }

    /// Note the builtins a `disable` of `args` takes away, after which zsh
    /// runs what PATH finds by their names ([`Reader::outside`]): each name,
    /// a pattern of `-m`, or any where a word an expansion, brace expansion or
    /// a glob may make stands among them; none with `-a`, `-f`, `-p`, `-r` or
    /// `-s`, which disable aliases, functions, patterns or reserved words.
    /// One that may take away a builtin by which the walk reads a setting is
    /// a doubt ([`Reader::disable_setters`]).
    pub(super) fn disable(&mut self, args: &[Word], place: &str) {
        let known = self.disabled.len();
        self.disable_names(args);
        let added = self.disabled[known..].to_vec();
        self.disable_setters(&added, place);
    }

    /// Note the builtins a `disable` of `args` takes away ([`Reader::disable`]).
    fn disable_names(&mut self, args: &[Word]) {
        let mut at = 0;
        let mut letters = String::new();
        while let Some(word) = args.get(at) {
            if word.expands || word.bare {
                self.disabled.push(String::from("*"));
                return;
            }
            let Some(flags) = word
                .text
                .strip_prefix('-')
                .filter(|flags| !flags.is_empty())
            else {
                break;
            };
            at += 1;
            if flags == "-" {
                break;
            }
            letters.push_str(flags);
        }
        if letters.contains(['a', 'f', 'p', 'r', 's']) {
            return;
        }
        for word in &args[at..] {
            if word.expands || word.bare {
                self.disabled.push(String::from("*"));
            } else if letters.contains('m') {
                self.disabled.push(word.text.clone());
            } else {
                // A name as it is, its pattern characters too.
                self.disabled.push(word.text.replace(
                    [
                        '*', '?', '[', ']', '(', ')', '|', '#', '^', '~', '<', '>', '\\',
                    ],
                    "?",
                ));
            }
        }
    }

    /// Whether a builtin named `name` may run as an outside program of that
    /// name, as zsh runs what PATH finds by the name of one a file disables
    /// (`disable print`, `disable -m 'p*'`, [`Reader::disable`]).
    pub(super) fn outside(&self, name: &str) -> bool {
        builtins::builtin(name)
            && self
                .disabled
                .iter()
                .any(|pattern| walk::may_match(pattern, name))
    }

    /// Whether the commands that feed a pipeline, `feeders`, each one's name
    /// and whether an expansion makes a word of it, may write the command
    /// line into it: one an expansion makes a word of (`print -r -- "$1"`),
    /// an `fc` or a `history` that lists the history, a function or an alias
    /// the files define, which may print anything; any when the check does
    /// not know them (none listed). A command the files do not define given
    /// only words as written writes nothing of the command line.
    fn carries(&self, feeders: &[(String, bool)]) -> bool {
        feeders.is_empty()
            || feeders.iter().any(|(name, expands)| {
                *expands
                    || matches!(name.as_str(), "fc" | "history" | "r")
                    || self.defined.contains(name)
                    || self.autoloads.contains(name)
            })
    }
}
