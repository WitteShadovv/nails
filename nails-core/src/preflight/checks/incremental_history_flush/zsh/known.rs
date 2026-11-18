// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The commands the zsh reader knows to be harmless: the list the startup
//! code keeps to, and every hook, widget, alias, function and job it reaches
//! ([`super::reached`]). Each command is read exactly, past its
//! precommands, by its name and every word ([`command`]); one the list does
//! not hold, or holds in another form, is a doubt ([`Verdict::Unknown`]). So
//! a command the reader reads that the list does not hold makes the check
//! warn that it cannot tell; one the reader does not read as zsh runs it,
//! the list never sees. What each entry does, and why that is harmless:
//!
//! - `:`, `true`, `false`, `[`, `test` and `[[ ... ]]` give a status and do
//!   nothing else. `print`, `echo` and `printf` write text to the terminal,
//!   with the options that only shape that text: not `print -z`, which puts
//!   the text in the line zsh edits next, `-s` and `-S`, which put it in the
//!   history, `-v`, which sets a parameter, `-u` and `-p`, which write to a
//!   descriptor or a coprocess, nor `printf -v`, and only where no word that
//!   may be an option is one an expansion makes. `whence`, `where`, `which`,
//!   `type`, `command -v` and `-V`, `jobs`, `dirs`, `pwd`, `times` and `log`
//!   print what names, jobs, directories, times and logins are; `wait` waits
//!   for the jobs, which the reader reads where they start ([`super::jobs`]).
//! - `return`, `break`, `continue` and `shift` end a function or a loop or
//!   shift its arguments. `exit`, `bye` and `logout` end the shell as the
//!   startup files run, before a line is typed; in a function a hook may run,
//!   the reader reads them as what may end the shell
//!   ([`super::walk::Event::Ends`]).
//! - `cd`, `chdir`, `pushd` and `popd` change the directory the shell is in,
//!   which runs the `chpwd` hooks, read as hooks; `umask` sets the mode files
//!   are made with; `rehash`, `hash` alone, `hash -r` and `hash -d` clear the
//!   table of commands or name a directory (`hash -d src=~/src`), not one
//!   that maps a command's name to a program.
//! - `setopt` and `unsetopt` of options by name, a loop's variable over
//!   names the walk lists among them, `set -o` and `set +o` of them, and the
//!   `-o` and `+o` of `emulate`, for every option of zsh 5.9 to 5.9.2 but
//!   `CSH_JUNKIE_LOOPS` ([`options::DOUBTED_OPTIONS`]): the three that write
//!   each line as zsh runs count as such a write, those that change how zsh
//!   reads code as the reader says ([`super::reading`]), and each other one
//!   changes what completion, globbing, history expansion, the prompt, job
//!   control, an error or the line editor do, none of which makes zsh write
//!   the lines typed before it ends or run another line than the one typed
//!   (with `ERR_EXIT` zsh ends as a typed command fails, and writes no
//!   history file then). `set` alone,
//!   `set -o` and `set +o` alone, which print, `set --`, which sets the
//!   arguments, and `set -A`, which sets an array, are on the list too, and
//!   `emulate` of zsh's, sh's or ksh's mode (by the first letter of its name
//!   past one `r`, as zsh picks it), with `-L` and `-R`, and of code `-c`
//!   gives as written, which the reader reads.
//! - `typeset`, `declare`, `local`, `export`, `readonly`, `integer`, `float`
//!   and `private` with the options that give a parameter attributes, print
//!   or mark functions, `unset` of parameters by name, and an assignment,
//!   each of a parameter [`parameter`] lets be: one of the user's own, which
//!   no part of zsh reads; one of zsh's own that sets where and how much
//!   history zsh keeps, the paths it finds commands and directories in, the
//!   locale, the terminal's name and the like
//!   ([`parameters::HARMLESS_PARAMETERS`]); or one whose effect the reader
//!   reads itself (`ZDOTDIR`, `fpath`, the prompts, `TMOUT`, the arrays of
//!   hook functions). Of zsh's own parameters any other is a doubt
//!   ([`parameters::OWN_PARAMETERS`]), and so is, in a function, one of the
//!   line editor's ([`ZLE_PARAMETERS`]), which may change the line zsh runs
//!   (`HISTNO`, `BUFFER`).
//! - `source` and `.` of a file the reader reads; `eval` of words as written,
//!   whose code the reader reads as its own; `autoload` of functions by name
//!   or path, whose files it reads where they run; `alias`, whose values it
//!   reads where they are used; `functions` that prints, copies or marks
//!   functions to be autoloaded; `trap` of code as written, which it reads as
//!   the hook of its signal, or that takes a trap away (`''`, `-`); `zstyle`
//!   that sets, takes away, lists or tests a style (not one that copies a
//!   style's value into a parameter); `let`, whose arithmetic it reads.
//! - `bindkey -e` and `-v`, which pick zsh's own emacs or vi keymap for the
//!   line, and `bindkey` alone, `-l` and `-L`, which list; `zle -l` and `-L`,
//!   which list the widgets; `fc` and `history` that list the history, or
//!   write, read, push or pop the history file (`fc -AI`, `fc -R`, `fc -p`),
//!   which the reader counts as a write of the file where one may be
//!   ([`super::walk::Event::Fc`]), not one that runs lines from it (`fc -e`,
//!   `fc -s`, an `fc` with none of those flags, `r`); and `kill -l` and `-L`,
//!   which list the signals. Any other key binding, widget, `zle` or
//!   `add-zle-hook-widget` is a doubt: it may make a key typed, or the line
//!   accepted, run another line than the one typed.
//! - A command by a name that is no builtin of zsh's and no reserved word
//!   ([`Verdict::Named`]) runs the function or the alias of that name the
//!   files define or autoload, whose code the reader reads, where one is
//!   certainly defined before it runs; else zsh runs the outside program
//!   PATH finds by that name, which may change the terminal, signal the
//!   shell or leave a process that does later, and that is a doubt
//!   ([`super::reached`]). So is a program by its path, one `command` or
//!   `exec` runs, and a coprocess.
//!
//! The cuts that held through every round are entries of the list by their
//! exact form: the stock `promptinit` and the functions it autoloads, known
//! by the SHA-256 of their files ([`super::stock`]), NixOS's dircolors line
//! in `/etc/zshrc` ([`super::install::dircolors_split`]), and an alias that
//! stands for an `fc` that only lists, where no file uses it with other
//! words ([`super::walk::Event::FcAlias`]).

mod options;
mod parameters;

pub(super) use options::option;
pub(super) use parameters::{ZLE_PARAMETERS, arithmetic_parameter, parameter};

use super::lexer::Word;

/// What the list says of a command ([the module](self)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Verdict {
    /// On the list, read exactly.
    Known,
    /// It runs by a name that is no builtin of zsh's and no reserved word:
    /// the function or the alias the files define or autoload by that name,
    /// or an outside program, as the reader decides once the files are read.
    Named,
    /// None the list holds: why, as a doubt says it after the command.
    Unknown(String),
}

/// How the command the list is asked about runs.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct How<'a> {
    /// After `command`, which runs an outside program.
    pub(super) outside: bool,
    /// After `exec`, which runs it in the shell's place.
    pub(super) exec: bool,
    /// The function whose code it is, when it is in one.
    pub(super) function: Option<&'a str>,
}

/// The builtins of zsh 5.9 to 5.9.2 the list reads by name, beside the
/// precommands (`builtin`, `command`, `exec`, `noglob`, `nocorrect`, `-`,
/// `time`, `!`), which the walk reads past: any other builtin runs in a form
/// the list does not hold. A name of a builtin of a module zsh does not load
/// as it is first run ([`super::builtins::unloaded`]) runs an outside
/// program by that name.
const LISTED: &[&str] = &[
    ":",
    "true",
    "false",
    "[",
    "[[",
    "test",
    "print",
    "echo",
    "printf",
    "whence",
    "where",
    "which",
    "type",
    "jobs",
    "dirs",
    "pwd",
    "times",
    "log",
    "wait",
    "return",
    "break",
    "continue",
    "shift",
    "exit",
    "bye",
    "logout",
    "cd",
    "chdir",
    "pushd",
    "popd",
    "umask",
    "rehash",
    "hash",
    "setopt",
    "unsetopt",
    "set",
    "emulate",
    "typeset",
    "declare",
    "local",
    "export",
    "readonly",
    "integer",
    "float",
    "private",
    "unset",
    "source",
    ".",
    "eval",
    "autoload",
    "alias",
    "functions",
    "trap",
    "zstyle",
    "let",
    "bindkey",
    "zle",
    "fc",
    "history",
    "kill",
];

/// The letters of the options of the `typeset` family that give a parameter
/// attributes, print or mark functions, as zsh 5.9 to 5.9.2 take them: `-m`,
/// whose patterns the reader reads as a doubt of its own, among them.
const TYPESET_LETTERS: &str = "aAEFfghHilLmprRtTuUxZ"; // pragma: allowlist secret

/// The commands a regular alias may end with that take whatever words it is
/// used with harmlessly, as a test or what prints: zsh hands the alias's last
/// command the words after it where it is used (`alias k=kill`, then `k -HUP
/// $$`), so an alias that ends with any other is a doubt where the files use
/// it with words ([`super::reached`]).
pub(super) const TAKES_ANY_WORDS: &[&str] = &[
    ":", "true", "false", "test", "[", "echo", "cd", "chdir", "pushd", "popd", "dirs", "pwd",
    "jobs", "times", "whence", "where", "which", "type",
];

/// Whether `word` holds an expansion, brace expansion or a glob, so that
/// zsh may make any word of it, an option among them.
fn computed(word: &Word) -> bool {
    word.expands || word.bare
}

/// Whether the first character of `word` may be one an expansion, brace
/// expansion or a glob gives it (`$o`, `"$o"`, `{-z,x}`, `*`), which may be a
/// `-`, so that it may be an option; of a `$'...'` quote, which the lexer
/// keeps as written, a first character that is a sign or an escape.
fn starts_computed(word: &Word) -> bool {
    if let Some(quoted) = word.text.strip_prefix("$'") {
        return quoted.starts_with(['-', '+', '\\']);
    }
    (word.expands && word.text.starts_with(['$', '`']))
        || (word.bare && word.text.starts_with(['$', '`', '{', '*', '?', '[', '(']))
}

/// The words of `words`, as a doubt shows them.
fn shown(words: &[Word]) -> String {
    words
        .iter()
        .map(|word| word.text.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The letters of the options a builtin of `args` starts with, as zsh reads
/// them: each word that starts with `-` (or `+` where `plus`) up to the
/// first that does not, or that is a sign and a digit (`-20`), `-` and `--`
/// ending them; a letter of `valued` takes the rest of its word or the next
/// word, and one of `numbered` the rest of its word or the next word where
/// that is a number. `Err` with a word where they may stand that an
/// expansion may make, which may be any option; else the letters and how
/// many words they took.
fn letters<'a>(
    args: &'a [Word],
    plus: bool,
    valued: &str,
    numbered: &str,
) -> Result<(String, usize), &'a Word> {
    let digit = |text: &str| text.starts_with(|c: char| c.is_ascii_digit());
    let mut letters = String::new();
    let mut at = 0;
    'words: while let Some(word) = args.get(at) {
        if starts_computed(word) {
            return Err(word);
        }
        let Some(rest) = word
            .text
            .strip_prefix('-')
            .or_else(|| word.text.strip_prefix('+').filter(|_| plus))
        else {
            break;
        };
        if digit(rest) {
            break;
        }
        if computed(word) {
            return Err(word);
        }
        at += 1;
        if rest.is_empty() || rest == "-" {
            break;
        }
        // `--fu` reads as `-fu`.
        let rest = rest.strip_prefix('-').unwrap_or(rest);
        for (index, letter) in rest.char_indices() {
            letters.push(letter);
            let tail = &rest[index + letter.len_utf8()..];
            if valued.contains(letter) {
                if tail.is_empty() {
                    at += 1;
                }
                continue 'words;
            }
            if numbered.contains(letter) {
                if digit(tail) {
                    continue 'words;
                }
                if tail.is_empty() && args.get(at).is_some_and(|next| digit(&next.text)) {
                    at += 1;
                    continue 'words;
                }
            }
        }
    }
    Ok((letters, at))
}

/// The verdict of `print` of `args`: on the list where its options only
/// shape the text it writes ([the module](self)).
fn print(args: &[Word]) -> Verdict {
    match letters(args, false, "fuv", "CxX") {
        Err(word) => Verdict::Unknown(format!(
            "zsh may expand `{}` into any option of `print`, `-z` among them",
            word.text
        )),
        Ok((letters, _)) => match letters.chars().find(|letter| "zsSvup".contains(*letter)) {
            Some(letter) => Verdict::Unknown(format!(
                "`print -{letter}` {}",
                match letter {
                    'z' => "puts the text in the line zsh edits next",
                    's' | 'S' => "puts the text in the history",
                    'v' => "sets a parameter",
                    _ => "writes to a descriptor or a coprocess",
                }
            )),
            None => Verdict::Known,
        },
    }
}

/// The verdict of the builtin `name` of `args`, one of [`LISTED`].
fn builtin(name: &str, args: &[Word]) -> Verdict {
    let unknown = |why: &str| Verdict::Unknown(why.to_string());
    let first = args.first().map(|word| word.text.as_str());
    match name {
        ":" | "true" | "false" | "[" | "[[" | "test" | "echo" | "whence" | "where" | "which"
        | "type" | "jobs" | "dirs" | "pwd" | "times" | "log" | "wait" | "return" | "break"
        | "continue" | "shift" | "exit" | "bye" | "logout" | "cd" | "chdir" | "pushd" | "popd"
        | "umask" | "rehash" | "source" | "." | "alias" | "let" => Verdict::Known,
        "print" => print(args),
        "printf" => match args.first() {
            Some(word) if computed(word) => {
                unknown("zsh may expand its first word into `-v`, with which it sets a parameter")
            }
            Some(word) if word.text.starts_with("-v") => unknown("`printf -v` sets a parameter"),
            _ => Verdict::Known,
        },
        "hash" => match letters(args, false, "", "") {
            Ok((letters, at))
                if letters.chars().all(|letter| "dr".contains(letter))
                    && (letters.contains('d') || at == args.len()) =>
            {
                Verdict::Known
            }
            _ => unknown("`hash` may map a command's name to the program zsh runs for it"),
        },
        "setopt" | "unsetopt" => {
            for word in args {
                if computed(word) || word.text.starts_with(['-', '+']) {
                    return Verdict::Unknown(format!(
                        "it cannot tell which options `{}` names",
                        word.text
                    ));
                }
                if let Some(why) = option(&word.text) {
                    return Verdict::Unknown(why);
                }
            }
            Verdict::Known
        }
        "set" => set(args),
        "emulate" => emulate(args),
        "typeset" | "declare" | "local" | "export" | "readonly" | "integer" | "float"
        | "private" => match letters(args, true, "", "EFLRZip") {
            Err(word) => Verdict::Unknown(format!(
                "zsh may expand `{}` into any of its options",
                word.text
            )),
            Ok((letters, _))
                if letters
                    .chars()
                    .all(|letter| TYPESET_LETTERS.contains(letter)) =>
            {
                Verdict::Known
            }
            Ok(_) => unknown("it gives an option the check does not read"),
        },
        "unset" => match letters(args, false, "", "") {
            Ok((letters, _)) if letters.chars().all(|letter| letter == 'v' || letter == 'm') => {
                Verdict::Known
            }
            Ok(_) => unknown("`unset -f` takes away a function, which zsh then runs no more"),
            Err(word) => Verdict::Unknown(format!(
                "zsh may expand `{}` into any of its options",
                word.text
            )),
        },
        "eval" => match args.iter().find(|word| word.expands || word.bare) {
            Some(word) => {
                Verdict::Unknown(format!("it runs code an expansion makes (`{}`)", word.text))
            }
            None => Verdict::Known,
        },
        "autoload" => match letters(args, true, "", "") {
            Ok(_) => Verdict::Known,
            Err(word) => Verdict::Unknown(format!(
                "zsh may expand `{}` into any of its options",
                word.text
            )),
        },
        "functions" => match letters(args, true, "x", "") {
            Ok((letters, _)) if letters.chars().all(|letter| "cktTuUxz".contains(letter)) => {
                Verdict::Known
            }
            Ok(_) => unknown("it gives an option the check does not read, `-M` among them"),
            Err(word) => Verdict::Unknown(format!(
                "zsh may expand `{}` into any of its options",
                word.text
            )),
        },
        "trap" => match args.iter().find(|word| word.expands || word.bare) {
            Some(word) => {
                Verdict::Unknown(format!("it runs code an expansion makes (`{}`)", word.text))
            }
            None => Verdict::Known,
        },
        "zstyle" => match args.first() {
            Some(word) if computed(word) => Verdict::Unknown(format!(
                "zsh may expand `{}` into any of its options",
                word.text
            )),
            Some(word)
                if word.text.starts_with('-')
                    && !matches!(
                        word.text.as_str(),
                        "-" | "--" | "-e" | "-d" | "-L" | "-t" | "-T" | "-m"
                    ) =>
            {
                unknown("it sets a parameter to a style's value")
            }
            _ => Verdict::Known,
        },
        "bindkey" => match args {
            [] => Verdict::Known,
            [one] if matches!(one.text.as_str(), "-e" | "-v" | "-l" | "-L" | "-lL" | "-Ll") => {
                Verdict::Known
            }
            _ => unknown(
                "it binds a key or changes a keymap, which may make a key typed run another \
                 widget than zsh's own",
            ),
        },
        "zle" => match first {
            Some("-l" | "-L" | "-lL" | "-Ll") if !args.iter().any(computed) => Verdict::Known,
            _ => unknown(
                "it makes, runs or changes a widget, which may make the line accepted another \
                 than the one typed",
            ),
        },
        "fc" | "history" => fc(name, args),
        "kill" => match first {
            Some("-l" | "-L") if !args.iter().any(computed) => Verdict::Known,
            _ => unknown("it may signal the shell, on which zsh ends and writes its history file"),
        },
        _ => unknown("the check knows no form of it to be harmless"),
    }
}

/// The verdict of an `fc` or a `history` (`name`) of `args`: on the list
/// where it lists the history or writes, reads, pushes or pops the file, as
/// the reader reads it, not where it runs lines from it ([the module](self)).
fn fc(name: &str, args: &[Word]) -> Verdict {
    match letters(args, false, "emt", "") {
        Ok((letters, _))
            if (name == "history" || letters.contains(['l', 'A', 'W', 'P', 'p', 'R']))
                && letters
                    .chars()
                    .all(|letter| "lnrdfEiDtmLIAWPpRa".contains(letter)) =>
        {
            Verdict::Known
        }
        Ok(_) => Verdict::Unknown(format!(
            "`{name}` may run lines from the history, as it does without a flag that lists, \
             writes or reads them"
        )),
        Err(word) => Verdict::Unknown(format!(
            "zsh may expand `{}` into any of its options",
            word.text
        )),
    }
}

/// The verdict of a `set` of `args` ([the module](self)).
fn set(args: &[Word]) -> Verdict {
    let mut words = args.iter();
    while let Some(word) = words.next() {
        if computed(word) {
            return Verdict::Unknown(format!(
                "zsh may expand `{}` into any of its options",
                word.text
            ));
        }
        match word.text.as_str() {
            "-o" | "+o" => match words.next() {
                None => return Verdict::Known,
                Some(name) if computed(name) => {
                    return Verdict::Unknown(format!(
                        "it cannot tell which option `{}` names",
                        name.text
                    ));
                }
                Some(name) => {
                    if let Some(why) = option(&name.text) {
                        return Verdict::Unknown(why);
                    }
                }
            },
            // An array and its values, or the arguments.
            "-A" | "+A" | "--" | "-" => return Verdict::Known,
            _ => {
                return Verdict::Unknown(format!(
                    "`set {}` gives an option by its letter, which the check does not read",
                    word.text
                ));
            }
        }
    }
    Verdict::Known
}

/// The verdict of an `emulate` of `args` ([the module](self)): of zsh's,
/// sh's or ksh's mode by its name, with `-L`, `-R` and `-c`, and options by
/// name.
fn emulate(args: &[Word]) -> Verdict {
    let mut words = args.iter();
    while let Some(word) = words.next() {
        if computed(word) {
            return Verdict::Unknown(format!(
                "zsh may expand `{}` into any mode or option",
                word.text
            ));
        }
        match word.text.as_str() {
            "-o" | "+o" => match words.next() {
                Some(name) if computed(name) => {
                    return Verdict::Unknown(format!(
                        "it cannot tell which option `{}` names",
                        name.text
                    ));
                }
                Some(name) => {
                    if let Some(why) = option(&name.text) {
                        return Verdict::Unknown(why);
                    }
                }
                None => return Verdict::Known,
            },
            "-c" => {
                words.next();
            }
            flags if flags.starts_with('-') && flags[1..].chars().all(|c| "LR".contains(c)) => {}
            mode if !mode.starts_with(['-', '+']) => {
                // zsh picks the mode by its first letter past one `r`: csh's
                // reads quotes and loops otherwise than the check does.
                if mode.strip_prefix('r').unwrap_or(mode).starts_with('c') {
                    return Verdict::Unknown(format!(
                        "`emulate {mode}` picks csh's mode, which reads quotes and loops \
                         otherwise than the check does"
                    ));
                }
            }
            other => {
                return Verdict::Unknown(format!(
                    "`emulate {other}` gives a flag the check does not read"
                ));
            }
        }
    }
    Verdict::Known
}

/// What the list says of the command `name`, as written, with the words
/// `args`, run as `how` says ([the module](self)). A function or an alias
/// named like the command a NAILS command is typed with, or like a command a
/// widget runs with the line at hand (`sudo`, `run-help`), that runs the
/// program of its own name with its own words and nothing else (`sudo() {
/// command sudo "$@" }`, `alias sudo=sudo`) hands that program what it would
/// get without it, so that command is on the list.
pub(super) fn command(name: &str, args: &[Word], how: How) -> Verdict {
    let own_name = how.function == Some(name)
        && (super::builtins::typed(name) || super::builtins::line_command(name))
        && (args.is_empty() || matches!(args, [only] if only.text == "$@"));
    if own_name && !how.exec {
        return Verdict::Known;
    }
    if how.outside {
        return Verdict::Unknown(format!(
            "`command {name}` runs an outside program, which may change the terminal, signal the \
             shell or leave a process that does later"
        ));
    }
    if how.exec {
        return Verdict::Unknown(format!(
            "`exec {name}` runs a program in the shell's place, after zsh writes its history file"
        ));
    }
    if name == "add-zle-hook-widget" {
        return Verdict::Unknown(
            "it makes a function a widget the line editor runs as each line is edited or \
             accepted, which may make the line accepted another than the one typed"
                .to_string(),
        );
    }
    if name == "coproc" {
        return Verdict::Unknown(
            "it starts a coprocess, which may run on after the startup files and signal the \
             shell"
                .to_string(),
        );
    }
    if name.contains('/') {
        return Verdict::Unknown(format!(
            "`{name}` is an outside program, which may change the terminal, signal the shell or \
             leave a process that does later"
        ));
    }
    if LISTED.contains(&name) {
        return builtin(name, args);
    }
    if super::builtins::builtin(name) && !super::builtins::unloaded(name) {
        return Verdict::Unknown(format!(
            "the check knows no form of `{name}` to be harmless"
        ));
    }
    Verdict::Named
}

/// Why the command `shown`, as written, that runs by the name `name` is
/// an outside program where no function or alias of that name is certainly
/// defined before it runs, as a doubt says it.
pub(super) fn outside_program(name: &str) -> String {
    format!(
        "`{name}` is no function or alias the files certainly define before it runs, so zsh \
         runs the outside program of that name, which may change the terminal, signal the shell \
         or leave a process that does later"
    )
}

/// `name` and `args`, as a doubt shows a command.
pub(super) fn shown_command(name: &str, args: &[Word]) -> String {
    if args.is_empty() {
        name.to_string()
    } else {
        format!("{name} {}", shown(args))
    }
}

#[cfg(test)]
#[path = "../zsh_known_tests.rs"]
mod tests;
