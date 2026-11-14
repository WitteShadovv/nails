// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What may make a zsh end by itself before activation kills it: zsh writes
//! its history file as it ends (Src/builtin.c, `zexit`), so a hook that may
//! end it writes the lines typed so far, the NAILS command among them. In a
//! function's code, which counts where zsh runs the function as a hook
//! ([`super::super::runs`]): `exit`, `bye` and `logout`, which end the shell
//! once the function returns; a `return` in code zsh runs at its top level (a
//! trap's string, a `sched`'s, a line a key types); `exec` with a command,
//! which zsh runs in the shell's place once it has written the file; and a
//! signal that may reach the shell's own process (`kill -HUP $$`, `kill 0`,
//! a pid an expansion makes, `pkill`, `killall`), on which zsh ends the same
//! way (SIGHUP, SIGALRM). Each but `exec` and `return` counts in a subshell
//! too (`$(exit)`, `( exit )`): zsh 5.9 to 5.9.2 write the history file in a
//! subshell that exits, and a signal reaches the shell. And anywhere, a `TMOUT`
//! above 0: zsh ends once a prompt has waited that many seconds
//! (Src/signals.c), with a `TRAPALRM` too, which a later file or a hook may
//! take away.

use super::super::lexer::Word;
use super::{Event, Frame, Walker};

/// The programs that signal processes by their name, user or terminal,
/// which may be the shell's own.
const SIGNALLERS: &[&str] = &["pkill", "killall", "killall5", "skill"];

/// Whether `kill` of `args`, as zsh's `kill` reads them (Src/jobs.c,
/// `bin_kill`), may signal the shell's own process: past `-q` and its value,
/// the signal (`-HUP`, `-9`, `-s HUP`, `-n 1`) and `--`, a pid that is not
/// a number above 0 as written (`$$`, `0`, `-1`, a process group), or any
/// word an expansion makes. `-l` and `-L` only list signals; a job (`%1`) is
/// a child of the shell.
fn may_signal_shell(args: &[Word]) -> bool {
    let computed = |word: &Word| word.expands || word.bare || word.text.contains(['$', '`']);
    let mut at = 0;
    let mut signal = false;
    while let Some(word) = args.get(at) {
        if computed(word) {
            return true;
        }
        match word.text.as_str() {
            "-l" | "-L" if at == 0 => return false,
            "-q" => at += 2,
            "--" => {
                at += 1;
                break;
            }
            "-s" | "-n" if !signal => {
                signal = true;
                at += 2;
            }
            text if text.starts_with('-') && !signal => {
                signal = true;
                at += 1;
            }
            _ => break,
        }
    }
    args.iter().skip(at).any(|word| {
        computed(word)
            || !(word.text.starts_with('%')
                || (word.text.chars().all(|c| c.is_ascii_digit())
                    && !word.text.trim_start_matches('0').is_empty()))
    })
}

/// Whether `value`, one given `TMOUT` as written, holds 0 or nothing, with
/// which zsh never ends by itself.
fn no_timeout(value: &str) -> bool {
    let value = value.trim_matches(['\'', '"']);
    value.chars().all(|c| c == '0')
}

impl Walker<'_> {
    /// Whether the walk is in the body of a function, an anonymous one
    /// among them, which `return` returns from.
    fn in_function_body(&self) -> bool {
        self.frames.iter().any(|open| open.frame == Frame::Function)
    }

    /// Note what the command `name` of `args` may end the shell with, in a
    /// function's code ([the module](self)), where `exec` runs it in the
    /// shell's place (`exec`).
    pub(super) fn ends(&mut self, name: &str, args: &[Word], exec: bool) {
        let Some(function) = self.function() else {
            return;
        };
        let program = name.rsplit('/').next().unwrap_or(name);
        // Whether it signals the shell's process, and whether it ends the
        // shell from a subshell too: zsh writes the history file in a
        // subshell that exits (`$(exit)`, `( exit )`), not in one an `exec`
        // replaces, and a `return` there returns from the function.
        let (signal, forked) = match program {
            _ if exec => (false, false),
            "exit" | "bye" | "logout" => (false, true),
            "return" if self.top && !self.in_function_body() => (false, false),
            "kill" if may_signal_shell(args) => (true, true),
            program if SIGNALLERS.contains(&program) => (true, true),
            _ => return,
        };
        let words: Vec<&str> = std::iter::once(name)
            .chain(args.iter().map(|arg| arg.text.as_str()))
            .collect();
        let command = if exec {
            format!("exec {}", words.join(" "))
        } else {
            words.join(" ")
        };
        let how = if signal {
            "may signal the shell's own process, on which zsh ends"
        } else {
            "may end the shell"
        };
        self.events.push(Event::Ends {
            doubt: format!(
                "it cannot tell whether zsh writes the history file as it ends by itself, as \
                 `{command}` in `{function}` in {} {how}, and zsh writes the file as it ends",
                self.place
            ),
            function,
            forked,
        });
    }

    /// Note a `TMOUT` that `word`, an assignment or a declaration of it, may
    /// set above 0 ([the module](self)), and count it as one the walk read.
    pub(super) fn tmout(&mut self, word: &Word) {
        self.tmouts += 1;
        let Some((target, value)) = word.text.split_once('=') else {
            // Declared as it is, it keeps its value.
            return;
        };
        if target == "TMOUT" && !word.expands && no_timeout(value) {
            return;
        }
        self.events.push(Event::Doubt(format!(
            "it cannot tell whether zsh writes the history file as it ends by itself, as \
             `{}` in {} may set TMOUT above 0, after which zsh ends once a prompt has waited \
             that many seconds, and writes the file as it ends",
            word.text, self.place
        )));
    }
}

#[cfg(test)]
mod tests {
    use super::Word;
    use super::{may_signal_shell, no_timeout};

    fn words(text: &str) -> Vec<Word> {
        text.split_whitespace()
            .map(|text| Word {
                text: text.to_string(),
                expands: text.contains('$'),
                quoted: false,
                bare: false,
            })
            .collect()
    }

    #[test]
    fn a_kill_may_signal_the_shell_by_any_pid_but_a_number_above_0() {
        for args in [
            "-HUP $$",
            "$$",
            "-s HUP $$",
            "-n 1 $pid",
            "-9 0",
            "0",
            "-- -1",
            "-HUP -123",
            "-q 1 -HUP $$",
            "-HUP 12 $$",
            "$sig 12",
        ] {
            assert!(may_signal_shell(&words(args)), "{args}");
        }
        for args in [
            "-l",
            "-L",
            "-l HUP",
            "-HUP 1234",
            "%1",
            "-s TERM %2 99",
            "-9",
        ] {
            assert!(!may_signal_shell(&words(args)), "{args}");
        }
    }

    #[test]
    fn a_tmout_of_0_or_nothing_never_ends_the_shell() {
        for value in ["0", "", "00", "'0'", "\"\""] {
            assert!(no_timeout(value), "{value}");
        }
        for value in ["900", "1", "-1", "0x10", "1e3", "$t"] {
            assert!(!no_timeout(value), "{value}");
        }
    }
}
