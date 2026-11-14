// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The jobs a file starts that may run on after the startup files, as the
//! walk reads them: a list zsh runs in the background (`&`, `&!`, `&|`), a
//! process substitution (`<(...)`, `>(...)`), and what a program that
//! detaches what it runs starts (`nohup`, `setsid`). A job may signal the
//! shell later, on which zsh ends and writes its history file
//! (`{ sleep 3; kill -HUP $$ } &!`, `$$` being the shell's pid in the job
//! too), so each is read for the commands it runs ([`Event::Job`]): a `kill`
//! that may signal the shell's process ([`super::ends::may_signal_shell`]),
//! the programs that signal processes by name, code it runs that the check
//! cannot read (a `source`, an `eval` of an expansion, a command whose name
//! an expansion makes), and every command it runs by name, which the check
//! resolves once the files are read (`super::super::jobs`): an outside
//! program may signal its parent, the shell, too (`sh -c 'kill -HUP
//! $PPID'`), and so may what it starts. An `exit` in a job ends the job, in
//! which zsh writes no line typed after it started. The code a shell is given
//! to run (`sh -c '(sleep 3; kill -HUP $PPID) &'`) is read for the jobs it
//! starts as the file's code is, as the shell may leave one running after it
//! ends; code an expansion makes there is a doubt.

use super::super::lexer::Word;
use super::ends::{SIGNALLERS, may_signal_shell};
use super::{Event, Walker, walk_text_in};

/// The shells whose `-c` takes code to run, read as zsh's for the jobs it
/// starts.
const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "mksh", "yash", "rbash"];

/// The programs that detach what they run from the shell, or run it later,
/// so that it may run on after the startup files, and zsh's `zpty`, which
/// runs a command in a pty beside the shell: in the foreground too, each is
/// such a job.
const DETACHERS: &[&str] = &[
    "nohup",
    "setsid",
    "daemonize",
    "start-stop-daemon",
    "systemd-run",
    "at",
    "batch",
    "crontab",
    "zpty",
];

/// The precommand words the walk notes as calls ([`super::command`]), which
/// run no program of their own.
const PRECOMMAND_CALLS: &[&str] = &["-", "nocorrect", "time", "!"];

/// The command `name` with `args`, as a warning shows it.
fn shown(name: &str, args: &[Word]) -> String {
    std::iter::once(name)
        .chain(args.iter().map(|arg| arg.text.as_str()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `text`, code as written, as a warning names a job by it: on one line,
/// its first 80 characters.
fn brief(text: &str) -> String {
    let mut brief = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some((cut, _)) = brief.char_indices().nth(80) {
        brief.truncate(cut);
        brief.push_str(" ...");
    }
    brief
}

/// What `events`, those of a job's code, run ([`Event::Job`]): the commands
/// it runs by name, and what in it may end the shell or that the check
/// cannot read.
type Summary = (Vec<(String, Vec<Word>, bool)>, Vec<String>);
fn summary(events: &[Event]) -> Summary {
    let mut calls = Vec::new();
    let mut stops = Vec::new();
    for event in events {
        match event {
            Event::Runs {
                name,
                args,
                outside,
            } => {
                let program = name.rsplit('/').next().unwrap_or(name);
                let computed = !matches!(name.as_str(), "[[" | "[")
                    && (name.contains(['$', '`']) || super::may_expand(name));
                let stop = if computed {
                    Some("runs a command whose name an expansion makes")
                } else if !outside && name == "kill" {
                    may_signal_shell(args).then_some("may signal the shell's own process")
                } else if SIGNALLERS.contains(&program) {
                    Some("may signal the shell's own process")
                } else if !outside && matches!(name.as_str(), "source" | ".") {
                    Some("runs code from a file the check does not read as the job's")
                } else if !outside
                    && name == "eval"
                    && args.iter().any(|arg| arg.expands || arg.bare)
                {
                    Some("runs code an expansion makes")
                } else {
                    None
                };
                match stop {
                    Some(why) => stops.push(format!("`{}` {why}", shown(name, args))),
                    None => calls.push((name.clone(), args.clone(), *outside)),
                }
            }
            Event::Call { name, args, .. } if !PRECOMMAND_CALLS.contains(&name.as_str()) => {
                calls.push((name.clone(), args.clone(), false));
            }
            _ => {}
        }
    }
    (calls, stops)
}

impl Walker<'_> {
    /// Note the job that `events`, from the walk's events at `start` on,
    /// make, as `what` names it ([`Event::Job`]).
    pub(super) fn job(&mut self, start: usize, what: String) {
        let (calls, stops) = summary(&self.events[start..]);
        self.events.push(Event::Job { what, calls, stops });
    }

    /// Note the list from the walk's events at `start` on as a job zsh runs
    /// in the background: the commands of the list being read, which an `&`
    /// ends.
    pub(super) fn background(&mut self, start: usize) {
        let commands: Vec<String> = self.events[start..]
            .iter()
            .filter_map(|event| match event {
                Event::Runs { name, args, .. } => Some(shown(name, args)),
                _ => None,
            })
            .collect();
        let what = format!(
            "the job `{}` that {} runs in the background",
            brief(&commands.join("; ")),
            self.place
        );
        self.job(start, what);
    }

    /// Note a process substitution whose code `code` the walk read into
    /// `events` as a job, which zsh runs beside the command it is in.
    pub(super) fn process_substitution(&mut self, code: &str, events: &[Event]) {
        let (calls, stops) = summary(events);
        self.events.push(Event::Job {
            what: format!(
                "the process substitution of `{}` in {}",
                brief(code),
                self.place
            ),
            calls,
            stops,
        });
    }

    /// Note a command `name` of `args` that detaches what it runs
    /// ([`DETACHERS`]) as a job: it runs a program, which may signal the
    /// shell later; and the jobs the code a shell is given with `-c` starts
    /// ([`SHELLS`]).
    pub(super) fn detaches(&mut self, name: &str, args: &[Word]) {
        let program = name.rsplit('/').next().unwrap_or(name);
        if SHELLS.contains(&program) {
            self.shell_code(name, args);
        }
        if DETACHERS.contains(&program) {
            let command = shown(name, args);
            self.events.push(Event::Job {
                what: format!("what `{command}` in {} starts", self.place),
                calls: Vec::new(),
                stops: vec![format!(
                    "`{program}` starts a program, which may signal the shell"
                )],
            });
        }
    }

    /// Note the jobs that the code `name`, a shell, is given in `args` with
    /// `-c` (in a word of its options, `-ec` too) starts: past its options,
    /// the first word, read as zsh code; a doubt where an expansion makes
    /// it, or makes a word where its options may stand.
    fn shell_code(&mut self, name: &str, args: &[Word]) {
        let mut code = false;
        let mut words = args.iter();
        let found = loop {
            let Some(word) = words.next() else {
                return;
            };
            if word.expands || word.bare {
                break None;
            }
            match word.text.as_str() {
                "--" | "-" => break words.next().filter(|_| code),
                text if text.starts_with("--") => {}
                text if text.starts_with(['-', '+']) => code |= text.contains('c'),
                _ if code => break Some(word),
                _ => return,
            }
        };
        match found {
            Some(word) if !word.expands && !word.bare => {
                let nested = walk_text_in(&word.text, self.place, self.function(), false);
                self.events.extend(
                    nested
                        .events
                        .into_iter()
                        .filter(|event| matches!(event, Event::Job { .. })),
                );
            }
            _ => self.events.push(Event::Job {
                what: format!("what `{}` in {} runs", shown(name, args), self.place),
                calls: Vec::new(),
                stops: vec![format!(
                    "`{name}` runs code an expansion makes, which may start a job"
                )],
            }),
        }
    }
}
