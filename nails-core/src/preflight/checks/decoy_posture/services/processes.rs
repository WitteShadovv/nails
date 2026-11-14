// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The running processes of the daemons, read from `<root>/proc`.
//!
//! A process counts by its name, `comm`, which the kernel takes from the file
//! it runs: the program's own name when it runs as a program, as its unit
//! and a hand start of `/usr/sbin/tuned` run it, or, on NixOS, the name its
//! wrapper gives the Python script, `.tuned-wrapped`, cut to 15 bytes as the
//! kernel cuts every `comm`. A daemon run through its interpreter, as
//! `python3 /usr/sbin/tuned` runs it, has the interpreter's name: such a
//! process counts by the script it runs, the first word after the
//! interpreter's own options as Python reads them, and not when Python runs
//! a command (`-c`), a module (`-m`) or its standard input instead.
//! `comm` and `cmdline` can be read by every user.
//!
//! A command line runs a daemon only where its first word is the daemon's
//! program, or a Python interpreter whose script is ([`own_args`]). Another
//! program that runs the daemon in turn, as `logsave` and `script` do, can
//! take what the daemon writes to its standard output and standard error
//! into a file of its own, so its options are no daemon's.

use crate::Filesystem;
use std::path::Path;

/// The longest name the kernel keeps in `comm`.
const COMM_LEN: usize = 15;

/// A process of one of the daemons.
pub(super) struct Process {
    /// Its number.
    pub(super) pid: String,
    /// The program of the daemon it runs.
    pub(super) name: &'static str,
    /// Its command line, or why NAILS cannot read it.
    pub(super) argv: Result<Vec<Vec<u8>>, String>,
}

/// The program of `programs` that `name`, a process name or a file name,
/// stands for: its own name, or the name NixOS's wrapper gives it.
fn program_of(programs: &[&'static str], name: &[u8]) -> Option<&'static str> {
    programs.iter().copied().find(|program| {
        let wrapped = format!(".{program}-wrapped");
        let wrapped = wrapped.as_bytes();
        name == program.as_bytes()
            || name == wrapped
            || name == &wrapped[..COMM_LEN.min(wrapped.len())]
    })
}

/// Whether `name` is the name of a Python interpreter, as `python3`,
/// `python3.14` and RHEL's `platform-python` are.
fn is_python(name: &str) -> bool {
    name == "platform-python"
        || name.strip_prefix("python").is_some_and(|rest| {
            rest.bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
        })
}

/// Where the script is among the words of a Python interpreter's command
/// line `argv`, as Python reads its own options: `-W` and `-X` take a value,
/// attached or in the next word, `--check-hash-based-pycs` the next word,
/// `--` ends them. `None` when it runs a command, a module or its standard
/// input, or nothing.
fn python_script_at(argv: &[Vec<u8>]) -> Option<usize> {
    let mut at = 1;
    while let Some(word) = argv.get(at) {
        at += 1;
        match word.as_slice() {
            b"--" => return (at < argv.len()).then_some(at),
            b"-" => return None,
            b"--check-hash-based-pycs" => at += 1,
            long if long.starts_with(b"--") => {}
            short if short.starts_with(b"-") => {
                for (index, letter) in short.iter().enumerate().skip(1) {
                    match letter {
                        b'c' | b'm' => return None,
                        b'W' | b'X' => {
                            if index + 1 == short.len() {
                                at += 1;
                            }
                            break;
                        }
                        _ => {}
                    }
                }
            }
            _ => return Some(at - 1),
        }
    }
    None
}

/// The script a Python interpreter's command line `argv` runs
/// ([`python_script_at`]).
fn python_script(argv: &[Vec<u8>]) -> Option<&[u8]> {
    python_script_at(argv).map(|at| argv[at].as_slice())
}

/// The file name of `word`, the part after its last `/`.
fn file_name(word: &[u8]) -> &[u8] {
    word.rsplit(|&byte| byte == b'/').next().unwrap_or(word)
}

/// Whether `name`, a file name, is `program`'s, or the name NixOS's wrapper
/// gives it.
fn names(program: &str, name: &[u8]) -> bool {
    name == program.as_bytes() || name == format!(".{program}-wrapped").as_bytes()
}

/// What `program` reads as its own command line in the command `words`:
/// the words after the first, where the first is the program (by its file
/// name, or the name NixOS's wrapper gives it), or, where the first is a
/// Python interpreter, the words after its script, where the script is the
/// program. `None` where the command runs anything else first, a program
/// that runs `program` in turn among it (see the [module docs](self)).
pub(super) fn own_args(program: &'static str, words: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let first = file_name(words.first()?);
    if names(program, first) {
        return Some(words[1..].to_vec());
    }
    if !std::str::from_utf8(first).is_ok_and(is_python) {
        return None;
    }
    let at = python_script_at(words)?;
    names(program, file_name(&words[at])).then(|| words[at + 1..].to_vec())
}

/// Whether a word of the command `words` names `program`, wherever it is:
/// the command runs it, maybe through another program.
pub(super) fn runs_anywhere(program: &'static str, words: &[Vec<u8>]) -> bool {
    words.iter().any(|word| names(program, file_name(word)))
}

/// The processes under `<root>/proc` that run one of `programs` (see the
/// [module docs](self)), in the order of their numbers; `scripts` are those
/// of `programs` that are Python scripts. One that ended since the listing
/// is left out.
pub(super) fn processes<F: Filesystem>(
    fs: &F,
    root: &Path,
    programs: &[&'static str],
    scripts: &[&'static str],
) -> Vec<Process> {
    let Ok(entries) = fs.list_directory(&root.join("proc")) else {
        return Vec::new();
    };
    let mut out: Vec<(u64, Process)> = Vec::new();
    for entry in entries {
        let Some(number) = entry
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.parse::<u64>().ok())
        else {
            continue;
        };
        let Ok(comm) = fs.read_file_content(&entry.join("comm")) else {
            continue;
        };
        let comm = comm.trim_end_matches('\n');
        let named = program_of(programs, comm.as_bytes());
        if named.is_none() && !is_python(comm) {
            continue;
        }
        let argv: Result<Vec<Vec<u8>>, String> = match fs.read_file_bytes(&entry.join("cmdline")) {
            // The last word of a command line is followed by a NUL too.
            Ok(bytes) => Ok(bytes
                .strip_suffix(b"\0")
                .unwrap_or(&bytes)
                .split(|&byte| byte == 0)
                .map(<[u8]>::to_vec)
                .collect()),
            Err(e) if e.io_kind() == Some(std::io::ErrorKind::NotFound) => continue,
            Err(e) => Err(format!("NAILS cannot read /proc/{number}/cmdline ({e})")),
        };
        let name = match named {
            Some(name) => name,
            None => {
                let script = argv
                    .as_deref()
                    .ok()
                    .and_then(python_script)
                    .and_then(|script| program_of(scripts, file_name(script)));
                let Some(name) = script else {
                    continue;
                };
                name
            }
        };
        out.push((
            number,
            Process {
                pid: number.to_string(),
                name,
                argv,
            },
        ));
    }
    out.sort_by_key(|(number, _)| *number);
    out.into_iter().map(|(_, process)| process).collect()
}

#[cfg(test)]
#[path = "processes_tests.rs"]
mod tests;
