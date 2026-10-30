// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! updatedb's command line, read as plocate's `parse_arguments()` reads it.
//!
//! updatedb reads `/etc/updatedb.conf` first and then its options, with
//! glibc's `getopt_long()` and the option table of plocate's `conf.cpp`
//! (mlocate's lacks `--add-single-prunepath`, `-b` and `-D`, so where it
//! refuses one of them it stops, which scans nothing either):
//!
//! - `--prunepaths`, `--prunefs` and `--prunenames` replace the file's list;
//!   `-e`/`--add-prunepaths`, `--add-single-prunepath`, `-f`/`--add-prunefs`
//!   and `-n`/`--add-prunenames` add to it. A replacing option after another
//!   option of its list, or a second one, makes updatedb stop;
//! - `-U`/`--database-root` starts the scan in that directory instead of `/`;
//! - a long option may be cut to a prefix no other option shares, and takes
//!   its argument after a `=` or as the next word; a short option takes the
//!   rest of its word or the next one, and options without an argument may
//!   share a word (`-vD`);
//! - an unknown or ambiguous option, a missing argument, a word that is no
//!   option (updatedb takes no operand), `-h` and `-V` all make it stop
//!   before it scans: [`Invocation::Stops`].

/// What the command line does with one prune list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListChange {
    /// The list was replaced: the file's entries no longer count.
    pub replaced: bool,
    /// The entries the options give, with the option that gave each.
    pub entries: Vec<(Vec<u8>, &'static str)>,
}

impl ListChange {
    fn replace(&mut self, option: &'static str, value: &[u8]) {
        self.replaced = true;
        self.entries.clear();
        self.add(option, value);
    }

    fn add(&mut self, option: &'static str, value: &[u8]) {
        self.entries.extend(
            value
                .split(|byte| is_space(*byte))
                .filter(|entry| !entry.is_empty())
                .map(|entry| (entry.to_vec(), option)),
        );
    }
}

/// What a command line makes updatedb do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    /// It scans, with these changes to the file's lists.
    Scans(Scan),
    /// It stops before it scans anything, for this reason.
    Stops(String),
}

/// The changes a command line makes to the scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scan {
    /// To `PRUNEPATHS`.
    pub paths: ListChange,
    /// To `PRUNEFS`.
    pub fs: ListChange,
    /// To `PRUNENAMES`.
    pub names: ListChange,
    /// The directory `--database-root` names, as written: updatedb resolves
    /// it with `realpath()` and stops when that fails.
    pub database_root: Option<Vec<u8>>,
    /// The database `--output` names, as written.
    pub output: Option<Vec<u8>>,
}

/// C's `isspace()` in the C locale.
fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// An option of plocate's updatedb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opt {
    AddPruneFs,
    AddPruneNames,
    AddPrunePaths,
    AddSinglePrunePath,
    DatabaseRoot,
    DebugPruning,
    Help,
    Output,
    PruneBindMounts,
    PruneFs,
    PruneNames,
    PrunePaths,
    RequireVisibility,
    Verbose,
    Version,
    BlockSize,
    Debug,
}

/// The long options, in the order of plocate's table, with whether each
/// takes an argument.
const LONG: &[(&str, Opt, bool)] = &[
    ("add-prunefs", Opt::AddPruneFs, true),
    ("add-prunenames", Opt::AddPruneNames, true),
    ("add-prunepaths", Opt::AddPrunePaths, true),
    ("add-single-prunepath", Opt::AddSinglePrunePath, true),
    ("database-root", Opt::DatabaseRoot, true),
    ("debug-pruning", Opt::DebugPruning, false),
    ("help", Opt::Help, false),
    ("output", Opt::Output, true),
    ("prune-bind-mounts", Opt::PruneBindMounts, true),
    ("prunefs", Opt::PruneFs, true),
    ("prunenames", Opt::PruneNames, true),
    ("prunepaths", Opt::PrunePaths, true),
    ("require-visibility", Opt::RequireVisibility, true),
    ("verbose", Opt::Verbose, false),
    ("version", Opt::Version, false),
    ("block-size", Opt::BlockSize, true),
    ("debug", Opt::Debug, false),
];

/// The short options (`U:Ve:f:hl:n:o:vb:D`), with whether each takes an
/// argument.
fn short(byte: u8) -> Option<(Opt, bool)> {
    Some(match byte {
        b'U' => (Opt::DatabaseRoot, true),
        b'V' => (Opt::Version, false),
        b'e' => (Opt::AddPrunePaths, true),
        b'f' => (Opt::AddPruneFs, true),
        b'h' => (Opt::Help, false),
        b'l' => (Opt::RequireVisibility, true),
        b'n' => (Opt::AddPruneNames, true),
        b'o' => (Opt::Output, true),
        b'v' => (Opt::Verbose, false),
        b'b' => (Opt::BlockSize, true),
        b'D' => (Opt::Debug, false),
        _ => return None,
    })
}

/// The long option `name` stands for: an exact match, or the one option it is
/// a prefix of. `None` when it names none, or more than one.
fn long(name: &[u8]) -> Option<(&'static str, Opt, bool)> {
    if let Some(exact) = LONG.iter().find(|(long, ..)| long.as_bytes() == name) {
        return Some(*exact);
    }
    let mut matches = LONG
        .iter()
        .filter(|(long, ..)| long.as_bytes().starts_with(name));
    let first = matches.next()?;
    // Every option of the table differs from the others, so a second prefix
    // match makes the name ambiguous.
    matches.next().is_none().then_some(*first)
}

/// updatedb's `parse_bool()`.
fn is_bool(value: &[u8]) -> bool {
    matches!(value, b"0" | b"no" | b"1" | b"yes")
}

/// What the arguments after the program name, `args`, make updatedb do (see
/// the [module docs](self)).
pub fn invocation(args: &[Vec<u8>]) -> Invocation {
    let mut state = State::default();
    let mut words = args.iter();
    let mut operand = false;
    while let Some(word) = words.next() {
        if word == b"--" {
            operand |= words.next().is_some();
            break;
        }
        let parsed = if let Some(rest) = word.strip_prefix(b"--") {
            let (name, inline) = match rest.iter().position(|&byte| byte == b'=') {
                Some(eq) => (&rest[..eq], Some(&rest[eq + 1..])),
                None => (rest, None),
            };
            let Some((spelled, opt, takes)) = long(name) else {
                return stops(format!(
                    "it knows no option --{}, or the name fits more than one",
                    String::from_utf8_lossy(name)
                ));
            };
            let value = match (takes, inline) {
                (true, Some(value)) => Some(value),
                (true, None) => match words.next() {
                    Some(next) => Some(next.as_slice()),
                    None => return stops(format!("--{spelled} has no argument")),
                },
                (false, None) => None,
                (false, Some(_)) => return stops(format!("--{spelled} takes no argument")),
            };
            state.apply(opt, value)
        } else if word.len() > 1 && word[0] == b'-' {
            let mut at = 1;
            let mut outcome = Ok(());
            while at < word.len() && outcome.is_ok() {
                let byte = word[at];
                at += 1;
                let Some((opt, takes)) = short(byte) else {
                    return stops(format!("it knows no option -{}", char::from(byte)));
                };
                if !takes {
                    outcome = state.apply(opt, None);
                    continue;
                }
                let value = if at < word.len() {
                    let value = &word[at..];
                    at = word.len();
                    value
                } else {
                    match words.next() {
                        Some(next) => next.as_slice(),
                        None => {
                            return stops(format!("-{} has no argument", char::from(byte)));
                        }
                    }
                };
                outcome = state.apply(opt, Some(value));
            }
            outcome
        } else {
            // getopt_long() moves an operand behind the options, and
            // updatedb refuses it once they are read.
            operand = true;
            Ok(())
        };
        if let Err(why) = parsed {
            return stops(why);
        }
    }
    if operand {
        return stops("it takes no operand".to_string());
    }
    Invocation::Scans(state.scan)
}

fn stops(why: String) -> Invocation {
    Invocation::Stops(why)
}

/// What `parse_arguments()` keeps track of.
#[derive(Default)]
struct State {
    scan: Scan,
    paths_changed: bool,
    fs_changed: bool,
    names_changed: bool,
    bind_mounts: bool,
    visibility: bool,
}

impl State {
    fn apply(&mut self, opt: Opt, value: Option<&[u8]>) -> Result<(), String> {
        let value = value.unwrap_or_default();
        let replace = |changed: &mut bool, name: &str| {
            if std::mem::replace(changed, true) {
                Err(format!("--{name} follows another option of its list"))
            } else {
                Ok(())
            }
        };
        match opt {
            Opt::PrunePaths => {
                replace(&mut self.paths_changed, "prunepaths")?;
                self.scan.paths.replace("--prunepaths", value);
            }
            Opt::PruneFs => {
                replace(&mut self.fs_changed, "prunefs")?;
                self.scan.fs.replace("--prunefs", value);
            }
            Opt::PruneNames => {
                replace(&mut self.names_changed, "prunenames")?;
                self.scan.names.replace("--prunenames", value);
            }
            Opt::AddPrunePaths => {
                self.paths_changed = true;
                self.scan.paths.add("--add-prunepaths", value);
            }
            Opt::AddSinglePrunePath => {
                self.paths_changed = true;
                self.scan
                    .paths
                    .entries
                    .push((value.to_vec(), "--add-single-prunepath"));
            }
            Opt::AddPruneFs => {
                self.fs_changed = true;
                self.scan.fs.add("--add-prunefs", value);
            }
            Opt::AddPruneNames => {
                self.names_changed = true;
                self.scan.names.add("--add-prunenames", value);
            }
            Opt::DatabaseRoot => {
                if self.scan.database_root.replace(value.to_vec()).is_some() {
                    return Err("--database-root is given twice".to_string());
                }
            }
            Opt::Output => {
                if self.scan.output.replace(value.to_vec()).is_some() {
                    return Err("--output is given twice".to_string());
                }
            }
            Opt::PruneBindMounts => {
                if std::mem::replace(&mut self.bind_mounts, true) {
                    return Err("--prune-bind-mounts is given twice".to_string());
                }
                if !is_bool(value) {
                    return Err("--prune-bind-mounts takes 0, no, 1 or yes".to_string());
                }
            }
            Opt::RequireVisibility => {
                if std::mem::replace(&mut self.visibility, true) {
                    return Err("--require-visibility is given twice".to_string());
                }
                if !is_bool(value) {
                    return Err("--require-visibility takes 0, no, 1 or yes".to_string());
                }
            }
            Opt::Help | Opt::Version => {
                return Err("it prints its help or version and ends".to_string());
            }
            Opt::DebugPruning | Opt::Verbose | Opt::BlockSize | Opt::Debug => {}
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "options_tests.rs"]
mod tests;
