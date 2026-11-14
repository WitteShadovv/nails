// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where tuned, tuned-ppd and firewalld log, read from their command lines.
//!
//! All three are Python programs that read their options with `argparse`, so
//! [`parse`] reads a command line as `argparse` does: a long option by its
//! name or a prefix only it has (`--lo` for `--log`), its value after `=` or
//! as the next word; short options alone or in a cluster (`-dl`), the last
//! one with its value attached (`-l/x`, `-l=/x`) or as the next word. An
//! option whose value is optional takes the next word only when that word is
//! no option. The last value of an option counts.
//!
//! What NAILS does not read as `argparse` would, a word it does not know, a
//! prefix more than one option has, a value that is missing, a word that
//! starts with `-` but may be a value, as a negative number or one with a
//! space is, or anything after `--`, makes the verdict [`Log::Unknown`].
//! `argparse` stops most of these with an error, and so the program, but
//! NAILS does not tell its errors from what it does not follow.
//!
//! - tuned (`/usr/sbin/tuned`) logs to a file with `--log` (`-l`), to
//!   `/var/log/tuned/tuned.log` unless a file follows, and with `--daemon`
//!   (`-d`) to that file whether `--log` is given or not. Without either it
//!   logs every line to its standard error, as Python's `logging` does.
//! - tuned-ppd (`/usr/sbin/tuned-ppd`) logs to a file with `--log` (`-l`), to
//!   `/var/log/tuned/tuned-ppd.log` unless a file follows, and to its
//!   standard error without it.
//! - firewalld logs as `--log-target` says: `mixed`, the default, appends its
//!   warnings and errors to the file `--log-file` names,
//!   `/var/log/firewalld` unless set, and every message with `--debug`;
//!   `file` appends every message there; `syslog` sends them to syslog,
//!   which on a systemd host is the journal; `console` writes them to its
//!   standard output.

use super::streams::Stream;
use std::collections::BTreeMap;

/// How an option takes its value, as `argparse` declares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Takes {
    /// `action="store_true"`: none.
    Nothing,
    /// `nargs="?"`: the next word when it is no option.
    Maybe,
    /// One value, always.
    One,
}

/// One option of a program.
struct Opt {
    /// Its short form, a letter after one `-`.
    short: Option<u8>,
    /// Its long form, after `--`.
    long: &'static str,
    /// How it takes its value.
    takes: Takes,
}

/// The options a command line sets, by their long form, each with its last
/// value: `None` for an option without one.
type Parsed = BTreeMap<&'static str, Option<Vec<u8>>>;

/// tuned's options.
const TUNED: &[Opt] = &[
    Opt {
        short: Some(b'd'),
        long: "daemon",
        takes: Takes::Nothing,
    },
    Opt {
        short: Some(b'D'),
        long: "debug",
        takes: Takes::Nothing,
    },
    Opt {
        short: Some(b'l'),
        long: "log",
        takes: Takes::Maybe,
    },
    Opt {
        short: Some(b'P'),
        long: "pid",
        takes: Takes::Maybe,
    },
    Opt {
        short: None,
        long: "no-dbus",
        takes: Takes::Nothing,
    },
    Opt {
        short: None,
        long: "no-socket",
        takes: Takes::Nothing,
    },
    Opt {
        short: Some(b'p'),
        long: "profile",
        takes: Takes::One,
    },
];

/// tuned-ppd's options.
const TUNED_PPD: &[Opt] = &[
    Opt {
        short: Some(b'D'),
        long: "debug",
        takes: Takes::Nothing,
    },
    Opt {
        short: Some(b'l'),
        long: "log",
        takes: Takes::Maybe,
    },
];

/// firewalld's options.
const FIREWALLD: &[Opt] = &[
    Opt {
        short: None,
        long: "debug",
        takes: Takes::Maybe,
    },
    Opt {
        short: None,
        long: "debug-gc",
        takes: Takes::Nothing,
    },
    Opt {
        short: None,
        long: "nofork",
        takes: Takes::Nothing,
    },
    Opt {
        short: None,
        long: "nopid",
        takes: Takes::Nothing,
    },
    Opt {
        short: None,
        long: "system-config",
        takes: Takes::One,
    },
    Opt {
        short: None,
        long: "default-config",
        takes: Takes::One,
    },
    Opt {
        short: None,
        long: "log-target",
        takes: Takes::One,
    },
    Opt {
        short: None,
        long: "log-file",
        takes: Takes::One,
    },
];

/// tuned's log file when `--log` names none.
pub(super) const TUNED_LOG: &str = "/var/log/tuned/tuned.log";

/// tuned-ppd's log file when `--log` names none.
pub(super) const TUNED_PPD_LOG: &str = "/var/log/tuned/tuned-ppd.log";

/// firewalld's log file when `--log-file` names none.
pub(super) const FIREWALLD_LOG: &str = "/var/log/firewalld";

/// A log file a daemon writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::preflight::checks::decoy_posture) struct FileLog {
    /// The file.
    pub(in crate::preflight::checks::decoy_posture) path: String,
    /// The options that make it log there, as a finding names them.
    pub(in crate::preflight::checks::decoy_posture) by: String,
    /// What it writes there.
    pub(in crate::preflight::checks::decoy_posture) what: &'static str,
}

/// Where a daemon logs, by its command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::preflight::checks::decoy_posture) enum Log {
    /// To no file of its own.
    NoFile,
    /// To a file.
    File(FileLog),
    /// To a standard stream, wherever that leads ([`super::streams`]).
    Stream {
        /// The stream.
        stream: Stream,
        /// The options that make it log there, as a finding names them.
        by: &'static str,
    },
    /// NAILS cannot tell, for this reason.
    Unknown(String),
}

/// Whether `word` is one `argparse` reads as an option, `None` when NAILS
/// cannot tell: one that starts with `-` but may be a value, as a negative
/// number or a word with a space is.
fn is_option(word: &[u8]) -> Option<bool> {
    if word.len() < 2 || word[0] != b'-' {
        return Some(false);
    }
    let number = word[1..]
        .iter()
        .all(|&byte| byte.is_ascii_digit() || byte == b'.');
    (!number && !word.contains(&b' ')).then_some(true)
}

/// The option of `options` that a long name after `--` stands for: the one
/// of that name, or the only one it is a prefix of.
fn long_option<'a>(options: &'a [Opt], name: &[u8]) -> Result<&'a Opt, String> {
    if let Some(exact) = options.iter().find(|opt| opt.long.as_bytes() == name) {
        return Ok(exact);
    }
    let mut matches = options
        .iter()
        .filter(|opt| !name.is_empty() && opt.long.as_bytes().starts_with(name));
    match (matches.next(), matches.next()) {
        (Some(only), None) => Ok(only),
        _ => Err(format!(
            "NAILS does not know its option --{}",
            String::from_utf8_lossy(name)
        )),
    }
}

/// The value of `opt` that the words from `*at` on give it, `attached` being
/// the one written into its own word; moves `*at` past a value taken from
/// the next word.
fn value(
    opt: &Opt,
    attached: Option<&[u8]>,
    args: &[Vec<u8>],
    at: &mut usize,
) -> Result<Option<Vec<u8>>, String> {
    if let Some(attached) = attached {
        if opt.takes == Takes::Nothing {
            return Err(format!("its option --{} takes no value", opt.long));
        }
        return Ok(Some(attached.to_vec()));
    }
    let next = args.get(*at);
    let take = match (opt.takes, next.map(|word| is_option(word))) {
        (Takes::Nothing, _) | (Takes::Maybe, None | Some(Some(true))) => false,
        (_, Some(None)) => {
            return Err(format!(
                "NAILS cannot tell whether {} is a value of --{}",
                String::from_utf8_lossy(next.map_or(&[][..], Vec::as_slice)),
                opt.long
            ));
        }
        (Takes::Maybe, Some(Some(false))) | (Takes::One, Some(Some(false))) => true,
        (Takes::One, None | Some(Some(true))) => {
            return Err(format!("its option --{} lacks its value", opt.long));
        }
    };
    if !take {
        return Ok(None);
    }
    *at += 1;
    Ok(next.cloned())
}

/// The options `args` set, read as `argparse` reads them with `options` (see
/// the [module docs](self)).
fn parse(options: &[Opt], args: &[Vec<u8>]) -> Result<Parsed, String> {
    let mut parsed = Parsed::new();
    let mut at = 0;
    while let Some(word) = args.get(at) {
        at += 1;
        if word.as_slice() == b"--" || is_option(word) != Some(true) {
            return Err(format!(
                "NAILS does not read its argument {}",
                String::from_utf8_lossy(word)
            ));
        }
        if let Some(long) = word.strip_prefix(b"--") {
            let (name, attached) = match long.iter().position(|&byte| byte == b'=') {
                Some(eq) => (&long[..eq], Some(&long[eq + 1..])),
                None => (long, None),
            };
            let opt = long_option(options, name)?;
            let found = value(opt, attached, args, &mut at)?;
            parsed.insert(opt.long, found);
            continue;
        }
        // A cluster of short options: each without a value, until one that
        // takes the rest of the word, or the next word, as its value.
        let mut letters = &word[1..];
        while let Some((&letter, rest)) = letters.split_first() {
            let Some(opt) = options.iter().find(|opt| opt.short == Some(letter)) else {
                return Err(format!(
                    "NAILS does not know its option -{}",
                    char::from(letter)
                ));
            };
            if opt.takes == Takes::Nothing {
                parsed.insert(opt.long, None);
                letters = rest;
                continue;
            }
            let attached = (!rest.is_empty()).then(|| rest.strip_prefix(b"=").unwrap_or(rest));
            let found = value(opt, attached, args, &mut at)?;
            parsed.insert(opt.long, found);
            break;
        }
    }
    Ok(parsed)
}

/// A value as a finding shows it.
fn shown(value: &[u8]) -> String {
    String::from_utf8_lossy(value).into_owned()
}

/// The log file `--log` (`-l`) names, or `default` when it names none, with
/// the option as a finding names it; `None` without the option.
fn log_file(parsed: &Parsed, default: &str) -> Result<Option<(String, String)>, String> {
    match parsed.get("log") {
        None => Ok(None),
        Some(None) => Ok(Some((default.to_string(), "-l".to_string()))),
        Some(Some(path)) if path.is_empty() => Err("it passes -l an empty file name".to_string()),
        Some(Some(path)) => Ok(Some((shown(path), format!("-l {}", shown(path))))),
    }
}

/// Where tuned logs with the arguments `args`.
pub(in crate::preflight::checks::decoy_posture) fn tuned(args: &[Vec<u8>]) -> Log {
    let parsed = match parse(TUNED, args) {
        Ok(parsed) => parsed,
        Err(why) => return Log::Unknown(why),
    };
    let daemon = parsed.contains_key("daemon");
    match log_file(&parsed, TUNED_LOG) {
        Err(why) => Log::Unknown(why),
        Ok(Some((path, by))) => Log::File(FileLog {
            path,
            by,
            what: "its log",
        }),
        Ok(None) if daemon => Log::File(FileLog {
            path: TUNED_LOG.to_string(),
            by: "-d, which logs to a file as -l does".to_string(),
            what: "its log",
        }),
        Ok(None) => Log::Stream {
            stream: Stream::Error,
            by: "neither -l nor -d",
        },
    }
}

/// Where tuned-ppd logs with the arguments `args`.
pub(in crate::preflight::checks::decoy_posture) fn tuned_ppd(args: &[Vec<u8>]) -> Log {
    let parsed = match parse(TUNED_PPD, args) {
        Ok(parsed) => parsed,
        Err(why) => return Log::Unknown(why),
    };
    match log_file(&parsed, TUNED_PPD_LOG) {
        Err(why) => Log::Unknown(why),
        Ok(Some((path, by))) => Log::File(FileLog {
            path,
            by,
            what: "its log",
        }),
        Ok(None) => Log::Stream {
            stream: Stream::Error,
            by: "no -l",
        },
    }
}

/// Where firewalld logs with the arguments `args`.
pub(in crate::preflight::checks::decoy_posture) fn firewalld(args: &[Vec<u8>]) -> Log {
    let parsed = match parse(FIREWALLD, args) {
        Ok(parsed) => parsed,
        Err(why) => return Log::Unknown(why),
    };
    let debug = match parsed.get("debug") {
        None => false,
        Some(None) => true,
        // argparse takes a level from 1 to firewalld's DEBUG_MAX, 10.
        Some(Some(level)) => match shown(level).parse::<u8>() {
            Ok(1..=10) => true,
            _ => return Log::Unknown(format!("it passes --debug the level {}", shown(level))),
        },
    };
    let file = match parsed.get("log-file") {
        Some(Some(path)) if !path.is_empty() => shown(path),
        Some(_) => return Log::Unknown("it passes --log-file an empty file".to_string()),
        None => FIREWALLD_LOG.to_string(),
    };
    let target = parsed.get("log-target").cloned().flatten();
    let (target, by) = match &target {
        None => ("mixed", "the log target mixed, the default".to_string()),
        Some(target) => (
            match target.as_slice() {
                b"mixed" => "mixed",
                b"file" => "file",
                b"syslog" => "syslog",
                b"console" => "console",
                other => {
                    return Log::Unknown(format!(
                        "it passes --log-target the target {}",
                        shown(other)
                    ));
                }
            },
            format!("--log-target={}", shown(target)),
        ),
    };
    let every = "every message it logs";
    match target {
        "syslog" => Log::NoFile,
        "console" => Log::Stream {
            stream: Stream::Output,
            by: "the log target console",
        },
        "file" => Log::File(FileLog {
            path: file,
            by,
            what: every,
        }),
        _ if debug => Log::File(FileLog {
            path: file,
            by: format!("{by} and --debug"),
            what: every,
        }),
        _ => Log::File(FileLog {
            path: file,
            by,
            what: "its warnings and errors",
        }),
    }
}

#[cfg(test)]
#[path = "options_tests.rs"]
mod tests;
