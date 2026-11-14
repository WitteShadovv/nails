// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The environment variables a decoy service sets itself, which its
//! `ExecStart=` may name: firewalld takes its options from
//! `$FIREWALLD_ARGS`, which `/etc/sysconfig/firewalld` sets.
//!
//! systemd gives a service the variables of its `Environment=` lines, then
//! those of the files its `EnvironmentFile=` lines name, read when it starts,
//! each file over the ones before it and over `Environment=`, and last takes
//! away what its `UnsetEnvironment=` lines name: a variable by its name, or an
//! assignment `NAME=value` only while the variable holds that value. A
//! variable neither sets comes from the service manager's own environment,
//! which NAILS does not read, and is left out, so a command that names it is
//! one NAILS cannot tell about.
//!
//! A file is read as systemd's `load_env_file()` reads it: `NAME=value` lines,
//! the value plain, in single quotes or in double quotes, a backslash
//! escaping the next character, a backslash at the end of a line going on
//! with the next, comments from `#` or `;`. An assignment whose name systemd
//! refuses it drops, and so does NAILS; a value both keep whatever control
//! characters it holds, as systemd 254, the oldest NAILS runs on, already
//! does. A file that is not UTF-8 stops the service, and NAILS cannot tell
//! about it.
//!
//! `-` before a file's name lets it be missing; a missing file without it
//! stops the service from starting, which NAILS does not judge. systemd
//! ignores a line whose name is not absolute or has a `..` in it, and so does
//! NAILS. A name with a specifier, a wildcard or a backslash, and an
//! `Environment=` or `UnsetEnvironment=` line NAILS cannot split, it cannot
//! tell about either.

use super::super::super::locate_database::exec::{Variables, environment_words, is_variable_name};
use super::super::super::locate_database::files::{DecoyFile, DecoyFiles};
use super::super::super::locate_database::unit::list_values;
use super::super::super::systemd_conf::Assignment;
use crate::Filesystem;

/// systemd's `WHITESPACE`.
fn is_blank(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

/// systemd's `NEWLINE`.
fn is_newline(byte: u8) -> bool {
    matches!(byte, b'\n' | b'\r')
}

/// Where `parse_env_file_internal()` is in a file.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    PreKey,
    Key,
    PreValue,
    Value,
    ValueEscape,
    SingleQuote,
    DoubleQuote,
    DoubleQuoteEscape,
    Comment,
    CommentEscape,
}

/// One assignment as the file's reading gives it, before it is checked.
struct Pending {
    key: Vec<u8>,
    value: Vec<u8>,
    /// Where the key's trailing blanks start, if it has any.
    key_blank: Option<usize>,
    /// Where an unquoted value's trailing blanks start, if it has any.
    value_blank: Option<usize>,
}

impl Pending {
    fn new() -> Self {
        Self {
            key: Vec::new(),
            value: Vec::new(),
            key_blank: None,
            value_blank: None,
        }
    }

    /// The assignment, its key's trailing blanks cut off, and its value's
    /// too when it `ended_unquoted`.
    fn finish(mut self, ended_unquoted: bool) -> (Vec<u8>, Vec<u8>) {
        if let Some(at) = self.key_blank {
            self.key.truncate(at);
        }
        if ended_unquoted && let Some(at) = self.value_blank {
            self.value.truncate(at);
        }
        (self.key, self.value)
    }
}

/// The assignments of an environment file, in its order, as systemd's
/// `parse_env_file_internal()` reads them: up to its first NUL byte, where
/// systemd's reading of the text ends.
fn assignments(bytes: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let mut state = State::PreKey;
    let mut pending = Pending::new();
    for &byte in bytes.iter().take_while(|&&byte| byte != 0) {
        state = match state {
            State::PreKey if matches!(byte, b'#' | b';') => State::Comment,
            State::PreKey if is_blank(byte) => State::PreKey,
            State::PreKey => {
                pending = Pending::new();
                pending.key.push(byte);
                State::Key
            }
            State::Key if is_newline(byte) => State::PreKey,
            State::Key if byte == b'=' => State::PreValue,
            State::Key => {
                if !is_blank(byte) {
                    pending.key_blank = None;
                } else if pending.key_blank.is_none() {
                    pending.key_blank = Some(pending.key.len());
                }
                pending.key.push(byte);
                State::Key
            }
            State::PreValue | State::Value if is_newline(byte) => {
                let unquoted = state == State::Value;
                out.push(std::mem::replace(&mut pending, Pending::new()).finish(unquoted));
                State::PreKey
            }
            State::PreValue if byte == b'\'' => State::SingleQuote,
            State::PreValue if byte == b'"' => State::DoubleQuote,
            State::PreValue | State::Value if byte == b'\\' => {
                pending.value_blank = None;
                State::ValueEscape
            }
            State::PreValue if is_blank(byte) => State::PreValue,
            State::PreValue | State::Value => {
                if !is_blank(byte) {
                    pending.value_blank = None;
                } else if pending.value_blank.is_none() {
                    pending.value_blank = Some(pending.value.len());
                }
                pending.value.push(byte);
                State::Value
            }
            State::ValueEscape => {
                // An escaped newline joins the lines; it is dropped.
                if !is_newline(byte) {
                    pending.value.push(byte);
                }
                State::Value
            }
            State::SingleQuote if byte == b'\'' => State::PreValue,
            State::SingleQuote | State::DoubleQuote => {
                if state == State::DoubleQuote && byte == b'\\' {
                    State::DoubleQuoteEscape
                } else if state == State::DoubleQuote && byte == b'"' {
                    State::PreValue
                } else {
                    pending.value.push(byte);
                    state
                }
            }
            State::DoubleQuoteEscape => {
                // As in a shell, a backslash stays unless it escapes one of
                // the characters that need it; an escaped newline joins the
                // lines.
                if b"\"\\`$".contains(&byte) {
                    pending.value.push(byte);
                } else if byte != b'\n' {
                    pending.value.extend([b'\\', byte]);
                }
                State::DoubleQuote
            }
            State::Comment if byte == b'\\' => State::CommentEscape,
            State::Comment if is_newline(byte) => State::PreKey,
            State::Comment => State::Comment,
            State::CommentEscape if is_newline(byte) => State::PreKey,
            State::CommentEscape => State::Comment,
        };
    }
    if !matches!(
        state,
        State::PreKey | State::Key | State::Comment | State::CommentEscape
    ) {
        out.push(pending.finish(state == State::Value));
    }
    out
}

/// The variables of an environment file, set over `variables`; `Err` when
/// systemd stops the service at it, as for a file that is not UTF-8.
///
/// systemd's `env_value_is_valid()` takes a value of any UTF-8 that fits in
/// `ARG_MAX`, control characters included, so only the name is judged.
fn apply_file(bytes: &[u8], shown: &str, variables: &mut Variables) -> Result<(), String> {
    for (key, value) in assignments(bytes) {
        let (Ok(key), Ok(value)) = (String::from_utf8(key), String::from_utf8(value)) else {
            return Err(format!("{shown} is not UTF-8"));
        };
        if is_variable_name(key.as_bytes()) {
            variables.insert(key, value);
        }
    }
    Ok(())
}

/// Take away from `variables` what an `UnsetEnvironment=` value names, its
/// words read as systemd's `config_parse_unset_environ()` reads them: a
/// variable by its name, or an assignment `NAME=value` only while the
/// variable holds that value, as `strv_env_delete()` matches them. A word
/// that is neither systemd ignores.
fn unset(value: &str, variables: &mut Variables) -> Result<(), String> {
    let words = environment_words(value)
        .map_err(|why| format!("NAILS cannot read its UnsetEnvironment={value} ({why})"))?;
    for word in words {
        let word = String::from_utf8_lossy(&word);
        match word.split_once('=') {
            Some((name, value)) => {
                if variables.get(name).is_some_and(|held| held == value) {
                    variables.remove(name);
                }
            }
            None => {
                variables.remove(word.as_ref());
            }
        }
    }
    Ok(())
}

/// The environment a service sets itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::preflight::checks::decoy_posture) struct Environment {
    /// Its variables, by name.
    pub(in crate::preflight::checks::decoy_posture) variables: Variables,
    /// The files it read, as the decoy names them, in their order.
    pub(in crate::preflight::checks::decoy_posture) files: Vec<String>,
}

/// The environment the `[Service]` `assignments` set, its files read with
/// `files` (see the [module docs](self)).
///
/// # Errors
///
/// Why NAILS cannot tell what it sets.
pub(in crate::preflight::checks::decoy_posture) fn environment<F: Filesystem>(
    files: &DecoyFiles<'_, F>,
    assignments: &[Assignment],
) -> Result<Environment, String> {
    let mut found = Environment::default();
    for value in list_values(assignments, "Environment") {
        let words = environment_words(&value)
            .map_err(|why| format!("NAILS cannot read its Environment={value} ({why})"))?;
        for word in words {
            let word = String::from_utf8_lossy(&word).into_owned();
            // systemd ignores a word that is no assignment.
            if let Some((name, value)) = word.split_once('=')
                && is_variable_name(name.as_bytes())
            {
                found.variables.insert(name.to_string(), value.to_string());
            }
        }
    }
    for value in list_values(assignments, "EnvironmentFile") {
        let (optional, name) = match value.strip_prefix('-') {
            Some(name) => (true, name),
            None => (false, value.as_str()),
        };
        // A backslash escapes the next character of a wildcard pattern.
        if name.contains(['%', '*', '?', '[', '\\']) {
            return Err(format!(
                "NAILS does not expand the specifier or wildcard of its EnvironmentFile={value}"
            ));
        }
        // systemd ignores a name that is not absolute, or not normalized
        // (`path_simplify_and_warn()`): one with a `..` in it.
        if !name.starts_with('/') || name.split('/').any(|part| part == "..") {
            continue;
        }
        let path = files.root().join(name.trim_start_matches('/'));
        match files.read(&path) {
            DecoyFile::Text(bytes) => {
                apply_file(&bytes, name, &mut found.variables)?;
                found.files.push(name.to_string());
            }
            DecoyFile::Null => found.files.push(name.to_string()),
            DecoyFile::Absent if optional => {}
            DecoyFile::Absent => {
                return Err(format!(
                    "its EnvironmentFile={name} does not exist, so the service does not start \
                     until it does"
                ));
            }
            DecoyFile::Unread(why) => return Err(why),
        }
    }
    for value in list_values(assignments, "UnsetEnvironment") {
        unset(&value, &mut found.variables)?;
    }
    Ok(found)
}

/// The variables an environment file of the content `bytes` sets (tests).
#[cfg(test)]
fn file_variables(bytes: &[u8]) -> Result<Variables, String> {
    let mut variables = Variables::new();
    apply_file(bytes, "the file", &mut variables)?;
    Ok(variables)
}

#[cfg(test)]
#[path = "environment_tests.rs"]
mod tests;
