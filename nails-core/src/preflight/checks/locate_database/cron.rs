// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The runs of updatedb that cron and anacron start.
//!
//! [`cron_jobs`] reads, under the root:
//!
//! - `/etc/crontab` and the files of `/etc/cron.d`, whose lines name the user
//!   a job runs as before its command;
//! - the users' crontabs: the files of `/var/spool/cron/crontabs` (Debian,
//!   Ubuntu) and of `/var/spool/cron` (cronie, on Fedora and Arch), whose
//!   lines name no user;
//! - `/etc/anacrontab`, whose lines are `period delay name command`;
//! - the scripts of `/etc/cron.hourly`, `cron.daily`, `cron.weekly` and
//!   `cron.monthly`, which cron or anacron runs with run-parts.
//!
//! A crontab line is a job when it starts with its five time fields, or with
//! `@reboot`, `@daily` or another of cron's names, and its command ends at
//! the first `%` no backslash escapes, as cron cuts it; empty lines, comments
//! and environment settings are no jobs. A job's command and a script are
//! read with [`super::shell`]. Debian's and Ubuntu's `/etc/cron.daily/plocate`
//! ends at once where systemd runs ([`ends_under_systemd`]), so it is no job
//! there.
//!
//! A directory NAILS cannot list, or a file it cannot read, may hold a job
//! that runs updatedb, so it is one NAILS cannot tell about: an unprivileged
//! `nails check` reads less than activation does.

use super::exec::ExecCommand;
use super::files::{DecoyFile, DecoyFiles};
use super::shell::updatedb_runs;
use crate::Filesystem;
use std::path::{Path, PathBuf};

/// The system crontabs, relative to the root.
const SYSTEM_CRONTABS: &[&str] = &["etc/crontab"];

/// The directories of system crontabs, relative to the root.
const SYSTEM_CRONTAB_DIRS: &[&str] = &["etc/cron.d"];

/// The directories of the users' crontabs, relative to the root.
const USER_CRONTAB_DIRS: &[&str] = &["var/spool/cron/crontabs", "var/spool/cron"];

/// anacron's table, relative to the root.
const ANACRONTAB: &str = "etc/anacrontab";

/// The directories whose scripts run-parts runs, relative to the root.
const SCRIPT_DIRS: &[&str] = &[
    "etc/cron.hourly",
    "etc/cron.daily",
    "etc/cron.weekly",
    "etc/cron.monthly",
];

/// cron's names for a schedule, in place of the five time fields.
const SCHEDULE_NAMES: &[&[u8]] = &[
    b"@reboot",
    b"@yearly",
    b"@annually",
    b"@monthly",
    b"@weekly",
    b"@daily",
    b"@midnight",
    b"@hourly",
];

/// A cron job that names updatedb, or a crontab, script or directory that
/// may hold one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronJob {
    /// Where it is: a line of a crontab, or a script; for one NAILS cannot
    /// read, what that is.
    pub place: String,
    /// What removes it; `None` for one NAILS cannot read.
    pub removal: Option<String>,
    /// The updatedb commands it runs, each, or why it is not known.
    pub runs: Vec<Result<ExecCommand, String>>,
}

/// What a crontab's lines name: the user field after the schedule or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Table {
    /// `/etc/crontab` and `/etc/cron.d`: a user field follows the schedule.
    System,
    /// A user's crontab: the command follows the schedule.
    User,
    /// `/etc/anacrontab`: `period delay name command`.
    Anacron,
}

/// The fields of `line` split at blanks, up to `count`, and the rest.
fn fields(line: &[u8], count: usize) -> Option<(Vec<&[u8]>, &[u8])> {
    let mut rest = line;
    let mut out = Vec::new();
    for _ in 0..count {
        rest = trim_start(rest);
        let end = rest
            .iter()
            .position(|&byte| byte == b' ' || byte == b'\t')
            .unwrap_or(rest.len());
        if end == 0 {
            return None;
        }
        out.push(&rest[..end]);
        rest = &rest[end..];
    }
    Some((out, trim_start(rest)))
}

fn trim_start(text: &[u8]) -> &[u8] {
    let start = text
        .iter()
        .position(|&byte| byte != b' ' && byte != b'\t')
        .unwrap_or(text.len());
    &text[start..]
}

/// The command of a crontab line, or `None` for a line that is no job.
fn command(line: &[u8], table: Table) -> Option<Vec<u8>> {
    let line = trim_start(line);
    let first = *line.first()?;
    let command = match table {
        Table::Anacron => {
            // The period is a number of days or one of cron's names; a
            // comment or an environment setting has none.
            let (head, rest) = fields(line, 3)?;
            let period = head[0];
            if !(period.iter().all(u8::is_ascii_digit) || SCHEDULE_NAMES.contains(&period)) {
                return None;
            }
            rest
        }
        Table::System | Table::User => {
            let schedule = if first == b'@' {
                let (head, _) = fields(line, 1)?;
                if !SCHEDULE_NAMES.contains(&head[0]) {
                    return None;
                }
                1
            } else if first.is_ascii_digit() || first == b'*' {
                5
            } else {
                // A comment, or an environment setting.
                return None;
            };
            let user = usize::from(table == Table::System);
            fields(line, schedule + user)?.1
        }
    };
    // cron cuts the command at the first unescaped `%` and passes the rest
    // as its input; `\%` is a `%`.
    let mut out = Vec::with_capacity(command.len());
    let mut bytes = command.iter().copied().peekable();
    while let Some(byte) = bytes.next() {
        match byte {
            b'\\' if bytes.peek() == Some(&b'%') => {
                out.push(b'%');
                bytes.next();
            }
            b'%' => break,
            _ => out.push(byte),
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Whether a cron script is Debian's plocate one, which ends at once where
/// systemd runs: its first command, past `set -e` and plain assignments
/// (`NAME=value` with a value the shell takes as it is), is
/// `if [ -d /run/systemd/system ]; then exit 0; fi`.
pub fn ends_under_systemd(text: &[u8]) -> bool {
    let text = String::from_utf8_lossy(text);
    let plain = |line: &str| {
        line.split_once('=').is_some_and(|(name, value)| {
            !name.is_empty()
                && !name.as_bytes()[0].is_ascii_digit()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_./:@+,=-".contains(&byte))
        })
    };
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| *line != "set -e" && !plain(line));
    lines.next() == Some("if [ -d /run/systemd/system ]; then")
        && lines.next() == Some("exit 0")
        && lines.next() == Some("fi")
}

/// The jobs of a crontab at `path`, appended to `out`.
fn crontab<F: Filesystem>(
    files: &DecoyFiles<'_, F>,
    path: &Path,
    table: Table,
    out: &mut Vec<CronJob>,
) {
    let name = files.shown(path);
    let text = match files.read(path) {
        DecoyFile::Text(text) => text,
        DecoyFile::Absent | DecoyFile::Null => return,
        DecoyFile::Unread(why) => {
            out.push(unread(format!("the crontab {name}"), why));
            return;
        }
    };
    for (index, line) in text.split(|&byte| byte == b'\n').enumerate() {
        let Some(command) = command(line, table) else {
            continue;
        };
        let runs = updatedb_runs(&command);
        if runs.is_empty() {
            continue;
        }
        out.push(CronJob {
            place: format!("line {} of {name}", index + 1),
            removal: Some(format!("remove line {} of {name}", index + 1)),
            runs,
        });
    }
}

/// The job of a run-parts script at `path`, if it names updatedb.
fn script<F: Filesystem>(files: &DecoyFiles<'_, F>, path: &Path, out: &mut Vec<CronJob>) {
    let name = files.shown(path);
    let text = match files.read(path) {
        DecoyFile::Text(text) => text,
        DecoyFile::Absent | DecoyFile::Null => return,
        DecoyFile::Unread(why) => {
            out.push(unread(format!("the cron script {name}"), why));
            return;
        }
    };
    if ends_under_systemd(&text) {
        return;
    }
    let runs = updatedb_runs(&text);
    if runs.is_empty() {
        return;
    }
    out.push(CronJob {
        place: name.clone(),
        removal: Some(format!("remove {name}")),
        runs,
    });
}

/// What NAILS cannot read, `what`, which may hold a job.
fn unread(what: String, why: String) -> CronJob {
    CronJob {
        place: what,
        removal: None,
        runs: vec![Err(why)],
    }
}

/// The files of `dir`, sorted, less its subdirectories; a directory NAILS
/// cannot list may hold `kind` (such as `crontabs`) that run updatedb.
fn dir_files<F: Filesystem>(
    fs: &F,
    files: &DecoyFiles<'_, F>,
    dir: &Path,
    kind: &str,
    out: &mut Vec<CronJob>,
) -> Vec<PathBuf> {
    match files.list(dir) {
        Ok(mut entries) => {
            entries.retain(|entry| !fs.is_directory(entry).unwrap_or(false));
            entries.sort();
            entries
        }
        Err(why) => {
            out.push(unread(format!("the {kind} in {}", files.shown(dir)), why));
            Vec::new()
        }
    }
}

/// Every cron job under the root that names updatedb (see the [module
/// docs](self)).
pub fn cron_jobs<F: Filesystem>(fs: &F, files: &DecoyFiles<'_, F>) -> Vec<CronJob> {
    let root = files.root().to_path_buf();
    let mut out = Vec::new();
    for crontab_path in SYSTEM_CRONTABS {
        crontab(files, &root.join(crontab_path), Table::System, &mut out);
    }
    for dir in SYSTEM_CRONTAB_DIRS {
        for path in dir_files(fs, files, &root.join(dir), "crontabs", &mut out) {
            crontab(files, &path, Table::System, &mut out);
        }
    }
    for dir in USER_CRONTAB_DIRS {
        for path in dir_files(fs, files, &root.join(dir), "crontabs", &mut out) {
            crontab(files, &path, Table::User, &mut out);
        }
    }
    crontab(files, &root.join(ANACRONTAB), Table::Anacron, &mut out);
    for dir in SCRIPT_DIRS {
        // Debian's run-parts runs only names of letters, digits, `_` and `-`,
        // Fedora's nearly every name: every file is read.
        for path in dir_files(fs, files, &root.join(dir), "cron scripts", &mut out) {
            script(files, &path, &mut out);
        }
    }
    out
}

#[cfg(test)]
#[path = "cron_tests.rs"]
mod tests;
