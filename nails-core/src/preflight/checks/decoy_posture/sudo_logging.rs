// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! sudo logging settings that record the hidden session on the decoy disk.
//!
//! sudo can keep two kinds of record of its own: a log file of every command
//! line it runs (`Defaults logfile=`), and I/O logs that capture the whole
//! terminal session of a command, keystrokes and screen output included
//! (`log_input`, `log_output`, the finer `log_stdin`/`log_ttyout`/... flags of
//! sudo 1.9, or the `LOG_INPUT:`/`LOG_OUTPUT:` command tags), written under
//! `iolog_dir`. Activation itself runs through sudo, so either one lands on the
//! decoy before any overlay is mounted, and an I/O log can hold the whole
//! hidden session typed into a `sudo -s` shell.
//!
//! The scan reads `/etc/sudoers` and follows `@include`/`@includedir` (and the
//! legacy `#include`/`#includedir`) the way sudo does. It does not evaluate the
//! scope of a `Defaults` line (user, host, command or runas lists): a setting
//! that applies to anyone may apply to the operator.

use crate::Filesystem;
use std::path::{Path, PathBuf};

/// The main sudoers file.
pub(super) const SUDOERS: &str = "/etc/sudoers";

/// Include nesting limit, the same order of magnitude sudo enforces; it only
/// stops an include cycle from looping.
const MAX_INCLUDE_DEPTH: usize = 8;

/// The I/O logging flags (sudo 1.8 and 1.9).
const IO_FLAGS: &[&str] = &[
    "log_input",
    "log_output",
    "log_stdin",
    "log_stdout",
    "log_stderr",
    "log_ttyin",
    "log_ttyout",
];

/// What the sudoers files configure for sudo's own logging.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SudoLogging {
    /// `Defaults logfile=` target, when set.
    pub logfile: Option<String>,
    /// I/O logging flags left enabled (after later negations are applied), and
    /// `LOG_INPUT:`/`LOG_OUTPUT:` tags found in user specifications.
    pub io_logging: Vec<String>,
    /// `Defaults iolog_dir=` target, when set.
    pub iolog_dir: Option<String>,
}

impl SudoLogging {
    /// One warning per finding, empty when sudo keeps no record of its own.
    pub fn findings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.io_logging.is_empty() {
            let dir = self
                .iolog_dir
                .as_deref()
                .unwrap_or("/var/log/sudo-io by default");
            out.push(format!(
                "sudoers enables sudo I/O logging ({}), which records whole terminal \
                 sessions, keystrokes and output, to the decoy disk ({dir}); remove it \
                 before activating",
                self.io_logging.join(", ")
            ));
        } else if let Some(dir) = &self.iolog_dir {
            out.push(format!(
                "sudoers sets iolog_dir={dir}; any sudo I/O logging records whole terminal \
                 sessions there on the decoy disk"
            ));
        }
        if let Some(file) = &self.logfile {
            out.push(format!(
                "sudoers sets logfile={file}; sudo writes every command line it runs to that \
                 file on the decoy disk"
            ));
        }
        out
    }
}

/// Read the sudoers configuration rooted at `main` and collect its logging
/// settings. Unreadable files (sudoers is mode 0440, so an unprivileged `nails
/// check` cannot read it) contribute nothing.
pub fn scan_sudoers<F: Filesystem>(fs: &F, main: &Path) -> SudoLogging {
    let mut logging = SudoLogging::default();
    let mut flags: Vec<(String, bool)> = Vec::new();
    scan_file(fs, main, 0, &mut logging, &mut flags);
    // Apply the flags in order, so a later `!log_output` cancels an earlier one.
    let mut enabled: Vec<String> = Vec::new();
    for (flag, on) in flags {
        enabled.retain(|f| *f != flag);
        if on {
            enabled.push(flag);
        }
    }
    logging.io_logging.extend(enabled);
    logging.io_logging.sort();
    logging.io_logging.dedup();
    logging
}

fn scan_file<F: Filesystem>(
    fs: &F,
    path: &Path,
    depth: usize,
    logging: &mut SudoLogging,
    flags: &mut Vec<(String, bool)>,
) {
    if depth > MAX_INCLUDE_DEPTH {
        return;
    }
    let Ok(content) = fs.read_file_content(path) else {
        return;
    };
    let base = path.parent().unwrap_or(Path::new("/"));
    for line in logical_lines(&content) {
        match parse_line(&line) {
            Line::Include(target) => scan_file(fs, &base.join(target), depth + 1, logging, flags),
            Line::IncludeDir(dir) => {
                for file in include_dir_files(fs, &base.join(dir)) {
                    scan_file(fs, &file, depth + 1, logging, flags);
                }
            }
            Line::Defaults(params) => {
                for param in params {
                    apply_param(&param, logging, flags);
                }
            }
            Line::UserSpec(tags) => {
                for tag in tags {
                    logging.io_logging.push(format!("{tag}: tag"));
                }
            }
            Line::Other => {}
        }
    }
}

/// The files sudo reads from an include directory: regular names that neither
/// end in `~` nor contain a `.`, in lexical order.
fn include_dir_files<F: Filesystem>(fs: &F, dir: &Path) -> Vec<PathBuf> {
    let Ok(mut entries) = fs.list_directory(dir) else {
        return Vec::new();
    };
    entries.retain(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| !name.ends_with('~') && !name.contains('.'))
    });
    entries.sort();
    entries
}

/// Join backslash-continued lines.
fn logical_lines(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for raw in content.lines() {
        if let Some(stripped) = raw.strip_suffix('\\') {
            current.push_str(stripped);
            current.push(' ');
            continue;
        }
        current.push_str(raw);
        out.push(std::mem::take(&mut current));
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// One parsed sudoers line, reduced to what the scan needs.
#[derive(Debug, PartialEq, Eq)]
enum Line {
    Include(String),
    IncludeDir(String),
    Defaults(Vec<String>),
    /// A user specification carrying `LOG_INPUT:`/`LOG_OUTPUT:` tags.
    UserSpec(Vec<&'static str>),
    Other,
}

fn parse_line(line: &str) -> Line {
    let trimmed = line.trim();
    for (prefix, dir) in [
        ("@includedir", true),
        ("#includedir", true),
        ("@include", false),
        ("#include", false),
    ] {
        if let Some(rest) = trimmed.strip_prefix(prefix)
            && rest.starts_with(char::is_whitespace)
        {
            let target = unquote(rest.trim()).to_string();
            return if dir {
                Line::IncludeDir(target)
            } else {
                Line::Include(target)
            };
        }
    }
    let content = strip_comment(trimmed);
    if content.is_empty() {
        return Line::Other;
    }
    let (first, rest) = content
        .split_once(char::is_whitespace)
        .unwrap_or((content, ""));
    if first == "Defaults" || first.starts_with("Defaults") && is_scoped_defaults(first) {
        return Line::Defaults(split_params(rest));
    }
    // Aliases cannot carry tags; anything else may be a user specification.
    if matches!(
        first,
        "User_Alias" | "Runas_Alias" | "Host_Alias" | "Cmnd_Alias" | "Cmd_Alias"
    ) {
        return Line::Other;
    }
    let tags: Vec<&'static str> = ["LOG_INPUT", "LOG_OUTPUT"]
        .into_iter()
        .filter(|tag| {
            content
                .split(|c: char| c.is_whitespace() || c == ',' || c == '=' || c == ')')
                .any(|token| {
                    token
                        .strip_prefix(tag)
                        .is_some_and(|rest| rest.starts_with(':'))
                })
        })
        .collect();
    if tags.is_empty() {
        Line::Other
    } else {
        Line::UserSpec(tags)
    }
}

/// `Defaults:user`, `Defaults@host`, `Defaults!cmnd`, `Defaults>runas`.
fn is_scoped_defaults(word: &str) -> bool {
    word.strip_prefix("Defaults")
        .and_then(|rest| rest.chars().next())
        .is_some_and(|c| matches!(c, ':' | '@' | '!' | '>'))
}

/// Drop a `#` comment that is outside double quotes. A `#` followed by a digit
/// is a numeric uid in a user list, not a comment.
fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;
    let mut chars = line.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            '#' if !in_quotes => {
                let uid = chars.peek().is_some_and(|(_, next)| next.is_ascii_digit());
                if !uid {
                    return line[..i].trim_end();
                }
            }
            _ => {}
        }
    }
    line
}

/// Split a `Defaults` parameter list on commas outside double quotes.
fn split_params(list: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for c in list.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' => {
                current.push(c);
                escaped = true;
            }
            '"' => {
                current.push(c);
                in_quotes = !in_quotes;
            }
            ',' if !in_quotes => out.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    out.push(current);
    out.into_iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

fn apply_param(param: &str, logging: &mut SudoLogging, flags: &mut Vec<(String, bool)>) {
    // `name=value`, `name += value`, `name -= value`, `name` or `!name`. The
    // name is the last word before the operator, so a scope list that the line
    // split left in front of it (`Defaults:alice, bob log_output`) is skipped.
    let (left, value) = match param.split_once('=') {
        Some((left, value)) => (left.trim_end_matches(['+', '-']), Some(value.trim())),
        None => (param, None),
    };
    let word = left.split_whitespace().last().unwrap_or_default();
    let (negated, name) = match word.strip_prefix('!') {
        Some(name) => (true, name),
        None => (false, word),
    };
    match name {
        "logfile" => {
            logging.logfile = match (negated, value) {
                (true, _) => None,
                (false, Some(value)) if !value.is_empty() => Some(unquote(value).to_string()),
                _ => logging.logfile.take(),
            };
        }
        "iolog_dir" => {
            logging.iolog_dir = match (negated, value) {
                (true, _) => None,
                (false, Some(value)) if !value.is_empty() => Some(unquote(value).to_string()),
                _ => logging.iolog_dir.take(),
            };
        }
        flag if IO_FLAGS.contains(&flag) && value.is_none() => {
            flags.push((flag.to_string(), !negated));
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RealFilesystem;

    fn scan_text(main: &str) -> SudoLogging {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sudoers");
        std::fs::write(&path, main).unwrap();
        scan_sudoers(&RealFilesystem, &path)
    }

    #[test]
    fn a_stock_sudoers_has_no_findings() {
        let logging = scan_text(
            "# sudoers\nDefaults env_reset\nDefaults secure_path=\"/usr/bin:/bin\"\n\
             root ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL) ALL\n@includedir /nonexistent\n",
        );
        assert_eq!(logging, SudoLogging::default());
        assert!(logging.findings().is_empty());
    }

    #[test]
    fn detects_logfile_and_io_logging() {
        let logging = scan_text(
            "Defaults logfile=\"/var/log/sudo.log\"\n\
             Defaults log_output, log_input\n\
             Defaults iolog_dir=/var/log/sudo-io/%{user}\n",
        );
        assert_eq!(logging.logfile.as_deref(), Some("/var/log/sudo.log"));
        assert_eq!(logging.io_logging, vec!["log_input", "log_output"]);
        assert_eq!(
            logging.iolog_dir.as_deref(),
            Some("/var/log/sudo-io/%{user}")
        );
        let findings = logging.findings();
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(findings[0].contains("whole terminal sessions"));
        assert!(findings[1].contains("/var/log/sudo.log"));
    }

    #[test]
    fn a_later_negation_cancels_a_flag() {
        let logging = scan_text("Defaults log_output\nDefaults:alice !log_output\n");
        assert!(logging.io_logging.is_empty(), "{logging:?}");
        let logging = scan_text("Defaults !logfile\nDefaults logfile = /x\n");
        assert_eq!(logging.logfile.as_deref(), Some("/x"));
        let logging = scan_text("Defaults:alice, bob !log_input\nDefaults:%wheel, bob log_input\n");
        assert_eq!(logging.io_logging, vec!["log_input"]);
    }

    #[test]
    fn scoped_defaults_and_continuations_count() {
        let logging =
            scan_text("Defaults>root log_ttyout\nDefaults@host1 env_reset, \\\n  log_stdin\n");
        assert_eq!(logging.io_logging, vec!["log_stdin", "log_ttyout"]);
    }

    #[test]
    fn command_tags_count_as_io_logging() {
        let logging = scan_text("alice ALL = (root) NOPASSWD: LOG_OUTPUT: /usr/bin/bash\n");
        assert_eq!(logging.io_logging, vec!["LOG_OUTPUT: tag"]);
        let logging = scan_text("alice ALL = (root) NOLOG_OUTPUT: ALL\n");
        assert!(logging.io_logging.is_empty());
        let logging = scan_text("alice ALL=(root)LOG_INPUT:ALL\n");
        assert_eq!(logging.io_logging, vec!["LOG_INPUT: tag"]);
    }

    #[test]
    fn comments_and_uids_are_told_apart() {
        let logging = scan_text(
            "# Defaults log_output\nDefaults env_reset # log_input\n#1000 ALL=(ALL) LOG_INPUT: ALL\n",
        );
        assert_eq!(logging.io_logging, vec!["LOG_INPUT: tag"]);
    }

    #[test]
    fn iolog_dir_alone_is_reported() {
        let findings = scan_text("Defaults iolog_dir=/srv/io\n").findings();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("iolog_dir=/srv/io"));
    }

    #[test]
    fn follows_include_dirs_like_sudo() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("sudoers");
        let drop_in = dir.path().join("sudoers.d");
        std::fs::create_dir(&drop_in).unwrap();
        std::fs::write(&main, "Defaults env_reset\n#includedir sudoers.d\n").unwrap();
        std::fs::write(drop_in.join("10-io"), "Defaults log_output\n").unwrap();
        // sudo skips names with a dot or a trailing tilde.
        std::fs::write(drop_in.join("README.txt"), "Defaults logfile=/a\n").unwrap();
        std::fs::write(drop_in.join("20-old~"), "Defaults logfile=/b\n").unwrap();
        std::fs::write(drop_in.join("30-inc"), "@include ../extra\n").unwrap();
        std::fs::write(dir.path().join("extra"), "Defaults logfile=/var/log/sudo\n").unwrap();

        let logging = scan_sudoers(&RealFilesystem, &main);
        assert_eq!(logging.io_logging, vec!["log_output"]);
        assert_eq!(logging.logfile.as_deref(), Some("/var/log/sudo"));
    }

    #[test]
    fn an_include_cycle_terminates() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("sudoers");
        std::fs::write(&main, "@include sudoers\nDefaults log_input\n").unwrap();
        let logging = scan_sudoers(&RealFilesystem, &main);
        assert_eq!(logging.io_logging, vec!["log_input"]);
    }

    #[test]
    fn an_unreadable_sudoers_contributes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let logging = scan_sudoers(&RealFilesystem, &dir.path().join("missing"));
        assert_eq!(logging, SudoLogging::default());
    }
}
