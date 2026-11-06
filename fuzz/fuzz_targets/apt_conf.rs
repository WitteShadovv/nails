// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! An apt configuration file of the decoy, from which NAILS reads whether
//! unattended-upgrades installs the pending updates at shutdown, which a
//! switch through logind is to it.
//!
//! The input is the file. The target checks that:
//!
//! - an empty line, or a line holding only a comment, put in before any of
//!   the first 16 lines changes nothing but the line numbers: the statements
//!   stay the same, and a file the reader refuses stays refused for the same
//!   reason. apt reads a file line by line, a statement and a `/* */` comment
//!   going on over as many lines as they take;
//! - after a file that ends outside every block and comment, a statement
//!   that sets the setting is read, last, with its value and its line, and so
//!   is a `#clear` of the setting and one of the scope above it;
//! - each item the reader names the setting has two tags, the setting's
//!   apart from ASCII case;
//! - a value never reads as the opposite of the default: read with the
//!   default true and with the default false, it reads the same both times
//!   or as the default both times;
//! - a value whose reading the reader leaves to the system's locale (a byte
//!   beyond ASCII before its first NUL) reads as the default both times.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_base::packages::apt_conf::{
    Parsed, Statement, SyntaxError, names, parse, string_to_bool, tags, value_by_locale,
};

/// The setting unattended-upgrades' shutdown helper reads.
const KEY: &[&str] = &["Unattended-Upgrade", "InstallOnShutdown"];

/// Lines that change nothing where a line starts.
const NOTHING: [&[u8]; 3] = [b"\n", b"// nothing\n", b"   \t\n"];

fuzz_target!(|data: &[u8]| {
    let first = parse(data);

    // A line of nothing put in before each of the first 16 lines in turn.
    let starts = std::iter::once(0)
        .chain(
            data.iter()
                .enumerate()
                .filter(|(_, byte)| **byte == b'\n')
                .map(|(at, _)| at + 1),
        )
        .take(16);
    for start in starts {
        for nothing in NOTHING {
            let shifted = [&data[..start], nothing, &data[start..]].concat();
            let line = data[..start].iter().filter(|&&byte| byte == b'\n').count() + 1;
            assert_eq!(
                unshift(parse(&shifted), line),
                first.clone().map(strip_lines),
                "{nothing:?} before line {line}"
            );
        }
    }

    if let Ok(parsed) = &first {
        let lines = data.split(|&byte| byte == b'\n').count();
        if parsed.open_blocks == 0 && !parsed.in_comment {
            let set = [data, b"\nUnattended-Upgrade::InstallOnShutdown \"true\";\n"].concat();
            let after = parse(&set).expect("a statement after a whole file is read");
            assert_eq!(
                after.statements.last(),
                Some(&Statement::Set {
                    item: b"Unattended-Upgrade::InstallOnShutdown".to_vec(),
                    value: b"true".to_vec(),
                    line: lines + 1,
                })
            );
            for name in [
                b"Unattended-Upgrade::InstallOnShutdown".as_slice(),
                b"Unattended-Upgrade",
            ] {
                let cleared = [data, b"\n#clear ", name, b";\n"].concat();
                let after = parse(&cleared).expect("a clear after a whole file is read");
                assert_eq!(
                    after.statements.last(),
                    Some(&Statement::Clear {
                        name: name.to_vec(),
                        line: lines + 1,
                    })
                );
            }
        }

        for statement in &parsed.statements {
            let Statement::Set { item, value, .. } = statement else {
                continue;
            };
            if names(item, KEY, false) {
                let tags = tags(item).expect("the setting has tags");
                assert_eq!(tags.len(), 2);
                for (tag, wanted) in tags.iter().zip(KEY) {
                    assert!(tag.eq_ignore_ascii_case(wanted.as_bytes()));
                }
            }
            let (on, off) = (string_to_bool(value, true), string_to_bool(value, false));
            assert!(on || !off, "{value:?}");
            if value_by_locale(value) {
                assert!(on && !off, "{value:?}");
            }
        }
    }
});

/// A result with every line number set to 0, for comparing two readings
/// whose lines differ.
fn strip_lines(mut parsed: Parsed) -> Parsed {
    for statement in &mut parsed.statements {
        match statement {
            Statement::Set { line, .. }
            | Statement::Clear { line, .. }
            | Statement::Include { line }
            | Statement::ConfigureIndex { line } => *line = 0,
        }
    }
    parsed
}

/// The reading of a file with a line put in before `line`, compared as the
/// reading of the file itself: every line number set to 0, and an error
/// after the put-in line one line earlier.
fn unshift(result: Result<Parsed, SyntaxError>, line: usize) -> Result<Parsed, SyntaxError> {
    match result {
        Ok(parsed) => Ok(strip_lines(parsed)),
        Err(mut error) => {
            if error.line > line {
                error.line -= 1;
            }
            Err(error)
        }
    }
}
