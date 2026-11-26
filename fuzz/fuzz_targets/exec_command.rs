// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The commands of a decoy's `ExecStart=` value, which the decoy-persistence
//! check reads to tell what a service runs. NAILS has to split the value as
//! systemd's `config_parse_exec()` does: a word split otherwise makes a
//! program that persists on the decoy look like another.
//!
//! The input is the value. The target checks that splitting it never panics
//! and that the words of each command NAILS reads, quoted and escaped again,
//! split into the same command.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_core::preflight::checks::locate_database::exec::exec_commands;

fuzz_target!(|data: &[u8]| {
    let value = String::from_utf8_lossy(data);
    let Ok(commands) = exec_commands(&value) else {
        return;
    };
    for command in &commands {
        // A program that starts like a prefix, or that is a lone `;`, reads
        // as one again whatever its quotes.
        let reread = command
            .program
            .first()
            .is_some_and(|byte| b"-@:+!".contains(byte))
            || command.program == b";";
        if reread {
            continue;
        }
        let mut again = quoted(&command.program, false);
        for arg in &command.args {
            again.push(' ');
            again.push_str(&quoted(arg, true));
        }
        assert_eq!(
            exec_commands(&again).as_deref(),
            Ok(std::slice::from_ref(command)),
            "{again}"
        );
    }
});

/// `word` quoted for an `ExecStart=` value so that systemd reads it back as
/// it is: `%` doubled, and in an argument `$` doubled too; the quote, the
/// backslash and every byte that is not printable ASCII escaped.
fn quoted(word: &[u8], argument: bool) -> String {
    let mut out = String::from("\"");
    for &byte in word {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'%' => out.push_str("%%"),
            b'$' if argument => out.push_str("$$"),
            0x20..=0x7e => out.push(char::from(byte)),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out.push('"');
    out
}
