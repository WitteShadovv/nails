// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The string escapes of a `.nix` line, and the line as Nix reads them.
//!
//! Nix gives a string the bytes its escapes stand for, so `"@v\ault"` is
//! `@vault` and `"2\58"` is `258`. The scan matches every marker in the line
//! as the file spells it and again in the line with the escapes of its
//! strings decoded ([`Decoded`]), so a name counts written either way.
//!
//! The escapes, as Nix 2.35 evaluates them (`nix-instantiate --eval`):
//!
//! - in a `"…"` string, `\n`, `\r` and `\t` are a newline, a carriage return
//!   and a tab, and a backslash before any other byte is that byte (`\"`,
//!   `\\`, `\$`, `\a`, `\5`); a backslash at the end of a line is the
//!   newline after it;
//! - in a `''…''` string, `'''` is `''`, `''$` is `$`, `''\` before `n`, `r`
//!   or `t` is the control character and before any other byte that byte,
//!   and a lone backslash is itself (`''a\nb''` is `a\nb`).
//!
//! `$${` is no escape: Nix keeps both dollars and reads no interpolation.

use super::nix_text::Context;
use std::ops::Range;

/// One escape in a string: the bytes of the line it takes, and what Nix
/// reads there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Escape {
    pub(super) raw: Range<usize>,
    pub(super) text: Vec<u8>,
}

/// What Nix reads for `raw`, a step through the text of a string (`''…''`
/// when `indented`) that may be an escape; `None` for any other step. A
/// step cut off by the end of the line stands for the newline after it.
pub(super) fn decode(raw: &[u8], indented: bool) -> Option<Vec<u8>> {
    let escaped = if indented {
        match raw {
            [b'\'', b'\'', b'\''] => return Some(b"''".to_vec()),
            [b'\'', b'\'', b'$'] => return Some(b"$".to_vec()),
            [b'\'', b'\'', b'\\', rest @ ..] => rest,
            _ => return None,
        }
    } else {
        match raw {
            [b'\\', rest @ ..] => rest,
            _ => return None,
        }
    };
    Some(vec![match escaped.first() {
        Some(b'n') | None => b'\n',
        Some(b'r') => b'\r',
        Some(b't') => b'\t',
        Some(&byte) => byte,
    }])
}

/// A line with the escapes of its strings decoded, lowercased like the text
/// the markers are matched against, and where each of its bytes comes from.
#[derive(Debug)]
pub(super) struct Decoded {
    pub(super) text: Vec<u8>,
    /// For each byte of `text`, the bytes of the line it stands for.
    from: Vec<Range<usize>>,
}

impl Decoded {
    /// `line` with `escapes`, which are in the order of the line and do not
    /// overlap, decoded.
    pub(super) fn of(line: &[u8], escapes: &[Escape]) -> Self {
        let mut text = Vec::with_capacity(line.len());
        let mut from = Vec::with_capacity(line.len());
        let mut at = 0;
        for escape in escapes {
            let raw = escape.raw.start..escape.raw.end.min(line.len());
            if raw.start < at {
                continue;
            }
            plain(line, at..raw.start, &mut text, &mut from);
            for &byte in &escape.text {
                text.push(byte);
                from.push(raw.clone());
            }
            at = raw.end;
        }
        plain(line, at..line.len(), &mut text, &mut from);
        text.make_ascii_lowercase();
        Self { text, from }
    }

    /// The bytes of the decoded text that stand for `raw`, a range of the
    /// line, or for part of it.
    pub(super) fn decoded(&self, raw: &Range<usize>) -> Range<usize> {
        let start = self.from.partition_point(|from| from.end <= raw.start);
        let end = self.from.partition_point(|from| from.start < raw.end);
        start..end.max(start)
    }

    /// The bytes of the line that `decoded`, a range of the decoded text,
    /// stands for.
    pub(super) fn raw(&self, decoded: &Range<usize>) -> Range<usize> {
        let line_end = self.from.last().map_or(0, |from| from.end);
        let start = self
            .from
            .get(decoded.start)
            .map_or(line_end, |from| from.start);
        let end = if decoded.end > decoded.start {
            self.from[decoded.end - 1].end
        } else {
            start
        };
        start..end
    }

    /// `context`, a context of the line, for the decoded text.
    pub(super) fn context(&self, context: &Context) -> Context {
        Context {
            names: context
                .names
                .iter()
                .map(|(range, named)| (self.decoded(range), *named))
                .collect(),
            arguments: context.arguments.iter().map(|r| self.decoded(r)).collect(),
            defined: context.defined.iter().map(|r| self.decoded(r)).collect(),
        }
    }
}

/// Add the bytes `range` of `line`, which hold no escape, to `text`, each
/// standing for itself.
fn plain(line: &[u8], range: Range<usize>, text: &mut Vec<u8>, from: &mut Vec<Range<usize>>) {
    text.extend_from_slice(&line[range.clone()]);
    from.extend(range.map(|i| i..i + 1));
}

#[cfg(test)]
#[path = "escapes_tests.rs"]
mod tests;
