// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared rendering primitives for CLI output
//!
//! The CLI decides once at start-up whether each stream takes colour and
//! whether output must stay ASCII, and installs that decision with
//! [`configure`]. Everything that prints a status mark (core messages,
//! preflight results, the CLI renderers, logging notices and prompts) draws it
//! from [`Mark`], so a glyph means the same thing everywhere and has exactly one
//! ASCII fallback.
//!
//! Colour is decided per stream because stdout and stderr are often different
//! sinks (a terminal and a pipe, or the journal). Until [`configure`] is called
//! nothing is coloured and Unicode marks are used.
//!
//! # Examples
//!
//! ```
//! use nails_core::output::{self, Mark, Stream, Style};
//!
//! let ascii = Style { color: false, ascii: true };
//! assert_eq!(ascii.marked(Mark::Fail, "mount failed"), "[FAIL] mount failed");
//!
//! let unicode = Style::default();
//! assert_eq!(unicode.marked(Mark::Pass, "done"), "✓ done");
//!
//! // Messages printed by the library use the configured style of their stream.
//! let _ = output::style(Stream::Stderr);
//! ```

use std::fmt::Display;
use std::io::{Write, stderr, stdout};
use std::sync::atomic::{AtomicBool, Ordering};

static STDOUT_COLOR: AtomicBool = AtomicBool::new(false);
static STDERR_COLOR: AtomicBool = AtomicBool::new(false);
static ASCII: AtomicBool = AtomicBool::new(false);

/// An output stream; colour is decided for each one separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    /// Command results.
    Stdout,
    /// Diagnostics, warnings, errors and prompts.
    Stderr,
}

/// Install the rendering decisions resolved by the CLI.
///
/// `colored` has a single process-wide switch, so it follows stdout, where the
/// renderers that still use it print. Text this crate writes to stderr is
/// painted from the stderr decision instead.
pub fn configure(color_stdout: bool, color_stderr: bool, ascii: bool) {
    STDOUT_COLOR.store(color_stdout, Ordering::Relaxed);
    STDERR_COLOR.store(color_stderr, Ordering::Relaxed);
    ASCII.store(ascii, Ordering::Relaxed);
    colored::control::set_override(color_stdout);
}

/// The configured style for `stream`.
pub fn style(stream: Stream) -> Style {
    let color = match stream {
        Stream::Stdout => STDOUT_COLOR.load(Ordering::Relaxed),
        Stream::Stderr => STDERR_COLOR.load(Ordering::Relaxed),
    };
    Style {
        color,
        ascii: ASCII.load(Ordering::Relaxed),
    }
}

/// Whether output is restricted to ASCII.
pub fn is_ascii() -> bool {
    ASCII.load(Ordering::Relaxed)
}

/// Status marks shared by every renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// Succeeded, verified, mounted.
    Pass,
    /// Needs attention, transitional.
    Warn,
    /// Failed, not mounted, critical.
    Fail,
    /// Informational.
    Info,
    /// Neither protected nor at risk, such as the decoy system. Deliberately
    /// uncoloured so it cannot be mistaken for a failure.
    Neutral,
    /// List bullet.
    Bullet,
    /// Points at a suggested action.
    Arrow,
}

impl Mark {
    /// Every mark, for exhaustive checks.
    pub const ALL: [Mark; 7] = [
        Mark::Pass,
        Mark::Warn,
        Mark::Fail,
        Mark::Info,
        Mark::Neutral,
        Mark::Bullet,
        Mark::Arrow,
    ];

    /// The Unicode glyph.
    pub const fn unicode(self) -> &'static str {
        match self {
            Mark::Pass => "✓",
            Mark::Warn => "⚠",
            Mark::Fail => "✗",
            Mark::Info => "ℹ",
            Mark::Neutral => "○",
            Mark::Bullet => "•",
            Mark::Arrow => "→",
        }
    }

    /// The ASCII replacement.
    pub const fn ascii(self) -> &'static str {
        match self {
            Mark::Pass => "[PASS]",
            Mark::Warn => "[WARN]",
            Mark::Fail => "[FAIL]",
            Mark::Info => "[INFO]",
            Mark::Neutral => "[-]",
            Mark::Bullet => "-",
            Mark::Arrow => "->",
        }
    }

    /// The colour the mark is painted in, if any.
    pub const fn tone(self) -> Option<Tone> {
        match self {
            Mark::Pass => Some(Tone::Green),
            Mark::Warn => Some(Tone::Yellow),
            Mark::Fail => Some(Tone::Red),
            Mark::Info => Some(Tone::Blue),
            Mark::Neutral | Mark::Bullet | Mark::Arrow => None,
        }
    }
}

/// Text colours and emphasis used by the renderers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Green,
    Yellow,
    Red,
    Cyan,
    Blue,
    Dim,
    Bold,
}

impl Tone {
    const fn sgr(self) -> &'static str {
        match self {
            Tone::Green => "32",
            Tone::Yellow => "33",
            Tone::Red => "31",
            Tone::Cyan => "36",
            Tone::Blue => "34",
            Tone::Dim => "2",
            Tone::Bold => "1",
        }
    }
}

/// How text is rendered on one stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Style {
    /// Emit ANSI colour sequences.
    pub color: bool,
    /// Use ASCII replacements for marks and box drawing.
    pub ascii: bool,
}

impl Style {
    /// `text` in `tone` when colour is on, unchanged otherwise.
    pub fn paint(self, text: impl Display, tone: Tone) -> String {
        if self.color {
            format!("\x1b[{}m{}\x1b[0m", tone.sgr(), text)
        } else {
            text.to_string()
        }
    }

    /// `text` in bold `tone` when colour is on, unchanged otherwise.
    pub fn paint_bold(self, text: impl Display, tone: Tone) -> String {
        if self.color {
            format!("\x1b[1;{}m{}\x1b[0m", tone.sgr(), text)
        } else {
            text.to_string()
        }
    }

    /// The glyph for `mark` in this style, uncoloured.
    pub fn glyph(self, mark: Mark) -> &'static str {
        if self.ascii {
            mark.ascii()
        } else {
            mark.unicode()
        }
    }

    /// The glyph for `mark`, coloured when colour is on.
    pub fn mark(self, mark: Mark) -> String {
        match mark.tone() {
            Some(tone) => self.paint_bold(self.glyph(mark), tone),
            None => self.glyph(mark).to_string(),
        }
    }

    /// `text` preceded by `mark`.
    pub fn marked(self, mark: Mark, text: impl Display) -> String {
        format!("{} {}", self.mark(mark), text)
    }
}

/// Rewrite a string so it is pure ASCII, for an `--ascii` surface that may
/// replay text produced elsewhere (for example a log message that embedded a
/// Unicode mark glyph).
///
/// Every mark glyph is swapped for its ASCII form ([`Mark::ascii`]); any other
/// non-ASCII scalar (a stray emoji, a combining variation selector such as the
/// `U+FE0F` after `⚠️`) is dropped so the result is guaranteed ASCII. Text that
/// is already ASCII is returned unchanged in spirit, character for character.
///
/// # Examples
///
/// ```
/// use nails_core::output;
///
/// assert_eq!(output::ascii_fallback("✓ Activation complete"), "[PASS] Activation complete");
/// assert!(output::ascii_fallback("⚠️  2 writers").is_ascii());
/// ```
pub fn ascii_fallback(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    'chars: for ch in text.chars() {
        if ch.is_ascii() {
            out.push(ch);
            continue;
        }
        for mark in Mark::ALL {
            if mark.unicode().starts_with(ch) {
                out.push_str(mark.ascii());
                continue 'chars;
            }
        }
        // Any other non-ASCII scalar (including the U+FE0F variation selector
        // that trails an emoji mark) is dropped so the output stays ASCII.
    }
    out
}

/// Format an error line for stderr.
///
/// # Examples
///
/// ```
/// use nails_core::output;
///
/// // Unconfigured: Unicode mark, no colour.
/// assert_eq!(output::format_error("test"), "✗ test");
/// ```
pub fn format_error(msg: &str) -> String {
    style(Stream::Stderr).marked(Mark::Fail, msg)
}

/// Format a warning line for stderr.
pub fn format_warn(msg: &str) -> String {
    style(Stream::Stderr).marked(Mark::Warn, msg)
}

/// Format a success line for stdout.
pub fn format_info(msg: &str) -> String {
    style(Stream::Stdout).marked(Mark::Pass, msg)
}

/// Print an error line to stderr.
pub fn error(msg: &str) {
    let _ = writeln!(stderr(), "{}", format_error(msg));
}

/// Print a warning line to stderr.
pub fn warn(msg: &str) {
    let _ = writeln!(stderr(), "{}", format_warn(msg));
}

/// Print a success line to stdout.
pub fn info(msg: &str) {
    let _ = writeln!(stdout(), "{}", format_info(msg));
}

/// Serialises the tests that change the global render state.
#[cfg(test)]
static RENDER_STATE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Holds the render-state test lock and resets the global render state on
/// creation and drop, so tests that change it neither overlap nor leak into one
/// another. A poisoned lock is recovered: the failed test's guard already reset
/// the state when it unwound.
#[cfg(test)]
pub(crate) struct RenderStateTestGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl RenderStateTestGuard {
    pub(crate) fn new() -> Self {
        let lock = RENDER_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        configure(false, false, false);
        Self { _lock: lock }
    }
}

#[cfg(test)]
impl Drop for RenderStateTestGuard {
    fn drop(&mut self) {
        configure(false, false, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COLOR: Style = Style {
        color: true,
        ascii: false,
    };
    const ASCII_STYLE: Style = Style {
        color: false,
        ascii: true,
    };

    #[test]
    fn every_ascii_mark_is_ascii_and_every_glyph_is_distinct() {
        for mark in Mark::ALL {
            assert!(mark.ascii().is_ascii(), "{mark:?}");
        }
        for (i, a) in Mark::ALL.iter().enumerate() {
            for b in &Mark::ALL[i + 1..] {
                assert_ne!(a.unicode(), b.unicode(), "{a:?} vs {b:?}");
                assert_ne!(a.ascii(), b.ascii(), "{a:?} vs {b:?}");
            }
        }
    }

    #[test]
    fn neutral_mark_is_never_coloured_like_a_failure() {
        assert_eq!(Mark::Neutral.tone(), None);
        assert_eq!(COLOR.mark(Mark::Neutral), "○");
        assert_ne!(COLOR.mark(Mark::Neutral), COLOR.mark(Mark::Fail));
    }

    #[test]
    fn coloured_style_wraps_marks_in_sgr_sequences() {
        assert_eq!(COLOR.mark(Mark::Fail), "\x1b[1;31m✗\x1b[0m");
        assert_eq!(COLOR.mark(Mark::Warn), "\x1b[1;33m⚠\x1b[0m");
        assert_eq!(COLOR.mark(Mark::Pass), "\x1b[1;32m✓\x1b[0m");
        assert_eq!(COLOR.paint("x", Tone::Dim), "\x1b[2mx\x1b[0m");
    }

    #[test]
    fn ascii_style_uses_bracket_markers_without_escapes() {
        let line = ASCII_STYLE.marked(Mark::Warn, "careful");
        assert_eq!(line, "[WARN] careful");
        assert_eq!(ASCII_STYLE.paint("plain", Tone::Red), "plain");
    }

    #[test]
    fn ascii_fallback_folds_mark_glyphs_and_drops_other_non_ascii() {
        // A leading Pass glyph becomes its bracket form.
        assert_eq!(
            ascii_fallback("✓ Activation complete in 1.7s"),
            "[PASS] Activation complete in 1.7s"
        );
        // The warn emoji (⚠ + U+FE0F variation selector) folds to [WARN] with the
        // selector dropped, and the whole result is ASCII.
        let warn = ascii_fallback("⚠️  2 writers still on the decoy");
        assert_eq!(warn, "[WARN]  2 writers still on the decoy");
        assert!(warn.is_ascii());
        // An arrow marker folds to its ASCII form.
        assert_eq!(ascii_fallback("  → base64 risky"), "  -> base64 risky");
        // Plain ASCII is returned unchanged.
        assert_eq!(ascii_fallback("plain log line"), "plain log line");
        // A stray non-mark glyph is dropped, keeping the output ASCII.
        assert!(ascii_fallback("snapshot 日本語 done").is_ascii());
    }

    #[test]
    fn unconfigured_state_has_no_colour() {
        let _guard = RenderStateTestGuard::new();
        assert_eq!(format_error("test"), "✗ test");
        assert_eq!(format_warn("test"), "⚠ test");
        assert_eq!(format_info("test"), "✓ test");
    }

    #[test]
    fn colour_is_decided_per_stream() {
        let _guard = RenderStateTestGuard::new();
        configure(false, true, false);

        assert!(format_error("e").contains('\u{1b}'));
        assert!(format_warn("w").contains('\u{1b}'));
        assert!(!format_info("i").contains('\u{1b}'));
        assert!(!style(Stream::Stdout).color);
        assert!(style(Stream::Stderr).color);
    }

    #[test]
    fn ascii_applies_to_both_streams() {
        let _guard = RenderStateTestGuard::new();
        configure(true, true, true);

        assert!(is_ascii());
        assert!(format_error("x").contains("[FAIL]"));
        assert!(format_info("x").contains("[PASS]"));
    }

    #[test]
    fn print_functions_do_not_panic() {
        let _guard = RenderStateTestGuard::new();
        error("test error");
        warn("test warning");
        info("test info");
    }
}
