// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The console layer: what the operator sees of the log on stderr.
//!
//! At the default verbosity the console is compact. An informational event
//! prints its message alone, so a progress line reads as a plain line. A
//! warning or an error prints the CLI's mark (`⚠`, `✗`, or `[WARN]`,
//! `[FAIL]` under `--ascii`), the message and its fields as `key: value`
//! details, because some events name the file or the error only in a field.
//! No level word and no raw `key=value` record reaches the screen. With `-v`
//! and `-vv` the console shows the full records (level, message and fields),
//! as a diagnostic view.
//!
//! The panic hook's event never reaches the console: it carries the payload
//! and the source location, which belong in the log on the hidden volume, and
//! the hook prints its own neutral line.

use std::fmt::{self, Write as _};

use nails_core::Verbosity;
use nails_core::output::{Mark, Style};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{
    self as fmt_layer, FmtContext, FormatEvent, FormatFields, MakeWriter,
};
use tracing_subscriber::registry::LookupSpan;

use crate::cli::output::OutputSettings;

/// The target of the panic hook's event, which stays off the console.
pub(crate) const PANIC_TARGET: &str = "panic";

/// The console layer for `settings`, writing to `writer`.
///
/// The level follows the verbosity (`-q` errors only, default INFO, `-v`
/// DEBUG, `-vv` TRACE), and colour follows `settings.color_stderr`.
pub(super) fn layer<S, W>(settings: &OutputSettings, writer: W) -> Box<dyn Layer<S> + Send + Sync>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let level = settings.tracing_level();
    let filter = filter_fn(move |meta| meta.target() != PANIC_TARGET && *meta.level() <= level);
    let base = fmt_layer::layer()
        .with_ansi(settings.color_stderr)
        .with_writer(writer);
    if settings.verbosity >= Verbosity::Verbose {
        // No timestamps even here: the elapsed time is reported by the progress
        // heartbeat, and a wall-clock stamp on every line only widens the
        // activity fingerprint if the output is ever copied off-box. The log
        // file on the hidden volume keeps a precise timestamp.
        base.without_time()
            .with_target(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_file(false)
            .with_line_number(false)
            .with_level(true)
            .with_filter(filter)
            .boxed()
    } else {
        base.event_format(Compact {
            style: settings.stderr_style(),
        })
        .with_filter(filter)
        .boxed()
    }
}

/// The compact event format of the default verbosity.
struct Compact {
    style: Style,
}

impl<S, N> FormatEvent<S, N> for Compact
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut recorded = Recorded::default();
        event.record(&mut recorded);
        writeln!(
            writer,
            "{}",
            compact_line(*event.metadata().level(), &recorded, self.style)
        )
    }
}

/// An event's message and its other fields, as text.
#[derive(Debug, Default)]
pub(super) struct Recorded {
    pub(super) message: String,
    pub(super) fields: Vec<(&'static str, String)>,
}

impl Recorded {
    fn push(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = value;
        } else {
            self.fields.push((field.name(), value));
        }
    }
}

impl Visit for Recorded {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.push(field, format!("{value:?}"));
    }
}

/// One console line: the message alone for an informational event; the mark,
/// the message and every field as `key: value` for a warning or an error.
pub(super) fn compact_line(level: Level, recorded: &Recorded, style: Style) -> String {
    let mark = match level {
        Level::ERROR => Mark::Fail,
        Level::WARN => Mark::Warn,
        _ => return recorded.message.clone(),
    };
    let mut text = recorded.message.clone();
    if !recorded.fields.is_empty() {
        let details: Vec<String> = recorded
            .fields
            .iter()
            .map(|(name, value)| format!("{name}: {value}"))
            .collect();
        let _ = write!(text, " ({})", details.join(", "));
    }
    style.marked(mark, text)
}
