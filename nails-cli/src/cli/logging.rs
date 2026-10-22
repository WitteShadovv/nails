// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Logging initialization for NAILS CLI
//!
//! This module initializes the tracing subscriber with:
//! - A console layer on stderr, filtered by the resolved verbosity and compact
//!   at the default verbosity (see the `console` module)
//! - An optional file layer for JSON-formatted logs (captures all events)
//!
//! The console never writes to stdout, which carries the command's own output:
//! under `--json` that is the documented JSON and nothing else (for `activate`
//! the progress and result lines of its schema).
//!
//! The file layer implements graceful fallback: if the hidden volume is not mounted
//! or LoggingManager initialization fails, logging continues on the console only.

use tracing_subscriber::Layer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::cli::output::OutputSettings;

mod console;
#[cfg(test)]
mod tests;

pub(crate) use console::PANIC_TARGET;

/// Initialize the tracing subscriber from the resolved output settings
///
/// Sets up a two-layer subscriber:
/// 1. **File layer** (JSON): captures every event (TRACE+) to the configured
///    log file on the hidden volume, unless `log_file` is false
///    (`--no-log-file`) or the hidden volume is unavailable.
/// 2. **Console layer**: on stderr, filtered by `settings.verbosity` (`-q`
///    errors only, default INFO, `-v` DEBUG, `-vv` TRACE), compact at the
///    default verbosity and full records with `-v` and `-vv`.
///
/// ANSI colour on the console layer follows `settings.color_stderr`, so pipes
/// and the journal never receive escape sequences unless `--color always` is
/// given. A missing hidden volume never fails the command: logging continues
/// on the console only.
pub fn init_subscriber(
    settings: &OutputSettings,
    log_file: bool,
    config_override: Option<&std::path::Path>,
) {
    let file_layer = if log_file {
        init_file_layer(config_override, settings).ok().flatten()
    } else {
        None
    };

    // `Option<Layer>` is itself a layer, so a missing file layer is a no-op.
    tracing_subscriber::registry()
        .with(file_layer)
        // Lifts an activation spinner (when one is on screen) around each log
        // line so the two never garble; a plain stderr write otherwise.
        .with(console::layer(settings, || {
            nails_core::reporter::progress::ProgressAwareStderr
        }))
        .init();
}

/// Print a notice about logging setup itself, before the subscriber exists.
///
/// Warnings are dropped under `--quiet`; errors are always shown.
fn emit_logging_init_message(settings: &OutputSettings, is_error: bool, message: &str) {
    if let Some(line) = logging_init_line(settings, is_error, message) {
        eprintln!("{line}");
    }
}

fn logging_init_line(settings: &OutputSettings, is_error: bool, message: &str) -> Option<String> {
    use nails_core::output::Mark;

    if !is_error && settings.is_quiet() {
        return None;
    }
    let mark = if is_error { Mark::Fail } else { Mark::Warn };
    Some(settings.stderr_style().marked(mark, message))
}

/// Initialize file logging layer with LoggingManager
///
/// Creates JSON file layer that writes to `{hidden_volume}/logs/nails.log`.
/// Implements graceful fallback if hidden volume is not mounted.
///
/// # Returns
///
/// - `Ok(Some(layer))` - File layer successfully created
/// - `Ok(None)` - Hidden volume not available, logged warning to stderr
/// - `Err(_)` - Unexpected error during initialization
#[allow(clippy::type_complexity)]
fn init_file_layer(
    config_override: Option<&std::path::Path>,
    settings: &OutputSettings,
) -> Result<
    Option<
        tracing_subscriber::filter::Filtered<
            tracing_subscriber::fmt::Layer<
                tracing_subscriber::Registry,
                tracing_subscriber::fmt::format::JsonFields,
                tracing_subscriber::fmt::format::Format<tracing_subscriber::fmt::format::Json>,
                std::sync::Mutex<std::fs::File>,
            >,
            tracing_subscriber::filter::LevelFilter,
            tracing_subscriber::Registry,
        >,
    >,
    Box<dyn std::error::Error>,
> {
    use nails_core::{LoggingManager, RealFilesystem};
    use std::fs::OpenOptions;

    // Resolve the configuration through the one shared entry point every command
    // uses (`commands::resolve_config`), so the log file is placed by exactly the
    // configuration the command runs with. A configuration that fails to load is
    // never silently replaced by binary-derived defaults: doing so would open a
    // log file next to the binary even though the operator named a configuration
    // that could not be read, and with an explicit `--config` the command itself
    // exits non-zero. On any load error file logging simply stays off; the
    // command surfaces the error on stderr.
    let config = match crate::cli::commands::resolve_config(config_override) {
        Ok(loaded) => loaded.into_config(),
        Err(_) => return Ok(None),
    };

    // A host NAILS refuses must leave nothing on the hidden volume, the log
    // directory included: decline file logging there exactly as for a root that
    // did not pass the attach gate, so a refused host writes no log line before
    // the command's own platform gate turns it away. A detection that fails tells
    // us nothing, so it does not suppress the log.
    if nails_core::platform::detect(&RealFilesystem)
        .is_ok_and(|profile| profile.require_supported().is_err())
    {
        return Ok(None);
    }

    let log_dir = config.log_path.clone();
    let hidden_volume_root = config.hidden_volume_root.clone();

    // Create LoggingManager using configured log_path
    let logging_manager = LoggingManager::new(log_dir, hidden_volume_root);

    // Initialize LoggingManager with validation
    // Returns Ok(None) for graceful degradation (hidden volume not available)
    let fs = RealFilesystem;
    let logging_config = match logging_manager.init_or_explain(&fs) {
        Ok(Ok(config)) => config,
        Ok(Err(reason)) => {
            // Graceful degradation: the hidden root did not pass the attach
            // gate. The command reports a refused root itself, so the reason
            // is repeated only on request.
            if settings.verbosity >= nails_core::Verbosity::Verbose {
                emit_logging_init_message(
                    settings,
                    false,
                    &format!("File logging disabled: {reason}"),
                );
            }
            return Ok(None);
        }
        Err(e) => {
            emit_logging_init_message(
                settings,
                true,
                &format!(
                    "Logging init failed: {}, continuing with stdout-only logging",
                    e
                ),
            );
            return Ok(None);
        }
    };

    // Open log file for appending. Mode 0600: the log lives on the hidden volume
    // and names the operator's activity, so only its owner may read it, and a
    // group- or world-readable log is never created even for a moment.
    #[cfg(unix)]
    let log_file_result = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&logging_config.log_file_path)
    };
    #[cfg(not(unix))]
    let log_file_result = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&logging_config.log_file_path);

    let log_file = match log_file_result {
        Ok(file) => file,
        Err(e) => {
            emit_logging_init_message(
                settings,
                false,
                &format!(
                    "Failed to open log file: {}, continuing without file logging",
                    e
                ),
            );
            return Ok(None);
        }
    };

    // `.mode()` above only applies when the file is created; a log left behind by
    // an older build at 0644 would keep its looser mode. Tighten any existing
    // file to 0600 on reopen so a group- or world-readable log never persists.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = log_file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
            emit_logging_init_message(
                settings,
                false,
                &format!("Failed to tighten log file permissions to 0600: {e}"),
            );
        }
    }

    // Build JSON file layer that captures ALL events
    let file_writer = std::sync::Mutex::new(log_file);
    let file_layer = fmt::layer()
        .json()
        .with_writer(file_writer)
        .with_target(true)
        .with_level(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_filter(LevelFilter::TRACE); // Capture ALL events to file

    Ok(Some(file_layer))
}
