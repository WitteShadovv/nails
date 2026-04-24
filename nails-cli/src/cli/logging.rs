//! Logging initialization for NAILS CLI
//!
//! This module provides functions to initialize the tracing subscriber with:
//! - A stdout layer for human-readable output (filtered by verbosity level)
//! - An optional file layer for JSON-formatted logs (captures all events)
//!
//! The file layer implements graceful fallback: if the hidden volume is not mounted
//! or LoggingManager initialization fails, logging continues with stdout-only mode.

use tracing_subscriber::Layer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RenderMode {
    Human,
    NoColor,
    Plain,
}

/// Stdout formatting mode for CLI command output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdoutFormat {
    /// Human-readable tracing output written to stderr.
    Human,
    /// Newline-delimited JSON tracing events written to stdout.
    ///
    /// Used by `nails activate --json` so structured progress events are emitted
    /// during activation before the final JSON result object is printed.
    ActivateJsonStream,
}

/// Initialize tracing subscriber with stdout and optional file logging
///
/// Sets up a two-layer subscriber:
/// 1. **File layer** (JSON): Captures ALL events (TRACE+) to `{hidden_volume}/logs/nails.log`
/// 2. **Stdout layer** (fmt): Human-readable output filtered by verbosity level
///
/// Implements graceful fallback: if hidden volume is not mounted or LoggingManager
/// initialization fails, continues with stdout-only logging (no errors raised).
///
/// # Arguments
///
/// * `verbose_count` - Number of `-v` flags passed (0, 1, 2+)
///
/// # Levels (Stdout Layer)
///
/// - 0 (normal): INFO and above (ERROR, WARN, INFO)
/// - 1 (`-v`): DEBUG and above
/// - 2+ (`-vv`): TRACE and above
///
/// # File Layer
///
/// Always captures TRACE+ regardless of user verbosity (full audit trail).
///
/// # Graceful Fallback (AC: Story 9.3, Task 2.4)
///
/// If hidden volume not mounted or LoggingManager fails:
/// - Logs warning to stderr
/// - Continues with stdout-only logging
/// - Does NOT fail the command
///
/// # Parameters
///
/// - `verbose_count`: Verbosity level (0 = INFO, 1 = DEBUG, 2+ = TRACE)
/// - `quiet`: Quiet mode - only show WARN and ERROR (AC: Story 9.3, AC #5)
/// - `no_logs`: Skip file logging entirely (AC: Story 9.3, Task 2.5)
/// - `config_override`: Optional explicit config file path (from `--config` flag)
pub fn init_stdout_subscriber(
    verbose_count: u8,
    quiet: bool,
    no_logs: bool,
    config_override: Option<&std::path::Path>,
) {
    init_stdout_subscriber_with_mode(
        verbose_count,
        quiet,
        no_logs,
        false,
        false,
        config_override,
        StdoutFormat::Human,
    );
}

/// Initialize tracing subscriber with an explicit stdout formatting mode.
pub fn init_stdout_subscriber_with_mode(
    verbose_count: u8,
    quiet: bool,
    no_logs: bool,
    no_color: bool,
    plain: bool,
    config_override: Option<&std::path::Path>,
    stdout_format: StdoutFormat,
) {
    let render_mode = render_mode(no_color, plain);

    // Map CLI flags to tracing level (AC #5)
    let stdout_level = if quiet {
        LevelFilter::WARN // Quiet mode: only WARN and ERROR
    } else {
        match verbose_count {
            0 => LevelFilter::INFO,  // Normal mode: INFO, WARN, ERROR
            1 => LevelFilter::DEBUG, // Verbose mode: DEBUG + INFO + WARN + ERROR
            _ => LevelFilter::TRACE, // Debug mode: TRACE + all above
        }
    };

    // Skip file layer if --no-logs flag is set (AC: Story 9.3, Task 2.5)
    if no_logs {
        init_stdout_only_subscriber(stdout_level, stdout_format, render_mode);
        return;
    }

    // Try to initialize LoggingManager for file logging (Task 2.1)
    let file_layer_result = init_file_layer(config_override, render_mode);

    match file_layer_result {
        Ok(Some(file_layer)) => {
            let subscriber = tracing_subscriber::registry().with(file_layer);

            match stdout_format {
                StdoutFormat::Human => {
                    let stdout_layer = fmt::layer()
                        .with_target(false)
                        .with_thread_ids(false)
                        .with_thread_names(false)
                        .with_file(false)
                        .with_line_number(false)
                        .with_level(true)
                        .with_ansi(matches!(render_mode, RenderMode::Human))
                        .with_writer(std::io::stderr)
                        .with_filter(stdout_level);

                    subscriber.with(stdout_layer).init();
                }
                StdoutFormat::ActivateJsonStream => {
                    let stdout_layer = fmt::layer()
                        .json()
                        .flatten_event(true)
                        .with_current_span(false)
                        .with_span_list(false)
                        .with_target(false)
                        .with_level(true)
                        .with_ansi(false)
                        .with_writer(std::io::stdout)
                        .with_filter(stdout_level);

                    subscriber.with(stdout_layer).init();
                }
            }
        }
        Ok(None) | Err(_) => {
            // Graceful fallback: stdout-only logging (Task 2.4)
            init_stdout_only_subscriber(stdout_level, stdout_format, render_mode);
        }
    }
}

fn render_mode(no_color: bool, plain: bool) -> RenderMode {
    if plain {
        RenderMode::Plain
    } else if no_color
        || std::env::var("NO_COLOR").is_ok()
        || std::env::var(nails_core::obfuscate::env_no_color()).is_ok()
    {
        RenderMode::NoColor
    } else {
        RenderMode::Human
    }
}

fn emit_logging_init_message(render_mode: RenderMode, is_error: bool, message: &str) {
    let formatted = match (render_mode, is_error) {
        (RenderMode::Plain, true) => format!("[FAIL] {message}"),
        (RenderMode::Plain, false) => format!("[WARN] {message}"),
        (RenderMode::NoColor, true) => format!("X {message}"),
        (RenderMode::NoColor, false) => format!("! {message}"),
        (RenderMode::Human, true) => nails_core::logging::format_early_error(message),
        (RenderMode::Human, false) => nails_core::logging::format_early_warning(message),
    };

    eprintln!("{formatted}");
}

fn init_stdout_only_subscriber(
    stdout_level: LevelFilter,
    stdout_format: StdoutFormat,
    render_mode: RenderMode,
) {
    match stdout_format {
        StdoutFormat::Human => {
            tracing_subscriber::fmt()
                .with_target(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .with_level(true)
                .with_ansi(matches!(render_mode, RenderMode::Human))
                .with_writer(std::io::stderr)
                .with_max_level(stdout_level)
                .init();
        }
        StdoutFormat::ActivateJsonStream => {
            tracing_subscriber::fmt()
                .json()
                .flatten_event(true)
                .with_current_span(false)
                .with_span_list(false)
                .with_target(false)
                .with_level(true)
                .with_ansi(false)
                .with_writer(std::io::stdout)
                .with_max_level(stdout_level)
                .init();
        }
    }
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
///
/// # Implementation (Task 2.1-2.4)
///
/// - Task 2.1: Create LoggingManager with config paths
/// - Task 2.2: Call LoggingManager::init() for validation
/// - Task 2.3: Build JSON file layer that captures ALL events
/// - Task 2.4: Graceful fallback if hidden volume not mounted
#[allow(clippy::type_complexity)]
fn init_file_layer(
    config_override: Option<&std::path::Path>,
    render_mode: RenderMode,
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

    // Determine log path from config (P1-03: honor config.log_path)
    let config_path = nails_core::config::discover_config_path(config_override);
    let config = nails_core::config::Config::load_or_default(&config_path)
        .unwrap_or_else(|_| nails_core::config::Config::default());

    let log_dir = config.log_path.clone();
    let hidden_volume_path = config.hidden_volume_root.clone();

    // Create LoggingManager using configured log_path
    let logging_manager = LoggingManager::new(log_dir, hidden_volume_path);

    // Initialize LoggingManager with validation (Task 2.2)
    // Returns Ok(None) for graceful degradation (hidden volume not available)
    let fs = RealFilesystem;
    let logging_config = match logging_manager.init(&fs) {
        Ok(Some(config)) => config,
        Ok(None) => {
            // Graceful degradation: hidden volume not available (Story 14.3, AC #3)
            return Ok(None);
        }
        Err(e) => {
            emit_logging_init_message(
                render_mode,
                true,
                &format!(
                    "Logging init failed: {}, continuing with stdout-only logging",
                    e
                ),
            );
            return Ok(None);
        }
    };

    // Open log file for appending (Task 2.3)
    #[cfg(unix)]
    let log_file_result = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o644) // Owner read/write, others read
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
            if matches!(render_mode, RenderMode::Human) {
                emit_logging_init_message(
                    render_mode,
                    false,
                    &format!(
                        "Failed to open log file: {}, continuing without file logging",
                        e
                    ),
                );
            } else {
                // Plain/no-color command output should stay focused on the command payload.
                tracing::debug!(error = %e, "Failed to open log file; continuing without file logging");
            }
            return Ok(None);
        }
    };

    // Build JSON file layer that captures ALL events (Task 2.3)
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
