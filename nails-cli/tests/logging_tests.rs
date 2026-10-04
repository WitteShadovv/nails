// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for the public CLI logging and output-settings surface
//!
//! Subscriber behaviour (levels, ANSI, file layer) is exercised in subprocess
//! unit tests next to the module, since a global subscriber can only be
//! installed once per process.

use nails::cli::logging::StdoutFormat;
use nails::cli::output::OutputSettings;

/// The subscriber entry point takes the resolved settings, not loose flags.
#[test]
fn init_subscriber_takes_resolved_output_settings() {
    let _: fn(&OutputSettings, bool, Option<&std::path::Path>, StdoutFormat) =
        nails::cli::logging::init_subscriber;
}

#[test]
fn stdout_format_variants_are_distinct() {
    assert_ne!(StdoutFormat::Human, StdoutFormat::ActivateJsonStream);
}
