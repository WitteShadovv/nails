// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where the window may open.
//!
//! In the hidden session everything the window writes lands on the hidden
//! volume, so it always opens there. On the decoy it would run a toolkit
//! beside the decoy's own desktop, a larger trace surface than the CLI, so it
//! opens only where two conditions hold:
//!
//! - the decoy keeps no persistent record (a volatile journal, no syslog or
//!   audit daemon): the findings of the activation pre-flight's
//!   decoy-persistence check, read without writing anything;
//! - the desktop is one whose disk, journal and D-Bus trace test has passed
//!   ([`ADMITTED_DESKTOPS`]), named by `XDG_CURRENT_DESKTOP`.
//!
//! A refusal names every reason, the desktop included, and the command that
//! works instead. It comes before the window's program starts, so nothing
//! has connected to a session bus or the accessibility bus.

use std::path::Path;

use nails_core::preflight::DecoyPersistenceCheck;
use nails_core::session::SessionView;
use nails_core::{NailsManager, RealFilesystem, RuntimeEnv};

use super::Refusal;
use crate::cli::output::ExitStatus;

/// The desktops whose trace test has passed on the decoy, as
/// `XDG_CURRENT_DESKTOP` names them. None has yet: until one does, the window
/// opens only in the hidden session.
///
/// That test has to clear what the window does at every start that its
/// environment cannot turn off, which is all on the session bus: its toolkit
/// starts no program (its winit backend draws no window decorations, see
/// `gui/Cargo.toml`), and its command line names no path.
///
/// - AccessKit, the screen reader's way in, asks the accessibility bus
///   whether a screen reader listens (`GetAll` of `org.a11y.Status` on
///   `org.a11y.Bus`, and a `PropertiesChanged` subscription). Where at-spi's
///   bus launcher does not run, that starts it through D-Bus activation, and
///   dbus-daemon logs a line that names the window's command line, `session`.
/// - Slint's winit backend reads the desktop's appearance from the settings
///   portal (`ReadOne`, or `Read` on an older portal, of
///   `org.freedesktop.portal.Settings` for the colour scheme, the accent
///   colour, the font and the cursor blink, and a `SettingChanged`
///   subscription). Its reads carry `NO_AUTO_START`: where
///   xdg-desktop-portal does not run they are refused, and nothing starts.
pub(super) const ADMITTED_DESKTOPS: &[&str] = &[];

/// What the gate knows about a decoy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DecoyFacts {
    /// Each persistent record the decoy keeps, with its fix.
    pub(super) persistence: Vec<String>,
    /// `XDG_CURRENT_DESKTOP`, when set.
    pub(super) desktop: Option<String>,
}

/// Let the window open, or refuse with every reason it does not.
pub(super) fn admit(env: &RuntimeEnv, config: Option<&Path>, engine: &Path) -> Result<(), Refusal> {
    if decoy_gate_waived(env) {
        return Ok(());
    }
    if in_hidden_session(env, config) {
        return Ok(());
    }
    let facts = DecoyFacts {
        persistence: DecoyPersistenceCheck::persistence_findings(&RealFilesystem),
        desktop: env
            .inherited
            .iter()
            .find(|(key, _)| *key == "XDG_CURRENT_DESKTOP")
            .map(|(_, value)| value.to_string_lossy().into_owned()),
    };
    decide_on_decoy(&facts, ADMITTED_DESKTOPS, engine)
}

/// Whether this machine is in the hidden session, from the live mount table
/// and the session plan (never from the state file alone).
fn in_hidden_session(env: &RuntimeEnv, config: Option<&Path>) -> bool {
    let config = nails_core::app::config::load_config_or_defaults(config).into_config();
    let state_path = config.state_file_path.clone();
    let manager =
        NailsManager::new(RealFilesystem, config, state_path).with_runtime_env(env.clone());
    matches!(
        manager.session_view(),
        SessionView::Hidden(_) | SessionView::HiddenWithoutPlan(_)
    )
}

/// A test build may waive the decoy gate, which no test host passes.
#[cfg(feature = "test-hooks")]
fn decoy_gate_waived(env: &RuntimeEnv) -> bool {
    env.test_hooks.admit_window.is_some()
}

#[cfg(not(feature = "test-hooks"))]
#[inline]
fn decoy_gate_waived(_env: &RuntimeEnv) -> bool {
    false
}

/// The gate on a decoy with `facts`, where the `admitted` desktops passed
/// their trace test. `engine` names the command that works instead.
pub(super) fn decide_on_decoy(
    facts: &DecoyFacts,
    admitted: &[&str],
    engine: &Path,
) -> Result<(), Refusal> {
    let desktop_admitted = facts
        .desktop
        .as_deref()
        .is_some_and(|desktop| desktop_is_admitted(desktop, admitted));
    if facts.persistence.is_empty() && desktop_admitted {
        return Ok(());
    }
    let binary = nails_core::next_step::shell_word(engine.as_os_str());
    let mut lines = Vec::new();
    if !facts.persistence.is_empty() {
        lines.push(
            "This decoy keeps a record on its disk, so the window does not open here:".to_string(),
        );
        lines.extend(
            facts
                .persistence
                .iter()
                .map(|finding| format!("- {finding}")),
        );
    }
    if !desktop_admitted {
        lines.push(format!(
            "The window has not been tested on this desktop ({}) yet, so it does not open here. \
             On the decoy it opens only on a desktop whose disk, journal and D-Bus trace test \
             has passed.",
            desktop_name(facts.desktop.as_deref())
        ));
    }
    let (status, code) = if facts.persistence.is_empty() {
        (ExitStatus::Unsupported, "desktop_untested")
    } else {
        lines.push(format!(
            "Fix this first: sudo {binary} check lists every finding."
        ));
        (ExitStatus::PreflightRefused, "decoy_persistent")
    };
    lines.push(format!("Use: sudo {binary} activate"));
    Err(Refusal::new(status, code, lines.join("\n")))
}

/// Whether `desktop`, a colon-separated `XDG_CURRENT_DESKTOP` list
/// (`ubuntu:GNOME`), names an admitted desktop.
fn desktop_is_admitted(desktop: &str, admitted: &[&str]) -> bool {
    desktop
        .split(':')
        .any(|name| admitted.iter().any(|ok| ok.eq_ignore_ascii_case(name)))
}

/// The desktop as the refusal names it: its printable characters only.
fn desktop_name(desktop: Option<&str>) -> String {
    match desktop {
        Some(desktop) if !desktop.trim().is_empty() => desktop
            .chars()
            .map(|c| if c.is_ascii_graphic() { c } else { '?' })
            .take(64)
            .collect(),
        _ => "XDG_CURRENT_DESKTOP is not set".to_string(),
    }
}
