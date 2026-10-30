// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The keys of `nails.toml` a value can be set for, and what each takes: the
//! table a window builds its settings controls from, so that it offers each
//! key the control the engine reads a value of it with.
//!
//! The engine's own table is `nails_base::config::edit::SETTINGS`, which reads
//! and checks every value; a test there keeps this one equal to it, key for
//! key and kind for kind, so the two cannot drift apart. A window still sends
//! every change through the engine's plan, which decides.

/// What a setting holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `true` or `false`.
    Bool,
    /// A whole number from 0 to `i64::MAX`.
    Integer,
    /// A path.
    Path,
    /// A string, such as a flake reference.
    Text,
    /// One of a fixed set of strings.
    Choice(&'static [&'static str]),
    /// A list of entry names, or `*`.
    Names,
}

/// A key of `nails.toml` and what it takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setting {
    /// The key as docs/configuration.md writes it: `persona.mode` is the
    /// `mode` key of the `[persona]` table.
    pub key: &'static str,
    /// What it holds.
    pub kind: Kind,
}

/// Every key a value can be set for, in the order of the reference's key
/// table.
pub const SETTINGS: &[Setting] = &[
    Setting {
        key: "hidden_volume_root",
        kind: Kind::Path,
    },
    Setting {
        key: "state_file_path",
        kind: Kind::Path,
    },
    Setting {
        key: "log_path",
        kind: Kind::Path,
    },
    Setting {
        key: "minimum_space_mb",
        kind: Kind::Integer,
    },
    Setting {
        key: "rebuild_space_mb",
        kind: Kind::Integer,
    },
    Setting {
        key: "show_opsec_reminders",
        kind: Kind::Bool,
    },
    Setting {
        key: "nixos_flake",
        kind: Kind::Text,
    },
    Setting {
        key: "persona.mask_inherited",
        kind: Kind::Names,
    },
    Setting {
        key: "persona.mode",
        kind: Kind::Choice(&["shared-home", "fresh-home"]),
    },
    Setting {
        key: "backend_watch.auto_emergency",
        kind: Kind::Bool,
    },
    Setting {
        key: "backend_watch.debounce_secs",
        kind: Kind::Integer,
    },
    Setting {
        key: "backend_watch.enabled",
        kind: Kind::Bool,
    },
    Setting {
        key: "backend_watch.poll_interval_secs",
        kind: Kind::Integer,
    },
    Setting {
        key: "session_mounts.alert",
        kind: Kind::Bool,
    },
    Setting {
        key: "session_mounts.read_only",
        kind: Kind::Bool,
    },
    Setting {
        key: "sleep_policy.mode",
        kind: Kind::Choice(&["warn", "block", "teardown"]),
    },
];

/// The keys a hidden session's own record names: while a session runs, is
/// entering or was left behind, the engine writes a change to them only when
/// it points them back where the session recorded them.
pub const SESSION_KEYS: &[&str] = &["hidden_volume_root", "state_file_path"];

/// The setting `key` names, if it is one.
#[must_use]
pub fn setting(key: &str) -> Option<&'static Setting> {
    SETTINGS.iter().find(|setting| setting.key == key)
}
