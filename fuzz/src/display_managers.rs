// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Which account a display manager logs in automatically, from the files it
//! reads, each model written from the display manager's source:
//!
//! - GDM: `get_automatic_login_details()` (daemon/gdm-manager.c) over
//!   `gdm_settings_direct_get_boolean()`, `gdm_settings_direct_get_string()`
//!   (common/gdm-settings-direct.c), `gdm_settings_parse_value_as_boolean()`
//!   (common/gdm-settings-utils.c) and the key file of
//!   common/gdm-settings-desktop-backend.c, which keeps what GLib read before
//!   a line it refuses.
//! - LightDM: `config_load_from_standard_locations()`,
//!   `load_config_directory()` and `config_load_from_file()`
//!   (common/configuration.c), `get_config_sections()` and
//!   `set_seat_properties()` (src/lightdm.c) and `seat_real_start()`
//!   (src/seat.c), for the seat `seat0`.
//! - SDDM, and Plasma Login Manager up to 6.6: `ConfigBase::load()` and
//!   `ConfigBase::loadInternal()` (src/common/ConfigReader.cpp) with
//!   `Display::Display()` (src/daemon/Display.cpp). A text with a NUL is
//!   undecided: a build on Qt 5 cuts the line there, one on Qt 6 does not.
//!
//! Each takes the texts of the files that exist, in the order the display
//! manager reads them; `None` stands for undecided.

use crate::gkeyfile::{self, KeyFile, Load};

/// GDM's verdict on its key file: whether autologin is turned on, and the
/// account named, as GDM reads it (empty when none is).
pub fn gdm(text: &str) -> Option<(bool, String)> {
    let file = match gkeyfile::load(text) {
        Load::Undecided => return None,
        // The backend keeps what GLib read, whether the load failed or not.
        Load::Loaded { file, .. } => file,
    };
    // gdm_settings_direct_get_boolean(): the schema's default, false, when
    // the key is missing; a value that is no boolean fails the call, and
    // get_automatic_login_details() then logs nobody in.
    let enabled = match file.value("daemon", "AutomaticLoginEnable") {
        None => false,
        Some(value) => parse_value_as_boolean(value).unwrap_or(false),
    };
    // gdm_settings_direct_get_string(): the schema's default is empty.
    let user = file
        .value("daemon", "AutomaticLogin")
        .unwrap_or_default()
        .to_string();
    Some((enabled, user))
}

/// `gdm_settings_parse_value_as_boolean()`.
fn parse_value_as_boolean(value: &str) -> Option<bool> {
    if value.eq_ignore_ascii_case("true") || value == "1" {
        Some(true)
    } else if value.eq_ignore_ascii_case("false") || value == "0" {
        Some(false)
    } else {
        None
    }
}

/// LightDM's `autologin-user` on `seat0`, as `seat_real_start()` takes it:
/// `Some(None)` when it logs nobody in. `drop_ins` are the `*.conf` files of
/// its directories in reading order, `main` is `lightdm.conf` when it exists.
pub fn lightdm(drop_ins: &[&str], main: Option<&str>) -> Option<Option<String>> {
    let mut config = KeyFile::default();
    for text in drop_ins {
        match gkeyfile::load(text) {
            Load::Undecided => return None,
            // load_config_directory() reports the error and goes on.
            Load::Loaded { failed: true, .. } => {}
            Load::Loaded { file, .. } => config_load_from_file(&mut config, &file),
        }
    }
    if let Some(text) = main {
        match gkeyfile::load(text) {
            Load::Undecided => return None,
            // config_load_from_standard_locations() fails and LightDM exits.
            Load::Loaded { failed: true, .. } => return Some(None),
            Load::Loaded { file, .. } => config_load_from_file(&mut config, &file),
        }
    }
    // get_config_sections(): "Seat:*" first, then each group of a matching
    // seat pattern in group order; set_seat_properties() sets every key of
    // each, so the last section with the key wins.
    let mut sections = vec!["Seat:*".to_string()];
    for (group, _) in &config.groups {
        if let Some(pattern) = group.strip_prefix("Seat:")
            && group != "Seat:*"
            && pattern_match_simple(pattern, "seat0")
        {
            sections.push(group.clone());
        }
    }
    let mut property: Option<Option<String>> = None;
    for section in &sections {
        if let Some((_, keys)) = config.groups.iter().find(|(g, _)| g == section) {
            for (key, raw) in keys {
                if key == "autologin-user" {
                    // config_get_string(): g_key_file_get_string().
                    property = Some(gkeyfile::parse_value_as_string(raw));
                }
            }
        }
    }
    // seat_real_start(): an empty name is none.
    Some(match property {
        Some(Some(name)) if !name.is_empty() => Some(name),
        _ => None,
    })
}

/// `config_load_from_file()`: every key of every group, `[SeatDefaults]`
/// moved into `[Seat:*]`, set over what came before.
fn config_load_from_file(config: &mut KeyFile, file: &KeyFile) {
    for (group, keys) in &file.groups {
        let group = if group == "SeatDefaults" {
            "Seat:*"
        } else {
            group.as_str()
        };
        for (key, value) in keys {
            config.set_value(group, key, value);
        }
    }
}

/// `g_pattern_match_simple()`: `*` matches any run of characters, `?` any
/// one.
fn pattern_match_simple(pattern: &str, string: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let string: Vec<char> = string.chars().collect();
    // matches[i][j]: pattern[i..] matches string[j..].
    let mut matches = vec![vec![false; string.len() + 1]; pattern.len() + 1];
    matches[pattern.len()][string.len()] = true;
    for i in (0..pattern.len()).rev() {
        for j in (0..=string.len()).rev() {
            matches[i][j] = match pattern[i] {
                '*' => matches[i + 1][j] || (j < string.len() && matches[i][j + 1]),
                '?' => j < string.len() && matches[i + 1][j + 1],
                c => j < string.len() && string[j] == c && matches[i + 1][j + 1],
            };
        }
    }
    matches[0][0]
}

/// `QChar::isSpace()`: the separators (Zs, Zl, Zp) and the controls tab to
/// carriage return and next line.
fn qt_is_space(c: char) -> bool {
    matches!(
        c,
        ' ' | '\t'
            | '\n'
            | '\u{0b}'
            | '\u{0c}'
            | '\r'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
    )
}

/// `QStringView::trimmed()`.
fn qt_trimmed(s: &str) -> &str {
    s.trim_matches(qt_is_space)
}

/// The `[Autologin] User` SDDM's `ConfigBase` holds once it has read
/// `texts` in order (`ConfigBase::load()`), empty when none sets it.
pub fn sddm_user(texts: &[&str]) -> Option<String> {
    if texts.iter().any(|text| text.contains('\0')) {
        return None;
    }
    let mut user = String::new();
    for text in texts {
        // loadInternal()
        let mut current_section = "General".to_string();
        for raw in text.split_inclusive('\n') {
            // QString::fromUtf8(in.readLine()) drops a byte order mark that
            // opens the line.
            let line = raw.strip_prefix('\u{feff}').unwrap_or(raw);
            let mut line_ref = qt_trimmed(line);
            if let Some(hash) = line_ref.find('#') {
                line_ref = qt_trimmed(&line_ref[..hash]);
            }
            if current_section == "XDisplay" {
                current_section = "X11".to_string();
            } else if current_section == "WaylandDisplay" {
                current_section = "Wayland".to_string();
            }
            if let Some(separator) = line_ref.find('=') {
                let name = qt_trimmed(&line_ref[..separator]);
                let value = qt_trimmed(&line_ref[separator + 1..]);
                if current_section == "Autologin" && name == "User" {
                    // ConfigEntry<QString>::setValue() trims.
                    user = qt_trimmed(value).to_string();
                }
            } else if line_ref.starts_with('[') && line_ref.ends_with(']') {
                current_section = line_ref[1..line_ref.len() - 1].to_string();
            }
        }
    }
    Some(user)
}
