// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! SDDM's own configuration reader, `ConfigBase::loadInternal()` of
//! src/common/ConfigReader.cpp, which Plasma Login Manager kept up to 6.6.
//!
//! Each line is trimmed and cut at its first `#`, wherever it is. A line with
//! a `=` is an assignment, otherwise a line in brackets opens a section; a
//! file starts in `[General]`. An assignment replaces the value set before
//! it, in this file or an earlier one, also with an empty value.

/// The `User=` of `[Autologin]` once `texts` are read in turn, `None` when
/// it ends up empty.
pub(super) fn autologin_user<'a>(texts: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let mut user = String::new();
    for text in texts {
        let mut section = "General";
        for line in text.split('\n') {
            // Qt decodes each line on its own, dropping a byte order mark at
            // its start.
            let line = line.strip_prefix('\u{feff}').unwrap_or(line).trim();
            let line = line.split('#').next().unwrap_or_default().trim();
            if let Some((name, value)) = line.split_once('=') {
                if section == "Autologin" && name.trim() == "User" {
                    value.trim().clone_into(&mut user);
                }
            } else if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = name;
            }
        }
    }
    (!user.is_empty()).then_some(user)
}
