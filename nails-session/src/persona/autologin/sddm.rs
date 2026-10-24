// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! SDDM's own configuration reader, `ConfigBase::loadInternal()` of
//! src/common/ConfigReader.cpp, which Plasma Login Manager kept up to 6.6.
//!
//! Each line is trimmed and cut at its first `#`, wherever it is. A line with
//! a `=` is an assignment, otherwise a line in brackets opens a section; a
//! file starts in `[General]`. An assignment replaces the value set before
//! it, in this file or an earlier one, also with an empty value. A build on
//! Qt 5 decodes a line only up to its first NUL, one on Qt 6 the whole line.

/// The Qt a build of the reader runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Qt {
    Five,
    Six,
}

/// Each value `text` assigns to `User` in `[Autologin]`, in order.
fn assignments(text: &str, qt: Qt) -> impl Iterator<Item = &str> {
    let mut section = "General";
    text.split('\n').filter_map(move |line| {
        let line = match qt {
            Qt::Five => line.split('\0').next().unwrap_or_default(),
            Qt::Six => line,
        };
        // Qt decodes each line on its own, dropping a byte order mark at its
        // start.
        let line = line.strip_prefix('\u{feff}').unwrap_or(line).trim();
        let line = line.split('#').next().unwrap_or_default().trim();
        if let Some((name, value)) = line.split_once('=') {
            (section == "Autologin" && name.trim() == "User").then(|| value.trim())
        } else {
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = name;
            }
            None
        }
    })
}

/// The `User=` of `[Autologin]` once `texts` are read in turn, `None` when
/// it ends up empty.
pub(super) fn autologin_user<'a>(
    texts: impl IntoIterator<Item = &'a str>,
    qt: Qt,
) -> Option<String> {
    let mut user = "";
    for text in texts {
        if let Some(last) = assignments(text, qt).last() {
            user = last;
        }
    }
    (!user.is_empty()).then(|| user.to_string())
}
