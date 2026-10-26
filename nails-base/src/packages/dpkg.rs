// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! dpkg's record of every package (Debian, Ubuntu).
//!
//! `/var/lib/dpkg/status` holds one stanza per package dpkg knows, stanzas
//! apart by an empty line, each a list of `Field: value` lines whose value may
//! go on over lines that start with white space. [`parse_status`] reads them
//! the way dpkg's `parse_stanza()` (lib/dpkg/parse.c) splits them: a stanza
//! ends only at a line with nothing on it (a line of spaces, or the `\r` a
//! CRLF file leaves, continues the field before it), a field's name ends at
//! white space or the colon, and names compare without regard to case. The
//! MS-DOS end-of-file byte, Ctrl+Z, which dpkg also takes for the end of a
//! line, is read as any other character here.
//!
//! Of each stanza it keeps the package's name, architecture, version and
//! state. dpkg refuses a whole status file with a stanza it cannot parse;
//! here such a stanza is left out and the others are read: one whose line has
//! no colon after the field's name, one that sets one of these four fields
//! twice, one that carries a value of these fields over to a line with more
//! than white space on it, and one without a `Package`. The `dpkg_status` fuzz
//! target compares the reading with a model of `parse_stanza()`.

use crate::{Filesystem, Result};
use std::path::Path;

/// dpkg's record of every package, relative to the root.
pub const STATUS: &str = "var/lib/dpkg/status";

/// dpkg's directory of each package's own files (`<name>.list`,
/// `<name>.md5sums`, its maintainer scripts), relative to the root.
pub const INFO: &str = "var/lib/dpkg/info";

/// The state of a package, the last word of its `Status` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum State {
    /// `not-installed`.
    NotInstalled,
    /// `config-files`: removed, its configuration files kept.
    ConfigFiles,
    /// `half-installed`: an installation or a removal stopped half way.
    HalfInstalled,
    /// `unpacked`.
    Unpacked,
    /// `half-configured`.
    HalfConfigured,
    /// `triggers-awaited`.
    TriggersAwaited,
    /// `triggers-pending`.
    TriggersPending,
    /// `installed`.
    Installed,
}

impl State {
    /// Every state with the word dpkg writes for it.
    pub const ALL: [(State, &'static str); 8] = [
        (State::NotInstalled, "not-installed"),
        (State::ConfigFiles, "config-files"),
        (State::HalfInstalled, "half-installed"),
        (State::Unpacked, "unpacked"),
        (State::HalfConfigured, "half-configured"),
        (State::TriggersAwaited, "triggers-awaited"),
        (State::TriggersPending, "triggers-pending"),
        (State::Installed, "installed"),
    ];

    /// The state dpkg writes as `word`.
    pub fn parse(word: &str) -> Option<State> {
        Self::ALL
            .iter()
            .find(|(_, name)| *name == word)
            .map(|(state, _)| *state)
    }

    /// The word dpkg writes for this state.
    pub fn as_str(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(state, _)| *state == self)
            .map_or("", |(_, name)| name)
    }

    /// Whether the package's files are on disk in this state: from
    /// `unpacked` on. A package half installed or half removed is not
    /// counted, nor one removed with its configuration files kept.
    pub fn files_present(self) -> bool {
        self >= State::Unpacked
    }
}

/// One package dpkg's status file records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// `Package`, the package's name.
    pub name: String,
    /// `Architecture`, when the stanza has one.
    pub architecture: Option<String>,
    /// `Version`, when the stanza has one.
    pub version: Option<String>,
    /// The state the last word of `Status` names, when it names one.
    pub state: Option<State>,
}

impl Package {
    /// Whether the package's files are on disk ([`State::files_present`]).
    pub fn files_present(&self) -> bool {
        self.state.is_some_and(State::files_present)
    }
}

/// The fields of a stanza that are kept, in the order [`Stanza::fields`]
/// holds them.
const FIELDS: [&str; 4] = ["Package", "Architecture", "Version", "Status"];

/// Whether `c` is white space to dpkg (`c_isspace()`): a space, a tab, a
/// newline, a vertical tab, a form feed or a carriage return.
fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r')
}

/// The stanza being read.
#[derive(Default)]
struct Stanza<'a> {
    /// The values of [`FIELDS`] it sets.
    fields: [Option<&'a str>; 4],
    /// The field of [`FIELDS`] the last line set, which a line that starts
    /// with white space would carry over.
    last: Option<usize>,
    /// Whether dpkg would refuse it.
    broken: bool,
}

impl<'a> Stanza<'a> {
    /// Read one line of the stanza, a line that is not empty.
    fn line(&mut self, line: &'a str) {
        if line.starts_with(is_space) {
            // A continuation of the field before it. Only white space adds
            // nothing to the value dpkg keeps, which it trims.
            self.broken |= self.last.is_some() && !line.trim_matches(is_space).is_empty();
            return;
        }
        self.last = None;
        let name_end = line.find(|c| is_space(c) || c == ':').unwrap_or(line.len());
        let (name, rest) = line.split_at(name_end);
        let Some(value) = rest.trim_start_matches(is_space).strip_prefix(':') else {
            // No colon after the name, or no name before it.
            self.broken = true;
            return;
        };
        if name.is_empty() {
            self.broken = true;
            return;
        }
        let Some(index) = FIELDS
            .iter()
            .position(|field| field.eq_ignore_ascii_case(name))
        else {
            return;
        };
        let slot = &mut self.fields[index];
        self.broken |= slot.is_some();
        *slot = Some(value.trim_matches(is_space));
        self.last = Some(index);
    }

    /// The package the stanza records, unless dpkg would refuse it or it
    /// names none.
    fn finish(self) -> Option<Package> {
        let [name, architecture, version, status] = self.fields;
        let name = name.filter(|name| !name.is_empty() && !self.broken)?;
        let present = |value: Option<&str>| value.filter(|v| !v.is_empty()).map(str::to_string);
        Some(Package {
            name: name.to_string(),
            architecture: present(architecture),
            version: present(version),
            state: status
                .and_then(|status| status.split(is_space).rfind(|word| !word.is_empty()))
                .and_then(State::parse),
        })
    }
}

/// The packages dpkg's status file `text` records, in its order (see the
/// [module docs](self)).
pub fn parse_status(text: &str) -> Vec<Package> {
    let mut packages = Vec::new();
    let mut stanza = Stanza::default();
    for line in text.split('\n') {
        if line.is_empty() {
            packages.extend(std::mem::take(&mut stanza).finish());
        } else {
            stanza.line(line);
        }
    }
    packages.extend(stanza.finish());
    packages
}

/// The package an entry of dpkg's `info` directory belongs to, and its
/// architecture when the name carries one: `<name>.<what>`, or
/// `<name>:<arch>.<what>` for a package of which several architectures can
/// be installed together. `None` for a name of neither form, such as the
/// directory's own `format`.
pub fn info_owner(file_name: &str) -> Option<(&str, Option<&str>)> {
    let (owner, what) = file_name.rsplit_once('.')?;
    if what.is_empty() {
        return None;
    }
    match owner.split_once(':') {
        None if !owner.is_empty() => Some((owner, None)),
        Some((name, arch)) if !name.is_empty() && !arch.is_empty() && !arch.contains(':') => {
            Some((name, Some(arch)))
        }
        _ => None,
    }
}

/// The packages dpkg's status file below `root` records ([`read_status_file`]
/// of its [`STATUS`]).
pub fn read_status<F: Filesystem>(fs: &F, root: &Path) -> Result<Option<Vec<Package>>> {
    read_status_file(fs, &root.join(STATUS))
}

/// The packages the dpkg status file at `path` records, read through `fs`
/// (see the [parent module](super) on access times): `None` when there is no
/// such file. A file larger than [`READ_LIMIT`](super::READ_LIMIT) is an
/// error, and bytes that are not UTF-8 are read as U+FFFD.
pub fn read_status_file<F: Filesystem>(fs: &F, path: &Path) -> Result<Option<Vec<Package>>> {
    let status = super::read_limited(fs, path)?;
    Ok(status.map(|bytes| parse_status(&String::from_utf8_lossy(&bytes))))
}
