// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The unit a timer, path or socket unit starts, its `Unit=` or `Service=`
//! read with the specifiers systemd expands there.
//!
//! systemd expands them with `unit_name_printf()` (src/core/unit-printf.c,
//! alike in systemd 255 to 261), from the trigger's id, the name of its unit
//! file with the trigger's instance (`gpg-agent-ssh@etc-pacman.d-gnupg.socket`
//! for that instance of `gpg-agent-ssh@.socket`):
//!
//! - `%n` is the id, `%N` the id without its type, `%p` its prefix (the part
//!   before the first `@`, or before the type), `%i` its instance (nothing
//!   for a name without one), `%j` the part of the prefix after its last dash
//!   (the whole prefix without one), and `%%` a `%`;
//! - `%a`, `%A`, `%b`, `%B`, `%H`, `%l`, `%q`, `%m`, `%M`, `%o`, `%v`, `%w`,
//!   `%W`, `%g`, `%G`, `%u` and `%U` are the host's architecture, release
//!   fields, boot and machine ID, host names, kernel and the manager's user
//!   and group, which NAILS does not take from the decoy: each stands for any
//!   text, so the trigger may start every unit whose name the text around
//!   them fits;
//! - any other letter or digit after a `%`, `%P`, `%I`, `%J` and `%f` among
//!   them, which systemd expands in a unit's commands but not in a unit
//!   name, makes systemd ignore the assignment ("Failed to resolve unit
//!   specifiers"), as it does one that gives more than 256 bytes;
//! - a `%` before any other character, or at the end, stays as written.
//!
//! A timer or a path starts the first `Unit=` systemd takes: one that
//! expands to a valid name of a unit that is no template and not the
//! trigger itself, as `config_parse_trigger_unit()` takes it; a socket the
//! last `Service=` that expands to such a name of a service, as
//! `config_parse_socket_service()` sets it, unless it is `Accept=yes`, which
//! starts instances of a template instead. Without one, each starts the
//! service of its id. Where a value with a host's specifier comes first, the
//! trigger may start what that value gives as well as what systemd takes
//! after it.

use super::super::systemd_conf::Assignment;

/// The specifiers systemd fills in from the host in a unit name.
const HOST_SPECIFIERS: &str = "aAbBHlqmMovwWgGuU";

/// The most bytes systemd lets an expansion give.
const NAME_MAX: usize = 256;

/// The unit types systemd knows, by their suffix.
const TYPES: &[&str] = &[
    "service",
    "socket",
    "target",
    "device",
    "mount",
    "automount",
    "swap",
    "timer",
    "path",
    "slice",
    "scope",
];

/// One part of an expanded name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    /// Text as it stands.
    Text(String),
    /// Any text: a specifier the host fills in.
    Any,
}

/// A name a trigger may start: what one value gives, in parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::preflight::checks) struct Target {
    pieces: Vec<Piece>,
    /// The value as the unit file writes it.
    pub(in crate::preflight::checks) written: String,
}

/// What systemd makes of one value.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Expanded {
    /// It ignores the assignment.
    Ignored,
    /// The value gives this name.
    Name(String),
    /// The value gives a name with text the host fills in.
    Host(Target),
}

impl Target {
    /// The target that is the name `name`.
    fn named(name: String) -> Self {
        Self {
            pieces: vec![Piece::Text(name.clone())],
            written: name,
        }
    }

    /// The name, where no part of it is the host's.
    pub(in crate::preflight::checks) fn name(&self) -> Option<&str> {
        match self.pieces.as_slice() {
            [Piece::Text(name)] => Some(name),
            _ => None,
        }
    }

    /// Whether some text in place of the host's parts gives `name`.
    pub(in crate::preflight::checks) fn fits(&self, name: &str) -> bool {
        meets(
            &tokens(&self.pieces),
            &tokens(&[Piece::Text(name.to_string())]),
        )
    }

    /// Whether some text in place of the host's parts gives an instance of
    /// the template `template` (`foo@.service`), or `template` itself.
    pub(in crate::preflight::checks) fn fits_template(&self, template: &str) -> bool {
        let Some((prefix, kind)) = template.split_once("@.") else {
            return self.fits(template);
        };
        let instances = [
            Piece::Text(format!("{prefix}@")),
            Piece::Any,
            Piece::Text(format!(".{kind}")),
        ];
        meets(&tokens(&self.pieces), &tokens(&instances))
    }
}

/// A character of a pattern, or any text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token {
    Char(char),
    Any,
}

/// The tokens of `pieces`.
fn tokens(pieces: &[Piece]) -> Vec<Token> {
    let mut out = Vec::new();
    for piece in pieces {
        match piece {
            Piece::Text(text) => out.extend(text.chars().map(Token::Char)),
            Piece::Any => out.push(Token::Any),
        }
    }
    out
}

/// Whether some text both `a` and `b` give.
fn meets(a: &[Token], b: &[Token]) -> bool {
    // seen[i][j]: a[i..] and b[j..] were found to share no text.
    let mut seen = vec![vec![false; b.len() + 1]; a.len() + 1];
    let mut stack = vec![(0, 0)];
    while let Some((i, j)) = stack.pop() {
        if seen[i][j] {
            continue;
        }
        seen[i][j] = true;
        if i == a.len() && j == b.len() {
            return true;
        }
        match (a.get(i), b.get(j)) {
            (Some(Token::Any), other) => {
                stack.push((i + 1, j));
                if other.is_some() {
                    stack.push((i, j + 1));
                }
            }
            (other, Some(Token::Any)) => {
                stack.push((i, j + 1));
                if other.is_some() {
                    stack.push((i + 1, j));
                }
            }
            (Some(Token::Char(x)), Some(Token::Char(y))) if x == y => stack.push((i + 1, j + 1)),
            _ => {}
        }
    }
    false
}

/// What systemd makes of `value` for the unit with the id `id` (see the
/// [module docs](self)).
fn expand(value: &str, id: &str) -> Expanded {
    let stem = id.rsplit_once('.').map_or(id, |(stem, _)| stem);
    let (prefix, instance) = stem.split_once('@').unwrap_or((stem, ""));
    let last = prefix.rsplit_once('-').map_or(prefix, |(_, last)| last);
    let mut pieces = Vec::new();
    let mut text = String::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            text.push(c);
            continue;
        }
        match chars.next() {
            None => text.push('%'),
            Some('%') => text.push('%'),
            Some('n') => text.push_str(id),
            Some('N') => text.push_str(stem),
            Some('p') => text.push_str(prefix),
            Some('i') => text.push_str(instance),
            Some('j') => text.push_str(last),
            Some(c) if HOST_SPECIFIERS.contains(c) => {
                if !text.is_empty() {
                    pieces.push(Piece::Text(std::mem::take(&mut text)));
                }
                pieces.push(Piece::Any);
            }
            Some(c) if c.is_ascii_alphanumeric() => return Expanded::Ignored,
            Some(c) => {
                text.push('%');
                text.push(c);
            }
        }
    }
    if pieces.is_empty() {
        return if text.len() > NAME_MAX {
            Expanded::Ignored
        } else {
            Expanded::Name(text)
        };
    }
    if !text.is_empty() {
        pieces.push(Piece::Text(text));
    }
    Expanded::Host(Target {
        pieces,
        written: value.to_string(),
    })
}

/// Whether systemd loads a unit by `name`: a valid name of a known type that
/// is no template (`unit_name_is_valid()` with `UNIT_NAME_PLAIN` and
/// `UNIT_NAME_INSTANCE`, as `manager_load_unit()` asks).
fn loadable(name: &str) -> bool {
    let Some((stem, kind)) = name.rsplit_once('.') else {
        return false;
    };
    let valid = |c: char| c.is_ascii_alphanumeric() || ":-_.\\@".contains(c);
    name.len() < NAME_MAX
        && !stem.is_empty()
        && TYPES.contains(&kind)
        && stem.chars().all(valid)
        && match stem.split_once('@') {
            Some((prefix, instance)) => !prefix.is_empty() && !instance.is_empty(),
            None => true,
        }
}

/// The service of the trigger's own id.
fn own_service(id: &str) -> Target {
    let stem = id.rsplit_once('.').map_or(id, |(stem, _)| stem);
    Target::named(format!("{stem}.service"))
}

/// The values of `key` in `assignments`, in order.
fn values<'a>(
    assignments: &'a [Assignment],
    key: &'a str,
) -> impl DoubleEndedIterator<Item = &'a str> {
    assignments
        .iter()
        .filter(move |assignment| assignment.key == key)
        .map(|assignment| assignment.value.as_str())
}

/// What a timer or a path unit with the id `id`, found as `name`, whose
/// `[Timer]` or `[Path]` section is `assignments`, may start (see the
/// [module docs](self)): one name, or every name it may start.
pub(in crate::preflight::checks) fn timer_targets(
    assignments: &[Assignment],
    id: &str,
    name: &str,
) -> Vec<Target> {
    let mut out = Vec::new();
    for value in values(assignments, "Unit") {
        match expand(value, id) {
            Expanded::Ignored => {}
            Expanded::Name(unit) => {
                if loadable(&unit) && unit != id && unit != name {
                    out.push(Target::named(unit));
                    return out;
                }
            }
            Expanded::Host(target) => out.push(target),
        }
    }
    out.push(own_service(id));
    out
}

/// What a socket unit with the id `id`, whose `[Socket]` section is
/// `assignments`, may start (see the [module docs](self)): one service, or
/// every service it may start, none for one that starts instances of a
/// template.
pub(in crate::preflight::checks) fn socket_targets(
    assignments: &[Assignment],
    id: &str,
) -> Vec<Target> {
    // systemd ignores a value it cannot read as a boolean.
    let accept = values(assignments, "Accept").rev().find_map(|value| {
        let value = value.to_ascii_lowercase();
        if ["1", "yes", "y", "true", "t", "on"].contains(&value.as_str()) {
            Some(true)
        } else if ["0", "no", "n", "false", "f", "off"].contains(&value.as_str()) {
            Some(false)
        } else {
            None
        }
    });
    if accept == Some(true) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for value in values(assignments, "Service").rev() {
        match expand(value, id) {
            Expanded::Ignored => {}
            Expanded::Name(service) => {
                if service.ends_with(".service") && loadable(&service) {
                    out.push(Target::named(service));
                    return out;
                }
            }
            Expanded::Host(target) => out.push(target),
        }
    }
    out.push(own_service(id));
    out
}

#[cfg(test)]
#[path = "targets_tests.rs"]
mod tests;
