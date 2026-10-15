// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Matching hidden-environment markers in the text of a `.nix` file.
//!
//! The scan works on bytes of ASCII-lowercased text, one line at a time, so a
//! match maps back to a line and to the original spelling by offset. Every
//! marker counts in comments as well: an examiner reads them, and a
//! commented-out line that names the hidden volume points at it as plainly as
//! a live one. The device-mapper name, often an ordinary word such as `data`,
//! counts only where it names the mapping ([`Pattern::Name`]).

use std::ops::Range;

/// How a marker is matched in a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Pattern {
    /// Plain text anywhere.
    Text(String),
    /// A path, or the name of a systemd unit made from one. It must begin a
    /// path (the byte before it cannot continue a file name; a `/` may
    /// precede it, as in `file:///mnt/data`) and end at the end of a path
    /// component (the byte after it cannot continue a file name). So
    /// `/mnt/data` matches `/mnt/data/nixos` but not `/mnt/data2` or
    /// `/srv/mnt/data`, and `mnt-data.mount` does not match
    /// `srv-mnt-data.mount`.
    Path(String),
    /// A word between bytes that cannot be part of a Nix identifier: `nails`
    /// matches `config.nails.enable` but not `snails`.
    Word(String),
    /// A device-mapper name where it names the mapping (see [`mapping_name`]),
    /// never as an ordinary word (`description = "Back up user data"`) or a
    /// directory (`/var/lib/postgresql/data`). `escaped` is the name as a
    /// systemd instance (`vg-root` is `vg\x2droot`).
    Name { name: String, escaped: String },
}

impl Pattern {
    /// The byte range of the first match in `line`. `luks` holds the ranges
    /// of the attribute names that `line` defines in a `luks.devices = { … }`
    /// block, as [`LuksBlocks::names`] returns them.
    pub(super) fn find(&self, line: &[u8], luks: &[Range<usize>]) -> Option<Range<usize>> {
        match self {
            Pattern::Text(text) => find_where(line, text, |_, _| true),
            Pattern::Path(path) => find_where(line, path, |before, after| {
                !continues_file_name(before) && !continues_file_name(after)
            }),
            Pattern::Word(word) => find_where(line, word, bounded),
            Pattern::Name { name, escaped } => mapping_name(line, name, escaped, luks),
        }
    }
}

/// Where `line` names the mapping `name`, in comments as well as in code:
///
/// - a `luks.devices` entry: `luks.devices.data`, `luks.devices."data"`, or an
///   attribute of a `luks.devices = { … }` block (`luks`);
/// - on a line that mentions `crypttab` or `cryptsetup`, as a word that is
///   not part of a path: crypttab text, `cryptsetup open /dev/sdb2 data`,
///   `systemd-cryptsetup@data.service` (with `escaped`, the instance name
///   systemd writes for a name with a `-` in it);
/// - at the start of a crypttab line: the name, then the device as a `/dev/`
///   path or a `UUID=`, `PARTUUID=`, `LABEL=`, `PARTLABEL=` or `ID=` tag.
fn mapping_name(
    line: &[u8],
    name: &str,
    escaped: &str,
    luks: &[Range<usize>],
) -> Option<Range<usize>> {
    if let Some(range) = luks_entry(line, name.as_bytes()) {
        return Some(range);
    }
    if let Some(range) = luks.iter().find(|r| line[(*r).clone()] == *name.as_bytes()) {
        return Some(range.clone());
    }
    if contains(line, b"crypttab") || contains(line, b"cryptsetup") {
        let word = find_where(line, name, |before, after| {
            bounded(before, after) && before != Some(b'/') && after != Some(b'/')
        });
        let instance = || {
            find_where(line, &format!("cryptsetup@{escaped}"), |_, after| {
                !after.is_some_and(is_identifier_byte)
            })
            .map(|range| range.end - escaped.len()..range.end)
        };
        if let Some(range) = word.or_else(instance) {
            return Some(range);
        }
    }
    crypttab_line(line, name.as_bytes())
}

/// `luks.devices.<name>` or `luks.devices."<name>"`: the range of the name.
fn luks_entry(line: &[u8], name: &[u8]) -> Option<Range<usize>> {
    const PREFIX: &[u8] = b"luks.devices.";
    (0..line.len()).find_map(|at| {
        let rest = line[at..].strip_prefix(PREFIX)?;
        let start = at + PREFIX.len();
        if let Some(quoted) = rest.strip_prefix(b"\"") {
            (quoted.strip_prefix(name)?.first() == Some(&b'"'))
                .then_some(start + 1..start + 1 + name.len())
        } else {
            let after = rest.strip_prefix(name)?.first().copied();
            (!after.is_some_and(is_identifier_byte)).then_some(start..start + name.len())
        }
    })
}

/// A crypttab line that opens `name`: the name first (after any indentation,
/// comment marker or opening quote), then the device.
fn crypttab_line(line: &[u8], name: &[u8]) -> Option<Range<usize>> {
    const DEVICE: &[&[u8]] = &[
        b"/dev/",
        b"uuid=",
        b"partuuid=",
        b"label=",
        b"partlabel=",
        b"id=",
    ];
    let mut start = 0;
    loop {
        let rest = &line[start..];
        start += if rest.starts_with(b"/*") {
            2
        } else if matches!(
            rest.first(),
            Some(b' ' | b'\t' | b'#' | b'*' | b'"' | b'\'')
        ) {
            1
        } else {
            break;
        };
    }
    let rest = line[start..].strip_prefix(name)?;
    let gap = rest
        .iter()
        .take_while(|&&b| b == b' ' || b == b'\t')
        .count();
    (gap > 0 && DEVICE.iter().any(|tag| rest[gap..].starts_with(tag)))
        .then_some(start..start + name.len())
}

/// Tracks the `luks.devices = { … }` blocks of a file, line by line, so the
/// attribute names they define can be told from the same word anywhere else.
/// Braces are counted on the whole line, comments included, so a block that
/// was commented out line by line is followed too.
#[derive(Debug, Default)]
pub(super) struct LuksBlocks {
    /// The brace depth inside the current block, 0 outside one.
    depth: usize,
    /// `luks.devices =` was seen and its `{` has not come yet.
    pending: bool,
}

impl LuksBlocks {
    /// The ranges in `line` of the attribute names it defines directly in a
    /// `luks.devices` block (`data` in `data = { … };` or `data.device = …;`).
    pub(super) fn names(&mut self, line: &[u8]) -> Vec<Range<usize>> {
        const KEY: &[u8] = b"luks.devices";
        let mut names = Vec::new();
        // An attribute may start here: at the start of a line inside a block,
        // and after its `{` or a `;` at its own level.
        let mut attribute = self.depth == 1;
        let mut i = 0;
        while i < line.len() {
            if line[i..].starts_with(KEY) {
                let next = skip_blanks(line, i + KEY.len());
                if line.get(next) == Some(&b'=') && line.get(next + 1) != Some(&b'=') {
                    self.pending = true;
                    i = next + 1;
                } else {
                    i += KEY.len();
                }
                continue;
            }
            match line[i] {
                b'{' => {
                    if self.pending {
                        self.pending = false;
                        self.depth = 1;
                    } else if self.depth > 0 {
                        self.depth += 1;
                    }
                    attribute = self.depth == 1;
                }
                b'}' => {
                    self.depth = self.depth.saturating_sub(1);
                    attribute = false;
                }
                b';' => {
                    self.pending = false;
                    attribute = self.depth == 1;
                }
                // Blanks and comment markers keep the position.
                b' ' | b'\t' | b'#' | b'*' | b'/' => {}
                _ if attribute => {
                    attribute = false;
                    if let Some((range, end)) = attribute_name(line, i) {
                        names.push(range);
                        i = end;
                        continue;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        names
    }
}

/// The attribute name at `start` (`data` or `"data"`) when an `=` or a `.`
/// follows it: its range without quotes, and where it ends.
fn attribute_name(line: &[u8], start: usize) -> Option<(Range<usize>, usize)> {
    let (range, end) = if line[start] == b'"' {
        let close = start + 1 + line[start + 1..].iter().position(|&b| b == b'"')?;
        (start + 1..close, close + 1)
    } else {
        let len = line[start..]
            .iter()
            .take_while(|&&b| is_identifier_byte(b) || b == b'\'')
            .count();
        if len == 0 {
            return None;
        }
        (start..start + len, start + len)
    };
    let next = skip_blanks(line, end);
    matches!(line.get(next), Some(b'=' | b'.')).then_some((range, next))
}

fn skip_blanks(line: &[u8], from: usize) -> usize {
    from + line.get(from..).map_or(0, |rest| {
        rest.iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count()
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The first occurrence of `needle` in `haystack` that `accept` takes, given
/// the bytes just before and just after it.
fn find_where(
    haystack: &[u8],
    needle: &str,
    accept: impl Fn(Option<u8>, Option<u8>) -> bool,
) -> Option<Range<usize>> {
    let needle = needle.as_bytes();
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find_map(|start| {
        let end = start + needle.len();
        let before = start.checked_sub(1).map(|i| haystack[i]);
        let after = haystack.get(end).copied();
        (haystack[start..end] == *needle && accept(before, after)).then_some(start..end)
    })
}

/// Neither neighbour can be part of a Nix identifier. `-` and `_` join words,
/// so `evolution-data-server` holds no word `data`.
fn bounded(before: Option<u8>, after: Option<u8>) -> bool {
    !before.is_some_and(is_identifier_byte) && !after.is_some_and(is_identifier_byte)
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

/// Whether `byte` continues a file name. Separators, quotes, spaces and Nix
/// punctuation do not; non-ASCII bytes do.
fn continues_file_name(byte: Option<u8>) -> bool {
    byte.is_some_and(|b| {
        b.is_ascii_alphanumeric()
            || matches!(b, b'.' | b'_' | b'-' | b'+' | b'@' | b'~' | b'%')
            || !b.is_ascii()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(pattern: &Pattern, line: &str) -> Option<String> {
        let mut luks = LuksBlocks::default();
        let lower = line.to_ascii_lowercase();
        let mut hit = None;
        for text in lower.split('\n') {
            let names = luks.names(text.as_bytes());
            if let Some(range) = pattern.find(text.as_bytes(), &names) {
                hit = Some(text[range].to_string());
                break;
            }
        }
        hit
    }

    fn data() -> Pattern {
        Pattern::Name {
            name: "data".into(),
            escaped: "data".into(),
        }
    }

    #[test]
    fn a_path_ends_at_a_component_boundary() {
        let path = Pattern::Path("/mnt/data".into());
        for hit in [
            "fileSystems.\"/mnt/data\" = {",
            "imports = [ /mnt/data/nixos ];",
            "url = \"git+file:///mnt/data/nixos\";",
            "# mount it at /mnt/data first",
            "x = /mnt/data;",
        ] {
            assert_eq!(found(&path, hit).as_deref(), Some("/mnt/data"), "{hit}");
        }
        for miss in [
            "fileSystems.\"/mnt/data2\" = {",
            "x = \"/mnt/data-old\";",
            "x = \"/mnt/data.bak\";",
            "x = \"/srv/mnt/data\";",
        ] {
            assert_eq!(found(&path, miss), None, "{miss}");
        }
        let unit = Pattern::Path("mnt-data.mount".into());
        assert_eq!(
            found(&unit, "after = [ \"mnt-data.mount\" ];").as_deref(),
            Some("mnt-data.mount")
        );
        for miss in [
            "after = [ \"srv-mnt-data.mount\" ];",
            "after = [ \"mnt-data.mounts\" ];",
        ] {
            assert_eq!(found(&unit, miss), None, "{miss}");
        }
    }

    #[test]
    fn a_word_is_bounded_by_non_identifier_bytes() {
        let word = Pattern::Word("nails".into());
        assert_eq!(
            found(&word, "config.nails.enable").as_deref(),
            Some("nails")
        );
        assert_eq!(found(&word, "# nails").as_deref(), Some("nails"));
        assert_eq!(found(&word, "hostName = \"snails-box\";"), None);
        assert_eq!(found(&word, "x = nails_y;"), None);
    }

    #[test]
    fn the_mapping_name_counts_where_it_names_the_mapping_comments_included() {
        for hit in [
            "boot.initrd.luks.devices.data.device = \"/dev/disk/by-uuid/1\";",
            "boot.initrd.luks.devices.\"data\".device = \"/dev/disk/by-uuid/1\";",
            "# boot.initrd.luks.devices.data.device = \"/dev/disk/by-uuid/7d2c9e14\";",
            "/* boot.initrd.luks.devices.\"data\".device = \"/dev/sdb2\"; */",
            "boot.initrd.luks.devices = {\n  data = { device = \"/dev/disk/by-uuid/1\"; };\n};",
            "boot.initrd.luks.devices = { other = { }; data.device = \"/dev/sdb2\"; };",
            "# boot.initrd.luks.devices = {\n#   data = {\n#     device = \"/dev/sdb2\";",
            "environment.etc.crypttab.text = \"data /dev/sdb2 none tcrypt\";",
            "# environment.etc.crypttab.text = \"data /dev/sdb2 none tcrypt\";",
            "text = ''\n  data UUID=7d2c9e14 none luks\n'';",
            "# data /dev/sdb2 none tcrypt",
            "script = \"cryptsetup open /dev/sdb2 data\";",
            "# cryptsetup open /dev/sdb2 data",
            "after = [ \"systemd-cryptsetup@data.service\" ];",
        ] {
            assert_eq!(found(&data(), hit).as_deref(), Some("data"), "{hit}");
        }
        let dashed = Pattern::Name {
            name: "vg-root".into(),
            escaped: "vg\\x2droot".into(),
        };
        assert_eq!(
            found(
                &dashed,
                "requires = [ \"systemd-cryptsetup@vg\\x2droot.service\" ];"
            )
            .as_deref(),
            Some("vg\\x2droot")
        );
    }

    #[test]
    fn the_mapping_name_as_an_ordinary_word_or_directory_passes() {
        for miss in [
            "# and is used to maintain compatibility with application data (e.g. databases)",
            "x = 1; # keep user data on /home",
            "description = \"Back up user data\";",
            "services.postgresql.dataDir = \"/var/lib/postgresql/data\";",
            "fileSystems.\"/srv/data\".device = \"/dev/sdb1\";",
            "services.evolution-data-server.enable = true;",
            "x = \"data2\";",
            "users.users.alice = {\n  data = 1;\n};",
            "boot.initrd.luks.devices.database.device = \"/dev/sdb2\";",
            "boot.initrd.luks.devices = { root = { }; };\nservices.x = {\n  data = 1;\n};",
            "# the data / logs split",
            "/data /dev/sdb1 none",
        ] {
            assert_eq!(found(&data(), miss), None, "{miss}");
        }
    }
}
