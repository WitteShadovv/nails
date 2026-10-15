// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Matching hidden-environment markers in the text of a `.nix` file.
//!
//! The scan works on bytes of ASCII-lowercased text, one line at a time, so a
//! match maps back to a line and to the original spelling by offset. The one
//! rule that must not see comments (a device-mapper name, often an ordinary
//! word such as `data`) reads a copy of the line with its comments blanked
//! ([`blank_comments`]), which keeps every offset.

use std::ops::Range;

/// How a marker is matched in a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Pattern {
    /// Plain text anywhere, comments included.
    Text(String),
    /// A path, comments included. It must begin a path (the byte before it
    /// cannot continue a file name; a `/` may precede it, as in
    /// `file:///mnt/data`) and end at the end of a path component (the byte
    /// after it cannot continue a file name). So `/mnt/data` matches
    /// `/mnt/data/nixos` but not `/mnt/data2` or `/srv/mnt/data`.
    Path(String),
    /// A word between bytes that cannot be part of a Nix identifier, comments
    /// included: `nails` matches `config.nails.enable` but not `snails`.
    Word(String),
    /// A word as for [`Pattern::Word`], but only outside comments and never
    /// next to a `/`: a device-mapper name in a `luks.devices` entry, in
    /// crypttab text or on a `cryptsetup` command line, but neither in the
    /// comments `nixos-generate-config` writes nor in a directory such as
    /// `/var/lib/postgresql/data`. The device path itself is a [`Pattern::Path`].
    Name(String),
}

impl Pattern {
    /// The byte range of the first match in `line`. `code` is the same line
    /// with its comments blanked, as [`blank_comments`] returns it.
    pub(super) fn find(&self, line: &[u8], code: &[u8]) -> Option<Range<usize>> {
        match self {
            Pattern::Text(text) => find_where(line, text, |_, _| true),
            Pattern::Path(path) => find_where(line, path, |before, after| {
                !continues_file_name(before) && !continues_file_name(after)
            }),
            Pattern::Word(word) => find_where(line, word, bounded),
            Pattern::Name(name) => find_where(code, name, |before, after| {
                bounded(before, after) && before != Some(b'/') && after != Some(b'/')
            }),
        }
    }
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

/// Where the lexer is: in code (with the depth of `{` it has to see closed
/// before a `}` ends the interpolation it is in), or in a string.
#[derive(Debug, Clone, Copy)]
enum Context {
    Code { braces: usize },
    String,
    IndentedString,
}

/// `text` with every Nix comment (`# …` to the end of the line, `/* … */`)
/// replaced by spaces. The result has the same length and keeps every newline,
/// so offsets and line numbers still point into `text`. Strings (`"…"` and
/// `''…''`, with their escapes and `${…}` interpolations) are kept whole: a
/// `#` inside one starts no comment, and the text of a string is matched like
/// code, since crypttab lines and unit scripts live in strings.
pub(super) fn blank_comments(text: &[u8]) -> Vec<u8> {
    let mut out = text.to_vec();
    let mut stack = vec![Context::Code { braces: 0 }];
    let mut i = 0;
    while i < text.len() {
        let rest = &text[i..];
        let context = stack.last().copied().unwrap_or(Context::Code { braces: 0 });
        i += match context {
            Context::Code { braces } => {
                if rest.starts_with(b"#") {
                    let end = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
                    blank(&mut out[i..i + end]);
                    end
                } else if rest.starts_with(b"/*") {
                    let end = rest[2..]
                        .windows(2)
                        .position(|pair| pair == b"*/")
                        .map_or(rest.len(), |at| at + 4);
                    blank(&mut out[i..i + end]);
                    end
                } else if rest.starts_with(b"\"") {
                    stack.push(Context::String);
                    1
                } else if rest.starts_with(b"''") && !ends_identifier(&text[..i]) {
                    stack.push(Context::IndentedString);
                    2
                } else if rest.starts_with(b"{") {
                    set_braces(&mut stack, braces + 1);
                    1
                } else if rest.starts_with(b"}") {
                    if braces == 0 && stack.len() > 1 {
                        stack.pop();
                    } else {
                        set_braces(&mut stack, braces.saturating_sub(1));
                    }
                    1
                } else {
                    1
                }
            }
            Context::String => {
                if rest.starts_with(b"\\") {
                    2
                } else if rest.starts_with(b"\"") {
                    stack.pop();
                    1
                } else if rest.starts_with(b"${") {
                    stack.push(Context::Code { braces: 0 });
                    2
                } else {
                    1
                }
            }
            Context::IndentedString => {
                if rest.starts_with(b"'''") || rest.starts_with(b"''$") {
                    3
                } else if rest.starts_with(b"''\\") {
                    4
                } else if rest.starts_with(b"''") {
                    stack.pop();
                    2
                } else if rest.starts_with(b"${") {
                    stack.push(Context::Code { braces: 0 });
                    2
                } else {
                    1
                }
            }
        };
    }
    out
}

/// Replace every byte of `span` but newlines with a space.
fn blank(span: &mut [u8]) {
    for byte in span.iter_mut().filter(|byte| **byte != b'\n') {
        *byte = b' ';
    }
}

fn set_braces(stack: &mut [Context], depth: usize) {
    if let Some(Context::Code { braces }) = stack.last_mut() {
        *braces = depth;
    }
}

/// Whether `before` ends in an identifier, which `''` would continue
/// (`x''` is an identifier, not the start of a string).
fn ends_identifier(before: &[u8]) -> bool {
    before
        .last()
        .is_some_and(|&b| is_identifier_byte(b) || b == b'\'')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blanked(text: &str) -> String {
        String::from_utf8(blank_comments(text.as_bytes())).unwrap()
    }

    fn found(pattern: &Pattern, line: &str) -> Option<String> {
        let code = blank_comments(line.as_bytes());
        pattern
            .find(line.as_bytes(), &code)
            .map(|range| line[range].to_string())
    }

    #[test]
    fn line_and_block_comments_are_blanked_in_place() {
        let text = "a = 1; # data\n/* data\n data */ b = 2;\n";
        let out = blanked(text);
        assert_eq!(out.len(), text.len());
        assert_eq!(out, "a = 1;       \n       \n         b = 2;\n");
    }

    #[test]
    fn strings_and_their_escapes_keep_a_hash() {
        let text = "x = \"a # b \\\" # c\"; # gone\ny = '' # shell\n ''${z} '''# '' ;\n";
        let out = blanked(text);
        assert!(out.contains("\"a # b \\\" # c\";       \n"), "{out}");
        assert!(out.contains("'' # shell\n ''${z} '''# '' ;"), "{out}");
    }

    #[test]
    fn an_interpolation_is_code_until_its_own_brace_closes() {
        let text = "s = \"${ { a = 1; }.a # x\n} rest # kept\"; # gone";
        let out = blanked(text);
        assert_eq!(out, "s = \"${ { a = 1; }.a    \n} rest # kept\";       ");
    }

    #[test]
    fn two_quotes_after_an_identifier_start_no_string() {
        let out = blanked("x'' = 1; # gone");
        assert_eq!(out, "x'' = 1;       ");
    }

    #[test]
    fn an_unterminated_comment_or_string_runs_to_the_end() {
        assert_eq!(blanked("a /* b"), "a     ");
        assert_eq!(blanked("a \" # b"), "a \" # b");
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
    fn a_name_counts_only_outside_comments_and_paths() {
        let name = Pattern::Name("data".into());
        for hit in [
            "boot.initrd.luks.devices.data.device = \"/dev/disk/by-uuid/1\";",
            "boot.initrd.luks.devices.\"data\".device = \"/dev/disk/by-uuid/1\";",
            "  data = { device = \"/dev/disk/by-uuid/1\"; };",
            "environment.etc.crypttab.text = \"data /dev/sdb2 none tcrypt\";",
            "script = \"cryptsetup open /dev/sdb2 data\";",
            "after = [ \"systemd-cryptsetup@data.service\" ];",
        ] {
            assert_eq!(found(&name, hit).as_deref(), Some("data"), "{hit}");
        }
        for miss in [
            "# and is used to maintain compatibility with application data (e.g. databases)",
            "x = 1; # keep user data on /home",
            "services.postgresql.dataDir = \"/var/lib/postgresql/data\";",
            "fileSystems.\"/srv/data\".device = \"/dev/sdb1\";",
            "services.evolution-data-server.enable = true;",
            "x = \"data2\";",
        ] {
            assert_eq!(found(&name, &miss.to_ascii_lowercase()), None, "{miss}");
        }
    }

    #[test]
    fn text_matches_anywhere() {
        let text = Pattern::Text("deniability".into());
        assert_eq!(
            found(&text, "# plausible deniability").as_deref(),
            Some("deniability")
        );
        assert_eq!(found(&Pattern::Text(String::new()), "x"), None);
        assert_eq!(found(&text, "short"), None);
    }
}
