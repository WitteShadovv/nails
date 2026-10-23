// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The copy lint: the message catalogue checked against `copy-lint.toml`.
//!
//! It runs in the fast gate (`just check`, through the test suite) in a
//! fraction of a second: it reads the rules file, walks
//! [`nails_base::catalog::CATALOG`], and refuses an avoid-list word on a
//! surface that forbids it, a bare `nails <command>`, an over-wide plain line,
//! a missing translator note, a placeholder that is used but not declared (or
//! the other way round), and two entries that share a text or an ID.
//!
//! The rule logic is exercised on seeded bad input below, so each check is
//! known to fire; `the_catalogue_passes_the_copy_lint` then proves the real
//! catalogue is clean.
//!
//! The bare-command rule also runs over the source of every crate, outside the
//! catalogue: `no_source_names_a_bare_nails_command` refuses a `nails <command>`
//! in any string a command can print, so a next step is always rendered
//! through `nails_base::next_step` with the real binary path.

use std::collections::BTreeMap;
use std::path::PathBuf;

use nails_base::catalog::{CATALOG, Message, Surface};
use serde::Deserialize;

/// The rules file, as `copy-lint.toml` writes it.
#[derive(Deserialize)]
struct Rules {
    #[serde(rename = "max-columns")]
    max_columns: usize,
    commands: Vec<String>,
    group: Vec<Group>,
}

/// One avoid-list group: the words refused on the named surfaces.
#[derive(Deserialize)]
struct Group {
    name: String,
    #[serde(rename = "forbid-on")]
    forbid_on: Vec<String>,
    words: Vec<String>,
}

/// `copy-lint.toml` sits at the workspace root, one level above this crate, as
/// the crate-graph test reaches the sibling manifests.
fn rules_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("nails-base sits in the workspace")
        .join("copy-lint.toml")
}

fn load_rules() -> Rules {
    let path = rules_path();
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    toml::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// One failing rule for one message.
#[derive(Debug)]
struct Violation {
    id: &'static str,
    rule: &'static str,
    detail: String,
}

/// A word made only of letters and digits is matched as a whole word; anything
/// with a space or punctuation is matched as a substring.
fn is_wordish(entry: &str) -> bool {
    !entry.is_empty() && entry.chars().all(|c| c.is_ascii_alphanumeric())
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Does `text` contain the avoid `entry`, by the whole-word/substring rule?
/// Case-insensitive throughout.
fn contains_avoid(text: &str, entry: &str) -> bool {
    let hay = text.to_ascii_lowercase();
    let needle = entry.to_ascii_lowercase();
    if needle.is_empty() {
        return false;
    }
    if !is_wordish(entry) {
        return hay.contains(&needle);
    }
    let bytes = hay.as_bytes();
    let mut from = 0;
    while let Some(rel) = hay[from..].find(&needle) {
        let at = from + rel;
        let before_ok = at == 0 || !is_word_byte(bytes[at - 1]);
        let end = at + needle.len();
        let after_ok = end >= bytes.len() || !is_word_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = at + 1;
    }
    false
}

/// The `{name}` placeholders in `text`, in order.
fn placeholders_in(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        let tail = &rest[open + 1..];
        let Some(close) = tail.find('}') else { break };
        names.push(tail[..close].to_string());
        rest = &tail[close + 1..];
    }
    names
}

/// A whitespace token stripped of surrounding punctuation, path parts kept.
fn word_token(raw: &str) -> &str {
    raw.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '/')
}

/// Does `text` hint a bare `nails <command>` (not `sudo <real path> …`)?
fn has_bare_nails_command(text: &str, commands: &[String]) -> bool {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    tokens.windows(2).any(|pair| {
        word_token(pair[0]) == "nails" && commands.iter().any(|c| c == word_token(pair[1]))
    })
}

/// The width of the first plain line over `max`, if any. A line that carries a
/// placeholder or a command to paste is exempt (its width is run-time data).
fn over_length_line(text: &str, max: usize) -> Option<usize> {
    text.split('\n')
        .filter(|line| !line.contains('{') && !line.contains("sudo "))
        .map(|line| line.chars().count())
        .find(|&cols| cols > max)
}

fn is_named(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn id_is_well_formed(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
}

/// Every copy-lint violation in `entries`, checked against `rules`.
fn lint(entries: &[Message], rules: &Rules) -> Vec<Violation> {
    let mut found = Vec::new();
    let mut id_counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut text_owner: BTreeMap<&str, &str> = BTreeMap::new();

    for message in entries {
        let id = message.id;
        let mut push = |rule, detail| found.push(Violation { id, rule, detail });

        if !id_is_well_formed(id) {
            push("id-format", format!("{id:?} is not lowercase dotted-kebab"));
        }
        *id_counts.entry(id).or_insert(0) += 1;
        if let Some(prev) = text_owner.insert(message.text, id) {
            push("duplicate-text", format!("shares its text with {prev:?}"));
        }
        if message.note.trim().is_empty() {
            push(
                "translator-note",
                "the translator note is empty".to_string(),
            );
        }

        let used = placeholders_in(message.text);
        for name in &used {
            if !is_named(name) {
                push("placeholder", format!("{{{name}}} is not a lowercase name"));
            }
            if !message.placeholders.contains(&name.as_str()) {
                push(
                    "placeholder",
                    format!("{{{name}}} is used but not declared"),
                );
            }
        }
        for declared in message.placeholders {
            if !used.iter().any(|name| name == declared) {
                push(
                    "placeholder",
                    format!("{{{declared}}} is declared but not used"),
                );
            }
        }

        if has_bare_nails_command(message.text, &rules.commands) {
            push(
                "bare-command",
                "a bare `nails <command>`; render `sudo <real path> <command>`".to_string(),
            );
        }
        if let Some(cols) = over_length_line(message.text, rules.max_columns) {
            push(
                "line-length",
                format!("a plain line is {cols} columns (max {})", rules.max_columns),
            );
        }

        for group in &rules.group {
            if !group
                .forbid_on
                .iter()
                .any(|s| s == message.surface.as_str())
            {
                continue;
            }
            let rule = if group.name == "neutral-forbidden" {
                "neutral-word"
            } else {
                "avoid-word"
            };
            for word in &group.words {
                if contains_avoid(message.text, word) {
                    push(
                        rule,
                        format!(
                            "{word:?} ({}) is not allowed on the {} surface",
                            group.name,
                            message.surface.as_str()
                        ),
                    );
                }
            }
        }
    }

    for (id, count) in id_counts {
        if count > 1 {
            found.push(Violation {
                id,
                rule: "duplicate-id",
                detail: format!("the ID appears {count} times"),
            });
        }
    }
    found
}

fn rules_of(rule: &str, violations: &[Violation]) -> bool {
    violations.iter().any(|v| v.rule == rule)
}

#[test]
fn the_catalogue_passes_the_copy_lint() {
    let rules = load_rules();
    let violations = lint(CATALOG, &rules);
    assert!(
        violations.is_empty(),
        "copy-lint violations:\n{}",
        violations
            .iter()
            .map(|v| format!("  [{}] {}: {}", v.rule, v.id, v.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Where the source may name a bare `nails <command>`, and why: text nobody
/// pastes a command from, or where the binary's path is not known. An entry
/// ending in `/` covers a directory.
const BARE_COMMAND_ALLOWED: &[(&str, &str)] = &[
    (
        "nails-cli/src/cli/args.rs",
        "the --help text, whose examples follow clap's `Usage: nails <command>` line",
    ),
    (
        "nails-base/src/config/loading.rs",
        "the comments of the configuration template, the file init writes",
    ),
    (
        "nails-forensics/src/residue_catalog/rows/",
        "the residue catalogue, reference text the threat model and the decoy requirements \
         are generated from, which verify and check quote as it is",
    ),
];

/// A source file that holds only tests or test fixtures, which print nothing
/// a person reads.
fn is_test_source(relative: &str) -> bool {
    let name = relative.rsplit('/').next().unwrap_or(relative);
    relative.contains("/tests/")
        || relative.contains("/mock/")
        || relative.contains("/test_support")
        || name.ends_with("tests.rs")
        || name.starts_with("tests_")
        || name == "fake.rs"
}

/// Every `.rs` file below `dir`, as paths relative to `root`.
fn rust_sources(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_sources(root, &path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let relative = path.strip_prefix(root).unwrap().to_string_lossy();
            out.push(relative.into_owned());
        }
    }
}

/// The lines of `text` a command can print: the code before an inline test
/// module, without its comments.
fn printable_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let end = text
        .find("\n#[cfg(test)]\nmod tests")
        .or_else(|| text.find("\n#[cfg(test)]\n#[path"))
        .unwrap_or(text.len());
    text[..end]
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
        .map(|(index, line)| (index + 1, line))
}

/// No string a command prints names a bare `nails <command>`: the binary is
/// not on `PATH`, so such a hint cannot be pasted. A next step is rendered
/// through `nails_base::next_step` with the real binary path instead.
#[test]
fn no_source_names_a_bare_nails_command() {
    let rules = load_rules();
    let root = rules_path().parent().unwrap().to_path_buf();
    let mut sources = Vec::new();
    let mut crates: Vec<_> = std::fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("nails-"))
                && path.join("src").is_dir()
        })
        .collect();
    crates.sort();
    assert!(crates.len() > 5, "the crates were found: {crates:?}");
    for krate in &crates {
        rust_sources(&root, &krate.join("src"), &mut sources);
    }
    let mut found = Vec::new();
    for relative in &sources {
        if is_test_source(relative)
            || BARE_COMMAND_ALLOWED
                .iter()
                .any(|(allowed, _)| relative.starts_with(allowed))
        {
            continue;
        }
        let text = std::fs::read_to_string(root.join(relative)).unwrap();
        for (number, line) in printable_lines(&text) {
            if has_bare_nails_command(line, &rules.commands) {
                found.push(format!("{relative}:{number}: {}", line.trim()));
            }
        }
    }
    assert!(
        found.is_empty(),
        "a bare `nails <command>`; render the next step through \
         nails_base::next_step::sudo_line:\n{}",
        found.join("\n")
    );
}

#[test]
fn the_source_scan_reads_only_the_printable_lines() {
    let text = "let a = \"run nails recover\";\n// nails status in a comment\n\
                #[cfg(test)]\nmod tests {\n    \"nails verify\"\n}\n";
    let lines: Vec<(usize, &str)> = printable_lines(text).collect();
    assert_eq!(lines, vec![(1, "let a = \"run nails recover\";")]);
    assert!(is_test_source("nails-cli/src/cli/output/status/tests.rs"));
    assert!(is_test_source("nails-base/src/filesystem/mock/state.rs"));
    assert!(!is_test_source("nails-cli/src/cli/commands/recover.rs"));
}

#[test]
fn the_rules_file_parses_and_has_the_expected_groups() {
    let rules = load_rules();
    assert_eq!(rules.max_columns, 80);
    assert!(rules.commands.iter().any(|c| c == "activate"));
    let names: Vec<&str> = rules.group.iter().map(|g| g.name.as_str()).collect();
    for expected in ["style", "internal", "storage", "neutral-forbidden"] {
        assert!(names.contains(&expected), "missing group {expected:?}");
    }
}

// --- The seeded cases: each proves one rule fires. ---

fn seed(id: &'static str, text: &'static str, note: &'static str, surface: Surface) -> Message {
    Message {
        id,
        text,
        note,
        placeholders: &[],
        surface,
    }
}

#[test]
fn flags_an_avoid_list_word() {
    let rules = load_rules();
    let bad = [seed(
        "seed.style",
        "Please run this now.",
        "note",
        Surface::Cli,
    )];
    assert!(rules_of("avoid-word", &lint(&bad, &rules)));
}

#[test]
fn flags_a_bare_nails_command() {
    let rules = load_rules();
    let bad = [seed(
        "seed.bare",
        "Then run nails recover to undo it.",
        "note",
        Surface::Cli,
    )];
    assert!(rules_of("bare-command", &lint(&bad, &rules)));
}

#[test]
fn flags_an_over_length_line() {
    let rules = load_rules();
    let bad = [seed(
        "seed.long",
        "This line has been padded with filler words so that it runs well beyond the eighty column budget.",
        "note",
        Surface::Cli,
    )];
    assert!(rules_of("line-length", &lint(&bad, &rules)));
}

#[test]
fn flags_a_missing_translator_note() {
    let rules = load_rules();
    let bad = [seed("seed.note", "All fine here.", "", Surface::Cli)];
    assert!(rules_of("translator-note", &lint(&bad, &rules)));
}

#[test]
fn flags_a_neutral_surface_word() {
    let rules = load_rules();
    let bad = [seed(
        "seed.neutral",
        "NAILS session",
        "note",
        Surface::Neutral,
    )];
    assert!(rules_of("neutral-word", &lint(&bad, &rules)));
}

#[test]
fn flags_a_placeholder_used_but_not_declared() {
    let rules = load_rules();
    let bad = [seed("seed.ph", "Run {command} now.", "note", Surface::Cli)];
    assert!(rules_of("placeholder", &lint(&bad, &rules)));
}

#[test]
fn flags_two_entries_that_share_a_text() {
    let rules = load_rules();
    let bad = [
        seed("seed.a", "The very same words.", "note", Surface::Cli),
        seed("seed.b", "The very same words.", "note", Surface::Cli),
    ];
    assert!(rules_of("duplicate-text", &lint(&bad, &rules)));
}

#[test]
fn an_internal_word_is_allowed_on_the_reference_surface_but_not_the_cli() {
    let rules = load_rules();
    let on_cli = [seed(
        "seed.ovl.cli",
        "The overlay is mounted.",
        "note",
        Surface::Cli,
    )];
    assert!(rules_of("avoid-word", &lint(&on_cli, &rules)));
    let on_reference = [seed(
        "seed.ovl.ref",
        "The overlay is mounted.",
        "note",
        Surface::Reference,
    )];
    assert!(
        !rules_of("avoid-word", &lint(&on_reference, &rules)),
        "an internal word is defined on the reference surface"
    );
}
