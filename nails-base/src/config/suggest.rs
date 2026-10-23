// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Readable messages for configuration parse errors
//!
//! serde reports an unknown key as "unknown field `x`, expected one of `a`,
//! `b`, ...". That list is long for the top-level table, and it buries the
//! most likely fix. This module rewrites such messages into a short
//! "did you mean" hint picked by edit distance from the keys serde lists, so
//! the hint is always drawn from the table the bad key actually sits in.

/// Keys of the retired live-overlay mode. The hidden session now overlays the
/// whole root, so these have no meaning; naming them says what to do instead
/// of suggesting a near-miss key.
const RETIRED_KEYS: &[&str] = &[
    "overlays",
    "overlay_mode",
    "overlay_exclusions",
    "overlay_exclusions_remove",
    "allow_leaky_exclusions",
    "ephemeral",
    "risky_services",
    "nixos_switch_required",
    "clear_history",
    "color_scheme",
    "prompt_label",
    "emergency",
];

/// Retired keys that carry their own note, because they were not dropped with
/// the live-overlay mode but replaced by a specific successor. The persistent-
/// decoy risk override is now the per-run `--allow-persistent-decoy` flag, so
/// `accept_persistent_decoy` is no longer read from the configuration file; an
/// old config that still sets it gets this note rather than a bare unknown-key
/// error.
const RETIRED_KEYS_WITH_NOTE: &[(&str, &str)] = &[(
    "accept_persistent_decoy",
    "it is now the per-run flag `--allow-persistent-decoy` and is no longer stored",
)];

/// The removal note for `name`, if it is a retired key.
fn retired_key_note(name: &str) -> Option<String> {
    if RETIRED_KEYS.contains(&name) {
        return Some(format!(
            "key `{name}` was removed: the hidden session overlays the whole root, so delete it"
        ));
    }
    RETIRED_KEYS_WITH_NOTE
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, note)| format!("key `{name}` was removed: {note}, so delete it"))
}

/// Rewrite a serde/toml error message into a one-line, actionable form.
pub(super) fn describe(message: &str) -> String {
    let message = message.split_whitespace().collect::<Vec<_>>().join(" ");

    if let Some(rest) = message.strip_prefix("unknown field `")
        && let Some((name, _)) = rest.split_once('`')
        && let Some(note) = retired_key_note(name)
    {
        return note;
    }

    for (prefix, noun) in [
        ("unknown field `", "unknown key"),
        ("unknown variant `", "unknown value"),
    ] {
        if let Some(rest) = message.strip_prefix(prefix)
            && let Some((name, expected)) = rest.split_once('`')
        {
            let candidates = backticked(expected);
            return match closest(name, &candidates) {
                Some(suggestion) => format!("{noun} `{name}` (did you mean `{suggestion}`?)"),
                None if candidates.is_empty() => format!("{noun} `{name}`"),
                None => format!(
                    "{noun} `{name}` (expected one of: {})",
                    candidates.join(", ")
                ),
            };
        }
    }

    message
}

/// Collect every backtick-quoted word, in order.
fn backticked(text: &str) -> Vec<&str> {
    text.split('`').skip(1).step_by(2).collect()
}

/// The candidate closest to `input`, if it is close enough to be a typo.
///
/// A candidate qualifies when its edit distance is at most a third of the
/// longer of the two names (minimum 1), which catches dropped, swapped and
/// substituted characters as well as a wrong last word such as
/// `hidden_volume_dir` for `hidden_volume_root`.
pub(super) fn closest<'a>(input: &str, candidates: &[&'a str]) -> Option<&'a str> {
    candidates
        .iter()
        .map(|candidate| (levenshtein(input, candidate), *candidate))
        .filter(|(distance, candidate)| {
            *distance <= (input.chars().count().max(candidate.chars().count()) / 3).max(1)
        })
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, candidate)| candidate)
}

/// Edit distance (insertions, deletions, substitutions) between two strings.
fn levenshtein(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0; b.len() + 1];

    for (i, ca) in a.chars().enumerate() {
        current[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let substitution = previous[j] + usize::from(ca != *cb);
            current[j + 1] = substitution.min(previous[j + 1] + 1).min(current[j] + 1);
        }
        std::mem::swap(&mut previous, &mut current);
    }

    previous[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_names_a_retired_key() {
        let message = "unknown field `overlays`, expected one of `hidden_volume_root`, `log_path`";
        assert_eq!(
            describe(message),
            "key `overlays` was removed: the hidden session overlays the whole root, so delete it"
        );
    }

    #[test]
    fn describe_names_the_retired_persistent_decoy_key() {
        // The storable persistent-decoy key became the per-run flag, so an old
        // config carrying it gets the successor note, not a near-miss guess.
        let message = "unknown field `accept_persistent_decoy`, expected one of \
             `hidden_volume_root`, `log_path`";
        assert_eq!(
            describe(message),
            "key `accept_persistent_decoy` was removed: it is now the per-run flag \
             `--allow-persistent-decoy` and is no longer stored, so delete it"
        );
    }

    #[test]
    fn levenshtein_counts_single_edits() {
        assert_eq!(levenshtein("", ""), 0);
        assert_eq!(levenshtein("abc", "abc"), 0);
        assert_eq!(levenshtein("abc", "ab"), 1);
        assert_eq!(levenshtein("ab", "abc"), 1);
        assert_eq!(levenshtein("abc", "abd"), 1);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
    }

    #[test]
    fn closest_picks_a_near_typo() {
        let keys = ["hidden_volume_root", "nixos_flake", "log_path"];
        assert_eq!(closest("nixos_flak", &keys), Some("nixos_flake"));
        assert_eq!(
            closest("hiden_volume_root", &keys),
            Some("hidden_volume_root")
        );
        assert_eq!(
            closest("hidden_volume_dir", &keys),
            Some("hidden_volume_root")
        );
    }

    #[test]
    fn closest_rejects_unrelated_names() {
        let keys = ["hidden_volume_root", "nixos_flake", "log_path"];
        assert_eq!(closest("colour", &keys), None);
        assert_eq!(closest("x", &keys), None);
        assert_eq!(closest("anything", &[]), None);
    }

    #[test]
    fn describe_unknown_field_adds_did_you_mean() {
        let message =
            "unknown field `nixos_flak`, expected one of `hidden_volume_root`, `nixos_flake`";
        assert_eq!(
            describe(message),
            "unknown key `nixos_flak` (did you mean `nixos_flake`?)"
        );
    }

    #[test]
    fn describe_unknown_field_without_match_lists_valid_keys() {
        let message = "unknown field `colour`, expected `enabled` or `hidden`";
        assert_eq!(
            describe(message),
            "unknown key `colour` (expected one of: enabled, hidden)"
        );
    }

    #[test]
    fn describe_unknown_variant_adds_did_you_mean() {
        let message = "unknown variant `explict`, expected `auto` or `explicit`";
        assert_eq!(
            describe(message),
            "unknown value `explict` (did you mean `explicit`?)"
        );
    }

    #[test]
    fn describe_field_of_struct_without_fields() {
        assert_eq!(
            describe("unknown field `x`, there are no fields"),
            "unknown key `x`"
        );
    }

    #[test]
    fn describe_passes_other_messages_through_on_one_line() {
        assert_eq!(
            describe("invalid type: integer `5`,\n  expected a string"),
            "invalid type: integer `5`, expected a string"
        );
    }
}
