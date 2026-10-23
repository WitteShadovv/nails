// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The EFF "large" diceware word list, vendored as data and exposed as a
//! checked table for the guided setup's passphrase helper.
//!
//! The list maps each roll of five six-sided dice to one word, so it holds
//! `6^5` = 7776 words. The file ships one `NNNNN<TAB>word` line per entry, in
//! roll order; the roll is implied by position, so only the words are kept
//! here. The list is third-party data under its own licence (see `REUSE.toml`).
//!
//! A word drawn at random is worth log2(7776), about 12.9 bits, only while
//! the 7776 words are distinct. The tests below pin the file to EFF's by its
//! SHA-256 and check that its rolls are every five-dice combination in order
//! and that no word repeats, so an edit or a merge that would weaken the list
//! fails the tests instead of reaching a passphrase.

/// The list as shipped: one `NNNNN<TAB>word` line per entry, 7776 lines.
const RAW: &str = include_str!("../data/eff_large_wordlist.txt");

/// The number of words in the EFF large list, one per five-dice roll.
pub const WORD_COUNT: usize = 7776;

/// The words in roll order (`11111` first, `66666` last).
///
/// Each line is a five-digit roll, a tab and the word; a line without a tab is
/// taken verbatim, so a malformed list surfaces in the tests below rather than
/// silently dropping an entry.
pub fn words() -> Vec<&'static str> {
    RAW.lines()
        .map(|line| line.split_once('\t').map_or(line, |(_roll, word)| word))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fmt::Write as _;

    use sha2::{Digest as _, Sha256};

    use super::*;

    /// The SHA-256 of `eff_large_wordlist.txt` as EFF serves it from
    /// <https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt>. EFF
    /// publishes no checksum of its own, so this is the digest of that file,
    /// which the vendored copy matches byte for byte.
    const EFF_SHA256: &str = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"; // pragma: allowlist secret

    /// The roll at `index` in roll order: `index` written in base 6 with five
    /// digits, each counted from 1 as a die face is, so `0` is `11111` and
    /// `7775` is `66666`.
    fn roll_at(index: u32) -> String {
        (0..5)
            .rev()
            .map(|place| {
                let face = index / 6_u32.pow(place) % 6 + 1;
                char::from_digit(face, 10).expect("a die face is a decimal digit")
            })
            .collect()
    }

    #[test]
    fn the_file_is_byte_for_byte_the_one_eff_publishes() {
        let mut digest = String::new();
        for byte in Sha256::digest(RAW.as_bytes()) {
            write!(digest, "{byte:02x}").expect("writing to a String cannot fail");
        }
        assert_eq!(
            digest, EFF_SHA256,
            "the vendored word list differs from the file EFF publishes"
        );
    }

    #[test]
    fn the_list_holds_one_word_per_roll() {
        assert_eq!(words().len(), WORD_COUNT);
    }

    #[test]
    fn every_line_is_a_five_dice_roll_and_a_lowercase_word() {
        for (index, line) in RAW.lines().enumerate() {
            let (roll, word) = line
                .split_once('\t')
                .unwrap_or_else(|| panic!("line {index} has no tab: {line:?}"));
            assert_eq!(roll.len(), 5, "roll {roll:?} is not five digits");
            assert!(
                roll.bytes().all(|b| (b'1'..=b'6').contains(&b)),
                "roll {roll:?} has a digit outside 1-6"
            );
            assert!(
                !word.is_empty() && word.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                "word {word:?} is not a lowercase, optionally hyphenated word"
            );
        }
    }

    #[test]
    fn the_rolls_are_every_five_dice_combination_in_order() {
        let rolls: Vec<&str> = RAW
            .lines()
            .map(|line| line.split_once('\t').map_or(line, |(roll, _word)| roll))
            .collect();
        assert_eq!(rolls.len(), 6_usize.pow(5));
        for (index, roll) in (0_u32..).zip(rolls) {
            assert_eq!(roll, roll_at(index), "line {index} is out of roll order");
        }
    }

    #[test]
    fn no_two_rolls_share_a_word() {
        // A repeated word comes up twice as often as any other, which takes
        // entropy from every passphrase drawn from the list.
        let mut seen = HashSet::with_capacity(WORD_COUNT);
        for word in words() {
            assert!(seen.insert(word), "{word:?} appears more than once");
        }
        assert_eq!(seen.len(), WORD_COUNT);
    }

    #[test]
    fn the_endpoints_are_the_known_first_and_last_words() {
        let words = words();
        assert_eq!(words.first().copied(), Some("abacus"));
        assert_eq!(words.last().copied(), Some("zoom"));
    }

    #[test]
    fn the_hyphenated_words_survive_parsing() {
        let words = words();
        for word in ["drop-down", "felt-tip", "t-shirt", "yo-yo"] {
            assert!(words.contains(&word), "the list is missing {word:?}");
        }
    }
}
