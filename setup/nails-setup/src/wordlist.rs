// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The EFF "large" diceware word list, vendored as data and exposed as a
//! checked table for the guided setup's passphrase helper.
//!
//! The list maps each roll of five six-sided dice to one word, so it holds
//! `6^5` = 7776 words. The file ships one `NNNNN<TAB>word` line per entry, in
//! roll order; the roll is implied by position, so only the words are kept
//! here. The list is third-party data under its own licence (see `REUSE.toml`).

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
    use super::*;

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
