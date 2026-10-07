// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shannon entropy of byte samples.
//!
//! Encrypted data and good random fill read close to 8 bits per byte;
//! compressed data comes close, which is why the callers combine entropy with
//! the absence of a known header before calling anything encrypted.

/// Entropy in bits per byte of `bytes`, from 0 (one value repeated) to 8.
pub fn bits_per_byte(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &byte in bytes {
        counts[usize::from(byte)] += 1;
    }
    let total = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// The threshold above which a sample of at least 64 KiB reads as
/// encrypted or random. Plain text sits near 4.5, executables near 6, and even
/// well-compressed data usually stays a little below this over a large sample.
pub const HIGH_ENTROPY: f64 = 7.95;

/// Whether every sample is high-entropy (and there is at least one).
pub fn all_high(samples: &[f64]) -> bool {
    !samples.is_empty() && samples.iter().all(|&bits| bits >= HIGH_ENTROPY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_bytes_have_no_entropy() {
        assert_eq!(bits_per_byte(&[0u8; 4096]), 0.0);
        assert_eq!(bits_per_byte(&[]), 0.0);
    }

    #[test]
    fn every_value_once_is_eight_bits() {
        let all: Vec<u8> = (0..=255).collect();
        assert!((bits_per_byte(&all) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn urandom_reads_as_high_entropy_and_text_does_not() {
        use std::io::Read;
        let mut random = vec![0u8; 64 << 10];
        std::fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut random)
            .unwrap();
        assert!(bits_per_byte(&random) >= HIGH_ENTROPY);

        let text = "the quick brown fox jumps over the lazy dog ".repeat(2000);
        assert!(bits_per_byte(text.as_bytes()) < 5.0);
        assert!(!all_high(&[]));
    }
}
