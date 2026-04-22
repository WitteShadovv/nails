//! Base configuration forensic verification.

use crate::error::Result;
use crate::filesystem::Filesystem;
use std::path::PathBuf;

/// Verifies base hardware-configuration.nix contains no hidden references
///
/// **Property 1: Forensically Clean Base**
///
/// Base /etc/nixos/hardware-configuration.nix contains zero evidence of
/// hidden environment. Indistinguishable from standard NixOS installation.
///
/// Scans base /etc/nixos/hardware-configuration.nix for forensic evidence
/// of hidden environment. Returns `Ok(true)` if base is clean, `Ok(false)`
/// if suspicious patterns detected.
///
/// # Suspicious Patterns
///
/// - `/mnt/hidden` or similar hidden mount points
/// - `hidden/nixos` or similar hidden config paths
/// - Active `nails` references such as `./nails/configuration.nix`
/// - `plausible` or `deniability` keywords
/// - Standalone `hidden` keyword (with word boundaries)
///
/// See thesis design.tex Section 4.3.4 for full details on three critical
/// properties of the NixOS config overlay mechanism.
///
/// # Arguments
///
/// * `fs` - Filesystem implementation for testing
///
/// # Returns
///
/// * `Ok(true)` - Base config is forensically clean
/// * `Ok(false)` - Base config contains suspicious patterns
/// * `Err` - Cannot read base config (filesystem error)
///
/// If the file does not exist (non-NixOS system), this returns `Ok(true)` and logs a warning.
///
/// # Example
///
/// ```no_run
/// use nails_core::{RealFilesystem, nixos::verify_base_config_clean};
///
/// let fs = RealFilesystem;
/// let is_clean = verify_base_config_clean(&fs)?;
///
/// if !is_clean {
///     eprintln!("WARNING: Base config contains hidden environment traces!");
/// }
/// # Ok::<(), nails_core::NailsError>(())
/// ```
pub fn verify_base_config_clean<F: Filesystem>(fs: &F) -> Result<bool> {
    let base_config = PathBuf::from("/etc/nixos/hardware-configuration.nix");

    if !fs.path_exists(&base_config)? {
        // Non-NixOS systems may not have this file. Treat as clean to avoid false failure.
        tracing::warn!(
            "Base hardware-configuration.nix not found at /etc/nixos/hardware-configuration.nix; skipping clean check"
        );
        return Ok(true);
    }

    let content = fs.read_file_content(&base_config)?;
    let content_lower = content.to_lowercase();

    // Suspicious path patterns (substring match is appropriate for paths)
    // Use obfuscated patterns to prevent the strings from appearing in the binary
    let hidden_path = crate::obfuscate::hidden_path_pattern();
    let hidden_nixos = crate::obfuscate::pattern_hidden_nixos();
    let hidden_slash = crate::obfuscate::pattern_hidden_slash();

    if content_lower.contains(&hidden_path)
        || content_lower.contains(&hidden_nixos)
        || content_lower.contains(&hidden_slash)
    {
        tracing::warn!("Base hardware-configuration.nix contains suspicious hidden path reference");
        return Ok(false);
    }

    if contains_bounded_ascii_token(&content_lower, "hidden") {
        tracing::warn!("Base hardware-configuration.nix contains suspicious 'hidden' keyword");
        return Ok(false);
    }

    if contains_bounded_ascii_token(&content_lower, "nails") {
        tracing::warn!("Base hardware-configuration.nix contains suspicious 'nails' keyword");
        return Ok(false);
    }

    // Plausible deniability keywords (these are unlikely to appear legitimately)
    if content_lower.contains("plausible") || content_lower.contains("deniability") {
        tracing::warn!("Base hardware-configuration.nix contains plausible deniability keywords");
        return Ok(false);
    }

    Ok(true)
}

fn contains_bounded_ascii_token(content: &str, token: &str) -> bool {
    let bytes = content.as_bytes();
    let token = token.as_bytes();

    if token.is_empty() || bytes.len() < token.len() {
        return false;
    }

    let mut i = 0usize;
    while i + token.len() <= bytes.len() {
        if &bytes[i..i + token.len()] == token {
            let prev = i.checked_sub(1).and_then(|idx| bytes.get(idx)).copied();
            let next = bytes.get(i + token.len()).copied();

            if prev.is_none_or(|b| !is_ascii_identifier_char(b))
                && next.is_none_or(|b| !is_ascii_identifier_char(b))
            {
                return true;
            }
        }

        i += 1;
    }

    false
}

fn is_ascii_identifier_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}
