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
/// - `nails` references (word boundary to avoid false positives like "snails")
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

    // Word boundary patterns (check for "hidden" as whole word)
    // This catches: "hidden ", " hidden", " hidden ", "#hidden", etc.
    // But NOT: "hiddenstorage", "snails", etc.
    let hidden_word_boundaries = [
        " hidden ",   // Middle of line with spaces
        "\nhidden ",  // Start of line
        " hidden\n",  // End of line
        "\nhidden\n", // Whole line
        "#hidden ",   // Comment without leading space
        "#hidden\n",  // Comment at end of line
        ";hidden ",   // After semicolon (Nix syntax)
        ";hidden\n",  // Semicolon then end of line
        ";hidden=",   // After semicolon with assignment (e.g., ;hidden=true)
        " hidden\"",  // Before quote
        "\"hidden ",  // After quote
        " hidden=",   // Assignment without space (e.g., hidden=true)
        "=hidden ",   // Assignment value
        "=hidden\n",  // Assignment value at end of line
    ];

    for pattern in &hidden_word_boundaries {
        if content_lower.contains(pattern) {
            tracing::warn!("Base hardware-configuration.nix contains suspicious 'hidden' keyword");
            return Ok(false);
        }
    }

    // "nails" keyword with word boundaries to avoid false positives
    // like "snails", "fingernails", etc.
    let nails_word_boundaries = [
        " nails ",
        "\nnails ",
        " nails\n",
        "\nnails\n",
        "#nails ",
        "#nails\n",
        ";nails ",
        ";nails\n",
        " nails\"",
        "\"nails ",
        ".nails ", // After dot (e.g., config.nails)
        ".nails\n",
        ".nails.", // Dot notation (e.g., config.nails.enable)
        ".nails=", // Assignment (e.g., config.nails=true)
    ];

    for pattern in &nails_word_boundaries {
        if content_lower.contains(pattern) {
            tracing::warn!("Base hardware-configuration.nix contains suspicious 'nails' keyword");
            return Ok(false);
        }
    }

    // Plausible deniability keywords (these are unlikely to appear legitimately)
    if content_lower.contains("plausible") || content_lower.contains("deniability") {
        tracing::warn!("Base hardware-configuration.nix contains plausible deniability keywords");
        return Ok(false);
    }

    Ok(true)
}
