//! Configuration Fingerprinting (Story 15.4)
//!
//! Provides stable fingerprinting of NixOS configuration inputs to enable
//! fast-path activation when configuration hasn't changed.
//!
//! Uses FNV-1a (64-bit) hash algorithm to produce a deterministic,
//! dependency-free hash of hardware and hidden configuration content.
//!
//! # Design
//!
//! The fingerprint is computed from:
//! - Hardware configuration content (`{hidden}/etc/nixos/hardware-configuration.nix`)
//! - Hidden configuration content (`{hidden}/config/nixos/configuration.nix`)
//!
//! Only file **content** is hashed. Timestamps, paths, and process state are
//! excluded so the fingerprint changes only when configuration actually changes.
//!
//! # Performance
//!
//! FNV-1a was chosen for:
//! - Fast computation (O(n) single pass)
//! - Zero external dependencies
//! - Stable output (same input always produces same hash)
//! - Good distribution for short inputs

/// Compute a stable fingerprint of NixOS config inputs (Story 15.4, AC1)
///
/// Hashes the content of the hardware configuration and hidden configuration
/// using FNV-1a (64-bit). This is a deterministic, dependency-free hash that
/// produces a stable hex string for comparing config inputs across activations.
///
/// # Volatile fields excluded
///
/// Only file *content* is hashed. Timestamps, temp paths, and process state
/// are intentionally excluded so the fingerprint changes only when the config
/// itself changes.
///
/// # Arguments
///
/// * `hardware_config_content` - Contents of `{hidden}/etc/nixos/hardware-configuration.nix`
/// * `hidden_config_content`   - Contents of `{hidden}/config/nixos/configuration.nix`
///
/// # Returns
///
/// A lowercase 16-character hex string (64-bit FNV-1a hash).
///
/// # Example
///
/// ```
/// use nails_core::nixos::compute_config_fingerprint;
///
/// let fp1 = compute_config_fingerprint("hardware = {}", "hidden = {}");
/// let fp2 = compute_config_fingerprint("hardware = {}", "hidden = {}");
/// assert_eq!(fp1, fp2, "Same inputs produce same fingerprint");
///
/// let fp3 = compute_config_fingerprint("hardware = { changed = true; }", "hidden = {}");
/// assert_ne!(fp1, fp3, "Different inputs produce different fingerprint");
/// ```
///
/// # Design Trade-off: Fingerprint Before Nix Validation
///
/// This function computes the fingerprint **without** validating Nix syntax.
///
/// **Rationale:**
/// - Performance: Syntax validation would require invoking `nix-instantiate` or similar,
///   which defeats the purpose of the fast-path optimization (skipping expensive operations)
/// - Simplicity: Hashing raw content is O(n) and uses only stdlib
/// - Correctness: Invalid Nix will fail during the actual build step, so errors are still caught
///
/// **Edge case handled:** If config files are missing or unreadable, the fingerprint
/// is computed from empty strings. This is intentional - the build step will fail with
/// a clear error if the configs are truly required, while still allowing the fingerprint
/// logic to complete for cases where configs might be optional (e.g., pre-flight checks).
pub fn compute_config_fingerprint(
    hardware_config_content: &str,
    hidden_config_content: &str,
) -> String {
    // FNV-1a 64-bit parameters
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET_BASIS;

    // Hash hardware config content
    for byte in hardware_config_content.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    // Separator to prevent concatenation collisions
    for byte in b"\x00NAILS_SEP\x00" {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    // Hash hidden config content
    for byte in hidden_config_content.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    format!("{:016x}", hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_config_fingerprint_deterministic() {
        let fp1 = compute_config_fingerprint("hardware", "hidden");
        let fp2 = compute_config_fingerprint("hardware", "hidden");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_compute_config_fingerprint_hardware_change_detected() {
        let fp1 = compute_config_fingerprint("hardware_v1", "hidden");
        let fp2 = compute_config_fingerprint("hardware_v2", "hidden");
        assert_ne!(fp1, fp2, "Hardware config change should alter fingerprint");
    }

    #[test]
    fn test_compute_config_fingerprint_hidden_config_change_detected() {
        let fp1 = compute_config_fingerprint("hardware", "hidden_v1");
        let fp2 = compute_config_fingerprint("hardware", "hidden_v2");
        assert_ne!(fp1, fp2, "Hidden config change should alter fingerprint");
    }

    #[test]
    fn test_compute_config_fingerprint_no_separator_collision() {
        let fp1 = compute_config_fingerprint("ab", "cd");
        let fp2 = compute_config_fingerprint("abc", "d");
        assert_ne!(fp1, fp2, "Separator should prevent concatenation collision");
    }

    #[test]
    fn test_compute_config_fingerprint_is_16_hex_chars() {
        let fp = compute_config_fingerprint("test", "data");
        assert_eq!(fp.len(), 16, "Fingerprint should be 16 hex chars (64-bit)");
        assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit()),
            "Fingerprint should be hex"
        );
    }
}
