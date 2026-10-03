//! Configuration Fingerprinting
//!
//! Provides stable fingerprinting of the hidden NixOS configuration tree to
//! enable fast-path activation when nothing the build depends on has changed.
//!
//! Uses FNV-1a (64-bit) to produce a deterministic, dependency-free hash over a
//! set of `(path, content)` entries.
//!
//! # Design
//!
//! The fingerprint is computed from every file the hidden build reads, not just
//! the two headline configuration files. The caller
//! ([`plan`](crate::platform::ConfigLayer::plan)) walks the hidden `etc/nixos`
//! and `config/nixos` trees — `flake.nix`, `flake.lock`, the hardware wrapper and
//! its base, `configuration.nix` and every imported module — and adds synthetic
//! entries for the flake reference and the selected configuration name. An edit to
//! any of them (a bumped `flake.lock`, a new imported module, a different flake
//! ref) changes the fingerprint and forces a rebuild; a byte-for-byte identical
//! tree reuses the cached toplevel.
//!
//! Only entry **keys and content** are hashed. Timestamps, inode numbers and
//! process state are excluded, so the fingerprint changes only when the inputs
//! actually change.
//!
//! # Performance
//!
//! FNV-1a is a single O(n) pass with no external dependencies and stable output,
//! which is what the fast-path check needs.

use crate::filesystem::Filesystem;
use std::path::Path;

/// Synthetic-entry key prefix for inputs that are not files on disk (the flake
/// reference and the configuration name). The NUL byte cannot appear in a real
/// relative path, so a synthetic key can never collide with a walked file.
pub(crate) const SYNTHETIC_KEY_PREFIX: &str = "\u{0}nails:";

/// How deep the config-tree walk will recurse before giving up, a guard against
/// a pathological directory cycle reached through a non-symlink path.
const MAX_WALK_DEPTH: usize = 32;

/// Collect the `(key, content)` entries that feed [`compute_config_fingerprint`]
/// from the hidden configuration.
///
/// Walks the hidden `etc/nixos` and `config/nixos` trees and records every real
/// file (`flake.nix`, `flake.lock`, the hardware wrapper and its base,
/// `configuration.nix`, imported modules) keyed by its path relative to the
/// hidden volume root. A symlink is recorded by the content it resolves to when
/// that is a readable file (so the staged configuration symlink still counts) but
/// is never recursed into, so the walk cannot follow a `result` symlink or a
/// staged store link down into `/nix/store`. The flake reference and the selected
/// configuration name are appended as synthetic entries so a different flake ref
/// or attribute name also changes the fingerprint.
pub(crate) fn collect_config_tree<F: Filesystem>(
    fs: &F,
    hidden_volume_root: &Path,
    flake_ref: Option<&str>,
    config_name: Option<&str>,
) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = Vec::new();

    for sub in ["etc/nixos", "config/nixos"] {
        let dir = hidden_volume_root.join(sub);
        walk_dir(fs, hidden_volume_root, &dir, &mut entries, 0);
    }

    if let Some(flake_ref) = flake_ref {
        entries.push((
            format!("{SYNTHETIC_KEY_PREFIX}flake-ref"),
            flake_ref.to_string(),
        ));
    }
    if let Some(config_name) = config_name {
        entries.push((
            format!("{SYNTHETIC_KEY_PREFIX}config-name"),
            config_name.to_string(),
        ));
    }

    entries
}

fn walk_dir<F: Filesystem>(
    fs: &F,
    root: &Path,
    dir: &Path,
    entries: &mut Vec<(String, String)>,
    depth: usize,
) {
    if depth > MAX_WALK_DEPTH {
        return;
    }
    let items = match fs.list_directory(dir) {
        Ok(items) => items,
        Err(_) => return,
    };
    for path in items {
        let rel_key = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();

        if fs.is_symlink(&path).unwrap_or(false) {
            // Record a symlink by the file it resolves to, but never recurse
            // through it — a symlink into the store would otherwise pull the
            // whole closure in (or loop).
            if let Ok(content) = fs.read_file_content(&path) {
                entries.push((rel_key, content));
            }
            continue;
        }

        if fs.is_directory(&path).unwrap_or(false) {
            walk_dir(fs, root, &path, entries, depth + 1);
        } else if let Ok(content) = fs.read_file_content(&path) {
            entries.push((rel_key, content));
        }
    }
}

/// Compute a stable fingerprint over the hidden configuration inputs.
///
/// Each entry is a `(key, content)` pair: for a walked file the key is its path
/// relative to the hidden volume root and the content is the file body; for a
/// synthetic input (flake ref, configuration name) the key starts with
/// [`SYNTHETIC_KEY_PREFIX`]. Entries are sorted by key before hashing, so the
/// result does not depend on the order the caller discovered them in.
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
/// let tree = [
///     ("etc/nixos/flake.nix".to_string(), "{ }".to_string()),
///     ("etc/nixos/flake.lock".to_string(), "{ \"nodes\": {} }".to_string()),
/// ];
/// let fp1 = compute_config_fingerprint(&tree);
/// let fp2 = compute_config_fingerprint(&tree);
/// assert_eq!(fp1, fp2, "Same inputs produce the same fingerprint");
///
/// // A bumped flake.lock changes the fingerprint.
/// let bumped = [
///     ("etc/nixos/flake.nix".to_string(), "{ }".to_string()),
///     ("etc/nixos/flake.lock".to_string(), "{ \"nodes\": { \"a\": 1 } }".to_string()),
/// ];
/// assert_ne!(fp1, compute_config_fingerprint(&bumped));
/// ```
pub fn compute_config_fingerprint(entries: &[(String, String)]) -> String {
    // FNV-1a 64-bit parameters.
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    // Sort by key so discovery order never changes the result. Keys are unique
    // per input (a relative path, or a synthetic key), so the ordering is total.
    let mut ordered: Vec<&(String, String)> = entries.iter().collect();
    ordered.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hash = FNV_OFFSET_BASIS;
    let mut mix = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
    };

    for (key, content) in ordered {
        // Length-prefix every field so no shift of bytes across the key/content
        // or entry boundary can forge a colliding tree.
        mix(&(key.len() as u64).to_le_bytes());
        mix(key.as_bytes());
        mix(&(content.len() as u64).to_le_bytes());
        mix(content.as_bytes());
        mix(b"\x00NAILS_SEP\x00");
    }

    format!("{:016x}", hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> Vec<(String, String)> {
        files
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn deterministic_for_identical_trees() {
        let a = tree(&[("flake.nix", "{ }"), ("flake.lock", "lock")]);
        let b = tree(&[("flake.nix", "{ }"), ("flake.lock", "lock")]);
        assert_eq!(
            compute_config_fingerprint(&a),
            compute_config_fingerprint(&b)
        );
    }

    #[test]
    fn independent_of_entry_order() {
        let a = tree(&[("flake.nix", "{ }"), ("flake.lock", "lock")]);
        let b = tree(&[("flake.lock", "lock"), ("flake.nix", "{ }")]);
        assert_eq!(
            compute_config_fingerprint(&a),
            compute_config_fingerprint(&b)
        );
    }

    #[test]
    fn flake_lock_change_detected() {
        let a = tree(&[("flake.nix", "{ }"), ("flake.lock", "rev-1")]);
        let b = tree(&[("flake.nix", "{ }"), ("flake.lock", "rev-2")]);
        assert_ne!(
            compute_config_fingerprint(&a),
            compute_config_fingerprint(&b),
            "editing flake.lock must change the fingerprint"
        );
    }

    #[test]
    fn imported_module_added_detected() {
        let a = tree(&[("configuration.nix", "cfg")]);
        let b = tree(&[("configuration.nix", "cfg"), ("modules/extra.nix", "extra")]);
        assert_ne!(
            compute_config_fingerprint(&a),
            compute_config_fingerprint(&b),
            "adding an imported module must change the fingerprint"
        );
    }

    #[test]
    fn imported_module_edit_detected() {
        let a = tree(&[("configuration.nix", "cfg"), ("modules/extra.nix", "v1")]);
        let b = tree(&[("configuration.nix", "cfg"), ("modules/extra.nix", "v2")]);
        assert_ne!(
            compute_config_fingerprint(&a),
            compute_config_fingerprint(&b),
            "editing an imported module must change the fingerprint"
        );
    }

    #[test]
    fn flake_ref_change_detected() {
        let a = tree(&[
            ("flake.nix", "{ }"),
            (
                &format!("{SYNTHETIC_KEY_PREFIX}flake-ref"),
                "/etc/nixos#host-a",
            ),
        ]);
        let b = tree(&[
            ("flake.nix", "{ }"),
            (
                &format!("{SYNTHETIC_KEY_PREFIX}flake-ref"),
                "/etc/nixos#host-b",
            ),
        ]);
        assert_ne!(
            compute_config_fingerprint(&a),
            compute_config_fingerprint(&b),
            "a different flake ref must change the fingerprint"
        );
    }

    #[test]
    fn config_name_change_detected() {
        let a = tree(&[(&format!("{SYNTHETIC_KEY_PREFIX}config-name"), "host-a")]);
        let b = tree(&[(&format!("{SYNTHETIC_KEY_PREFIX}config-name"), "host-b")]);
        assert_ne!(
            compute_config_fingerprint(&a),
            compute_config_fingerprint(&b),
            "a different configuration name must change the fingerprint"
        );
    }

    #[test]
    fn no_boundary_collision_between_key_and_content() {
        // Moving a byte across the key/content boundary must not collide, thanks
        // to the length prefixes.
        let a = tree(&[("ab", "cd")]);
        let b = tree(&[("abc", "d")]);
        assert_ne!(
            compute_config_fingerprint(&a),
            compute_config_fingerprint(&b)
        );
    }

    #[test]
    fn is_16_hex_chars() {
        let fp = compute_config_fingerprint(&tree(&[("f", "c")]));
        assert_eq!(fp.len(), 16);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
