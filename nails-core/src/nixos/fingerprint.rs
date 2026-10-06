// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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
/// The set of files walked depends on which build the activation will run:
///
/// * **Flake build** (`flake_source` is `Some`): the build reads the flake
///   source directory and nothing else, so that directory's files are the
///   fingerprint inputs. The hidden `etc/nixos` tree is deliberately *not*
///   walked here: it doubles as the live `/etc` overlay upper layer, which the
///   hidden session's own `switch-to-configuration` rewrites (on hosts that
///   manage `/etc/nixos` through `environment.etc` the regenerated store
///   symlinks land in that upper), so folding it into the fingerprint made every
///   post-session re-activation look changed and killed the fast path even when
///   the operator changed nothing. Covering the real build input instead means
///   an edit to the flake forces a rebuild while incidental `/etc` churn does
///   not.
/// * **Legacy build** (`flake_source` is `None`): `nixos-rebuild` reads the
///   overlaid `/etc/nixos`, so the hidden `etc/nixos` and `config/nixos` trees
///   are the inputs and are walked as before.
///
/// Every real file (`flake.nix`, `flake.lock`, imported modules, the hardware
/// wrapper and its base, `configuration.nix`) is recorded keyed by its path
/// relative to the directory walked. A symlink is recorded by the content it
/// resolves to when that is a readable file (so the staged configuration symlink
/// still counts) but is never recursed into, so the walk cannot follow a
/// `result` symlink or a staged store link down into `/nix/store`. The flake
/// reference and the selected configuration name are appended as synthetic
/// entries so a different flake ref or attribute name also changes the
/// fingerprint.
pub(crate) fn collect_config_tree<F: Filesystem>(
    fs: &F,
    hidden_volume_root: &Path,
    flake_ref: Option<&str>,
    config_name: Option<&str>,
    flake_source: Option<&Path>,
) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = Vec::new();

    if let Some(flake_source) = flake_source {
        // Flake build: the flake source directory is the build input.
        walk_dir(fs, flake_source, flake_source, &mut entries, 0);
    } else {
        // Legacy build: the staged hidden config trees are the build input.
        for sub in ["etc/nixos", "config/nixos"] {
            let dir = hidden_volume_root.join(sub);
            walk_dir(fs, hidden_volume_root, &dir, &mut entries, 0);
        }
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
        // Skip VCS metadata: a flake source directory under version control
        // carries a `.git` whose contents (HEAD, index, refs, logs) churn with
        // every commit and checkout without changing what the build evaluates, so
        // folding it in would reintroduce the volatile-input problem this walk
        // exists to avoid.
        if path.file_name().is_some_and(|name| name == ".git") {
            continue;
        }

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

    // ---- collect_config_tree: flake-source vs hidden-tree walking ----

    use crate::filesystem::MockFilesystem;

    /// Register a plain file in the mock: its content plus a directory listing
    /// entry under its parent (rebuilt from the files passed per directory).
    fn mock_dir(fs: &MockFilesystem, dir: &str, files: &[(&str, &str)]) {
        let entries: Vec<std::path::PathBuf> = files
            .iter()
            .map(|(name, _)| std::path::PathBuf::from(format!("{dir}/{name}")))
            .collect();
        fs.mock_set_directory_contents(Path::new(dir), entries);
        for (name, content) in files {
            let path = format!("{dir}/{name}");
            fs.mock_set_path_exists(&path, true);
            fs.mock_set_file_content(&path, content);
        }
    }

    const HIDDEN_ROOT: &str = "/mnt/hidden";
    const FLAKE_SOURCE: &str = "/mnt/hidden/nixos";

    fn fp_flake(fs: &MockFilesystem) -> String {
        compute_config_fingerprint(&collect_config_tree(
            fs,
            Path::new(HIDDEN_ROOT),
            Some("/mnt/hidden/nixos#host"),
            Some("host"),
            Some(Path::new(FLAKE_SOURCE)),
        ))
    }

    #[test]
    fn flake_build_hashes_the_flake_source() {
        let fs = MockFilesystem::new();
        mock_dir(
            &fs,
            FLAKE_SOURCE,
            &[("flake.nix", "A"), ("flake.lock", "L")],
        );
        let before = fp_flake(&fs);

        // Editing the flake source changes the fingerprint.
        mock_dir(
            &fs,
            FLAKE_SOURCE,
            &[("flake.nix", "B"), ("flake.lock", "L")],
        );
        assert_ne!(
            before,
            fp_flake(&fs),
            "editing the flake source must change the fingerprint"
        );
    }

    #[test]
    fn flake_build_ignores_hidden_etc_nixos_churn() {
        let fs = MockFilesystem::new();
        mock_dir(
            &fs,
            FLAKE_SOURCE,
            &[("flake.nix", "A"), ("flake.lock", "L")],
        );
        // The hidden /etc/nixos tree is also the live /etc overlay upper, so the
        // session rewrites it. In flake mode it must not feed the fingerprint.
        mock_dir(
            &fs,
            "/mnt/hidden/etc/nixos",
            &[("hardware-configuration.nix", "wrapper-v1")],
        );
        let before = fp_flake(&fs);

        mock_dir(
            &fs,
            "/mnt/hidden/etc/nixos",
            &[
                ("hardware-configuration.nix", "wrapper-v2"),
                ("flake.nix", "regenerated-store-symlink"),
            ],
        );
        assert_eq!(
            before,
            fp_flake(&fs),
            "churn in the hidden /etc/nixos overlay upper must not change a flake-build fingerprint"
        );
    }

    #[test]
    fn legacy_build_hashes_hidden_trees() {
        let fs = MockFilesystem::new();
        mock_dir(
            &fs,
            "/mnt/hidden/etc/nixos",
            &[("configuration.nix", "cfg-v1")],
        );
        let legacy = |fs: &MockFilesystem| {
            compute_config_fingerprint(&collect_config_tree(
                fs,
                Path::new(HIDDEN_ROOT),
                Some("/mnt/hidden/config/nixos"),
                None,
                None,
            ))
        };
        let before = legacy(&fs);
        mock_dir(
            &fs,
            "/mnt/hidden/etc/nixos",
            &[("configuration.nix", "cfg-v2")],
        );
        assert_ne!(
            before,
            legacy(&fs),
            "a legacy build must still track the hidden config trees"
        );
    }

    #[test]
    fn git_metadata_is_excluded() {
        let fs = MockFilesystem::new();
        // A `.git` directory present in the listing must be skipped entirely,
        // without being recursed into or read.
        let entries = vec![
            std::path::PathBuf::from(format!("{FLAKE_SOURCE}/flake.nix")),
            std::path::PathBuf::from(format!("{FLAKE_SOURCE}/.git")),
        ];
        fs.mock_set_directory_contents(Path::new(FLAKE_SOURCE), entries);
        fs.mock_set_path_exists(&format!("{FLAKE_SOURCE}/flake.nix"), true);
        fs.mock_set_file_content(&format!("{FLAKE_SOURCE}/flake.nix"), "A");
        // Mark `.git` as a directory with contents that would otherwise be walked.
        let git = format!("{FLAKE_SOURCE}/.git");
        fs.mock_set_path_type(&git, crate::filesystem::mock::PathKind::Dir);
        mock_dir(&fs, &git, &[("HEAD", "ref: refs/heads/main")]);

        let entries = collect_config_tree(
            &fs,
            Path::new(HIDDEN_ROOT),
            Some("/mnt/hidden/nixos#host"),
            Some("host"),
            Some(Path::new(FLAKE_SOURCE)),
        );
        assert!(
            entries.iter().all(|(key, _)| !key.contains(".git")),
            "the .git directory must be excluded from the fingerprint: {entries:?}"
        );
    }
}
