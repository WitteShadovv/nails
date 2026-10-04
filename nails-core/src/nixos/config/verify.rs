// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Base configuration forensic verification.

use crate::error::Result;
use crate::filesystem::Filesystem;
use std::path::Path;

/// Base `/etc/nixos` directory scanned for hidden-environment traces.
const BASE_NIXOS_DIR: &str = "/etc/nixos";

/// Kernel mount table exposing the backing source of each mount point.
const SELF_MOUNTINFO: &str = "/proc/self/mountinfo";

/// Scans the base `/etc/nixos` tree for traces of the hidden environment.
///
/// Every `*.nix` file under `/etc/nixos` (the flake, `configuration.nix`,
/// `hardware-configuration.nix`, and any imported module) is read and matched
/// against both a fixed set of hidden-environment keywords and a dynamic set
/// derived from the caller's configuration: the configured `hidden_volume_root`
/// path and the backing device that `/proc/self/mountinfo` reports for it
/// (device-mapper name and full source path). Matching the configured root and
/// its device means a `nixos-generate-config` `fileSystems` entry for the hidden
/// device is caught regardless of its mount point, not only when it happens to
/// live under `/mnt/hidden`.
///
/// This is a best-effort trace scan, not a proof: a clean result means none of
/// the known markers were found, which is weaker than the base being byte-for-byte
/// identical to a stock install. UUID references (`/dev/disk/by-uuid/...`) are not
/// resolved here because the filesystem trait cannot read symlinks; the mount-table
/// layer carries that resolution.
///
/// # Suspicious Patterns
///
/// - `/mnt/hidden`, `hidden/nixos`, or `/hidden/` style paths
/// - The configured `hidden_volume_root` path
/// - The backing device of the hidden root (mapper name or source path)
/// - Standalone `hidden` or `nails` keywords (with word boundaries)
/// - `plausible` or `deniability` keywords
///
/// # Arguments
///
/// * `fs` - Filesystem implementation (real or mock)
/// * `hidden_volume_root` - Configured hidden volume root to match against
///
/// # Returns
///
/// * `Ok(true)` - No hidden-environment traces found in the base config
/// * `Ok(false)` - At least one suspicious pattern was found
/// * `Err` - A base `.nix` file could not be read (filesystem error)
///
/// If no `*.nix` files exist under `/etc/nixos` (non-NixOS system), this returns
/// `Ok(true)` and logs a warning.
///
/// # Example
///
/// ```no_run
/// use std::path::Path;
/// use nails_core::{RealFilesystem, nixos::verify_base_config_clean};
///
/// let fs = RealFilesystem;
/// let is_clean = verify_base_config_clean(&fs, Path::new("/mnt/hidden"))?;
///
/// if !is_clean {
///     eprintln!("WARNING: Base config contains hidden environment traces!");
/// }
/// # Ok::<(), nails_core::NailsError>(())
/// ```
pub fn verify_base_config_clean<F: Filesystem>(fs: &F, hidden_volume_root: &Path) -> Result<bool> {
    let nix_files = fs.find_files_with_pattern(Path::new(BASE_NIXOS_DIR), ".nix")?;

    if nix_files.is_empty() {
        // Non-NixOS systems (or an empty tree) have no base config to inspect.
        tracing::warn!(
            "No .nix files found under {BASE_NIXOS_DIR}; skipping base-config clean check"
        );
        return Ok(true);
    }

    // Dynamic markers derived from the configured hidden volume and its device.
    let mut path_markers: Vec<String> = Vec::new();
    let mut token_markers: Vec<String> = Vec::new();

    let root_marker = hidden_volume_root.to_string_lossy().to_lowercase();
    // Guard against degenerate roots (e.g. "/") matching everything.
    if root_marker.len() > 1 {
        path_markers.push(root_marker);
    }

    for source in resolve_backing_sources(fs, hidden_volume_root) {
        if let Some(name) = source.strip_prefix("/dev/mapper/")
            && !name.is_empty()
        {
            token_markers.push(name.to_string());
        }
        if source.len() > 1 {
            path_markers.push(source);
        }
    }

    for file in &nix_files {
        let content_lower = fs.read_file_content(file)?.to_lowercase();

        if let Some(reason) = find_suspicious_marker(&content_lower, &path_markers, &token_markers)
        {
            tracing::warn!(
                file = %file.display(),
                reason,
                "Base NixOS config contains a hidden-environment reference"
            );
            return Ok(false);
        }
    }

    Ok(true)
}

/// Returns a short reason if `content_lower` contains any hidden-environment marker.
fn find_suspicious_marker(
    content_lower: &str,
    path_markers: &[String],
    token_markers: &[String],
) -> Option<&'static str> {
    // Fixed path patterns (substring match is appropriate for paths).
    if content_lower.contains("/mnt/hidden")
        || content_lower.contains("hidden/nixos")
        || content_lower.contains("/hidden/")
    {
        return Some("hidden path reference");
    }

    // Configured hidden root and backing device paths.
    for marker in path_markers {
        if content_lower.contains(marker.as_str()) {
            return Some("configured hidden volume or backing device reference");
        }
    }

    // Registry-driven content markers (the staged `/etc/nixos` import line and
    // any other substring NAILS writes into a file on the decoy side). Taking
    // these from the shared artifact registry keeps this check in step with what
    // activation actually writes, rather than re-hardcoding the import line here.
    for artifact in crate::artifacts::ARTIFACTS {
        if artifact.kind == crate::artifacts::ArtifactKind::ContentMarker
            && content_lower.contains(&artifact.value.to_lowercase())
        {
            return Some("staged NAILS content marker");
        }
    }

    if contains_bounded_ascii_token(content_lower, "hidden") {
        return Some("'hidden' keyword");
    }

    if contains_bounded_ascii_token(content_lower, "nails") {
        return Some("'nails' keyword");
    }

    // Backing device names (e.g. a device-mapper target) as bounded tokens.
    for token in token_markers {
        if contains_bounded_ascii_token(content_lower, token) {
            return Some("hidden volume backing device name");
        }
    }

    // Plausible deniability keywords (unlikely to appear legitimately).
    if content_lower.contains("plausible") || content_lower.contains("deniability") {
        return Some("plausible deniability keywords");
    }

    None
}

/// Resolves the backing source(s) that `/proc/self/mountinfo` reports for
/// `hidden_volume_root`, lowercased. Returns an empty list when the mount table
/// is unavailable or has no matching entry (path-only matching then applies).
fn resolve_backing_sources<F: Filesystem>(fs: &F, hidden_volume_root: &Path) -> Vec<String> {
    let Ok(mountinfo) = fs.read_file_content(Path::new(SELF_MOUNTINFO)) else {
        return Vec::new();
    };

    let mut sources = Vec::new();
    for line in mountinfo.lines() {
        // mountinfo: <pre> " - " <fstype> <source> <super_opts>
        // <pre> fields: mount_id parent_id major:minor root mount_point opts [optional...]
        let Some((pre, post)) = line.split_once(" - ") else {
            continue;
        };

        let mut pre_fields = pre.split(' ');
        // Field 5 (index 4) is the mount point; it may carry octal escapes.
        let Some(mount_point) = pre_fields.nth(4) else {
            continue;
        };
        if Path::new(&octal_unescape(mount_point)) != hidden_volume_root {
            continue;
        }

        // Post-separator fields: fstype, source, super_opts.
        let mut post_fields = post.split(' ');
        let Some(source) = post_fields.nth(1) else {
            continue;
        };
        sources.push(octal_unescape(source).to_lowercase());
    }

    sources
}

/// Decodes the octal escapes (`\040` space, `\011` tab, `\012` newline,
/// `\134` backslash, and any `\ooo`) that the kernel writes into mountinfo
/// fields. Non-escape bytes pass through unchanged.
fn octal_unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && matches!(bytes[i + 1], b'0'..=b'7')
            && matches!(bytes[i + 2], b'0'..=b'7')
            && matches!(bytes[i + 3], b'0'..=b'7')
        {
            // Compute in a wider type: a leading octal digit of 4-7 would
            // overflow `u8` (7 * 64 = 448) and panic in debug builds.
            let code = (u16::from(bytes[i + 1] - b'0') << 6)
                | (u16::from(bytes[i + 2] - b'0') << 3)
                | u16::from(bytes[i + 3] - b'0');
            out.push(code as u8);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }

    String::from_utf8_lossy(&out).into_owned()
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

#[cfg(test)]
mod octal_decode_tests {
    use super::octal_unescape;

    #[test]
    fn decodes_kernel_escapes_and_passes_through_plain_bytes() {
        assert_eq!(
            octal_unescape("/mnt/hidden\\040volume"),
            "/mnt/hidden volume"
        );
        assert_eq!(octal_unescape("a\\011b"), "a\tb");
        assert_eq!(octal_unescape("a\\134b"), "a\\b");
        assert_eq!(octal_unescape("/dev/mapper/vault"), "/dev/mapper/vault");
    }

    #[test]
    fn decodes_high_octal_value_without_overflow() {
        // A leading octal digit of 4-7 exceeds a single-byte product; the
        // decoder must widen the arithmetic instead of overflowing.
        assert_eq!(octal_unescape("\\101"), "A");
        assert_eq!(octal_unescape("\\176"), "~");
    }

    #[test]
    fn leaves_incomplete_escapes_untouched() {
        assert_eq!(octal_unescape("\\04"), "\\04");
        assert_eq!(octal_unescape("\\09x"), "\\09x");
    }
}
