//! NixOS Configuration Manipulation
//!
//! Provides functions for preparing, validating, and injecting NixOS
//! configuration overlays.
//!
//! # Key Concepts
//!
//! **Property 1: Forensically Clean Base**
//! Base /etc/nixos/hardware-configuration.nix contains zero evidence of
//! hidden environment. Indistinguishable from standard NixOS installation.
//!
//! **Property 2: Standard NixOS Mechanism**
//! Uses native NixOS `imports = [...]` array for configuration injection.
//! No custom patches or binary modifications required.
//!
//! **Property 3: Atomic Transitions**
//! Overlay mount is atomic (all-or-nothing). Config switch happens instantly
//! via /etc overlay. Clean rollback on failure.
//!
//! # Architecture
//!
//! The configuration overlay works by:
//! 1. Validating hidden storage has required NixOS configuration structure
//! 2. Staging a symlink from `{hidden}/etc/nixos/nails/configuration.nix` to
//!    `{hidden}/config/nixos/configuration.nix`
//! 3. Injecting an import statement into the overlayed hardware-configuration.nix
//! 4. The import resolves via the symlink to the hidden configuration

use crate::error::{NailsError, Result};
use crate::filesystem::Filesystem;
use std::path::{Path, PathBuf};

/// NixOS configuration overlay information
///
/// Contains paths to the key files in the NixOS configuration overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NixOSConfigInfo {
    /// Path to modified hardware-configuration.nix in hidden storage
    pub hardware_config_path: PathBuf,

    /// Path to hidden configuration.nix
    pub hidden_config_path: PathBuf,

    /// Path to etc/nixos overlay directory in hidden storage
    pub etc_nixos_overlay: PathBuf,
}

/// Strip Nix comments from source text (lines starting with # and /* */ blocks).
///
/// This is a lightweight sanitizer for import validation; it is not a full Nix parser.
fn strip_nix_comments(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_block_comment = false;

    while let Some(c) = chars.next() {
        if in_block_comment {
            if c == '*' && matches!(chars.peek(), Some('/')) {
                chars.next();
                in_block_comment = false;
            }
            continue;
        }

        if c == '/' && matches!(chars.peek(), Some('*')) {
            chars.next();
            in_block_comment = true;
            continue;
        }

        if c == '#' {
            // Skip to end of line, preserving newline.
            for next in chars.by_ref() {
                if next == '\n' {
                    output.push('\n');
                    break;
                }
            }
            continue;
        }

        output.push(c);
    }

    output
}

/// Return true if the hardware configuration contains the expected import.
///
/// This ignores comment-only references to avoid false positives.
pub fn contains_nails_import(content: &str) -> bool {
    let stripped = strip_nix_comments(content);
    stripped.contains("./nails/configuration.nix")
}

/// Validates and prepares NixOS configuration overlay
///
/// **Property 2: Standard NixOS Mechanism**
///
/// Uses native NixOS `imports = [...]` array for configuration injection.
/// The modified hardware-configuration.nix contains a standard import statement
/// that references the hidden configuration.nix. No custom patches or binary
/// modifications required.
///
/// **Property 3: Atomic Transitions**
///
/// Overlay mount is atomic (all-or-nothing). Config switch happens instantly
/// via /etc overlay. Clean rollback on failure.
///
/// Ensures hidden storage contains required NixOS configuration structure:
/// - `{hidden}/etc/nixos/hardware-configuration.nix` (modified with import)
/// - `{hidden}/config/nixos/configuration.nix` (hidden environment config)
///
/// The modified hardware-configuration.nix MUST contain an import line
/// referencing the hidden configuration.nix file.
///
/// See thesis design.tex Section 4.3.4 for full details on three critical
/// properties of the NixOS config overlay mechanism.
///
/// # Arguments
///
/// * `fs` - Filesystem implementation for testing
/// * `hidden_path` - Path to hidden storage root (e.g., `/mnt/hidden`)
///
/// # Returns
///
/// * `Ok(NixOSConfigInfo)` - Validated overlay paths
/// * `Err(NailsError::NixOSError)` - Validation failed
///
/// # Example
///
/// ```no_run
/// use nails_core::{RealFilesystem, nixos::prepare_nixos_config_overlay};
/// use std::path::PathBuf;
///
/// let fs = RealFilesystem;
/// let hidden_path = PathBuf::from("/mnt/hidden");
///
/// let config_info = prepare_nixos_config_overlay(&fs, &hidden_path)?;
/// # Ok::<(), nails_core::NailsError>(())
/// ```
pub fn prepare_nixos_config_overlay<F: Filesystem>(
    fs: &F,
    hidden_path: &Path,
) -> Result<NixOSConfigInfo> {
    let etc_nixos = hidden_path.join("etc/nixos");
    let hardware_config = etc_nixos.join("hardware-configuration.nix");
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");

    // Validate etc/nixos directory exists
    if !fs.path_exists(&etc_nixos)? {
        return Err(NailsError::NixOSError(format!(
            "Hidden storage missing etc/nixos directory: {}",
            etc_nixos.display()
        )));
    }

    // Validate modified hardware-configuration.nix exists
    if !fs.path_exists(&hardware_config)? {
        return Err(NailsError::NixOSError(format!(
            "Modified hardware-configuration.nix not found at {}",
            hardware_config.display()
        )));
    }

    // Validate hidden configuration.nix exists at new location
    if !fs.path_exists(&hidden_config)? {
        return Err(NailsError::NixOSError(format!(
            "Hidden configuration.nix not found at {}",
            hidden_config.display()
        )));
    }

    // Validate modified config contains relative import to hidden config via nails/ symlink
    let content = fs.read_file_content(&hardware_config)?;
    let expected_import = "./nails/configuration.nix";

    if !contains_nails_import(&content) {
        return Err(NailsError::NixOSError(format!(
            "Modified hardware-configuration.nix does not contain required import: {}",
            expected_import
        )));
    }

    Ok(NixOSConfigInfo {
        hardware_config_path: hardware_config,
        hidden_config_path: hidden_config,
        etc_nixos_overlay: etc_nixos,
    })
}

/// Stage the hidden config symlink into the hidden /etc/nixos tree (Story 15.2)
///
/// Creates `{hidden}/etc/nixos/nails/` directory (if missing) and a symlink
/// `{hidden}/etc/nixos/nails/configuration.nix` → `{hidden}/config/nixos/configuration.nix`.
///
/// This is idempotent: if the directory and symlink already exist and are correct,
/// this function succeeds without any change.
///
/// After activation the overlay places `{hidden}/etc/nixos/` over `/etc/nixos/`, so
/// `/etc/nixos/nails/configuration.nix` resolves to the hidden config. The relative
/// import `./nails/configuration.nix` in hardware-configuration.nix then picks it up.
///
/// # Arguments
///
/// * `fs` - Filesystem implementation
/// * `hidden_path` - Path to hidden storage root (e.g., `/mnt/hidden`)
///
/// # Errors
///
/// Returns `NailsError::NixOSError` if directory creation or symlink creation fails.
pub fn stage_hidden_config_symlink<F: Filesystem>(fs: &F, hidden_path: &Path) -> Result<()> {
    let nails_dir = hidden_path.join("etc/nixos/nails");
    let symlink_path = nails_dir.join("configuration.nix");
    let symlink_target = hidden_path.join("config/nixos/configuration.nix");

    // Ensure the hidden config exists before staging the link.
    if !fs.path_exists(&symlink_target)? {
        return Err(NailsError::NixOSError(format!(
            "Hidden configuration.nix not found at {}",
            symlink_target.display()
        )));
    }

    // Create {hidden}/etc/nixos/nails/ if it doesn't exist (idempotent)
    if !fs.path_exists(&nails_dir)? {
        fs.create_directory(&nails_dir).map_err(|e| {
            NailsError::NixOSError(format!(
                "Failed to create directory {}: {}",
                nails_dir.display(),
                e
            ))
        })?;
    }

    // Create symlink (idempotent: no-op if it already points to the correct target)
    fs.create_symlink(&symlink_target, &symlink_path)
        .map_err(|e| {
            NailsError::NixOSError(format!(
                "Failed to create symlink {} -> {}: {}",
                symlink_path.display(),
                symlink_target.display(),
                e
            ))
        })?;

    Ok(())
}

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
    if content_lower.contains("/mnt/hidden")
        || content_lower.contains("hidden/nixos")
        || content_lower.contains("/hidden/")
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

/// Ensure the hardware configuration includes the NAILS import block.
///
/// Returns updated content when the import is missing, or the original content
/// when the import is already present (idempotent).
pub fn ensure_nails_import_block(content: &str) -> String {
    if contains_active_path(content, "./nails/configuration.nix") {
        return content.to_string();
    }

    const NAILS_ENTRY: &str = "    ./nails/configuration.nix";
    const INJECTED_BLOCK: &str =
        "# NAILS: injected import (do not edit)\nimports = [\n  ./nails/configuration.nix\n];\n\n";

    if let Some(imports_pos) = find_imports_bracket(content) {
        // An imports = [ ... ] block exists — insert our entry as the first element.
        let (before, after) = content.split_at(imports_pos);
        format!("{}{}\n{}", before, NAILS_ENTRY, after)
    } else {
        // No imports block — prepend a complete one.
        format!("{}{}", INJECTED_BLOCK, content)
    }
}

/// Injects a NAILS import block into the overlayed `/etc/nixos/hardware-configuration.nix`.
///
/// This function must be called **after** the `/etc` overlay has been mounted so that
/// writes land in the overlay upper layer, leaving the base underlay forensically clean.
///
/// ## Injection behaviour
///
/// * If no `imports` attribute exists in the file, a complete block is **prepended**:
///   ```nix
///   # NAILS: injected import (do not edit)
///   imports = [
///     ./nails/configuration.nix
///   ];
///   ```
/// * If an `imports = [` attribute already exists, `./nails/configuration.nix` is inserted
///   as the **first** element without adding a second `imports` attribute.
/// * If `./nails/configuration.nix` is already present the function is a **no-op**
///   (idempotent).
///
/// ## Errors
///
/// Returns `Err(NailsError::NixOSError)` on permission or I/O failure.
pub fn inject_import_block<F: Filesystem>(fs: &F) -> Result<()> {
    let target = PathBuf::from("/etc/nixos/hardware-configuration.nix");

    if !fs.path_exists(&target)? {
        // Non-NixOS systems may not have this file — skip injection gracefully.
        tracing::debug!(
            "inject_import_block: /etc/nixos/hardware-configuration.nix not found, skipping (non-NixOS system?)"
        );
        return Ok(());
    }

    let content = fs.read_file_content(&target)?;

    let new_content = ensure_nails_import_block(&content);
    if new_content == content {
        tracing::debug!("inject_import_block: ./nails/configuration.nix already present, skipping");
        return Ok(());
    }

    fs.write_file_content(&target, &new_content)?;
    tracing::info!(
        "inject_import_block: injected ./nails/configuration.nix into {}",
        target.display()
    );
    Ok(())
}

/// Returns the byte offset of the character **immediately after** the opening `[` of the
/// first `imports = [` (or `imports=[`) attribute found in `content`, so that a new entry
/// can be inserted there as the first element.
///
/// Returns `None` if no `imports` attribute is present.
fn find_imports_bracket(content: &str) -> Option<usize> {
    // Match `imports` followed by optional whitespace, `=`, optional whitespace, `[`
    let bytes = content.as_bytes();
    let search = b"imports";

    let mut i = 0usize;
    let mut in_string = false;
    let mut in_comment = false;

    while i < bytes.len() {
        let b = bytes[i];

        if in_comment {
            if b == b'\n' {
                in_comment = false;
            }
            i += 1;
            continue;
        }

        if in_string {
            if b == b'\\' {
                // Skip escaped char in string
                i = i.saturating_add(2);
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        if b == b'#' {
            in_comment = true;
            i += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
            i += 1;
            continue;
        }

        if i + search.len() > bytes.len() {
            break;
        }

        if &bytes[i..i + search.len()] != search {
            i += 1;
            continue;
        }

        // Ensure we're not matching a larger identifier or dotted access (e.g., config.imports)
        let prev = if i == 0 { None } else { Some(bytes[i - 1]) };
        if prev.is_some_and(|p| is_ident_char(p) || p == b'.') {
            i += 1;
            continue;
        }
        let next = bytes.get(i + search.len()).copied();
        if next.is_some_and(is_ident_char) {
            i += 1;
            continue;
        }

        // Skip whitespace after "imports"
        let mut j = i + search.len();
        while j < bytes.len() && is_whitespace(bytes[j]) {
            j += 1;
        }
        // Expect '='
        if j >= bytes.len() || bytes[j] != b'=' {
            i += 1;
            continue;
        }
        j += 1;
        // Skip whitespace after '='
        while j < bytes.len() && is_whitespace(bytes[j]) {
            j += 1;
        }
        // Expect '['
        if j >= bytes.len() || bytes[j] != b'[' {
            i += 1;
            continue;
        }
        // Return position right after the '[', then skip to the next line start so our
        // inserted entry appears on its own line.
        j += 1; // move past '['
        if j < bytes.len() && bytes[j] == b'\n' {
            j += 1;
        }
        return Some(j);
    }
    None
}

fn contains_active_path(content: &str, path: &str) -> bool {
    let bytes = content.as_bytes();
    let needle = path.as_bytes();

    let mut i = 0usize;
    let mut in_string = false;
    let mut in_comment = false;

    while i < bytes.len() {
        let b = bytes[i];

        if in_comment {
            if b == b'\n' {
                in_comment = false;
            }
            i += 1;
            continue;
        }

        if in_string {
            if b == b'\\' {
                i = i.saturating_add(2);
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        if b == b'#' {
            in_comment = true;
            i += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
            i += 1;
            continue;
        }

        if i + needle.len() <= bytes.len() && &bytes[i..i + needle.len()] == needle {
            return true;
        }

        i += 1;
    }

    false
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn is_whitespace(b: u8) -> bool {
    b == b' ' || b == b'\t' || b == b'\n' || b == b'\r'
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;

    #[test]
    fn test_prepare_nixos_config_overlay_success() {
        let fs = MockFilesystem::new();
        let hidden_path = std::path::PathBuf::from("/mnt/hidden");

        // Setup filesystem structure using mock
        fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");
        fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", "file");

        let etc_nixos = hidden_path.join("etc/nixos");
        let hardware_config = etc_nixos.join("hardware-configuration.nix");
        let hidden_config = hidden_path.join("config/nixos/configuration.nix");

        // Create file content with import
        fs.write_file_content(&hardware_config, "imports = [ ./nails/configuration.nix ];")
            .unwrap();
        fs.write_file_content(&hidden_config, "{ ... }: { }")
            .unwrap();

        // Validate overlay
        let result = prepare_nixos_config_overlay(&fs, &hidden_path).unwrap();

        assert_eq!(result.hardware_config_path, hardware_config);
        assert_eq!(result.hidden_config_path, hidden_config);
        assert_eq!(result.etc_nixos_overlay, etc_nixos);
    }

    #[test]
    fn test_verify_base_config_clean_success() {
        let fs = MockFilesystem::new();
        let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

        // Create base config with no suspicious patterns
        fs.write_file_content(&base_config, "{ config, pkgs, ... }: { }")
            .unwrap();

        let is_clean = verify_base_config_clean(&fs).unwrap();
        assert!(is_clean, "Base config should be clean");
    }

    #[test]
    fn test_verify_base_config_clean_suspicious_hidden_path() {
        let fs = MockFilesystem::new();
        let base_config = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

        // Create base config with suspicious /mnt/hidden reference
        fs.write_file_content(&base_config, "{ fileSystems.\"/mnt/hidden\" = { }; }")
            .unwrap();

        let is_clean = verify_base_config_clean(&fs).unwrap();
        assert!(
            !is_clean,
            "Base config should not be clean with /mnt/hidden"
        );
    }

    #[test]
    fn test_inject_import_block_no_imports_prepends_full_block() {
        let fs = MockFilesystem::new();
        let target = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

        // Create base config without imports
        let original = "{ config, pkgs, ... }: {\n  boot.loader.grub.enable = true;\n}";
        fs.write_file_content(&target, original).unwrap();

        // Inject import block
        inject_import_block(&fs).unwrap();

        // Verify import was prepended
        let content = fs.read_file_content(&target).unwrap();
        assert!(content.contains("# NAILS: injected import"));
        assert!(content.contains("imports = ["));
        assert!(content.contains("./nails/configuration.nix"));
        assert!(
            content.contains(original),
            "Original content should be preserved"
        );
    }

    #[test]
    fn test_inject_import_block_idempotent_when_already_injected() {
        let fs = MockFilesystem::new();
        let target = std::path::PathBuf::from("/etc/nixos/hardware-configuration.nix");

        // Create config that already has the import
        let original = "imports = [ ./nails/configuration.nix ];\n{ config, pkgs, ... }: { }";
        fs.write_file_content(&target, original).unwrap();

        // Inject import block (should be no-op)
        inject_import_block(&fs).unwrap();

        // Verify content unchanged
        let content = fs.read_file_content(&target).unwrap();
        assert_eq!(
            content, original,
            "Content should be unchanged (idempotent)"
        );
    }

    #[test]
    fn test_stage_hidden_config_symlink_creates_dir_and_symlink() {
        let fs = MockFilesystem::new();
        let hidden_path = std::path::PathBuf::from("/mnt/hidden");

        // Setup hidden config
        fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");
        fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", "file");
        let hidden_config = hidden_path.join("config/nixos/configuration.nix");
        fs.write_file_content(&hidden_config, "{ }").unwrap();

        // Stage symlink
        stage_hidden_config_symlink(&fs, &hidden_path).unwrap();

        // Verify nails directory was created
        let nails_dir = hidden_path.join("etc/nixos/nails");
        assert!(
            fs.path_exists(&nails_dir).unwrap(),
            "nails directory should exist"
        );

        // Verify symlink was created
        let symlink_path = nails_dir.join("configuration.nix");
        assert!(
            fs.path_exists(&symlink_path).unwrap(),
            "symlink should exist"
        );
    }
}
