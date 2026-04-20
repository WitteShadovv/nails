//! NixOS configuration import injection and Nix source parsing helpers.

use crate::error::Result;
use crate::filesystem::Filesystem;
use std::path::PathBuf;

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
