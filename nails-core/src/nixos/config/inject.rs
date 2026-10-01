//! NixOS hardware-configuration wrapper staging and parse checking.

use super::{HARDWARE_BASE_CONFIG_FILE, HARDWARE_CONFIG_FILE, HARDWARE_WRAPPER};
use crate::error::Result;
use crate::filesystem::Filesystem;
use crate::process::{ProcessCommand, ProcessRunner, RealProcessRunner};
use std::path::Path;

/// Ensures the overlayed `/etc/nixos/hardware-configuration.nix` is the NAILS wrapper.
///
/// This must be called **after** the `/etc` overlay has been mounted so that
/// writes land in the overlay upper layer, leaving the base underlay
/// forensically clean.
///
/// ## Behaviour
///
/// Instead of editing the original Nix source, the original file is preserved
/// verbatim as `hardware-configuration.base.nix` and `hardware-configuration.nix`
/// is replaced with a fixed wrapper that imports the base file and the hidden
/// module ([`HARDWARE_WRAPPER`]). The wrapper is a constant, so the result is
/// always valid Nix no matter how the original file was written.
///
/// The function is idempotent: once the base file exists and the live file is
/// already the wrapper, it is a no-op. On a non-NixOS system (no
/// `hardware-configuration.nix`) it skips gracefully.
///
/// ## Errors
///
/// Returns `Err(NailsError::NixOSError)` on permission or I/O failure.
pub fn inject_import_block<F: Filesystem>(fs: &F) -> Result<()> {
    let dir = Path::new("/etc/nixos");
    let hardware = dir.join(HARDWARE_CONFIG_FILE);

    if !fs.path_exists(&hardware)? {
        // Non-NixOS systems may not have this file — skip gracefully.
        tracing::debug!(
            "inject_import_block: {} not found, skipping (non-NixOS system?)",
            hardware.display()
        );
        return Ok(());
    }

    if ensure_hardware_wrapper(fs, dir)? {
        tracing::info!(
            "inject_import_block: staged hardware-configuration wrapper under {}",
            dir.display()
        );
    } else {
        tracing::debug!("inject_import_block: hardware-configuration wrapper already in place");
    }
    Ok(())
}

/// Ensures `hardware-configuration.nix` under `dir` is the NAILS wrapper, with
/// the original preserved as `hardware-configuration.base.nix`.
///
/// Returns `Ok(true)` when a write was performed and `Ok(false)` when nothing
/// changed (already wrapped). The caller guarantees `hardware-configuration.nix`
/// exists unless the base file is already present.
pub(crate) fn ensure_hardware_wrapper<F: Filesystem>(fs: &F, dir: &Path) -> Result<bool> {
    let hardware = dir.join(HARDWARE_CONFIG_FILE);
    let base = dir.join(HARDWARE_BASE_CONFIG_FILE);

    if fs.path_exists(&base)? {
        // The original is already preserved; make sure the live file is the
        // wrapper (idempotent — second run is a no-op).
        if fs.path_exists(&hardware)? && fs.read_file_content(&hardware)? == HARDWARE_WRAPPER {
            return Ok(false);
        }
        fs.write_file_content(&hardware, HARDWARE_WRAPPER)?;
        return Ok(true);
    }

    // First run: preserve the original verbatim, then install the wrapper.
    let original = fs.read_file_content(&hardware)?;
    if original == HARDWARE_WRAPPER {
        // Wrapper present without a base file: there is nothing to preserve, and
        // writing the base from the wrapper would make it import itself. Leave
        // the live file untouched rather than create that cycle.
        return Ok(false);
    }
    fs.write_file_content(&base, &original)?;
    fs.write_file_content(&hardware, HARDWARE_WRAPPER)?;
    Ok(true)
}

/// Parses Nix source files without evaluating them.
///
/// Implementations check only syntax; they never evaluate expressions, follow
/// imports, or copy anything into a Nix store.
pub trait NixParser: Send + Sync + std::fmt::Debug {
    /// Parse the file at `path`.
    ///
    /// Returns `Ok(())` when the file parses, or `Err(message)` carrying the
    /// parser's diagnostic when it does not.
    fn parse_file(&self, path: &Path) -> std::result::Result<(), String>;
}

/// Parses Nix files with `nix-instantiate --parse`.
///
/// `--parse` lexes and parses the single named file only: it does not evaluate
/// it, follow its imports, or realise anything into a store. In test and
/// test-like runtimes the host guard refuses external programs, so the parse is
/// skipped there; the gate is a production defence exercised through an injected
/// parser in unit tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealNixParser;

impl NixParser for RealNixParser {
    fn parse_file(&self, path: &Path) -> std::result::Result<(), String> {
        if crate::runtime_safety::should_skip_host_interaction() {
            return Ok(());
        }

        let command = ProcessCommand::tool("nix-instantiate")
            .arg("--parse")
            .arg(path);
        match RealProcessRunner.run_text(&command) {
            Ok((true, _, _)) => Ok(()),
            Ok((false, _, stderr)) => {
                let message = stderr.trim();
                if message.is_empty() {
                    Err("nix-instantiate --parse reported a syntax error".to_string())
                } else {
                    Err(message.to_string())
                }
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Parse-checks the composed hardware configuration under `etc_nixos_dir`.
///
/// Parses the wrapper, the preserved base file, and the hidden module, in that
/// order, skipping any that do not exist (they are created elsewhere; this gate
/// only rejects files that exist and fail to parse). `nix-instantiate --parse`
/// does not follow imports, so each file is parsed explicitly. Returns the first
/// parser error, prefixed with the offending path.
pub fn parse_check_composed_config<F: Filesystem>(
    parser: &dyn NixParser,
    fs: &F,
    etc_nixos_dir: &Path,
    hidden_module: &Path,
) -> Result<std::result::Result<(), String>> {
    let candidates = [
        etc_nixos_dir.join(HARDWARE_CONFIG_FILE),
        etc_nixos_dir.join(HARDWARE_BASE_CONFIG_FILE),
        hidden_module.to_path_buf(),
    ];

    for file in candidates {
        if !fs.path_exists(&file)? {
            continue;
        }
        if let Err(message) = parser.parse_file(&file) {
            return Ok(Err(format!("{}: {}", file.display(), message)));
        }
    }

    Ok(Ok(()))
}
