//! Configuration preparation: validate and stage NixOS config overlay.

use crate::error::{NailsError, Result};
use crate::filesystem::Filesystem;
use std::path::Path;

use super::{AUTO_GENERATED_HIDDEN_CONFIGURATION, NixOSConfigInfo};

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
    let expected_import = crate::artifacts::NIXOS_IMPORT_MARKER;

    if !super::contains_nails_import(&content) {
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

pub fn ensure_hidden_configuration_module<F: Filesystem>(fs: &F, hidden_path: &Path) -> Result<()> {
    let config_dir = hidden_path.join("config/nixos");
    let hidden_config = config_dir.join("configuration.nix");

    if !fs.path_exists(&config_dir)? {
        fs.create_directory(&config_dir).map_err(|e| {
            NailsError::NixOSError(format!(
                "Failed to create hidden config directory {}: {}",
                config_dir.display(),
                e
            ))
        })?;
    }

    fs.set_permissions(&config_dir, 0o700).map_err(|e| {
        NailsError::NixOSError(format!(
            "Failed to set permissions on hidden config directory {}: {}",
            config_dir.display(),
            e
        ))
    })?;

    if fs.path_exists(&hidden_config)? {
        fs.set_permissions(&hidden_config, 0o600).map_err(|e| {
            NailsError::NixOSError(format!(
                "Failed to set permissions on hidden configuration.nix at {}: {}",
                hidden_config.display(),
                e
            ))
        })?;
        return Ok(());
    }

    fs.write_file_content(&hidden_config, AUTO_GENERATED_HIDDEN_CONFIGURATION)
        .map_err(|e| {
            NailsError::NixOSError(format!(
                "Failed to auto-generate hidden configuration.nix at {}: {}",
                hidden_config.display(),
                e
            ))
        })?;

    fs.set_permissions(&hidden_config, 0o600).map_err(|e| {
        NailsError::NixOSError(format!(
            "Failed to set permissions on hidden configuration.nix at {}: {}",
            hidden_config.display(),
            e
        ))
    })?;

    tracing::info!(
        path = %hidden_config.display(),
        "Seeded the hidden configuration.nix template (all settings commented out)"
    );

    Ok(())
}

/// Stages the hidden `/etc/nixos` hardware configuration as a wrapper.
///
/// The original hardware configuration is preserved verbatim as
/// `hardware-configuration.base.nix` and `hardware-configuration.nix` becomes a
/// fixed wrapper that imports the base file plus `./nails/configuration.nix`
/// (see [`super::HARDWARE_WRAPPER`]). This never edits Nix source text, so the
/// staged file is always valid Nix regardless of the original's shape.
///
/// On a fresh hidden store (neither file present) the base is seeded from
/// `base_hardware_config` (the decoy `/etc/nixos/hardware-configuration.nix`). An
/// existing store is migrated in place and left unchanged on subsequent runs.
pub fn ensure_hidden_hardware_configuration<F: Filesystem>(
    fs: &F,
    hidden_path: &Path,
    base_hardware_config: &Path,
) -> Result<()> {
    let hidden_etc_nixos = hidden_path.join("etc/nixos");
    let hidden_hardware = hidden_etc_nixos.join(super::HARDWARE_CONFIG_FILE);
    let hidden_base = hidden_etc_nixos.join(super::HARDWARE_BASE_CONFIG_FILE);

    if !fs.path_exists(&hidden_etc_nixos)? {
        fs.create_directory(&hidden_etc_nixos).map_err(|e| {
            NailsError::NixOSError(format!(
                "Failed to create hidden etc/nixos directory {}: {}",
                hidden_etc_nixos.display(),
                e
            ))
        })?;
    }

    fs.set_permissions(&hidden_etc_nixos, 0o700).map_err(|e| {
        NailsError::NixOSError(format!(
            "Failed to set permissions on hidden etc/nixos directory {}: {}",
            hidden_etc_nixos.display(),
            e
        ))
    })?;

    let base_exists = fs.path_exists(&hidden_base)?;
    let hardware_exists = fs.path_exists(&hidden_hardware)?;

    if !base_exists && !hardware_exists {
        // Fresh hidden store: seed the base from the decoy hardware config, then
        // install the wrapper.
        let raw_seed = fs.read_file_content(base_hardware_config).map_err(|e| {
            NailsError::NixOSError(format!(
                "Failed to bootstrap hidden hardware-configuration.nix from {}: {}",
                base_hardware_config.display(),
                e
            ))
        })?;
        // Never carry the decoy's swap or hibernation into the hidden system: a
        // switch-to-configuration would re-enable a disk swap the operator turned
        // off, paging hidden-session memory to the decoy disk.
        let (seed, neutralized) = neutralize_swap_in_hardware_config(&raw_seed);
        if neutralized {
            tracing::warn!(
                "Stripped swapDevices/resumeDevice from the seeded hidden hardware configuration \
                 to keep the hidden system free of disk swap and hibernation"
            );
        }
        fs.write_file_content(&hidden_base, &seed).map_err(|e| {
            NailsError::NixOSError(format!(
                "Failed to write hidden hardware-configuration.base.nix at {}: {}",
                hidden_base.display(),
                e
            ))
        })?;
        fs.write_file_content(&hidden_hardware, super::HARDWARE_WRAPPER)
            .map_err(|e| {
                NailsError::NixOSError(format!(
                    "Failed to write hidden hardware-configuration.nix at {}: {}",
                    hidden_hardware.display(),
                    e
                ))
            })?;
    } else {
        // Existing store: ensure the wrapper (idempotent; an older in-place
        // edited file is preserved verbatim as the base on first migration).
        super::inject::ensure_hardware_wrapper(fs, &hidden_etc_nixos).map_err(|e| {
            NailsError::NixOSError(format!(
                "Failed to stage hidden hardware-configuration wrapper at {}: {}",
                hidden_hardware.display(),
                e
            ))
        })?;
    }

    if fs.path_exists(&hidden_base)? {
        fs.set_permissions(&hidden_base, 0o600).map_err(|e| {
            NailsError::NixOSError(format!(
                "Failed to set permissions on hidden hardware-configuration.base.nix at {}: {}",
                hidden_base.display(),
                e
            ))
        })?;
    }

    fs.set_permissions(&hidden_hardware, 0o600).map_err(|e| {
        NailsError::NixOSError(format!(
            "Failed to set permissions on hidden hardware-configuration.nix at {}: {}",
            hidden_hardware.display(),
            e
        ))
    })?;

    Ok(())
}

/// Comment out any active `swapDevices` definition and `resumeDevice` line in a
/// `hardware-configuration.nix`, returning the rewritten text and whether
/// anything was changed.
///
/// This works at the line level rather than parsing Nix: it comments the
/// `swapDevices` assignment (single- or multi-line) and any `resumeDevice` /
/// `boot.resumeDevice` line. An already-empty `swapDevices = [ ];` is left
/// untouched so the common NixOS default does not trigger a spurious warning.
/// Commenting is conservative: valid Nix stays valid, and the hidden system
/// simply inherits no swap or hibernation from the decoy.
fn neutralize_swap_in_hardware_config(content: &str) -> (String, bool) {
    let mut out = String::with_capacity(content.len() + 32);
    let mut changed = false;
    let mut in_swap_block = false;

    for line in content.lines() {
        if in_swap_block {
            out.push_str("# ");
            out.push_str(line);
            out.push('\n');
            changed = true;
            if line.contains(']') {
                in_swap_block = false;
            }
            continue;
        }

        let trimmed = line.trim_start();

        if trimmed.starts_with("swapDevices") {
            let opens = line.contains('[');
            let closes = line.contains(']');
            // `swapDevices = [ ];` with nothing between the brackets is already
            // empty; leave it so the NixOS default does not warn.
            if opens
                && closes
                && let (Some(open), Some(close)) = (line.find('['), line.rfind(']'))
                && close > open
                && line[open + 1..close].trim().is_empty()
            {
                out.push_str(line);
                out.push('\n');
                continue;
            }
            out.push_str("# ");
            out.push_str(line);
            out.push('\n');
            changed = true;
            // Multi-line definition (`swapDevices =` then the list on later
            // lines): keep commenting until the closing bracket.
            if !closes {
                in_swap_block = true;
            }
            continue;
        }

        if trimmed.starts_with("resumeDevice") || trimmed.starts_with("boot.resumeDevice") {
            out.push_str("# ");
            out.push_str(line);
            out.push('\n');
            changed = true;
            continue;
        }

        out.push_str(line);
        out.push('\n');
    }

    (out, changed)
}

/// Stage the complete hidden NixOS config before pre-flight checks run.
///
/// Combines [`stage_hidden_config_symlink`] (the hidden module and the
/// `./nails/configuration.nix` symlink) with [`ensure_hidden_hardware_configuration`]
/// (the wrapper that imports it). Activation calls this before the pre-flight
/// phase so the read-only `nixos-config` check only has to validate what staging
/// produced instead of creating files itself. The hardware wrapper is skipped in
/// overlay-only mode, where no NixOS profile switch happens and
/// `/etc/nixos/hardware-configuration.nix` may not exist.
pub fn stage_hidden_nixos_config<F: Filesystem>(
    fs: &F,
    hidden_path: &Path,
    overlay_only: bool,
) -> Result<()> {
    stage_hidden_config_symlink(fs, hidden_path)?;

    if !overlay_only {
        let base_hardware_config = Path::new("/etc/nixos/hardware-configuration.nix");
        ensure_hidden_hardware_configuration(fs, hidden_path, base_hardware_config)?;
    }

    Ok(())
}

/// Stage the hidden config symlink into the hidden /etc/nixos tree
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

    ensure_hidden_configuration_module(fs, hidden_path)?;

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

    fs.set_permissions(&nails_dir, 0o700).map_err(|e| {
        NailsError::NixOSError(format!(
            "Failed to set permissions on hidden nails config directory {}: {}",
            nails_dir.display(),
            e
        ))
    })?;

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

#[cfg(test)]
mod swap_neutralize_tests {
    use super::neutralize_swap_in_hardware_config;

    #[test]
    fn single_line_swap_devices_is_commented() {
        let input = "{\n  swapDevices = [ { device = \"/dev/sda2\"; } ];\n}\n";
        let (out, changed) = neutralize_swap_in_hardware_config(input);
        assert!(changed);
        assert!(out.contains("# "), "{out}");
        for line in out.lines() {
            if line.contains("/dev/sda2") {
                assert!(line.trim_start().starts_with('#'), "{line}");
            }
        }
    }

    #[test]
    fn multi_line_swap_devices_is_fully_commented() {
        let input = "{\n  swapDevices =\n    [ { device = \"/dev/sda2\"; }\n      { device = \"/dev/sdb2\"; }\n    ];\n}\n";
        let (out, changed) = neutralize_swap_in_hardware_config(input);
        assert!(changed);
        for line in out.lines() {
            if line.contains("/dev/sd") || line.trim_start().starts_with("];") {
                assert!(
                    line.trim_start().starts_with('#'),
                    "line not commented: {line}"
                );
            }
        }
    }

    #[test]
    fn empty_swap_devices_is_left_untouched() {
        let input = "{\n  swapDevices = [ ];\n}\n";
        let (out, changed) = neutralize_swap_in_hardware_config(input);
        assert!(!changed);
        assert!(out.contains("swapDevices = [ ];"));
    }

    #[test]
    fn resume_device_is_commented() {
        let input = "{\n  boot.resumeDevice = \"/dev/sda2\";\n}\n";
        let (out, changed) = neutralize_swap_in_hardware_config(input);
        assert!(changed);
        for line in out.lines() {
            if line.contains("resumeDevice") {
                assert!(line.trim_start().starts_with('#'), "{line}");
            }
        }
    }

    #[test]
    fn config_without_swap_is_unchanged() {
        let input = "{\n  imports = [ ./hardware.nix ];\n}\n";
        let (out, changed) = neutralize_swap_in_hardware_config(input);
        assert!(!changed);
        assert_eq!(out, input);
    }
}
