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
    let expected_import = "./nails/configuration.nix";

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
        package = "ripgrep",
        "Auto-generated minimal hidden configuration.nix"
    );

    Ok(())
}

pub fn ensure_hidden_hardware_configuration<F: Filesystem>(
    fs: &F,
    hidden_path: &Path,
    base_hardware_config: &Path,
) -> Result<()> {
    let hidden_etc_nixos = hidden_path.join("etc/nixos");
    let hidden_hardware = hidden_etc_nixos.join("hardware-configuration.nix");

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

    let hidden_exists = fs.path_exists(&hidden_hardware)?;
    let source_content = if hidden_exists {
        fs.read_file_content(&hidden_hardware).map_err(|e| {
            NailsError::NixOSError(format!(
                "Failed to read hidden hardware-configuration.nix at {}: {}",
                hidden_hardware.display(),
                e
            ))
        })?
    } else {
        fs.read_file_content(base_hardware_config).map_err(|e| {
            NailsError::NixOSError(format!(
                "Failed to bootstrap hidden hardware-configuration.nix from {}: {}",
                base_hardware_config.display(),
                e
            ))
        })?
    };

    let ensured_content = super::ensure_nails_import_block(&source_content);
    if !hidden_exists || ensured_content != source_content {
        fs.write_file_content(&hidden_hardware, &ensured_content)
            .map_err(|e| {
                NailsError::NixOSError(format!(
                    "Failed to write hidden hardware-configuration.nix at {}: {}",
                    hidden_hardware.display(),
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
