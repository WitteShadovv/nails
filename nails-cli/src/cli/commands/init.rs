//! Init command handler
//!
//! Bootstraps the NAILS directory structure on a hidden volume.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::cli::args::InitArgs;
use nails_core::config::CONFIG_FILE_NAME;
use nails_core::{
    RealFilesystem, ensure_hidden_hardware_configuration, stage_hidden_config_symlink,
};

/// Required subdirectories to create
const SUBDIRS: &[&str] = &[
    "overlays",
    "logs",
    "config",
    "config/nixos",
    "etc",
    "etc/nixos",
    "home",
    "nix",
    ".work",
    ".work/etc",
    ".work/home",
    ".work/nix",
];

/// Execute the init command
pub fn execute(args: InitArgs) -> Result<(), Box<dyn std::error::Error>> {
    execute_with_base_hardware_config(args, Path::new("/etc/nixos/hardware-configuration.nix"))
}

fn execute_with_base_hardware_config(
    args: InitArgs,
    base_hardware_config: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let base = &args.path;

    // Validate the path exists
    if !base.exists() {
        return Err(format!("Path does not exist: {}", base.display()).into());
    }

    if !base.is_dir() {
        return Err(format!("Path is not a directory: {}", base.display()).into());
    }

    // Create subdirectories with 0700 permissions
    for dir_name in SUBDIRS {
        let dir = base.join(dir_name);
        create_dir_0700(&dir)?;
        println!("  Created {}/", dir.display());
    }

    // Generate starter config
    let config_path = base.join("config").join(CONFIG_FILE_NAME);
    if config_path.exists() {
        println!("  Skipped {} (already exists)", config_path.display());
    } else {
        fs::write(&config_path, nails_core::Config::init_template(base))?;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&config_path, perms)?;
        println!("  Created {}", config_path.display());
    }

    create_initial_state_file(base)?;

    bootstrap_hidden_nixos_layout(base, base_hardware_config)?;

    println!();
    println!(
        "NAILS directory structure initialized at {}",
        base.display()
    );

    Ok(())
}

fn bootstrap_hidden_nixos_layout(
    base: &Path,
    base_hardware_config: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let fs = RealFilesystem;

    stage_hidden_config_symlink(&fs, base)?;
    ensure_hidden_hardware_configuration(&fs, base, base_hardware_config)?;

    println!("  Ensured {}/", base.join("etc/nixos/nails").display());
    println!(
        "  Ensured {}",
        base.join("etc/nixos/hardware-configuration.nix").display()
    );
    println!(
        "  Ensured {}",
        base.join("config/nixos/configuration.nix").display()
    );

    Ok(())
}

/// Create a directory with 0700 permissions, no-op if it already exists
fn create_dir_0700(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    let perms = fs::Permissions::from_mode(0o700);
    fs::set_permissions(path, perms)?;
    Ok(())
}

fn create_initial_state_file(base: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let state_path = base.join("state.json");

    // Hold the exclusive state lock while touching the state file, so init cannot
    // race a concurrent activate/deactivate over the same hidden volume.
    let _state_lock = nails_core::StateLock::try_acquire(base).map_err(|e| e.to_string())?;

    if state_path.exists() {
        if !state_path.is_file() {
            return Err(format!(
                "State path exists but is not a file: {}",
                state_path.display()
            )
            .into());
        }
        println!("  Skipped {} (already exists)", state_path.display());
        return Ok(());
    }

    nails_core::StateFile::default().save_with_custom_root(&state_path, base)?;
    println!("  Created {}", state_path.display());

    Ok(())
}

#[cfg(test)]
mod tests;
