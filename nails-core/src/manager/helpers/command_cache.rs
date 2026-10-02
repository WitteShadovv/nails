use crate::process::run::{LDD_BUDGET, ProcessCommand, ProcessRunner, RealProcessRunner};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub(super) enum CachedCommand {
    Direct(PathBuf),
    ViaLoader {
        display_path: PathBuf,
        loader: PathBuf,
        library_path: OsString,
        program: PathBuf,
    },
}

impl CachedCommand {
    pub(super) fn display_path(&self) -> &Path {
        match self {
            Self::Direct(path) => path,
            Self::ViaLoader { display_path, .. } => display_path,
        }
    }

    /// Describe this command for the shared process runner.
    ///
    /// A `Direct` command runs the binary at its path; a `ViaLoader` command runs
    /// the dynamic loader as `--library-path <dirs> <program> <args>` so the
    /// loader searches the pre-overlay `/nix/store` bind before any `DT_RUNPATH`,
    /// exactly as the previous hand-built command did. The caller adds a deadline
    /// and runs it through [`RealProcessRunner`], which also starts the child from
    /// a cleared environment and resolves nothing from the caller's `PATH`.
    pub(super) fn to_process_command(&self, args: &[&str]) -> ProcessCommand {
        match self {
            Self::Direct(path) => ProcessCommand::exact(path).args(args),
            Self::ViaLoader {
                loader,
                library_path,
                program,
                ..
            } => ProcessCommand::exact(loader)
                .arg("--library-path")
                .arg(library_path)
                .arg(program)
                .args(args),
        }
    }
}

pub(super) fn systemctl_command() -> CachedCommand {
    super::SYSTEMCTL_COMMAND.get().cloned().unwrap_or_else(|| {
        CachedCommand::Direct(PathBuf::from("/run/current-system/sw/bin/systemctl"))
    })
}

const NIX_STORE_PREFIX: &str = "/nix/store";

/// Translate a path under `/nix/store` into the equivalent path under the
/// pre-overlay read-only bind of the store (`/run/nails/original-nix-store`).
///
/// The bind exposes the same store contents at a path that does not change when
/// `/nix` is overlaid, so a command built against it keeps running without
/// depending on the overlaid store and without copying any bytes. Paths outside
/// the store are returned unchanged.
fn map_into_bind(path: &Path, bind_root: &Path) -> PathBuf {
    match path.strip_prefix(NIX_STORE_PREFIX) {
        Ok(relative) => bind_root.join(relative),
        Err(_) => path.to_path_buf(),
    }
}

/// Parse `ldd` output into the dynamic loader and the set of library
/// directories a command needs.
///
/// `ldd` prints resolved shared objects as `name => /path (0x...)` lines and the
/// program interpreter as a standalone `/path (0x...)` line (the vDSO line has
/// no path). The loader is the first standalone absolute path; library
/// directories are the parents of every resolved object plus the loader itself,
/// de-duplicated while preserving discovery order.
fn parse_ldd_output(ldd_output: &str) -> (Option<PathBuf>, Vec<PathBuf>) {
    let mut loader = None;
    let mut directories: Vec<PathBuf> = Vec::new();

    let push_parent = |directories: &mut Vec<PathBuf>, path: &Path| {
        if let Some(parent) = path.parent() {
            let parent = parent.to_path_buf();
            if !directories.contains(&parent) {
                directories.push(parent);
            }
        }
    };

    for line in ldd_output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some((_, resolved)) = line.split_once("=>") {
            // Resolved shared object: the path after `=>`.
            if let Some(path) = resolved
                .split_whitespace()
                .find(|token| token.starts_with('/'))
                .map(PathBuf::from)
            {
                push_parent(&mut directories, &path);
            }
        } else if let Some(path) = line
            .split_whitespace()
            .find(|token| token.starts_with('/'))
            .map(PathBuf::from)
        {
            // Standalone absolute path: the program interpreter (loader).
            if loader.is_none() {
                loader = Some(path.clone());
            }
            push_parent(&mut directories, &path);
        }
    }

    (loader, directories)
}

/// Build the command used to run `systemctl` (and friends) after `/nix` is
/// overlaid.
///
/// For a store binary the command is resolved against `bind_root`, the
/// pre-overlay read-only bind of `/nix/store`: the loader, its `--library-path`
/// and the program itself all point under the bind. The dynamic loader searches
/// `--library-path` before any `DT_RUNPATH`, so no bytes are copied and nothing
/// depends on the overlaid store view. Binaries outside the store are invoked
/// directly.
pub(super) fn build_cached_command(
    command_path: &Path,
    bind_root: &Path,
) -> std::io::Result<CachedCommand> {
    let canonical =
        std::fs::canonicalize(command_path).unwrap_or_else(|_| command_path.to_path_buf());

    if !canonical.starts_with("/nix/store/") {
        return Ok(CachedCommand::Direct(canonical));
    }

    // Resolve `ldd` from the fixed system directories and bound it with a
    // deadline so a hung resolver cannot stall activation before the overlay.
    let ldd_output = RealProcessRunner
        .run(
            &ProcessCommand::tool("ldd")
                .arg(canonical.as_os_str())
                .deadline(LDD_BUDGET),
        )
        .map_err(runner_error_to_io)?;
    if !ldd_output.status.success() {
        return Err(command_failed_error(
            &format!("ldd {}", canonical.display()),
            &ldd_output,
        ));
    }

    let (loader, library_dirs) = parse_ldd_output(&String::from_utf8_lossy(&ldd_output.stdout));
    let loader = loader.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "ldd output for {} did not list a dynamic loader",
                canonical.display()
            ),
        )
    })?;

    let mut cached_library_dirs: Vec<PathBuf> = Vec::new();
    for library_dir in &library_dirs {
        let mapped = map_into_bind(library_dir, bind_root);
        if !cached_library_dirs.contains(&mapped) {
            cached_library_dirs.push(mapped);
        }
    }

    let cached_loader = map_into_bind(&loader, bind_root);
    let cached_program = map_into_bind(&canonical, bind_root);

    tracing::debug!(
        command = %cached_program.display(),
        loader = %cached_loader.display(),
        library_path = ?cached_library_dirs,
        "Prepared runtime command against original-nix-store bind before /nix overlay"
    );

    let library_path = std::env::join_paths(cached_library_dirs)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;

    Ok(CachedCommand::ViaLoader {
        display_path: command_path.to_path_buf(),
        loader: cached_loader,
        library_path,
        program: cached_program,
    })
}

pub(super) fn command_failed_error(command: &str, output: &std::process::Output) -> std::io::Error {
    std::io::Error::other(format!(
        "{command} failed with status {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

/// Map a [`crate::NailsError`] from the shared runner onto the `io::Error` these
/// cache and service helpers speak, preserving the kind where it is meaningful.
pub(super) fn runner_error_to_io(err: crate::NailsError) -> std::io::Error {
    match err {
        crate::NailsError::IoError(io) => io,
        crate::NailsError::Timeout { .. } => {
            std::io::Error::new(std::io::ErrorKind::TimedOut, err.to_string())
        }
        other => std::io::Error::other(other.to_string()),
    }
}

#[cfg(test)]
mod tests;
