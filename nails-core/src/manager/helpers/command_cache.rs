// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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
    super::SYSTEMCTL_COMMAND
        .get()
        .cloned()
        .unwrap_or_else(|| CachedCommand::Direct(host_tool_path("systemctl")))
}

/// Where [`host_tool_path`] looks for a host tool, in order: the NixOS
/// command directories first (so a NixOS host keeps resolving its system
/// profile), then the FHS locations every other supported distribution keeps
/// `systemctl` and `journalctl` in.
pub(super) const HOST_TOOL_DIRS: &[&str] = &[
    crate::platform::NIXOS_SYSTEM_PROFILE_BIN,
    "/run/wrappers/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

/// Resolve a host tool (`systemctl`, `journalctl`, `nix`, ...) by name.
///
/// The `/nix` runtime-command cache resolves `systemctl`, `nix` and `nix-daemon`
/// through this before the overlay is applied, so the paths it records point at
/// the real, pre-overlay system profile. Resolution runs through
/// [`HostCommands`](crate::platform::HostCommands) — root-owned, trust-checked
/// when nails runs as root — over [`HOST_TOOL_DIRS`], and falls back to the
/// system-profile binary directory only when nothing resolves, so no caller
/// spells the store path itself. Searching the NixOS directories alone made
/// every `systemctl` and `journalctl` call fail on Debian and Ubuntu: journald
/// was never restarted around the `/var` overlay, and the runtime journal was
/// never rotated before the teardown scrubbed it.
pub(super) fn host_tool_path(name: &str) -> PathBuf {
    crate::platform::HostCommands::new(HOST_TOOL_DIRS.iter().copied())
        .resolve(name)
        .unwrap_or_else(|_| PathBuf::from(crate::platform::NIXOS_SYSTEM_PROFILE_BIN).join(name))
}

const NIX_STORE_PREFIX: &str = "/nix/store";

/// Translate a path under `/nix/store` into the equivalent path under the
/// pre-overlay read-only bind of the store, which lives inside the
/// per-activation runtime root (`<runtime-root>/original-nix-store`).
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
/// `ldd` prints resolved shared objects as `soname => /path (0x...)` lines. The
/// program interpreter appears in one of two shapes depending on the glibc
/// version and on whether the requested interpreter path differs from the one
/// it resolved to: a standalone `/path (0x...)` line, or `/requested => /resolved
/// (0x...)` with an absolute path on the left (a library's left side is a bare
/// soname). The vDSO line has no path, and a static binary prints only
/// `statically linked`. The loader is the first interpreter line found, taking
/// the resolved path; library directories are the parents of every resolved
/// object plus the loader, de-duplicated while preserving discovery order.
///
/// The authoritative loader comes from the ELF `PT_INTERP` header
/// ([`read_elf_interpreter`]); this parse is used for the library directories
/// and as the loader fallback when the binary cannot be read as ELF.
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

        if let Some((requested, resolved)) = line.split_once("=>") {
            // Resolved object: the path after `=>`. An absolute path on the left
            // marks the program interpreter rather than a soname-keyed library.
            if let Some(path) = resolved
                .split_whitespace()
                .find(|token| token.starts_with('/'))
                .map(PathBuf::from)
            {
                if requested.trim_start().starts_with('/') && loader.is_none() {
                    loader = Some(path.clone());
                }
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

/// `PT_INTERP`: the program header naming the dynamic loader.
const PT_INTERP: u32 = 3;

/// Read the dynamic loader a program requests from its ELF `PT_INTERP` header.
///
/// This is the authoritative answer `ldd` itself derives the loader from, read
/// in-process so it does not depend on the shape of `ldd`'s output. Returns
/// `Ok(None)` for a valid ELF file without an interpreter (a statically linked
/// program) and an `InvalidData` error for anything that is not a well-formed
/// 32- or 64-bit ELF file in either byte order.
fn read_elf_interpreter(bytes: &[u8]) -> std::io::Result<Option<PathBuf>> {
    use std::os::unix::ffi::OsStrExt;

    let invalid = |what: &str| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("not a readable ELF file: {what}"),
        )
    };

    if bytes.len() < 16 || bytes[..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(invalid("bad magic"));
    }
    let is_64 = match bytes[4] {
        1 => false,
        2 => true,
        _ => return Err(invalid("unknown class")),
    };
    let little = match bytes[5] {
        1 => true,
        2 => false,
        _ => return Err(invalid("unknown byte order")),
    };

    let field = |offset: usize, width: usize| -> std::io::Result<u64> {
        let slice = bytes
            .get(offset..offset + width)
            .ok_or_else(|| invalid("truncated header"))?;
        let mut value: u64 = 0;
        for (index, byte) in slice.iter().enumerate() {
            let shift = if little { index } else { width - 1 - index };
            value |= u64::from(*byte) << (8 * shift);
        }
        Ok(value)
    };
    let to_usize = |value: u64| usize::try_from(value).map_err(|_| invalid("offset overflow"));

    // (e_phoff, e_phentsize, e_phnum) and, per program header, the offsets of
    // (p_type, p_offset, p_filesz) with the width of the latter two.
    let (phoff, phentsize, phnum, off_at, size_at, word) = if is_64 {
        (field(0x20, 8)?, field(0x36, 2)?, field(0x38, 2)?, 8, 32, 8)
    } else {
        (field(0x1c, 4)?, field(0x2a, 2)?, field(0x2c, 2)?, 4, 16, 4)
    };
    let phoff = to_usize(phoff)?;
    let phentsize = to_usize(phentsize)?;

    for index in 0..to_usize(phnum)? {
        let header = index
            .checked_mul(phentsize)
            .and_then(|delta| phoff.checked_add(delta))
            .ok_or_else(|| invalid("program header overflow"))?;
        if field(header, 4)? as u32 != PT_INTERP {
            continue;
        }
        let start = to_usize(field(header + off_at, word)?)?;
        let size = to_usize(field(header + size_at, word)?)?;
        let raw = start
            .checked_add(size)
            .and_then(|end| bytes.get(start..end))
            .ok_or_else(|| invalid("truncated interpreter"))?;
        let name = raw.split(|byte| *byte == 0).next().unwrap_or_default();
        if name.is_empty() {
            return Err(invalid("empty interpreter"));
        }
        return Ok(Some(PathBuf::from(std::ffi::OsStr::from_bytes(name))));
    }
    Ok(None)
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

    // The loader comes from the program's own ELF header. A store binary with no
    // interpreter is statically linked: it needs no loader or library path and
    // runs directly from the pre-overlay bind (`ldd` would only fail on it).
    let elf_loader = match std::fs::read(&canonical) {
        Ok(bytes) => match read_elf_interpreter(&bytes) {
            Ok(None) => {
                return Ok(CachedCommand::Direct(map_into_bind(&canonical, bind_root)));
            }
            Ok(Some(interpreter)) => {
                Some(std::fs::canonicalize(&interpreter).unwrap_or(interpreter))
            }
            Err(_) => None,
        },
        Err(_) => None,
    };

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

    let (ldd_loader, mut library_dirs) =
        parse_ldd_output(&String::from_utf8_lossy(&ldd_output.stdout));
    let loader = elf_loader.or(ldd_loader).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "found no dynamic loader for {}: no readable ELF PT_INTERP and none in ldd output",
                canonical.display()
            ),
        )
    })?;
    // The loader's own directory must be on the library path even when `ldd`
    // listed it under a different (symlinked) directory.
    if let Some(parent) = loader.parent()
        && !library_dirs.iter().any(|dir| dir == parent)
    {
        library_dirs.push(parent.to_path_buf());
    }

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
    // The message keeps the path the runner named (the program that failed).
    match &err {
        crate::NailsError::IoError { source, .. } => {
            std::io::Error::new(source.kind(), err.to_string())
        }
        crate::NailsError::Timeout { .. } => {
            std::io::Error::new(std::io::ErrorKind::TimedOut, err.to_string())
        }
        other => std::io::Error::other(other.to_string()),
    }
}

#[cfg(test)]
mod tests;
