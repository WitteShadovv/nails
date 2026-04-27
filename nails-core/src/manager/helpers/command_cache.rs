use std::ffi::OsString;
use std::os::unix::fs as unix_fs;
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

    pub(super) fn spawn_output(
        &self,
        args: &[&str],
    ) -> std::result::Result<std::process::Output, std::io::Error> {
        let mut command = self.base_command();
        command.args(args);
        command.output().map_err(|err| {
            std::io::Error::new(
                err.kind(),
                format!(
                    "failed to spawn systemctl at {}: {}",
                    self.display_path().display(),
                    err
                ),
            )
        })
    }

    fn base_command(&self) -> std::process::Command {
        match self {
            Self::Direct(path) => std::process::Command::new(path),
            Self::ViaLoader {
                loader,
                library_path,
                program,
                ..
            } => {
                let mut command = std::process::Command::new(loader);
                command.arg("--library-path").arg(library_path).arg(program);
                command
            }
        }
    }
}

pub(super) fn systemctl_command() -> CachedCommand {
    super::SYSTEMCTL_COMMAND.get().cloned().unwrap_or_else(|| {
        CachedCommand::Direct(PathBuf::from("/run/current-system/sw/bin/systemctl"))
    })
}

fn cache_relative_path(source: &Path) -> PathBuf {
    source
        .strip_prefix("/")
        .map(PathBuf::from)
        .unwrap_or_else(|_| source.to_path_buf())
}

fn copy_file_with_parent(source: &Path, destination: &Path) -> std::io::Result<()> {
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::copy(source, destination)?;
    let permissions = std::fs::metadata(source)?.permissions();
    std::fs::set_permissions(destination, permissions)?;
    Ok(())
}

fn remove_destination_if_present(destination: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            std::fs::remove_dir_all(destination)
        }
        Ok(_) => std::fs::remove_file(destination),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn copy_entry_with_parent(source: &Path, destination: &Path) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(source)?;
    let file_type = metadata.file_type();

    if file_type.is_symlink() {
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        remove_destination_if_present(destination)?;
        unix_fs::symlink(std::fs::read_link(source)?, destination)?;
        return Ok(());
    }

    if file_type.is_file() {
        return copy_file_with_parent(source, destination);
    }

    if file_type.is_dir() {
        return copy_tree_with_parent(source, destination);
    }

    Ok(())
}

fn copy_tree_with_parent(source_dir: &Path, destination_dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(destination_dir)?;
    for entry in std::fs::read_dir(source_dir)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination_dir.join(entry.file_name());
        copy_entry_with_parent(&source_path, &destination_path)?;
    }
    Ok(())
}

fn query_store_closure(root_path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let output = std::process::Command::new("/run/current-system/sw/bin/nix-store")
        .args(["-qR"])
        .arg(root_path)
        .output()?;
    if !output.status.success() {
        return Err(command_failed_error(
            &format!("nix-store -qR {}", root_path.display()),
            &output,
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(PathBuf::from)
        .collect())
}

fn store_root(path: &Path) -> Option<PathBuf> {
    let mut components = path.components();
    let root = components.next()?;
    let nix = components.next()?;
    let store = components.next()?;
    let derivation = components.next()?;

    let root_path = PathBuf::from(root.as_os_str());
    let nix_path = root_path.join(nix.as_os_str());
    let store_path = nix_path.join(store.as_os_str());
    let derivation_path = store_path.join(derivation.as_os_str());

    if derivation_path.starts_with("/nix/store/") {
        Some(derivation_path)
    } else {
        None
    }
}

fn parse_ldd_library_dirs(ldd_output: &str) -> Vec<PathBuf> {
    let mut directories = Vec::new();

    for line in ldd_output.lines() {
        let candidate = line
            .split_whitespace()
            .find(|token| token.starts_with('/'))
            .map(PathBuf::from);

        let Some(path) = candidate else {
            continue;
        };

        let Some(parent) = path.parent() else {
            continue;
        };

        let parent = parent.to_path_buf();
        if !directories.contains(&parent) {
            directories.push(parent);
        }
    }

    directories
}

fn read_elf_interpreter(binary_path: &Path) -> std::io::Result<PathBuf> {
    fn read_u16(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u16> {
        let slice = bytes.get(offset..offset + 2)?;
        Some(if little_endian {
            u16::from_le_bytes([slice[0], slice[1]])
        } else {
            u16::from_be_bytes([slice[0], slice[1]])
        })
    }

    fn read_u32(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
        let slice = bytes.get(offset..offset + 4)?;
        Some(if little_endian {
            u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
        } else {
            u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]])
        })
    }

    fn read_u64(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u64> {
        let slice = bytes.get(offset..offset + 8)?;
        Some(if little_endian {
            u64::from_le_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ])
        } else {
            u64::from_be_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ])
        })
    }

    let bytes = std::fs::read(binary_path)?;
    if bytes.get(0..4) != Some(&[0x7f, b'E', b'L', b'F']) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is not an ELF binary", binary_path.display()),
        ));
    }

    let class = *bytes.get(4).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "ELF header missing class")
    })?;
    let data = *bytes.get(5).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ELF header missing endianness",
        )
    })?;
    let little_endian = match data {
        1 => true,
        2 => false,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported ELF endianness: {data}"),
            ));
        }
    };

    const PT_INTERP: u32 = 3;
    match class {
        1 => {
            let phoff = read_u32(&bytes, 28, little_endian).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing e_phoff")
            })? as usize;
            let phentsize = read_u16(&bytes, 42, little_endian).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing e_phentsize")
            })? as usize;
            let phnum = read_u16(&bytes, 44, little_endian).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing e_phnum")
            })? as usize;

            for index in 0..phnum {
                let offset = phoff + index * phentsize;
                let p_type = read_u32(&bytes, offset, little_endian).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid program header")
                })?;
                if p_type != PT_INTERP {
                    continue;
                }

                let p_offset = read_u32(&bytes, offset + 4, little_endian).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "missing p_offset")
                })? as usize;
                let p_filesz = read_u32(&bytes, offset + 16, little_endian).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "missing p_filesz")
                })? as usize;
                let raw = bytes.get(p_offset..p_offset + p_filesz).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "PT_INTERP out of range")
                })?;
                let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
                return Ok(PathBuf::from(
                    String::from_utf8_lossy(&raw[..end]).into_owned(),
                ));
            }
        }
        2 => {
            let phoff = read_u64(&bytes, 32, little_endian).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing e_phoff")
            })? as usize;
            let phentsize = read_u16(&bytes, 54, little_endian).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing e_phentsize")
            })? as usize;
            let phnum = read_u16(&bytes, 56, little_endian).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing e_phnum")
            })? as usize;

            for index in 0..phnum {
                let offset = phoff + index * phentsize;
                let p_type = read_u32(&bytes, offset, little_endian).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid program header")
                })?;
                if p_type != PT_INTERP {
                    continue;
                }

                let p_offset = read_u64(&bytes, offset + 8, little_endian).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "missing p_offset")
                })? as usize;
                let p_filesz = read_u64(&bytes, offset + 32, little_endian).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "missing p_filesz")
                })? as usize;
                let raw = bytes.get(p_offset..p_offset + p_filesz).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "PT_INTERP out of range")
                })?;
                let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
                return Ok(PathBuf::from(
                    String::from_utf8_lossy(&raw[..end]).into_owned(),
                ));
            }
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported ELF class: {class}"),
            ));
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "{} does not declare a PT_INTERP program header",
            binary_path.display()
        ),
    ))
}

pub(super) fn build_cached_command(command_path: &Path) -> std::io::Result<CachedCommand> {
    let canonical =
        std::fs::canonicalize(command_path).unwrap_or_else(|_| command_path.to_path_buf());

    if !canonical.starts_with("/nix/store/") {
        return Ok(CachedCommand::Direct(canonical));
    }

    let interpreter_path = read_elf_interpreter(&canonical)?;
    let interpreter = std::fs::canonicalize(&interpreter_path).unwrap_or(interpreter_path);
    let command_store_root = store_root(&canonical).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not inside /nix/store", canonical.display()),
        )
    })?;
    let interpreter_store_root = store_root(&interpreter).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not inside /nix/store", interpreter.display()),
        )
    })?;
    let ldd_output = std::process::Command::new("/run/current-system/sw/bin/ldd")
        .arg(&canonical)
        .output()?;
    if !ldd_output.status.success() {
        return Err(command_failed_error(
            &format!("ldd {}", canonical.display()),
            &ldd_output,
        ));
    }

    let cache_root = PathBuf::from("/run/nails/systemctl-cache");

    let mut closure_roots = query_store_closure(&command_store_root)?;
    if !closure_roots.contains(&command_store_root) {
        closure_roots.push(command_store_root.clone());
    }
    if !closure_roots.contains(&interpreter_store_root) {
        closure_roots.push(interpreter_store_root.clone());
    }

    for closure_root in &closure_roots {
        let cached_closure_root = cache_root.join(cache_relative_path(closure_root));
        copy_tree_with_parent(closure_root, &cached_closure_root)?;
    }

    let cached_program = cache_root.join(cache_relative_path(&canonical));

    let cached_loader = cache_root.join(cache_relative_path(&interpreter));
    copy_file_with_parent(&interpreter, &cached_loader)?;

    let mut cached_library_dirs = Vec::new();
    for library_dir in parse_ldd_library_dirs(&String::from_utf8_lossy(&ldd_output.stdout)) {
        let cached_library_dir = cache_root.join(cache_relative_path(&library_dir));
        copy_tree_with_parent(&library_dir, &cached_library_dir)?;
        if !cached_library_dirs.contains(&cached_library_dir) {
            cached_library_dirs.push(cached_library_dir);
        }
    }

    for closure_root in &closure_roots {
        for library_subdir in ["lib", "lib64"] {
            let library_dir = closure_root.join(library_subdir);
            if library_dir.is_dir() {
                let cached_library_dir = cache_root.join(cache_relative_path(&library_dir));
                if !cached_library_dirs.contains(&cached_library_dir) {
                    cached_library_dirs.push(cached_library_dir);
                }
            }
        }
    }

    if let Some(parent) = interpreter.parent() {
        let cached_interpreter_dir = cache_root.join(cache_relative_path(parent));
        if !cached_library_dirs.contains(&cached_interpreter_dir) {
            cached_library_dirs.push(cached_interpreter_dir);
        }
    }

    tracing::debug!(
        command = %cached_program.display(),
        loader = %cached_loader.display(),
        library_path = ?cached_library_dirs,
        "Cached runtime command before /nix overlay"
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

#[cfg(test)]
mod tests;
