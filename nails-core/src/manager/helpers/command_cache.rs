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
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;

    fn make_output(status: i32, stdout: &[u8], stderr: &[u8]) -> std::process::Output {
        std::process::Output {
            status: std::process::ExitStatus::from_raw(status << 8),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        }
    }

    fn make_elf64_with_interp(interpreter: &str) -> Vec<u8> {
        let interp_bytes = interpreter.as_bytes();
        let interp_size = interp_bytes.len() + 1;
        let phoff = 64u64;
        let phentsize = 56u16;
        let phnum = 1u16;
        let interp_offset = 0x100u64;

        let mut bytes = vec![0u8; interp_offset as usize + interp_size];
        bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;

        bytes[32..40].copy_from_slice(&phoff.to_le_bytes());
        bytes[54..56].copy_from_slice(&phentsize.to_le_bytes());
        bytes[56..58].copy_from_slice(&phnum.to_le_bytes());

        let header = phoff as usize;
        bytes[header..header + 4].copy_from_slice(&3u32.to_le_bytes());
        bytes[header + 8..header + 16].copy_from_slice(&interp_offset.to_le_bytes());
        bytes[header + 32..header + 40].copy_from_slice(&(interp_size as u64).to_le_bytes());

        let interp_start = interp_offset as usize;
        bytes[interp_start..interp_start + interp_bytes.len()].copy_from_slice(interp_bytes);
        bytes
    }

    fn make_elf32_with_interp(interpreter: &str) -> Vec<u8> {
        let interp_bytes = interpreter.as_bytes();
        let interp_size = interp_bytes.len() + 1;
        let phoff = 52u32;
        let phentsize = 32u16;
        let phnum = 1u16;
        let interp_offset = 0x80u32;

        let mut bytes = vec![0u8; interp_offset as usize + interp_size];
        bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 1;
        bytes[5] = 1;
        bytes[6] = 1;

        bytes[28..32].copy_from_slice(&phoff.to_le_bytes());
        bytes[42..44].copy_from_slice(&phentsize.to_le_bytes());
        bytes[44..46].copy_from_slice(&phnum.to_le_bytes());

        let header = phoff as usize;
        bytes[header..header + 4].copy_from_slice(&3u32.to_le_bytes());
        bytes[header + 4..header + 8].copy_from_slice(&interp_offset.to_le_bytes());
        bytes[header + 16..header + 20].copy_from_slice(&(interp_size as u32).to_le_bytes());

        let interp_start = interp_offset as usize;
        bytes[interp_start..interp_start + interp_bytes.len()].copy_from_slice(interp_bytes);
        bytes
    }

    #[test]
    fn cache_relative_path_strips_root_prefix_only_for_absolute_paths() {
        assert_eq!(
            cache_relative_path(Path::new("/nix/store/foo")),
            PathBuf::from("nix/store/foo")
        );
        assert_eq!(
            cache_relative_path(Path::new("relative/path")),
            PathBuf::from("relative/path")
        );
    }

    #[test]
    fn cached_command_display_path_matches_variant() {
        let direct = CachedCommand::Direct(PathBuf::from("/bin/systemctl"));
        assert_eq!(direct.display_path(), Path::new("/bin/systemctl"));

        let via_loader = CachedCommand::ViaLoader {
            display_path: PathBuf::from("/shown/systemctl"),
            loader: PathBuf::from("/loader"),
            library_path: OsString::from("/lib"),
            program: PathBuf::from("/program"),
        };
        assert_eq!(via_loader.display_path(), Path::new("/shown/systemctl"));
    }

    #[test]
    fn parse_ldd_library_dirs_extracts_unique_parent_directories_in_order() {
        let output = r#"
linux-vdso.so.1 (0x00007ffea63e7000)
libc.so.6 => /nix/store/aaa-glibc/lib/libc.so.6 (0x00007f)
libpthread.so.0 => /nix/store/aaa-glibc/lib/libpthread.so.0 (0x00007f)
libm.so.6 => /nix/store/bbb-math/lib64/libm.so.6 (0x00007f)
/nix/store/ccc-loader/lib64/ld-linux-x86-64.so.2 (0x00007f)
not-a-path => ???
"#;

        assert_eq!(
            parse_ldd_library_dirs(output),
            vec![
                PathBuf::from("/nix/store/aaa-glibc/lib"),
                PathBuf::from("/nix/store/bbb-math/lib64"),
                PathBuf::from("/nix/store/ccc-loader/lib64"),
            ]
        );
    }

    #[test]
    fn store_root_returns_first_nix_store_derivation_only() {
        assert_eq!(
            store_root(Path::new("/nix/store/abcd-package/bin/tool")),
            Some(PathBuf::from("/nix/store/abcd-package"))
        );
        assert_eq!(
            store_root(Path::new("/tmp/nix/store/abcd-package/bin/tool")),
            None
        );
        assert_eq!(store_root(Path::new("/nix/store")), None);
    }

    #[test]
    fn command_failed_error_trims_stderr_and_includes_status() {
        let output = make_output(17, b"", b" permission denied\n\n");
        let error = command_failed_error("ldd /bin/true", &output);

        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        let message = error.to_string();
        assert!(
            message.contains("ldd /bin/true failed with status exit status: 17"),
            "{message}"
        );
        assert!(message.ends_with("permission denied"), "{message}");
    }

    #[test]
    fn remove_destination_if_present_handles_missing_file_regular_file_and_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("file.txt");
        let dir_path = temp_dir.path().join("dir");

        remove_destination_if_present(&file_path).unwrap();

        fs::write(&file_path, "hello").unwrap();
        remove_destination_if_present(&file_path).unwrap();
        assert!(!file_path.exists());

        fs::create_dir_all(dir_path.join("nested")).unwrap();
        remove_destination_if_present(&dir_path).unwrap();
        assert!(!dir_path.exists());
    }

    #[test]
    fn copy_file_with_parent_copies_contents_and_permissions() {
        let temp_dir = tempfile::tempdir().unwrap();
        let source = temp_dir.path().join("source.txt");
        let destination = temp_dir.path().join("deep/path/copied.txt");

        fs::write(&source, "secret").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o751)).unwrap();

        copy_file_with_parent(&source, &destination).unwrap();

        assert_eq!(fs::read_to_string(&destination).unwrap(), "secret");
        let mode = fs::metadata(&destination).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o751);
    }

    #[test]
    fn copy_entry_with_parent_preserves_symlink_targets() {
        let temp_dir = tempfile::tempdir().unwrap();
        let source_dir = temp_dir.path().join("source");
        let destination_dir = temp_dir.path().join("destination");
        let target = source_dir.join("target.txt");
        let link = source_dir.join("link.txt");
        fs::create_dir_all(&source_dir).unwrap();
        fs::write(&target, "payload").unwrap();
        unix_fs::symlink(&target, &link).unwrap();

        let destination = destination_dir.join("link.txt");
        copy_entry_with_parent(&link, &destination).unwrap();

        assert!(
            fs::symlink_metadata(&destination)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(&destination).unwrap(), target);
    }

    #[test]
    fn copy_tree_with_parent_recursively_copies_files_and_links() {
        let temp_dir = tempfile::tempdir().unwrap();
        let source = temp_dir.path().join("source");
        let destination = temp_dir.path().join("destination");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::write(source.join("nested/data.txt"), "payload").unwrap();
        unix_fs::symlink(Path::new("nested/data.txt"), source.join("data-link")).unwrap();

        copy_tree_with_parent(&source, &destination).unwrap();

        assert_eq!(
            fs::read_to_string(destination.join("nested/data.txt")).unwrap(),
            "payload"
        );
        assert_eq!(
            fs::read_link(destination.join("data-link")).unwrap(),
            PathBuf::from("nested/data.txt")
        );
    }

    #[test]
    fn read_elf_interpreter_rejects_non_elf_files() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("not-elf");
        fs::write(&path, b"plain text").unwrap();

        let error = read_elf_interpreter(&path).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("is not an ELF binary"));
    }

    #[test]
    fn read_elf_interpreter_parses_elf64_pt_interp() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("elf64.bin");
        fs::write(
            &path,
            make_elf64_with_interp("/nix/store/loader-64/lib64/ld-linux-x86-64.so.2"),
        )
        .unwrap();

        assert_eq!(
            read_elf_interpreter(&path).unwrap(),
            PathBuf::from("/nix/store/loader-64/lib64/ld-linux-x86-64.so.2")
        );
    }

    #[test]
    fn read_elf_interpreter_parses_elf32_pt_interp() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("elf32.bin");
        fs::write(
            &path,
            make_elf32_with_interp("/nix/store/loader-32/lib/ld-linux.so.2"),
        )
        .unwrap();

        assert_eq!(
            read_elf_interpreter(&path).unwrap(),
            PathBuf::from("/nix/store/loader-32/lib/ld-linux.so.2")
        );
    }

    #[test]
    fn read_elf_interpreter_rejects_unsupported_class_and_missing_interp() {
        let temp_dir = tempfile::tempdir().unwrap();

        let unsupported = temp_dir.path().join("unsupported.bin");
        let mut unsupported_bytes = vec![0u8; 64];
        unsupported_bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        unsupported_bytes[4] = 9;
        unsupported_bytes[5] = 1;
        fs::write(&unsupported, unsupported_bytes).unwrap();
        let unsupported_error = read_elf_interpreter(&unsupported).unwrap_err();
        assert!(
            unsupported_error
                .to_string()
                .contains("unsupported ELF class: 9")
        );

        let missing_interp = temp_dir.path().join("missing-interp.bin");
        let mut missing_interp_bytes = vec![0u8; 128];
        missing_interp_bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        missing_interp_bytes[4] = 2;
        missing_interp_bytes[5] = 1;
        missing_interp_bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        missing_interp_bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        missing_interp_bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        fs::write(&missing_interp, missing_interp_bytes).unwrap();
        let missing_interp_error = read_elf_interpreter(&missing_interp).unwrap_err();
        assert!(
            missing_interp_error
                .to_string()
                .contains("does not declare a PT_INTERP program header")
        );
    }

    #[test]
    fn build_cached_command_returns_direct_for_non_store_paths() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("systemctl");
        fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();

        match build_cached_command(&path).unwrap() {
            CachedCommand::Direct(canonical) => {
                assert_eq!(canonical, fs::canonicalize(&path).unwrap())
            }
            other => panic!("expected direct command, got {other:?}"),
        }
    }

    #[test]
    fn via_loader_base_command_includes_loader_library_path_and_program() {
        let command = CachedCommand::ViaLoader {
            display_path: PathBuf::from("/display/systemctl"),
            loader: PathBuf::from("/loader"),
            library_path: OsString::from("/lib:/lib64"),
            program: PathBuf::from("/program"),
        };

        let base = command.base_command();
        let args: Vec<_> = base.get_args().map(|arg| arg.to_os_string()).collect();

        assert_eq!(base.get_program(), Path::new("/loader"));
        assert_eq!(
            args,
            vec![
                OsString::from("--library-path"),
                OsString::from("/lib:/lib64"),
                OsString::from("/program"),
            ]
        );
    }

    #[test]
    fn spawn_output_wraps_process_spawn_errors_with_display_path() {
        let command = CachedCommand::Direct(PathBuf::from("/definitely/missing/systemctl"));

        let error = command.spawn_output(&["status"]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        let message = error.to_string();
        assert!(
            message.contains("failed to spawn systemctl at /definitely/missing/systemctl"),
            "{message}"
        );
    }
}
