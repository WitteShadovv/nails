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
