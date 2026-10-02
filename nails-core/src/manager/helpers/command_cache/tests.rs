use super::*;
use std::ffi::OsString;
use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;

fn make_output(status: i32, stdout: &[u8], stderr: &[u8]) -> std::process::Output {
    std::process::Output {
        status: std::process::ExitStatus::from_raw(status << 8),
        stdout: stdout.to_vec(),
        stderr: stderr.to_vec(),
    }
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
fn map_into_bind_translates_store_paths_and_preserves_others() {
    let bind_root = Path::new("/run/nails/original-nix-store");

    assert_eq!(
        map_into_bind(Path::new("/nix/store/aaa-glibc/lib/libc.so.6"), bind_root),
        PathBuf::from("/run/nails/original-nix-store/aaa-glibc/lib/libc.so.6")
    );
    assert_eq!(
        map_into_bind(Path::new("/nix/store"), bind_root),
        PathBuf::from("/run/nails/original-nix-store")
    );
    // Paths outside the store are left untouched.
    assert_eq!(
        map_into_bind(Path::new("/usr/bin/systemctl"), bind_root),
        PathBuf::from("/usr/bin/systemctl")
    );
    // An identity bind root (test runtime) is a no-op.
    assert_eq!(
        map_into_bind(Path::new("/nix/store/aaa/bin/x"), Path::new("/nix/store")),
        PathBuf::from("/nix/store/aaa/bin/x")
    );
}

#[test]
fn parse_ldd_output_extracts_loader_and_library_dirs_in_order() {
    let output = r#"
linux-vdso.so.1 (0x00007ffea63e7000)
libc.so.6 => /nix/store/aaa-glibc/lib/libc.so.6 (0x00007f)
libpthread.so.0 => /nix/store/aaa-glibc/lib/libpthread.so.0 (0x00007f)
libm.so.6 => /nix/store/bbb-math/lib64/libm.so.6 (0x00007f)
/nix/store/ccc-loader/lib64/ld-linux-x86-64.so.2 (0x00007f)
not-a-path => ???
"#;

    let (loader, dirs) = parse_ldd_output(output);

    assert_eq!(
        loader,
        Some(PathBuf::from(
            "/nix/store/ccc-loader/lib64/ld-linux-x86-64.so.2"
        ))
    );
    assert_eq!(
        dirs,
        vec![
            PathBuf::from("/nix/store/aaa-glibc/lib"),
            PathBuf::from("/nix/store/bbb-math/lib64"),
            PathBuf::from("/nix/store/ccc-loader/lib64"),
        ]
    );
}

#[test]
fn parse_ldd_output_returns_no_loader_for_static_binaries() {
    let (loader, dirs) = parse_ldd_output("\tstatically linked\n");
    assert_eq!(loader, None);
    assert!(dirs.is_empty());
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
fn build_cached_command_returns_direct_for_non_store_paths() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("systemctl");
    fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();

    match build_cached_command(&path, Path::new("/run/nails/original-nix-store")).unwrap() {
        CachedCommand::Direct(canonical) => {
            assert_eq!(canonical, fs::canonicalize(&path).unwrap())
        }
        other => panic!("expected direct command, got {other:?}"),
    }
}

#[test]
fn via_loader_to_process_command_uses_the_loader_library_path_and_program() {
    let command = CachedCommand::ViaLoader {
        display_path: PathBuf::from("/display/systemctl"),
        loader: PathBuf::from("/run/nails/original-nix-store/ccc/lib64/ld-linux-x86-64.so.2"),
        library_path: OsString::from(
            "/run/nails/original-nix-store/aaa/lib:/run/nails/original-nix-store/ccc/lib64",
        ),
        program: PathBuf::from("/run/nails/original-nix-store/ddd/bin/systemctl"),
    };

    // The loader is run directly with --library-path before the program, so the
    // pre-overlay store bind is searched ahead of any DT_RUNPATH; user args follow.
    assert_eq!(
        command.to_process_command(&["status"]),
        ProcessCommand::exact("/run/nails/original-nix-store/ccc/lib64/ld-linux-x86-64.so.2")
            .arg("--library-path")
            .arg("/run/nails/original-nix-store/aaa/lib:/run/nails/original-nix-store/ccc/lib64")
            .arg("/run/nails/original-nix-store/ddd/bin/systemctl")
            .arg("status")
    );
}

#[test]
fn direct_to_process_command_runs_the_exact_binary() {
    let command = CachedCommand::Direct(PathBuf::from("/bin/systemctl"));

    assert_eq!(
        command.to_process_command(&["is-active", "gdm.service"]),
        ProcessCommand::exact("/bin/systemctl").args(["is-active", "gdm.service"])
    );
}
