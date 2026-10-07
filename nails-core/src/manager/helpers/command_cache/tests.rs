// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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

/// `ldd` output captured from glibc 2.42 on NixOS for `systemctl`: the
/// interpreter line has an absolute path on both sides of `=>`.
const LDD_GLIBC_ARROW_LOADER: &str = "\
\tlinux-vdso.so.1 (0x00007ffc1d5f5000)
\tlibsystemd-shared-260.so => /nix/store/b4b1-systemd-260.4/lib/systemd/libsystemd-shared-260.so (0x000073c6e5600000)
\tlibm.so.6 => /nix/store/znb3-glibc-2.42-84/lib/libm.so.6 (0x000073c6e5ba3000)
\t/nix/store/znb3-glibc-2.42-84/lib/ld-linux-x86-64.so.2 => /nix/store/znb3-glibc-2.42-84/lib64/ld-linux-x86-64.so.2 (0x000073c6e5cfd000)
\tlibc.so.6 => /nix/store/znb3-glibc-2.42-84/lib/libc.so.6 (0x000073c6e5200000)
";

#[test]
fn parse_ldd_output_reads_an_interpreter_line_with_an_arrow() {
    let (loader, dirs) = parse_ldd_output(LDD_GLIBC_ARROW_LOADER);

    assert_eq!(
        loader,
        Some(PathBuf::from(
            "/nix/store/znb3-glibc-2.42-84/lib64/ld-linux-x86-64.so.2"
        ))
    );
    assert_eq!(
        dirs,
        vec![
            PathBuf::from("/nix/store/b4b1-systemd-260.4/lib/systemd"),
            PathBuf::from("/nix/store/znb3-glibc-2.42-84/lib"),
            PathBuf::from("/nix/store/znb3-glibc-2.42-84/lib64"),
        ]
    );
}

#[test]
fn parse_ldd_output_ignores_a_not_dynamic_message() {
    let (loader, dirs) = parse_ldd_output("\tnot a dynamic executable\n");
    assert_eq!(loader, None);
    assert!(dirs.is_empty());
}

/// Build a minimal ELF image with one program header of type `p_type` whose
/// segment holds `interp` (NUL-terminated), in the given class and byte order.
fn elf_image(is_64: bool, little: bool, p_type: u32, interp: &[u8]) -> Vec<u8> {
    let put = |buf: &mut Vec<u8>, offset: usize, value: u64, width: usize| {
        for index in 0..width {
            let shift = if little { index } else { width - 1 - index };
            buf[offset + index] = (value >> (8 * shift)) as u8;
        }
    };
    let (ehsize, phentsize) = if is_64 { (64, 56) } else { (52, 32) };
    let interp_offset = ehsize + phentsize;
    let mut buf = vec![0u8; interp_offset + interp.len() + 1];
    buf[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    buf[4] = if is_64 { 2 } else { 1 };
    buf[5] = if little { 1 } else { 2 };
    buf[6] = 1;
    buf[interp_offset..interp_offset + interp.len()].copy_from_slice(interp);
    let filesz = (interp.len() + 1) as u64;
    if is_64 {
        put(&mut buf, 0x20, ehsize as u64, 8);
        put(&mut buf, 0x36, phentsize as u64, 2);
        put(&mut buf, 0x38, 1, 2);
        put(&mut buf, ehsize, u64::from(p_type), 4);
        put(&mut buf, ehsize + 8, interp_offset as u64, 8);
        put(&mut buf, ehsize + 32, filesz, 8);
    } else {
        put(&mut buf, 0x1c, ehsize as u64, 4);
        put(&mut buf, 0x2a, phentsize as u64, 2);
        put(&mut buf, 0x2c, 1, 2);
        put(&mut buf, ehsize, u64::from(p_type), 4);
        put(&mut buf, ehsize + 4, interp_offset as u64, 4);
        put(&mut buf, ehsize + 16, filesz, 4);
    }
    buf
}

#[test]
fn read_elf_interpreter_reads_pt_interp_in_every_class_and_byte_order() {
    let interp = b"/nix/store/znb3-glibc-2.42-84/lib/ld-linux-x86-64.so.2";
    for (is_64, little) in [(true, true), (true, false), (false, true), (false, false)] {
        let image = elf_image(is_64, little, PT_INTERP, interp);
        assert_eq!(
            read_elf_interpreter(&image).unwrap(),
            Some(PathBuf::from(std::str::from_utf8(interp).unwrap())),
            "is_64={is_64} little={little}"
        );
    }
}

#[test]
fn read_elf_interpreter_reports_a_static_binary_as_no_interpreter() {
    // PT_LOAD (1) only: a statically linked program has no PT_INTERP.
    let image = elf_image(true, true, 1, b"ignored");
    assert_eq!(read_elf_interpreter(&image).unwrap(), None);
}

#[test]
fn read_elf_interpreter_rejects_non_elf_and_truncated_input() {
    let script = read_elf_interpreter(b"#!/bin/sh\nexit 0\n").unwrap_err();
    assert_eq!(script.kind(), std::io::ErrorKind::InvalidData);

    let mut truncated = elf_image(true, true, PT_INTERP, b"/lib/ld.so");
    truncated.truncate(70);
    let error = read_elf_interpreter(&truncated).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn read_elf_interpreter_parses_the_running_test_binary() {
    // Whatever the toolchain produced (dynamic or static), a real ELF parses.
    let bytes = fs::read(std::env::current_exe().unwrap()).unwrap();
    if let Some(loader) = read_elf_interpreter(&bytes).unwrap() {
        assert!(loader.is_absolute(), "{}", loader.display());
    }
}

#[test]
fn host_tool_dirs_search_the_nixos_profile_first_and_then_the_fhs_locations() {
    // Searching only the NixOS directories made systemctl and journalctl
    // unresolvable on Debian and Ubuntu; the FHS directories must follow the
    // NixOS ones so a NixOS host still prefers its system profile.
    let position = |dir: &str| HOST_TOOL_DIRS.iter().position(|d| *d == dir);
    for nixos in [
        crate::platform::NIXOS_SYSTEM_PROFILE_BIN,
        "/run/wrappers/bin",
    ] {
        let nixos_at = position(nixos).unwrap_or_else(|| panic!("{nixos} missing"));
        for fhs in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
            let fhs_at = position(fhs).unwrap_or_else(|| panic!("{fhs} missing"));
            assert!(nixos_at < fhs_at, "{nixos} must come before {fhs}");
        }
    }
}

#[test]
fn host_tool_path_resolves_a_tool_from_an_fhs_directory() {
    // `sh` lives in /bin on every FHS host and in the system profile on NixOS;
    // either way it must resolve to an existing file, never to the fallback
    // spelling of a profile path that does not exist.
    let sh = host_tool_path("sh");
    assert!(sh.is_file(), "sh resolved to {}", sh.display());
}
