use nails_core::{Config, MockFilesystem, NailsManager, NixOSBuilder};
use serial_test::serial;
use std::ffi::OsString;
use std::fs;
use std::path::Path;

struct PathEnvGuard {
    original: Option<OsString>,
}

impl PathEnvGuard {
    fn capture() -> Self {
        Self {
            original: std::env::var_os("PATH"),
        }
    }

    fn prepend(&self, dir: &Path) {
        let mut paths = vec![dir.to_path_buf()];
        if let Some(existing) = &self.original {
            paths.extend(std::env::split_paths(existing));
        }

        unsafe {
            std::env::set_var(
                "PATH",
                std::env::join_paths(paths).expect("failed to compose PATH for test"),
            );
        }
    }
}

impl Drop for PathEnvGuard {
    fn drop(&mut self) {
        match &self.original {
            Some(path) => unsafe {
                std::env::set_var("PATH", path);
            },
            None => unsafe {
                std::env::remove_var("PATH");
            },
        }
    }
}

fn make_flake_manager(hidden_root: &Path) -> NailsManager<MockFilesystem> {
    let state_path = hidden_root.join("state.json");
    let flake_dir = hidden_root.join("explicit-flake");

    fs::create_dir_all(&flake_dir).expect("flake dir");
    fs::write(flake_dir.join("flake.nix"), "{ outputs = _: {}; }\n").expect("flake.nix");

    let flake_ref = format!("{}#host-alpha", flake_dir.display());
    let builder =
        NixOSBuilder::new_with_flake_ref(flake_ref.clone(), hidden_root.join("nails-system"));

    NailsManager::with_nixos(
        MockFilesystem::new(),
        Config {
            hidden_volume_root: hidden_root.to_path_buf(),
            state_file_path: state_path.clone(),
            nixos_flake: Some(flake_ref),
            ..Config::default()
        },
        state_path,
        builder,
    )
}

fn write_executable_script(path: &Path, body: &str) {
    fs::write(path, body).expect("script body");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = fs::metadata(path).expect("script metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("script permissions");
    }
}

#[test]
#[serial]
fn read_only_flake_preflight_uses_read_only_metadata_and_attr_checks_only() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let hidden_root = temp_dir.path();
    let log_path = hidden_root.join("nix-invocations.log");
    let bin_dir = hidden_root.join("bin");
    fs::create_dir_all(&bin_dir).expect("bin dir");

    write_executable_script(
        &bin_dir.join("nix"),
        &format!(
            "#!/usr/bin/env sh\nprintf '%s\\n' \"$*\" >> {}\nif [ \"$1 $2\" = \"flake metadata\" ]; then\n  printf '{{\"url\":\"path:/tmp/test\"}}\\n'\n  exit 0\nfi\nif [ \"$1 $2 $3\" = \"eval --raw --expr\" ]; then\n  printf '1\\n'\n  exit 0\nfi\nprintf 'unexpected nix subcommand: %s %s %s\\n' \"$1\" \"$2\" \"$3\" 1>&2\nexit 1\n",
            log_path.display()
        ),
    );

    let path_guard = PathEnvGuard::capture();
    path_guard.prepend(&bin_dir);

    let manager = make_flake_manager(hidden_root);
    manager
        .run_read_only_nixos_preflight(false)
        .expect("flake preflight should succeed");

    let invocations = fs::read_to_string(&log_path).expect("invocation log");
    let lines: Vec<_> = invocations.lines().collect();

    assert_eq!(
        lines.len(),
        2,
        "expected exactly two nix invocations: {invocations}"
    );
    assert!(
        lines[0].starts_with("flake metadata "),
        "expected nix flake metadata invocation: {invocations}"
    );
    assert!(
        lines[1].starts_with("eval --raw --expr "),
        "expected cheap nix attr-existence eval invocation: {invocations}"
    );
    assert!(
        lines[0].contains("--no-write-lock-file"),
        "expected read-only flake preflight flags: {invocations}"
    );
    assert!(
        lines[0].contains("--json"),
        "preflight should request machine-readable metadata: {invocations}"
    );
    assert!(
        !lines[1].contains("config.system.build.toplevel.drvPath"),
        "preflight should avoid forcing full toplevel drvPath evaluation: {invocations}"
    );
    assert!(
        lines[1].contains("builtins.getFlake"),
        "preflight should use a cheap attr existence probe: {invocations}"
    );
    assert!(
        !hidden_root.join("state.json").exists(),
        "read-only preflight should not create a state file"
    );
}

#[test]
#[serial]
fn read_only_flake_preflight_reports_missing_selected_attr_without_mutation() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let hidden_root = temp_dir.path();
    let log_path = hidden_root.join("nix-invocations.log");
    let bin_dir = hidden_root.join("bin");
    fs::create_dir_all(&bin_dir).expect("bin dir");

    write_executable_script(
        &bin_dir.join("nix"),
        &format!(
            "#!/usr/bin/env sh\nprintf '%s\\n' \"$*\" >> {}\nif [ \"$1 $2\" = \"flake metadata\" ]; then\n  printf '{{\"url\":\"path:/tmp/test\"}}\\n'\n  exit 0\nfi\nif [ \"$1 $2 $3\" = \"eval --raw --expr\" ]; then\n  printf '%s\\n' 'error: __NAILS_MISSING_NIXOS_CONFIGURATION__:host-alpha' 1>&2\n  exit 1\nfi\nprintf 'unexpected nix subcommand: %s %s %s\\n' \"$1\" \"$2\" \"$3\" 1>&2\nexit 1\n",
            log_path.display()
        ),
    );

    let path_guard = PathEnvGuard::capture();
    path_guard.prepend(&bin_dir);

    let manager = make_flake_manager(hidden_root);
    let err = manager
        .run_read_only_nixos_preflight(false)
        .expect_err("flake preflight should fail when selected attr is missing");

    let err_text = err.to_string();
    assert!(err_text.contains("nixos-build-target"), "{err_text}");
    assert!(err_text.contains("host-alpha"), "{err_text}");
    assert!(
        err_text.contains("does not provide nixosConfiguration"),
        "{err_text}"
    );
    assert!(!hidden_root.join("state.json").exists());
}

#[test]
#[serial]
fn overlay_only_skips_read_only_flake_preflight_entirely() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let hidden_root = temp_dir.path();
    let log_path = hidden_root.join("nix-invocations.log");
    let bin_dir = hidden_root.join("bin");
    fs::create_dir_all(&bin_dir).expect("bin dir");

    write_executable_script(
        &bin_dir.join("nix"),
        &format!(
            "#!/usr/bin/env sh\nprintf '%s\\n' \"$*\" >> {}\nprintf 'overlay-only preflight should not invoke nix\\n' 1>&2\nexit 99\n",
            log_path.display()
        ),
    );

    let path_guard = PathEnvGuard::capture();
    path_guard.prepend(&bin_dir);

    let manager = make_flake_manager(hidden_root);
    manager
        .run_read_only_nixos_preflight(true)
        .expect("overlay-only mode should skip flake preflight");

    assert!(
        !log_path.exists(),
        "overlay-only mode should not invoke nix during read-only preflight"
    );
}
