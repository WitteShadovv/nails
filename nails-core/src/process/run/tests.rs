use super::*;
use serial_test::serial;
use std::fs;
use std::path::Component;

fn write_file(path: &Path, body: &str, mode: u32) {
    fs::write(path, body).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions).unwrap();
}

/// Prepends to PATH and restores it when dropped, so a failing assertion
/// cannot leak the change. The original entries stay so that tests running
/// alongside still find their programs.
struct PathGuard(Option<OsString>);

impl PathGuard {
    fn prepend(dir: &Path) -> Self {
        let original = std::env::var_os("PATH");
        let mut dirs = vec![dir.to_path_buf()];
        if let Some(existing) = &original {
            dirs.extend(std::env::split_paths(existing));
        }
        unsafe {
            std::env::set_var("PATH", std::env::join_paths(dirs).unwrap());
        }
        Self(original)
    }
}

impl Drop for PathGuard {
    fn drop(&mut self) {
        match &self.0 {
            Some(path) => unsafe { std::env::set_var("PATH", path) },
            None => unsafe { std::env::remove_var("PATH") },
        }
    }
}

fn io_error(err: NailsError) -> std::io::Error {
    match err {
        NailsError::IoError(io) => io,
        other => panic!("expected IoError, got {other:?}"),
    }
}

#[test]
fn tool_resolves_to_an_absolute_path_inside_the_system_tool_dirs() {
    let resolved = resolve(&Program::Tool("sh")).unwrap();

    assert!(resolved.is_absolute(), "{}", resolved.display());
    let parent = resolved.parent().unwrap();
    assert!(
        SYSTEM_TOOL_DIRS.iter().any(|dir| Path::new(dir) == parent),
        "sh resolved outside the system tool dirs: {}",
        resolved.display()
    );
}

#[test]
fn tool_missing_from_the_system_tool_dirs_is_not_found() {
    let err = io_error(resolve(&Program::Tool("nails-no-such-tool")).unwrap_err());

    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert!(err.to_string().contains("nails-no-such-tool"));
    assert!(err.to_string().contains("/usr/bin"));
}

#[test]
#[serial]
fn tool_resolution_ignores_the_caller_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    write_file(
        &temp_dir.path().join("nails-stub-tool"),
        "#!/bin/sh\n",
        0o755,
    );
    let _path = PathGuard::prepend(temp_dir.path());

    let err = io_error(resolve(&Program::Tool("nails-stub-tool")).unwrap_err());

    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn find_executable_skips_directories_and_non_executable_files() {
    let temp_dir = tempfile::tempdir().unwrap();
    let not_executable = temp_dir.path().join("a");
    let directory = temp_dir.path().join("b");
    let first = temp_dir.path().join("c");
    let second = temp_dir.path().join("d");
    for dir in [&not_executable, &directory, &first, &second] {
        fs::create_dir_all(dir).unwrap();
    }
    write_file(&not_executable.join("tool"), "", 0o644);
    fs::create_dir_all(directory.join("tool")).unwrap();
    write_file(&first.join("tool"), "", 0o755);
    write_file(&second.join("tool"), "", 0o755);

    let found = find_executable(
        "tool",
        [
            not_executable.as_path(),
            directory.as_path(),
            first.as_path(),
            second.as_path(),
        ],
    );

    assert_eq!(found, Some(first.join("tool")));
    assert_eq!(find_executable("tool", [not_executable.as_path()]), None);
}

#[test]
#[serial]
fn caller_path_resolves_through_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let stub = temp_dir.path().join("nails-stub-tool");
    write_file(&stub, "#!/bin/sh\n", 0o755);
    let _path = PathGuard::prepend(temp_dir.path());

    assert_eq!(
        resolve(&Program::CallerPath("nails-stub-tool")).unwrap(),
        stub
    );
}

#[test]
#[serial]
fn caller_path_skips_relative_path_entries() {
    let temp_dir = tempfile::tempdir().unwrap();
    write_file(
        &temp_dir.path().join("nails-stub-tool"),
        "#!/bin/sh\n",
        0o755,
    );
    let cwd = std::env::current_dir().unwrap();
    let depth = cwd
        .components()
        .filter(|component| matches!(component, Component::Normal(_)))
        .count();
    let relative =
        PathBuf::from("../".repeat(depth)).join(temp_dir.path().strip_prefix("/").unwrap());
    assert!(relative.join("nails-stub-tool").is_file());
    let _path = PathGuard::prepend(&relative);

    let err = io_error(resolve(&Program::CallerPath("nails-stub-tool")).unwrap_err());

    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert!(err.to_string().contains("not found on PATH"));
}

#[test]
fn exact_program_resolves_to_itself() {
    let path = PathBuf::from("/nix/var/nix/profiles/system/bin/switch-to-configuration");

    assert_eq!(resolve(&Program::Exact(path.clone())).unwrap(), path);
}

#[test]
fn real_runner_refuses_commands_that_did_not_opt_in_during_tests() {
    let temp_dir = tempfile::tempdir().unwrap();
    let marker = temp_dir.path().join("ran");
    let command = ProcessCommand::tool("sh")
        .arg("-c")
        .arg(format!("touch '{}'", marker.display()));

    assert_refused_in_test_runtime(RealProcessRunner.run(&command), "sh");
    assert!(!marker.exists(), "refused command must not start");
}

#[test]
fn real_runner_runs_opted_in_commands_and_captures_output() {
    let command = ProcessCommand::tool("sh")
        .args(["-c", "printf out; printf err 1>&2; exit 3"])
        .allow_in_test_runtime();

    let output = RealProcessRunner.run(&command).unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(output.stdout, b"out");
    assert_eq!(output.stderr, b"err");

    assert_eq!(
        RealProcessRunner.run_text(&command).unwrap(),
        (false, "out".to_string(), "err".to_string())
    );
}

#[test]
fn real_runner_closes_stdin() {
    let command = ProcessCommand::tool("sh")
        .args([
            "-c",
            "if read -r line; then printf read; else printf eof; fi",
        ])
        .allow_in_test_runtime();

    let (_, stdout, _) = RealProcessRunner.run_text(&command).unwrap();

    assert_eq!(stdout, "eof");
}

#[test]
#[serial]
fn real_runner_removes_requested_environment_variables() {
    unsafe {
        std::env::set_var("NAILS_RUN_TEST_VARIABLE", "inherited");
    }
    let base = ProcessCommand::tool("sh")
        .args(["-c", "printf '%s' \"${NAILS_RUN_TEST_VARIABLE-unset}\""])
        .allow_in_test_runtime();

    let inherited = RealProcessRunner.run_text(&base.clone()).unwrap();
    let removed = RealProcessRunner
        .run_text(&base.env_remove("NAILS_RUN_TEST_VARIABLE"))
        .unwrap();
    unsafe {
        std::env::remove_var("NAILS_RUN_TEST_VARIABLE");
    }

    assert_eq!(inherited.1, "inherited");
    assert_eq!(removed.1, "unset");
}

#[test]
fn real_runner_reports_spawn_failures_with_the_executable_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let missing = temp_dir.path().join("missing");
    let not_executable = temp_dir.path().join("script");
    write_file(&not_executable, "#!/bin/sh\n", 0o644);

    let err = io_error(
        RealProcessRunner
            .run(&ProcessCommand::exact(&missing).allow_in_test_runtime())
            .unwrap_err(),
    );
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert!(err.to_string().contains("failed to start"));
    assert!(err.to_string().contains(&missing.display().to_string()));

    let err = io_error(
        RealProcessRunner
            .run(&ProcessCommand::exact(&not_executable).allow_in_test_runtime())
            .unwrap_err(),
    );
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn command_display_joins_the_program_and_its_arguments() {
    assert_eq!(
        ProcessCommand::tool("systemctl")
            .args(["stop", "gdm.service"])
            .to_string(),
        "systemctl stop gdm.service"
    );
    assert_eq!(
        ProcessCommand::exact("/run/current-system/bin/switch-to-configuration")
            .arg("test")
            .to_string(),
        "/run/current-system/bin/switch-to-configuration test"
    );
    assert_eq!(ProcessCommand::caller_path("nix").to_string(), "nix");
}

#[test]
fn shared_host_commands_resolve_from_system_dirs_and_stay_guarded() {
    assert_eq!(
        systemctl_command(&["is-active", "gdm.service"]),
        ProcessCommand::new(Program::Tool("systemctl")).args(["is-active", "gdm.service"])
    );
    assert_eq!(
        signal_command(4242, "TERM"),
        ProcessCommand::tool("kill").args(["-TERM", "4242"])
    );
    assert!(!systemctl_command(&[]).allowed_in_test_runtime);
    assert!(!signal_command(1, "KILL").allowed_in_test_runtime);
}

#[test]
fn mock_runner_records_calls_and_replays_scripted_results() {
    let runner = MockProcessRunner::new()
        .with_response(Ok(exited(1, "first", "")))
        .with_response(Err(NailsError::InvalidState("scripted".into())));
    let first = ProcessCommand::tool("systemctl").arg("stop");
    let second = ProcessCommand::caller_path("nix").arg("eval");
    let third = ProcessCommand::exact("/bin/true");

    assert_eq!(runner.run(&first).unwrap().status.code(), Some(1));
    assert!(runner.run(&second).is_err());
    assert!(runner.run(&third).unwrap().status.success());
    assert_eq!(runner.calls(), vec![first, second, third]);
}

#[test]
fn run_text_decodes_output_lossily() {
    let runner = MockProcessRunner::new().with_response(Ok(Output {
        stdout: vec![b'o', 0xff, b'k'],
        ..exited(0, "", "warn")
    }));

    let (success, stdout, stderr) = runner.run_text(&ProcessCommand::tool("cp")).unwrap();

    assert!(success);
    assert_eq!(stdout, "o\u{fffd}k");
    assert_eq!(stderr, "warn");
}
