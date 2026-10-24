// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::RuntimeEnv;
use crate::runtime_env::ScopedRuntimeEnv;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Component;

/// Writes `body` to `path` through a child process, so this process never holds
/// a write descriptor for the file. A process another test thread forks would
/// inherit such a descriptor until it execs, and running the file in that
/// window fails with ETXTBSY.
fn write_file(path: &Path, body: &str, mode: u32) {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let mut writer = Command::new("/bin/sh")
        .arg("-c")
        .arg("cat > \"$1\"")
        .arg("sh")
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    writer
        .stdin
        .take()
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
    assert!(
        writer.wait().unwrap().success(),
        "writing {}",
        path.display()
    );
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions).unwrap();
}

/// Makes the runner see a caller `PATH` with `dir` in front, on this thread,
/// until the guard is dropped. The test process's own entries follow so that a
/// program the test does not stub still resolves; the process environment
/// itself is never changed.
fn prepend_path(dir: &Path) -> ScopedRuntimeEnv {
    let mut dirs = vec![dir.to_path_buf()];
    if let Some(existing) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&existing));
    }
    ScopedRuntimeEnv::new(RuntimeEnv::empty().with_path(std::env::join_paths(dirs).unwrap()))
}

/// Makes the runner see `vars` as the caller's environment, on this thread.
fn caller_env(vars: &[(&str, &str)]) -> ScopedRuntimeEnv {
    ScopedRuntimeEnv::new(
        RuntimeEnv::empty().with_inherited(
            vars.iter()
                .map(|(key, value)| ((*key).into(), (*value).into()))
                .collect(),
        ),
    )
}

fn io_error(err: NailsError) -> std::io::Error {
    match err {
        NailsError::IoError { source: io, .. } => io,
        other => panic!("expected IoError, got {other:?}"),
    }
}

#[test]
fn tool_resolves_to_an_absolute_path_inside_the_system_tool_dirs() {
    let resolved = resolve(&Program::Tool("sh"), None).unwrap();

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
    let err = io_error(resolve(&Program::Tool("nails-no-such-tool"), None).unwrap_err());

    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert!(err.to_string().contains("nails-no-such-tool"));
    assert!(err.to_string().contains("/usr/bin"));
}

#[test]
fn tool_resolution_ignores_the_caller_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    write_file(
        &temp_dir.path().join("nails-stub-tool"),
        "#!/bin/sh\n",
        0o755,
    );
    let _env = prepend_path(temp_dir.path());

    let err = io_error(resolve(&Program::Tool("nails-stub-tool"), None).unwrap_err());

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
fn caller_path_resolves_through_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let stub = temp_dir.path().join("nails-stub-tool");
    write_file(&stub, "#!/bin/sh\n", 0o755);
    let _env = prepend_path(temp_dir.path());

    assert_eq!(
        resolve(&Program::CallerPath("nails-stub-tool"), None).unwrap(),
        stub
    );
}

#[test]
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
    let _env = prepend_path(&relative);

    let err = io_error(resolve(&Program::CallerPath("nails-stub-tool"), None).unwrap_err());

    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert!(err.to_string().contains("not found on PATH"));
}

#[test]
fn caller_path_falls_back_to_the_system_tool_dirs_for_a_minimal_path() {
    // A systemd unit's PATH holds none of the tools; `sh` is in every system dir set.
    let empty = tempfile::tempdir().unwrap();
    let _env = ScopedRuntimeEnv::new(RuntimeEnv::empty().with_path(empty.path().as_os_str()));

    let resolved = resolve(&Program::CallerPath("sh"), None).unwrap();

    let parent = resolved.parent().unwrap();
    assert!(
        SYSTEM_TOOL_DIRS.iter().any(|dir| Path::new(dir) == parent),
        "sh resolved outside the system tool dirs: {}",
        resolved.display()
    );
}

#[test]
fn an_injected_search_path_has_no_system_fallback() {
    let empty = tempfile::tempdir().unwrap();

    let err =
        io_error(resolve(&Program::CallerPath("sh"), Some(empty.path().as_os_str())).unwrap_err());

    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert!(
        err.to_string().contains("not found on the search path"),
        "{err}"
    );
}

#[test]
fn caller_path_resolves_through_an_injected_search_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let stub = temp_dir.path().join("nails-stub-tool");
    write_file(&stub, "#!/bin/sh\n", 0o755);

    let resolved = resolve(
        &Program::CallerPath("nails-stub-tool"),
        Some(temp_dir.path().as_os_str()),
    );

    assert_eq!(resolved.unwrap(), stub);
}

#[test]
fn injected_search_path_replaces_the_caller_path() {
    let on_path = tempfile::tempdir().unwrap();
    write_file(
        &on_path.path().join("nails-stub-tool"),
        "#!/bin/sh\n",
        0o755,
    );
    let empty = tempfile::tempdir().unwrap();
    let _env = prepend_path(on_path.path());

    let err = io_error(
        resolve(
            &Program::CallerPath("nails-stub-tool"),
            Some(empty.path().as_os_str()),
        )
        .unwrap_err(),
    );

    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert!(err.to_string().contains("not found on the search path"));
}

#[test]
fn tool_resolution_ignores_an_injected_search_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    write_file(
        &temp_dir.path().join("nails-stub-tool"),
        "#!/bin/sh\n",
        0o755,
    );

    let err = io_error(
        resolve(
            &Program::Tool("nails-stub-tool"),
            Some(temp_dir.path().as_os_str()),
        )
        .unwrap_err(),
    );

    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn real_runner_starts_a_caller_path_program_from_the_search_path_with_the_fixed_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    write_file(
        &temp_dir.path().join("nails-stub-tool"),
        "#!/bin/sh\nprintf '%s' \"$PATH\"\n",
        0o755,
    );

    let (ok, stdout, stderr) = RealProcessRunner
        .run_text(
            &ProcessCommand::caller_path("nails-stub-tool")
                .search_path(temp_dir.path())
                .allow_in_test_runtime(),
        )
        .unwrap();

    assert!(ok, "stub failed: {stderr}");
    assert_eq!(stdout, SYSTEM_TOOL_DIRS.join(":"));
}

#[test]
fn exact_program_resolves_to_itself() {
    let path = PathBuf::from("/nix/var/nix/profiles/system/bin/switch-to-configuration");

    assert_eq!(resolve(&Program::Exact(path.clone()), None).unwrap(), path);
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

/// The variable names in the child's environment, read with `env`, which prints
/// exactly what it inherits and adds nothing of its own.
fn child_env_keys(command: ProcessCommand) -> Vec<String> {
    let (ok, stdout, stderr) = RealProcessRunner.run_text(&command).unwrap();
    assert!(ok, "env failed: {stderr}");
    stdout
        .lines()
        .filter_map(|line| line.split_once('=').map(|(key, _)| key.to_string()))
        .collect()
}

#[test]
fn real_runner_gives_the_child_only_the_allowlisted_environment() {
    // A secret the caller holds (dropped), locale/terminal variables (kept), and
    // NIX_PATH (dropped unless the command opts in).
    let _env = caller_env(&[
        ("NAILS_RUN_SECRET", "leak"),
        ("LANG", "en_US.UTF-8"),
        ("LC_ALL", "C"),
        ("TERM", "xterm-256color"),
        ("NIX_PATH", "nixpkgs=/caller/channel"),
    ]);

    let keys = child_env_keys(ProcessCommand::tool("env").allow_in_test_runtime());

    // The child sees only the fixed PATH and allowlisted locale/terminal keys.
    assert!(keys.contains(&"PATH".to_string()), "{keys:?}");
    assert!(keys.contains(&"LANG".to_string()), "{keys:?}");
    assert!(keys.contains(&"LC_ALL".to_string()), "{keys:?}");
    assert!(keys.contains(&"TERM".to_string()), "{keys:?}");
    assert!(
        !keys.contains(&"NAILS_RUN_SECRET".to_string()),
        "caller secret leaked to the child: {keys:?}"
    );
    assert!(
        !keys.contains(&"NIX_PATH".to_string()),
        "NIX_PATH reached the child without allow_env: {keys:?}"
    );
    for key in &keys {
        assert!(
            key == "PATH" || key == "LANG" || key == "TERM" || key.starts_with("LC_"),
            "non-allowlisted variable {key} reached the child: {keys:?}"
        );
    }
}

#[test]
fn real_runner_sets_a_fixed_path_the_caller_cannot_override() {
    let temp_dir = tempfile::tempdir().unwrap();
    let _env = prepend_path(temp_dir.path());

    // allow_env("PATH") must not win over the fixed PATH.
    let (ok, stdout, _) = RealProcessRunner
        .run_text(
            &ProcessCommand::tool("sh")
                .args(["-c", "printf '%s' \"$PATH\""])
                .allow_env("PATH")
                .allow_in_test_runtime(),
        )
        .unwrap();

    assert!(ok);
    assert_eq!(stdout, SYSTEM_TOOL_DIRS.join(":"));
}

#[test]
fn real_runner_passes_allowed_variables_through() {
    let _env = caller_env(&[("NIX_PATH", "nixpkgs=/caller/channel")]);

    let base = ProcessCommand::tool("sh")
        .args(["-c", "printf '%s' \"${NIX_PATH-unset}\""])
        .allow_in_test_runtime();
    let dropped = RealProcessRunner.run_text(&base.clone()).unwrap();
    let kept = RealProcessRunner
        .run_text(&base.allow_env("NIX_PATH"))
        .unwrap();

    assert_eq!(dropped.1, "unset");
    assert_eq!(kept.1, "nixpkgs=/caller/channel");
}

#[test]
fn real_runner_sets_explicit_session_variables_on_the_child() {
    // The caller does not hold DBUS_SESSION_BUS_ADDRESS; set_env supplies the
    // operator's session bus explicitly, as the notify-send path does.

    let (ok, stdout, _) = RealProcessRunner
        .run_text(
            &ProcessCommand::tool("sh")
                .args(["-c", "printf '%s' \"${DBUS_SESSION_BUS_ADDRESS-unset}\""])
                .set_env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
                .allow_in_test_runtime(),
        )
        .unwrap();

    assert!(ok);
    assert_eq!(stdout, "unix:path=/run/user/1000/bus");
}

#[test]
fn real_runner_set_env_cannot_override_the_fixed_path() {
    // set_env must not be able to redirect the child onto a caller-chosen PATH.

    let (ok, stdout, _) = RealProcessRunner
        .run_text(
            &ProcessCommand::tool("sh")
                .args(["-c", "printf '%s' \"$PATH\""])
                .set_env("PATH", "/tmp/evil")
                .allow_in_test_runtime(),
        )
        .unwrap();

    assert!(ok);
    assert_eq!(stdout, SYSTEM_TOOL_DIRS.join(":"));
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

/// Whether `pid` is gone or already a zombie, i.e. no longer the running
/// `sleep` it started as. Reading `/proc/<pid>/stat` works whether or not an
/// init reaps the orphan: a missing entry or state `Z` both mean dead, while a
/// recycled PID shows a different `comm`. Polls briefly so a reaper that has not
/// run yet does not fail the check.
fn sleep_pid_is_gone(pid: i32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match sleep_pid_state(pid) {
            None | Some('Z') => return true,
            _ if Instant::now() >= deadline => return false,
            _ => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

/// The scheduler state of `pid` while it is still a `sleep` process, or `None`
/// once its `/proc` entry is gone or the PID has been recycled.
fn sleep_pid_state(pid: i32) -> Option<char> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    if &stat[open + 1..close] != "sleep" {
        return None;
    }
    stat[close + 1..].split_whitespace().next()?.chars().next()
}

#[test]
fn deadline_kills_the_whole_process_group() {
    let temp_dir = tempfile::tempdir().unwrap();
    let pid_file = temp_dir.path().join("grandchild.pid");
    // Background a sleep (the grandchild), record its PID, then block in the
    // foreground so the deadline fires while the whole group is alive.
    let script = format!("sleep 60 & echo $! > '{}'; sleep 60", pid_file.display());
    let command = ProcessCommand::tool("sh")
        .arg("-c")
        .arg(&script)
        .deadline(Duration::from_millis(200))
        .allow_in_test_runtime();

    let start = Instant::now();
    let err = RealProcessRunner.run(&command).unwrap_err();
    let elapsed = start.elapsed();

    match err {
        NailsError::Timeout { command, budget } => {
            assert!(command.contains("sh -c"), "{command}");
            assert_eq!(budget, Duration::from_millis(200));
        }
        other => panic!("expected Timeout, got {other:?}"),
    }
    assert!(
        elapsed < Duration::from_secs(5),
        "returned after {elapsed:?}"
    );

    let pid: i32 = fs::read_to_string(&pid_file)
        .expect("script should have recorded the grandchild PID")
        .trim()
        .parse()
        .expect("recorded PID should be an integer");
    assert!(
        sleep_pid_is_gone(pid),
        "grandchild {pid} survived the deadline"
    );
}

#[test]
fn deadline_returns_output_when_the_command_finishes_in_time() {
    let command = ProcessCommand::tool("sh")
        .args(["-c", "printf out; printf err 1>&2; exit 2"])
        .deadline(Duration::from_secs(5))
        .allow_in_test_runtime();

    let output = RealProcessRunner.run(&command).unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"out");
    assert_eq!(output.stderr, b"err");
}

#[test]
fn deadline_closes_child_stdin() {
    let command = ProcessCommand::tool("sh")
        .args([
            "-c",
            "if read -r line; then printf read; else printf eof; fi",
        ])
        .deadline(Duration::from_secs(5))
        .allow_in_test_runtime();

    let (_, stdout, _) = RealProcessRunner.run_text(&command).unwrap();

    assert_eq!(stdout, "eof");
}

#[test]
fn run_streaming_reports_progress_and_returns_output() {
    // Runs a little longer than one progress interval so at least one heartbeat
    // fires, then exits successfully with output.
    let command = ProcessCommand::tool("sh")
        .args(["-c", "sleep 0.3; printf done"])
        .allow_in_test_runtime();

    let mut ticks: Vec<Duration> = Vec::new();
    let output = RealProcessRunner
        .run_streaming(
            &command,
            Duration::from_millis(100),
            &mut |elapsed, _last| {
                ticks.push(elapsed);
            },
        )
        .unwrap();

    assert!(output.status.success());
    assert_eq!(output.stdout, b"done");
    assert!(
        !ticks.is_empty(),
        "expected at least one progress heartbeat, got none"
    );
    // Progress carries the total elapsed time, which only grows.
    assert!(ticks.windows(2).all(|w| w[1] >= w[0]), "{ticks:?}");
}

#[test]
fn run_streaming_never_fires_progress_for_a_quick_command() {
    let command = ProcessCommand::tool("sh")
        .args(["-c", "printf quick"])
        .allow_in_test_runtime();

    let mut ticks = 0usize;
    let (ok, stdout, _) = RealProcessRunner
        .run_streaming_text(&command, Duration::from_secs(30), &mut |_, _| ticks += 1)
        .unwrap();

    assert!(ok);
    assert_eq!(stdout, "quick");
    assert_eq!(ticks, 0, "a sub-second command must not report progress");
}

#[test]
fn run_streaming_surfaces_last_stderr_line_while_keeping_full_buffer() {
    // Emits two stderr lines before finishing, with a pause so at least one
    // heartbeat fires between them. The heartbeat must see the most recent line,
    // and the returned buffer must still hold every line for classification.
    let command = ProcessCommand::tool("sh")
        .args([
            "-c",
            "printf 'building foo\\n' >&2; sleep 0.25; printf 'building bar\\n' >&2; sleep 0.25; printf done",
        ])
        .allow_in_test_runtime();

    let mut last_seen: Vec<Option<String>> = Vec::new();
    let output = RealProcessRunner
        .run_streaming(
            &command,
            Duration::from_millis(100),
            &mut |_elapsed, last| {
                last_seen.push(last.map(str::to_owned));
            },
        )
        .unwrap();

    assert!(output.status.success());
    assert_eq!(output.stdout, b"done");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("building foo"), "{stderr:?}");
    assert!(stderr.contains("building bar"), "{stderr:?}");
    // The callback saw a concrete build line at least once, and the final line
    // observed is the most recent one the command wrote.
    let observed: Vec<&String> = last_seen.iter().flatten().collect();
    assert!(
        !observed.is_empty(),
        "expected the heartbeat to surface a build line, got {last_seen:?}"
    );
    assert_eq!(observed.last().map(|s| s.as_str()), Some("building bar"));
}

#[test]
fn progress_line_folds_in_the_last_build_line_and_truncates() {
    let elapsed = Duration::from_secs(130);
    assert_eq!(
        progress_line("building", elapsed, None),
        "still building, 2m10s"
    );
    assert_eq!(
        progress_line("building", elapsed, Some("   ")),
        "still building, 2m10s",
        "a blank last line is dropped"
    );
    assert_eq!(
        progress_line("building", elapsed, Some("linking foo")),
        "still building, 2m10s — linking foo"
    );

    let long = "x".repeat(400);
    let rendered = progress_line("building", elapsed, Some(&long));
    assert!(rendered.ends_with('…'));
    let shown = rendered.rsplit("— ").next().unwrap();
    assert_eq!(shown.chars().count(), PROGRESS_LINE_MAX);
}

#[test]
fn heartbeat_last_line_shown_only_on_a_tty() {
    // On an interactive terminal the build line is live feedback and is kept.
    assert_eq!(
        heartbeat_last_line(Some("linking foo"), true),
        Some("linking foo")
    );
    // Off a terminal (pipe, journal, detached worker) only the neutral form is
    // emitted, so raw build output never widens the activity fingerprint.
    assert_eq!(heartbeat_last_line(Some("linking foo"), false), None);
    // No build line to show stays `None` regardless of the stream.
    assert_eq!(heartbeat_last_line(None, true), None);
    assert_eq!(heartbeat_last_line(None, false), None);
}

#[test]
fn format_elapsed_is_compact_and_scales() {
    assert_eq!(format_elapsed(Duration::from_secs(5)), "5s");
    assert_eq!(format_elapsed(Duration::from_secs(130)), "2m10s");
    assert_eq!(format_elapsed(Duration::from_secs(3723)), "1h02m03s");
}

#[test]
fn commands_carry_no_deadline_unless_one_is_set() {
    assert_eq!(
        ProcessCommand::tool("systemctl").arg("status").timeout,
        None
    );
    assert_eq!(
        ProcessCommand::tool("nix")
            .deadline(NIX_STORE_PING_BUDGET)
            .timeout,
        Some(NIX_STORE_PING_BUDGET)
    );
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
