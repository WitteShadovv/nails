// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The child processes the transitions run, each bounded by a deadline:
//! `systemctl` to enqueue the soft-reboot or a power action, `dmsetup` to
//! mark the hidden backend for deferred removal, and `ip`, for the way back's
//! [`network`](super::network) restore, to delete the links and the
//! policy-routing rules a session added and reset each device's hardware
//! address to the one recorded at entry.
//!
//! Every tool runs by absolute path (recorded at activation, or one of a fixed
//! list of system locations), with a cleared environment and no output, so a
//! wedged PID 1 costs at most the deadline.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How long one `systemctl` or `dmsetup` call may take, [`daemon_reload`]
/// aside: none of them waits for a queued job or for udev.
pub const TOOL_BUDGET: Duration = Duration::from_secs(3);

/// System locations searched for a tool the plan does not name.
const SYSTEM_BIN_DIRS: &[&str] = &[
    "/run/current-system/sw/bin",
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
];

/// `recorded` when it exists, else `name` in the first system directory that
/// has it.
pub fn find(recorded: Option<&Path>, name: &str) -> Option<PathBuf> {
    if let Some(path) = recorded
        && path.is_file()
    {
        return Some(path.to_path_buf());
    }
    SYSTEM_BIN_DIRS
        .iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|p| p.is_file())
}

/// The link the first system directory goes through.
const CURRENT_SYSTEM: &str = "/run/current-system";

/// The system directories as they resolve once `/run/current-system` names
/// `system`: its `sw/bin` stands in place of the link's. Without a system (a
/// host that is not NixOS) they are as they are.
fn system_dirs_for(system: Option<&Path>) -> Vec<PathBuf> {
    SYSTEM_BIN_DIRS
        .iter()
        .map(
            |dir| match (system, Path::new(dir).strip_prefix(CURRENT_SYSTEM)) {
                (Some(system), Ok(rest)) => system.join(rest),
                _ => PathBuf::from(dir),
            },
        )
        .collect()
}

/// `name` where [`find`] will find it in the tree at `root` (`/`, but in
/// tests) once `/run/current-system` names `system`: the last step of the way
/// back repoints that link to the decoy's NixOS system before it runs a tool,
/// so the hidden session can check before the switch that the step will find
/// what it needs.
pub fn find_for_system(root: &Path, system: Option<&Path>, name: &str) -> Option<PathBuf> {
    system_dirs_for(system)
        .into_iter()
        .map(|dir| root.join(dir.strip_prefix("/").unwrap_or(&dir)).join(name))
        .find(|p| p.is_file())
}

/// How a bounded tool call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// It exited 0 in time.
    Done,
    /// It could not start, or it exited non-zero: the work was not done.
    Refused,
    /// It died by a signal or overran its deadline: whether the work was done
    /// is unknown.
    Unknown,
}

/// Run `program args…` and wait at most `budget`; a child that overruns is
/// killed. The child ignores SIGTERM, SIGINT and SIGHUP: enqueueing a
/// shutdown stops the unit it runs in, and the call must outlive that stop.
pub fn run(program: &Path, args: &[&str], budget: Duration) -> Outcome {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", SYSTEM_BIN_DIRS.join(":"))
        .env("LC_ALL", "C")
        .env("SYSTEMD_PAGER", "")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir("/");
    ignore_stop_signals(&mut command);
    let Ok(mut child) = command.spawn() else {
        return Outcome::Refused;
    };
    let deadline = Instant::now() + budget;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Outcome::Done,
            Ok(Some(status)) if status.code().is_some() => return Outcome::Refused,
            Ok(Some(_)) => return Outcome::Unknown,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Outcome::Unknown;
            }
        }
    }
}

/// [`run`], `true` only when the tool is known to have succeeded.
pub fn run_bounded(program: &Path, args: &[&str], budget: Duration) -> bool {
    run(program, args, budget) == Outcome::Done
}

/// Ignore SIGTERM, SIGINT and SIGHUP in this process from now on. The
/// emergency hot path kills the shell it was started from and enqueues a stop
/// of every session, its own included; neither may end it halfway.
#[allow(unsafe_code)]
pub fn survive_session_stop() {
    for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        // SAFETY: `signal(2)` with SIG_IGN installs no handler; it only
        // changes this process's disposition, which nothing else relies on
        // once the hot path has begun.
        unsafe {
            libc::signal(sig, libc::SIG_IGN);
        }
    }
}

/// Set SIGTERM, SIGINT and SIGHUP to ignored in the child. An ignored
/// disposition survives `exec`.
#[allow(unsafe_code)]
pub fn ignore_stop_signals(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure only calls `signal(2)`, which is async-signal-safe,
    // with constant arguments. It allocates nothing and touches no shared
    // state, so it is safe to run between fork and exec.
    unsafe {
        command.pre_exec(|| {
            for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
                libc::signal(sig, libc::SIG_IGN);
            }
            Ok(())
        });
    }
}

/// Enqueue `target` (`soft-reboot.target`, `poweroff.target`,
/// `reboot.target`) without waiting, replacing every other job irreversibly.
/// It talks to PID 1 directly, so it works with logind and D-Bus already gone,
/// and it checks no inhibitors. The outcome is [`Outcome::Unknown`] when the
/// call was cut short, typically because the shutdown it enqueued is already
/// stopping the caller.
pub fn start_target(systemctl: &Path, target: &str) -> Outcome {
    run(
        systemctl,
        &[
            "start",
            "--no-block",
            "--job-mode=replace-irreversibly",
            "--",
            target,
        ],
        TOOL_BUDGET,
    )
}

/// The target of every soft-reboot.
pub const SOFT_REBOOT_TARGET: &str = "soft-reboot.target";

/// Reload the service manager, so a runtime drop-in written to `/run` applies.
pub fn daemon_reload(systemctl: &Path) -> bool {
    run_bounded(systemctl, &["daemon-reload"], Duration::from_secs(30))
}

/// The units PID 1 holds in the failed state, `None` when `systemctl` could
/// not be asked.
pub fn failed_units(systemctl: &Path) -> Option<Vec<String>> {
    run_output(
        systemctl,
        &[
            "list-units",
            "--state=failed",
            "--all",
            "--plain",
            "--no-legend",
            "--no-pager",
            "--full",
        ],
        TOOL_BUDGET,
    )
    .map(|text| parse_unit_list(&text))
}

/// The unit names, the first column, of a `systemctl list-units --plain
/// --no-legend` listing; lines whose first word is no unit name are skipped.
pub fn parse_unit_list(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| crate::whole_root::runtime_units::valid_unit_name(name))
        .map(str::to_string)
        .collect()
}

/// Mark the device-mapper device `name` for removal on its last close. Its
/// key leaves kernel memory the moment the switch releases the last opener.
pub fn remove_deferred(dmsetup: &Path, name: &str) -> bool {
    run_bounded(
        dmsetup,
        &["remove", "--deferred", "--noudevsync", "--", name],
        TOOL_BUDGET,
    )
}

/// Run `program args…` like [`run`] and return its standard output when it
/// exited 0 in time.
pub fn run_output(program: &Path, args: &[&str], budget: Duration) -> Option<String> {
    match run_reading(program, args, budget, Stream::Stdout) {
        (Ran::Exited(status), text) if status.success() => Some(text),
        _ => None,
    }
}

/// Run `program args…` like [`run`], with the last line it wrote to its
/// standard error: what a tool that refused says about why.
pub fn run_explained(program: &Path, args: &[&str], budget: Duration) -> (Outcome, String) {
    let (ran, text) = run_reading(program, args, budget, Stream::Stderr);
    let outcome = match ran {
        Ran::NotStarted => Outcome::Refused,
        Ran::Overran => Outcome::Unknown,
        Ran::Exited(status) if status.success() => Outcome::Done,
        Ran::Exited(status) if status.code().is_some() => Outcome::Refused,
        Ran::Exited(_) => Outcome::Unknown,
    };
    let said = text
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty())
        .unwrap_or_default()
        .to_string();
    (outcome, said)
}

/// Which output stream [`run_reading`] keeps.
#[derive(Clone, Copy)]
enum Stream {
    Stdout,
    Stderr,
}

/// How a run of [`run_reading`] ended.
enum Ran {
    /// The program could not be started.
    NotStarted,
    /// It overran its budget and was killed.
    Overran,
    /// It exited, with this status.
    Exited(std::process::ExitStatus),
}

/// Run `program args…` bounded by `budget`, keeping the text of `stream` and
/// dropping the other one.
fn run_reading(program: &Path, args: &[&str], budget: Duration, stream: Stream) -> (Ran, String) {
    let piped = |kept: bool| if kept { Stdio::piped() } else { Stdio::null() };
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", SYSTEM_BIN_DIRS.join(":"))
        .env("LC_ALL", "C")
        .env("SYSTEMD_PAGER", "")
        .stdin(Stdio::null())
        .stdout(piped(matches!(stream, Stream::Stdout)))
        .stderr(piped(matches!(stream, Stream::Stderr)))
        .current_dir("/");
    ignore_stop_signals(&mut command);
    let Ok(mut child) = command.spawn() else {
        return (Ran::NotStarted, String::new());
    };
    let pipe: Option<Box<dyn std::io::Read + Send>> = match stream {
        Stream::Stdout => child.stdout.take().map(|p| Box::new(p) as _),
        Stream::Stderr => child.stderr.take().map(|p| Box::new(p) as _),
    };
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        if let Some(mut pipe) = pipe {
            let _ = std::io::Read::read_to_string(&mut pipe, &mut text);
        }
        text
    });
    let deadline = Instant::now() + budget;
    let ran = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ran::Exited(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break Ran::Overran;
            }
        }
    };
    (ran, reader.join().unwrap_or_default())
}

/// One job in PID 1's queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// Its number, which `systemctl cancel` takes.
    pub id: u32,
    /// Its unit.
    pub unit: String,
    /// What it does to the unit: `start`, `stop`, `restart`…
    pub kind: String,
}

/// PID 1's queued jobs in `systemctl list-jobs --plain --no-legend` output
/// (`ID UNIT TYPE STATE` per line).
pub fn parse_jobs(list: &str) -> Vec<Job> {
    list.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let id = fields.next()?.parse().ok()?;
            let unit = fields.next()?.to_string();
            let kind = fields.next()?.to_string();
            Some(Job { id, unit, kind })
        })
        .collect()
}

/// The units of PID 1's queued jobs in `systemctl list-jobs --plain
/// --no-legend` output (`ID UNIT TYPE STATE` per line).
pub fn job_units(list: &str) -> Vec<String> {
    list.lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .map(str::to_string)
        .collect()
}

/// Wait, at most `budget`, until PID 1 runs no job but those for the units in
/// `ours`. `false` when the deadline passed or `systemctl` could not answer.
pub fn wait_for_other_jobs(systemctl: &Path, ours: &[&str], budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        let Some(list) = run_output(
            systemctl,
            &["list-jobs", "--plain", "--no-legend"],
            left.min(TOOL_BUDGET),
        ) else {
            return false;
        };
        if job_units(&list)
            .iter()
            .all(|unit| ours.contains(&unit.as_str()))
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Remove the device-mapper device `name` now. Refused (`false`) while
/// anything holds it open: a mounted filesystem or a device stacked on it.
pub fn remove_now(dmsetup: &Path, name: &str) -> bool {
    run_bounded(
        dmsetup,
        &["remove", "--noudevsync", "--", name],
        TOOL_BUDGET,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_unit_listing_yields_the_unit_names_only() {
        let listing = "nscd.service                    loaded failed failed Name Service Cache Daemon\n\
                       generate-shutdown-ramfs.service loaded failed failed Generate shutdown ramfs\n\
                       \n\
                       0 loaded units listed.\n";
        assert_eq!(
            parse_unit_list(listing),
            ["nscd.service", "generate-shutdown-ramfs.service"]
        );
        assert!(parse_unit_list("").is_empty());
    }

    #[test]
    fn a_tool_that_exits_zero_in_time_succeeds_and_a_slow_one_is_killed() {
        let sh = find(None, "sh").expect("a shell");
        assert!(run_bounded(&sh, &["-c", "exit 0"], TOOL_BUDGET));
        assert!(!run_bounded(&sh, &["-c", "exit 3"], TOOL_BUDGET));
        let start = Instant::now();
        assert!(!run_bounded(
            &sh,
            &["-c", "sleep 5"],
            Duration::from_millis(100)
        ));
        assert!(start.elapsed() < Duration::from_secs(3));
        assert!(!run_bounded(
            Path::new("/nonexistent/tool"),
            &[],
            TOOL_BUDGET
        ));
    }

    #[test]
    fn a_job_list_reads_as_number_unit_and_kind() {
        assert_eq!(
            parse_jobs("12 late.service stop running\n7 soft-reboot.target start waiting\nx\n"),
            [
                Job {
                    id: 12,
                    unit: "late.service".into(),
                    kind: "stop".into(),
                },
                Job {
                    id: 7,
                    unit: "soft-reboot.target".into(),
                    kind: "start".into(),
                },
            ]
        );
    }

    #[test]
    fn the_wait_ends_once_only_our_jobs_are_left_and_times_out_otherwise() {
        use crate::test_support::write_executable;
        assert_eq!(
            job_units("12 late.service stop running\n7 soft-reboot.target start waiting\n"),
            ["late.service", "soft-reboot.target"]
        );
        let dir = tempfile::tempdir().unwrap();
        // Busy for the first two calls, then only our own jobs. It stops
        // answering at the hundredth call, so a wait that should have ended
        // fails there.
        let count = dir.path().join("calls");
        let tool = dir.path().join("systemctl");
        write_executable(
            &tool,
            format!(
                "#!/bin/sh\nn=$(cat {c} 2>/dev/null || echo 0); echo $((n + 1)) > {c}\n\
                 [ \"$n\" -ge 99 ] && exit 1\n\
                 echo '7 soft-reboot.target start waiting'\n\
                 [ \"$n\" -lt 2 ] && echo '12 late.service stop running'\nexit 0\n",
                c = count.display()
            ),
            0o755,
        );
        let ours = ["soft-reboot.target", "systemd-soft-reboot.service"];
        // A budget no test run reaches: the third call ends the wait, however
        // long the calls take on a loaded host.
        assert!(wait_for_other_jobs(&tool, &ours, Duration::from_secs(3600)));
        assert_eq!(std::fs::read_to_string(&count).unwrap().trim(), "3");

        let busy = dir.path().join("busy");
        write_executable(
            &busy,
            "#!/bin/sh\necho '12 late.service stop running'\n",
            0o755,
        );
        let start = Instant::now();
        assert!(!wait_for_other_jobs(
            &busy,
            &ours,
            Duration::from_millis(200)
        ));
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn a_tool_that_refuses_says_why_on_its_last_line_of_stderr() {
        let sh = find(None, "sh").expect("a shell");
        assert_eq!(
            run_explained(
                &sh,
                &[
                    "-c",
                    "echo out; echo first >&2; echo 'the reason' >&2; echo >&2; exit 1"
                ],
                TOOL_BUDGET
            ),
            (Outcome::Refused, "the reason".to_string())
        );
        assert_eq!(
            run_explained(&sh, &["-c", "exit 0"], TOOL_BUDGET),
            (Outcome::Done, String::new())
        );
        assert_eq!(
            run_explained(&sh, &["-c", "exec sleep 5"], Duration::from_millis(100)).0,
            Outcome::Unknown
        );
        assert_eq!(
            run_explained(Path::new("/nonexistent/tool"), &[], TOOL_BUDGET).0,
            Outcome::Refused
        );
        assert_eq!(
            run_output(&sh, &["-c", "echo kept; echo dropped >&2"], TOOL_BUDGET).as_deref(),
            Some("kept\n")
        );
    }

    #[test]
    fn a_tool_killed_by_a_signal_has_an_unknown_outcome_and_ignores_sigterm() {
        let sh = find(None, "sh").expect("a shell");
        assert_eq!(run(&sh, &["-c", "exit 1"], TOOL_BUDGET), Outcome::Refused);
        assert_eq!(
            run(&sh, &["-c", "kill -KILL $$"], TOOL_BUDGET),
            Outcome::Unknown
        );
        assert_eq!(
            run(
                &sh,
                &["-c", "kill -TERM $$; kill -HUP $$; kill -INT $$; exit 0"],
                TOOL_BUDGET
            ),
            Outcome::Done
        );
        assert_eq!(
            run(&sh, &["-c", "sleep 5"], Duration::from_millis(100)),
            Outcome::Unknown
        );
    }

    #[test]
    fn a_recorded_tool_wins_and_a_missing_one_falls_back_to_the_system() {
        let dir = tempfile::tempdir().unwrap();
        let recorded = dir.path().join("systemctl");
        std::fs::write(&recorded, "").unwrap();
        assert_eq!(find(Some(&recorded), "systemctl"), Some(recorded.clone()));
        std::fs::remove_file(&recorded).unwrap();
        assert_ne!(find(Some(&recorded), "sh"), Some(recorded));
        assert_eq!(find(None, "no-such-tool-anywhere"), None);
    }

    /// Once the link names a NixOS system, its `sw/bin` is searched in the
    /// link's place, first; the other directories stay. Without a system
    /// nothing is repointed.
    #[test]
    fn a_repointed_system_stands_in_for_the_current_system_link() {
        let decoy = Path::new("/nix/store/aaa-nixos-system-decoy");
        let dirs = system_dirs_for(Some(decoy));
        assert_eq!(dirs[0], decoy.join("sw/bin"));
        assert_eq!(
            dirs[1..],
            SYSTEM_BIN_DIRS[1..]
                .iter()
                .map(PathBuf::from)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            system_dirs_for(None),
            SYSTEM_BIN_DIRS
                .iter()
                .map(PathBuf::from)
                .collect::<Vec<_>>()
        );
    }

    /// Put an empty file at `path` below `root`.
    fn put(root: &Path, path: &str) -> PathBuf {
        let file = root.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "").unwrap();
        file
    }

    /// The lookup reads the tree at its root: there, a tool is found in the
    /// repointed system's `sw/bin` and in the other system directories, never
    /// in the system the link names before the repoint.
    #[test]
    fn a_tool_in_the_repointed_system_is_found_there() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let decoy = Path::new("/nix/store/aaa-nixos-system-decoy");
        assert_eq!(find_for_system(root, Some(decoy), "ip"), None);
        put(root, "run/current-system/sw/bin/ip");
        assert_eq!(find_for_system(root, Some(decoy), "ip"), None);
        let in_decoy = put(root, "nix/store/aaa-nixos-system-decoy/sw/bin/ip");
        assert_eq!(find_for_system(root, Some(decoy), "ip"), Some(in_decoy));
    }

    /// Without a system the directories are searched as they are, below the
    /// root and in their order.
    #[test]
    fn a_tool_in_a_system_directory_below_the_root_is_found() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        assert_eq!(find_for_system(root, None, "ip"), None);
        let in_sbin = put(root, "sbin/ip");
        assert_eq!(find_for_system(root, None, "ip"), Some(in_sbin));
        let in_usr_bin = put(root, "usr/bin/ip");
        assert_eq!(find_for_system(root, None, "ip"), Some(in_usr_bin));
        let in_current = put(root, "run/current-system/sw/bin/ip");
        assert_eq!(find_for_system(root, None, "ip"), Some(in_current));
    }
}
