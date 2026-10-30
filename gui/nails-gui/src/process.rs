// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The window's own process: the name it shows, the limits it runs under,
//! and, when a hidden session's menu entry started it, the environment it
//! gives itself.
//!
//! - **Its name.** The program is called `session` (see [`text::APP_ID`]),
//!   so the name the kernel gives the process at `exec`, the one a process
//!   list shows, is neutral already. The window sets it again first thing
//!   ([`name_neutrally`]), so a start through another file name (a bundled
//!   loader, say) still shows `session`, and every thread it starts
//!   afterwards inherits it.
//! - **Its limits**, on every start ([`limit`]): no core dump (the limit is 0,
//!   soft and hard), not dumpable, which also keeps the operator's other
//!   programs from attaching to it, and `no_new_privs`, so nothing it starts
//!   afterwards gains privileges. The launcher sets the first and the last
//!   before it starts the window, but `exec` makes every process dumpable
//!   again, so the window sets all three itself. On a menu entry's start it
//!   sets them only once it has started pkexec, which has to become root:
//!   under `no_new_privs`, `execve` ignores a set-user-ID bit.
//! - **Its environment**, on a menu entry's start
//!   ([`harden_menu_entry_start`]). The launcher starts the window with the
//!   environment of [`window_env`] and `/dev/null` as its output; a desktop
//!   that runs the menu entry hands it the session's whole environment and
//!   its own streams instead (a journal, on some desktops). So before its
//!   toolkit starts, the window starts itself again, with `exec` (it stays
//!   the same process): on the same allowlist, with its home and every XDG
//!   directory in a directory of its own in the operator's runtime directory
//!   (`/run/user/<uid>`, used only when it is the operator's, private and in
//!   RAM), in `/`, with `/dev/null` as its output streams and its core dumps
//!   already off, a limit `exec` keeps. Started again so, it finds its
//!   environment to be the allowlist's own and goes on.
//! - **Its command line**, `session` alone from the launcher, and
//!   `session --engine -` ([`RESTART_ARGS`]) once a menu entry's start ran
//!   again: the engine's path then comes on standard input, which the window
//!   reads to its end and puts `/dev/null` in place of ([`engine_on_stdin`]).
//!   Every log that quotes the window's command line (dbus-daemon's line for
//!   a service its bus traffic starts, say) names no place.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nails_api::window_env::{self, DirFacts};

use crate::text;

/// The `f_type` of a tmpfs in `statfs(2)`.
const TMPFS_MAGIC: i128 = 0x0102_1994;

/// What `--engine` takes for an engine that comes on standard input.
pub const ENGINE_ON_STDIN: &str = "-";

/// The arguments the window starts itself again with on a menu entry's
/// start: the engine comes on standard input, so its path is on no command
/// line.
pub const RESTART_ARGS: [&str; 2] = ["--engine", ENGINE_ON_STDIN];

/// The longest engine path the window takes on standard input, `PATH_MAX`.
const ENGINE_MAX: usize = 4096;

/// Give the calling thread, and so every thread it starts afterwards, the
/// window's neutral name. Called first thing on the main thread, it is the
/// name of the process.
///
/// # Errors
///
/// The error of `prctl(PR_SET_NAME)`.
pub fn name_neutrally() -> std::io::Result<()> {
    let name = std::ffi::CString::new(text::APP_ID).map_err(std::io::Error::other)?;
    rustix::thread::set_name(&name)?;
    Ok(())
}

/// Close the ways into the window's memory: no core dump (limit 0, soft and
/// hard, which every child inherits), not dumpable, and `no_new_privs`.
/// Called on the main thread before the toolkit starts a thread of its own,
/// and after pkexec started, if the window starts it.
///
/// # Errors
///
/// The first of the three settings that failed.
pub fn limit() -> std::io::Result<()> {
    no_core_dumps()?;
    rustix::thread::set_no_new_privs(true)?;
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
    Ok(())
}

/// Turn off core dumps: a limit of 0, soft and hard, which `exec` keeps and
/// every child inherits.
fn no_core_dumps() -> std::io::Result<()> {
    use rustix::process::{Resource, Rlimit};
    rustix::process::setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;
    Ok(())
}

/// Give the window that a menu entry started for `engine` the launcher's
/// environment: start it again on the allowlist unless it already runs on
/// it, as `session --engine -` with `engine` on its standard input.
///
/// Returns once the window runs on the allowlist; when it does not yet, it
/// only returns if it could not start itself again.
///
/// # Errors
///
/// Why the window could not start itself again: its program cannot be found,
/// the runtime directory cannot be used, its own directory cannot be made,
/// the engine cannot be handed over, core dumps cannot be turned off or the
/// `exec` failed.
pub fn harden_menu_entry_start(engine: &Path) -> Result<(), String> {
    let uid = rustix::process::getuid().as_raw();
    let program = std::env::current_exe()
        .map_err(|error| format!("the window cannot find its own program: {error}"))?;
    let env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let restart = Restart {
        program: &program,
        args: &RESTART_ARGS.map(OsString::from),
        input: engine.as_os_str().as_bytes(),
    };
    restart_on_allowlist(&window_env::runtime_dir_of(uid), uid, &restart, &env)
}

/// How the window starts itself again.
#[derive(Debug, Clone, Copy)]
pub struct Restart<'a> {
    /// Its program.
    pub program: &'a Path,
    /// Its arguments after its name.
    pub args: &'a [OsString],
    /// What its standard input holds.
    pub input: &'a [u8],
}

/// [`harden_menu_entry_start`] for the operator `uid` with the runtime
/// directory `runtime`, started again as `restart` says, from the
/// environment `env` it was started with.
///
/// # Errors
///
/// As [`harden_menu_entry_start`].
pub fn restart_on_allowlist(
    runtime: &Path,
    uid: u32,
    restart: &Restart<'_>,
    env: &[(OsString, OsString)],
) -> Result<(), String> {
    if runs_on_allowlist(env, runtime) {
        return Ok(());
    }
    let facts = facts_of(runtime)
        .map_err(|error| format!("{} cannot be used: {error}", runtime.display()))?;
    window_env::judge(&facts, uid)
        .map_err(|why| format!("{} cannot be used: {why}", runtime.display()))?;
    let input = input_pipe(restart.input)
        .map_err(|error| format!("the window could not hand itself its engine: {error}"))?;
    let own = make_own_dir(runtime).map_err(|error| {
        format!(
            "the window's directory in {} could not be made: {error}",
            runtime.display()
        )
    })?;
    let vars = window_env::vars(pairs(env), runtime, &own);
    // Not `no_new_privs` yet, which `exec` would keep as well: the window
    // starts pkexec first.
    no_core_dumps()
        .map_err(|error| format!("the window could not turn off its core dumps: {error}"))?;
    let error = restart_command(restart.program, restart.args, &vars, input).exec();
    Err(format!("the window could not start itself again: {error}"))
}

/// A pipe that holds `input` and then its end: the standard input of the
/// window started again. The writing end closes before this returns.
fn input_pipe(input: &[u8]) -> std::io::Result<std::io::PipeReader> {
    if input.len() > ENGINE_MAX {
        return Err(std::io::Error::other("its path is too long"));
    }
    // A pipe holds far more than a path, so the write never waits.
    let (reader, mut writer) = std::io::pipe()?;
    writer.write_all(input)?;
    Ok(reader)
}

/// The engine that a menu entry's start, started again, finds on its
/// standard input ([`RESTART_ARGS`]), read to its end. Standard input then
/// leads to `/dev/null`.
///
/// # Errors
///
/// Why there is no engine: standard input could not be read, held nothing
/// or more than a path, or could not be put back.
pub fn engine_on_stdin() -> Result<PathBuf, String> {
    let engine = read_engine(std::io::stdin().lock())?;
    let closed = std::fs::File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .and_then(|null| rustix::stdio::dup2_stdin(&null).map_err(std::io::Error::from));
    closed.map_err(|error| format!("the window could not close its standard input: {error}"))?;
    Ok(engine)
}

/// The engine's path that `input` holds up to its end.
///
/// # Errors
///
/// That `input` could not be read, or held nothing or more than a path.
pub fn read_engine(input: impl Read) -> Result<PathBuf, String> {
    let mut bytes = Vec::new();
    input
        .take(ENGINE_MAX as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("the window could not read its engine: {error}"))?;
    if bytes.is_empty() {
        return Err("no engine came on standard input".to_string());
    }
    if bytes.len() > ENGINE_MAX {
        return Err("the engine on standard input is longer than a path".to_string());
    }
    Ok(PathBuf::from(OsString::from_vec(bytes)))
}

/// Whether `env` is the allowlist's own for `runtime`: its home is a
/// directory right in `runtime`, and the allowlist taken from `env` with
/// that home is `env` itself.
#[must_use]
pub fn runs_on_allowlist(env: &[(OsString, OsString)], runtime: &Path) -> bool {
    let Some(home) = env
        .iter()
        .find(|(key, _)| key == "HOME")
        .map(|(_, value)| PathBuf::from(value))
    else {
        return false;
    };
    if home.parent() != Some(runtime) {
        return false;
    }
    let mut given = env.to_vec();
    given.sort();
    window_env::vars(pairs(env), runtime, &home) == given
}

/// The command that starts `program` again by the window's name alone, with
/// `args`, on `vars` and nothing else, in `/`, with `input` as its standard
/// input and `/dev/null` as its output.
#[must_use]
pub fn restart_command(
    program: &Path,
    args: &[OsString],
    vars: &[(OsString, OsString)],
    input: impl Into<Stdio>,
) -> Command {
    let mut command = Command::new(program);
    command
        .arg0(text::APP_ID)
        .args(args)
        .env_clear()
        .envs(vars.iter().map(|(key, value)| (key, value)))
        .current_dir("/")
        .stdin(input)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn pairs(
    env: &[(OsString, OsString)],
) -> impl Iterator<Item = (&std::ffi::OsStr, &std::ffi::OsStr)> {
    env.iter()
        .map(|(key, value)| (key.as_os_str(), value.as_os_str()))
}

/// What [`window_env::judge`] needs to know of `dir`, read without following
/// a symlink.
fn facts_of(dir: &Path) -> std::io::Result<DirFacts> {
    let meta = std::fs::symlink_metadata(dir)?;
    let in_ram = meta.is_dir()
        && rustix::fs::statfs(dir).is_ok_and(|fs| i128::from(fs.f_type) == TMPFS_MAGIC);
    Ok(DirFacts {
        is_dir: meta.is_dir(),
        owner: meta.uid(),
        mode: meta.mode() & 0o7777,
        in_ram,
    })
}

/// Make the window's own directory in `runtime`: a fresh, neutral name and
/// mode 0700. The window runs as the operator, so it is the operator's.
fn make_own_dir(runtime: &Path) -> std::io::Result<PathBuf> {
    let mut random = [0u8; window_env::OWN_DIR_BYTES];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let dir = runtime.join(window_env::own_dir_name(&random));
    // A fresh name: an entry already there fails the creation instead of
    // being reused.
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
}

#[cfg(test)]
#[path = "process_tests.rs"]
mod tests;
