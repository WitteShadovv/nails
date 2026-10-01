//! External Program Execution
//!
//! nails starts external programs through a [`ProcessRunner`]. The real
//! runner is the one place that decides:
//!
//! - **which binary runs**: host tools resolve to an absolute path from a fixed
//!   list of system directories ([`SYSTEM_TOOL_DIRS`]) instead of the caller's
//!   `PATH`, which can point into user-writable profiles while nails runs as
//!   root;
//! - **whether it may run at all**: commands are refused in test and test-like
//!   runtimes unless they opt in, so a test that reaches the real runner gets
//!   an error instead of stopping services or signalling host processes;
//! - **how the child starts**: stdin is closed and stdout/stderr are captured.
//!
//! Call sites describe a command with [`ProcessCommand`]; unit tests substitute
//! a recording runner.

use crate::{NailsError, Result};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;

/// Directories searched, in order, for [`Program::Tool`].
///
/// The NixOS system profile comes first, then the FHS locations used by
/// Debian, Ubuntu and most other distributions. All of them are root-owned on
/// a sane host.
pub const SYSTEM_TOOL_DIRS: &[&str] = &[
    "/run/current-system/sw/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

/// The executable a [`ProcessCommand`] starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Program {
    /// A host tool such as `systemctl`, resolved from [`SYSTEM_TOOL_DIRS`].
    Tool(&'static str),
    /// A binary looked up on the caller's `PATH`.
    ///
    /// Only the Nix toolchain (`nix`, `nixos-rebuild`) still resolves this
    /// way: the builder tests and the VM tests substitute stub builds by
    /// prepending a directory to `PATH`, so moving it to [`Program::Tool`]
    /// needs a different stub mechanism first.
    CallerPath(&'static str),
    /// An exact executable, such as a system generation's
    /// `switch-to-configuration` script.
    Exact(PathBuf),
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tool(name) | Self::CallerPath(name) => f.write_str(name),
            Self::Exact(path) => write!(f, "{}", path.display()),
        }
    }
}

/// One external command: the program, its arguments and environment changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessCommand {
    program: Program,
    args: Vec<OsString>,
    removed_env: Vec<OsString>,
    allowed_in_test_runtime: bool,
}

impl ProcessCommand {
    /// A command that runs `program` with no arguments.
    pub fn new(program: Program) -> Self {
        Self {
            program,
            args: Vec::new(),
            removed_env: Vec::new(),
            allowed_in_test_runtime: false,
        }
    }

    /// A command running the host tool `name`; see [`Program::Tool`].
    pub fn tool(name: &'static str) -> Self {
        Self::new(Program::Tool(name))
    }

    /// A command running `name` from the caller's `PATH`; see
    /// [`Program::CallerPath`].
    pub fn caller_path(name: &'static str) -> Self {
        Self::new(Program::CallerPath(name))
    }

    /// A command running the executable at `path`.
    pub fn exact(path: impl Into<PathBuf>) -> Self {
        Self::new(Program::Exact(path.into()))
    }

    /// Appends one argument.
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    /// Appends several arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|arg| arg.as_ref().to_os_string()));
        self
    }

    /// Removes `key` from the environment the child inherits.
    pub fn env_remove(mut self, key: impl AsRef<OsStr>) -> Self {
        self.removed_env.push(key.as_ref().to_os_string());
        self
    }

    /// Lets the command run in test and test-like runtimes.
    ///
    /// Commands are refused there by default because most of them act on the
    /// running host. Opt in only for commands whose effects stay inside paths
    /// the caller chose, or that tests deliberately point at stubs.
    pub fn allow_in_test_runtime(mut self) -> Self {
        self.allowed_in_test_runtime = true;
        self
    }
}

impl fmt::Display for ProcessCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.program)?;
        for arg in &self.args {
            write!(f, " {}", arg.to_string_lossy())?;
        }
        Ok(())
    }
}

/// Starts external programs.
pub trait ProcessRunner {
    /// Runs `command` to completion and returns its exit status and output.
    ///
    /// A non-zero exit is not an error; callers inspect [`Output::status`].
    fn run(&self, command: &ProcessCommand) -> Result<Output>;

    /// Runs `command` and returns whether it succeeded, with stdout and
    /// stderr decoded lossily as UTF-8.
    fn run_text(&self, command: &ProcessCommand) -> Result<(bool, String, String)> {
        let output = self.run(command)?;
        Ok((
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ))
    }
}

/// Runner that starts real processes on the host.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealProcessRunner;

impl ProcessRunner for RealProcessRunner {
    fn run(&self, command: &ProcessCommand) -> Result<Output> {
        if !command.allowed_in_test_runtime && crate::runtime_safety::should_skip_host_interaction()
        {
            return Err(NailsError::InvalidState(format!(
                "Refusing to run {} from a test/test-like runtime context; use a mock process runner or executor instead",
                command.program
            )));
        }

        let executable = resolve(&command.program)?;
        tracing::debug!("Running {} ({})", command, executable.display());

        let mut child = std::process::Command::new(&executable);
        child.args(&command.args);
        for key in &command.removed_env {
            child.env_remove(key);
        }

        child.output().map_err(|err| {
            NailsError::IoError(std::io::Error::new(
                err.kind(),
                format!("failed to start {}: {}", executable.display(), err),
            ))
        })
    }
}

/// `systemctl <args>`, shared by the restart and session executors.
pub(crate) fn systemctl_command(args: &[&str]) -> ProcessCommand {
    ProcessCommand::tool("systemctl").args(args)
}

/// `kill -<signal> <pid>`, shared by the restart and session executors.
pub(crate) fn signal_command(pid: u32, signal: &str) -> ProcessCommand {
    ProcessCommand::tool("kill")
        .arg(format!("-{}", signal))
        .arg(pid.to_string())
}

/// Resolves `program` to the absolute path that is executed.
fn resolve(program: &Program) -> Result<PathBuf> {
    match program {
        Program::Tool(name) => find_executable(name, SYSTEM_TOOL_DIRS.iter().map(Path::new))
            .ok_or_else(|| {
                not_found(format!(
                    "{} not found in {}",
                    name,
                    SYSTEM_TOOL_DIRS.join(", ")
                ))
            }),
        Program::CallerPath(name) => {
            let path = std::env::var_os("PATH").unwrap_or_default();
            // Relative entries would make the result depend on the working
            // directory, so only absolute ones are searched.
            let dirs: Vec<PathBuf> = std::env::split_paths(&path)
                .filter(|dir| dir.is_absolute())
                .collect();
            find_executable(name, dirs.iter().map(PathBuf::as_path))
                .ok_or_else(|| not_found(format!("{} not found on PATH", name)))
        }
        Program::Exact(path) => Ok(path.clone()),
    }
}

/// First `dir/name` that is a regular file with an execute bit set.
fn find_executable<'a>(name: &str, dirs: impl IntoIterator<Item = &'a Path>) -> Option<PathBuf> {
    dirs.into_iter()
        .map(|dir| dir.join(name))
        .find(|candidate| {
            std::fs::metadata(candidate).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
}

fn not_found(message: String) -> NailsError {
    NailsError::IoError(std::io::Error::new(std::io::ErrorKind::NotFound, message))
}

#[cfg(test)]
mod mock;
#[cfg(test)]
pub(crate) use mock::{MockProcessRunner, exited};

#[cfg(test)]
mod tests;
