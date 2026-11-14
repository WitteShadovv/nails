// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Research build only: how the units that run the RAM copy of the binary
//! start it, for an experiment on an enforcing SELinux host. This module lives
//! on a research branch that is never merged.
//!
//! Every unit that runs a RAM copy (the transition step of
//! `systemd-soft-reboot.service`, the hidden session's watcher and sleep guard,
//! the decoy's reconcile one-shot and wtmpdb writer after the way back) takes
//! its start lines from [`service_lines`]. Which mechanism they use is read
//! from [`CELL_FILE`], which only the experiment's harness writes, before the
//! activation:
//!
//! - no file, or `none`: [`Mechanism::Direct`], the start command names the
//!   copy, as the shipped units do;
//! - `env`: [`Mechanism::Env`], the copy starts through `/usr/bin/env`, a
//!   program PID 1 makes a domain transition on;
//! - `context`: [`Mechanism::Context`], the unit sets `SELinuxContext=` to the
//!   unconfined service domain and names the copy;
//! - `relabel`: [`Mechanism::Relabel`], the start command names the copy, and
//!   every RAM copy gets the label of a program in `/usr/bin` when it is
//!   written ([`relabel_copy`]), so PID 1 makes a domain transition on the
//!   copy itself.
//!
//! [`trace`] appends the SELinux context of every start of the binary to
//! [`TRACE_FILE`] when its directory exists, so the harness can read the domain
//! of a step that ends before anything could look at it. Without the
//! harness's files neither changes anything.

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// The file that names the mechanism; only the experiment's harness writes it.
pub const CELL_FILE: &str = "/run/dsx/dsxcell";

/// The directory whose existence turns [`trace`] on.
pub const TRACE_DIR: &str = "/run/dsx/dsxrec";

/// The file [`trace`] appends to.
pub const TRACE_FILE: &str = "/run/dsx/dsxrec/dsxtrace";

/// The trampoline of [`Mechanism::Env`].
pub const ENV: &str = "/usr/bin/env";

/// The context of [`Mechanism::Context`]: the unconfined service domain of a
/// targeted policy.
pub const CONTEXT: &str = "system_u:system_r:unconfined_service_t:s0";

/// The label [`relabel_copy`] gives a RAM copy: that of a program in
/// `/usr/bin` under a targeted policy.
pub const PROGRAM_LABEL: &str = "system_u:object_r:bin_t:s0";

/// How a unit starts the RAM copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// The start command names the copy.
    Direct,
    /// The start command runs the copy through [`ENV`].
    Env,
    /// The unit sets `SELinuxContext=` to [`CONTEXT`] and names the copy.
    Context,
    /// The start command names the copy, which carries [`PROGRAM_LABEL`].
    Relabel,
}

impl Mechanism {
    /// The mechanism `text` names; anything unknown is [`Mechanism::Direct`].
    pub fn parse(text: &str) -> Self {
        match text.trim() {
            "env" => Self::Env,
            "context" => Self::Context,
            "relabel" => Self::Relabel,
            _ => Self::Direct,
        }
    }
}

/// The mechanism [`CELL_FILE`] names, or [`Mechanism::Direct`] without it.
pub fn mechanism() -> Mechanism {
    mechanism_from(Path::new(CELL_FILE))
}

/// The mechanism the file at `path` names, or [`Mechanism::Direct`] when it
/// cannot be read.
pub fn mechanism_from(path: &Path) -> Mechanism {
    std::fs::read_to_string(path).map_or(Mechanism::Direct, |text| Mechanism::parse(&text))
}

/// The `[Service]` lines that start `command` (the copy and its arguments)
/// with `mechanism`, the start command prefixed with `prefix` (`-` or
/// nothing).
pub fn lines_for(mechanism: Mechanism, prefix: &str, command: &str) -> String {
    match mechanism {
        Mechanism::Direct | Mechanism::Relabel => format!("ExecStart={prefix}{command}\n"),
        Mechanism::Env => format!("ExecStart={prefix}{ENV} {command}\n"),
        Mechanism::Context => format!("SELinuxContext={CONTEXT}\nExecStart={prefix}{command}\n"),
    }
}

/// [`lines_for`] with the mechanism [`CELL_FILE`] names.
pub fn service_lines(prefix: &str, command: &str) -> String {
    lines_for(mechanism(), prefix, command)
}

/// Give the RAM copy at `path` [`PROGRAM_LABEL`] when [`CELL_FILE`] names
/// [`Mechanism::Relabel`]; nothing otherwise. Best effort: a copy that keeps
/// its label starts as it would with the shipped units.
pub fn relabel_copy(path: &Path) {
    if mechanism() == Mechanism::Relabel {
        let mut value = PROGRAM_LABEL.as_bytes().to_vec();
        value.push(0);
        let _ = rustix::fs::setxattr(
            path,
            "security.selinux",
            &value,
            rustix::fs::XattrFlags::empty(),
        );
    }
}

/// The text of a `/proc/self/attr` entry, or the error reading it gave.
fn attr(name: &str) -> String {
    match std::fs::read(Path::new("/proc/self/attr").join(name)) {
        Ok(bytes) => String::from_utf8_lossy(&bytes)
            .trim_end_matches(['\0', '\n'])
            .to_string(),
        Err(error) => format!("<{error}>"),
    }
}

/// One line for [`trace`]: the boot clock, the process and its parent, its
/// SELinux context now and before its last `execve`, and its arguments.
pub fn trace_line(argv: &[OsString]) -> String {
    let uptime = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|text| text.split_whitespace().next().map(str::to_string))
        .unwrap_or_default();
    let args: Vec<String> = argv
        .iter()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    format!(
        "uptime={uptime} pid={} ppid={} current={} prev={} args={}\n",
        std::process::id(),
        rustix::process::Pid::as_raw(rustix::process::getppid()),
        attr("current"),
        attr("prev"),
        args.join(" ")
    )
}

/// Append [`trace_line`] to [`TRACE_FILE`] when [`TRACE_DIR`] exists.
pub fn trace(argv: &[OsString]) {
    if !Path::new(TRACE_DIR).is_dir() {
        return;
    }
    let line = trace_line(argv);
    let _ = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o666)
        .open(TRACE_FILE)
        .and_then(|mut file| file.write_all(line.as_bytes()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mechanism_is_direct_unless_named() {
        assert_eq!(Mechanism::parse("env\n"), Mechanism::Env);
        assert_eq!(Mechanism::parse("context"), Mechanism::Context);
        assert_eq!(Mechanism::parse("relabel"), Mechanism::Relabel);
        assert_eq!(Mechanism::parse("none"), Mechanism::Direct);
        assert_eq!(Mechanism::parse(""), Mechanism::Direct);
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            mechanism_from(&dir.path().join("missing")),
            Mechanism::Direct
        );
        std::fs::write(dir.path().join("cell"), "context\n").unwrap();
        assert_eq!(mechanism_from(&dir.path().join("cell")), Mechanism::Context);
    }

    #[test]
    fn each_mechanism_starts_the_copy_its_way() {
        let command = "/run/overlay-runtime/control transition";
        assert_eq!(
            lines_for(Mechanism::Direct, "-", command),
            "ExecStart=-/run/overlay-runtime/control transition\n"
        );
        assert_eq!(
            lines_for(Mechanism::Env, "-", command),
            "ExecStart=-/usr/bin/env /run/overlay-runtime/control transition\n"
        );
        assert_eq!(
            lines_for(Mechanism::Relabel, "-", command),
            "ExecStart=-/run/overlay-runtime/control transition\n"
        );
        assert_eq!(
            lines_for(Mechanism::Context, "", command),
            "SELinuxContext=system_u:system_r:unconfined_service_t:s0\n\
             ExecStart=/run/overlay-runtime/control transition\n"
        );
    }

    #[test]
    fn a_trace_line_names_the_arguments() {
        let line = trace_line(&["control".into(), "transition".into()]);
        assert!(line.contains(" args=transition\n"), "{line}");
        assert!(line.starts_with("uptime="), "{line}");
    }
}
