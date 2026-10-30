// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! How the window reaches the engine's helper, decided before the toolkit
//! starts.
//!
//! - **From the launcher.** `sudo <root>/nails gui` starts the helper as root
//!   and the window as the operator on the two ends of one socket pair; the
//!   window's end is its standard input (file descriptor 0). This works on
//!   the decoy, where the launcher has already checked that the window may
//!   open there, and in a hidden session.
//! - **In a hidden session, from its menu entry.** The entry that activation
//!   writes into the hidden root starts the window as the operator with
//!   `--engine <root>/nails`, and the window asks pkexec to start the helper,
//!   `pkexec <root>/nails helper --stdio`, on a pair of its own. pkexec's
//!   lines land on the hidden volume there, and only there: the window does
//!   this only when `/` is the overlay of a hidden session whose upper lies
//!   on the volume of that engine.
//! - **Anywhere else** (the window started by hand on the decoy, say) it
//!   opens nothing: no display, no session bus, no pkexec. It names the
//!   launcher's line on its standard error and exits.
//!
//! The launcher starts the window from `<root>/gui/bin/session`, beside the
//! engine at `<root>/nails`, so that is the engine a page names when the
//! window was not told one.

use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};

/// How the window reaches the helper.
#[derive(Debug)]
pub enum Start {
    /// On the end of the pair the launcher handed it.
    Launcher {
        /// The window's end of the pair.
        stream: UnixStream,
        /// The engine beside the window, when it lies in a NAILS tree.
        engine: Option<PathBuf>,
    },
    /// By starting `engine helper --stdio` through pkexec, in a hidden
    /// session.
    Pkexec {
        /// The engine the menu entry named.
        engine: PathBuf,
    },
    /// Not at all: the window opens nothing and prints this.
    Refuse(String),
}

/// The engine's file name, beside the window's `gui` directory.
const ENGINE: &str = "nails";

/// The program that starts the helper as root in a hidden session.
pub const PKEXEC: &str = "pkexec";

/// The root the window was installed under, from its own program (or, when
/// it runs through a bundled loader, that loader): `<root>/gui/<dir>/<file>`
/// gives `<root>`. `None` for a program that does not lie in such a tree.
#[must_use]
pub fn install_root(program: &Path) -> Option<PathBuf> {
    let gui = program.parent()?.parent()?;
    if gui.file_name()? != "gui" {
        return None;
    }
    gui.parent().map(Path::to_path_buf)
}

/// The engine of the window installed under `root`.
#[must_use]
pub fn engine_of(root: &Path) -> PathBuf {
    root.join(ENGINE)
}

/// The line that opens the window from a terminal with `engine` (or a
/// placeholder when the engine is not known).
#[must_use]
pub fn gui_line(engine: Option<&Path>) -> String {
    sudo_line(engine, "gui")
}

/// The line that runs `command` of `engine` from a terminal (a placeholder
/// for the engine when it is not known).
#[must_use]
pub fn sudo_line(engine: Option<&Path>, command: &str) -> String {
    match engine {
        Some(engine) => format!("sudo {} {command}", shell_word(&engine.to_string_lossy())),
        None => format!("sudo <hidden volume>/{ENGINE} {command}"),
    }
}

/// `word` as one word of a shell line: as it is when it holds nothing a
/// shell reads specially, else in single quotes.
fn shell_word(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-+:@%=,".contains(&b));
    if plain {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

/// Decide how the window reaches the helper: `engine` is the engine a menu
/// entry named with `--engine`, if any, `launcher` the socket the launcher
/// handed the window, if any, `program` the window's own program and
/// `mountinfo` this process's mount table.
///
/// A named engine is the menu entry's way in, which never reads its standard
/// input as the launcher's socket; the launcher names none.
#[must_use]
pub fn decide(
    engine: Option<PathBuf>,
    launcher: Option<UnixStream>,
    program: &Path,
    mountinfo: Option<&str>,
) -> Start {
    if let Some(engine) = engine {
        let hidden = engine.is_absolute()
            && match (engine.parent(), mountinfo) {
                (Some(root), Some(mountinfo)) => root_is_hidden_overlay(mountinfo, root),
                _ => false,
            };
        if hidden {
            return Start::Pkexec { engine };
        }
        return refuse(Some(&engine));
    }
    let beside = install_root(program).map(|root| engine_of(&root));
    match launcher {
        Some(stream) => Start::Launcher {
            stream,
            engine: beside,
        },
        None => refuse(beside.as_deref()),
    }
}

fn refuse(engine: Option<&Path>) -> Start {
    Start::Refuse(format!(
        "The window opens from a terminal: {}",
        gui_line(engine)
    ))
}

/// Take standard input when it is a socket, which is how the launcher hands
/// the window its end of the pair, and put `/dev/null` in its place, so that
/// dropping the returned stream closes the window's every copy of its end.
/// `None`, and standard input untouched, when it is anything else.
#[must_use]
pub fn take_launcher_socket() -> Option<UnixStream> {
    let stdin = std::io::stdin();
    let owned = stdin.as_fd().try_clone_to_owned().ok()?;
    let file = File::from(owned);
    if !file.metadata().ok()?.file_type().is_socket() {
        return None;
    }
    let null = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .ok()?;
    rustix::stdio::dup2_stdin(&null).ok()?;
    Some(UnixStream::from(std::os::fd::OwnedFd::from(file)))
}

/// Whether `/` is the overlay of a hidden session whose upper lies under
/// `root`, read from `mountinfo` (the text of `/proc/self/mountinfo`). The
/// last mount on `/` is the one in view. Anything unexpected reads as no.
#[must_use]
pub fn root_is_hidden_overlay(mountinfo: &str, root: &Path) -> bool {
    let Some(entry) = mountinfo
        .lines()
        .filter_map(MountLine::parse)
        .rfind(|entry| entry.mount_point == "/")
    else {
        return false;
    };
    if entry.fstype != "overlay" {
        return false;
    }
    entry
        .super_options
        .split(',')
        .filter_map(|option| option.strip_prefix("upperdir="))
        .map(unescape_octal)
        .any(|upper| upper.starts_with('/') && Path::new(&upper).starts_with(root))
}

/// The fields of one mountinfo line the window reads.
struct MountLine<'a> {
    mount_point: String,
    fstype: &'a str,
    super_options: &'a str,
}

impl<'a> MountLine<'a> {
    /// `id parent dev root mount-point options [optional...] - fstype source
    /// super-options`, or `None` for a line of another shape.
    fn parse(line: &'a str) -> Option<Self> {
        let fields: Vec<&str> = line.split(' ').collect();
        let separator = fields.iter().position(|&field| field == "-")?;
        if separator < 6 || fields.len() < separator + 4 {
            return None;
        }
        Some(Self {
            mount_point: unescape_octal(fields[4]),
            fstype: fields[separator + 1],
            super_options: fields[separator + 3],
        })
    }
}

/// Undo the kernel's `\ooo` octal escapes of a mountinfo field.
fn unescape_octal(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes
            .get(i + 1..i + 4)
            .filter(|digits| bytes[i] == b'\\' && digits.iter().all(|d| (b'0'..=b'7').contains(d)))
            .map(|d| {
                u32::from(d[0] - b'0') * 64 + u32::from(d[1] - b'0') * 8 + u32::from(d[2] - b'0')
            })
            .and_then(|value| u8::try_from(value).ok());
        match octal {
            Some(byte) => {
                out.push(byte);
                i += 4;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Start `engine helper --stdio` through `pkexec` (the program [`PKEXEC`]
/// names, or a stand-in of a test) on one end of a new pair, and return the
/// child and the window's end.
///
/// # Errors
///
/// The error of making the pair or of starting pkexec (not found, say).
pub fn start_helper(pkexec: &Path, engine: &Path) -> std::io::Result<(Child, UnixStream)> {
    let (window, helper) = UnixStream::pair()?;
    let mut command = Command::new(pkexec);
    command
        .arg(engine)
        .args(["helper", "--stdio"])
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(helper.try_clone()?)))
        .stdout(Stdio::from(std::os::fd::OwnedFd::from(helper)))
        .stderr(Stdio::null());
    let child = command.spawn();
    // The window keeps no copy of the helper's end, so it reads the end of
    // the pipe as soon as the helper (or pkexec) is gone.
    drop(command);
    Ok((child?, window))
}

/// How pkexec ended before the helper spoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkexecEnd {
    /// The person closed the password dialog: a cancel.
    Dismissed,
    /// No password could be asked for (no authentication agent), or it was
    /// refused.
    NotAuthorized,
    /// pkexec or the helper ended in another way.
    Other(Option<i32>),
}

/// What pkexec's exit `status` means, when the pipe closed before the
/// helper's hello: 126 when the dialog was dismissed, 127 when no agent could
/// ask or the authorization failed (pkexec's own codes).
#[must_use]
pub fn pkexec_end(status: ExitStatus) -> PkexecEnd {
    match status.code() {
        Some(126) => PkexecEnd::Dismissed,
        Some(127) => PkexecEnd::NotAuthorized,
        code => PkexecEnd::Other(code),
    }
}

#[cfg(test)]
#[path = "launch_tests.rs"]
mod tests;
