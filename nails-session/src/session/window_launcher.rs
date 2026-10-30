// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The window's launcher in the hidden session: its menu entry, and the
//! polkit action whose password dialog it opens.
//!
//! A build with the window writes both at every entry, into the next root, so
//! they land in an upper on the hidden volume and never on the decoy:
//!
//! - the menu entry "Session" runs the window as whoever clicks it, naming the
//!   engine it is to start: `<window> --engine <engine>`. The window asks
//!   pkexec for the engine's root helper and nothing else (`pkexec <engine>
//!   helper --stdio`), and talks to it over that pipe, as it talks to the
//!   helper that `nails gui` starts;
//! - the action is that command's. pkexec takes the action whose
//!   `org.freedesktop.policykit.exec.path` is the program it runs (its real
//!   path, from polkit 127 on) and, where the action sets
//!   `org.freedesktop.policykit.exec.argv1`, whose first argument is that one.
//!   It looks at no argument after the first, so the action also matches
//!   `<engine> helper` with more arguments; the helper, started by pkexec,
//!   refuses any but `--stdio` before it does anything, so the one command
//!   the dialog covers is `<engine> helper --stdio`. The dialog says "Session
//!   needs your password each time it opens." instead of naming the engine's
//!   path. Like pkexec's own action, it asks for an administrator's password
//!   every time.
//!
//! Where they go depends on the family. A Debian, Ubuntu, Fedora or Arch root
//! reads both from `/usr/share`, for every account. NixOS reads desktop
//! entries from the store's directories and from each home only, so there the
//! entry goes into the operator's home (`~/.local/share/applications`), and
//! the action into `/etc/polkit-1/actions`, which polkit reads from release
//! 126 on.
//!
//! Every path is resolved inside the next root, as the hidden root will
//! resolve it ([`nextroot`]): a decoy whose `/usr/share/applications` or home
//! is an absolute link never takes a write onto the decoy disk, and a
//! directory that resolves into the Nix store is refused. Writing them is best
//! effort: a failure costs the menu entry, never the activation, and one line
//! says so; `sudo <engine> gui` in a terminal of the session opens the window
//! all the same.

use crate::target_user::TargetUser;
use nails_teardown::whole_root::nextroot;
use rustix::fs::{AtFlags, Mode, OFlags};
use std::ffi::OsStr;
use std::io::Write;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

/// The window's id: the name of its menu entry's file, and the app id the
/// window gives itself so that the desktop puts the two together.
pub const APP_ID: &str = "session";

/// The polkit action of the window's helper.
pub const ACTION_ID: &str = "session.open";

/// The name of the menu entry, and the window's title.
pub const NAME: &str = "Session";

/// What the password dialog says when the window asks for its helper.
pub const MESSAGE: &str = "Session needs your password each time it opens.";

/// The window's option that names the engine whose helper it starts.
pub const ENGINE_OPTION: &str = "--engine";

/// The engine's subcommand for the helper: the first argument the action
/// matches.
pub const HELPER_COMMAND: &str = "helper";

/// The menu entry's directory below the operator's home on NixOS.
const HOME_ENTRIES: &str = ".local/share/applications";

/// The launcher a build with the window writes into the hidden session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowLauncher {
    /// The engine (`<root>/nails`, as the running binary names itself): the
    /// program the action matches.
    pub engine: PathBuf,
    /// The window's program beside it, which the menu entry runs.
    pub window: PathBuf,
}

/// One file of the launcher: where it goes in the hidden root, and what it
/// holds.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Planned<'a> {
    /// Its directory, as the hidden root names it.
    dir: PathBuf,
    /// Its name in that directory.
    name: String,
    /// Its text.
    text: String,
    /// The account that owns it and every directory made for it: the
    /// operator's for a file in the home, the activating account's (root)
    /// otherwise.
    owner: Option<&'a TargetUser>,
}

impl Planned<'_> {
    /// The file as the hidden root names it.
    fn path(&self) -> PathBuf {
        self.dir.join(&self.name)
    }
}

/// `path` as text that a menu entry and a policy can carry: absolute, valid
/// UTF-8, and without a control character.
fn text_of(path: &Path) -> Result<&str, String> {
    let text = path
        .to_str()
        .ok_or_else(|| format!("{} is not valid UTF-8", path.display()))?;
    if !path.is_absolute() {
        return Err(format!("{text} is not an absolute path"));
    }
    if text.chars().any(char::is_control) {
        return Err(format!("{} holds a control character", path.display()));
    }
    Ok(text)
}

/// `arg` as one argument of a desktop entry's `Exec` key: in double quotes,
/// with `"`, `` ` ``, `$` and `\` escaped by a backslash and `%` doubled, then
/// every backslash doubled again, because a reader undoes the string escape of
/// the key's value before it undoes the quoting.
fn exec_arg(arg: &str) -> String {
    let mut quoted = String::from("\"");
    for c in arg.chars() {
        match c {
            '"' | '`' | '$' | '\\' => {
                quoted.push('\\');
                quoted.push(c);
            }
            '%' => quoted.push_str("%%"),
            _ => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted.replace('\\', "\\\\")
}

/// The menu entry: "Session", running the window with the engine it starts.
/// `TryExec` hides it while the window's program is missing.
pub fn desktop_entry(launcher: &WindowLauncher) -> Result<String, String> {
    let window = text_of(&launcher.window)?;
    let engine = text_of(&launcher.engine)?;
    Ok(format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name={NAME}\n\
         Exec={} {ENGINE_OPTION} {}\n\
         TryExec={}\n\
         Terminal=false\n\
         Categories=System;\n",
        exec_arg(window),
        exec_arg(engine),
        window.replace('\\', "\\\\"),
    ))
}

/// The polkit action for `<engine> helper`, with the neutral message and an
/// administrator's password every time.
///
/// polkit keeps only the last piece of an annotation's text that its XML
/// parser hands it, and the parser splits the text at every character
/// reference, so an engine path with a character XML must escape could never
/// match: such a path is refused instead.
pub fn policy(launcher: &WindowLauncher) -> Result<String, String> {
    let engine = text_of(&launcher.engine)?;
    if engine.contains(['&', '<', '>', '"', '\'']) {
        return Err(format!(
            "{engine} holds a character a polkit action cannot match"
        ));
    }
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE policyconfig PUBLIC\n \
         \"-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN\"\n \
         \"http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd\">\n\
         <policyconfig>\n  \
         <action id=\"{ACTION_ID}\">\n    \
         <description>{NAME}</description>\n    \
         <message>{MESSAGE}</message>\n    \
         <defaults>\n      \
         <allow_any>auth_admin</allow_any>\n      \
         <allow_inactive>auth_admin</allow_inactive>\n      \
         <allow_active>auth_admin</allow_active>\n    \
         </defaults>\n    \
         <annotate key=\"org.freedesktop.policykit.exec.path\">{engine}</annotate>\n    \
         <annotate key=\"org.freedesktop.policykit.exec.argv1\">{HELPER_COMMAND}</annotate>\n  \
         </action>\n\
         </policyconfig>\n"
    ))
}

/// The files of the launcher for a hidden root of `nixos`'s family, where
/// `operator` activates. Each one that cannot be planned names why.
fn plan<'a>(
    nixos: bool,
    operator: Option<&'a TargetUser>,
    launcher: &WindowLauncher,
) -> Vec<Result<Planned<'a>, String>> {
    let entry_name = format!("{APP_ID}.desktop");
    let entry = desktop_entry(launcher).and_then(|text| {
        if !nixos {
            return Ok(Planned {
                dir: PathBuf::from("/usr/share/applications"),
                name: entry_name,
                text,
                owner: None,
            });
        }
        let operator = operator.ok_or_else(|| {
            "the menu entry goes into the operator's home, and no operator is known".to_string()
        })?;
        Ok(Planned {
            dir: operator.passwd_home().join(HOME_ENTRIES),
            name: entry_name,
            text,
            owner: Some(operator),
        })
    });
    let policy = policy(launcher).map(|text| Planned {
        dir: PathBuf::from(if nixos {
            "/etc/polkit-1/actions"
        } else {
            "/usr/share/polkit-1/actions"
        }),
        name: format!("{ACTION_ID}.policy"),
        text,
        owner: None,
    });
    vec![entry, policy]
}

/// Write the launcher into the next root `root` of a hidden root of `nixos`'s
/// family, where `operator` activates, and return the files written, as the
/// hidden root names them. One line says what could not be written, if
/// anything; the activation goes on either way.
pub fn put_in_place(
    root: &Path,
    nixos: bool,
    operator: Option<&TargetUser>,
    launcher: &WindowLauncher,
) -> Vec<PathBuf> {
    let mut written = Vec::new();
    let mut failed = Vec::new();
    for planned in plan(nixos, operator, launcher) {
        match planned.and_then(|file| {
            write(root, &file)
                .map(|()| file.path())
                .map_err(|error| format!("{}: {error}", file.path().display()))
        }) {
            Ok(path) => written.push(path),
            Err(why) => failed.push(why),
        }
    }
    if failed.is_empty() {
        tracing::debug!(files = ?written, "the window's launcher is in the hidden session");
    } else {
        tracing::warn!(
            "The window's launcher was not written into the hidden session in full ({}); \
             there, `sudo {} gui` in a terminal opens the window",
            failed.join("; "),
            nails_base::next_step::shell_word(launcher.engine.as_os_str())
        );
    }
    written
}

/// Write `file` into the next root `root`.
fn write(root: &Path, file: &Planned<'_>) -> std::io::Result<()> {
    if let Some(operator) = file.owner
        && nextroot::open_dir_in_root(root, operator.passwd_home()).is_err()
    {
        return Err(std::io::Error::other(
            "the operator's home is not in the hidden root",
        ));
    }
    let dir = nextroot::create_dir_all_in_root(root, &file.dir, &mut |parent, name| {
        made(parent, name, file.owner)
    })?;
    refuse_store(root, &dir)?;
    let _ = rustix::fs::unlinkat(&dir, file.name.as_str(), AtFlags::empty());
    let fd = rustix::fs::openat(
        &dir,
        file.name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    )?;
    let mut out = std::fs::File::from(fd);
    out.write_all(file.text.as_bytes())?;
    rustix::fs::fchmod(&out, Mode::from_raw_mode(0o644))?;
    if let Some(operator) = file.owner {
        std::os::unix::fs::fchown(&out, Some(operator.uid), Some(operator.gid))?;
    }
    Ok(())
}

/// Give the directory `name` just made in `parent` its mode, and its owner
/// when it is in the operator's home: `0700` there, as the XDG base directory
/// specification asks of a directory an application makes, `0755` elsewhere.
/// Opened without following a link, so a swapped entry is never changed.
fn made(parent: BorrowedFd<'_>, name: &OsStr, owner: Option<&TargetUser>) -> std::io::Result<()> {
    let dir = rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mode = if owner.is_some() { 0o700 } else { 0o755 };
    rustix::fs::fchmod(&dir, Mode::from_raw_mode(mode))?;
    if let Some(operator) = owner {
        rustix::fs::fchown(
            dir.as_fd(),
            Some(rustix::fs::Uid::from_raw(operator.uid)),
            Some(rustix::fs::Gid::from_raw(operator.gid)),
        )?;
    }
    Ok(())
}

/// Refuse a directory that resolved into the Nix store, through a link such as
/// a home manager's `~/.local/share/applications`: a file written there would
/// change a store path in the upper.
fn refuse_store(root: &Path, dir: &OwnedFd) -> std::io::Result<()> {
    let root_real = nextroot::open_mount_root(root).and_then(|fd| nextroot::real_path(&fd))?;
    let real = nextroot::real_path(dir)?;
    let inside = real
        .strip_prefix(&root_real)
        .map_err(|_| std::io::Error::other("it resolves outside the hidden root"))?;
    if inside.starts_with("nix/store") {
        return Err(std::io::Error::other(format!(
            "it resolves into the Nix store (/{})",
            inside.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
#[path = "window_launcher_tests.rs"]
mod tests;
