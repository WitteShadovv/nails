// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The running kernel's SELinux, as the label of NAILS's program in RAM
//! ([`crate::whole_root::program_label`]) and the disk guard's check of the
//! policy ([`crate::whole_root::guard_policy`]) need it.
//!
//! Where SELinux runs with a policy loaded, a program PID 1 starts runs in the
//! domain the policy gives a start from PID 1's context through the label of
//! the program's file, and in PID 1's own domain where it gives none.
//! [`Selinux`] holds what the label's checks ask: PID 1's context, this
//! process's own and that of the running systemd-udevd, the context the policy
//! gives a start or a new file, which permissions the policy denies, whether a
//! policy capability is on, and the label of a file, written and read.
//! [`Kernel`] answers them on the running system: the contexts from
//! `/proc/1/attr/current`, `/proc/self/attr/current` and that file of the
//! systemd-udevd process; the policy's answers from selinuxfs, the kernel's
//! interface to the loaded policy, through its `create` and `access` files, as
//! libselinux's `security_compute_create_name` and `security_compute_av` ask
//! them, and its `policy_capabilities` directory; and the label from the
//! file's `security.selinux` attribute, which the kernel answers from its own
//! record of the file where SELinux runs.
//!
//! No policy gives a domain on a kernel that runs no SELinux, which makes no
//! mount point for selinuxfs in sysfs at boot ([`SELINUXFS`]), nor on one that
//! runs it with no policy loaded, where every process has the context
//! `kernel`: there [`Selinux::pid1`] is `None`. Where sysfs itself is not
//! mounted, nothing tells, and the question fails. A kernel that runs a policy
//! is asked through selinuxfs, so a selinuxfs that is not mounted there fails
//! the questions about the policy, as does a caller the policy does not let
//! ask them.

use rustix::fd::BorrowedFd;
use rustix::fs::XattrFlags;
use std::io::{self, Read as _, Write as _};
use std::path::Path;

/// Where selinuxfs is mounted, and where the kernel makes its mount point at
/// boot when it runs SELinux.
pub const SELINUXFS: &str = "/sys/fs/selinux";

/// PID 1's SELinux context.
const PID1_CONTEXT: &str = "/proc/1/attr/current";

/// This process's own SELinux context.
const OWN_CONTEXT: &str = "/proc/self/attr/current";

/// Where the kernel lists the running processes, each in a directory named by
/// its number.
const PROCFS: &str = "/proc";

/// The name the kernel gives systemd-udevd's process (`comm`), from the file
/// systemd starts it from, a link to `udevadm` or not.
pub const UDEVD_COMM: &str = "systemd-udevd";

/// The unit systemd runs udevd in, whose cgroup holds udevd's process.
pub const UDEVD_UNIT: &str = "systemd-udevd.service";

/// The context of every process on a kernel that runs SELinux with no policy
/// loaded.
const NO_POLICY: &str = "kernel";

/// The extended attribute that holds a file's SELinux label.
pub const LABEL_XATTR: &str = "security.selinux";

/// The largest value the kernel returns for an extended attribute
/// (`XATTR_SIZE_MAX`): a buffer this size reads any label in one call.
pub const LABEL_MAX: usize = 64 * 1024;

/// The questions the label of NAILS's program asks SELinux, and the label of a
/// file written and read: tests replace it.
pub trait Selinux: std::fmt::Debug {
    /// PID 1's context, or `None` where no policy gives a program a domain:
    /// the kernel runs no SELinux, or runs it with no policy loaded.
    fn pid1(&self) -> io::Result<Option<String>>;
    /// This process's own context, asked only where [`Selinux::pid1`] tells
    /// of a policy: the domain it runs in.
    fn current(&self) -> io::Result<String>;
    /// The context of the running systemd-udevd, which starts the programs
    /// its rules name, or `None` where none runs: asked only where
    /// [`Selinux::pid1`] tells of a policy.
    fn udevd(&self) -> io::Result<Option<String>>;
    /// The context the loaded policy gives a process in `source` that starts
    /// a program from a file labelled `file`: `source` again where it gives
    /// none of its own.
    fn exec_context(&self, source: &str, file: &str) -> io::Result<String>;
    /// The label the loaded policy gives a new object of `class` (`file`,
    /// `dir`) that a process in `source` makes in a directory labelled
    /// `parent`, under the name `name` where one is given: the rules for that
    /// name apply as well as those for any name.
    fn new_label(
        &self,
        source: &str,
        parent: &str,
        class: &str,
        name: Option<&str>,
    ) -> io::Result<String>;
    /// Those of `perms`, permissions of `class`, that the loaded policy denies
    /// `source` on `target`, in their order.
    fn denied(
        &self,
        source: &str,
        target: &str,
        class: &str,
        perms: &[&'static str],
    ) -> io::Result<Vec<&'static str>>;
    /// Whether the loaded policy turns the policy capability `name` on.
    fn capability(&self, name: &str) -> io::Result<bool>;
    /// Write `value` as the label of the open file `file`.
    fn set_label(&self, file: BorrowedFd<'_>, value: &[u8]) -> io::Result<()>;
    /// The label of the open file `file`, as the kernel gives it.
    fn label(&self, file: BorrowedFd<'_>) -> io::Result<Vec<u8>>;
    /// The label of the file at `path`, a link in its last component not
    /// followed, as the kernel gives it.
    fn path_label(&self, path: &Path) -> io::Result<String>;
}

/// The running kernel's SELinux.
#[derive(Debug, Clone, Copy, Default)]
pub struct Kernel;

/// The running kernel, for the hosts that hold a `&'static dyn Selinux`.
pub static KERNEL: Kernel = Kernel;

impl Selinux for Kernel {
    fn pid1(&self) -> io::Result<Option<String>> {
        pid1_context(Path::new(SELINUXFS), Path::new(PID1_CONTEXT))
    }

    fn current(&self) -> io::Result<String> {
        own_context(Path::new(OWN_CONTEXT))
    }

    fn udevd(&self) -> io::Result<Option<String>> {
        udevd_context_in(Path::new(PROCFS))
    }

    fn exec_context(&self, source: &str, file: &str) -> io::Result<String> {
        exec_context_in(Path::new(SELINUXFS), source, file, transact)
    }

    fn new_label(
        &self,
        source: &str,
        parent: &str,
        class: &str,
        name: Option<&str>,
    ) -> io::Result<String> {
        new_label_in(
            Path::new(SELINUXFS),
            (source, parent, class),
            name,
            transact,
        )
    }

    fn denied(
        &self,
        source: &str,
        target: &str,
        class: &str,
        perms: &[&'static str],
    ) -> io::Result<Vec<&'static str>> {
        denied_in(
            Path::new(SELINUXFS),
            (source, target, class),
            perms,
            transact,
        )
    }

    fn capability(&self, name: &str) -> io::Result<bool> {
        capability_in(Path::new(SELINUXFS), name)
    }

    fn set_label(&self, file: BorrowedFd<'_>, value: &[u8]) -> io::Result<()> {
        rustix::fs::fsetxattr(file, LABEL_XATTR, value, XattrFlags::empty())
            .map_err(io::Error::from)
    }

    fn label(&self, file: BorrowedFd<'_>) -> io::Result<Vec<u8>> {
        let mut value = vec![0; LABEL_MAX];
        let len = rustix::fs::fgetxattr(file, LABEL_XATTR, &mut value[..])?;
        value.truncate(len);
        Ok(value)
    }

    fn path_label(&self, path: &Path) -> io::Result<String> {
        let mut value = vec![0; LABEL_MAX];
        let len = rustix::fs::lgetxattr(path, LABEL_XATTR, &mut value[..])?;
        value.truncate(len);
        context_text(&value)
    }
}

/// A transaction on a selinuxfs file: write the request, read the answer.
type Transact = fn(&Path, &str) -> io::Result<Vec<u8>>;

/// [`Selinux::exec_context`] through the selinuxfs at `selinuxfs`: its
/// `create` file, asked for a process of `source` that starts a file of
/// `file`, answers the context the start enters.
fn exec_context_in(
    selinuxfs: &Path,
    source: &str,
    file: &str,
    transact: Transact,
) -> io::Result<String> {
    new_label_in(selinuxfs, (source, file, "process"), None, transact)
}

/// [`Selinux::new_label`] through the selinuxfs at `selinuxfs`: its `create`
/// file, asked for an object of `class` that a process of `source` makes in
/// `parent`, with `name` where one is given, answers the label of the object.
/// The name goes in percent-encoded, as the kernel reads it, wherever it holds
/// a byte other than a letter, a digit, `.`, `_` or `-`.
fn new_label_in(
    selinuxfs: &Path,
    (source, parent, class): (&str, &str, &str),
    name: Option<&str>,
    transact: Transact,
) -> io::Result<String> {
    let index = class_index(selinuxfs, class)?;
    let mut request = format!("{source} {parent} {index}");
    if let Some(name) = name {
        request.push(' ');
        request.push_str(&percent_encoded(name));
    }
    let answer = transact(&selinuxfs.join("create"), &request)?;
    context_text(&answer)
}

/// `name` as selinuxfs's `create` file reads a name: every byte other than a
/// letter, a digit, `.`, `_` or `-` as `%` and two hexadecimal digits, since
/// the kernel reads `+` as a blank and a name ends at a blank.
fn percent_encoded(name: &str) -> String {
    let mut encoded = String::with_capacity(name.len());
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// [`Selinux::denied`] through the selinuxfs at `selinuxfs`: its `access`
/// file, asked about `source` on `target` in `class`, answers the
/// permissions the policy allows, and each of `perms` it leaves out is
/// denied.
fn denied_in(
    selinuxfs: &Path,
    (source, target, class): (&str, &str, &str),
    perms: &[&'static str],
    transact: Transact,
) -> io::Result<Vec<&'static str>> {
    let index = class_index(selinuxfs, class)?;
    let answer = transact(
        &selinuxfs.join("access"),
        &format!("{source} {target} {index}"),
    )?;
    let allowed = allowed_of(&answer)?;
    let mut denied = Vec::new();
    for &perm in perms {
        if allowed & perm_bit(selinuxfs, class, perm)? == 0 {
            denied.push(perm);
        }
    }
    Ok(denied)
}

/// [`Selinux::capability`] through the selinuxfs at `selinuxfs`: its
/// `policy_capabilities` directory holds a file for each capability the
/// kernel knows, which reads `1` where the loaded policy turns it on and `0`
/// where it does not. A capability the kernel does not know is an error.
fn capability_in(selinuxfs: &Path, name: &str) -> io::Result<bool> {
    let path = selinuxfs.join("policy_capabilities").join(name);
    let text = std::fs::read_to_string(&path).map_err(|e| at(&path, e))?;
    match text.trim() {
        "1" => Ok(true),
        "0" => Ok(false),
        other => Err(invalid(format!(
            "{}: {other:?} is neither 1 nor 0",
            path.display()
        ))),
    }
}

/// PID 1's context as [`Kernel`] reads it ([`Selinux::pid1`]): `None` without
/// the mount point `selinuxfs` in a sysfs that is there, or where the file
/// `pid1` reads `kernel`, the context of every process where no policy is
/// loaded. Without the sysfs the mount point would be in, nothing tells
/// whether the kernel runs SELinux, which is an error.
fn pid1_context(selinuxfs: &Path, pid1: &Path) -> io::Result<Option<String>> {
    if let Err(e) = std::fs::symlink_metadata(selinuxfs) {
        if e.kind() != io::ErrorKind::NotFound {
            return Err(at(selinuxfs, e));
        }
        let sysfs = selinuxfs.parent().unwrap_or(selinuxfs);
        return std::fs::symlink_metadata(sysfs)
            .map(|_| None)
            .map_err(|e| at(sysfs, e));
    }
    let context = context_text(&std::fs::read(pid1).map_err(|e| at(pid1, e))?)?;
    Ok((context != NO_POLICY).then_some(context))
}

/// This process's own context as [`Kernel`] reads it ([`Selinux::current`])
/// from the file `own`.
fn own_context(own: &Path) -> io::Result<String> {
    context_text(&std::fs::read(own).map_err(|e| at(own, e))?)
}

/// The context of the running systemd-udevd as [`Kernel`] reads it
/// ([`Selinux::udevd`]) from the procfs at `proc`: the process named
/// [`UDEVD_COMM`] in the cgroup of [`UDEVD_UNIT`], whose `attr/current` gives
/// its context. A process that ends while it is read is not it. `None` where
/// no such process runs; an error where `proc` cannot be listed or udevd's
/// context cannot be read.
fn udevd_context_in(proc: &Path) -> io::Result<Option<String>> {
    for entry in std::fs::read_dir(proc).map_err(|e| at(proc, e))? {
        let entry = entry.map_err(|e| at(proc, e))?;
        let name = entry.file_name();
        if name.is_empty() || !name.as_encoded_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }
        let dir = entry.path();
        let named_so = std::fs::read_to_string(dir.join("comm"))
            .is_ok_and(|comm| comm.trim_end_matches('\n') == UDEVD_COMM);
        let in_unit = named_so
            && std::fs::read_to_string(dir.join("cgroup")).is_ok_and(|cgroup| {
                crate::cgroup::service_unit_from_cgroup(&cgroup).as_deref() == Some(UDEVD_UNIT)
            });
        if in_unit {
            return own_context(&dir.join("attr/current")).map(Some);
        }
    }
    Ok(None)
}

/// A context as the kernel gives it, without the NUL or the newline it ends
/// with. One that is empty, is not UTF-8, or holds a blank, a NUL or a newline
/// of its own is an error: a request names each context as one word.
fn context_text(raw: &[u8]) -> io::Result<String> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| invalid("an SELinux context that is not UTF-8".to_string()))?
        .trim_end_matches(['\0', '\n']);
    if text.is_empty() || text.contains(|c: char| c.is_whitespace() || c == '\0') {
        return Err(invalid(format!("{text:?} is no SELinux context")));
    }
    Ok(text.to_string())
}

/// The type of `context`, its third field: the domain of a process, the type
/// of a file. `None` where `context` has no third field, as `kernel`.
pub fn type_of(context: &str) -> Option<&str> {
    let mut fields = context.splitn(4, ':');
    let (_user, _role, kind) = (fields.next()?, fields.next()?, fields.next()?);
    (!kind.is_empty()).then_some(kind)
}

/// The number the loaded policy gives `class`, which a request names it by.
fn class_index(selinuxfs: &Path, class: &str) -> io::Result<u16> {
    let path = selinuxfs.join("class").join(class).join("index");
    let text = std::fs::read_to_string(&path).map_err(|e| at(&path, e))?;
    text.trim()
        .parse()
        .map_err(|_| invalid(format!("{}: {text:?} is no class number", path.display())))
}

/// The bit of `perm` in the access vectors of `class`: the loaded policy
/// numbers a class's permissions from 1 to 32.
fn perm_bit(selinuxfs: &Path, class: &str, perm: &str) -> io::Result<u32> {
    let path = selinuxfs.join("class").join(class).join("perms").join(perm);
    let text = std::fs::read_to_string(&path).map_err(|e| at(&path, e))?;
    match text.trim().parse::<u32>() {
        Ok(number @ 1..=32) => Ok(1 << (number - 1)),
        _ => Err(invalid(format!(
            "{}: {text:?} is no permission number",
            path.display()
        ))),
    }
}

/// The permissions an answer of selinuxfs's `access` allows: the first of its
/// words, in hexadecimal.
fn allowed_of(answer: &[u8]) -> io::Result<u32> {
    let text = String::from_utf8_lossy(answer);
    text.split_whitespace()
        .next()
        .and_then(|allowed| u32::from_str_radix(allowed, 16).ok())
        .ok_or_else(|| invalid(format!("{text:?} is no access decision")))
}

/// Write `request` to the selinuxfs file at `path` and read its answer, as
/// one transaction on one open file.
fn transact(path: &Path, request: &str) -> io::Result<Vec<u8>> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| at(path, e))?;
    let written = file.write(request.as_bytes()).map_err(|e| at(path, e))?;
    if written != request.len() {
        return Err(at(
            path,
            io::Error::new(io::ErrorKind::WriteZero, "the request was cut short"),
        ));
    }
    let mut answer = vec![0; 4096];
    let len = file.read(&mut answer).map_err(|e| at(path, e))?;
    answer.truncate(len);
    Ok(answer)
}

/// `error`, saying the path it came from.
fn at(path: &Path, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{}: {error}", path.display()))
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[path = "selinux_tests.rs"]
mod tests;
