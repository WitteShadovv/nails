// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the running kernel's SELinux makes of a program PID 1 starts.
//!
//! Where SELinux runs with a policy loaded, a program PID 1 starts runs in the
//! domain the policy gives a start from PID 1's context through the label of
//! the program's file, and in PID 1's own domain where it gives none:
//! [`crate::whole_root::exec_prefix`] says why that matters to NAILS's steps.
//! [`Selinux`] holds the questions its checks ask: PID 1's context, the label
//! of a file, the context the policy gives a start, and which permissions the
//! policy denies. [`Kernel`] answers them on the running system: the label
//! from the file's `security.selinux` attribute, which the kernel answers from
//! its own record of the file where SELinux runs; PID 1's context from
//! [`PID1_CONTEXT`]; and the policy's answers from selinuxfs, the kernel's
//! interface to the loaded policy, through its `create` and `access` files, as
//! libselinux's `security_compute_create` and `security_compute_av` ask them.
//!
//! No policy gives a domain on a kernel that runs no SELinux, which makes no
//! mount point for selinuxfs in sysfs at boot ([`SELINUXFS`]), nor on one that
//! runs it with no policy loaded, where every process has the context
//! [`NO_POLICY`]: there [`Selinux::pid1`] is `None` and nothing else is asked.
//! Where sysfs itself is not mounted, nothing tells, and the question fails. A
//! kernel that runs a policy is asked through selinuxfs, so a selinuxfs that
//! is not mounted there fails the questions about the policy, as does a caller
//! the policy does not let ask them.

use crate::whole_root::nextroot;
use std::io::{self, Read as _, Write as _};
use std::path::Path;

/// Where selinuxfs is mounted, and where the kernel makes its mount point at
/// boot when it runs SELinux.
pub const SELINUXFS: &str = "/sys/fs/selinux";

/// PID 1's SELinux context.
pub const PID1_CONTEXT: &str = "/proc/1/attr/current";

/// The context of every process on a kernel that runs SELinux with no policy
/// loaded.
pub const NO_POLICY: &str = "kernel";

/// The questions a check of PID 1's start of a program asks SELinux.
pub trait Selinux {
    /// PID 1's context, or `None` where no policy gives a program a domain:
    /// the kernel runs no SELinux, or runs it with no policy loaded.
    fn pid1(&self) -> io::Result<Option<String>>;
    /// The label of the file at `path` as if `root` were `/`, its links
    /// followed inside `root`.
    fn label(&self, root: &Path, path: &Path) -> io::Result<String>;
    /// The context the loaded policy gives a process in `source` that starts
    /// a program from a file labelled `file`: `source` again where it gives
    /// none of its own.
    fn exec_context(&self, source: &str, file: &str) -> io::Result<String>;
    /// Those of `perms`, permissions of `class`, that the loaded policy denies
    /// `source` on `target`, in their order.
    fn denied(
        &self,
        source: &str,
        target: &str,
        class: &str,
        perms: &[&'static str],
    ) -> io::Result<Vec<&'static str>>;
}

/// The running kernel's SELinux.
#[derive(Debug, Clone, Copy, Default)]
pub struct Kernel;

impl Selinux for Kernel {
    fn pid1(&self) -> io::Result<Option<String>> {
        pid1_context(Path::new(SELINUXFS), Path::new(PID1_CONTEXT))
    }

    /// From the attribute [`nextroot::label_in_root`] reads.
    fn label(&self, root: &Path, path: &Path) -> io::Result<String> {
        context_text(&nextroot::label_in_root(root, path)?)
    }

    fn exec_context(&self, source: &str, file: &str) -> io::Result<String> {
        exec_context_in(Path::new(SELINUXFS), source, file, transact)
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
    let process = class_index(selinuxfs, "process")?;
    let answer = transact(
        &selinuxfs.join("create"),
        &format!("{source} {file} {process}"),
    )?;
    context_text(&answer)
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

/// PID 1's context as [`Kernel`] reads it ([`Selinux::pid1`]): `None` without
/// the mount point `selinuxfs` in a sysfs that is there, or where the file
/// `pid1` reads [`NO_POLICY`]. Without the sysfs the mount point would be in,
/// nothing tells whether the kernel runs SELinux, which is an error.
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

/// A context as the kernel gives it, without the NUL or the newline it ends
/// with. One that is empty, is not UTF-8, or holds a blank, a NUL or a newline
/// of its own is an error: a request names each context as one word.
pub fn context_text(raw: &[u8]) -> io::Result<String> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| invalid("an SELinux context that is not UTF-8".to_string()))?
        .trim_end_matches(['\0', '\n']);
    if text.is_empty() || text.contains(|c: char| c.is_whitespace() || c == '\0') {
        return Err(invalid(format!("{text:?} is no SELinux context")));
    }
    Ok(text.to_string())
}

/// The type of `context`, its third field: the domain of a process. `None`
/// where `context` has no third field, as [`NO_POLICY`].
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
