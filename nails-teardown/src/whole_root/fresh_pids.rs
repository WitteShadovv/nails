// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Process numbers after the way back that read like a fresh boot.
//!
//! A soft-reboot keeps the kernel, and with it the counter the kernel hands
//! out process numbers from. Every process the decoy and the hidden session
//! started moved it on, so without help the decoy's units would start on the
//! way back with numbers no fresh boot gives them: where the decoy keeps
//! classic wtmp, its getty and login records keep those numbers on the decoy
//! disk, next to the low numbers of every earlier boot.
//!
//! The way back sets the counter (`/proc/sys/kernel/ns_last_pid`) back as its
//! very last step ([`lower`]), when every hidden process has stopped and
//! before PID 1 starts a single decoy unit. The kernel skips a number still in
//! use, so nothing can get a number twice. Where to set it is measured
//! ([`Record`]):
//!
//! 1. the entry, in the decoy, records the number of an anchor, a process the
//!    decoy's boot started and every start of its service manager starts again
//!    (the getty, else logind), and the lowest number the decoy's own
//!    userspace holds, the floor ([`record`]);
//! 2. the entry's switch records the counter as it hands over to the hidden
//!    root, which a soft-reboot starts much as it starts the decoy again;
//! 3. the way back, armed in the hidden session, reads how many numbers the
//!    hidden start used up to its own copy of the anchor, and sets the counter
//!    that many below the decoy's anchor ([`counter`]), so the decoy's anchor
//!    gets about the number its own boot gave it.
//!
//! Without an anchor to measure by, the counter goes to just below the floor.
//! A soft-reboot starts fewer processes than a cold boot (no initrd, no file
//! system check, no new kernel threads for the devices it finds), so from the
//! floor the getty lands about a hundred numbers below a cold boot's.
//!
//! It is best effort and never blocks the way back: without a record, outside
//! PID 1's PID namespace, when the counter is already lower or cannot be
//! written (a kernel built without `CONFIG_CHECKPOINT_RESTORE` has no such
//! file), the numbers continue as before. The transition cannot report that,
//! so `deactivate` checks before the switch ([`way_back_can_lower`]) and warns.

use crate::proc::parse_stat;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The kernel's last allocated process number of the writer's PID namespace.
pub const NS_LAST_PID: &str = "/proc/sys/kernel/ns_last_pid";

/// The processes the entry may anchor on, by `comm`, in order: the getty,
/// whose number reaches wtmp, then logind.
pub const ANCHORS: [&str; 2] = ["agetty", "systemd-logind"];

/// How far above the floor an anchor may sit: one further up was started
/// again long after the boot and says nothing about where its units began.
const ANCHOR_SPAN: u32 = 2048;

/// How many numbers a start of the service manager may use up to its anchor
/// for the measure to count.
const START_SPAN: u32 = 4096;

/// A process the entry anchors on: its `comm`, its controlling terminal (the
/// getty of tty1 is told from a serial one) and its number in the decoy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    /// The process's `comm`, one of [`ANCHORS`].
    pub comm: String,
    /// Its controlling terminal, as `/proc/<pid>/stat` gives it (0 for none).
    pub tty: i32,
    /// Its number in the decoy.
    pub pid: u32,
}

/// What the session measures to set the counter back on the way back.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The lowest number the decoy's own userspace held at entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floor: Option<u32>,
    /// The decoy's anchors at entry, in the order of [`ANCHORS`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchors: Vec<Anchor>,
    /// The counter as the entry's switch handed over to the hidden root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at_switch: Option<u32>,
    /// The counter the way back sets, measured when it was armed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter: Option<u32>,
}

impl Record {
    /// Whether nothing was recorded.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The counter the way back sets: the measured one, else just below the
    /// floor.
    pub fn way_back_counter(&self) -> Option<u32> {
        self.counter
            .or_else(|| self.floor.map(|floor| floor.saturating_sub(1).max(1)))
    }
}

/// A live userspace process in the root PID 1 runs in.
struct Process {
    pid: u32,
    comm: String,
    tty: i32,
}

/// Every live userspace process in the root PID 1 runs in, under the procfs
/// at `proc` (`/proc` on the real system): neither PID 1 nor a kernel thread
/// nor a zombie, nor a process kept from the initrd or running in another root
/// (a chroot or a container), whose numbers say nothing about where this
/// root's start began.
fn processes(proc: &Path) -> Vec<Process> {
    let Some(root) = file_id(&proc.join("1").join("root")) else {
        return Vec::new();
    };
    let Ok(dir) = std::fs::read_dir(proc) else {
        return Vec::new();
    };
    dir.flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|&pid| pid > 1)
        .filter_map(|pid| {
            let dir = proc.join(pid.to_string());
            let stat = parse_stat(&std::fs::read_to_string(dir.join("stat")).ok()?)?;
            if stat.is_kernel_thread()
                || stat.state == 'Z'
                || file_id(&dir.join("root")) != Some(root)
            {
                return None;
            }
            let comm = std::fs::read_to_string(dir.join("comm")).ok()?;
            Some(Process {
                pid,
                comm: comm.trim_end_matches('\n').to_string(),
                tty: stat.tty,
            })
        })
        .collect()
}

/// The lowest number of a live userspace process in the root PID 1 runs in
/// (see [`processes`]). `None` when there is none.
pub fn boot_floor(proc: &Path) -> Option<u32> {
    processes(proc).iter().map(|p| p.pid).min()
}

/// The entry's part of the record, read in the decoy under the procfs at
/// `proc`: the floor ([`boot_floor`]) and, for each of [`ANCHORS`], the
/// lowest-numbered such process that sits no more than [`ANCHOR_SPAN`] above
/// the floor.
pub fn record(proc: &Path) -> Record {
    let live = processes(proc);
    let Some(floor) = live.iter().map(|p| p.pid).min() else {
        return Record::default();
    };
    let anchors = ANCHORS
        .iter()
        .filter_map(|comm| {
            let first = live
                .iter()
                .filter(|p| p.comm == *comm)
                .min_by_key(|p| p.pid)?;
            (first.pid - floor <= ANCHOR_SPAN).then(|| Anchor {
                comm: first.comm.clone(),
                tty: first.tty,
                pid: first.pid,
            })
        })
        .collect();
    Record {
        floor: Some(floor),
        anchors,
        ..Record::default()
    }
}

/// The counter the way back sets, measured in the hidden session under the
/// procfs at `proc` when it is armed: for the first anchor the hidden start
/// also runs (the same `comm` on the same terminal), the decoy's number of it
/// less the numbers the hidden start used up to its own copy. `None` when no
/// anchor can be measured, which leaves the floor.
pub fn counter(record: &Record, proc: &Path) -> Option<u32> {
    let at_switch = record.at_switch?;
    let live = processes(proc);
    record.anchors.iter().find_map(|anchor| {
        let hidden = live
            .iter()
            .filter(|p| p.comm == anchor.comm && p.tty == anchor.tty)
            .map(|p| p.pid)
            .min()?;
        let used = hidden
            .checked_sub(at_switch)
            .filter(|&n| n > 0 && n <= START_SPAN)?;
        anchor.pid.checked_sub(used).filter(|&c| c >= 1)
    })
}

/// The device and inode of the file `path` names, following a link: the
/// directory a `/proc/<pid>/root` link names, or a namespace.
fn file_id(path: &Path) -> Option<(u64, u64)> {
    std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

/// Where [`lower`] looks.
#[derive(Debug, Clone)]
pub struct Places {
    /// The counter, [`NS_LAST_PID`].
    pub ns_last_pid: PathBuf,
    /// This process's PID namespace (`/proc/self/ns/pid`).
    pub own_namespace: PathBuf,
    /// PID 1's PID namespace (`/proc/1/ns/pid`).
    pub init_namespace: PathBuf,
}

impl Places {
    /// The real system.
    pub fn system() -> Self {
        Self::under(Path::new("/"))
    }

    /// The places below `root` (`/` on the real system).
    pub fn under(root: &Path) -> Self {
        let proc = root.join("proc");
        Self {
            ns_last_pid: root.join(NS_LAST_PID.trim_start_matches('/')),
            own_namespace: proc.join("self/ns/pid"),
            init_namespace: proc.join("1/ns/pid"),
        }
    }

    /// Whether this process runs in PID 1's PID namespace, whose counter the
    /// decoy's units are numbered from.
    fn in_init_namespace(&self) -> bool {
        match (file_id(&self.own_namespace), file_id(&self.init_namespace)) {
            (Some(own), Some(init)) => own == init,
            _ => false,
        }
    }

    /// PID 1's counter now: `None` when it cannot be read or this process
    /// runs in another PID namespace.
    pub fn current(&self) -> Option<u32> {
        if !self.in_init_namespace() {
            return None;
        }
        std::fs::read_to_string(&self.ns_last_pid)
            .ok()?
            .trim()
            .parse()
            .ok()
    }
}

/// What [`lower`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lowered {
    /// The counter was set to this number: the next process gets the lowest
    /// free number above it.
    Set(u32),
    /// The plan records nothing to set it to.
    NoRecord,
    /// This process does not run in PID 1's PID namespace.
    OtherNamespace,
    /// The counter is at or below that number already.
    AlreadyLow,
    /// The counter could not be read or written.
    Failed,
}

/// Set the counter to `target` ([`Record::way_back_counter`]), so the next
/// process PID 1 starts is numbered as the decoy's own boot numbered its
/// units. Never raises the counter. See the module docs.
pub fn lower(target: Option<u32>, places: &Places) -> Lowered {
    let Some(target) = target else {
        return Lowered::NoRecord;
    };
    if !places.in_init_namespace() {
        return Lowered::OtherNamespace;
    }
    let Some(current) = places.current() else {
        return Lowered::Failed;
    };
    if current <= target {
        return Lowered::AlreadyLow;
    }
    match std::fs::write(&places.ns_last_pid, target.to_string()) {
        Ok(()) => Lowered::Set(target),
        Err(_) => Lowered::Failed,
    }
}

/// Whether the way back will be able to set the counter back, checked in the
/// hidden session before the switch: the plan records where to (`record`),
/// this process runs in PID 1's PID namespace, and the counter takes a write.
/// The write puts back the value just read, which changes nothing: a process
/// started in between only makes the kernel skip the number it took.
pub fn way_back_can_lower(record: &Record, places: &Places) -> bool {
    record.floor.is_some()
        && places
            .current()
            .is_some_and(|now| std::fs::write(&places.ns_last_pid, now.to_string()).is_ok())
}

#[cfg(test)]
#[path = "fresh_pids_tests.rs"]
mod tests;
