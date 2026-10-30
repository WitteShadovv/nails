// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The soft-reboot request of the entry and the way back, and what logind
//! holds of it.
//!
//! The entry and the way back soft-reboot through logind, as `systemctl
//! soft-reboot` does. logind first tells every program that holds a shutdown
//! delay inhibitor that the system is going down and waits for them (for up
//! to `InhibitDelayMaxSec=`: 5 s by default, 30 s where unattended-upgrades
//! raises it), and only then enqueues `soft-reboot.target` with PID 1. Until
//! then it only holds the request: it can still drop it (on systemd 257 and
//! newer, anyone allowed to reboot can cancel it, `shutdown -c`), and PID 1
//! can still refuse it when the wait ends. A program that holds a shutdown
//! *block* inhibitor is in the middle of something it must not lose (a
//! package or firmware update): logind refuses the request outright on
//! systemd 257 and newer, and lets root override it on 255.
//!
//! So a request is only as good as the job PID 1 holds for it.
//! [`request_soft_reboot`] refuses while a program blocks shutdown, asks
//! logind, and waits until PID 1 holds the job; when logind drops the request
//! or holds it past its own delay, it makes sure nothing is left queued before
//! it reports that nothing will come. [`drop_soft_reboot`] drops what logind
//! still holds for an entry that is being taken down. logind is asked with
//! `busctl` (JSON output), each call bounded: a call that fails reads as
//! logind not being there, except once logind was asked to drop a soft-reboot
//! it held, where only its word that it holds nothing counts.

use crate::whole_root::tools::{self, Outcome, SOFT_REBOOT_TARGET, TOOL_BUDGET};
use serde_json::Value;
use std::path::Path;
use std::time::{Duration, Instant};

/// The tool logind is asked with.
pub const BUSCTL: &str = "busctl";

/// logind's manager object: service, path and interface.
const MANAGER: [&str; 3] = [
    "org.freedesktop.login1",
    "/org/freedesktop/login1",
    "org.freedesktop.login1.Manager",
];

/// The units of a soft-reboot job in PID 1's queue.
const SOFT_REBOOT_UNITS: [&str; 2] = [SOFT_REBOOT_TARGET, "systemd-soft-reboot.service"];

/// One logind inhibitor, as `ListInhibitors` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inhibitor {
    /// What it inhibits, `:`-separated (`shutdown:sleep`).
    pub what: String,
    /// Who holds it.
    pub who: String,
    /// Why.
    pub why: String,
    /// `block`, `block-weak` (systemd 257 and newer) or `delay`.
    pub mode: String,
    /// The holder's process.
    pub pid: u32,
}

impl Inhibitor {
    /// Whether it blocks a shutdown outright. A weak block is one its holder
    /// lets a privileged caller override, and a delay one only holds the
    /// shutdown back until its holder is done.
    pub fn blocks_shutdown(&self) -> bool {
        self.mode == "block" && self.what.split(':').any(|what| what == "shutdown")
    }
}

/// Run `busctl` with JSON output and parse what it printed.
fn busctl_json(busctl: &Path, args: &[&str]) -> Option<Value> {
    let mut all = vec!["--json=short", "--timeout=2"];
    all.extend_from_slice(args);
    let text = tools::run_output(busctl, &all, TOOL_BUDGET)?;
    serde_json::from_str(text.trim()).ok()
}

/// The value of the manager's property `name`.
fn property(busctl: &Path, name: &str) -> Option<Value> {
    let mut args = vec!["get-property"];
    args.extend(MANAGER);
    args.push(name);
    busctl_json(busctl, &args).and_then(|reply| reply.get("data").cloned())
}

/// The reply of the manager's method `name`, called without arguments.
fn call(busctl: &Path, name: &str) -> Option<Value> {
    let mut args = vec!["call"];
    args.extend(MANAGER);
    args.push(name);
    busctl_json(busctl, &args).and_then(|reply| reply.get("data").cloned())
}

/// Whether logind holds a shutdown (`PreparingForShutdown`): from the moment
/// it accepts the request until the system goes down, or until it drops it.
pub fn preparing_for_shutdown(busctl: &Path) -> Option<bool> {
    property(busctl, "PreparingForShutdown")?.as_bool()
}

/// How long logind holds a shutdown back for delay inhibitors
/// (`InhibitDelayMaxUSec`).
pub fn delay_max(busctl: &Path) -> Option<Duration> {
    property(busctl, "InhibitDelayMaxUSec")?
        .as_u64()
        .map(Duration::from_micros)
}

/// The inhibitors logind knows of.
pub fn inhibitors(busctl: &Path) -> Option<Vec<Inhibitor>> {
    parse_inhibitors(&call(busctl, "ListInhibitors")?)
}

/// The inhibitors in the data of a `ListInhibitors` reply: one argument, an
/// array of `(what, who, why, mode, uid, pid)`.
fn parse_inhibitors(data: &Value) -> Option<Vec<Inhibitor>> {
    let text = |entry: &Value, index: usize| entry.get(index)?.as_str().map(str::to_string);
    data.get(0)?
        .as_array()?
        .iter()
        .map(|entry| {
            Some(Inhibitor {
                what: text(entry, 0)?,
                who: text(entry, 1)?,
                why: text(entry, 2)?,
                mode: text(entry, 3)?,
                pid: u32::try_from(entry.get(5)?.as_u64()?).ok()?,
            })
        })
        .collect()
}

/// The kind of shutdown logind holds (`soft-reboot`, `reboot`, `poweroff`…),
/// `None` when it holds none or cannot be asked. Systemd 257 and newer name it
/// in the shutdown's metadata; 255 only in the shutdown it scheduled, which a
/// cancel clears, so there it may be the empty string.
pub fn shutdown_held(busctl: &Path) -> Option<String> {
    if !preparing_for_shutdown(busctl)? {
        return None;
    }
    let named = property(busctl, "PreparingForShutdownWithMetadata")
        .and_then(|data| data.get("type")?.get("data")?.as_str().map(str::to_string));
    Some(named.unwrap_or_else(|| {
        property(busctl, "ScheduledShutdown")
            .and_then(|data| data.get(0)?.as_str().map(str::to_string))
            .unwrap_or_default()
    }))
}

/// Ask logind to drop the shutdown it holds (`CancelScheduledShutdown`).
/// Since systemd 257 that drops a soft-reboot it still holds back for a delay
/// inhibitor too; systemd 255 keeps such a request until its delay ends.
pub fn cancel(busctl: &Path) -> Option<bool> {
    call(busctl, "CancelScheduledShutdown")?.get(0)?.as_bool()
}

/// Whether PID 1 holds a soft-reboot job, `None` when it cannot be asked.
pub fn pid1_holds_soft_reboot(systemctl: &Path) -> Option<bool> {
    let list = tools::run_output(
        systemctl,
        &["list-jobs", "--plain", "--no-legend", "--full"],
        TOOL_BUDGET,
    )?;
    Some(
        tools::job_units(&list)
            .iter()
            .any(|unit| SOFT_REBOOT_UNITS.contains(&unit.as_str())),
    )
}

/// How long [`request_soft_reboot`] waits and how often it looks.
#[derive(Debug, Clone, Copy)]
pub struct Waits {
    /// Between two looks.
    pub poll: Duration,
    /// Past logind's own delay, for its timer and a slow PID 1.
    pub margin: Duration,
    /// The most of logind's delay it waits out.
    pub cap: Duration,
}

impl Waits {
    /// The waits of a switch.
    pub const SWITCH: Waits = Waits {
        poll: Duration::from_millis(100),
        margin: Duration::from_secs(10),
        cap: Duration::from_secs(120),
    };
}

/// Whether the switch is still wanted, asked between two looks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wanted {
    /// Go on waiting.
    Yes,
    /// It was called off, for this reason (its plan was taken down).
    No(String),
}

/// What became of a soft-reboot request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// PID 1 holds the soft-reboot job: the switch comes.
    Queued,
    /// Nothing is queued: a program blocks shutdown, logind refused the
    /// soft-reboot, or it dropped it. The reason, for the operator.
    Refused(String),
    /// The switch was called off, but logind still holds the soft-reboot and
    /// cannot drop it (systemd 255): it comes when logind's delay ends.
    Held(String),
}

/// Ask logind for the soft-reboot, as `systemctl soft-reboot` does (without
/// its wall message), and wait until PID 1 holds the job.
///
/// - A program that holds a shutdown block inhibitor is in the middle of
///   something: refused, naming it, before logind is asked.
/// - logind refuses (a block inhibitor taken in between, or a shutdown or
///   sleep it already holds): refused with its reason. Nothing is queued.
/// - logind takes it: the wait lasts as long as logind may hold it back
///   (its `InhibitDelayMaxUSec`, at most `waits.cap`) plus `waits.margin`.
///   PID 1 holding the job ends it. logind dropping the request (cancelled,
///   or refused by PID 1) is a refusal: nothing is queued.
/// - Past the wait, logind is asked to drop the request: dropped, it is a
///   refusal; kept (systemd 255 cannot drop it) or not answered, the
///   soft-reboot is enqueued with PID 1 directly, as logind would do it when
///   its delay ends, so that nothing is left to come later.
/// - Without logind, `systemctl` enqueues it with PID 1 itself; a call cut
///   short with nothing held anywhere is enqueued directly.
///
/// `wanted` is asked between two looks: called off, logind is asked to drop
/// the request and nothing is enqueued.
pub fn request_soft_reboot(
    systemctl: &Path,
    busctl: Option<&Path>,
    waits: Waits,
    wanted: &mut dyn FnMut() -> Wanted,
) -> Request {
    if let Some(blocker) = busctl
        .and_then(inhibitors)
        .and_then(|list| list.into_iter().find(Inhibitor::blocks_shutdown))
    {
        return Request::Refused(format!(
            "{} blocks shutdown ({}, PID {})",
            blocker.who, blocker.why, blocker.pid
        ));
    }
    let (asked, said) = tools::run_explained(systemctl, &["--no-wall", "soft-reboot"], TOOL_BUDGET);
    if asked == Outcome::Refused && pid1_holds_soft_reboot(systemctl) != Some(true) {
        return Request::Refused(if said.is_empty() {
            "logind refused the soft-reboot".to_string()
        } else {
            said
        });
    }
    let allowed = busctl
        .and_then(delay_max)
        .unwrap_or_default()
        .min(waits.cap)
        + waits.margin;
    let deadline = Instant::now() + allowed;
    loop {
        if pid1_holds_soft_reboot(systemctl) == Some(true) {
            return Request::Queued;
        }
        if let Wanted::No(why) = wanted() {
            return give_up(systemctl, busctl, why, false);
        }
        if busctl.and_then(preparing_for_shutdown) == Some(false) {
            // logind holds nothing; PID 1 may have taken the job meanwhile.
            if pid1_holds_soft_reboot(systemctl) == Some(true) {
                return Request::Queued;
            }
            if asked == Outcome::Unknown {
                // The call was cut short before logind took it.
                return enqueue(systemctl);
            }
            return Request::Refused(
                "logind dropped the soft-reboot before it started: it was cancelled, or PID 1 \
                 refused it"
                    .to_string(),
            );
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(waits.poll);
    }
    give_up(
        systemctl,
        busctl,
        format!(
            "the soft-reboot did not start within {} s",
            allowed.as_secs()
        ),
        true,
    )
}

/// End a wait that brought no job: ask logind to drop the request, then
/// report a refusal when it no longer holds one, or else enqueue the
/// soft-reboot directly (`enqueue_if_held`) or report it held.
fn give_up(systemctl: &Path, busctl: Option<&Path>, why: String, enqueue_if_held: bool) -> Request {
    if let Some(busctl) = busctl {
        let _ = cancel(busctl);
    }
    if pid1_holds_soft_reboot(systemctl) == Some(true) {
        return Request::Queued;
    }
    match busctl.and_then(preparing_for_shutdown) {
        Some(false) => Request::Refused(format!("{why}; nothing is queued")),
        _ if enqueue_if_held => enqueue(systemctl),
        _ => Request::Held(format!(
            "{why}, but logind still holds the soft-reboot and cannot drop it: it comes \
             when logind's delay ends"
        )),
    }
}

/// Enqueue the soft-reboot with PID 1 directly.
fn enqueue(systemctl: &Path) -> Request {
    match tools::start_target(systemctl, SOFT_REBOOT_TARGET) {
        Outcome::Done | Outcome::Unknown => Request::Queued,
        Outcome::Refused => Request::Refused("PID 1 refused the soft-reboot".to_string()),
    }
}

/// What is left of a soft-reboot after [`drop_soft_reboot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pending {
    /// No soft-reboot is held: none was, or logind dropped it.
    Nothing,
    /// logind holds one it cannot drop (systemd 255), or stopped answering
    /// once asked to drop it: it comes when logind's delay ends.
    Held,
    /// PID 1 holds the soft-reboot job: it is under way.
    Started,
}

/// Drop the soft-reboot logind still holds, for an entry being taken down.
/// A shutdown of another kind (a reboot someone asked for) is left alone.
pub fn drop_soft_reboot(systemctl: Option<&Path>, busctl: Option<&Path>) -> Pending {
    if systemctl.and_then(pid1_holds_soft_reboot) == Some(true) {
        return Pending::Started;
    }
    let Some(busctl) = busctl else {
        return Pending::Nothing;
    };
    match shutdown_held(busctl) {
        Some(kind) if kind.is_empty() || kind == "soft-reboot" => {}
        _ => return Pending::Nothing,
    }
    let _ = cancel(busctl);
    if systemctl.and_then(pid1_holds_soft_reboot) == Some(true) {
        return Pending::Started;
    }
    // logind held it a moment ago: only its word that it holds nothing now
    // counts, one that stopped answering may still hold it.
    match preparing_for_shutdown(busctl) {
        Some(false) => Pending::Nothing,
        Some(true) | None => Pending::Held,
    }
}

#[cfg(test)]
#[path = "logind_tests.rs"]
mod tests;
