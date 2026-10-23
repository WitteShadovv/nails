// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Having the decoy's wtmpdb boot writer record the way back as the boot a
//! power cycle records.
//!
//! wtmpdb's boot writer (`wtmpdb boot`, the start of
//! `wtmpdb-update-boot.service`) chooses the name and the time of the boot row
//! it adds like this (`main_boot` in wtmpdb 0.73.0, the release Debian 13
//! ships, the same since 0.13.0):
//!
//! - it asks the service manager over the system bus how many soft-reboots
//!   this boot has had (`SoftRebootsCount`, systemd 256 and newer). One or
//!   more, and the row is `soft-reboot`, stamped now;
//! - when it cannot ask, it goes by the kernel's uptime (`CLOCK_BOOTTIME`):
//!   above 300 seconds the row is `soft-reboot` stamped now, otherwise
//!   `reboot` stamped with the time the kernel started, now minus the uptime;
//! - with no soft-reboot to report, as after a power cycle, the row is
//!   `reboot`, stamped with the time the kernel started.
//!
//! A soft-reboot keeps the kernel, so on the way back the service manager
//! reports the session's soft-reboots and the uptime runs from the decoy's
//! cold boot. Left alone, the writer names the row `soft-reboot`. Kept from
//! the bus, it still does once the decoy has been up for five minutes, and
//! before that it stamps a `reboot` row with the decoy's cold boot, earlier
//! than the shutdown that precedes it (`wtmpdb last` then lists that boot as
//! a crash).
//!
//! So for the decoy's first start after the way back, a drop-in has the
//! writer's unit start it through [`run`]: in a time namespace whose boot
//! clock starts at the switch, with the system bus pointed at nothing. The
//! writer takes its fallback, finds an uptime of seconds and writes what a
//! power cycle writes: a `reboot` row stamped with the time of the switch.
//!
//! wtmpdb itself writes that row, in its own SQLite transaction, so the
//! database holds what that boot would leave: no second transaction, no
//! rollback journal of NAILS's own, no page rewritten after the fact, no file
//! time later than the insert, and the word `soft-reboot` never reaches the
//! disk. The other way, renaming the row after the writer has written it,
//! would put `soft-reboot` on the disk first (flash storage can keep the old
//! copy after the rewrite), leave a page layout and file times that one
//! insert does not leave, and need a SQLite writer of NAILS's own.
//!
//! The drop-in changes the start only: the writer's stop (`wtmpdb shutdown`,
//! which records the shutdown time) runs as the decoy has it. [`run`] removes
//! the drop-in before it starts the writer, so a later soft-reboot of the
//! decoy finds the writer's unit as the decoy has it. Where a step fails, or
//! the kernel does not move a started program into a time namespace (before
//! Linux 6.2), the writer runs as it would without NAILS. On the namespace
//! path its output, which would only report the missing bus, goes nowhere.

use crate::noatime;
use crate::whole_root::boot_records::{self, FIXUP_DIR};
use crate::whole_root::plan::{self, SERVICE_CONFIG_MODE};
use std::ffi::OsString;
use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

/// The argument the drop-in passes to the RAM copy of the binary to start the
/// writer. Neutral, like the other transition-side arguments.
pub const WRITER_ARG: &str = "boot-writer";

/// The wtmpdb boot writer's unit.
pub const WRITER_UNIT: &str = "wtmpdb-update-boot.service";

/// The drop-in directory for [`WRITER_UNIT`], below a `/run` root.
pub const DROPIN_DIR: &str = "systemd/system/wtmpdb-update-boot.service.d";

/// The drop-in's file name (neutral), sorted late so that its start command
/// replaces the decoy's.
pub const DROPIN_NAME: &str = "zz-overlay-runtime.conf";

/// The drop-in on the decoy, as the artifact registry names it.
pub const DROPIN_PATH: &str =
    "/run/systemd/system/wtmpdb-update-boot.service.d/zz-overlay-runtime.conf";

/// The decoy's wtmpdb database, relative to its root: Debian's path, then the
/// upstream default. Either present means wtmpdb records the decoy's boots.
const DATABASES: [&str; 2] = ["var/log/wtmp.db", "var/lib/wtmpdb/wtmp.db"];

/// Where the decoy's packages install units, below its root.
const VENDOR_UNIT_DIRS: [&str; 2] = ["usr/lib/systemd/system", "lib/systemd/system"];

/// Where the decoy's administrator changes units, below its root.
const ADMIN_UNIT_DIR: &str = "etc/systemd/system";

/// The variable libsystemd reads the system bus address from.
const BUS_ENV: &str = "DBUS_SYSTEM_BUS_ADDRESS";

/// The longest uptime the writer is shown. It takes an uptime as such only up
/// to 300 seconds, and names the row `soft-reboot` past that. A decoy whose
/// start took longer than this from the switch to the writer gets a row
/// stamped this long before the writer ran, still after the shutdown before
/// it; the margin covers the writer's own start.
const UPTIME_CAP: Duration = Duration::from_secs(240);

/// The first Linux release that moves a program into the time namespace its
/// caller unshared when it is executed, not only when a child is forked.
const EXEC_ENTERS_TIME_NS: (u32, u32) = (6, 2);

/// The decoy's wtmpdb boot writer, as the command its unit starts, when the
/// way back can run it through [`run`]. `root` is the decoy root. `None` when
/// the decoy keeps no wtmpdb database, has no such unit, changes the unit
/// with a file of its own, or starts something other than one plain `wtmpdb
/// boot` command: the writer then runs as the decoy has it. The unit is read
/// without updating its access time.
pub fn writer_command(root: &Path) -> Option<Vec<String>> {
    if !DATABASES.iter().any(|db| root.join(db).is_file()) {
        return None;
    }
    // An administrator's unit or any drop-in may change the command; only the
    // unit as the package ships it is known.
    let mut changed = std::iter::once(root.join(ADMIN_UNIT_DIR).join(WRITER_UNIT)).chain(
        std::iter::once(ADMIN_UNIT_DIR)
            .chain(VENDOR_UNIT_DIRS)
            .map(|dir| root.join(dir).join(format!("{WRITER_UNIT}.d"))),
    );
    if changed.any(|path| path.symlink_metadata().is_ok()) {
        return None;
    }
    let unit = VENDOR_UNIT_DIRS
        .iter()
        .map(|dir| root.join(dir).join(WRITER_UNIT))
        .find(|path| path.is_file())?;
    let command = start_command(&read_noatime(&unit).ok()?)?;
    let program = command.first()?;
    root.join(program.trim_start_matches('/'))
        .is_file()
        .then_some(command)
}

/// Read `path` as UTF-8 without updating its access time.
fn read_noatime(path: &Path) -> io::Result<String> {
    use rustix::fs::{Mode, OFlags, open};
    let fd = noatime::with_noatime(|flags| {
        open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | flags,
            Mode::empty(),
        )
    })?;
    let mut text = String::new();
    std::fs::File::from(fd).read_to_string(&mut text)?;
    Ok(text)
}

/// The one start command of a unit's `[Service]` section, split into words,
/// when it is a plain `wtmpdb boot`: an absolute path to `wtmpdb`, then
/// `boot`, then plain words. `None` for anything else, a continued line
/// included, so a command this module cannot run unchanged is never replaced.
fn start_command(unit: &str) -> Option<Vec<String>> {
    let mut section = "";
    let mut starts: Vec<&str> = Vec::new();
    for line in unit.lines().map(str::trim) {
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.ends_with('\\') {
            return None;
        }
        if line.starts_with('[') {
            section = line;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if section == "[Service]" && key.trim() == "ExecStart" {
            match value.trim() {
                "" => starts.clear(),
                value => starts.push(value),
            }
        }
    }
    let [command] = starts.as_slice() else {
        return None;
    };
    // A prefix (`-`, `@`, `+`, `!`, `:`, `|`), quoting, an escape, a variable
    // or a specifier would change what systemd runs from what the words say.
    if command.starts_with(['-', '@', '+', '!', ':', '|'])
        || command.contains(['"', '\'', '\\', '$', '%', ';'])
    {
        return None;
    }
    let words: Vec<String> = command.split_ascii_whitespace().map(String::from).collect();
    let is_writer = words.first().is_some_and(|program| {
        program.starts_with('/')
            && Path::new(program).file_name() == Some(std::ffi::OsStr::new("wtmpdb"))
    }) && words.get(1).map(String::as_str) == Some("boot");
    is_writer.then_some(words)
}

/// The arguments the drop-in passes to the binary copy: [`WRITER_ARG`], the
/// boot clock at the switch and the writer's command.
pub fn writer_args(switched_at: Duration, writer: &[String]) -> Vec<String> {
    [WRITER_ARG.to_string(), boot_records::clock_arg(switched_at)]
        .into_iter()
        .chain(writer.iter().cloned())
        .collect()
}

/// The drop-in text: it replaces the writer's start command with the binary
/// copy at `binary`, which starts the writer through [`run`].
fn dropin_text(binary: &Path, switched_at: Duration, writer: &[String]) -> String {
    format!(
        "[Service]\nExecStart=\nExecStart={} {}\n",
        binary.display(),
        writer_args(switched_at, writer).join(" ")
    )
}

/// Install the drop-in under `run` (readable by all, as PID 1 wants its
/// configuration).
pub fn install_dropin(
    run: &Path,
    binary: &Path,
    switched_at: Duration,
    writer: &[String],
) -> io::Result<()> {
    let dir = run.join(DROPIN_DIR);
    std::fs::create_dir_all(&dir)?;
    plan::write_atomic_with_mode(
        &dir.join(DROPIN_NAME),
        dropin_text(binary, switched_at, writer).as_bytes(),
        SERVICE_CONFIG_MODE,
    )
}

/// Remove the drop-in under `run`, and its directory when that is left empty.
pub fn remove_dropin(run: &Path) {
    let dir = run.join(DROPIN_DIR);
    let _ = std::fs::remove_file(dir.join(DROPIN_NAME));
    let _ = std::fs::remove_dir(&dir);
}

/// The system bus address the writer is given: a path in the binary copy's
/// directory that nothing ever creates.
fn no_bus_address() -> String {
    format!("unix:path=/run/{FIXUP_DIR}/no-bus")
}

/// Start the decoy's writer (`writer`, its command) in place of this process,
/// as the drop-in's start command: see the module docs. `run` is the `/run`
/// root and `switched_at` the boot clock at the switch. Returns only when the
/// writer could not be started.
pub fn run(run: &Path, switched_at: Duration, writer: &[OsString]) -> io::Error {
    // One start only: a later soft-reboot of the decoy finds its own unit.
    remove_dropin(run);
    match prepare(switched_at, writer) {
        Some(mut command) => command.exec(),
        None => io::Error::new(io::ErrorKind::InvalidInput, "no writer command"),
    }
}

/// The writer's command, `None` when `writer` is empty. When the kernel can
/// start it in a time namespace whose boot clock starts at `switched_at`,
/// the calling thread unshares that namespace now (it applies to what the
/// thread starts from then on, not to itself) and the command keeps the
/// writer from the bus and discards its output. Otherwise the command is the
/// writer as the decoy runs it.
pub fn prepare(switched_at: Duration, writer: &[OsString]) -> Option<Command> {
    let (program, args) = writer.split_first()?;
    let mut command = Command::new(program);
    command.args(args);
    let uname = rustix::system::uname();
    let entered = uname
        .release()
        .to_str()
        .is_ok_and(enters_at_exec)
        .then(|| enter_time_namespace(switched_at))
        .is_some_and(|entered| entered.is_ok());
    if entered {
        command
            .env(BUS_ENV, no_bus_address())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    }
    Some(command)
}

/// Whether the kernel `release` (`uname -r`) moves an executed program into
/// the time namespace its caller unshared.
fn enters_at_exec(release: &str) -> bool {
    let mut numbers = release
        .split(['.', '-', '+'])
        .map(|part| part.parse::<u32>().ok());
    match (numbers.next().flatten(), numbers.next().flatten()) {
        (Some(major), Some(minor)) => (major, minor) >= EXEC_ENTERS_TIME_NS,
        _ => false,
    }
}

/// How far the namespace's boot clock is set back from the real one, given
/// the real boot clock `now` and the boot clock at the switch: to the switch,
/// unless that is more than [`UPTIME_CAP`] ago.
fn clock_offset(now: Duration, switched_at: Duration) -> Duration {
    switched_at.min(now).max(now.saturating_sub(UPTIME_CAP))
}

/// The `/proc/<pid>/timens_offsets` line that sets the boot clock back by
/// `back`: `boottime <seconds> <nanoseconds>`, the seconds negative and the
/// nanoseconds a positive part below one second.
fn offsets_line(back: Duration) -> String {
    let (secs, nanos) = (back.as_secs(), back.subsec_nanos());
    if nanos == 0 {
        format!("boottime -{secs} 0\n")
    } else {
        format!("boottime -{} {}\n", secs + 1, 1_000_000_000 - nanos)
    }
}

/// Unshare a time namespace for what this thread starts from now on, its boot
/// clock set back to the switch ([`clock_offset`]).
pub fn enter_time_namespace(switched_at: Duration) -> io::Result<()> {
    let back = clock_offset(boot_records::boot_clock(), switched_at);
    unshare_time()?;
    // The kernel takes the offsets only before the first process enters. The
    // namespace is this thread's: `/proc/self` would name the main thread's,
    // so the file is reached by the thread's own ID.
    let tid = rustix::thread::gettid().as_raw_nonzero();
    std::fs::write(format!("/proc/{tid}/timens_offsets"), offsets_line(back))
}

#[allow(unsafe_code)]
fn unshare_time() -> io::Result<()> {
    use rustix::thread::{UnshareFlags, unshare_unsafe};
    // SAFETY: only a new time namespace is unshared. It sets the namespace the
    // processes this one starts enter, and shares nothing with another
    // thread; `unshare_unsafe` is unsafe only for `CLONE_FILES`, not passed.
    unsafe { unshare_unsafe(UnshareFlags::NEWTIME) }.map_err(io::Error::from)
}

#[cfg(test)]
#[path = "boot_writer_tests.rs"]
mod tests;
