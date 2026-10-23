// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Making the decoy's login and boot records read as one clean power cycle.
//!
//! A plain decoy that is shut down and later switched on leaves, in its login
//! and boot records, a shutdown entry and then a boot entry stamped with the
//! time it came back. A whole-root session reaches the decoy again through a
//! `systemctl soft-reboot`, and on two shipped families the decoy's own boot
//! writers record that soft-reboot in a way an ordinary power cycle never does:
//!
//! - where the decoy keeps its records in **wtmpdb** (a SQLite database, the
//!   standard on Debian 13), the boot writer names the boot row `soft-reboot`
//!   instead of `reboot`, or stamps a `reboot` row with the decoy's cold boot
//!   ([`boot_writer`] has the details);
//! - where the decoy keeps **classic wtmp** and its service manager both writes
//!   that file and predates the version that resets the start time across a
//!   soft-reboot (systemd 255 and earlier), the boot record of the way back
//!   carries the decoy's *first* boot time, not the time it actually came back.
//!   The file then holds a boot stamped before the shutdown that precedes it,
//!   which an ordinary boot never writes.
//!
//! Both are written by the decoy's own units *after* the switch, so they cannot
//! be changed before it. The way back therefore leaves in `/run` (RAM) what the
//! decoy's first start needs, and passes it the boot clock (`CLOCK_BOOTTIME`)
//! at the switch, which the kernel keeps across a soft-reboot and which dates
//! the way back as a power cycle would date the boot:
//!
//! - where wtmpdb records the boots, a drop-in that starts its writer so that
//!   it records a `reboot` at the time of the switch itself ([`boot_writer`]);
//! - a one-shot unit that runs once the writers have, before any login. Its
//!   step ([`run`]) corrects a backdated classic-wtmp boot record to the time
//!   of the switch, removes every piece the way back left in `/run` (its own
//!   unit and binary copy included) and restores `/run`'s `noexec` flag where
//!   the way back cleared it.
//!
//! Neither writer is masked, so each still records the shutdown time when the
//! decoy later stops: no row goes missing. Nothing here writes to the kernel
//! log: a name there would reach the decoy's ring buffer. Every step is best
//! effort, and a failure leaves the records as they would be without the fix.
//!
//! What stays visible until the next power-off, to anyone with a shell on the
//! running decoy, is in RAM: the one-shot's start and finish in the decoy's
//! journal, and both units still loaded from files that are gone, so
//! `systemctl status` notes that they changed on disk and shows the writer's
//! start command and drop-in.

use crate::noatime;
use crate::whole_root::boot_writer;
use crate::whole_root::nextroot;
use crate::whole_root::plan::{self, SERVICE_CONFIG_MODE};
use std::ffi::OsStr;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

/// The argument the one-shot unit passes to the RAM copy of the binary to run
/// the reconcile step. Neutral, like the other transition-side arguments.
pub const RECONCILE_ARG: &str = "reconcile-records";

/// The flag the unit adds when the way back left `/run` executable so the copy
/// there could run; the reconcile step makes `/run` `noexec` again before it
/// exits.
pub const NOEXEC_FLAG: &str = "--restore-noexec";

/// The directory below `/run` that holds the binary copy (neutral name). The
/// reconcile step removes it as a whole.
pub const FIXUP_DIR: &str = "overlay-runtime-boot";

/// [`FIXUP_DIR`] on the decoy, as the artifact registry names it.
pub const FIXUP_DIR_PATH: &str = "/run/overlay-runtime-boot";

/// The binary copy inside [`FIXUP_DIR`] (neutral name).
pub const FIXUP_BINARY: &str = "control";

/// The reconcile one-shot's unit name, in `/run/systemd/system` (neutral name).
pub const FIXUP_UNIT: &str = "overlay-runtime-boot.service";

/// The one-shot's unit on the decoy, as the artifact registry names it.
pub const FIXUP_UNIT_PATH: &str = "/run/systemd/system/overlay-runtime-boot.service";

/// The target that pulls the reconcile one-shot into the decoy's first start.
/// It is reached after the boot writers, which run in early boot.
pub const FIXUP_WANTED_BY: &str = "multi-user.target";

/// The link that pulls the one-shot in, as the artifact registry names it.
pub const FIXUP_LINK_PATH: &str =
    "/run/systemd/system/multi-user.target.wants/overlay-runtime-boot.service";

/// The unit that lets users log in. The one-shot runs before it, so no login
/// is recorded before the boot record is corrected, by a getty or a display
/// manager logging a user in automatically.
const FIXUP_BEFORE: &str = "systemd-user-sessions.service";

/// The decoy's classic wtmp, relative to a filesystem root.
const WTMP_PATH: &str = "var/log/wtmp";

/// The runtime unit directory below a `/run` root.
const RUNTIME_UNIT_DIR: &str = "systemd/system";

// --- classic wtmp on-disk layout (glibc struct utmpx, x86_64) ---------------

/// `struct utmpx` is 384 bytes on every Linux architecture (fixed by the glibc
/// ABI, not the word size).
const UTMP_RECORD_SIZE: usize = 384;

/// Offset of `ut_type` (a 16-bit int) in a record.
const UT_TYPE_OFFSET: usize = 0;

/// Offset of `ut_tv.tv_sec` (a 32-bit int, even on 64-bit) in a record.
const UT_TV_SEC_OFFSET: usize = 340;

/// Offset of `ut_tv.tv_usec` (a 32-bit int) in a record.
const UT_TV_USEC_OFFSET: usize = 344;

/// `ut_type` value for a boot record (`BOOT_TIME`).
const BOOT_TIME: i16 = 2;

fn read_i16_le(record: &[u8], offset: usize) -> i16 {
    i16::from_le_bytes([record[offset], record[offset + 1]])
}

fn read_i32_le(record: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes([
        record[offset],
        record[offset + 1],
        record[offset + 2],
        record[offset + 3],
    ])
}

/// The classic-wtmp boot record a soft-reboot into this decoy left stamped
/// before an event that precedes it, with the time it should carry instead.
///
/// `data` is the whole wtmp file and `switched` the time (seconds since the
/// epoch, as the 32-bit `tv_sec` holds it) of the switch back to the decoy.
/// The result is the byte offset of that record's `tv_sec` and the corrected
/// value, or `None` when the last boot record already carries a plausible time
/// (an ordinary boot, or a service manager that resets the start time across a
/// soft-reboot, so there is nothing to neutralise).
///
/// "Backdated" is judged against the file itself: the last boot record is
/// backdated when an earlier record carries a later time, which an ordinary
/// boot — always the newest event when it is written — never does. The
/// corrected time is `switched`, or one second past the latest earlier record
/// if the clock reads behind it, so the boot never predates what comes before
/// it.
fn backdated_boot_fix(data: &[u8], switched: i32) -> Option<(usize, i32)> {
    let count = data.len() / UTMP_RECORD_SIZE;
    let record = |i: usize| &data[i * UTMP_RECORD_SIZE..(i + 1) * UTMP_RECORD_SIZE];

    let last_boot = (0..count)
        .rev()
        .find(|&i| read_i16_le(record(i), UT_TYPE_OFFSET) == BOOT_TIME)?;

    let boot_time = read_i32_le(record(last_boot), UT_TV_SEC_OFFSET);
    let earlier_max = (0..last_boot)
        .map(|i| read_i32_le(record(i), UT_TV_SEC_OFFSET))
        .max()
        .unwrap_or(i32::MIN);

    (boot_time < earlier_max).then(|| {
        let corrected = switched.max(earlier_max.saturating_add(1));
        (last_boot * UTMP_RECORD_SIZE + UT_TV_SEC_OFFSET, corrected)
    })
}

/// The kernel's boot clock (`CLOCK_BOOTTIME`): the time since the kernel
/// started, which a soft-reboot does not reset.
pub fn boot_clock() -> Duration {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    Duration::new(
        u64::try_from(now.tv_sec).unwrap_or(0),
        u32::try_from(now.tv_nsec).unwrap_or(0),
    )
}

/// `clock` (a boot clock reading) as the command-line argument the units pass:
/// whole microseconds.
pub fn clock_arg(clock: Duration) -> String {
    clock.as_micros().to_string()
}

/// The boot clock reading in a [`clock_arg`] argument; `None` for anything
/// but a plain run of decimal digits that fits.
pub fn parse_clock_arg(arg: &OsStr) -> Option<Duration> {
    let text = arg.to_str()?;
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok().map(Duration::from_micros)
}

/// The wall-clock time at the boot clock reading `then`, as classic wtmp stores
/// it: whole seconds and the sub-second part in microseconds, each a 32-bit
/// field. A reading later than now is taken as now; on the unreachable error
/// path the seconds clamp to `i32::MAX`.
fn wall_clock_at(then: Duration) -> (i32, i32) {
    let since = boot_clock().saturating_sub(then);
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .saturating_sub(since);
    let sec = i32::try_from(at.as_secs()).unwrap_or(i32::MAX);
    (sec, at.subsec_micros() as i32)
}

/// Correct a backdated boot record in the classic wtmp at `path` to `sec` and
/// `usec`, the time of the switch, in place (the file keeps its inode, owner
/// and mode). Returns whether a record was changed. An absent or too-small
/// file, or one with nothing to fix, is no change.
///
/// The file is read without updating its access time: the boot writers have
/// just appended to it, so under the default `relatime` a plain read would
/// stamp it with the moment of the way back, which no ordinary boot does.
fn reconcile_wtmp(path: &Path, sec: i32, usec: i32) -> io::Result<bool> {
    use rustix::fs::{Mode, OFlags, open};
    let opened = noatime::with_noatime(|flags| {
        open(path, OFlags::RDWR | OFlags::CLOEXEC | flags, Mode::empty())
    });
    let mut file = match opened {
        Ok(fd) => std::fs::File::from(fd),
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let Some((offset, corrected)) = backdated_boot_fix(&data, sec) else {
        return Ok(false);
    };
    file.seek(SeekFrom::Start(offset as u64))?;
    file.write_all(&corrected.to_le_bytes())?;
    // tv_usec of the corrected record: an ordinary boot's start time carries a
    // live microsecond reading, so stamp the real sub-second part of the time
    // of the switch. A cleared field (a round `000000`) is what no genuine boot
    // record holds and would single this record out in `utmpdump`.
    file.seek(SeekFrom::Start(
        (offset + (UT_TV_USEC_OFFSET - UT_TV_SEC_OFFSET)) as u64,
    ))?;
    file.write_all(&usec.to_le_bytes())?;
    Ok(true)
}

/// What the decoy's first start needs after the way back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fix {
    /// The decoy's wtmpdb boot writer, started through [`boot_writer::run`].
    writer: Option<Vec<String>>,
    /// Whether the decoy keeps a classic wtmp whose boot record the reconcile
    /// step may correct.
    classic_wtmp: bool,
}

impl Fix {
    /// What the decoy root mounted at `root` needs: `None` when it keeps no
    /// records a soft-reboot gives away (or none this module can act on), so
    /// nothing is left for its start.
    pub fn for_decoy(root: &Path) -> Option<Self> {
        let fix = Self {
            writer: boot_writer::writer_command(root),
            classic_wtmp: matches!(
                std::fs::metadata(root.join(WTMP_PATH)),
                Ok(meta) if meta.len() >= UTMP_RECORD_SIZE as u64
            ),
        };
        (fix.writer.is_some() || fix.classic_wtmp).then_some(fix)
    }
}

/// Install, under `run`, the pieces the decoy's first start needs to read as a
/// clean power cycle: the wtmpdb writer's drop-in where `fix` names the writer,
/// the reconcile one-shot and the binary copy it runs. `binary` is the RAM copy
/// of the tool read before the scrub removed the runtime directory,
/// `switched_at` the boot clock at the switch, and `restore_noexec` whether the
/// way back must make `/run` `noexec` again, which the reconcile step then does
/// once the copy has run. The caller leaves `/run` executable until then.
///
/// The binary copy goes last, and a failure removes every piece already
/// written, so the decoy is left as it would be without the fix.
pub fn install(
    run: &Path,
    binary: &[u8],
    fix: &Fix,
    switched_at: Duration,
    restore_noexec: bool,
) -> io::Result<()> {
    let result = install_pieces(run, binary, fix, switched_at, restore_noexec);
    if result.is_err() {
        remove_pieces(run);
    }
    result
}

fn install_pieces(
    run: &Path,
    binary: &[u8],
    fix: &Fix,
    switched_at: Duration,
    restore_noexec: bool,
) -> io::Result<()> {
    let bin_path = run.join(FIXUP_DIR).join(FIXUP_BINARY);
    if let Some(writer) = &fix.writer {
        boot_writer::install_dropin(run, &bin_path, switched_at, writer)?;
    }

    // The reconcile one-shot and the symlink that pulls it into the first start.
    let unit_dir = run.join(RUNTIME_UNIT_DIR);
    std::fs::create_dir_all(&unit_dir)?;
    plan::write_atomic_with_mode(
        &unit_dir.join(FIXUP_UNIT),
        unit_text(&bin_path, switched_at, restore_noexec).as_bytes(),
        SERVICE_CONFIG_MODE,
    )?;
    let wants = unit_dir.join(format!("{FIXUP_WANTED_BY}.wants"));
    std::fs::create_dir_all(&wants)?;
    let link = wants.join(FIXUP_UNIT);
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(Path::new("..").join(FIXUP_UNIT), &link)?;

    // The binary copy, in its own directory so the step can remove it whole.
    std::fs::create_dir_all(run.join(FIXUP_DIR))?;
    write_executable(&bin_path, binary)
}

/// Write `bytes` to `path` as a private executable, through a temporary file in
/// the same directory renamed over the target, so the copy is never seen torn
/// or at another mode.
fn write_executable(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("/"));
    let temp = dir.join(format!(".{FIXUP_BINARY}.{}", std::process::id()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o700)
            .open(&temp)?;
        file.write_all(bytes)?;
        drop(file);
        std::fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// The arguments the one-shot unit passes to the binary copy: [`RECONCILE_ARG`],
/// the boot clock at the switch and, when the way back cleared it, the flag
/// that restores `noexec`.
pub fn reconcile_args(switched_at: Duration, restore_noexec: bool) -> Vec<String> {
    let mut args = vec![RECONCILE_ARG.to_string(), clock_arg(switched_at)];
    if restore_noexec {
        args.push(NOEXEC_FLAG.to_string());
    }
    args
}

/// The reconcile one-shot's unit text. It is ordered after the boot writers
/// (`After=` a unit that does not exist is ignored) and before logins, its
/// output goes nowhere, and its start command is prefixed `-` so a failure
/// never marks it failed, which the decoy would list.
fn unit_text(binary: &Path, switched_at: Duration, restore_noexec: bool) -> String {
    format!(
        "[Unit]\n\
         Description=Overlay runtime boot bookkeeping\n\
         After=systemd-update-utmp.service {} local-fs.target\n\
         Before={FIXUP_WANTED_BY} {FIXUP_BEFORE}\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         StandardInput=null\n\
         StandardOutput=null\n\
         StandardError=null\n\
         ExecStart=-{} {}\n\
         \n\
         [Install]\n\
         WantedBy={FIXUP_WANTED_BY}\n",
        boot_writer::WRITER_UNIT,
        binary.display(),
        reconcile_args(switched_at, restore_noexec).join(" ")
    )
}

/// Remove every piece [`install`] writes under `run`, with each directory left
/// empty that only they used: the decoy's own wants live under `/etc` and
/// `/usr`, not `/run`. The binary copy is removed last: a running copy keeps
/// executing after its file is unlinked.
fn remove_pieces(run: &Path) {
    boot_writer::remove_dropin(run);
    let unit_dir = run.join(RUNTIME_UNIT_DIR);
    let wants = unit_dir.join(format!("{FIXUP_WANTED_BY}.wants"));
    let _ = std::fs::remove_file(wants.join(FIXUP_UNIT));
    let _ = std::fs::remove_dir(&wants);
    let _ = std::fs::remove_file(unit_dir.join(FIXUP_UNIT));
    let _ = std::fs::remove_dir_all(run.join(FIXUP_DIR));
}

/// Run the reconcile step on the decoy's first start, then remove every piece
/// of the fix from `/run`. `run` is the `/run` root, `root` the filesystem root
/// the records sit under (`/` in use, a temporary tree in tests) and
/// `switched_at` the boot clock at the switch. `restore_noexec` makes `/run`
/// `noexec` again, last of all. Best effort: each part is attempted and a
/// failure of one does not stop the others.
pub fn run(run: &Path, root: &Path, switched_at: Duration, restore_noexec: bool) {
    // 1. Neutralise a backdated classic-wtmp boot record, stamping it with the
    //    time of the switch (seconds and real microseconds): the start of the
    //    boot it records, before anything that boot wrote.
    let (sec, usec) = wall_clock_at(switched_at);
    let _ = reconcile_wtmp(&root.join(WTMP_PATH), sec, usec);

    // 2. Remove the writer's drop-in (already gone once the writer has run),
    //    the one-shot, its link and the binary copy.
    remove_pieces(run);

    // 3. Restore /run's noexec flag last, once the copy has run.
    if restore_noexec {
        let _ = nextroot::set_noexec(run, true);
    }
}

#[cfg(test)]
#[path = "boot_records_tests.rs"]
mod tests;
