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
//!   standard on recent Debian), the boot writer asks the service manager
//!   whether this start followed a soft-reboot and, when it did, names the boot
//!   row `soft-reboot` instead of `reboot`. Ordinary use never writes that word.
//! - where the decoy keeps **classic wtmp** and its service manager both writes
//!   that file and predates the version that resets the start time across a
//!   soft-reboot (systemd 255 and earlier), the boot record of the way back
//!   carries the decoy's *first* boot time, not the time it actually came back.
//!   The file then holds a boot stamped before the shutdown that precedes it,
//!   which an ordinary boot never writes.
//!
//! Both are written by the decoy's own units *after* the switch, so they cannot
//! be changed before it. The way back therefore leaves two small pieces behind
//! for the decoy's first start, and a one-shot unit that runs once the writers
//! have, reconciles the records and removes every piece of itself:
//!
//! - a drop-in for the wtmpdb boot writer that keeps it from reaching the
//!   service manager, so it falls back to `reboot` and never records
//!   `soft-reboot`. The writer is not masked, so it still records the shutdown
//!   time when the decoy later stops: no row goes missing.
//! - the reconcile step ([`run`]) corrects a backdated classic-wtmp boot record
//!   to the time the decoy came back, removes the drop-in, removes its own unit
//!   and binary copy, and restores `/run`'s `noexec` flag where the way back
//!   cleared it. Everything it touches lives in `/run` (RAM): nothing of it
//!   survives a real power-off.
//!
//! It never writes to the kernel log: a name there would reach the decoy's ring
//! buffer. The reconcile step is best effort throughout; a failure leaves the
//! decoy no worse than before the fix existed.

use crate::whole_root::nextroot;
use crate::whole_root::plan::{self, SERVICE_CONFIG_MODE};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// The argument the one-shot unit passes to the RAM copy of the binary to run
/// the reconcile step. Neutral, like the other transition-side arguments.
pub const RECONCILE_ARG: &str = "reconcile-records";

/// The flag the unit adds when the way back left `/run` executable so the copy
/// there could run; the reconcile step makes `/run` `noexec` again before it
/// exits.
pub const NOEXEC_FLAG: &str = "--restore-noexec";

/// The directory below `/run` that holds the reconcile step's binary copy
/// (neutral name). The step removes it as a whole.
pub const FIXUP_DIR: &str = "overlay-runtime-boot";

/// The reconcile step's binary copy inside [`FIXUP_DIR`] (neutral name).
pub const FIXUP_BINARY: &str = "control";

/// The reconcile one-shot's unit name, in `/run/systemd/system` (neutral name).
pub const FIXUP_UNIT: &str = "overlay-runtime-boot.service";

/// The target that pulls the reconcile one-shot into the decoy's first start.
/// It is reached after the boot writers, which run in early boot.
pub const FIXUP_WANTED_BY: &str = "multi-user.target";

/// The decoy's classic wtmp, relative to a filesystem root.
const WTMP_PATH: &str = "var/log/wtmp";

/// The decoy's wtmpdb database, relative to a filesystem root; its presence
/// means wtmpdb is the writer.
const WTMPDB_PATH: &str = "var/log/wtmp.db";

/// The wtmpdb boot writer's unit, whose drop-in keeps it from naming a boot
/// row `soft-reboot`.
const WTMPDB_UNIT: &str = "wtmpdb-update-boot.service";

/// The drop-in directory for [`WTMPDB_UNIT`], below a `/run` root.
const WTMPDB_DROPIN_DIR: &str = "systemd/system/wtmpdb-update-boot.service.d";

/// The drop-in's file name (neutral), sorted late so it wins over the decoy's
/// own drop-ins.
const WTMPDB_DROPIN_NAME: &str = "zz-overlay-runtime.conf";

/// The drop-in text. It points the boot writer's system-bus connection at a
/// path with no socket, so the writer cannot ask the service manager whether a
/// soft-reboot happened and falls back to recording an ordinary `reboot`. It
/// applies to the writer's start and stop alike; the stop (`wtmpdb shutdown`,
/// which records the shutdown time) needs no bus, so it still runs.
const WTMPDB_DROPIN_TEXT: &str =
    "[Service]\nEnvironment=DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/overlay-runtime-boot/no-bus\n";

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
/// `data` is the whole wtmp file and `now` the time (seconds since the epoch,
/// as the 32-bit `tv_sec` holds it) the decoy came back. The result is the
/// byte offset of that record's `tv_sec` and the corrected value, or `None`
/// when the last boot record already carries a plausible time (an ordinary
/// boot, or a service manager that resets the start time across a soft-reboot,
/// so there is nothing to neutralise).
///
/// "Backdated" is judged against the file itself: the last boot record is
/// backdated when an earlier record carries a later time, which an ordinary
/// boot — always the newest event when it is written — never does. The
/// corrected time is `now`, or one second past the latest earlier record if
/// the clock reads behind it, so the boot never predates what comes before it.
fn backdated_boot_fix(data: &[u8], now: i32) -> Option<(usize, i32)> {
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
        let corrected = now.max(earlier_max.saturating_add(1));
        (last_boot * UTMP_RECORD_SIZE + UT_TV_SEC_OFFSET, corrected)
    })
}

/// The current time as classic wtmp stores it: whole seconds and the sub-second
/// part in microseconds, each a 32-bit field. Sampled once so the pair is
/// coherent. On the unreachable error path the seconds clamp to `i32::MAX`.
fn now_timeval() -> (i32, i32) {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let sec = i32::try_from(since.as_secs()).unwrap_or(i32::MAX);
    (sec, since.subsec_micros() as i32)
}

/// Correct a backdated boot record in the classic wtmp at `path` to the time
/// `now_sec`/`now_usec` the decoy came back, in place (the file keeps its inode,
/// owner and mode). Returns whether a record was changed. An absent or too-small
/// file, or one with nothing to fix, is no change.
fn reconcile_wtmp(path: &Path, now_sec: i32, now_usec: i32) -> io::Result<bool> {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let Some((offset, corrected)) = backdated_boot_fix(&data, now_sec) else {
        return Ok(false);
    };
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.seek(SeekFrom::Start(offset as u64))?;
    file.write_all(&corrected.to_le_bytes())?;
    // tv_usec of the corrected record: an ordinary boot's start time carries a
    // live microsecond reading, so stamp the real sub-second part of the time
    // the decoy came back. A cleared field (a round `000000`) is what no genuine
    // boot record holds and would single this record out in `utmpdump`.
    file.seek(SeekFrom::Start(
        (offset + (UT_TV_USEC_OFFSET - UT_TV_SEC_OFFSET)) as u64,
    ))?;
    file.write_all(&now_usec.to_le_bytes())?;
    Ok(true)
}

/// Whether the decoy root mounted at `nextroot` keeps login and boot records
/// the reconcile step must act on: a wtmpdb database (its boot writer names
/// soft-reboots) or a non-empty classic wtmp (its boot record can be
/// backdated). A decoy with neither needs no reconcile step, so none is left.
pub fn decoy_keeps_records(nextroot: &Path) -> bool {
    if nextroot.join(WTMPDB_PATH).is_file() {
        return true;
    }
    matches!(
        std::fs::metadata(nextroot.join(WTMP_PATH)),
        Ok(meta) if meta.len() >= UTMP_RECORD_SIZE as u64
    )
}

/// Install, under `run`, the pieces the decoy's first start needs to read as a
/// clean power cycle: the wtmpdb boot-writer drop-in, the binary copy and the
/// reconcile one-shot. `binary` is the RAM copy of the tool read before the
/// scrub removed the runtime directory. `restore_noexec` records whether the
/// way back must make `/run` `noexec` again, which the reconcile step then
/// does once it has run the copy. The caller leaves `/run` executable until
/// then. Best effort: a failure leaves the decoy as it would be without the fix.
pub fn install(run: &Path, binary: &[u8], restore_noexec: bool) -> io::Result<()> {
    // The binary copy, in its own directory so the step can remove it whole.
    let bin_dir = run.join(FIXUP_DIR);
    std::fs::create_dir_all(&bin_dir)?;
    let bin_path = bin_dir.join(FIXUP_BINARY);
    write_executable(&bin_path, binary)?;

    // The wtmpdb boot-writer drop-in (harmless where the writer is absent).
    let dropin_dir = run.join(WTMPDB_DROPIN_DIR);
    std::fs::create_dir_all(&dropin_dir)?;
    plan::write_atomic_with_mode(
        &dropin_dir.join(WTMPDB_DROPIN_NAME),
        WTMPDB_DROPIN_TEXT.as_bytes(),
        SERVICE_CONFIG_MODE,
    )?;

    // The reconcile one-shot and the symlink that pulls it into the first start.
    let unit_dir = run.join(RUNTIME_UNIT_DIR);
    std::fs::create_dir_all(&unit_dir)?;
    plan::write_atomic_with_mode(
        &unit_dir.join(FIXUP_UNIT),
        unit_text(&bin_path, restore_noexec).as_bytes(),
        SERVICE_CONFIG_MODE,
    )?;
    let wants = unit_dir.join(format!("{FIXUP_WANTED_BY}.wants"));
    std::fs::create_dir_all(&wants)?;
    let link = wants.join(FIXUP_UNIT);
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(Path::new("..").join(FIXUP_UNIT), &link)?;
    Ok(())
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

/// The reconcile one-shot's unit text. It is ordered after the boot writers
/// (`After=` a unit that does not exist is ignored), its output goes nowhere,
/// and its start command is prefixed `-` so a failure never marks it failed,
/// which the decoy would list.
fn unit_text(binary: &Path, restore_noexec: bool) -> String {
    let noexec = if restore_noexec {
        format!(" {NOEXEC_FLAG}")
    } else {
        String::new()
    };
    format!(
        "[Unit]\n\
         Description=Overlay runtime boot bookkeeping\n\
         After=systemd-update-utmp.service {WTMPDB_UNIT} local-fs.target\n\
         Before={FIXUP_WANTED_BY}\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         StandardInput=null\n\
         StandardOutput=null\n\
         StandardError=null\n\
         ExecStart=-{} {RECONCILE_ARG}{noexec}\n\
         \n\
         [Install]\n\
         WantedBy={FIXUP_WANTED_BY}\n",
        binary.display()
    )
}

/// Run the reconcile step on the decoy's first start, then remove every piece
/// of the fix from `/run`. `run` is the `/run` root and `root` the filesystem
/// root the records sit under (`/` in use, a temporary tree in tests).
/// `restore_noexec` makes `/run` `noexec` again, last of all. Best effort: each
/// part is attempted and a failure of one does not stop the others.
pub fn run(run: &Path, root: &Path, restore_noexec: bool) {
    // 1. Neutralise a backdated classic-wtmp boot record, stamping it with a
    //    live time (seconds and real microseconds), as a fresh boot carries.
    let (now_sec, now_usec) = now_timeval();
    let _ = reconcile_wtmp(&root.join(WTMP_PATH), now_sec, now_usec);

    // 2. Remove the wtmpdb boot-writer drop-in and its directory if left empty.
    let dropin_dir = run.join(WTMPDB_DROPIN_DIR);
    let _ = std::fs::remove_file(dropin_dir.join(WTMPDB_DROPIN_NAME));
    let _ = std::fs::remove_dir(&dropin_dir);

    // 3. Remove the one-shot and its wants symlink (and that directory if it is
    //    left empty: the decoy's own wants live under /etc and /usr, not /run).
    let unit_dir = run.join(RUNTIME_UNIT_DIR);
    let wants = unit_dir.join(format!("{FIXUP_WANTED_BY}.wants"));
    let _ = std::fs::remove_file(wants.join(FIXUP_UNIT));
    let _ = std::fs::remove_dir(&wants);
    let _ = std::fs::remove_file(unit_dir.join(FIXUP_UNIT));

    // 4. Remove the binary copy and its directory. The running copy keeps
    //    executing after its file is unlinked, so this is safe to do here.
    let _ = std::fs::remove_dir_all(run.join(FIXUP_DIR));

    // 5. Restore /run's noexec flag last, once the copy has run.
    if restore_noexec {
        let _ = nextroot::set_noexec(run, true);
    }
}

#[cfg(test)]
#[path = "boot_records_tests.rs"]
mod tests;
