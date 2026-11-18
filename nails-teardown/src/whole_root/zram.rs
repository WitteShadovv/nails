// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The decoy's zram swap after the way back, as a cold boot sets it up.
//!
//! zram-generator's swap is a zram device set up at each start of the service
//! manager (`systemd-zram-setup@zramN.service`) and reset when that unit
//! stops. A soft-reboot keeps the kernel, and with it every zram device: when
//! the reset at the stop fails (the device is still busy), the device keeps
//! its size and what it holds, and the next start cannot set it up again
//! (the kernel refuses a new size for a device that has one), so that root
//! runs without its zram swap and with the unit failed. The decoy's own stop
//! at the entry can leave its device so, as a plain soft-reboot can.
//!
//! So the way back, once every hidden unit has stopped, resets each zram
//! device that holds a swap area no swap uses ([`reset_idle_swaps`]): the
//! decoy's start can set it up as its cold boot did. It does not tell such a
//! device from one the decoy set up itself and left with its swap off, which
//! it resets as well. A device in use, one that
//! was never set up and one that holds anything but a swap area are left
//! alone: a swap area out of use keeps nothing a later start reads, but
//! another device can hold a filesystem the decoy expects to find again. The
//! kernel refuses to reset a device that is open.
//!
//! Resetting a device logs its change of size to the kernel log, so the way
//! back does it before it takes the kernel log's cursor.

use std::io::Read;
use std::path::{Path, PathBuf};

/// The signature of a swap area (version 2), which `mkswap` writes in the
/// last ten bytes of the area's first page.
const SWAP_SIGNATURE: &[u8] = b"SWAPSPACE2";

/// Where [`reset_idle_swaps`] looks.
#[derive(Debug, Clone)]
pub struct Places {
    /// The block devices' sysfs directory (`/sys/block`).
    pub sys_block: PathBuf,
    /// The device nodes' directory (`/dev`).
    pub dev: PathBuf,
    /// The kernel's list of swaps in use (`/proc/swaps`).
    pub swaps: PathBuf,
    /// The page size the swap areas were written with.
    pub page_size: usize,
}

impl Places {
    /// The real system.
    pub fn system() -> Self {
        Self::under(Path::new("/"))
    }

    /// The places below `root` (`/` on the real system), with this machine's
    /// page size.
    pub fn under(root: &Path) -> Self {
        Self {
            sys_block: root.join("sys/block"),
            dev: root.join("dev"),
            swaps: root.join("proc/swaps"),
            page_size: rustix::param::page_size(),
        }
    }
}

/// What became of one zram device ([`reset_idle_swaps`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reset {
    /// It held a swap area no swap used, and was reset.
    Done,
    /// It held a swap area no swap used, but the kernel refused the reset.
    Refused,
    /// A swap uses it.
    InUse,
    /// It was never set up, or its state cannot be read.
    NotSetUp,
    /// It holds no swap area, or its first page cannot be read.
    NoSwapArea,
}

/// Reset each zram device that holds a swap area no swap uses (see the module
/// docs), and say what became of each zram device, by name, in name order.
pub fn reset_idle_swaps(places: &Places) -> Vec<(String, Reset)> {
    let in_use = std::fs::read_to_string(&places.swaps).unwrap_or_default();
    let mut devices: Vec<String> = std::fs::read_dir(&places.sys_block)
        .map(|dir| {
            dir.flatten()
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|name| is_zram(name))
                .collect()
        })
        .unwrap_or_default();
    devices.sort();
    devices
        .into_iter()
        .map(|name| {
            let reset = reset_one(places, &name, &in_use);
            (name, reset)
        })
        .collect()
}

/// Whether `name` is a zram device's: `zram` and a number.
fn is_zram(name: &str) -> bool {
    name.strip_prefix("zram")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// [`reset_idle_swaps`] for the device `name`, with `in_use` the text of the
/// swaps list.
fn reset_one(places: &Places, name: &str, in_use: &str) -> Reset {
    let sys = places.sys_block.join(name);
    let set_up = std::fs::read_to_string(sys.join("initstate")).is_ok_and(|s| s.trim() == "1");
    if !set_up {
        return Reset::NotSetUp;
    }
    let node = places.dev.join(name);
    if swaps_use(in_use, &node, name) {
        return Reset::InUse;
    }
    if !holds_swap_area(&node, places.page_size) {
        return Reset::NoSwapArea;
    }
    match std::fs::write(sys.join("reset"), "1") {
        Ok(()) => Reset::Done,
        Err(_) => Reset::Refused,
    }
}

/// Whether the swaps list `in_use` (`/proc/swaps`) names the device `name`,
/// whose node is `node`.
fn swaps_use(in_use: &str, node: &Path, name: &str) -> bool {
    let real = Path::new("/dev").join(name);
    in_use
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
        .any(|path| Path::new(path) == node || Path::new(path) == real)
}

/// Whether the device at `node` holds a swap area: [`SWAP_SIGNATURE`] ends
/// its first page of `page_size` bytes.
fn holds_swap_area(node: &Path, page_size: usize) -> bool {
    let Some(start) = page_size.checked_sub(SWAP_SIGNATURE.len()) else {
        return false;
    };
    let mut page = vec![0u8; page_size];
    std::fs::File::open(node)
        .and_then(|mut device| device.read_exact(&mut page))
        .is_ok_and(|()| page[start..] == *SWAP_SIGNATURE)
}

#[cfg(test)]
#[path = "zram_tests.rs"]
mod tests;
