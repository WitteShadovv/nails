// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The running kernel's side of the write fence ([`KERNEL`]): the
//! [`FenceKernel`] the entry's check and its transition use.

use crate::mountinfo::{MountEntry, read_mountinfo, unescape_octal};
use crate::whole_root::disk_guard::{self, DevNum, Sysfs, block_device};
use crate::whole_root::fence::{
    Device, EFI_CRASH_LOG, FenceKernel, Program, Rules, Superblock, Swap,
};
use crate::whole_root::{fence_bpf, nextroot};
use rustix::mount::{FsPickFlags, MountFlags, UnmountFlags};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The running kernel.
pub static KERNEL: RealKernel = RealKernel;

/// The pstore backend registered now, `(null)` for none.
const PSTORE_BACKEND: &str = "/sys/module/pstore/parameters/backend";
/// pstore's EFI backend's switch: writing `Y` unregisters it from Linux 6.12
/// on; before, it only keeps a later load from registering.
const EFI_PSTORE_DISABLE: &str = "/sys/module/efi_pstore/parameters/pstore_disable";
/// Present only for a module that can be unloaded (not built in).
const EFI_PSTORE_INITSTATE: &str = "/sys/module/efi_pstore/initstate";
/// The drop-in that keeps a later `modprobe efi_pstore` disabled.
const MODPROBE_DROPIN: &str = "/run/modprobe.d/50-overlay-runtime.conf";

#[allow(unsafe_code)]
fn delete_module(name: &std::ffi::CStr) -> io::Result<()> {
    // SAFETY: `name` is a NUL-terminated string that outlives the call, and
    // the flags are a plain integer.
    let ret = unsafe { libc::syscall(libc::SYS_delete_module, name.as_ptr(), libc::O_NONBLOCK) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// The running kernel, through `/proc`, `/sys` and the system calls.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealKernel;

fn to_io(e: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(e.raw_os_error())
}

/// Reconfigure the superblock of the mount at `path` read-only without
/// touching any mount's own flags (`fspick`, the new mount API), as a legacy
/// remount would.
fn reconfigure_at(path: &Path) -> io::Result<()> {
    let fs = rustix::mount::fspick(
        rustix::fs::CWD,
        path,
        FsPickFlags::FSPICK_CLOEXEC
            | FsPickFlags::FSPICK_NO_AUTOMOUNT
            | FsPickFlags::FSPICK_SYMLINK_NOFOLLOW,
    )
    .map_err(to_io)?;
    rustix::mount::fsconfig_set_flag(&fs, "ro").map_err(to_io)?;
    rustix::mount::fsconfig_reconfigure(&fs).map_err(to_io)
}

/// A mount of `sb` that a lookup of its mount point reaches.
fn visible_mount<'a>(mounts: &'a [MountEntry], sb: &Superblock) -> Option<&'a MountEntry> {
    mounts
        .iter()
        .find(|m| m.dev == sb.sb_dev && nextroot::reaches(&m.mount_point, m.mount_id))
}

/// The node a superblock's device is reached through now: its recorded node
/// while that is still the device, else `/dev/block/major:minor`.
fn node_now(device: &Device) -> PathBuf {
    if block_device(&device.node) == Some(device.dev) {
        return device.node.clone();
    }
    PathBuf::from(format!("/dev/block/{}", device.dev.text()))
}

impl FenceKernel for RealKernel {
    fn sync(&self) {
        rustix::fs::sync();
    }

    fn swaps(&self) -> Vec<Swap> {
        let text = std::fs::read_to_string("/proc/swaps").unwrap_or_default();
        text.lines()
            .skip(1)
            .filter_map(|line| line.split_whitespace().next())
            .filter_map(|name| {
                let path = PathBuf::from(unescape_octal(name));
                let meta = std::fs::metadata(&path).ok()?;
                Some(match block_device(&path) {
                    Some(dev) => Swap::Device(dev),
                    None => Swap::File(DevNum::from_raw(meta.dev()).text()),
                })
            })
            .collect()
    }

    fn reconfigure(&self, sb: &Superblock, scratch: &Path) -> io::Result<()> {
        let mounts = read_mountinfo()?;
        if let Some(mount) = visible_mount(&mounts, sb) {
            return reconfigure_at(&mount.mount_point).map_err(|e| {
                if e.raw_os_error() == Some(libc::EBUSY) {
                    let ids: Vec<i32> = mounts
                        .iter()
                        .filter(|m| m.dev == sb.sb_dev)
                        .map(|m| m.mount_id)
                        .collect();
                    let held = holders(Path::new("/proc"), &ids);
                    if !held.is_empty() {
                        return io::Error::new(
                            e.kind(),
                            format!("{e} (held: {})", held.join("; ")),
                        );
                    }
                }
                e
            });
        }
        // No mount shows it: mount it for a moment as it is now, which shares
        // the superblock and changes nothing, and reconfigure through that.
        let Some(device) = &sb.device else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no mount shows {}", sb.sb_dev),
            ));
        };
        let dir = scratch.join(sb.sb_dev.replace(':', "-"));
        std::fs::create_dir_all(&dir)?;
        let flags = MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC;
        let mounted = rustix::mount::mount(
            node_now(device),
            &dir,
            sb.fstype.as_str(),
            flags,
            None::<&std::ffi::CStr>,
        )
        .map_err(to_io)
        .and_then(|()| {
            let done = reconfigure_at(&dir);
            let _ = rustix::mount::unmount(&dir, UnmountFlags::DETACH);
            done
        });
        let _ = std::fs::remove_dir(&dir);
        mounted
    }

    fn superblock_read_only(&self, sb: &Superblock) -> Option<bool> {
        let mounts = read_mountinfo().ok()?;
        let mount = mounts.iter().find(|m| m.dev == sb.sb_dev)?;
        Some(mount.super_opts.split(',').next() == Some("ro"))
    }

    fn device_read_only(&self, device: &Device) -> bool {
        Sysfs::system().is_read_only(device.dev)
    }

    fn set_read_only(&self, device: &Device) -> io::Result<()> {
        disk_guard::set_read_only(&node_now(device), true)
    }

    fn discard_max(&self, queue: &Path) -> io::Result<u64> {
        std::fs::read_to_string(queue)?
            .trim()
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))
    }

    fn discard_off(&self, queue: &Path) -> io::Result<()> {
        std::fs::write(queue, "0\n")
    }

    fn attach(&self, rules: &Rules) -> io::Result<Program> {
        fence_bpf::attach(rules, &cgroup_root()?)
    }

    fn crash_log_backend(&self) -> Option<String> {
        let text = std::fs::read_to_string(PSTORE_BACKEND).ok()?;
        let name = text.trim();
        (!name.is_empty() && name != "(null)").then(|| name.to_string())
    }

    fn efi_crash_log_stoppable(&self) -> bool {
        Path::new(EFI_PSTORE_INITSTATE).exists()
            || unregisters_at_runtime(&rustix::system::uname().release().to_string_lossy())
    }

    fn stop_efi_crash_log(&self) -> io::Result<()> {
        let dropin = Path::new(MODPROBE_DROPIN);
        if let Some(dir) = dropin.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(dropin, "options efi_pstore pstore_disable=Y\n")?;
        let _ = std::fs::write(EFI_PSTORE_DISABLE, "Y");
        if self.crash_log_backend().as_deref() == Some(EFI_CRASH_LOG)
            && Path::new(EFI_PSTORE_INITSTATE).exists()
        {
            delete_module(c"efi_pstore")?;
        }
        Ok(())
    }

    fn probe(&self, rules: &Rules) -> io::Result<()> {
        cgroup_root()?;
        fence_bpf::load(rules).map(drop)
    }
}

/// Whether a kernel of `release` unregisters pstore's EFI backend when its
/// `pstore_disable` is set (6.12 and newer; before, the parameter is read
/// only when the module loads).
pub fn unregisters_at_runtime(release: &str) -> bool {
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    (major, minor) >= (6, 12)
}

/// What keeps a filesystem from going read-only, under the procfs at
/// `proc`: each process with a file open for writing on one of the mounts
/// `mount_ids`, and each with a deleted file open or mapped (a deleted
/// inode in use blocks the remount whichever mount it is on), as
/// `pid comm: path`, at most eight.
pub fn holders(proc: &Path, mount_ids: &[i32]) -> Vec<String> {
    let mut found = Vec::new();
    let Ok(dir) = std::fs::read_dir(proc) else {
        return found;
    };
    for entry in dir.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let base = proc.join(pid.to_string());
        let comm = std::fs::read_to_string(base.join("comm")).unwrap_or_default();
        let comm = comm.trim();
        for fd in std::fs::read_dir(base.join("fd"))
            .into_iter()
            .flatten()
            .flatten()
        {
            let target = std::fs::read_link(fd.path()).unwrap_or_default();
            let target = target.to_string_lossy();
            let info = std::fs::read_to_string(base.join("fdinfo").join(fd.file_name()))
                .unwrap_or_default();
            let field = |key: &str| {
                info.lines()
                    .find_map(|l| l.strip_prefix(key))
                    .map(|v| v.trim().to_string())
            };
            let on_it = field("mnt_id:")
                .and_then(|v| v.parse::<i32>().ok())
                .is_some_and(|id| mount_ids.contains(&id));
            let writing = field("flags:")
                .and_then(|v| u32::from_str_radix(&v, 8).ok())
                .is_some_and(|flags| flags & 3 != 0);
            if on_it && (writing || target.ends_with(" (deleted)")) {
                found.push(format!("{pid} {comm}: {target}"));
            }
        }
        let maps = std::fs::read_to_string(base.join("maps")).unwrap_or_default();
        let mut seen = std::collections::BTreeSet::new();
        for line in maps.lines().filter(|l| l.ends_with(" (deleted)")) {
            if let Some(path) = line.split_whitespace().nth(5)
                && path.starts_with('/')
                && !path.starts_with("/memfd:")
                && !path.starts_with("/dev/")
                && seen.insert(path.to_string())
            {
                found.push(format!("{pid} {comm}: {path} (deleted, mapped)"));
            }
        }
        if found.len() >= 8 {
            found.truncate(8);
            break;
        }
    }
    found
}

/// Where the root of the cgroup2 hierarchy is mounted: `/sys/fs/cgroup` on a
/// unified host, `/sys/fs/cgroup/unified` on a hybrid one. A host without
/// cgroup2 cannot have the fence.
pub fn cgroup_root() -> io::Result<PathBuf> {
    let mounts = read_mountinfo()?;
    mounts
        .iter()
        .filter(|m| m.fstype == "cgroup2" && m.root == Path::new("/"))
        .map(|m| m.mount_point.clone())
        .min_by_key(|p| p != Path::new("/sys/fs/cgroup"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no cgroup2 hierarchy is mounted"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holders_name_writers_and_deleted_files_on_the_filesystem() {
        let proc = tempfile::tempdir().unwrap();
        let pid = proc.path().join("42");
        std::fs::create_dir_all(pid.join("fd")).unwrap();
        std::fs::create_dir_all(pid.join("fdinfo")).unwrap();
        std::fs::write(pid.join("comm"), "journald\n").unwrap();
        let fd = |n: &str, target: &str, mnt: i32, flags: &str| {
            std::os::unix::fs::symlink(target, pid.join("fd").join(n)).unwrap();
            std::fs::write(
                pid.join("fdinfo").join(n),
                format!("pos:\t0\nflags:\t{flags}\nmnt_id:\t{mnt}\n"),
            )
            .unwrap();
        };
        fd("3", "/var/log/x", 7, "0100002"); // read-write on the filesystem
        fd("4", "/etc/os-release", 7, "0100000"); // read-only on it
        fd("5", "/home/y", 9, "0100001"); // written, another filesystem
        fd("6", "/var/old (deleted)", 7, "0100000"); // deleted, read-only
        std::fs::write(
            pid.join("maps"),
            "7f00-7f01 r-xp 00000000 00:21 12 /usr/lib/libc.so.6 (deleted)\n\
             7f02-7f03 r-xp 00000000 00:21 13 /usr/lib/libc.so.6 (deleted)\n\
             7f04-7f05 rw-s 00000000 00:01 14 /memfd:x (deleted)\n",
        )
        .unwrap();
        let mut held = holders(proc.path(), &[7]);
        held.sort();
        assert_eq!(
            held,
            vec![
                "42 journald: /usr/lib/libc.so.6 (deleted, mapped)",
                "42 journald: /var/log/x",
                "42 journald: /var/old (deleted)",
            ]
        );
    }
}

#[cfg(test)]
mod release_tests {
    use super::unregisters_at_runtime;

    #[test]
    fn pstore_disable_unregisters_from_6_12_on() {
        for (release, unregisters) in [
            ("6.8.0-151-generic", false),
            ("6.11.9", false),
            ("6.12.118+deb13-amd64", true),
            ("6.18.55", true),
            ("7.0.0-44-generic", true),
            ("junk", false),
        ] {
            assert_eq!(unregisters_at_runtime(release), unregisters, "{release}");
        }
    }
}
