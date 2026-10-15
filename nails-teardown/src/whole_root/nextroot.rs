// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Mount primitives for `/run/nextroot` and the init check before a switch.
//!
//! Everything below `/run/nextroot` is *extrinsic* to systemd: the orderly
//! shutdown of a soft-reboot never unmounts it, and PID 1 switches root into
//! it. These are the few mount operations the transitions need, in both
//! directions:
//!
//! - the root overlay: a non-recursive, read-only bind of the decoy root as the
//!   lower, the upper and work directories on the hidden volume;
//! - plain and read-only binds (`/run`, the hidden volume, the ESP);
//! - an overlay over one other decoy filesystem (a separate `/home`);
//! - the decoy root device mounted again, for the way back;
//! - detaching a whole tree (rollback, a stray `/run/nextroot`).
//!
//! Every mount below the next root is private from the moment it exists. The
//! decoy's `/` is shared (systemd makes it so at boot), so a bind of a decoy
//! filesystem joins that filesystem's peer group, and a mount below such a
//! bind would appear below the decoy's own mount too (a carried `/boot` below
//! the hidden volume's bind would show at `/mnt/data/root/decoy/boot` in the
//! decoy, and keep the decoy from unmounting the hidden volume at the switch).
//! Making the finished tree private ([`make_rprivate`]) comes too late for
//! that, and stays as a backstop. The next root's own mount (the root overlay
//! at entry, the decoy root on the way back) stays shared until then: logind
//! decides whether a plain `reboot` becomes a soft-reboot by looking for an
//! OS tree at `/run/nextroot` from a mount namespace of its own, which
//! receives the mounts below a shared root only: below a private one it would
//! miss the `os-release` of a NixOS next root, which lives in a store mounted
//! there.
//!
//! [`precheck`] does what PID 1 (systemd >= 258) does before it switches: the
//! init must resolve *inside* the new root, and the root must be an OS tree. A
//! root that fails either freezes the machine with no way back except a power
//! cycle, so every switch is checked first.

use crate::mountinfo::{MountEntry, escape_overlay_path, read_mountinfo};
use crate::noatime::with_noatime;
use rustix::fs::{Mode, OFlags, ResolveFlags, StatVfsMountFlags};
use rustix::mount::{MountFlags, MountPropagationFlags, UnmountFlags};
use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

/// Where PID 1 looks for the next root on a soft-reboot.
pub const NEXTROOT: &str = "/run/nextroot";

fn to_io(e: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(e.raw_os_error())
}

fn c_string(text: &str) -> io::Result<CString> {
    CString::new(text).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in mount data"))
}

/// Bind `source` onto `target`, recursively or not, and make the new mount
/// (and with `recursive` everything below it) private. A bind is never the
/// next root's own mount.
pub fn bind(source: &Path, target: &Path, recursive: bool) -> io::Result<()> {
    if recursive {
        rustix::mount::mount_bind_recursive(source, target).map_err(to_io)?;
    } else {
        rustix::mount::mount_bind(source, target).map_err(to_io)?;
    }
    private_or_detach(target, recursive)
}

/// Make the mount at `target`, just made below the next root, private: nothing
/// mounted below it later propagates anywhere (see the module docs).
pub fn make_private(target: &Path) -> io::Result<()> {
    rustix::mount::mount_change(target, MountPropagationFlags::PRIVATE).map_err(to_io)
}

/// Make the mount just made at `target` private, or detach it again: nothing
/// mounted below it later may propagate to the peers of what it was made
/// from (see the module docs).
fn private_or_detach(target: &Path, recursive: bool) -> io::Result<()> {
    let mut flags = MountPropagationFlags::PRIVATE;
    if recursive {
        flags |= MountPropagationFlags::REC;
    }
    if let Err(e) = rustix::mount::mount_change(target, flags) {
        let _ = rustix::mount::unmount(target, UnmountFlags::DETACH);
        return Err(to_io(e));
    }
    Ok(())
}

/// Make the bind mount at `target` read-only, keeping the per-mount flags it
/// already has (a user namespace refuses to clear locked `nosuid`/`nodev`).
pub fn remount_read_only(target: &Path) -> io::Result<()> {
    remount_bind(target, true)
}

/// Make the bind mount at `target` writable again, keeping its other per-mount
/// flags.
pub fn remount_writable(target: &Path) -> io::Result<()> {
    remount_bind(target, false)
}

fn remount_bind(target: &Path, read_only: bool) -> io::Result<()> {
    let current = rustix::fs::statvfs(target).map_err(to_io)?.f_flag;
    let mut flags = MountFlags::BIND;
    if read_only {
        flags |= MountFlags::RDONLY;
    }
    for (have, keep) in [
        (StatVfsMountFlags::NOSUID, MountFlags::NOSUID),
        (StatVfsMountFlags::NODEV, MountFlags::NODEV),
        (StatVfsMountFlags::NOEXEC, MountFlags::NOEXEC),
        (StatVfsMountFlags::NOATIME, MountFlags::NOATIME),
        (StatVfsMountFlags::NODIRATIME, MountFlags::NODIRATIME),
        (StatVfsMountFlags::RELATIME, MountFlags::RELATIME),
    ] {
        if current.contains(have) {
            flags |= keep;
        }
    }
    rustix::mount::mount_remount(target, flags, "").map_err(to_io)
}

/// Whether the mount at `path` is `noexec`.
pub fn is_noexec(path: &Path) -> io::Result<bool> {
    let flags = rustix::fs::statvfs(path).map_err(to_io)?.f_flag;
    Ok(flags.contains(StatVfsMountFlags::NOEXEC))
}

/// Set or clear `noexec` on the mount at `path`, keeping its other per-mount
/// flags. Debian and Ubuntu mount `/run` `noexec`; the transition step and the
/// session's units run the binary copy from it.
pub fn set_noexec(path: &Path, noexec: bool) -> io::Result<()> {
    let current = rustix::fs::statvfs(path).map_err(to_io)?.f_flag;
    let mut flags = MountFlags::BIND;
    for (have, keep) in [
        (StatVfsMountFlags::RDONLY, MountFlags::RDONLY),
        (StatVfsMountFlags::NOSUID, MountFlags::NOSUID),
        (StatVfsMountFlags::NODEV, MountFlags::NODEV),
        (StatVfsMountFlags::NOATIME, MountFlags::NOATIME),
        (StatVfsMountFlags::NODIRATIME, MountFlags::NODIRATIME),
        (StatVfsMountFlags::RELATIME, MountFlags::RELATIME),
    ] {
        if current.contains(have) {
            flags |= keep;
        }
    }
    if noexec {
        flags |= MountFlags::NOEXEC;
    }
    rustix::mount::mount_remount(path, flags, "").map_err(to_io)
}

/// A read-only bind of `source` at `target` (not recursive).
pub fn bind_read_only(source: &Path, target: &Path) -> io::Result<()> {
    bind(source, target, false)?;
    if let Err(e) = remount_read_only(target) {
        let _ = rustix::mount::unmount(target, UnmountFlags::DETACH);
        return Err(e);
    }
    Ok(())
}

/// Make the tree at `target` recursively private, so nothing propagates
/// between it and the rest of the system. Every mount below the next root is
/// private already; this is the backstop for the finished tree.
pub fn make_rprivate(target: &Path) -> io::Result<()> {
    rustix::mount::mount_change(
        target,
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .map_err(to_io)
}

fn overlay_path(path: &Path) -> io::Result<String> {
    escape_overlay_path(path).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} cannot be an overlay layer", path.display()),
        )
    })
}

/// Mount an overlay at `target` with one lower layer.
pub fn mount_overlay(lower: &Path, upper: &Path, work: &Path, target: &Path) -> io::Result<()> {
    let data = format!(
        "lowerdir={},upperdir={},workdir={}",
        overlay_path(lower)?,
        overlay_path(upper)?,
        overlay_path(work)?
    );
    let data = c_string(&data)?;
    rustix::mount::mount(
        "overlay",
        target,
        "overlay",
        MountFlags::empty(),
        data.as_c_str(),
    )
    .map_err(to_io)
}

/// An overlay at `target` whose lower is the filesystem mounted at `source`
/// alone (none of its submounts), read-only so the overlay can never update an
/// atime on it. `helper` is an empty directory used for the lower bind; the
/// overlay keeps a private clone of its layers, so the helper mount is gone
/// again when this returns.
pub fn overlay_over(
    source: &Path,
    helper: &Path,
    upper: &Path,
    work: &Path,
    target: &Path,
) -> io::Result<()> {
    std::fs::create_dir_all(helper)?;
    bind_read_only(source, helper)?;
    let mounted = mount_overlay(helper, upper, work, target);
    let _ = rustix::mount::unmount(helper, UnmountFlags::DETACH);
    let _ = std::fs::remove_dir(helper);
    mounted
}

/// Mount the block device `source` (`fstype`, with optional `data`) at
/// `target`.
pub fn mount_device(
    source: &Path,
    fstype: &str,
    data: Option<&str>,
    target: &Path,
) -> io::Result<()> {
    let data = data.map(c_string).transpose()?;
    rustix::mount::mount(source, target, fstype, MountFlags::empty(), data.as_deref())
        .map_err(to_io)
}

/// The mount points of the live mount table.
pub fn mount_points() -> Vec<PathBuf> {
    read_mountinfo()
        .unwrap_or_default()
        .into_iter()
        .map(|e| e.mount_point)
        .collect()
}

/// Whether `path` is a mount point in `entries`.
pub fn is_mount_point(entries: &[MountEntry], path: &Path) -> bool {
    entries.iter().any(|e| e.mount_point == path)
}

/// Detach every mount on or below `path` among `mount_points`, deepest first.
/// Returns the mount points detached.
pub fn detach_under(path: &Path, mount_points: &[PathBuf]) -> Vec<PathBuf> {
    let mut under: Vec<&PathBuf> = mount_points
        .iter()
        .filter(|m| m.starts_with(path))
        .collect();
    under.sort_by_key(|m| std::cmp::Reverse(m.components().count()));
    under
        .into_iter()
        .filter(|m| rustix::mount::unmount(m.as_path(), UnmountFlags::DETACH).is_ok())
        .cloned()
        .collect()
}

/// Detach the whole tree at `path` from the live mount table, repeating while
/// mounts remain (stacked mounts come off one per round). Returns what is
/// still mounted on or below `path` afterwards.
pub fn detach_tree(path: &Path) -> Vec<PathBuf> {
    for _ in 0..8 {
        let points = mount_points();
        if !points.iter().any(|m| m.starts_with(path)) {
            return Vec::new();
        }
        if detach_under(path, &points).is_empty() {
            break;
        }
    }
    mount_points()
        .into_iter()
        .filter(|m| m.starts_with(path))
        .collect()
}

/// Remove the runtime directory `dir`, detaching every mount below it first.
/// An activation killed between its lower bind and that bind's read-only
/// remount leaves a writable bind of a decoy filesystem there (the root
/// itself, for the root overlay), and a recursive removal would walk into it.
/// Nothing is removed while anything stays mounted below `dir`.
pub fn remove_runtime_dir(dir: &Path) {
    if detach_tree(dir).is_empty() {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Open `path` as if `root` were `/`: absolute symlinks and `..` stay inside
/// `root`, the way PID 1 resolves the init in the next root.
fn open_in_root(root: &Path, path: &Path) -> io::Result<OwnedFd> {
    open_in_root_with(root, path, OFlags::PATH)
}

/// [`open_in_root`] with the open flags `flags`.
fn open_in_root_with(root: &Path, path: &Path, flags: OFlags) -> io::Result<OwnedFd> {
    let dir = rustix::fs::open(
        root,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(to_io)?;
    let relative = path.strip_prefix("/").unwrap_or(path);
    let relative = if relative.as_os_str().is_empty() {
        Path::new(".")
    } else {
        relative
    };
    rustix::fs::openat2(
        &dir,
        relative.as_os_str().as_bytes(),
        flags | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::IN_ROOT,
    )
    .map_err(to_io)
}

/// The directory at `path` as if `root` were `/`, for the `*at` calls that
/// create, replace or remove an entry in it. The descriptor reads nothing
/// (`O_PATH`).
///
/// A plain path below `/run/nextroot` resolves an absolute symlink on the
/// running system: a decoy whose `/home` or `~/.config` is such a link would
/// take a write meant for the next root onto the decoy disk.
pub fn open_dir_in_root(root: &Path, path: &Path) -> io::Result<OwnedFd> {
    open_in_root_with(root, path, OFlags::PATH | OFlags::DIRECTORY)
}

/// The names in the directory at `path`, resolved as if `root` were `/`.
pub fn list_in_root(root: &Path, path: &Path) -> io::Result<Vec<OsString>> {
    let fd = open_in_root_with(root, path, OFlags::RDONLY | OFlags::DIRECTORY)?;
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::new(fd).map_err(to_io)? {
        let name = entry.map_err(to_io)?.file_name().to_bytes().to_vec();
        if name != b"." && name != b".." {
            names.push(OsString::from_vec(name));
        }
    }
    Ok(names)
}

/// Create the directory `path` and every missing parent as if `root` were
/// `/`, and open it like [`open_dir_in_root`]. `made` is called with the
/// parent and the name of each directory created (mode `0777` less the
/// umask, as `mkdir -p`), to give it an owner. A component that exists but
/// does not resolve to a directory inside `root`, such as a dangling link,
/// fails the call: nothing is created through it.
pub fn create_dir_all_in_root(
    root: &Path,
    path: &Path,
    made: &mut dyn FnMut(BorrowedFd<'_>, &OsStr) -> io::Result<()>,
) -> io::Result<OwnedFd> {
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => names.push(name),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("not a plain path: {}", path.display()),
                ));
            }
        }
    }
    let mut dir = open_dir_in_root(root, Path::new("/"))?;
    let mut current = PathBuf::from("/");
    for name in names {
        current.push(name);
        dir = match open_dir_in_root(root, &current) {
            Ok(fd) => fd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                rustix::fs::mkdirat(&dir, name, Mode::from_raw_mode(0o777)).map_err(to_io)?;
                made(dir.as_fd(), name)?;
                open_dir_in_root(root, &current)?
            }
            Err(e) => return Err(e),
        };
    }
    Ok(dir)
}

/// The path the kernel reports for `fd`: absolute, with no symlink in it, so
/// a later call on it reaches the same directory.
pub fn real_path(fd: &OwnedFd) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

/// Whether `path` exists as if `root` were `/`: absolute symlinks resolve
/// inside `root`, so on NixOS `/etc/systemd/system` (a link into `/etc/static`
/// and the store) is looked up in that root's store, not the running one's.
pub fn exists_in_root(root: &Path, path: &Path) -> bool {
    open_in_root(root, path).is_ok()
}

/// Read the file at `path` as if `root` were `/` (absolute symlinks resolve
/// inside `root`): the next root's `/etc/fstab`, which on NixOS is a link
/// into the hidden store, or the decoy's own.
///
/// The file is opened with `O_NOATIME` ([`with_noatime`]), so a check or an
/// entry that reads the decoy's fstab does not stamp it with the time of the
/// read on a `relatime` filesystem; a caller that neither owns the file nor
/// holds `CAP_FOWNER` cannot avoid that. The flag covers the file alone: on
/// NixOS the decoy's `/etc/fstab` and `/etc/static` are links on its root,
/// and the lookup that follows them can still update their access times.
pub fn read_in_root(root: &Path, path: &Path) -> io::Result<Vec<u8>> {
    let dir = rustix::fs::open(
        root,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(to_io)?;
    let relative = path.strip_prefix("/").unwrap_or(path);
    let fd = with_noatime(|noatime| {
        rustix::fs::openat2(
            &dir,
            relative.as_os_str().as_bytes(),
            noatime | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::IN_ROOT,
        )
    })
    .map_err(to_io)?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::fs::File::from(fd), &mut bytes)?;
    Ok(bytes)
}

/// Why a root failed the pre-switch check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrecheckError {
    /// The init does not resolve inside the root.
    InitMissing(PathBuf, String),
    /// The init resolves but is not an executable regular file.
    InitNotExecutable(PathBuf),
    /// Neither `/etc/os-release` nor `/usr/lib/os-release` resolves inside it.
    NotAnOsTree,
}

impl std::fmt::Display for PrecheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrecheckError::InitMissing(init, why) => {
                write!(
                    f,
                    "the init {} does not resolve in the next root: {why}",
                    init.display()
                )
            }
            PrecheckError::InitNotExecutable(init) => {
                write!(
                    f,
                    "the init {} in the next root is not an executable file",
                    init.display()
                )
            }
            PrecheckError::NotAnOsTree => write!(
                f,
                "the next root has neither /etc/os-release nor /usr/lib/os-release"
            ),
        }
    }
}

impl std::error::Error for PrecheckError {}

/// Check that `root` is a root PID 1 can switch into: `init` resolves inside
/// it to an executable regular file, and it is an OS tree.
pub fn precheck(root: &Path, init: &Path) -> Result<(), PrecheckError> {
    let fd = open_in_root(root, init)
        .map_err(|e| PrecheckError::InitMissing(init.to_path_buf(), e.to_string()))?;
    let stat = rustix::fs::fstat(&fd)
        .map_err(|e| PrecheckError::InitMissing(init.to_path_buf(), e.to_string()))?;
    let mode = stat.st_mode;
    let regular = (mode & libc::S_IFMT) == libc::S_IFREG;
    if !regular || mode & 0o111 == 0 {
        return Err(PrecheckError::InitNotExecutable(init.to_path_buf()));
    }
    let os_tree = ["/etc/os-release", "/usr/lib/os-release"]
        .iter()
        .any(|p| open_in_root(root, Path::new(p)).is_ok());
    if !os_tree {
        return Err(PrecheckError::NotAnOsTree);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn executable(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn an_fhs_root_with_its_init_and_os_release_passes() {
        let root = tempfile::tempdir().unwrap();
        executable(&root.path().join("usr/lib/systemd/systemd"));
        std::fs::create_dir_all(root.path().join("usr/lib")).unwrap();
        std::fs::write(root.path().join("usr/lib/os-release"), "ID=debian\n").unwrap();
        std::fs::create_dir_all(root.path().join("etc")).unwrap();
        symlink("../usr/lib/os-release", root.path().join("etc/os-release")).unwrap();
        precheck(root.path(), Path::new("/usr/lib/systemd/systemd")).unwrap();
    }

    #[test]
    fn absolute_symlinks_resolve_inside_the_root_like_pid1_does() {
        // NixOS: /run/current-system -> /nix/store/…, an absolute symlink that
        // must resolve inside the next root, never on the running system.
        let root = tempfile::tempdir().unwrap();
        let system = root.path().join("nix/store/aaa-nixos-system");
        executable(&system.join("systemd/lib/systemd/systemd"));
        std::fs::create_dir_all(root.path().join("run")).unwrap();
        symlink(
            "/nix/store/aaa-nixos-system",
            root.path().join("run/current-system"),
        )
        .unwrap();
        std::fs::create_dir_all(root.path().join("etc/static")).unwrap();
        std::fs::write(system.join("os-release"), "ID=nixos\n").unwrap();
        symlink(
            "/nix/store/aaa-nixos-system/os-release",
            root.path().join("etc/os-release"),
        )
        .unwrap();
        precheck(
            root.path(),
            Path::new("/run/current-system/systemd/lib/systemd/systemd"),
        )
        .unwrap();
        // A symlink that escapes upwards is clamped to the root.
        symlink(
            "../../../../../../nix/store/aaa-nixos-system",
            root.path().join("run/up"),
        )
        .unwrap();
        precheck(
            root.path(),
            Path::new("/run/up/systemd/lib/systemd/systemd"),
        )
        .unwrap();
    }

    #[test]
    fn files_are_read_through_symlinks_resolved_inside_the_root() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("etc/static")).unwrap();
        std::fs::write(root.path().join("etc/static/fstab"), "inside\n").unwrap();
        symlink("/etc/static/fstab", root.path().join("etc/fstab")).unwrap();
        assert_eq!(
            read_in_root(root.path(), Path::new("/etc/fstab")).unwrap(),
            b"inside\n"
        );
        assert!(read_in_root(root.path(), Path::new("/etc/absent")).is_err());
    }

    #[test]
    fn directories_are_created_and_listed_through_links_resolved_inside_the_root() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("srv/people")).unwrap();
        // Absolute, and a name no host has: a lookup on the running system
        // would fail, one inside the root reaches srv/people.
        symlink("/srv/people", root.path().join("nails-test-home")).unwrap();
        let mut made = Vec::new();
        let fd = create_dir_all_in_root(
            root.path(),
            Path::new("/nails-test-home/alice/.config"),
            &mut |_, name| {
                made.push(name.to_owned());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(made, ["alice", ".config"]);
        assert_eq!(
            real_path(&fd).unwrap(),
            root.path()
                .canonicalize()
                .unwrap()
                .join("srv/people/alice/.config")
        );
        assert_eq!(
            list_in_root(root.path(), Path::new("/nails-test-home")).unwrap(),
            [OsString::from("alice")]
        );
        // An existing directory is opened, not made again.
        create_dir_all_in_root(root.path(), Path::new("/srv"), &mut |_, _| {
            panic!("nothing to make")
        })
        .unwrap();
    }

    #[test]
    fn nothing_is_created_through_a_dangling_link_or_a_dot_dot() {
        let root = tempfile::tempdir().unwrap();
        symlink("/gone", root.path().join("away")).unwrap();
        let mut none = |_: BorrowedFd<'_>, _: &OsStr| -> io::Result<()> { panic!("nothing made") };
        assert!(create_dir_all_in_root(root.path(), Path::new("/away/x"), &mut none).is_err());
        assert!(create_dir_all_in_root(root.path(), Path::new("/a/../b"), &mut none).is_err());
        assert!(!root.path().join("gone").exists() && !root.path().join("a").exists());
    }

    #[test]
    fn a_file_the_caller_does_not_own_is_read_without_o_noatime() {
        // The kernel refuses O_NOATIME (EPERM) on a file the caller neither
        // owns nor holds CAP_FOWNER for, and the read falls back to a plain
        // open. /proc/version is root's and has no access time to protect; as
        // root the first open already succeeds.
        let text = read_in_root(Path::new("/"), Path::new("/proc/version")).unwrap();
        assert!(text.starts_with(b"Linux version"), "{text:?}");
    }

    #[test]
    fn a_missing_or_unusable_init_or_a_non_os_tree_is_refused() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("etc")).unwrap();
        std::fs::write(root.path().join("etc/os-release"), "ID=x\n").unwrap();
        assert!(matches!(
            precheck(root.path(), Path::new("/sbin/init")),
            Err(PrecheckError::InitMissing(..))
        ));
        std::fs::create_dir_all(root.path().join("sbin")).unwrap();
        std::fs::write(root.path().join("sbin/init"), "").unwrap();
        assert!(matches!(
            precheck(root.path(), Path::new("/sbin/init")),
            Err(PrecheckError::InitNotExecutable(_))
        ));
        std::fs::remove_file(root.path().join("etc/os-release")).unwrap();
        executable(&root.path().join("sbin/init"));
        assert_eq!(
            precheck(root.path(), Path::new("/sbin/init")),
            Err(PrecheckError::NotAnOsTree)
        );
    }

    #[test]
    fn detach_under_takes_the_deepest_mounts_first_and_only_below_the_path() {
        // Not mounted in this test: nothing is detached, nothing panics, and
        // the selection is by path component, never by string prefix.
        let points = vec![
            PathBuf::from("/run/nextroot"),
            PathBuf::from("/run/nextroot/boot"),
            PathBuf::from("/run/nextrootx"),
        ];
        assert!(detach_under(Path::new("/nonexistent-root"), &points).is_empty());
    }
}
