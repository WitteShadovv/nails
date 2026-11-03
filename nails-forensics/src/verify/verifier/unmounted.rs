// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What an offline scan cannot read because it is not mounted under the
//! root: the mount points of the decoy's fstab and the homes of its login
//! accounts that hold nothing there, and how to mount each without writing
//! to the decoy's disk.

use super::crypt_open::opening;
use super::deep_scan::is_login_shell;
use super::*;
use crate::filesystem::MountEntry;
use nails_base::crypttab::parse_crypttab;
use nails_base::fstab::{FstabEntry, parse_fstab, spec_device};
use nails_base::next_step::shell_word;
use std::ffi::OsStr;

/// The decoy's table of the filesystems it mounts.
const FSTAB_FILE: &str = "/etc/fstab";

/// The decoy's table of the encrypted volumes it opens.
const CRYPTTAB_FILE: &str = "/etc/crypttab";

/// Why a place of the decoy that does not resolve inside the root is listed:
/// nothing is looked up through it on the machine running verify.
const NOT_RESOLVED: &str = "it does not resolve inside the root, so nothing there was read";

/// How the device an fstab entry names is mounted on the machine that runs
/// verify, by the superblock its mounts share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mounted {
    /// Mounted, its filesystem read-write (the decoy's own in a session).
    ReadWrite,
    /// Mounted, its filesystem read-only.
    ReadOnly,
    /// Not mounted, or not found on this machine.
    No,
}

impl<F: Filesystem> Verifier<F> {
    /// The places of the decoy system an offline scan cannot read, because
    /// what the decoy mounts there is not mounted under the root: each mount
    /// point of the decoy's `/etc/fstab` that is missing or empty there, and
    /// each home of a login account of its `/etc/passwd` that is, outside
    /// those mount points, and the fstab itself when it cannot be read inside
    /// the root. A btrfs decoy scanned by its system subvolume alone misses
    /// its `@home` this way, and on archinstall its `@log`. The line of a
    /// mount point says how to mount it without writing to the decoy's disk:
    /// again and read-only when its device is mounted already, read-only and
    /// without a journal replay when it is not, a file of the image through
    /// a read-only loop device, and a mapping that is not open here once it
    /// is opened read-only ([`Self::how_to_mount`]).
    ///
    /// The decoy's files are read inside the root ([`Self::read_in_image`]),
    /// so NixOS's `/etc/fstab`, a link into the store, is followed into the
    /// image's store, and each place is resolved inside the root
    /// ([`Self::place`]), so no link leads out of the image. A place is then
    /// looked at with `lstat` and `stat` and listed with `O_NOATIME`, and one
    /// that cannot be looked at is left out.
    pub(super) fn unmounted_areas(&self) -> Vec<String> {
        let mut areas = Vec::new();
        let table = self.filesystem.mount_table().unwrap_or_default();
        let mut entries = match self.read_in_image(Path::new(FSTAB_FILE)) {
            Ok(text) => parse_fstab(&text)
                .into_iter()
                .filter(|entry| {
                    entry.file.is_absolute()
                        && entry.file != Path::new("/")
                        && !entry.is_swap()
                        && !entry.is_virtual()
                        && !entry.is_host_share()
                        && !entry.is_network()
                        // The source of a bind lies in the image, and was scanned.
                        && !entry.is_bind()
                })
                .collect(),
            Err(_) => {
                if let Some(why) = self.why_unread(Path::new(FSTAB_FILE)) {
                    areas.push(format!(
                        "/etc/fstab, the decoy's table of what it mounts ({why}: what it mounts \
                         is not known)"
                    ));
                }
                Vec::new()
            }
        };
        entries.sort_by(|a, b| a.file.cmp(&b.file));
        entries.dedup_by(|a, b| a.file == b.file);

        let mut unmounted: Vec<PathBuf> = Vec::new();
        for entry in entries {
            if unmounted.iter().any(|seen| entry.file.starts_with(seen)) {
                continue;
            }
            let why = match self.place(&entry.file) {
                None => NOT_RESOLVED.to_string(),
                Some(place) if self.holds_nothing(&place) => format!(
                    "missing or empty under the root. {}",
                    self.how_to_mount(&entry, &place, &table)
                ),
                Some(_) => continue,
            };
            areas.push(format!(
                "{}, which the decoy's /etc/fstab mounts ({why})",
                entry.file.display()
            ));
            unmounted.push(entry.file);
        }
        for (user, home) in self.login_homes() {
            if unmounted.iter().any(|seen| home.starts_with(seen)) {
                continue;
            }
            let why = match self.place(&home) {
                None => NOT_RESOLVED,
                Some(place) if self.holds_nothing(&place) => {
                    "missing or empty under the root: mount what holds it there without writing \
                     to it before the scan"
                }
                Some(_) => continue,
            };
            areas.push(format!(
                "{}, the home of {user} in the decoy's /etc/passwd ({why})",
                home.display()
            ));
        }
        areas
    }

    /// The login accounts of the decoy's `/etc/passwd` (from
    /// [`FIRST_LOGIN_UID`] on, with a login shell) and their homes.
    fn login_homes(&self) -> Vec<(String, PathBuf)> {
        let Ok(text) = self.read_in_image(Path::new(PASSWD_FILE)) else {
            return Vec::new();
        };
        text.lines()
            .filter_map(|line| {
                let fields: Vec<&str> = line.split(':').collect();
                let [user, _, uid, _, _, home, shell] = fields[..] else {
                    return None;
                };
                let login = uid.parse::<u32>().is_ok_and(|uid| uid >= FIRST_LOGIN_UID)
                    && is_login_shell(shell)
                    && home.starts_with('/');
                login.then(|| (user.to_string(), PathBuf::from(home)))
            })
            .collect()
    }

    /// Why the decoy's file `path` could not be read, when it is there under
    /// the root: a link says where it leads inside the root. `None` when
    /// nothing is there, or for a link to `/dev/null`, which holds nothing by
    /// design.
    fn why_unread(&self, path: &Path) -> Option<String> {
        let entry = self.rebase(path);
        let link = matches!(self.filesystem.is_symlink(&entry), Ok(true));
        if !link && !matches!(self.filesystem.path_exists(&entry), Ok(true)) {
            return None;
        }
        if !link {
            return Some("it could not be read".to_string());
        }
        let inside = match &self.context {
            VerifyContext::Offline { root } => self.filesystem.resolve_in_root(root, path),
            VerifyContext::Host => Some(path.to_path_buf()),
        };
        match inside {
            Some(inside) if inside == Path::new("/dev/null") => None,
            Some(inside) => Some(format!(
                "a link that leads to {} inside the root, where no file can be read",
                inside.display()
            )),
            None => Some("a link that does not resolve inside the root".to_string()),
        }
    }

    /// Whether `place`, a decoy path resolved under the root, is missing or
    /// an empty folder. A link (one whose target could not be resolved, say)
    /// is not followed, and answers no.
    fn holds_nothing(&self, place: &Path) -> bool {
        if !matches!(self.filesystem.is_symlink(place), Ok(false)) {
            return false;
        }
        match self.filesystem.inode(place) {
            Ok(None) => true,
            Ok(Some(_)) => {
                matches!(self.filesystem.is_directory(place), Ok(true))
                    && self
                        .filesystem
                        .list_directory(place)
                        .is_ok_and(|entries| entries.is_empty())
            }
            Err(_) => false,
        }
    }

    /// How to mount what `entry` mounts on `place` without writing to the
    /// decoy's disk. A file of the image is attached to a read-only loop
    /// device first, and a mapping that is not open here is opened read-only
    /// first, as the decoy's `/etc/crypttab` opens it: the kernel keeps
    /// either device read-only, and it is mounted with the option that skips
    /// its filesystem's journal replay. A device that is mounted already has
    /// its journal behind it: a second mount shares that filesystem,
    /// read-only as it is or made read-only once mounted. Any other device is
    /// made read-only first and mounted without a journal replay.
    fn how_to_mount(&self, entry: &FstabEntry, place: &Path, table: &[MountEntry]) -> String {
        let at = shell_word(place.as_os_str());
        // A btrfs subvolume is named at each mount of it.
        let subvol = entry
            .option_value("subvol")
            .map(|subvol| format!("subvol={subvol}"))
            .or_else(|| {
                entry
                    .option_value("subvolid")
                    .map(|id| format!("subvolid={id}"))
            });
        let with = |first: Option<&str>| {
            let options: Vec<&str> = first.into_iter().chain(subvol.as_deref()).collect();
            if options.is_empty() {
                String::new()
            } else {
                format!("-o {} ", options.join(","))
            }
        };
        let replay_free = with(Some(replay_free(&entry.vfstype)));
        if is_loop_file(entry) {
            let Some(file) = self.place(Path::new(&entry.spec)) else {
                return format!(
                    "Its device is the file {} of the image, which does not resolve inside the \
                     root, so no command is given",
                    entry.spec
                );
            };
            return format!(
                "Its device is a file in the image: attach it read-only, with `sudo losetup \
                 --read-only --find --show {}{}`, then mount the loop device that prints there \
                 without a journal replay before the scan, with `sudo mount {replay_free}<loop \
                 device> {at}`",
                loop_options(entry),
                shell_word(file.as_os_str())
            );
        }
        let device = entry
            .device()
            .map_or_else(|| "<device>".to_string(), |dev| shell_word(dev.as_os_str()));
        if let Some(name) = self.closed_mapping(entry) {
            return self.how_to_open(name, &format!("{replay_free}{device} {at}"));
        }
        match self.mounted_now(entry, table) {
            Mounted::ReadWrite => format!(
                "Its device is mounted here already, read-write: mount it there again and make \
                 that mount read-only before the scan, with `sudo mount {}{device} {at} && sudo \
                 mount -o remount,bind,ro {at}`",
                with(None)
            ),
            Mounted::ReadOnly => format!(
                "Its device is mounted here already, read-only: mount it there before the scan, \
                 with `sudo mount {}{device} {at}`",
                with(Some("ro"))
            ),
            Mounted::No => format!(
                "Its device is not mounted here: make it read-only and mount it there without a \
                 journal replay before the scan, with `sudo blockdev --setro {device} && sudo \
                 mount {replay_free}{device} {at}`"
            ),
        }
    }

    /// The name of the device-mapper mapping that `entry` mounts, when the
    /// mapping is not open here: its `/dev/mapper` node is missing.
    fn closed_mapping<'e>(&self, entry: &'e FstabEntry) -> Option<&'e str> {
        let name = entry.spec.strip_prefix("/dev/mapper/")?;
        matches!(
            self.filesystem.path_exists(Path::new(&entry.spec)),
            Ok(false)
        )
        .then_some(name)
    }

    /// How to open the mapping `name` read-only, from the source and as the
    /// decoy's `/etc/crypttab` opens it ([`opening`]), and then run `mount`
    /// with `mounting` (its options, the device and the mount point). What
    /// the line opens it with that no option carries over is named after the
    /// command.
    fn how_to_open(&self, name: &str, mounting: &str) -> String {
        let volume = self
            .read_in_image(Path::new(CRYPTTAB_FILE))
            .ok()
            .and_then(|text| {
                parse_crypttab(&text)
                    .into_iter()
                    .find(|volume| volume.name == name)
            });
        let Some(volume) = volume else {
            return format!(
                "Its device is a mapping that is not open here: {}, where <source> is the \
                 encrypted device or file that holds it",
                open_and_mount("", "<source>", name, mounting)
            );
        };
        let opening = opening(&volume, |path| self.here(path));
        let source = self.here(&volume.source);
        let mut how = format!(
            "Its device is a mapping of the decoy's /etc/crypttab that is not open here: {}",
            open_and_mount(
                &opening.options,
                source.as_deref().unwrap_or("<source>"),
                name,
                mounting
            )
        );
        if source.is_none() {
            how.push_str(&format!(
                ", where <source> is {} of the image, which does not resolve inside the root",
                volume.source
            ));
        }
        if !opening.left_out.is_empty() {
            how.push_str(&format!(
                ". It needs parameters of its own for what its line there also opens it with, \
                 which the command leaves out: {}",
                opening.left_out.join(", ")
            ));
        }
        how
    }

    /// Where a device or file that the decoy's `/etc/crypttab` names lies
    /// here, shell-quoted: a device node (a `UUID=` and its like by udev's
    /// link) as it is, a file of the image resolved inside the root. `None`
    /// for a file that does not resolve there.
    fn here(&self, path: &str) -> Option<String> {
        let here = match spec_device(path) {
            Some(device) => device,
            None => self.place(Path::new(path))?,
        };
        Some(shell_word(here.as_os_str()))
    }

    /// How the device `entry` names is mounted here now: the device node of
    /// its spec, its links followed, against the source of each mount of the
    /// mount table, theirs followed too. A device that is not found here is
    /// not mounted.
    fn mounted_now(&self, entry: &FstabEntry, table: &[MountEntry]) -> Mounted {
        let Some(device) = entry
            .device()
            .and_then(|dev| self.filesystem.canonicalize(&dev).ok())
        else {
            return Mounted::No;
        };
        let mounted = table.iter().find(|mount| {
            mount.source.starts_with("/dev/")
                && self
                    .filesystem
                    .canonicalize(&mount.source)
                    .is_ok_and(|source| source == device)
        });
        match mounted {
            None => Mounted::No,
            Some(mount) if mount.super_opts.split(',').any(|option| option == "ro") => {
                Mounted::ReadOnly
            }
            Some(_) => Mounted::ReadWrite,
        }
    }
}

/// Whether `entry` mounts a file of the image, which mount(8) attaches to a
/// loop device of its own: a spec that is a path outside `/dev`.
fn is_loop_file(entry: &FstabEntry) -> bool {
    let spec = Path::new(&entry.spec);
    spec.is_absolute() && !spec.starts_with("/dev")
}

/// The `losetup` options that set the loop device of `entry` up as its
/// fstab line does: from `offset=` into the file, over `sizelimit=` bytes.
fn loop_options(entry: &FstabEntry) -> String {
    [("offset", "--offset"), ("sizelimit", "--sizelimit")]
        .into_iter()
        .filter_map(|(key, option)| {
            let value = entry.option_value(key)?;
            Some(format!("{option} {} ", shell_word(OsStr::new(value))))
        })
        .collect()
}

/// The command that opens the mapping `name` read-only from `source` with
/// `options` and mounts it with `mounting`, and what it does.
fn open_and_mount(options: &str, source: &str, name: &str, mounting: &str) -> String {
    format!(
        "open it read-only and mount it there without a journal replay before the scan, with \
         `sudo cryptsetup open --readonly {options}{source} {} && sudo mount {mounting}`",
        shell_word(OsStr::new(name))
    )
}

/// The options that mount a filesystem of type `fstype` read-only without
/// replaying its journal or log onto the disk, which a plain `ro` does on
/// ext4, btrfs, XFS and f2fs (mount(8), ext4(5), btrfs(5), xfs(5), the
/// kernel's f2fs documentation). Other types keep no journal to replay.
fn replay_free(fstype: &str) -> &'static str {
    match fstype {
        "ext2" | "ext3" | "ext4" => "ro,noload",
        "btrfs" => "ro,rescue=nologreplay",
        "xfs" | "f2fs" => "ro,norecovery",
        _ => "ro",
    }
}
