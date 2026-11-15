// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The options of the decoy's fstab and crypttab lines whose effect NAILS
//! reads: the lists a plain line's options keep to.
//!
//! Each option is named by the part before its first `=`, as systemd's
//! generators and `libmount` name it ([`option_named`]), and each list says in
//! which forms NAILS reads it ([`Form`]). An option that no list holds, or one
//! a list holds in another form than the line gives, makes the line not plain
//! ([`Unplain::Unknown`], [`Unplain::Unread`], [`Unplain::NoValue`]). That
//! holds for every option of a crypttab line, and of an fstab line that the
//! claims count and whose first field names local storage: a bind line of any
//! type, a swap line, and a line of any other type but a RAM, kernel,
//! host-share, network or overlay filesystem's and a FUSE program's that takes
//! a remote source ([`reads_every_option`]). Of any other fstab line, an option
//! no list holds makes the line not plain where its value may name a path or a
//! device ([`may_name_a_path`]): one that is absolute, a tag, or holds a `/` or
//! a `:`, as a `driver:param` form such as `cmd:/bin/prog` does. A line that is
//! not plain is a finding of its own (see the `plain` module), and the claims
//! count it as one the boot mounts or opens ([`reads_every_known`]).
//!
//! What NAILS reads of an option it knows, and why the others are harmless:
//!
//! - `noauto`, `auto`, `x-systemd.automount`, `comment=systemd.automount`,
//!   `bind`, `rbind`, `subvol=` and `subvolid=` the judge reads itself (see
//!   the `options`, `lines` and `paths` modules), by their names, with or
//!   without a value. `x-systemd.wanted-by=` and `x-systemd.required-by=` it
//!   reads with `local-fs.target`, which pulls the line in as without them, and
//!   alone, which systemd ignores: one that names another unit links the line
//!   into that unit in place of `local-fs.target`.
//! - Of a path or a device that an option names ([`Form::Reads`]), the judge
//!   reads a path where it leads, with no link followed, and resolves a
//!   device's path in `/dev` through links that stay in `/dev`, a udev link,
//!   a link in `/dev/block` or a volume group's link among them, as it reads
//!   a line's source (see the `reads` module): ext4's `journal_path=` and
//!   `journal_dev=` (a device by its number), XFS's `logdev=` and `rtdev=`
//!   and btrfs's `device=`, which the filesystem opens and writes to,
//!   `x-systemd.requires-mounts-for=` and `x-systemd.wants-mounts-for=`,
//!   whose mounts systemd makes first, cifs's `credentials=`, a file
//!   `mount.cifs` reads, an overlay's `lowerdir=`, `upperdir=` and
//!   `workdir=`, the folders it is made of, and of a crypttab line
//!   `tpm2-device=` and `fido2-device=`, which `systemd-cryptsetup` opens and
//!   writes TPM or FIDO2 commands to unless they are `auto`, and
//!   `tpm2-signature=` and `tpm2-pcrlock=`, files it reads. `header=` and
//!   `tcrypt-keyfile=` the `reads` module reads as before.
//! - The generic flags of `libmount` (`defaults`, `ro`, `rw`, `exec`,
//!   `noexec`, `suid`, `nosuid`, `dev`, `nodev`, `sync`, `async`, `dirsync`)
//!   and the atime family (`atime`, `noatime`, `diratime`, `nodiratime`,
//!   `relatime`, `norelatime`, `strictatime`, `nostrictatime`, `lazytime`,
//!   `nolazytime`) set what the mount lets run or open and when it writes, on
//!   the filesystem the line mounts. `nofail` and `_netdev` change only when
//!   the boot mounts the line, and whether it goes on without it, `user`,
//!   `users`, `owner`, `group` and their `no` forms only who may mount it by
//!   hand, and `loop` that `libmount` opens the line's file through a loop
//!   device, as it does for a regular file anyway: NAILS reads that file as
//!   the line's source.
//! - `comment=` is a comment to `libmount`, and `x-gvfs-*` hints to the
//!   desktop's file manager, which shows or names the mount by them.
//!   `x-systemd.device-timeout=`, `x-systemd.mount-timeout=` and
//!   `x-systemd.idle-timeout=` set how long systemd waits for the device or the
//!   mount and when it unmounts an idle automount. `x-systemd.makefs` and
//!   `x-systemd.growfs` make or grow a filesystem on the line's own device,
//!   which NAILS reads as its source, `x-initrd.mount` has the initrd mount the
//!   line, which the boot then still mounts, and `X-mount.mkdir` has
//!   `libmount` make the mount point, as systemd does for every mount.
//! - The options of a filesystem that the stock lines of the supported
//!   families carry tune how that filesystem writes to its own device, or
//!   whose its files are: btrfs's compression, free-space cache, SSD and
//!   discard options and `commit=`; ext4's `errors=`, `commit=`, `data=`,
//!   `discard`, barriers, ACLs and extended attributes; XFS's log buffers,
//!   inode numbers and quota off; F2FS's garbage collection, inline data,
//!   logging and fsync modes, as `genfstab` copies them; FAT's, exFAT's and
//!   NTFS's owners, masks, code pages and short names; a swap line's `sw`,
//!   `pri=` and `discard`; FUSE's `allow_other`, `allow_root` and
//!   `default_permissions`; and ZFS's `zfsutil`. None names a device, a path
//!   or another part of the filesystem, or changes whether the boot mounts the
//!   line. An option of one filesystem on a line of another, such as `errors=`
//!   on a btrfs line, which btrfs refuses, is no option NAILS reads there.
//! - Of a crypttab line, the formats (`luks`, `plain`, `bitlk` and the
//!   TrueCrypt ones, which the judge reads), `discard`, `swap` and `tmp`
//!   (swap or a filesystem made on the mapping), `nofail`, `_netdev`,
//!   `x-initrd.attach` and Debian's `initramfs` (when it is opened),
//!   `readonly`, the cipher, sizes and offsets in the source, the key slot and
//!   key file size and offset, `keyfile-erase`, the crypt workers, and how
//!   often, how long and how the boot asks for the passphrase (`tries=`,
//!   `timeout=`, `keyfile-timeout=`, `password-echo=`, `headless`,
//!   `token-timeout=`, `try-empty-password`, `tpm2-pcrs=`): none names a
//!   device or a file besides the line's source and key file. `keyscript=`
//!   is not plain for its own reason (see the `reads` module).
//!
//! NAILS reads a flag only alone: one given with a value, such as `nofail=1`,
//! is not plain, as no stock line gives one and `libmount` releases read it
//! in different ways. `noauto`, `auto` and the options the judge reads by
//! their names it reads with any value, as systemd does.

#[cfg(test)]
#[path = "known_tests.rs"]
mod tests;

use super::paths::is_claimed;
use super::plain::{Unplain, takes_a_remote_source_line};
use crate::crypttab::CrypttabEntry;
use crate::fstab::{FstabEntry, option_named};

/// In which forms NAILS reads an option it knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    /// Alone only, as a flag: with a value it is not read.
    Flag,
    /// Alone or with any value.
    Any,
    /// With a value that is not empty.
    Valued,
    /// Alone, which systemd ignores, or with `local-fs.target`.
    LocalFs,
    /// With a value that names a path or a device, read as a source is.
    Reads(Reading),
}

/// How the value of an option that names a path or a device is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reading {
    /// An absolute path: a device by its path in `/dev`, any other path as
    /// the path of a file or a folder.
    Path,
    /// A list of absolute paths, apart by `:`.
    Paths,
    /// `auto`, which names no device, or an absolute path, as [`Self::Path`].
    AutoOrPath,
    /// A device by its number, as the kernel's `new_decode_dev()` reads it.
    Number,
    /// A path or a tag, which the `reads` module reads, and anything else,
    /// which systemd ignores or refuses.
    KeyLike,
}

/// The options of one list, by the form NAILS reads them in: each list of
/// names apart by white space.
struct List {
    /// Read alone only.
    flags: &'static str,
    /// Read alone or with any value.
    any: &'static str,
    /// Read with a value that is not empty.
    valued: &'static str,
    /// Read alone or with `local-fs.target`.
    local_fs: &'static str,
    /// The starts of names read alone or with any value.
    prefixes: &'static str,
    /// Read with a value that names a path or a device.
    reads: &'static [(&'static str, Reading)],
}

const EMPTY: List = List {
    flags: "",
    any: "",
    valued: "",
    local_fs: "",
    prefixes: "",
    reads: &[],
};

/// Options any fstab line may give.
const GENERIC: List = List {
    flags: "defaults ro rw exec noexec suid nosuid dev nodev sync async dirsync atime noatime \
            diratime nodiratime relatime norelatime strictatime nostrictatime lazytime \
            nolazytime nofail _netdev user nouser users nousers owner noowner group nogroup loop",
    any: "noauto auto bind rbind comment x-systemd.automount x-systemd.makefs x-systemd.growfs \
          x-initrd.mount X-mount.mkdir x-mount.mkdir",
    valued: "x-systemd.device-timeout x-systemd.mount-timeout x-systemd.idle-timeout",
    local_fs: "x-systemd.wanted-by x-systemd.required-by",
    prefixes: "x-gvfs-",
    reads: &[
        ("x-systemd.requires-mounts-for", Reading::Path),
        ("x-systemd.wants-mounts-for", Reading::Path),
    ],
};

/// Options of a swap line.
const SWAP: List = List {
    flags: "sw",
    any: "discard",
    valued: "pri",
    ..EMPTY
};

/// Options of an ext2, ext3 or ext4 line.
const EXT: List = List {
    flags: "discard nodiscard nobarrier acl noacl user_xattr nouser_xattr delalloc nodelalloc \
            noauto_da_alloc journal_checksum nojournal_checksum journal_async_commit \
            dioread_nolock dioread_lock noinit_itable block_validity noblock_validity i_version \
            inlinecrypt nombcache prefetch_block_bitmaps grpid bsdgroups nogrpid sysvgroups",
    any: "barrier auto_da_alloc init_itable",
    valued: "errors commit data data_err stripe resgid resuid max_batch_time min_batch_time \
             journal_ioprio",
    reads: &[
        ("journal_path", Reading::Path),
        ("journal_dev", Reading::Number),
    ],
    ..EMPTY
};

/// Options of a btrfs line.
const BTRFS: List = List {
    flags: "nospace_cache clear_cache ssd ssd_spread nossd nossd_spread nodiscard autodefrag \
            noautodefrag acl noacl barrier nobarrier datacow nodatacow datasum nodatasum \
            flushoncommit noflushoncommit treelog notreelog user_subvol_rm_allowed skip_balance",
    any: "compress compress-force space_cache discard",
    valued: "subvol subvolid commit max_inline metadata_ratio thread_pool fatal_errors",
    reads: &[("device", Reading::Path)],
    ..EMPTY
};

/// Options of an XFS line.
const XFS: List = List {
    flags: "attr2 noattr2 inode32 inode64 largeio nolargeio swalloc noquota discard nodiscard \
            wsync filestreams ikeep noikeep grpid bsdgroups nogrpid sysvgroups",
    valued: "logbufs logbsize allocsize sunit swidth",
    reads: &[("logdev", Reading::Path), ("rtdev", Reading::Path)],
    ..EMPTY
};

/// Options of a FAT line (`vfat`, `msdos`).
const FAT: List = List {
    flags: "uni_xlate nonumtail flush quiet showexec sys_immutable discard dos1xfloppy usefree \
            rodir",
    any: "utf8",
    valued: "uid gid umask dmask fmask allow_utime codepage iocharset shortname errors tz \
             time_offset check",
    ..EMPTY
};

/// Options of an NTFS line (`ntfs`, `ntfs3`, `ntfs-3g`).
const NTFS: List = List {
    flags: "windows_names",
    valued: "uid gid umask dmask fmask iocharset nls",
    ..EMPTY
};

/// Options of an exFAT line.
const EXFAT: List = List {
    flags: "discard",
    valued: "uid gid umask dmask fmask iocharset errors",
    ..EMPTY
};

/// Options of an F2FS line, as `genfstab` copies them from the mount table.
const F2FS: List = List {
    flags: "discard nodiscard no_heap heap user_xattr nouser_xattr inline_xattr noinline_xattr \
            acl noacl inline_data noinline_data inline_dentry noinline_dentry flush_merge \
            noflush_merge barrier nobarrier extent_cache noextent_cache checkpoint_merge \
            nocheckpoint_merge gc_merge nogc_merge age_extent_cache",
    valued: "background_gc discard_unit mode active_logs alloc_mode fsync_mode memory errors \
             inline_xattr_size compress_algorithm compress_log_size",
    ..EMPTY
};

/// Options of a FUSE line.
const FUSE: List = List {
    flags: "allow_other allow_root default_permissions",
    ..EMPTY
};

/// Options of a ZFS line.
const ZFS: List = List {
    flags: "zfsutil",
    ..EMPTY
};

/// Options of a cifs line that name a path.
const CIFS: List = List {
    reads: &[("credentials", Reading::Path)],
    ..EMPTY
};

/// Options of an overlay line that name its folders.
const OVERLAY: List = List {
    reads: &[
        ("lowerdir", Reading::Paths),
        ("upperdir", Reading::Path),
        ("workdir", Reading::Path),
    ],
    ..EMPTY
};

/// Options of a crypttab line, but `keyscript=` (see the `reads` module).
const CRYPTTAB: List = List {
    flags: "luks plain bitlk tcrypt tcrypt-hidden tcrypthidden tcrypt-system tcrypt-veracrypt \
            veracrypt discard swap nofail _netdev x-initrd.attach initramfs readonly read-only \
            same-cpu-crypt submit-from-crypt-cpus no-read-workqueue no-write-workqueue \
            keyfile-erase",
    any: "noauto auto tmp headless try-empty-password",
    valued: "cipher hash size sector-size offset skip keyfile-size keyfile-offset key-slot \
             keyslot tries timeout keyfile-timeout password-echo token-timeout tpm2-pcrs \
             veracrypt-pim x-systemd.device-timeout",
    reads: &[
        ("header", Reading::KeyLike),
        ("tcrypt-keyfile", Reading::KeyLike),
        ("tpm2-device", Reading::AutoOrPath),
        ("fido2-device", Reading::AutoOrPath),
        ("tpm2-signature", Reading::Path),
        ("tpm2-pcrlock", Reading::Path),
    ],
    ..EMPTY
};

/// The options of a line of the type `vfstype` besides the generic ones.
fn of_type(vfstype: &str) -> &'static List {
    let fuse = ["fuse", "fuse3", "fuseblk"].iter().any(|kind| {
        vfstype == *kind
            || vfstype
                .strip_prefix(kind)
                .is_some_and(|rest| rest.starts_with('.'))
    });
    match vfstype {
        "swap" => &SWAP,
        "ext2" | "ext3" | "ext4" => &EXT,
        "btrfs" => &BTRFS,
        "xfs" => &XFS,
        "vfat" | "msdos" => &FAT,
        "ntfs" | "ntfs3" | "ntfs-3g" => &NTFS,
        "exfat" => &EXFAT,
        "f2fs" => &F2FS,
        "zfs" => &ZFS,
        "cifs" | "smb3" => &CIFS,
        "overlay" => &OVERLAY,
        _ if fuse => &FUSE,
        _ => &EMPTY,
    }
}

/// The name of `option` in `list` and the form NAILS reads it in, if the
/// list knows it.
fn in_list(list: &List, option: &str) -> Option<(&'static str, Form)> {
    let named = |names: &'static str, form: Form| {
        names
            .split_whitespace()
            .find(|name| option_named(option, name).is_some())
            .map(|name| (name, form))
    };
    named(list.flags, Form::Flag)
        .or_else(|| named(list.any, Form::Any))
        .or_else(|| named(list.valued, Form::Valued))
        .or_else(|| named(list.local_fs, Form::LocalFs))
        .or_else(|| {
            list.reads
                .iter()
                .find(|(name, _)| option_named(option, name).is_some())
                .map(|(name, reading)| (*name, Form::Reads(*reading)))
        })
        .or_else(|| {
            list.prefixes
                .split_whitespace()
                .find(|prefix| option.starts_with(prefix))
                .map(|prefix| (prefix, Form::Any))
        })
}

/// The name of `option` in the first of `lists` that knows it, and the form
/// NAILS reads it in.
fn find(lists: &[&List], option: &str) -> Option<(&'static str, Form)> {
    lists.iter().find_map(|list| in_list(list, option))
}

/// The name of `option` that a finding may show: the part before its first
/// `=`, never its value, which can hold a password.
fn name_of(option: &str) -> String {
    option
        .split_once('=')
        .map_or(option, |(name, _)| name)
        .to_string()
}

/// Whether the value `value` of an option NAILS does not know may name a
/// path or a device: one that is absolute, a tag, or that holds a `/` or a
/// `:`, as a relative path with folders, a `driver:param` form such as
/// `cmd:/bin/prog`, or a device by its `major:minor` does.
pub(super) fn may_name_a_path(value: &str) -> bool {
    value.contains(['/', ':'])
        || ["UUID=", "LABEL=", "PARTUUID=", "PARTLABEL=", "ID="]
            .iter()
            .any(|tag| value.starts_with(tag))
}

/// Why `option`, which NAILS knows as `name` in `form`, is not read in the
/// form the line gives it: nothing for a form NAILS reads.
fn unread_form(name: &'static str, form: Form, option: &str) -> Option<Unplain> {
    let value = option_named(option, name).flatten();
    let read = match form {
        Form::Any | Form::Reads(Reading::KeyLike) => true,
        Form::Flag => value.is_none(),
        Form::Valued => {
            return value
                .is_none_or(str::is_empty)
                .then_some(Unplain::NoValue(name));
        }
        Form::LocalFs => match value {
            None => true,
            Some("") => return Some(Unplain::NoValue(name)),
            Some(unit) => unit == "local-fs.target",
        },
        Form::Reads(reading) => match value {
            None | Some("") => return Some(Unplain::NoValue(name)),
            Some(value) => reads_in_form(reading, value),
        },
    };
    (!read).then(|| Unplain::Unread(name_of(option)))
}

/// Whether `value`, of an option that names a path or a device read as
/// `reading`, is in a form NAILS reads.
fn reads_in_form(reading: Reading, value: &str) -> bool {
    match reading {
        Reading::Path => value.starts_with('/'),
        Reading::Paths => value.split(':').all(|part| part.starts_with('/')),
        Reading::AutoOrPath => value == "auto" || value.starts_with('/'),
        Reading::Number => device_number(value).is_some(),
        Reading::KeyLike => true,
    }
}

/// The device a number names, as the kernel reads it with `kstrtouint(…,
/// 0)` and `new_decode_dev()`: decimal, `0x` hexadecimal or `0` octal, as
/// `major:minor`. `None` for anything else.
pub(super) fn device_number(value: &str) -> Option<String> {
    let (digits, radix) = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        (hex, 16)
    } else if value.len() > 1 && value.starts_with('0') {
        (&value[1..], 8)
    } else {
        (value, 10)
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    let dev = u32::from_str_radix(digits, radix).ok()?;
    let major = (dev & 0xfff00) >> 8;
    let minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
    Some(format!("{major}:{minor}"))
}

/// Whether NAILS reads every option of the fstab line `entry`: the claims
/// count it, and its first field names local storage (see the module
/// docs).
pub(super) fn reads_every_option(entry: &FstabEntry) -> bool {
    is_claimed(entry) && !takes_a_remote_source_line(entry)
}

/// The lists the options of the fstab line `entry` are read by: its type's,
/// then the generic one.
fn fstab_lists(entry: &FstabEntry) -> [&'static List; 2] {
    [of_type(&entry.vfstype), &GENERIC]
}

/// Why the options of the fstab line `entry` make a line that is not plain
/// (see the module docs): nothing for a line whose options NAILS reads. Of a
/// line NAILS does not read every option of, only those that name a path or a
/// device count: an option it knows that names one in a form it does not
/// read, and one it does not know whose value may name one.
pub(super) fn unread_fstab(entry: &FstabEntry) -> Vec<Unplain> {
    let every = reads_every_option(entry);
    let lists = fstab_lists(entry);
    let mut why: Vec<Unplain> = Vec::new();
    for option in entry.options.iter().filter(|option| !option.is_empty()) {
        let reason = match find(&lists, option) {
            Some((name, form)) if every || matches!(form, Form::Reads(_)) => {
                unread_form(name, form, option)
            }
            Some(_) => None,
            None if every => Some(Unplain::Unknown(name_of(option))),
            None => option
                .split_once('=')
                .is_some_and(|(_, value)| may_name_a_path(value))
                .then(|| Unplain::Unknown(name_of(option))),
        };
        if let Some(reason) = reason.filter(|reason| !why.contains(reason)) {
            why.push(reason);
        }
    }
    why
}

/// Why the options of the crypttab line `entry` make a line that is not
/// plain (see the module docs), but for `keyscript=`, which the `reads`
/// module tells: nothing for a line whose options NAILS reads.
pub(super) fn unread_crypttab(entry: &CrypttabEntry) -> Vec<Unplain> {
    let mut why: Vec<Unplain> = Vec::new();
    for option in entry.options.iter().filter(|option| !option.is_empty()) {
        if option_named(option, "keyscript").is_some() {
            continue;
        }
        let reason = match find(&[&CRYPTTAB], option) {
            Some((name, form)) => unread_form(name, form, option),
            None => Some(Unplain::Unknown(name_of(option))),
        };
        if let Some(reason) = reason.filter(|reason| !why.contains(reason)) {
            why.push(reason);
        }
    }
    why
}

/// Whether NAILS knows every option of the fstab line `entry`, each in a
/// form it reads, whether or not it reads every option of that line: the
/// claims count a line as one the boot does not mount only then.
pub(super) fn reads_every_known(entry: &FstabEntry) -> bool {
    let lists = fstab_lists(entry);
    entry
        .options
        .iter()
        .filter(|option| !option.is_empty())
        .all(|option| {
            find(&lists, option)
                .is_some_and(|(name, form)| unread_form(name, form, option).is_none())
        })
}

/// Whether NAILS knows every option of the crypttab line `entry`, each in a
/// form it reads, `keyscript=` not among them: the claims count a line as one
/// the boot does not open only then.
pub(super) fn reads_every_known_crypttab(entry: &CrypttabEntry) -> bool {
    unread_crypttab(entry).is_empty()
        && !entry
            .options
            .iter()
            .any(|option| option_named(option, "keyscript").is_some())
}

/// The options of the fstab line `entry` whose value names a path or a
/// device in a form NAILS reads, each with its name, how it is read and its
/// value.
pub(super) fn fstab_option_reads(entry: &FstabEntry) -> Vec<(&'static str, Reading, &str)> {
    reads_of(&fstab_lists(entry), &entry.options)
}

/// The options of the crypttab line `entry` whose value names a path or a
/// device in a form NAILS reads, each with its name, how it is read and its
/// value.
pub(super) fn crypttab_option_reads(entry: &CrypttabEntry) -> Vec<(&'static str, Reading, &str)> {
    reads_of(&[&CRYPTTAB], &entry.options)
}

fn reads_of<'a>(lists: &[&List], options: &'a [String]) -> Vec<(&'static str, Reading, &'a str)> {
    options
        .iter()
        .filter_map(|option| {
            let (name, form) = find(lists, option)?;
            let Form::Reads(reading) = form else {
                return None;
            };
            let value = option_named(option, name).flatten()?;
            reads_in_form(reading, value).then_some((name, reading, value))
        })
        .collect()
}
