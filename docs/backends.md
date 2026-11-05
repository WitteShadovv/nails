# Storage backends

NAILS never unlocks, mounts or encrypts storage. It needs a filesystem that is
already mounted and writable at `hidden_volume_root`, and it keeps the upper of
the hidden root (one overlay over the whole decoy root) there. Which backend provides that filesystem
changes what an adversary with one or more disk images can learn, so this page
lists what has been tested, what every backend must provide, and the
deniability trade-offs of each supported backend.

The examples use the neutral mapping name `data` and the hidden root
`/mnt/data`. Substitute your own, and keep the mapping name and mount point
free of anything that hints at hidden storage: they surface in `/dev/mapper`,
generated mount unit names and the journal. Give the filesystem no label at all
(`mkfs.ext4` sets none unless you pass `-L`): even a neutral one shows in
`/dev/disk/by-label`, in systemd's device units, in file managers and in
`lsblk`, and the `hidden-volume` check warns about any.

## Support matrix

| Status | Backend | Evidence |
|---|---|---|
| **Tested** | LUKS2 + ext4 on a whole block device | Every E2E run: `nix/e2e-tests/lib/hidden-volume.nix` formats a dedicated virtual disk with `cryptsetup luksFormat`, opens it and creates ext4 inside. |
| **Tested** | VeraCrypt hidden volume, opened with `cryptsetup open --type tcrypt --tcrypt-hidden`, ext4 inside | The VeraCrypt VM test in `nix/e2e-tests/tests/backends/` creates an outer and a hidden VeraCrypt volume with the `veracrypt` console tool, opens the hidden one with `cryptsetup`, runs a session over it and images the decoy root. It runs in every E2E run that rebuilds the tests (each pull request that changes the code, each push to `main`) and nightly. The whole configuration on real hardware was evaluated by hand once. |
| **Tested** | A directory on a separate local disk, bind-mounted at the hidden root | The `bind-mounted-root` VM test: an ext4 disk that the decoy does not mount or list in its fstab, with a directory of it bound at `/mnt/data`. A bind of a folder of a filesystem the decoy uses is refused (see below). |
| **Refused** | A folder; a btrfs subvolume or a bind mount of a filesystem the decoy uses; the filesystem the decoy's fstab mounts; a logical volume, a device-mapper mapping, an md array or a loop device stacked on the decoy's storage or swap; an unencrypted image file on a decoy filesystem; a network block device (`nbd`) or a userspace block device (`ublk`), whole or partitioned, anything stacked on one, and a filesystem that keeps its log, journal or another of its devices on one | Not storage of its own: everything written there lands on the decoy's disk. A program serves an `nbd` or `ublk` device, and nothing on this computer shows where it keeps the data, which can be an image file on the decoy's disk. Refused by the attach gate before anything is written (see [the attach gate](threat-model.md#the-attach-gate)); the `preflight-decoy-filesystem` VM test covers the folder, subvolume, bind, image-file, fstab-filesystem and `nbd` cases, an XFS log and an ext4 journal on `nbd` among them. A folder is always refused; `--allow-decoy-storage` turns the other refusals into a warning, for storage you know the decoy does not use, or an `nbd` or `ublk` device you know is served from storage it does not use. A session on such a device also needs its server and connection to survive the soft-reboots, which stop every userspace daemon. |
| **Expected to work** | Any local Linux filesystem that passes the preflight probes (ext4, xfs, btrfs, f2fs) on any other kernel block device, including iSCSI devices | Untested. The preflight probes decide. Network traffic to a remote block device is outside the host-side threat model, and the connection must survive the soft-reboots, which stop every userspace daemon (an iSCSI client among them). |
| **Unsupported** | NFS, CIFS/SMB, sshfs, 9p, overlays, FUSE filesystems, ZFS datasets and ZFS volumes as the hidden root; FAT, exFAT, NTFS | The attach gate refuses a filesystem that shows no disk it stores its data on (`storage_unjudged`), since where its writes land cannot be told. A ZFS dataset is one: its mount names only its pool, and the gate does not read which disks the pool is on. An image file on such a filesystem is refused the same way, unless the decoy mounts that filesystem at `/` or one of its system folders (`/home`, `/var` and the like) or lists it in its fstab; there an encrypted container only warns, as on a decoy filesystem on an ordinary disk. A ZFS volume (a zvol, `/dev/zd*`) keeps its data in its pool too, so a hidden root on one is refused the same way, whether its filesystem is on the volume itself, on a partition of it or on anything stacked on it, and so is one whose data reaches such a volume any other way: in an image file on a filesystem on it, through a log, journal or other device its filesystem keeps on it, or on a filesystem of the decoy's on it, a bind of a folder of one or the one its fstab mounts at the root included. `--allow-decoy-storage` lifts none of these. A ZFS dataset the decoy mounts elsewhere, or a bind of a folder of one, is refused as the decoy's filesystem instead (see above), which the flag does lift. One its fstab mounts at the root is refused as storage that cannot be judged. FAT, exFAT and NTFS cannot host an overlayfs upper layer and are refused by the `upper-fs-capability` preflight check. |
| **Unsupported** | A VeraCrypt volume made with Argon2id ("Argon2" in the KDF list of VeraCrypt 1.26.29 and newer) | No cryptsetup release can open it yet, so cryptsetup on the decoy cannot unlock it. See [VeraCrypt volumes made with Argon2id](#veracrypt-volumes-made-with-argon2id). |
| **Not evaluated** | Shufflecake; volumes mounted by the VeraCrypt application itself | No claims. `backend-detect` names a Shufflecake (`sflc_<dev>_<vol>`) volume and a mapping the VeraCrypt application made (`veracrypt<N>`) in its summary, but no Shufflecake-specific hazards are checked. A cross-backend E2E matrix is not part of the suite yet. |

## Requirements for the hidden root

Whatever the backend, the filesystem at the hidden root must:

- **be storage of its own**, mounted and writable at `hidden_volume_root`
  (preflight check `hidden-volume`, which asks the attach gate): a mount point,
  with no second filesystem mounted over it, on no storage the decoy uses (see
  [the attach gate](threat-model.md#the-attach-gate)). An encrypted container
  file on a filesystem the decoy uses is accepted with a warning: that
  filesystem's journal and copy-on-write snapshots (btrfs, snapper) can keep old
  copies of the parts of the container that changed, so a whole device or a
  partition the decoy does not use is better. Where that filesystem lies on an
  `nbd` or `ublk` device the container is refused, which the override lifts,
  and where it lies on a ZFS volume it is refused outright. Only root can read
  the loop device's record of where the container file lives, so run `init` and
  `check` on a root in a file container with sudo: unprivileged they refuse it
  with `storage_unjudged` (and `status` and `verify` log to stderr only). `--allow-decoy-storage` accepts the
  decoy's storage, or an `nbd` or `ublk` device you know is served from
  elsewhere, with a warning, never a folder;
- **support symbolic links** (`symlink-support`);
- **support `trusted.*` xattrs, report a file type (`d_type`) from readdir, and
  store overlayfs whiteouts** (`upper-fs-capability`). The check proves this
  before the session is touched: in a throwaway `.probe-*` directory on the
  hidden root it sets and removes a trusted xattr, reads directory entry types
  and tries a small overlay that it exercises with a new file and a whiteout,
  then removes the directory. The overlay is mounted detached, so no mount
  table lists it and it is gone when the probe ends; without root, or on a
  kernel that cannot mount it that way, the check fails before it writes
  anything (see
  [What `check` touches](operator-guide.md#what-check-touches)). On failure it
  names the detected filesystem type;
- **keep every overlay upper and its work directory on one filesystem**.
  overlayfs refuses an upper and work directory on different filesystems.
  NAILS keeps both under the hidden root (`<root>/root/upper` and
  `<root>/root/work`, and `<root>/root/mounts/<path>/` for each other decoy
  filesystem it overlays), so do not mount another filesystem inside the hidden
  root;
- **be kernel-managed** (dm-crypt, a loop device). Activation soft-reboots:
  every userspace process stops, so a FUSE mount backed by a process dies at the
  switch. A kernel mount survives it: the decoy's shutdown unmounts the hidden
  volume's own mount unit, but the bind NAILS places inside the next root keeps
  it alive, and it appears at the same path in the hidden session;
- **lie on a partition whose type systemd leaves alone**, when it is on a
  disk the decoy boots from (`backend-partition-type`): the generic Linux
  type, never that of a `/home`, `/srv`, `/var`, `/var/tmp` or swap
  partition, even on a decoy that masks the systemd generator that acts on
  those (see [Partition type in preflight](#partition-type-in-preflight)).

`sudo /mnt/data/nails check` (or `activate --dry-run`) prints every preflight
result, including the backend detection below.

## Backend detection in preflight

The `backend-detect` check identifies the device stack under the hidden root.
Discards over the hidden volume fail activation closed (a stack that rests on
RAM-only `zram` devices alone is excepted); the other findings only warn. It
reads `/proc/self/mountinfo` to find the hidden root's device, follows the
device-mapper layers in `/sys`, and the device behind a loop over a block
device (a loop over a file is a file container, whose filesystem it does not
follow), and reports:

| Finding | Detected from | What to do |
|---|---|---|
| **Refuses:** discards are enabled over the hidden volume | a cryptsetup mapping (`dm/uuid` starts with `CRYPT-`) or a mapping the VeraCrypt application made has a non-zero `queue/discard_max_bytes`, or its LUKS2 header `config.flags` holds `allow-discards`; a stack whose bottom devices are all RAM-only `zram` devices is excepted, but not one that also rests on a disk (a logical volume cached on `zram`, say), nor one whose devices the check could not all read (it reads at most 16) | Re-open the hidden volume without discards. For a stored LUKS2 flag, run `cryptsetup refresh --persistent <name>` without `--allow-discards`, then check `cryptsetup luksDump` reports `(no flags)`. To accept the risk for one run instead, pass `nails activate --allow-discards`, a NAILS flag distinct from cryptsetup's that only the long help (`--help`) lists. See [Discards](#discards-trim). |
| The hidden root lives in a file container | A loop device in the stack has a `loop/backing_file` that is a regular file | Accept the [timestamp exposure](#timestamps) or move to a whole-device hidden volume. |
| The container sits on a copy-on-write filesystem | The container file's filesystem is btrfs, zfs or bcachefs | Prefer a whole-device hidden volume; at least disable automatic snapshots of that filesystem. |
| The loop device is backed by a file on a FUSE mount | The backing file's filesystem is `fuse.*` (for example the VeraCrypt application without kernel crypto) | The attach gate already refuses such a root (`storage_unjudged`) before the check runs. Open the volume with cryptsetup so the kernel manages the mapping. |
| The LUKS2 header carries a `systemd-tpm2`, `systemd-fido2` or `systemd-pkcs11` token | `tokens.*.type` in the LUKS2 JSON header | The token names the unlock method in plain text, and a TPM2 token seals the key to this machine's TPM, binding the volume to the host. Remove it with `systemd-cryptenroll --wipe-slot` or `cryptsetup token remove` if the volume must not point at this machine. |
| The device below a LUKS mapping keeps a LUKS header the mapping was not opened with | The device starts with a LUKS header whose uuid is not the one the mapping names (cryptsetup writes the volume's uuid into `dm/uuid`); or, for a mapping opened with a detached header, the device holds a LUKS2 secondary header at one of the offsets cryptsetup puts one at, 16 KiB to 4 MiB in | blkid and an examiner identify the device as LUKS. See [Leftover LUKS headers](#leftover-luks-headers). |
| A loop device over a block device was attached without autoclear | `loop/autoclear` is `0` for a loop device whose `loop/backing_file` is a block device | It stays bound after the volume is closed, after a session too, so `losetup -a` on the decoy names it. Detach it with `losetup -d` once the volume is closed. |

The check reads the start of the device below each LUKS mapping read-only and
without changing its access time, which needs root: a LUKS1 or LUKS2 header,
its uuid, and for LUKS2 the flags and tokens `cryptsetup luksDump` prints. The
mapping's own header, the one whose uuid the mapping names, shows anyone who
reads the disk that an encrypted volume is there, and the pass line says so. A
device that starts with no LUKS header belongs to a mapping opened with a
detached header, which the description names; the flags and tokens of such a
header are in its file. An unreadable device leaves the description as it is.
A mapping the VeraCrypt application made (`veracrypt<N>`, with no uuid) is
named as such, the further cipher layers of a cascade cryptsetup opened
(`SUBDEV`) as cascade layers, and dm-integrity and dm-verity mappings as
mappings that encrypt nothing. cryptsetup also builds sub-devices of its own
below a LUKS2 volume, of the type `SUBDEV` too but with the volume's uuid,
which no cascade layer carries: from cryptsetup 2.8 on, the integrity layer of
a volume with authenticated encryption (`luksFormat --integrity`), which it
names `<name>_dif`, and, while `cryptsetup reencrypt` runs on the open volume,
an overlay that holds the volume's segments and a hotzone (`<name>-overlay`,
`<name>-hotzone-forward` or `-backward`). The check names the `_dif` one a
dm-integrity mapping and the others LUKS2 sub-devices, and reads the volume's
header from the device below them, where cryptsetup keeps it. A LUKS mapping
on a whole device, a Shufflecake volume, or anything the check cannot
identify, passes with a one-line description of the stack. A hidden root that
is not a mount point is skipped, and so is one on a filesystem the decoy uses
(a bind of one of its folders, a btrfs subvolume of it, or the filesystem
itself), whose stack is the decoy's: the `hidden-volume` check reports either.
Discards over the stack of such a filesystem, which keeps the hidden root's
data, are refused all the same.

### Leftover LUKS headers

A volume opened with a detached header (`cryptsetup luksFormat --header
<file>`) leaves its device without a LUKS signature only when nothing of an
earlier header is there. If the device held a LUKS volume before, that
volume's primary header, at the start, or its LUKS2 secondary header, 16 KiB to
4 MiB in, can be left over, and `backend-detect` warns. What may be
overwritten depends on where the current volume keeps its data:
`cryptsetup luksDump <header file>` lists its data segment and the offset it
starts at. Only the bytes before that offset hold nothing of the volume, so a
leftover there can be overwritten with random data, from where setup happens.
A leftover past that offset lies inside the volume's data, and only making the
volume again, its files copied off and back, removes it. NAILS never writes to
the device.

## Encryption in preflight

The `backend-encryption` check asks whether the hidden root's storage has
encryption of its own. It only warns. It starts from every device of the
hidden root's filesystem (each device of a btrfs filesystem, and each one a
bcachefs filesystem names in its source) and walks the device stack under
each as `backend-detect` does, going on further:

- from a partition into its disk, when that disk keeps its data elsewhere: a
  loop or device-mapper device, or a disk built on others, such as an md
  array;
- into the device behind a loop over a block device;
- for a loop over a file, into every device of the filesystem that the loop
  driver recorded for the file. Reading that record needs root; without it
  the check goes by the file's path. A path that leads to another filesystem
  than the record, as after a mount over the file's folder, ends that way in
  doubt.

Each way down to a device at the bottom of the stack has to pass an
encrypting layer that is not the decoy's own. That rules out the decoy's
storage as the attach gate counts it (the filesystems at `/` and at the
system folders, every `/etc/fstab` entry and every `/etc/crypttab` volume, see
[the attach gate](threat-model.md#the-attach-gate)), and, for a partition of
it on a disk that keeps its data elsewhere, such as an md array, that disk and
every device below it: the devices of the array the decoy's root lies on are
the decoy's, as its boot opens them. It also rules out a volume opened, under
any name, from a device or an image file the decoy's crypttab opens, except a
line for the hidden drive itself (one that opens it or a device it is stored
on): that line is no claim, and `backend-entries` refuses it. So a logical
volume spread over an encrypted and a plain disk, a mirror with one plain disk,
or a btrfs filesystem with one plain device warns about the plain disk.

| Result | When |
|---|---|
| Passes | Each way down passes a layer that is not the decoy's: a cryptsetup mapping of type TCRYPT, LUKS1, LUKS2, PLAIN, LOOPAES, BITLK or FVAULT2 (`dm/uuid` starts with `CRYPT-<type>-`), a SUBDEV mapping (cryptsetup's name for the layers it puts below such a mapping, such as the further ciphers of a VeraCrypt cascade), or a mapping named as the VeraCrypt application names its own (`veracrypt<N>`, with no uuid). |
| Warns: nothing encrypts it | A way down reaches a device, which the warning names, with no encrypting layer above it. Anyone who reads that device, or a copy of it, reads the hidden root's files. dm-integrity and dm-verity encrypt nothing. |
| Warns: only the decoy's own encryption | The only encryption on a way down is a layer of the decoy's own storage, such as the LUKS volume under its `/home` for an image file kept there, the LUKS devices of the md array its root lies on for another partition of that array, or a volume the decoy's crypttab opens, from a device or an image file, that was opened under another name. Whoever unlocks the decoy reads the hidden root's files, and the threat model counts on an adversary who gets the decoy's credentials (see [Compelled disclosure of the decoy](threat-model.md#compelled-disclosure-of-the-decoy)). |
| Warns: encryption cannot be confirmed | A way down passes a device-mapper device of a kind the check does not know, a cryptsetup type it does not know, a loop device whose file it cannot follow to a disk, whose path and recorded filesystem disagree or whose recorded filesystem is not mounted here, or a ZFS volume, a network block device (`nbd`), a userspace block device (`ublk`) or a `zram` device, which keep their data where sysfs does not show; or the stack holds more devices than the check reads (16 below any one device, 64 in all); or the filesystem shows no block device at all, as a ZFS dataset or a network filesystem. A pass also needs `/etc/fstab` and `/etc/crypttab` read, since either may name the encryption found as the decoy's. |
| Warns: in RAM | The hidden root is a tmpfs or ramfs. Nothing on it survives a power-off or a reboot, so it serves to try NAILS out, not to keep a hidden environment. |

The check knows a mapping by its device-mapper uuid and name, as cryptsetup
and the VeraCrypt application set them. It never reads a mapping's table,
which holds the key of a crypt mapping, so a mapping made by hand with
`dmsetup` under such a uuid or name passes as well, whatever its table does.

The check confirms encryption, not deniability. A LUKS header shows that an
encrypted volume exists, and whether a VeraCrypt hidden volume can be told
from the free space of its outer volume depends on how it is used (see
[Deniability hazards](#deniability-hazards)).

## Outer volume in preflight

A VeraCrypt hidden volume lies in the free space of its outer volume, so a
write to the outer volume can land on the hidden one. VeraCrypt guards against
that only with its hidden-volume protection, which cryptsetup does not offer
and which the VeraCrypt application applies only through FUSE. The
`outer-volume` check warns, and never fails, when another VeraCrypt or
TrueCrypt mapping of the storage the hidden root's volume is opened from is
open read-write beside it.

For each TCRYPT, SUBDEV or VeraCrypt mapping of the hidden root's stack, the
check takes the device below it and the devices that hold the same data: a
loop device over that device, and, where that device is itself a loop device,
the device or file behind it with every other loop device over it (over a
file, only those that read it from the same offset). A TCRYPT, SUBDEV or
VeraCrypt mapping built on any of them that is no part of the hidden root's
stack is another mapping of the volume, most likely its outer volume. A
SUBDEV mapping whose uuid names a volume uuid is a LUKS2 volume's own
sub-device, such as its integrity layer or a device of its online
reencryption, not part of a VeraCrypt or TrueCrypt volume, and counts as
neither.

| Result | When |
|---|---|
| Warns | Such a mapping is writable: the kernel does not hold it read-only (`ro` is `0`). The warning names its topmost mapping (`outer (dm-4)`), the device it is opened from and where it is mounted, read-write or read-only. A mapping the VeraCrypt application made stays writable even when the application mounted the volume read-only. |
| Warns: cannot check | The mount table cannot be read, the hidden root's filesystem shows no block device, or sysfs does not let the check list the devices below the hidden root, or those built on its storage (`slaves/`, `holders/`, `/sys/class/block`). |
| Passes | Every such mapping is read-only, as `cryptsetup open --readonly` makes it; there is none; or the hidden root is in no VeraCrypt or TrueCrypt volume. |

Close the outer volume before activating, or open it with
`cryptsetup open --readonly` when it has to be shown. The check reads sysfs
and the mount table only, never a mapping's table. It does not see a volume
the VeraCrypt application opened through FUSE (as it does with hidden-volume
protection), which holds no kernel link to the device, nor a mapping of
another kind over the same device.

## Partition type in preflight

systemd-gpt-auto-generator runs at every boot, unless it is masked, and looks
at the partitions of the disk the root file system is on. By a partition's GPT
type alone it mounts the first partition of the `/home`, `/srv`, `/var` or
`/var/tmp` type at that folder, when no fstab line mounts the folder and the
folder is empty (`/var` only when the partition's uuid is the one the machine
ID gives it); it uses the first partition of the swap type as swap, unless an
fstab line names a swap; and it asks for the passphrase first when such a
partition is a LUKS volume. It leaves a partition with the no-auto flag (bit
63 of its attributes) alone, and the next one of its type is then the first.
Where the generator runs, a hidden volume on a partition of one of these types
shows itself at the decoy's next boot: a failed mount, a failed swap or a
passphrase prompt for a partition the decoy knows nothing of. Nothing of this
happens in the hidden session, whose root is an overlay, which the generator
does not act on, but the type stays in the partition table for anyone who
reads it.

Ubuntu 24.04 and 26.04 mask the generator by default: their systemd package
links `/etc/systemd/system-generators/systemd-gpt-auto-generator` to
`/dev/null`, and systemd runs no generator masked so (see
systemd.generator(7)). Debian 13 and NixOS do not mask it by default. On a
decoy that masks it, a partition of these types shows nothing at boot, but
its type is in the partition table all the same.

The generator acts on three more types under some conditions. It mounts the
first extended boot loader partition of the disk at `/boot`, and the first EFI
system partition at `/boot` or `/efi`, on first access, when no fstab line
mounts that folder and the folder is empty or missing. It leaves the EFI
system partition alone when an fstab line names that partition, at any folder
from systemd 255 on, and in 254 only at `/boot`, when `/boot` exists and the
disk has no extended boot loader partition. From systemd 256 on, it mounts
neither when an fstab line mounts anything at or below `/boot` or `/efi`, such
as `/boot/efi`, where 254 and 255 look at lines for `/boot` and `/efi`
themselves, not below them. So on 254 and 255 a `/boot/efi` line for another
partition does not keep the first EFI system partition from `/efi`. On a UEFI
boot the generator mounts them only when the boot loader says it started from
that disk, but on a BIOS boot it skips that condition: there the first EFI
system partition gets an automount whenever one of the two folders meets the
conditions above, as `/efi` usually does. At boot, when the kernel command
line names no root, it takes a root partition from the disk of the EFI system
partition the boot loader started from.

The `backend-partition-type` check follows the hidden root's own storage
(through device-mapper layers and loops over block devices, never into the
filesystem that holds a container file) and judges each of its partitions on a
disk the decoy boots from: a disk below its root file system, or below the
filesystem mounted at `/boot`, `/boot/efi` or `/efi`. It reads the disk's
partition table read-only and without changing an access time, and finds the
partition's entry by its number and its start. Without root, where the disk
cannot be read, it takes the entry from udev's record of the partition. A
partition the decoy uses itself is left to the `hidden-volume` check.

| Result | When |
|---|---|
| Refuses | The partition has the GPT type of a `/home`, `/srv`, `/var`, `/var/tmp` or swap partition. A swap partition is refused with the no-auto flag too, though systemd leaves it alone then. |
| Warns | The partition has one of the first four types with the no-auto flag, which systemd honours; or the type of a root, EFI system or extended boot loader partition, which systemd acts on only under the conditions above; or the table does not list the partition where the kernel has it, or is damaged: its header or its entries do not match the checksums it keeps, not every entry could be checked against them, or an entry does not fit within the blocks its partitions may use; or neither the disk nor udev's record of the partition could be read. |
| Passes | Any other type, an MBR, or no partition of a disk the decoy boots from: a disk of its own such as an external drive, a container file, a RAM filesystem. |

The fix is the generic Linux type, given from a live system or where setup
happens, never on the decoy:
`sgdisk --typecode=<number>:0FC63DAF-8483-4772-8E79-3D69D8477DE4 <disk>`, with
the number and the disk the check names, by its `/dev/disk/by-id` link where
there is one. Retyping changes the partition table, not the data on the
partition. The check does not predict the generator in every detail: it does
not ask whether the partition is the first of its type on the disk, whether the
folder is empty, whether the root lies on several disks, where the generator
does nothing, whether the kernel command line turns the generator off
(`systemd.gpt_auto=0`), or whether the decoy masks it, as Ubuntu 24.04 and
26.04 do by default. It judges each of those cases the same, as the type
shows in the partition table either way.

## Per-backend summary

| | VeraCrypt file container | VeraCrypt device | LUKS2 |
|---|---|---|---|
| **Unlock** | `cryptsetup open --type tcrypt --veracrypt --tcrypt-hidden <file> data` | `cryptsetup open --type tcrypt --veracrypt --tcrypt-hidden /dev/sdX2 data` | `cryptsetup open /dev/sdX2 data` |
| **Discards** | Never. Destroys or exposes the hidden volume | Never. Destroys or exposes the hidden volume | Keep off. Leaks the used/free layout; check that no persistent flag is stored |
| **Timestamps** | mtime and ctime change every read-write session; ctime cannot be restored | No decoy-side file timestamps | No decoy-side file timestamps |
| **Host traces** | Loop device, container timestamps, plus the common traces | Device-mapper device, plus the common traces | A visible LUKS2 header unless the header is detached, plus the common traces |
| **Lock** | `umount`, then `cryptsetup close` (also frees the loop device cryptsetup attached) | `umount`, then `cryptsetup close` | `umount`, then `cryptsetup close` |

Prefer cryptsetup over the VeraCrypt application for both VeraCrypt layouts:
cryptsetup creates a plain kernel dm-crypt mapping with no userspace process
behind it, which is what the kernel-managed requirement above needs.

### VeraCrypt hidden volume in a file container

```bash
sudo cryptsetup open --type tcrypt --veracrypt --tcrypt-hidden \
  /path/to/container data
sudo mount /dev/mapper/data /mnt/data
```

cryptsetup attaches the container to a free loop device itself. Run
`nails init` and `nails check` on such a root with sudo: the attach gate reads
the loop device's record of the container's filesystem, which only root can
read.

- **Discard policy:** never pass `--allow-discards`, neither for the hidden
  volume nor for the outer volume. See [Discards](#discards-trim).
- **Timestamp behaviour:** writes through the loop device update the container
  file's mtime and ctime in every read-write session. `touch` can set mtime
  back, but that sets ctime to the current time, and ctime cannot be set from
  userspace. The container therefore shows when it was last used. See
  [Timestamps](#timestamps).
- **Host traces:** the common traces below, a loop device bound to the
  container while it is open, and the container's timestamps. Opening the
  container from a file manager can add it to the desktop's recent-files list.
- **Lock sequence:** `sudo umount /mnt/data`, then
  `sudo cryptsetup close data`. Closing also detaches the loop device
  cryptsetup attached; one you attached yourself with `losetup` needs
  `sudo losetup -d /dev/loopN`. `losetup -a` must not list the container
  afterwards.
- **Version advisory:** creating a hidden volume in a file container with
  VeraCrypt 1.26.6 through 1.26.28 could write plaintext zero sectors at
  128 MiB intervals where random-looking data should be
  ([GHSA-jjcr-75w7-58jp](https://github.com/veracrypt/VeraCrypt/security/advisories/GHSA-jjcr-75w7-58jp)).
  1.26.29 stops writing them, but upgrading VeraCrypt does not remove those
  already in a container. VeraCrypt's
  [release notes](https://veracrypt.jp/en/Release%20Notes.html) say that if
  you rely on plausible deniability, you should recreate the affected outer
  container and its hidden volume with 1.26.29 or later, then securely erase
  the old container. Make the new container away from the decoy, as in
  [Where setup happens](operator-guide.md#where-setup-happens), and copy the
  data from the old hidden volume straight into the new one, never through the
  decoy's disk. On an SSD or a copy-on-write filesystem, erasing the old
  container can leave copies of it behind; see
  [Copy-on-write, journaling and SSD remnants](#copy-on-write-journaling-and-ssd-remnants).

### VeraCrypt hidden volume on a whole device

```bash
sudo cryptsetup open --type tcrypt --veracrypt --tcrypt-hidden /dev/sdX2 data
sudo mount /dev/mapper/data /mnt/data
```

A partition or a whole disk created by VeraCrypt holds the outer and hidden
volumes directly. There is no loop device and no container file whose
timestamps change. A partition on a disk the decoy boots from needs the
generic Linux type, which `backend-partition-type` checks (see
[Partition type in preflight](#partition-type-in-preflight)).

- **Discard policy:** never pass `--allow-discards`, neither for the hidden
  volume nor for the outer volume. See [Discards](#discards-trim).
- **Timestamp behaviour:** nothing on the decoy filesystem records use of the
  device. The filesystems inside carry their own timestamps, visible only
  after unlocking.
- **Host traces:** the common traces below. The partition shows up as random
  data, which the outer volume is there to explain.
- **Lock sequence:** `sudo umount /mnt/data`, then
  `sudo cryptsetup close data`.

Both VeraCrypt layouts: cryptsetup cannot open an outer volume with
VeraCrypt's hidden-volume protection, so writing to an outer volume opened by
cryptsetup can overwrite the hidden volume. Open the outer volume with
`--readonly` when you only need to show it, and refresh decoy content in the
outer volume with the VeraCrypt application and its hidden-volume protection.
The `outer-volume` check warns while another mapping of the volume is open
read-write beside the hidden one (see
[Outer volume in preflight](#outer-volume-in-preflight)).

VeraCrypt's own [Security Requirements for Hidden Volumes](https://veracrypt.jp/en/Security%20Requirements%20for%20Hidden%20Volumes.html)
go further for Linux: mount a hidden volume only while a live system runs whose
writes to its system volume go to a RAM disk, with every filesystem outside
hidden volumes mounted read-only or not at all. Whoever cannot do that, and
cannot ensure that the system writes nothing sensitive to other filesystems,
"must not mount or create hidden VeraCrypt volumes under Linux". A NAILS setup
does not meet that live-system condition. NAILS itself never unlocks or mounts
the volume: before every session you unlock the hidden volume with cryptsetup
and mount it read-write on the running decoy, an installed system whose own
disk stays writable, which leaves the traces listed under
[Pre-activation residue](operator-guide.md#pre-activation-residue). A live
system such as Tails comes in only for the setup and the first install
([First install from Tails](install-from-tails.md)); every session starts on
the decoy. Weigh that against VeraCrypt's rule for your own threat model.

### VeraCrypt volumes made with Argon2id

Checked on 2026-10-19. The versions below change; check them again when you
set up a volume.

VeraCrypt 1.26.29 (June 2026) can protect a volume's header with a key derived
by Argon2id instead of PBKDF2. Its volume wizard lists it as "Argon2" in the
KDF list ("KDF Algorithm" on Windows), after the PBKDF2 entries; the default
stays PBKDF2 with SHA-512.
No cryptsetup release can open a volume made with Argon2id. cryptsetup's
development branch gained the support in June 2026, but the newest release,
2.8.8 of September 2026, does not have it, and the decoys NAILS supports ship
that release or an older one:

| Decoy | cryptsetup |
|---|---|
| Ubuntu 24.04 | 2.7.0 |
| Debian 13 | 2.7.5 |
| Ubuntu 26.04 | 2.8.4 |
| NixOS 26.05 | 2.8.6 |
| NixOS unstable | 2.8.8 |

A Debian or Ubuntu release does not normally get a newer cryptsetup version
once it is out, so on Debian 13 and the Ubuntu LTS releases the limit is likely
to last for years after a cryptsetup release adds the support.
`sudo nails check` names the version a decoy has, in its `cryptsetup-argon2id`
row. It reads it from the package database (dpkg or pacman) or the NixOS store
path, never by running cryptsetup: running `cryptsetup --version` on the decoy
reads the binary and can stamp its access time, the trace described under
[Backend tooling and history](decoy-requirements.md#backend-tooling-and-history).
A check that is not running as root, or a host whose cryptsetup none of those
name (Fedora's rpm database among them), skips the note. Tails 7 is based on
Debian 13 and has its cryptsetup 2.7.5, so a
[first install from Tails](install-from-tails.md) needs PBKDF2 as well.

Opening such a volume fails without naming the cause:
`cryptsetup open --type tcrypt` prints
`No device header detected with this passphrase.`, the message it gives for a
mistyped password, and asks again. A VeraCrypt header is encrypted apart
from its 64-byte salt, so nothing outside the volume shows which algorithm it
uses, and neither cryptsetup nor NAILS can warn you.

- **Make both volumes with PBKDF2.** In VeraCrypt's wizard, keep the default
  KDF or choose any entry other than Argon2, for the hidden volume and for
  the outer volume: the decoy has to be able to open the outer volume when you
  show it.
- **Change a volume already made with Argon2id** on the separate machine.
  VeraCrypt's Volumes ▸ Set Header Key Derivation Algorithm, with any entry
  other than Argon2 chosen, re-encrypts the header with a key derived by
  PBKDF2 and leaves the data as it is. Given the hidden volume's password, it
  changes the hidden volume's header; given the outer volume's, the outer
  one's.

### LUKS2

```bash
sudo cryptsetup open /dev/sdX2 data
sudo mount /dev/mapper/data /mnt/data
```

This is the backend the E2E suite runs on.

- **Discard policy:** keep discards off. cryptsetup-open(8) warns that
  `--allow-discards` makes filesystem-level operations visible on the
  physical device, such as the filesystem type and used space. LUKS2 can
  store the flag in its header (`--persistent`) and then enables discards on
  every later open; the `backend-detect` check refuses activation while
  discards reach the hidden volume, whether from a runtime `--allow-discards`
  or a stored flag (by hand: `cryptsetup luksDump /dev/sdX2` must report
  `(no flags)` on its `Flags:` line).
- **Timestamp behaviour:** nothing on the decoy filesystem records use of the
  device. The LUKS2 header changes only when you run a management command
  (key slots, tokens, persistent flags).
- **Host traces:** the common traces below. A LUKS2 header announces an
  encrypted volume (`cryptsetup isLuks`, `blkid`), so deniability rests on
  that volume having a plausible reason to exist. A detached header
  (`cryptsetup luksFormat --header <file>`, kept on separate media and passed
  to `open` with `--header`) leaves the device without a signature; fill the
  device with random data before formatting so that used and unused areas
  look alike, which also overwrites any header an earlier volume left there
  (see [Leftover LUKS headers](#leftover-luks-headers)).
- **Lock sequence:** `sudo umount /mnt/data`, then
  `sudo cryptsetup close data`.

### Common host traces

Every backend leaves the same traces on the decoy side while you unlock it:

- **Shell history.** The unlock and mount commands name the tool, the mapping
  and, for a container, its path. Type them in a shell with history disabled;
  see [History off on the decoy](operator-guide.md#history-off-on-the-decoy).
- **The journal.** sudo logs every command line it runs, and the kernel and
  udev log the loop and device-mapper devices being created. Keep the journal
  volatile (journald `Storage=volatile`) or on impermanent storage.
- **Persistent configuration.** Never list the hidden volume in
  `/etc/crypttab`, `/etc/fstab` or the decoy NixOS configuration
  (`boot.initrd.luks.devices`, `fileSystems`). The `backend-entries`
  pre-flight check refuses activation while a crypttab or fstab line opens or
  mounts the hidden volume, or a device it is stored on; a line that opens only
  another volume on the same drive warns (see
  [crypttab and fstab](decoy-requirements.md#crypttab-and-fstab)).

`nails deactivate` and `nails emergency` close the hidden backend themselves:
before the soft-reboot back they mark its device-mapper stack for deferred
removal with `dmsetup`, which the `host-tools` pre-flight check requires for
such a backend, and the switch releases the last reference (the overlay that
held the hidden volume), so the kernel removes the mapping, and a loop device
set up with autoclear, at that moment. You do not run the lock sequence after a
session; you run it only when you unlocked the volume on the decoy without
activating, or for a backend that is not device-mapper based. A device they
cannot mark (the hidden session removed `dmsetup`, say) they name once the
soft-reboot is enqueued: it stays open after the switch until you power off.
Closing the mapping does not clear the key from RAM: dm-crypt wipes the master
key when a mapping is removed, but other copies (page cache, freed pages,
process memory) survive a soft-reboot and a warm reboot, unless the firmware
honours the TCG memory-overwrite request, and setting that request writes EFI
NVRAM. Use `nails deactivate --poweroff` or `nails emergency --poweroff` to
power off instead and let RAM decay.

## Deniability hazards

### Discards (TRIM)

A discard tells the device that a block is unused. Through dm-crypt it is
forwarded only when the mapping was opened with `--allow-discards`; without
that flag dm-crypt drops discards, so `fstrim`, a periodic fstrim timer or a
`discard` mount option cannot reach the device. That default is the only safe
setting for a volume that contains a hidden volume:

- **On the hidden volume,** discards turn its free blocks into zeroed or
  unmapped blocks inside what should be the outer volume's random-looking free
  space, which leaves a readable used/free map. In a loop-backed container
  they punch holes in the container file, which records the same map in the
  file's allocation.
- **On the outer volume,** its filesystem discards its own free space, and
  that free space is where the hidden volume lives. On an SSD or a
  loop-backed container the discarded blocks can read back as zeros, which
  destroys the hidden volume.

cryptsetup-open(8) documents both options involved: `--allow-discards` with
its warning that discards make filesystem-level operations visible on the
physical device, and `--tcrypt-hidden` for opening the hidden volume. To check
a mapping, `cryptsetup status data` lists `discards` under `flags` when they
are enabled, and `lsblk --discard` shows a non-zero `DISC-MAX`.

NAILS fails activation closed when it detects discards reaching the hidden
volume (the `backend-detect` check above). An operator who understands the
exposure can override that one refusal for a single run with NAILS's own
`nails activate --allow-discards` (mirrored by `nails check --allow-discards`),
an expert flag that turns the refusal into a warning. It is buried in the long
help: `--help` lists it, `-h` does not. It is not the same as cryptsetup's
open-time `--allow-discards` above: the cryptsetup option enables discards at
the mapping and remains the thing to avoid, while the NAILS flag never touches
the mapping and only accepts an already-enabled discard for that one
activation. It is a per-run flag, never stored in `nails.toml`; the safe fix is
still to re-open the volume with discards off.

### Timestamps

A file container is a regular file on the decoy filesystem. Every read-write
session updates its mtime and ctime, and reads can update its atime. A
container whose timestamps keep moving while nothing on the decoy explains it
points at use. Restoring mtime with `touch` sets ctime to the current time, and
ctime cannot be set from userspace. A whole-device hidden volume has no such
timestamps.

### Copy-on-write, journaling and SSD remnants

A container on a copy-on-write filesystem (btrfs, zfs, bcachefs) is not
rewritten in place: changed blocks land in new locations and the old versions
stay in free space, or in snapshots, until they are reused. A single disk image
then holds several versions of the container, and comparing them shows which
regions changed; changes inside what should be the outer volume's unused space
reveal the hidden volume. An SSD keeps old copies of remapped blocks the same
way, out of reach of the operating system, and an adversary who images the
disk more than once can compare the images directly. A journaling filesystem
can also keep copies of recently changed metadata.

For a decoy on a copy-on-write filesystem or an SSD, prefer a hidden volume on
a whole device or partition over a file container, and disable automatic
snapshots (snapper, timeshift, btrbk, zfs auto-snapshot) of any filesystem
that holds a container.
