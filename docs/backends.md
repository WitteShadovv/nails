# Storage backends

NAILS never unlocks, mounts or encrypts storage. It needs a filesystem that is
already mounted and writable at `hidden_volume_root`, and it layers the hidden
environment over the decoy from there. Which backend provides that filesystem
changes what an adversary with one or more disk images can learn, so this page
lists what has been tested, what every backend must provide, and the
deniability trade-offs of each supported backend.

The examples use the neutral mapping name `data` and the hidden root
`/mnt/data`. Substitute your own, and keep the mapping name, mount point and
filesystem label free of anything that hints at hidden storage: they surface in
`/dev/mapper`, `/dev/disk/by-label`, generated mount unit names and the journal.

## Support matrix

| Status | Backend | Evidence |
|---|---|---|
| **Tested** | LUKS2 + ext4 on a whole block device | Every E2E run: `nix/e2e-tests/lib/hidden-volume.nix` formats a dedicated virtual disk with `cryptsetup luksFormat`, opens it and creates ext4 inside. |
| **Evaluated once** | VeraCrypt hidden volume, opened with `cryptsetup open --type tcrypt --tcrypt-hidden`, ext4 inside | One manual forensic evaluation. Not exercised in CI. |
| **Expected to work** | Any local Linux filesystem that passes the preflight probes (ext4, xfs, btrfs, f2fs) on any kernel block device, including iSCSI and NBD devices | Untested. The preflight probes decide. Network traffic to a remote block device is outside the host-side threat model, and the connection must outlive the login session. |
| **Unsupported** | NFS, CIFS/SMB, sshfs, 9p and most FUSE filesystems as the hidden root; FAT, exFAT, NTFS | Cannot host an overlayfs upper layer. Refused by the `upper-fs-capability` preflight check. |
| **Not evaluated** | Shufflecake; volumes mounted by the VeraCrypt application itself | No claims. A cross-backend E2E matrix is not part of the suite yet. |

## Requirements for the hidden root

Whatever the backend, the filesystem at the hidden root must:

- **be mounted and writable** at `hidden_volume_root` (preflight check
  `hidden-volume`);
- **support symbolic links** (`symlink-support`);
- **support `trusted.*` xattrs, report a file type (`d_type`) from readdir, and
  store overlayfs whiteouts** (`upper-fs-capability`). The check proves this
  before the session is touched: in a throwaway `.probe-*` directory on the
  hidden root it sets and removes a trusted xattr, reads directory entry types
  and trial-mounts a small overlay that it exercises with a copy-up and a
  whiteout, then removes the directory. On failure it names the detected
  filesystem type;
- **keep every overlay upper and its work directory on one filesystem**.
  overlayfs refuses an upper and work directory on different filesystems.
  NAILS keeps both under the hidden root (`<root>/<name>` and
  `<root>/.work/<name>`), so do not mount another filesystem inside the hidden
  root;
- **stay mounted independently of the login session**. By default
  `nails activate` ends the graphical session before it mounts anything, so the
  mount must be kernel-managed (dm-crypt, a loop device), not a FUSE process
  started inside that session.

`sudo nails activate --dry-run` previews activation and prints every preflight
result, including the backend detection below.

## Backend detection in preflight

The `backend-detect` check identifies the device stack under the hidden root
and warns about hazards specific to it. It never fails activation and has no
configuration knob. It reads `/proc/self/mountinfo` to find the hidden root's
device, follows the device-mapper and loop layers in `/sys` and reports:

| Warning | Detected from | What to do |
|---|---|---|
| Discards are enabled on a tcrypt or plain dm-crypt mapping | `dm/uuid` starts with `CRYPT-TCRYPT-` or `CRYPT-PLAIN-` and `queue/discard_max_bytes` is non-zero | Close the mapping and open it again without `--allow-discards`. See [Discards](#discards-trim). |
| The hidden root lives in a file container | A loop device in the stack has a `loop/backing_file` | Accept the [timestamp exposure](#timestamps) or move to a whole-device hidden volume. |
| The container sits on a copy-on-write filesystem | The container file's filesystem is btrfs, zfs or bcachefs | Prefer a whole-device hidden volume; at least disable automatic snapshots of that filesystem. |
| The loop device is backed by a file on a FUSE mount | The backing file's filesystem is `fuse.*` (for example the VeraCrypt application without kernel crypto) | Open the volume with cryptsetup so the kernel manages the mapping. |

A LUKS mapping on a whole device, or anything the check cannot identify,
passes with a one-line description of the stack. A hidden root that is not a
mount point is skipped; the `hidden-volume` check fails it.

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
behind it, which is what the session requirement above needs.

### VeraCrypt hidden volume in a file container

```bash
sudo cryptsetup open --type tcrypt --veracrypt --tcrypt-hidden \
  /path/to/container data
sudo mount /dev/mapper/data /mnt/data
```

cryptsetup attaches the container to a free loop device itself.

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

### VeraCrypt hidden volume on a whole device

```bash
sudo cryptsetup open --type tcrypt --veracrypt --tcrypt-hidden /dev/sdX2 data
sudo mount /dev/mapper/data /mnt/data
```

A partition or a whole disk created by VeraCrypt holds the outer and hidden
volumes directly. There is no loop device and no container file whose
timestamps change.

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
  every later open, so check that `cryptsetup luksDump /dev/sdX2` reports
  `(no flags)` on its `Flags:` line.
- **Timestamp behaviour:** nothing on the decoy filesystem records use of the
  device. The LUKS2 header changes only when you run a management command
  (key slots, tokens, persistent flags).
- **Host traces:** the common traces below. A LUKS2 header announces an
  encrypted volume (`cryptsetup isLuks`, `blkid`), so deniability rests on
  that volume having a plausible reason to exist. A detached header
  (`cryptsetup luksFormat --header <file>`, kept on separate media and passed
  to `open` with `--header`) leaves the device without a signature; fill the
  device with random data before formatting so that used and unused areas
  look alike.
- **Lock sequence:** `sudo umount /mnt/data`, then
  `sudo cryptsetup close data`.

### Common host traces

Every backend leaves the same traces on the decoy side while you unlock it:

- **Shell history.** The unlock and mount commands name the tool, the mapping
  and, for a container, its path. Type them in a shell with history disabled;
  see "Shell History Protection" in the
  [operator guide](operator-guide.md#history-off-on-the-decoy).
- **The journal.** sudo logs every command line it runs, and the kernel and
  udev log the loop and device-mapper devices being created. Keep the journal
  volatile (journald `Storage=volatile`) or on impermanent storage.
- **Persistent configuration.** Never list the hidden volume in
  `/etc/crypttab`, `/etc/fstab` or the decoy NixOS configuration
  (`boot.initrd.luks.devices`, `fileSystems`).

`nails deactivate` ends with a reboot, which removes every mapping and loop
device. The reboot does not clear the keys from RAM: dm-crypt wipes the master
key when a mapping is removed, but other copies (page cache, freed pages,
process memory) survive a warm reboot unless the firmware honours the TCG
memory-overwrite request, and setting that request writes EFI NVRAM. Use
`nails deactivate --poweroff` to power off instead and let RAM decay. After
`nails emergency`, which neither reboots nor powers off by default, run the lock
sequence yourself.

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
