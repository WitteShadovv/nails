# Storage backends

NAILS never unlocks, mounts or encrypts storage. It needs a filesystem that is
already mounted and writable at `hidden_volume_root`, and it keeps the upper of
the hidden root (one overlay over the whole decoy root) there. Which backend provides that filesystem
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
| **Tested** | VeraCrypt hidden volume, opened with `cryptsetup open --type tcrypt --tcrypt-hidden`, ext4 inside | The VeraCrypt VM test in `nix/e2e-tests/tests/backends/` creates an outer and a hidden VeraCrypt volume with the `veracrypt` console tool, opens the hidden one with `cryptsetup`, runs a session over it and images the decoy root. It runs in every E2E run that rebuilds the tests (each pull request that changes the code, each push to `main`) and nightly. The whole configuration on real hardware was evaluated by hand once. |
| **Tested** | A directory on a separate local disk, bind-mounted at the hidden root | The `bind-mounted-root` VM test: an ext4 disk that the decoy does not mount or list in its fstab, with a directory of it bound at `/mnt/data`. A bind of a folder of a filesystem the decoy uses is refused (see below). |
| **Refused** | A folder; a btrfs subvolume or a bind mount of a filesystem the decoy uses; the filesystem the decoy's fstab mounts; a logical volume or other device stacked on the decoy's storage or swap; an unencrypted image file on a decoy filesystem | Not storage of its own: everything written there lands on the decoy's disk. Refused by the attach gate before anything is written; the `preflight-decoy-filesystem` VM test covers the folder, subvolume, bind, image-file and fstab-filesystem cases. A folder is always refused; `--allow-decoy-storage` turns the other refusals into a warning, for storage you know the decoy does not use. |
| **Expected to work** | Any local Linux filesystem that passes the preflight probes (ext4, xfs, btrfs, f2fs) on any kernel block device, including iSCSI and NBD devices | Untested. The preflight probes decide. Network traffic to a remote block device is outside the host-side threat model, and the connection must survive the soft-reboots, which stop every userspace daemon (an iSCSI or NBD client among them). |
| **Unsupported** | NFS, CIFS/SMB, sshfs, 9p, overlays, FUSE filesystems and ZFS datasets as the hidden root; FAT, exFAT, NTFS | The attach gate refuses a filesystem that shows no disk it stores its data on (`storage_unjudged`), since where its writes land cannot be told. A ZFS dataset is one: its mount names only its pool, and the gate does not read which disks the pool is on. An image file on such a filesystem is refused the same way, unless the decoy mounts that filesystem at `/` or one of its system folders (`/home`, `/var` and the like) or lists it in its fstab; there an encrypted container only warns, as on any decoy filesystem. FAT, exFAT and NTFS cannot host an overlayfs upper layer and are refused by the `upper-fs-capability` preflight check. |
| **Unsupported** | A VeraCrypt volume made with Argon2id ("Argon2" in the KDF list of VeraCrypt 1.26.29 and newer) | No cryptsetup release can open it yet, so cryptsetup on the decoy cannot unlock it. See [VeraCrypt volumes made with Argon2id](#veracrypt-volumes-made-with-argon2id). |
| **Not evaluated** | Shufflecake; volumes mounted by the VeraCrypt application itself | No claims. `backend-detect` names a Shufflecake (`sflc_<dev>_<vol>`) volume in its summary, but no Shufflecake-specific hazards are checked. A cross-backend E2E matrix is not part of the suite yet. |

## Requirements for the hidden root

Whatever the backend, the filesystem at the hidden root must:

- **be storage of its own**, mounted and writable at `hidden_volume_root`
  (preflight check `hidden-volume`, which asks the attach gate): a mount point,
  with no second filesystem mounted over it, on no storage the decoy uses (see
  [the attach gate](threat-model.md#the-attach-gate)). An encrypted container
  file on a filesystem the decoy uses is accepted with a warning: that
  filesystem's journal and copy-on-write snapshots (btrfs, snapper) can keep old
  copies of the parts of the container that changed, so a whole device or a
  partition the decoy does not use is better. Only root can read the loop
  device's record of where the container file lives, so run `init` and
  `check` on a root in a file container with sudo: unprivileged they refuse it
  with `storage_unjudged` (and `status` and `verify` log to stderr only). `--allow-decoy-storage` accepts the
  decoy's storage with a warning, never a folder;
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
  NAILS keeps both under the hidden root (`<root>/root/upper` and
  `<root>/root/work`, and `<root>/root/mounts/<path>/` for each other decoy
  filesystem it overlays), so do not mount another filesystem inside the hidden
  root;
- **be kernel-managed** (dm-crypt, a loop device). Activation soft-reboots:
  every userspace process stops, so a FUSE mount backed by a process dies at the
  switch. A kernel mount survives it: the decoy's shutdown unmounts the hidden
  volume's own mount unit, but the bind NAILS places inside the next root keeps
  it alive, and it appears at the same path in the hidden session.

`sudo /mnt/data/nails check` (or `activate --dry-run`) prints every preflight
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
| The loop device is backed by a file on a FUSE mount | The backing file's filesystem is `fuse.*` (for example the VeraCrypt application without kernel crypto) | The attach gate already refuses such a root (`storage_unjudged`) before the check runs. Open the volume with cryptsetup so the kernel manages the mapping. |
| The LUKS2 header stores the persistent `allow-discards` flag | `config.flags` in the LUKS2 JSON header, read from the device below the mapping | `cryptsetup refresh --persistent <name>` without `--allow-discards`, then check `cryptsetup luksDump` reports `(no flags)`. |
| The LUKS2 header carries a `systemd-tpm2`, `systemd-fido2` or `systemd-pkcs11` token | `tokens.*.type` in the LUKS2 JSON header | The token names the unlock method in plain text, and a TPM2 token seals the key to this machine's TPM, binding the volume to the host. Remove it with `systemd-cryptenroll --wipe-slot` or `cryptsetup token remove` if the volume must not point at this machine. |

The LUKS2 header is read directly from the device node below the mapping (the
same fields `cryptsetup luksDump` prints), which needs root; a detached header
or an unreadable device is skipped. A LUKS mapping on a whole device with a
clean header, a Shufflecake volume, or anything the check cannot identify,
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
`cryptsetup --version` prints the version a decoy has. Tails 7 is based on
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
  every later open; the `backend-detect` check reads the header and warns when
  the flag is stored (by hand: `cryptsetup luksDump /dev/sdX2` must report
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
  look alike.
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
removal, and the switch releases the last reference (the overlay that held the
hidden volume), so the kernel removes the mapping, and a loop device set up with
autoclear, at that moment. You do not run the lock sequence after a session; you
run it only when you unlocked the volume on the decoy without activating, or for
a backend that is not device-mapper based. Closing the mapping does not clear
the key from RAM: dm-crypt wipes the master key when a mapping is removed, but
other copies (page cache, freed pages, process memory) survive a soft-reboot and
a warm reboot, unless the firmware honours the TCG memory-overwrite request, and
setting that request writes EFI NVRAM. Use `nails deactivate --poweroff` or
`nails emergency --poweroff` to power off instead and let RAM decay.

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
