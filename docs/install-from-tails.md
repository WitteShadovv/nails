# First install from Tails

[Tails](https://tails.net) is a live system: it starts from a USB stick, runs from memory and
forgets everything when it shuts down. It connects through Tor and unlocks VeraCrypt and LUKS
volumes. That makes it a good place for the first installation of NAILS, which has to happen
outside the decoy system (see [Where to verify](verify-release.md#where-to-verify)). This page goes
through it with Tails 7, the current version in October 2026. Later updates come from inside a
hidden session instead (see [Updating NAILS](operator-guide.md#updating-nails)).

## Before you start

- **A Tails USB stick.** [tails.net](https://tails.net/install/) explains how to make one.
- **The hidden volume, made beforehand.** Tails can unlock VeraCrypt volumes but cannot create
  them: make a VeraCrypt volume with VeraCrypt on another computer. Its filesystem must be ext4,
  xfs, btrfs or f2fs (see [Requirements for the hidden root](backends.md#requirements-for-the-hidden-root)).
- **PBKDF2, not Argon2id.** When you make the outer and the hidden volume in VeraCrypt, keep its
  default KDF or choose any entry other than Argon2. Tails unlocks VeraCrypt volumes with the
  cryptsetup of Debian 13 (2.7.5), which cannot open a volume made with Argon2id, and neither can
  any decoy NAILS supports. Tails would refuse your correct password with the same error as a
  wrong one. [VeraCrypt volumes made with Argon2id](backends.md#veracrypt-volumes-made-with-argon2id)
  has the versions and says how to change a volume you already made.
- **A drive or partition of its own** for the hidden volume, as
  [Where setup happens](operator-guide.md#where-setup-happens) recommends. Do not use Tails to reach
  a container file on the decoy's own disk: Tails would have to mount the decoy's filesystem, and
  mounting writes to the decoy disk (ext4, for one, records when and where it was last mounted).

## 1. Start Tails

Start Tails, on another computer if the hidden volume is on an external drive: then the first
installation does not touch the decoy computer at all. On the Welcome Screen, set an administration
password (Tails offers this under its additional settings; see Tails' own Welcome Screen
documentation for the exact steps). Copying NAILS onto the hidden volume needs `sudo`, and Tails
cannot set the password once it has started. Then connect to Tor.

## 2. Unlock the hidden volume

Unlock the hidden volume, not the outer one. Opening a VeraCrypt volume outside the VeraCrypt
application — as you do here, through the system's disk tools — gives no hidden-volume protection,
so a write to the outer volume could overwrite the hidden one; never unlock or write to the outer
volume from Tails.
The Tails guide to [VeraCrypt volumes](https://tails.net/doc/encryption_and_privacy/veracrypt/) has
the steps for a file container and for a partition: give the hidden volume's password and choose to
unlock the hidden volume. A LUKS2 volume on an external drive unlocks from the dialog that appears
when you plug the drive in.

Tails mounts the volume in a folder under `/media/amnesia/`, named after the filesystem's label, or
its UUID when it has none. The commands below use `/media/amnesia/data`; put in your folder's name.

## 3. Download the release

Open Tor Browser and download `nails` and `checksums.txt` for the release you are installing from the
[Releases page](https://github.com/WitteShadovv/nails/releases) into a folder in your Home folder. The
release marked *Latest* there is the current stable one; release candidates are marked *Pre-release*.
In Tails that folder is in memory and is gone at shutdown. Do not save the files in the Persistent
Storage, if you have one: it would keep them on the Tails stick.

## 4. Check the download

Open a terminal (Apps ▸ System Tools ▸ Console), change to that folder and follow
[Verify a release](verify-release.md):

- **The checksum check** works in Tails as written.
- **The provenance check** uses `cosign` (see [Verify a release](verify-release.md)). Tails does not
  include it, and the distribution packages Tails can install for the session are older than the
  version that guide requires, so run the provenance check for the same release on another computer
  you trust before you run `nails` for the first time — `nails init` already runs it as root on the
  decoy. Until then only the checksum has been checked, and it does not say who built the file.

## 5. Copy NAILS onto the hidden volume

```bash
sudo install -m0755 nails /media/amnesia/data/nails
```

`install` run with `sudo` leaves the binary owned by root and writable by root alone.

## 6. Close the volume and shut down

Eject the volume with the eject button next to it in the sidebar of Files, then shut down Tails.

## Next

Start the decoy system, unlock and mount the hidden volume there as
[Storage backends](backends.md#per-backend-summary) shows, and continue with step 2 of the
[Quick start](../README.md#quick-start), `nails init`.
