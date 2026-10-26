# Changelog

All notable changes to NAILS (NixOS Anti-forensics Isolation & Layering System) are documented in
this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and the project
uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for commit history.

Each release is one annotated `v*` tag: a single workflow builds, rebuilds, tests and attests it
and drafts the GitHub release, which a maintainer then publishes (see `RELEASING.md`). The section
of this changelog for that version becomes the release notes word for word, and
`docs/verify-release.md` explains how to verify the assets.

## [Unreleased]

### Upgrade notes

- A `nails.toml` that still sets `accept_persistent_decoy` is refused by the new binary, and the
  decoy is no place to edit it. Before you move `<hidden-root>/nails.new` over `<hidden-root>/nails`,
  run `<hidden-root>/nails.new config validate` inside a hidden session (it checks the
  `config/nails.toml` next to it), delete the key if it is reported, and pass
  `--allow-persistent-decoy` on the activations that need the override.

### Added

- `nails check` and activation warn when hidden sessions cannot load the running kernel's modules
  (the `kernel-modules` check). A kernel package update in a hidden session (on Arch Linux, a
  `pacman -Syu` that brings a new `linux`) deletes `/usr/lib/modules/<release>` in the overlay
  upper, and every later hidden session starts without modules for the kernel it runs on. The check
  reads the upper and warns when a hidden session deleted or replaced that tree, a directory above
  it or its index (`modules.dep`, or `modules.dep.bin`, the form `modprobe` reads), made one of
  those directories anew so the decoy's copy no longer shows through, or wrote its own index before
  the decoy last rebuilt its own, and when the decoy itself lacks the tree. The fix it prints is
  the `discard` of the path that holds the change, with `--allow-decoy-storage` when the run was
  given it. It offers an update of the decoy's kernel to a new release only when that path is
  `/usr/lib/modules/<release>` itself: a change above that tree hides the decoy's modules for every
  kernel, so there a kernel update does not bring them back. Only root can see whether a directory
  was made anew, so an unprivileged `nails check` that needs to know says it cannot tell instead of
  passing. A decoy without `/usr/lib/modules`, such as NixOS, passes.
- `nails check` and activation warn when hidden sessions' package database no longer follows the
  decoy's (the `package-drift` check). A package change in a hidden session lands in the overlay
  upper, and a later update of the decoy does not reach the record hidden sessions keep of their
  own: dpkg's `status` file and rpm's database are copied whole at a hidden session's first change,
  and pacman lists a package twice when a hidden session and the decoy both changed it. For dpkg the
  check names each package the decoy installed, updated or removed since hidden sessions made their
  copy, with its version on each side, and leaves out the packages a hidden session changed itself
  (their files under `/var/lib/dpkg/info` in the upper show which); for pacman each package listed
  twice, or listed without the files a hidden session deleted. For rpm it reads both SQLite
  databases with a reader of its own (no SQLite library, no `rpm`, nothing written), the committed
  transactions of each write-ahead log included, names each package the decoy changed since as for
  dpkg, and counts a package as a hidden session's own when the upper holds or deleted one of the
  files the package installs. The fix names the package manager's commands to run in a hidden
  session, and a hidden session that deleted or replaced the database itself draws the `discard`
  that brings the decoy's back. Activation shows the warning before it asks to log you out (unless
  `-y` skips the question), lists it again among the warnings of its result (exit 9), and reports it
  to a window's event stream as an `advisory` event. It never refuses. The decoy's database is read
  as root, with `O_NOATIME`, or without root only from a filesystem mounted `noatime`, so an
  unprivileged `nails check` that would need to read it elsewhere says it cannot tell. It also tells
  where it can without the mount table, from the kernel's own word (`statx`) on which directories
  are mount points, and passes a dpkg record whose copy holds the same bytes, whatever its format.
  It still says it cannot tell only where no answer is possible without a trace: a symbolic link on
  the way to the decoy's database, a database or upper that cannot be read, an rpm transaction
  stopped half way, or a kernel before 5.8 without the mount table. The Argon2id advice reads the
  installed cryptsetup through the same dpkg and pacman readers, which now take dpkg's field names
  in any case, as dpkg does.
- `check` notes when the installed cryptsetup cannot open a VeraCrypt volume whose header key is
  derived with Argon2id (the "Argon2" entry added in VeraCrypt 1.26.29), keyed on the installed
  cryptsetup version. No released cryptsetup opens such a volume, and nothing outside the encrypted
  header reveals the algorithm, so it advises making both the outer and the hidden VeraCrypt volume
  with PBKDF2. The version is read from the package database (dpkg or pacman) or the NixOS store
  path, never by running cryptsetup, which would stamp the decoy binary's access time at every
  check and activation; a `check` that is not running as root, or a host whose cryptsetup none of
  these name (Fedora's rpm database among them), skips the note.
- `check` and activation warn when a DMA-capable device could read RAM over the bus: the kernel does
  not remap DMA through an IOMMU, some devices' IOMMU groups are identity-mapped, or a Thunderbolt or
  USB4 controller reports no DMA protection. Each group counts on its own, so a kernel that leaves
  the IOMMU off by default (no `intel_iommu=on`, as on NixOS) and has it turned on only by the
  firmware's Kernel DMA Protection, which remaps the Thunderbolt and USB4 devices and leaves every
  internal device and slot identity-mapped, warns even while a docked device's group is remapped.
  The warning names the devices in the identity-mapped groups, so you can tell a built-in device the
  kernel identity-maps on purpose (AMD's kernel does so for an APU's integrated GPU while memory
  encryption is off) from a card in a slot or a docked device. NAILS cannot change the firmware
  setting; the warning says how, and to power off before the machine leaves your control.
- `nails activate` and `nails check` refuse a decoy with a pending offline system update staged
  (a `/system-update` or `/etc/system-update` marker, on the decoy or in the overlay upper), which
  would otherwise be applied inside the hidden session and reboot the machine out from under it.
  A marker a session deleted (a whiteout in the upper) does not count. For a marker in the upper,
  which neither the decoy's updater nor an `rm` on the decoy reaches, the refusal names the
  `discard` command that deletes it, with `--allow-decoy-storage` when the run was given it.
- `nails discard` takes `--allow-decoy-storage`, as `init`, `activate` and `check` do, for a hidden
  root that this computer's own storage seems to hold. Without it, discard refused such a root even
  when activation had accepted it, so nothing could be discarded there.
- `status` reports why the last session switch was refused. When a soft-reboot cannot switch root,
  the reason is kept on the hidden volume and shown the next time, instead of a refused switch going
  unexplained; a later successful switch clears it.
- `status` reports why and when the last session switch was refused, instead of a refused switch
  going unexplained. When the soft-reboot into the hidden session cannot switch root, the reason is
  kept on the hidden volume, written through the volume's mount in the prepared root and never on
  the decoy disk (so a hidden root accepted on the decoy's storage with `--allow-decoy-storage`
  keeps none), and shown once you open the volume again. When the way back is refused, the reason
  is kept in RAM with the session's runtime files and shown in the hidden session. `status --json`
  reports it as the `switch_refused` attention, with the refusal's own reason as `reason` and a
  `switch_refusal` object (`reason` and `at`). The next `activate` or `deactivate` clears it when it
  arms its own switch.
- `check` and `rehearse` document and probe more of the cross-distro residue surface a session can
  leave on a persistent decoy: chrony's drift and real-time-clock files, NetworkManager connection
  records, the Plymouth boot log, snapper timeline snapshots, copy-on-write and compressed storage
  history, and the GRUB boot-success counter on Fedora. Each is listed in the decoy requirements and
  threat model with where it lives, how it is checked and how to avoid it. The chrony, Plymouth and
  snapper probes run on every decoy, NixOS included, and report their files wherever the decoy runs
  the daemon. Fedora installs chrony by default, and so does Ubuntu on new systems since 25.10.
- `nails activate` and `nails check` take a per-run `--allow-discards` expert flag that turns the
  discards-over-the-hidden-volume refusal into a warning for one activation. It is buried in the
  long help: `--help` lists it, `-h` does not. It changes nothing about the encryption mapping and
  is never stored in `nails.toml`. It is distinct from cryptsetup's open-time `--allow-discards`
  (the option that turns discards on in the first place); the safe fix is still to re-open the
  volume with discards off. See docs/backends.md.
- docs/backends.md weighs VeraCrypt's rule that on Linux a hidden volume be mounted only from a
  live system writing to a RAM disk: a NAILS setup does not meet it, since you unlock and mount the
  hidden volume with cryptsetup on the running decoy before every session. It also passes on
  VeraCrypt's warning for hidden volumes made in file containers with VeraCrypt 1.26.6 through
  1.26.28, which upgrading VeraCrypt does not repair: if you rely on deniability, recreate the
  container and its hidden volume with 1.26.29 or later, away from the decoy, then securely erase
  the old container.
- Development: the `gui/` workspace, where the graphical interface will be built, gets its
  guardrails before any toolkit dependency lands. Its graph is checked against a cargo-deny policy
  of its own, `gui/deny.toml`, wherever `deny.toml` is checked, and cargo-vet is part of the CI gate
  for it: a third-party crate that no audit or recorded exemption covers fails the pull request that
  brings it in. Its tests are held to a line-coverage floor of 85%, the file size and orphan module
  checks now cover it and the `setup/` workspace, and `nix build .#nails-gui` builds its binary,
  still a placeholder that draws no window.
- `check` and the `inherited-autostart` warning list the autologin of Plasma Login Manager, KDE's
  display manager: `User=` under `[Autologin]`, or under the first seat's `[Autologin][seat0]`, in
  `/etc/plasmalogin.conf` and the drop-ins of `/etc/plasmalogin.conf.d` and
  `/usr/lib/plasmalogin/plasmalogin.conf.d`, read as releases up to 6.6 parse them and as KConfig
  parses them since 6.7, in each language a translated `User=` is for. KDE Frameworks 6.26 to 6.28,
  which Plasma Login Manager 6.7 also runs on, keep the settings of drop-ins differently from 6.29
  and later, and the files are read both ways. An account any of these readings names is listed,
  whatever `Relogin` says; on systemd 256 and later, Plasma Login Manager 6.7 and later log in after
  a soft-reboot only with `Relogin=true` (docs/operator-guide.md).

### Changed

- `rehearse` reports a decoy on a copy-on-write or compressed filesystem (btrfs, bcachefs, zfs or an
  f2fs mount with compression) as "not checked" rather than "clean" for leaked-then-deleted traces:
  such a filesystem keeps old copies in unreferenced extents and stores file contents compressed, so a
  raw plaintext scan can neither reach those old copies nor read a compressed extent, and a clean scan
  there cannot prove a trace is gone. A live decoy is classified from its mount table, and an offline
  image or an unmounted `--device` from its on-disk superblock and, for a whole disk, partition by
  partition, so a decoy read that way is reported "not checked" too. An f2fs counts only when it can
  compress: a mounted one whose options show compression, which the kernel always lists for an f2fs
  made with the compression feature, and an image or unmounted device whose superblock carries that
  feature. A plain f2fs stores every file verbatim and gets a clean result.
- Discards (TRIM) reaching the hidden volume now refuse activation instead of only warning:
  forwarding TRIM to the physical device leaves a readable map of used and free blocks, where a
  deniable volume should look like uniform random data, and writing an outer volume with discards
  on can destroy a hidden volume inside it. A LUKS2 mapping with runtime or stored discards is
  included, and a stack that rests on RAM-only zram devices alone is excepted: a zram device
  elsewhere in a stack that also rests on a disk (the cache of a cached logical volume, say)
  excepts nothing, and neither does a stack the check could not read to its end. Every activation
  runs the refusal, like the decoy-entry and decoy-flake refusals, and it names no device-mapper
  node.
- A derivative of a supported distribution — one whose os-release `ID_LIKE` names `debian` or
  `ubuntu`, such as Linux Mint — now runs with a warning that NAILS has not tested it, instead of
  being accepted silently. Fedora, Arch and their known derivatives, Enterprise Linux rebuilds
  (RHEL, CentOS, AlmaLinux, Rocky, Oracle) and SteamOS are each refused with a reason that names
  them and says NAILS has not yet validated them. A host whose `ID_LIKE` names `debian` or `ubuntu`
  and also `fedora`, `rhel`, `centos` or `arch` is refused, naming that family, wherever each
  stands in the list; 0.3.0-rc.3 accepted it as a Debian derivative.
- The platform table now holds the gate Fedora and its derivatives will take once Fedora is
  admitted. Fedora will be gated on its edition (os-release `VARIANT_ID`) as well as its release:
  Cloud will be the tested edition, and Workstation, KDE Plasma Desktop, any other edition and a
  Fedora host that names none will run with a warning that NAILS has not been tested on that
  edition, in `init`, `check` and `activate`; the `platform` row of `check` will name a tested
  edition (`Fedora 44 Cloud`). Nobara and Ultramarine will be refused below release 44 or without
  a release, and from 44 run with the untested-derivative warning. Fedora, Nobara and Ultramarine
  are still refused until Fedora's support has been verified, so no host's verdict changes yet.
- `check` and activation now warn on Ubuntu 26.04 instead of treating it as a clean tested release.
  A known upstream issue affects it: after the switch into the hidden session, AppArmor blocks chrony
  and CUPS from reaching systemd and the journal, so the clock does not sync and printing times out,
  and after the way back the decoy lists chrony as failed until its next full reboot, which hints a
  soft-reboot happened. 26.04 remains a tested release; reboot the decoy fully after a session to
  clear it. The fault is upstream, not in NAILS.
- Ubuntu 26.04 joins the automated distribution tests, beside Debian 13 and Ubuntu 24.04. They
  expect chrony's known upstream failure in the hidden session and after the way back, so they show
  when Ubuntu fixes it. Printing (CUPS), which their image does not install, is still checked by
  hand.
- A host that boots from a sealed composefs image is now refused even when it does not set
  `/run/ostree-booted`, recognised by its kernel command line or the composefs runtime directory.
  NAILS cannot overlay an immutable system.
- The hidden session's state file can now record which Linux family the host belongs to, without
  changing its on-disk format. A state file written by a 0.3.0 pre-release loads unchanged after the
  upgrade with its integrity digest intact, so an existing install is never read as corrupt.
- The host-tools pre-flight check requires only the tools NAILS actually spawns — `systemctl`,
  `loginctl` and `ip` on every host, `dmsetup` when the hidden volume is on device-mapper, and `nix`
  on NixOS — and names a missing one with an install hint for the host's package manager (`apt`,
  `dnf` or `pacman`). It no longer requires `systemd-run`, `cp`, `chown`, `sync`, `swapoff` or
  `kill`, which NAILS does through system calls or systemd units rather than by spawning a binary.
- When systemd is too old for a soft-reboot, `check` and activation now say how to upgrade this
  host, the way its distribution documents it: Debian 13 by its release notes, Ubuntu 24.04 or 26.04
  with `do-release-upgrade`, Fedora 44 with `dnf system-upgrade`, a full `pacman -Syu` on Arch,
  EndeavourOS, CachyOS and Manjaro, and on NixOS a current release for the decoy's nixpkgs, rebuilt
  and booted. Nobara, Ultramarine and a Debian derivative NAILS runs on are pointed at a release
  built on a tested one, upgraded as each documents, and any other host at the platforms NAILS runs
  on. The hint used to name the Debian, Ubuntu and NixOS releases whatever the host.
- `check` shows the "NixOS profile" section only on NixOS, or where an explicit NixOS build target is
  configured; a Debian, Ubuntu, Fedora or Arch decoy no longer prints a NixOS-profile line that does
  not apply to it.
- The machine-readable `--json` output moves to contract version 2 (`schema_version` is now `2`), a
  breaking change for scripts. Every command but `completions` prints exactly one envelope on stdout
  — the root privilege gate, a usage error (`config` without its subcommand among them), a Ctrl+C
  and an internal error included — and `activate` no longer streams progress lines before its result
  (`config show` likewise prints one document rather than a multi-line one). The envelope's `ok` is
  `true` only when the exit code is `0` or `9`, so a `verify` warning, a degraded `emergency` or
  `recover`, and a refused `check` now read as `ok: false`. A `rehearse scan` that could not check
  every device exits `9` and still reads `ok: true`: its exit code, not `ok`, says it is not a clean
  result. `status` reports where the machine is as `place` (`decoy`, `hidden` or `activating`, or
  `unknown` when reading the record was refused, so no report could be built) and the one thing that
  needs the operator as `attention` (`record_unreadable` in any place when the record cannot be read
  or trusted; only a hidden root without a way back and an interrupted activation come first),
  replacing the version-1 `posture`, `session`, `state` and `state_source` fields. An error now
  carries a stable `code`, the human `message`, and a typed `next` step — the command to run next,
  or `null` — in place of the free-form `hint`. A cancel
  reports one shape: an error with the code `cancelled`, no data, and exit `130`. That is a "no" at
  any prompt; Ctrl+C at a prompt, during `emergency --countdown` or in an activation before its
  point of no return; and, under `--json`, Ctrl+C or SIGTERM during `status`, `verify`, `check`,
  `config`, `init` or `rehearse`. A teardown that has begun (`deactivate` past its prompt,
  `emergency` once it acts, `recover`, `discard` once it deletes) runs to its end and reports its
  result. An internal error is the error `internal_error`, with exit `1`; one that comes after the
  result was printed leaves that envelope as it is, `ok` included, and still exits `1`.

  Exit codes that changed in this release:

  | Code | Before | Now |
  |---|---|---|
  | 1 | failed; also a "no" at the `activate` or `deactivate` question | failed, or not possible here. A "no" at any prompt now exits 130 instead |
  | 130 | Ctrl+C | Ctrl+C, and a "no" at any prompt |

  Codes 2, 3, 4, 5, 6, 7, 8 and 9 keep their meaning. Scripts that read the removed JSON field names,
  that treated a declined prompt as exit 1, or that parsed `activate --json` as a stream of lines must
  be updated. A JSON schema per command ships under `docs/schemas/`.
- The `--no-preflight` flag is removed. Activation always runs the full pre-flight registry, so the
  decoy-entry (`backend-entries`), decoy-flake (`nixos-build-target`) and discard (`backend-detect`)
  refusals the flag used to leave in place now run as part of every activation. Drop `--no-preflight`
  from any script.
- The persistent-decoy risk override is a per-run flag only. `--accept-persistent-decoy` is renamed
  `--allow-persistent-decoy` (on `activate` and `check`), matching `--allow-decoy-storage`, and the
  storable `accept_persistent_decoy` key is removed from `nails.toml`, so a fail-closed check can no
  longer be turned off for good. A config file that still sets the key is refused with a note that it
  is now the per-run `--allow-persistent-decoy` flag.
- `reset-upper` is renamed `discard` and hidden from the command list. It still takes a path, lists
  what it would delete and confirms first; its `--json` envelope now reports the command and its
  error code as `discard`.
- The `doctor` alias for `check` is removed. Run `check`.
- Activation gives the root of each overlay's upper, which becomes the hidden `/` or the root of an
  overlaid decoy filesystem such as a separate `/home`, and each directory the upper holds below it
  on the way to the operator's home the SELinux label of the decoy directory it stands for. Without
  them a host that runs SELinux sees the hidden `/` as `unlabeled_t`, which confined services may
  not even look up. The labels are read from the decoy without changing anything there, not even an
  access time, and each is written onto the hidden volume before the overlay over that upper is
  mounted. No other directory NAILS makes on the hidden volume takes a label from the decoy, so on
  such a host each shows as `unlabeled_t` unless the volume was relabelled, among them `root`,
  `root/mounts/<unit>` and the work directories, which the hidden session sees through the hidden
  volume's bind, and the hidden `/etc/nixos`, with `/etc` where `init` made it, that
  `init --hardware-config` makes in the root upper. Where the mount table in `/proc/self/mounts`
  lists a selinuxfs, or cannot be read while `/sys/fs/selinux` exists or `/etc/selinux/config` sets
  `SELINUX=` or `SELINUXTYPE=`, or the host cannot be detected, a label that cannot be copied
  refuses the activation and undoes it: a hidden volume whose filesystem
  stores no labels, a decoy directory without one, a policy that denies the relabel, or an operator
  without a home on the decoy, in the fresh-home persona and, once the upper holds a home for them,
  in the shared-home persona. Elsewhere a label is copied only where the decoy has one, so a decoy
  without labels gets the hidden root it got before. That includes a host that keeps an
  `/etc/selinux/config` from SELinux packages installed once, or an empty `/sys/fs/selinux`, while
  no selinuxfs is mounted: SELinux does not run there, and the activation says so in one line. `nails check` does not test this yet; see
  docs/decoy-requirements.md.

### Fixed

- A hidden session reaches `local-fs.target`, `remote-fs.target` and `swap.target` when the session
  keeps a decoy filesystem or swap off that the target requires. The session masked such a unit (an
  fstab entry without `nofail` that is not mounted now, a network filesystem, a swap line, the
  automount of a filesystem it binds or overlays), and systemd silently drops the start of a target
  that requires a masked unit, and with it every unit only that target pulls in: on Debian 13, a
  session entered with the ESP unmounted ran without `local-fs.target`. Such a unit is now skipped
  instead: a runtime drop-in gives it a start condition that never holds, so the hidden systemd
  starts it, finds the condition unmet and reaches the target, and the decoy disk stays unmounted.
  The fsck, makefs, mkswap, growfs and quota units its fstab line pulls in would start on the decoy
  disk before that condition is tested, so they are skipped with it. A skipped mount still waits for
  its device, so an entry whose device is not there at activation is masked as before, and `nails
  check` and `nails activate` warn that the hidden session will not reach its target (attach the
  device, or give the entry `nofail`); a device gone by the switch has its units masked then.
  Entries with `nofail` stay masked. `verify` reports a skip drop-in left on the decoy.
- An `/etc/fstab` entry that gives both `noauto` and `auto` is read as systemd's fstab generator
  reads it, by the last of the two. An entry such as `noauto,auto` is mounted at boot; the session
  left it to the hidden systemd as never mounted, and the hidden systemd mounted it read-write, and
  the attach gate did not count its device among the storage the decoy uses. The older automount
  spelling `comment=systemd.automount` counts as an automount, as it does for systemd.
- Units that fail in the hidden root and have no job there are masked there, as the boot-loader
  units already were.
  On Debian 13, `systemd-remount-fs.service` failed in every hidden session, because the root
  overlay refuses the decoy root's fstab options, and so did `systemd-growfs-root.service`, which
  cannot grow it. On Ubuntu 26.04, GRUB's boot-record unit is `grub2-common.service`, which failed
  in every hidden session entered with `/boot` mounted (`grub-editenv` cannot write the read-only
  `grubenv`); it is now masked like `grub-common.service` on Debian and Ubuntu 24.04. The masks
  hold in the hidden session only, and the decoy runs the units as before.
- The way back removes the session's runtime masks by name, as it removes its drop-ins. When the
  snapshot of `/run` the entry takes was gone by the way back, the scrub kept them, and the decoy
  started again with its swap, its unmounted disks and its boot-loader units masked until its next
  boot.
- `nails rehearse scan` reports more storage it cannot vouch for as "not checked" (exit 9) where it
  used to report a clean pass (exit 0). An offline image or an unmounted `--device` that is an
  encrypted container (LUKS or BitLocker) is reported "not checked" with the advice to scan its
  unlocked mapping instead, where its ciphertext used to count as a clean scan; so are an LVM physical
  volume and storage on which the scan identifies no filesystem. A whole-disk image is classified
  partition by partition and names each partition it could not check, a btrfs, f2fs or bcachefs
  superblock is found even beside a stale signature of another format (an ISO9660 descriptor
  mkfs.f2fs left in place), and a zfs dataset of the live decoy is listed as not checked instead of
  being skipped. An image cut short, as a copy that stopped early leaves it, is not checked either: an
  ext4, xfs or f2fs image that ends before its filesystem does, and a whole-disk image that ends
  before a partition its table lists or before the disk its GPT was written for. An empty image or
  device (a copy that failed, a loop device with no file behind it) is reported as not scanned with
  exit 9 instead of a clean pass with exit 0, and a scan that left a device unread no longer prints
  the green "not found" headline.
- `nails rehearse scan` reports a bare vfat, exFAT or swap image cut short as "not checked" (exit 9)
  where it reported a clean pass (exit 0). It reads the size the boot sector or swap header
  records, as it does for ext4, xfs and f2fs, so an image that ends before its filesystem or swap
  area does is known to be incomplete. A boot sector or swap header that records what no such
  filesystem has (a sector size the kernel does not take, no sector at all, a swap header of
  another version) counts as storage the scan does not identify. An ext4 or f2fs image cut inside
  its superblock, before its feature flags, is reported as cut short too.
- `nails rehearse scan` reports file-level encryption and NTFS as "not checked" (exit 9) where it
  reported a clean pass (exit 0): a raw plaintext scan cannot read what a filesystem stores
  encrypted or compressed file by file. That covers NTFS, which can compress the files of a folder
  marked compressed, whether an `ntfs` or `ntfs3` mount, any `fuseblk` mount (the type ntfs-3g
  mounts NTFS as) or an NTFS image; an ext4 or f2fs with the encrypt feature (fscrypt), which the
  scan reads from the superblock of a mounted device too; and a device that holds the folder of an
  eCryptfs mount (an encrypted home or Private folder): the filesystem the folder lies on, or each
  one it may lie on where the mount table does not show which, and for a `--device` also a whole
  disk with that filesystem in a partition or a device below or above it (a loop device or a mapping
  built on the partition), which the scan reads from sysfs. A `--device` the scan cannot place
  against such a folder is not checked either. The scan sees an eCryptfs folder only while it is
  mounted, and never in an `--offline` scan, which reads no mount table.
- The whole-root session overlay pins its feature options (`index=off`, `metacopy=off`,
  `redirect_dir=nofollow`) on every host, matching the pre-flight capability probe. On a kernel
  that turns these on by default (such as Arch's), the hidden overlay could keep an index, copy up
  only a file's metadata, or follow a redirect, so data could stay in the lower layer after a
  rollback and the overlay no longer behaved as NAILS's forensic guarantees assume.
- The `decoy-persistence` check judges journald's journal by the running systemd's built-in default
  when no configuration sets `Storage=`: below systemd 259 the default is still `auto`, but from 259
  (Ubuntu 26.04) it is `persistent`, so a decoy that keeps no explicit setting now counts as
  persistent and is refused, where it was read as volatile before. When no configuration file sets
  `Storage=`, the `journal.storage` credential counts as journald reads it: from systemd 256 only,
  as journald received it in `/run/credentials/systemd-journald.service/`, and only when its bytes
  are exactly the value, so `volatile` followed by a newline, as `echo` writes it, does not count.
  Only root can read that copy, so for an unprivileged `check` or `status` the built-in default
  decides, and a journal that only the credential makes volatile can count as persistent; run them
  with `sudo`. A systemd whose version cannot be read is treated as persistent.
- An empty `Storage=` in the journald configuration keeps the value set before it, as journald keeps
  it, where NAILS reset it to the default.
- The journald, logind and systemd-coredump configuration is read line by line for UTF-8, as systemd
  reads it, where a file holding a byte that is not valid UTF-8 was skipped whole and the files
  after it were still read. A comment that is not valid UTF-8 (a Latin-1 comment, say) is skipped,
  so a `Storage=persistent` beside it is still seen instead of the decoy reading as amnesic. Any
  other line that is not valid UTF-8 stops the reading there, as a malformed section header does:
  the assignments before it count and the files after it are not read, so a `Storage=volatile` in a
  later drop-in, which journald never reads, no longer lets a persistent journal pass. Like systemd,
  NAILS counts the Unicode noncharacters (U+FFFF and the like) as not valid UTF-8.
- A journald, logind or systemd-coredump configuration with a main file or drop-in that is not a
  regular file is no longer read as if that entry were not there. systemd lists a drop-in by its
  name alone, so a directory with a drop-in's name shadows the drop-in of that name below it, and
  NAILS read the one below instead. The releases then read such an entry differently: up to 259 a
  directory stops the reading where it comes and a link to `/dev/null` reads as empty, while 260
  and later read none of the configuration, the main file included, when a drop-in or the main
  file is a directory, a device (`/dev/null` too), a FIFO or a socket. NAILS counts such a
  configuration as unread whatever release runs, as the daemons read their files when they start
  and an update can bring another release before they next do, at the latest when the decoy starts
  again after the way back. So does a configuration with a file or drop-in directory NAILS cannot
  read where systemd, running as root, can (an unprivileged `check` used to skip such a file):
  `decoy-persistence` refuses an unread journald configuration and warns about an unread coredump
  one, `sleep-policy` warns that the lid or an idle session may suspend the host and that a closed
  lid may leave the session unlocked, and the sleep guard's `block` mode takes the lid switch. Mask
  a vendor drop-in with an empty file, which every release reads alike. A link to a path that does
  not exist still shadows the file below it and adds nothing, as in every release.
- On systemd 255 and older, NAILS reads the main journald, logind and systemd-coredump
  configuration file from `/etc` alone, as those releases do. It took the first of `/etc`, `/run`,
  `/usr/local/lib` and `/usr/lib` that has one, as 256 and later look for it, so on Ubuntu 24.04,
  which runs 255, a `/run/systemd/journald.conf` that sets `Storage=volatile`, with
  `/etc/systemd/journald.conf` gone, let a decoy pass whose journald keeps its `auto` default and
  persists to an on-disk `/var/log/journal`. When NAILS cannot read the running release, a main
  file outside `/etc` that changes what is read leaves the configuration unread.
- `check` no longer hangs when `/usr/lib/systemd/journald.conf`, whose commented `#Storage=` NAILS
  takes for the vendor's default, is a FIFO, and no longer reads without end when it is a device
  such as `/dev/zero`. A vendor file that is no regular file, or one over 1 MiB, gives no such hint,
  so the default stays the fail-closed one.
- A btrfs decoy root is accepted only when the mounted root is a real subvolume (its mount root
  equals its `subvol=`). A bind mount of a plain folder on a btrfs filesystem is now refused before
  activation, naming the folder, instead of passing the pre-flight check and then failing the
  way-back mount. A subvolume whose path holds a space, a tab or a backslash, which the mount table
  writes escaped, is a subvolume all the same; one whose path holds a comma is refused, because the
  way back could not name it to mount it again.
- A decoy mount point that is a symlink (for example `/home` linking to `var/home`, as on
  ostree-based systems) is resolved to its real path inside the decoy root. NAILS now decides, mounts
  and masks the filesystem where the decoy really keeps it (`var-home.mount`, not `home.mount`), and
  fresh-home mode creates the home at that real path instead of a directory where the decoy has a
  symlink. A link whose target does not exist yet is followed too, as systemd follows it. The
  automount of such an entry is masked under its real path too (`var-home.automount`), so the
  hidden session no longer starts in emergency mode when the filesystem behind it is overlaid, and
  `nails check` reports the decision at the real path. An entry that the hidden session's own files
  resolve to another path than the decoy's (a symlink on the way that a session replaced) is also
  decided at that path, so the hidden systemd cannot mount the decoy's filesystem there. A path that
  such a link leads into the hidden volume is masked, where the hidden volume's own entries are left
  to its bind.
- Decoy-persistence pre-flight now catches a syslog or audit daemon (rsyslog, syslog-ng, the
  `syslogd` of sysklogd, inetutils or busybox, metalog, socklog, auditd) whether it runs as a service
  unit, a systemd template instance (such as `syslog-ng@default`), the unit `syslog.service` names on
  Debian and Ubuntu, or a bare process, so a logging daemon on the decoy can no longer slip past
  activation. It also reads the systemd 262 kernel coredump socket pattern correctly instead of
  mis-reporting it as a raw core-dump path, catches Ubuntu's default-enabled kdump (refused, see
  Security), and no longer warns about `sudo` logfile or
  I/O-logging settings on systems where sudo-rs (Ubuntu's default sudo since 25.10) ignores them.
- The `memory-wipe` check reads the decoy kernel's configuration (`CONFIG_INIT_ON_FREE_DEFAULT_ON`)
  when the kernel command line is silent, from the running kernel's own `/proc/config.gz` (NixOS and
  Arch) or the copy in `/boot` or `/usr/lib/modules`, warns when the decoy kernel does not zero freed
  memory, and notes a RAM-wipe-on-shutdown mechanism (the dracut `ram-wipe` module) when one is
  installed. It counts `init_on_free` as off when `page_poison=1` takes precedence over it, and reads
  `init_on_free=enable` and `=disable` as the kernel does from Linux 6.16. The operator guide of the
  0.3.0 pre-releases advised `init_on_free=1 page_poison=1`; if you followed it, remove
  `page_poison=1`: on a kernel built with page poisoning, the NixOS kernel among them, it turns
  `init_on_free` off, and freed slab objects keep their contents.
- `nails activate` refuses a host NAILS does not support before it writes anything to the hidden
  volume, so a refused host is left byte-identical, with no state lock and no log line, and the
  command exits with the unsupported-platform status (8). The refusal previously came after the state
  lock and the log file had already been written.
- The optional NixOS module `nix/modules/hidden-network-identity.nix` now builds. NixOS refused its
  placeholder hostname `localhost`, which it would have mapped to 127.0.0.2 in `/etc/hosts`, so a
  hidden configuration that imported the module as shipped did not build. The module now leaves that
  mapping out while the hostname is `localhost`, and a VM test builds a hidden system with it.
- The way back now puts the decoy's network state back before returning to it, after a `deactivate`
  and after a plain `emergency`. It deletes the virtual links a session brought up (a tunnel, a
  dummy or a bridge) and, with `iw`, the Wi-Fi interfaces it added on one of the decoy's radios, and
  counts a link as the decoy's only when it has the index it had at entry, so a tunnel the session
  brought up under the name of one of the decoy's goes too, while a link the session only renamed
  stays. It sets each device's hardware address and the hostname back, deletes the policy-routing
  rules and nftables tables the session added (those of wg-quick, NetworkManager, a VPN app, a
  container runtime or libvirt), writes back the network settings for all devices and for new ones
  (`net.ipv4.ip_forward` and the `all` and `default` keys of `net.ipv4.conf` and `net.ipv6.conf`),
  and puts the per-link state NetworkManager and systemd-resolved keep under `/run`,
  NetworkManager's in-memory profiles included, back in place, so every file keeps its owner and
  mode. A part of that state activation could not read in full is left as the session leaves it
  rather than deleted as if the decoy had none. The decoy's NetworkManager therefore no longer
  adopts a session link and records a profile for it on disk. The way back does not put back the
  addresses and routes a session gave the decoy's own devices, what it added inside a firewall table
  the decoy already had or with legacy iptables, the settings of a single device, anything it
  deleted or the name it gave one of the decoy's links, or any firewall table on a decoy without
  `nft`. A Wi-Fi interface of the decoy's that software in the session replaced with its own, as iwd
  does by default and airmon-ng does for monitor mode, is not made again either, so the decoy has no
  Wi-Fi on that radio until it powers off or reboots. Take VPN connections down, end monitor mode
  and stop containers and virtual machines before you deactivate, or end the session with
  `--poweroff`.
- `nails activate` and `nails check` refuse a host without `ip`, or without `dmsetup` when the hidden
  volume is on device-mapper (dm-crypt, LUKS or a VeraCrypt mapping) or its backend cannot be read.
  The way back runs both and skipped their work without a word when one was missing: without
  `dmsetup` the hidden mapping and its key stayed open on the decoy, listed in `/dev/mapper`, and
  without `ip` the links and hardware addresses a session changed were not put back. The refusal
  names the package to install: `iproute2` (`iproute` on Fedora) and `dmsetup` (`device-mapper` on
  Fedora and Arch). On NixOS the refusal now says to add a missing tool to the decoy's
  `environment.systemPackages`, where the check looks for it, rather than the hidden system's.
- The way back now sets a device's MAC address back also when its driver refuses to change the address
  of a device that is up, as USB Ethernet adapters such as the ASIX AX88179 and many Wi-Fi drivers do.
  The change used to fail silently there: the decoy came back with the hidden session's random address,
  which its NetworkManager keeps when the decoy's profile sets none, and which can reach the decoy disk
  in a DHCP lease. The way back now takes such a device down for the change and brings it up again, as
  NetworkManager does, leaves a device that was down as it was, and reads every address back. A device
  whose address it still cannot set back keeps the session's address until power-off, and nothing tells
  you so: end a session that changed a MAC address with `--poweroff` when that address must never reach
  the decoy. A VM test checks the change on an emulated NE2000 network card, whose driver refuses it
  in the same way, after `deactivate` and after a plain `emergency`.
- `activate --json` and `deactivate --json` print their one envelope only once the soft-reboot (or
  the power-off) is enqueued, so it reports whether that worked. They printed a success envelope
  before enqueueing it, and a failure to enqueue it followed as a second, error envelope: a script
  that read the first line took a failed switch for a success. A failure is now the only envelope,
  with `ok` false and exit 1. The switch stops the reader too, so a reader stopped first may not
  read a success. Without `--json` the output is unchanged: it still comes before the switch, which
  ends the terminal.
- `nails deactivate` in a hidden root whose session plan in `/run` is missing or cannot be read
  refuses at once, before it asks anything, with exit 6 and `emergency --poweroff` as the next step.
  It asked for confirmation, printed that the session was ending and that the decoy would start in
  a few seconds, and only then failed with exit 1, pointing at a plain `emergency`, which finds no
  plan there either and does nothing. After a way back that fails, its hint no longer says a plain
  `emergency` returns to the decoy: it returns where it can prepare the return and powers off where
  it cannot.
- `nails deactivate` and `nails emergency` name each hidden backend device they could not mark for
  deferred removal (the hidden session removed `dmsetup`, say) once the soft-reboot is enqueued:
  it stays open after the switch, its key in RAM, until power-off. `deactivate` logged such a
  device only at debug level and `emergency` left it out of its report. Under `--json` both list
  it as `backend_left_open`, `deactivate` with a sentence in its new `warnings`, and
  `emergency --quiet` no longer stays silent about it.
- `nails deactivate` warns before it asks when the last step of the way back will find no `ip`
  (iproute2), no `nft` (nftables) or, on a machine with a Wi-Fi interface, no `iw`, in the hidden
  session's system directories or, on NixOS, in the decoy's system it returns to. Without `ip` the
  virtual links the session made, the MAC addresses it changed and the policy-routing rules it
  added stay on the decoy until power-off, without `nft` the nftables tables it added (a VPN app's
  table that blocks all traffic outside its tunnel keeps the decoy offline), and without `iw` the
  Wi-Fi interfaces it added on the decoy's radios. `deactivate --poweroff` leaves none of them.
  Under `--json` each warning is in the envelope's `warnings`.
- `nails check` and activation warn when the decoy has no `nft` (nftables), or has a Wi-Fi
  interface and no `iw` (the new `network-tools` check). Activation lists the decoy's own firewall
  tables with `nft`, and the way back deletes the tables a session added with it, and a Wi-Fi
  interface a session added on one of the decoy's radios with `iw`. Without them the way back leaves
  those on the decoy until power-off, and nothing said so before the session: a VPN app's table
  that blocks all traffic outside its tunnel keeps the decoy offline, and a stock NixOS decoy has no
  `nft`. The warning names the package to install, on NixOS with `networking.nftables.enable` as
  the other way to get `nft`, and looks for the tools where the way back does. It warns and does
  not refuse.
- The `activate --json` schema now ties `ok` to the outcome, as the output always did: a document
  that is not `ok` carries its error, and a failed activation (data status `failed`) is never
  `ok`. It accepted both contradictions, so a reader that validated a document could not tell a
  refused activation read as a success.
- `nails activate` refuses a state file it is not allowed to read (a permission denied, as an
  SELinux or AppArmor label can cause) as an unknown state, with exit 6, as the 0.3.0-rc.2 notes
  say it refuses an unreadable one. It took such a file for a state it could trust and went on.
- `nails activate` refuses a state file it is not allowed to read, or even to look up (a permission
  denied on the file or on a directory above it, as an SELinux or AppArmor policy can cause), as an
  unknown state, with exit 6, as the 0.3.0-rc.2 notes say it refuses an unreadable one. It took a
  file it could not read for a state it could trust, and one it could not look up for no state file
  at all, and went on. Every command now treats a denied lookup of the state file as it treats a
  denied read.
- `nails init` refuses a host NAILS does not support with exit 8, the unsupported-platform status,
  before it probes or writes anything, also with `--no-hardware-config` or `--hardware-config`, as
  the 0.3.0-rc.2 notes say unsupported hosts are refused. With either flag it skipped the platform
  check and wrote the layout on such a host; without them it refused with exit 4, after it had
  created and removed a probe file and symlink in the target. A release NAILS has not been tested on
  now warns with either flag too. The probes now come only after every precondition that can be
  read, so an obstruction or a missing base hardware configuration is refused with the target
  untouched.
- `nails discard` deletes a symlink the hidden session left at the path also when it points to
  nothing on the decoy, as a staged update's `/system-update` does; it reported nothing to delete.
  A symlink is deleted itself, never what it points at.
- `nails discard` refuses a path that lies below a symlink in the hidden session's copy (a
  `/home/alice` that the session linked to `/data/alice`) and names the link to discard instead.
  Followed on the decoy, the link led the deletion out of the hidden copy, onto the decoy's own
  files at the path it names.
- The pieces the way back leaves in `/run` for a Debian or Ubuntu decoy's first start (a copy of the
  binary, a one-shot unit and the wtmpdb writer's drop-in) are removed again when writing them fails
  part-way, and `nails verify` reports them when their step never ran. They stayed in RAM until
  power-off, with `/run` left executable. The drop-in is written last, after the copy it starts, so
  a way back cut short leaves the writer as the decoy has it, never pointing at a missing file. The
  threat model now also lists what they show until the next power-off: the one-shot's start in the
  decoy's journal and both units in `systemctl status`.
- `check`, the `inherited-autostart` warning and activation read only the autostart entries that are
  regular files once their links are followed, as systemd's autostart generator does. A FIFO named
  `*.desktop` in `~/.config/autostart`, `/etc/xdg/autostart` or the autostart directory of a NixOS
  profile blocked them, as reading it waits for a writer, and a link to a device such as `/dev/zero`
  was read without end. Such an entry, a directory or a link to nothing is now skipped unread, and a
  file of the same name in a later directory of the search path decides.

### Security

- An armed kdump on the decoy now refuses activation instead of only warning. If the kernel panics
  during a hidden session, kdump's crash kernel writes a dump of the session's memory, which can hold
  the hidden volume's key, and its kernel log to `/var/crash` on the decoy disk, outside the
  overlay. kdump counts as armed when `/sys/kernel/kexec_crash_loaded` reads `1` or
  `kdump-tools.service` or `kdump.service` is enabled or active, and Ubuntu arms kdump-tools by
  default from 24.10. An enabled unit counts even when it is stopped: the soft-reboot into the
  hidden session starts it again, and it loads the crash kernel there. A `kexec_crash_loaded` that
  cannot be read or holds anything but `0` or `1` is refused the same way.
  `--allow-persistent-decoy` accepts it for one run, with a warning. `nails status` shows an armed
  kdump on the decoy, and `status --json` carries it as `decoy_kdump_armed`.
- The hidden session masks systemd's GPT auto-generator, which mounts the partitions it finds by
  their type on the root filesystem's disk and turns on a swap partition where the fstab does not
  cover them, so the generator never mounts a decoy partition the fstab policy did not decide on. On
  the root overlay it finds no disk, so the mask is a defence in depth for a decoy where it would:
  one whose separate `/usr` is mounted read-only. The hidden root gets that `/usr` as a read-only
  bind, and with `/` on no disk the generator takes the disk of `/usr`. The mask is written at the
  switch and lives in `/run` for the session alone; a switch whose masks cannot be written is
  refused, and `nails verify` warns about a mask left on the decoy.
- `check` and `activate` no longer mount the trial overlay of the `upper-fs-capability` probe where
  the rest of the system can see it. The probe mounted it for a moment in PID 1's mount namespace,
  at `<hidden-root>/.probe-<pid>-<time>/merged`, and when systemd noticed the mount the journal got
  a line such as `mnt-data-.probe\x2d1141\x2d….mount: Deactivated successfully.`, which names the
  hidden root's mount point and the time of the run. A decoy whose journal was still persistent
  (a run before the decoy was made amnesic, or one with `--allow-persistent-decoy`) may hold such a
  line on its disk. The trial overlay is now mounted detached, through the kernel's mount API: no
  mount table lists it, and it is gone when the probe ends or the process dies. Where the kernel
  cannot mount it that way (without root, before Linux 5.2, or in a sandbox that blocks the call),
  the check fails before it writes anything. The README, the help and the next step `init` prints
  said that `check` (and `activate --dry-run`) changes nothing, and the 0.3.0-rc.2 notes called it a
  read-only report that writes nothing; the README, the help and `init` now say that it leaves no
  file or mount behind, and the operator guide says what it touches: probe files on the hidden
  volume that it removes again, the modification times they leave there, and no mount.
- On Debian 13 the way back now has the decoy's wtmpdb boot writer record the decoy's start as an
  ordinary `reboot`, stamped with the time of the switch. The 0.3.0-rc.3 notes said the way back
  already kept the writer from recording `soft-reboot`; that was wrong. Kept from the system bus,
  wtmpdb 0.73.0 still named the boot row `soft-reboot` once the decoy had been up for five minutes,
  and before that it dated a `reboot` row to the decoy's cold boot, which `wtmpdb last` lists as a
  crash. The way back now starts the writer in a time namespace whose boot clock starts at the
  switch, so it writes the row a power cycle writes and `soft-reboot` never reaches the disk. The
  cross-distro records test checks this in a VM on Debian 13, with the way back past five minutes
  of uptime.
- A backdated classic-`wtmp` boot record (systemd 255 and earlier, as on Ubuntu 24.04) is now
  corrected to the time of the switch, before anyone can log in, instead of the moment the
  correcting step ran, which dated the boot after the first records of its own start. The step no
  longer updates the file's access time on every way back.
- The 0.3.0-rc.3 notes and the threat model called the process numbers of the getty and login
  records written after the way back a weaker tell that needs a cold-boot baseline and is gone at
  the next power-off. Where the decoy keeps classic `wtmp` (Ubuntu 24.04, Debian 13 and NixOS), those
  records stay on the decoy disk, next to the low numbers of every earlier boot in the same file.
  Debian 13 is among them although `last` there reads wtmpdb, which keeps no process numbers: its
  getty still writes `/var/log/wtmp`. Only a session ended with `--poweroff`, which has no way back,
  leaves none of them.
- Ctrl+C at the `deactivate` and `discard` prompts cancels at once, with the cancelled notice and
  exit 130 (under `--json` the cancel envelope). The signal handlers these commands install restart
  an interrupted read, so Ctrl+C only echoed `^C` there, and a "y" typed afterwards went on. The
  prompts now wait for the answer as `activate`'s does.
- Ctrl+C during `emergency --countdown` cancels the emergency before it acts, with the cancelled
  notice and exit 130 (under `--json` the cancel envelope). Run as root it ended the process by the
  signal with nothing reported; run without root it was ignored. A terminal hangup during the
  countdown no longer aborts it as root: only Ctrl+C or SIGTERM does, so a closed terminal does not
  stop the emergency.
- An internal error (a panic) exits 1, a code of the exit table, where it exited 101; under `--json`
  it prints the error `internal_error`. `config path`, `config show` and `config validate` with
  `--json` no longer crash on a configuration path that is not valid UTF-8.
- A hint that names a command to run names it by the binary's real path, quoted for the shell when
  the path holds a space or another special character (a volume mounted by its label, say), so it
  pastes as it is. The DMA-protection warning, the warning on an untested release or derivative,
  `verify`'s guidance for a stale record and for RAM, the configuration-not-found error and `init`'s
  errors named a bare `nails` command, which `sudo` cannot run because the binary is not on its
  `PATH`; so did the comment on the emergency unit in the hidden NixOS module written to a fresh
  volume.
- `recover` gives each refusal the next step that fits it: in the hidden session `deactivate`, where
  it pointed at `emergency`, which kills the session and loses unsaved work; while an activation is
  entering, none, with the advice to wait for its soft-reboot. A recovery that itself fails (the
  record cannot be written) exits 1 with the error `recover_failed` instead of 6.
- `status` shows a state file it cannot read or trust as an unknown state, wherever the machine is,
  with what to do about it unless something more urgent comes first (a hidden root without a way
  back, an interrupted activation). In the hidden session it showed the inactive default that stands
  in for the record, with no word of the damage.
- The autologin that `check` and the `inherited-autostart` warning list is read as each display
  manager reads its files. A key counts only in its own group: `[daemon]` for GDM, `[Autologin]` for
  SDDM, and for LightDM `[Seat:*]`, `[SeatDefaults]` and the `[Seat:…]` groups that match the first
  seat. The files are read in the display manager's order, and a later one overrides an earlier one,
  an empty value too: an empty `User=` in `/etc/sddm.conf` or `autologin-user=` in
  `/etc/lightdm/lightdm.conf` now turns off the autologin a drop-in sets, where it was skipped and the
  drop-in's account listed. SDDM's vendor drop-ins in `/usr/lib/sddm/sddm.conf.d` and LightDM's in
  `lightdm/lightdm.conf.d` below `/usr/share`, `/usr/local/share` and `/etc/xdg` are read too, which
  were not; in SDDM's every file but the hidden ones is read, as SDDM reads them, not only the
  `*.conf` ones. GDM's `AutomaticLoginEnable=1` turns autologin on, as for GDM, and each GDM file that
  turns it on is listed, not only the first. A file a display manager refuses as malformed counts as
  it does for that display manager: GDM keeps what it read before the bad line, LightDM skips such a
  drop-in and does not start on such a `lightdm.conf`. SDDM and Plasma Login Manager sort a
  directory's drop-ins by the collation of their locale, which the files do not tell, so where
  collations disagree on the order of two (`kde_settings.conf` and `kde-autologin.conf`, say) the
  account either order ends with is listed. A line that holds a NUL is read as GLib and SDDM read
  it, and one a display manager may read two ways counts both ways: SDDM reads a line up to a NUL on
  Qt 5 and whole on Qt 6, and GLib judges a language tag beyond ASCII by its own Unicode tables. Only
  regular files are read: a FIFO, socket or device in one of these places is skipped, where `check`,
  the warning and activation could hang reading it.
- In the `fresh-home` persona, activation no longer follows a symbolic link in the upper when it
  makes the operator's home. Where a hidden session had replaced `/home`, or a directory below it on
  the way to the home, with a link, absolute (to `/var/home`, say) or relative, that leads out of
  the upper, the next activation could make the home, with its mode, owner and opaque attribute,
  wherever the link led, which can be the decoy disk. Each directory on the way is now opened in the
  one above it without following a link and made there when it is missing, and a link, or anything
  else that is not a directory, on the way refuses the activation, which makes nothing and names
  it: delete the link from the upper on the hidden volume and activate again. A home already in
  place is kept as it is, as before. A new home now takes its opaque attribute first, and it is
  removed again when its mode or owner cannot be set either: a home whose mode or owner failed was
  left without the attribute, and every later activation kept it, with the decoy home showing
  through.

## [0.3.0-rc.3] - 2026-10-20

### Changed

- The release binary is built with Rust 1.99.1; 0.3.0-rc.2 was built with 1.93.0.
- A release run boots every NixOS VM test on the tagged commit. Until now it took a test whose
  derivation had passed in an earlier run from the project's binary cache, without booting it.
- NAILS's automated VM tests cover Debian 13 and Ubuntu 24.04, and Ubuntu 26.04 is a supported target checked by hand (its automated image is still to be added). A later release, such as Ubuntu
  26.10 (released on 2026-10-15), still runs, but `init`, `check` and `activate` now warn that
  NAILS has not been tested on it; 0.3.0-rc.2 accepted every release from Debian 13 and Ubuntu
  24.04 on without a word. `check` names the detected host in a new `platform` row, which carries
  that warning.

### Fixed

- The attach gate and the storage checks resolve an `/etc/fstab` or `/etc/crypttab` entry that
  names its device by a tag (`LABEL=`, `UUID=`, `PARTLABEL=`, `PARTUUID=`) whose value holds a
  space, a slash or another character udev encodes in the link it makes for the tag, or is in
  single quotes. Such an entry named a path that no link has, and a value starting with a slash
  named that path itself.
- A command no longer hangs on a mount table that names one mount ID twice, as a read of
  `/proc/self/mountinfo` can while a mount is replaced: the lookup of the mount at a path went
  round in a circle for ever.
- A `utab` line with an empty value is skipped, as libmount skips it, instead of surviving a
  switch under its mount ID.
- The `decoy-persistence` and `sleep-policy` checks read the journald, logind and
  systemd-coredump configuration as systemd reads it: a line also ends at a carriage return or a
  NUL byte, a section name with a control character, a quote or a backslash stops the reading of
  that file and of every file after it, and a byte order mark is dropped from the first line that
  starts with one, not only from the first line. Assignments that systemd never applies counted,
  so a check could pass or fail on a setting the daemon does not use.
- `nails rehearse scan --offline` finds the UTF-16 form of the canary in a sparse disk image also
  when it ends where a hole starts; it reported such a canary as not found.
- `nails verify --disk` no longer wraps round the block numbers of a GPT whose byte offsets do not
  fit in 64 bits, which let a corrupt or crafted table place a partition, the free space or the
  partition entries anywhere on the disk.
- The refusal of a Debian or Ubuntu host below the minimum release, or whose release cannot be
  read, names the minimum as the distribution writes it, `Debian 13` and `Ubuntu 24.04`, instead of
  `Debian 13.0` and `Ubuntu 24.4`.
- `nails check` could report a host ready that `activate` then refused with exit 8, such as Fedora,
  Arch or a Debian host without the merged `/usr`. Its new `platform` row fails there, with the
  reason `activate` gives.

### Security

- The way back no longer leaves a login or boot record on the decoy that an ordinary power cycle
  never writes. On Debian with wtmpdb the boot writer named the boot row `soft-reboot` when the
  service manager reported a soft-reboot; on a service manager that keeps the userspace start time
  across a soft-reboot (systemd 255 and earlier, as on Ubuntu 24.04) the classic-`wtmp` boot record
  carried the decoy's first boot time, so the file held a boot stamped before the shutdown that
  precedes it. The way back now keeps the wtmpdb boot writer from recording `soft-reboot` and
  corrects a backdated `wtmp` boot record to the time the decoy came back, without masking either
  writer, so no shutdown row goes missing and the decoy's login and boot records read as one clean
  power cycle. The process numbers of the getty and login records written after the way back still
  continue from the decoy's boot, a weaker tell a later release will address.
  **Until you run a build with this fix**, end Debian 13 and Ubuntu 24.04 sessions with
  `nails deactivate --poweroff` (or `nails emergency --poweroff`): a power-off has no way back, so
  none of these records are written.
- The hidden session masks a decoy swap or mount under the unit name systemd gives it also when its
  `/etc/fstab` entry names the device by a tag whose value holds a character udev encodes in its
  link or is in single quotes (`LABEL=swap\040space`), or has a path with a `.` component or `..`
  right after the leading `/` (`/dev/disk/by-id/./x`, `/mnt/./backup`). NAILS masked a name systemd
  never generates and left the real unit free, so the hidden session could swap onto a decoy disk or
  mount a decoy filesystem. A decoy filesystem overlaid at such a mount point now keeps its hidden
  layers under the simplified name, the name of its unit (`<hidden-root>/root/mounts/mnt-backup` for
  `/mnt/./backup`, where 0.3.0-rc.2 used `mnt-.-backup`): rename the directory while NAILS is
  inactive, or the hidden files in it stay out of view.
- A release can be verified without a GitHub account. It carries its three attestations as
  Sigstore bundles (`provenance.sigstore.json`, `sbom.sigstore.json`, `vex.sigstore.json`), which
  cosign 3.1.3 or later checks against the downloaded files, also on a computer without a network
  connection; `docs/verify-release.md` shows how. The release workflow runs the same check before
  it drafts the release.

### Known issues

- On Ubuntu 26.04, chrony (time sync) and CUPS (printing) fail after the switch into the hidden
  session: AppArmor blocks their messages to systemd and to the journal, whose sockets were set up
  before the switch. Other services that AppArmor confines may fail the same way. In the hidden
  session the clock is not synchronized and printing times out, and after the way back the decoy
  lists chrony as failed until its next full reboot, which hints that a soft-reboot happened.
  Reboot fully after a session to clear it. The fault lies outside NAILS: a plain
  `systemctl soft-reboot` into another root, without NAILS, breaks chrony the same way.

## [0.3.0-rc.2] - 2026-10-16

NAILS 0.3.0 replaces the per-directory live overlays of 0.2 with one design: the hidden session is
an overlay over the whole decoy root, entered and left with `systemctl soft-reboot`.
Debian 13 or newer, Ubuntu 24.04 or newer and, provisionally, their derivatives join NixOS as
decoys.

0.3.0-rc.1 was tagged but never published: its release run stopped at the SBOM attestation.

### Upgrade notes

Upgrade only while NAILS is inactive: end a 0.2 session with its own `nails deactivate` (a reboot
ends it too) before replacing the binary. This release breaks compatibility with earlier state,
config and CLI surfaces; there are no compatibility shims.

- The decoy needs systemd 254 or newer. The hidden root lives under `<hidden-root>/root/`
  (among them `upper`, `work` and `mounts`); the uppers of the 0.2 per-directory overlays
  (`<hidden-root>/<name>`, `<hidden-root>/.work`) are not read. Move what you need into a hidden
  session and delete them. On NixOS the hidden hardware configuration now lives in
  `<hidden-root>/root/upper/etc/nixos/`; run `nails init` again to place it.
- On NixOS, a decoy whose `/etc/nixos` is a flake needs a hidden flake. 0.2 built that flake through
  its overlay of `/etc`; 0.3 refuses to build the decoy's own flake (`nixos-build-target`,
  `--no-preflight` included), also when `nixos_flake` or `--nixos-flake` names it
  (`/etc/nixos#host`, the form 0.2's examples used, `path:/etc/nixos`, `git+file:///etc/nixos`,
  `path:/etc?dir=nixos` or a link to it) and when `<hidden-root>/nixos` is a link to it, because the
  build would read only the decoy's files and leave out the hidden module and the hidden hardware
  configuration. Write a self-contained flake in `<hidden-root>/nixos` that imports the hidden
  module (`<hidden-root>/config/nixos/configuration.nix`) and reads none of the decoy's files, write
  and lock it inside a hidden session (`activate --overlay-only` enters one), never on the decoy,
  and build it there with `nixos-rebuild build --flake <hidden-root>/nixos#<host> --impure`,
  `<host>` being the decoy's hostname; `nixos_flake` names such a flake elsewhere.
- The hidden root must be a volume of its own. NAILS now refuses a root that 0.2 accepted: a folder
  (no mount point), a btrfs subvolume or bind of a folder of a filesystem the decoy uses, a logical
  volume in the decoy's volume group, an image file on a decoy filesystem, and an overlay, FUSE,
  network or ZFS filesystem. Move the hidden volume to a device of its own (see "Where setup
  happens" in the operator guide). An unprivileged `check` or `status` on a distribution whose
  `/etc/crypttab` only root can read gets `storage_unjudged` and logs to stderr only; run it with
  `sudo`.
- Configuration moves from `config/nails.yaml` (YAML) to strict `config/nails.toml` (TOML) next to
  the binary. 0.3 never reads `config/nails.yaml` and does not warn about it: an unconverted setup
  runs with the defaults. Convert each key by hand: `hidden_volume_path` is now `hidden_volume_root`
  (leave it unset to derive it from the binary's location), unknown keys are rejected, and the keys
  listed under "Removed" must be deleted. `nails init` writes a documented template and
  `nails config show --example` prints every key.
- Invoke the binary from the hidden volume by full path (`sudo "$ROOT/nails" …`); nails is never on
  the decoy `PATH`. `activate --flake` is now `--nixos-flake`, `status -v` is now
  `status --details`, `--plain` and `--no-color` are replaced by `--ascii` and
  `--color auto|always|never`, and `--no-logs` by `--no-log-file`; see "Removed" for the flags
  that are gone.
- `activate` and `deactivate` now ask for confirmation, and without a terminal they refuse with
  exit 2 (`needs_confirmation`); 0.2 skipped the prompt unless `--interactive` was given. Add `-y`
  to every script, keybinding or unit that runs them; `emergency` never prompts.
- Exit codes and JSON output changed. JSON output carries `schema_version = 1`; scripts that
  parsed the old output must be updated against the exit-code table in `nails --help` and the
  schemas under `docs/schemas/`.
- The on-disk state schema changed. 0.3 cannot verify a `state.json` that 0.2 wrote: `status`
  reports the state as unknown and `activate` refuses (exit 6) until you delete the file, from a
  clean inactive system; do not hand-edit it. `nails recover` removes what an interrupted activation
  left.

### Added

- The whole-root session. `nails activate` builds one overlay over the whole decoy root at
  `/run/nextroot` (the decoy root read-only as the lower, `<hidden-root>/root/upper` as the upper),
  applies a fixed policy to every other decoy filesystem (the ESP and `/boot` bound read-only, other
  mounted local filesystems overlaid with an upper under `<hidden-root>/root/mounts/`, swap,
  unmounted disks, network filesystems and disk-backed overlay entries masked), binds `/run` and the
  hidden volume into it, writes the session plan with a RAM copy of the binary and configuration to
  `/run/overlay-runtime`, and soft-reboots. An `/etc/fstab` that cannot be read refuses the entry.
  Every mount below `/run/nextroot` is private from the moment it exists, so none of them propagates
  into the decoy's own mounts; only the next root's own mount stays shared until the switch, so that
  the mount namespaces made before the entry (logind's, a sandboxed service's) see the next root and
  lose it again on a rollback. The policy's mount points and the decoy filesystems the session
  carries for the way back are placed as the hidden root resolves their paths, so an absolute link
  on the way (a `/home` linked elsewhere) never takes them onto the decoy disk. The boot-loader
  units that would write to the read-only ESP and `/boot` at every start
  (`systemd-boot-random-seed`, `grub-common`, `grub-initrd-fallback`) are masked in the hidden
  session only. Every process of the hidden session starts inside the overlay. Activation logs you
  out after a confirmation (`-y` skips it) and, as its last step, kills the decoy's interactive
  shells, so a shell that saves history on exit never writes the activation command (the
  `incremental-history-flush` check warns about shells that save after every command).
- On NixOS the hidden system is built into the next root's store (`nix build --store /run/nextroot`,
  the evaluation cache on the hidden volume), activated chrooted, and entered by repointing
  `/run/current-system` after every decoy unit has stopped: one soft-reboot, no bootloader install,
  no system profile change. It is built from the first of: a flake given with `--nixos-flake` or
  `nixos_flake`, a flake in `<hidden-root>/nixos`, and the legacy configuration (the decoy's
  `/etc/nixos` with the hidden hardware configuration, which imports the hidden module
  `<hidden-root>/config/nixos/configuration.nix`). A flake has the hidden module only if it imports
  it, and a decoy whose own `/etc/nixos` is a flake is refused (`nixos-build-target`,
  `--no-preflight` included) until a hidden flake is given; naming that flake with `--nixos-flake`
  or `nixos_flake` as a local path or a `path:`, `git+file:` or `file:` reference, also with a query
  (`?ref=main`), a `dir` parameter (`path:/etc?dir=nixos`) or through a link, or a
  `<hidden-root>/nixos` that is a link to it, is refused the same way. Inside the hidden session
  `nixos-rebuild test` applies changes: plain for the legacy configuration, and with
  `--flake <hidden-root>/nixos#<host> --impure` for a hidden flake, `<host>` being the decoy's
  hostname (on a flake decoy a plain `nixos-rebuild test` builds the decoy's own flake, without the
  hidden module). `--overlay-only` enters with the decoy's own system plus the hidden `/etc` and
  home; `check` says that no hidden system is built, and `activate` then names none. The paths of
  the hidden system's closure that still come from the decoy store are copied onto the hidden
  volume, so a decoy that garbage-collects or rebuilds between sessions does not break the hidden
  system. On Debian and Ubuntu the hidden configuration is the upper's `/etc`.
- The switch in both directions runs from the RAM copy (`ExecStart=` of
  `systemd-soft-reboot.service`) and acts only on an armed plan. On the way back it deletes the
  runtime journal, which the decoy's journald and the hidden one write alike, so a volatile decoy's
  journal starts again at the return, without the decoy's own records from before the session;
  scrubs the top of `/run` (two levels deep, three below `/run/systemd`) of what else the decoy did
  not leave there when it stopped for the entry, such as a PID file that the hidden session's copy
  of a decoy service wrote again; puts the decoy's name-server records below `/run/resolvconf` back
  as the decoy left them, so the hidden session's name servers and search domains (a VPN's, say) do
  not reach `/etc/resolv.conf` on the decoy disk; removes the session's drop-ins by name, leaving
  the decoy's own; resets units the session left failed; and, once the hidden units have stopped,
  gives the decoy's libmount `utab` lines back under the new mount IDs of the mounts the way back
  restores, without the hidden session's lines, and writes journald's kmsg cursor so the decoy
  journal imports no hidden kernel record. Each switch keeps only the `utab` lines whose mount it
  carries, by the line's mount ID or, for a line without one, by its path, source and root, and
  writes the file as libmount does (a new file renamed over the old one, under libmount's lock): the
  kernel hands the IDs of the mounts a switch leaves behind to later mounts, and a stale line would
  lend its options to one of those or to a new mount at its path; an `x-initrd.mount` lent that way
  could hang the next soft-reboot or power-off. After a session the decoy has its mounts back as it
  had them when the entry began: before the decoy's userspace starts, the way back makes again every
  mount it can take from the decoy root or a filesystem the session carried, in the decoy's order
  and with each mount's own options (NixOS's read-only bind over a store on the root filesystem, a
  mount stacked under a carried one, a RAM filesystem the initrd mounted), each with its `utab` line
  under its new mount ID, so those that the decoy's initrd marked `x-initrd.mount` are left to the
  final unmount at its next shutdown, as after a boot; a decoy line that names no mount the way back
  makes again is not given back. `activate` warns about a decoy mount the way back cannot make again
  where the session carries its filesystem, and about one that a plain soft-reboot keeps (NixOS's
  `/etc` overlay). Where the session itself puts a decoy filesystem behind an automount in place
  (`x-systemd.automount`, often the ESP), it masks that automount, and the way back leaves the
  automount to the decoy's start. Every way back to the
  decoy (the return, an emergency, an entry rolled back or recovered, a leftover next root disarmed
  at a reboot) also writes back the kernel's module loader, hotplug and firmware paths, which every
  entry records before anything runs and which a NixOS activation in the session points at the
  hidden store, and removes the session's unit masks. The session's drop-ins and runtime units are
  readable by all, so PID 1 logs no warning that names them as world-inaccessible. The session keeps
  working with `blk-availability.service` (Debian, Ubuntu), Ubuntu 26.04's D-Bus units and NixOS
  static addresses (`networking.interfaces`), whose stop would otherwise unmount the hidden volume,
  stall the login screen or drop the network.
- `nails deactivate` runs in the hidden session and soft-reboots back to the plain decoy after a
  confirmation (`-y` skips it); `--poweroff` powers off instead. The hidden volume is unmounted and
  its device-mapper stack closed by the switch itself, so dm-crypt wipes the master key from RAM; a
  backend that is not device-mapper based is unmounted but not closed.
- `nails emergency` acts at once, before argument parsing, configuration and logging: in the hidden
  session it prepares the way back, marks the backend for closing, enqueues the soft-reboot with
  PID 1 and kills every hidden cgroup (`cgroup.kill`); the machine returns to the decoy's login
  screen (NAILS logs nobody in, but a display manager set to log an account in automatically logs it
  in again, as at boot). `--countdown <SECS>` waits first with a Ctrl+C hint, `--poweroff` and
  `--reboot` replace the soft-reboot back, and a way back that cannot be prepared powers off. The
  result names the action and any fallback, the cgroups and processes killed, the timed phases and
  any mount left behind; an emergency that leaves a mount behind, or can only ask the kernel to
  power off, exits 7. On the decoy, it removes what an interrupted activation left and enqueues a
  requested `--poweroff` or `--reboot` right after; when it enqueues none, it also reloads PID 1,
  which would otherwise keep the removed drop-ins and masks loaded, and makes `/run` `noexec` again
  where the decoy had it so.
- `nails recover` removes an interrupted activation's leftovers on the decoy (`/run/nextroot`,
  `/run/overlay-runtime`, the session's drop-ins and unit masks), gives the kernel back the decoy's
  helper paths, closes the hidden backend where nothing uses it and resets the state. Like a
  rollback and an emergency on the decoy, it also removes the copies of the next root's mounts that
  every mount namespace made before the activation received (logind's, a sandboxed service's).
- `nails check` (alias `doctor`, and what `activate --dry-run` runs): a read-only readiness report
  built from the same pre-flight registry as activation, with each check's result and fix, the
  effective configuration, the decision for every decoy filesystem and the persona mode. It writes
  nothing, supports `--json` and exits 4 when a check fails.
- The attach gate: `init`, `activate`, `check`, `deactivate`, `reset-upper`, `rehearse plant` and
  the log and state writers accept only a hidden root that is a mounted volume of its own, before
  anything is written or probed. They refuse a folder, a second filesystem mounted over the root
  and, outside the session, storage the decoy uses (per its mount table, `/etc/fstab`,
  `/etc/crypttab` and sysfs); in the session only the volume the session started from is accepted.
  A refusal is one neutral message with exit 4 and a code (`not_separate_volume`, `root_covered`,
  `storage_unjudged`) that names no storage tool or device, and `--no-preflight` does not skip it.
  `--allow-decoy-storage` (`init`, `activate`, `check`) turns a refusal of decoy storage into a
  warning for storage the operator knows the decoy does not use; `status` shows the choice. Run as
  root, the gate reads `/etc/fstab` and `/etc/crypttab` without updating their access time.
- New pre-flight checks: `systemd-version`, `soft-reboot-units` (prints the module an older nixpkgs
  needs), `decoy-root` (refuses a tmpfs, ZFS or overlay decoy root), `session-state`,
  `fstab-policy`, `mount-namespace` (activation must share PID 1's mount namespace),
  `upper-fs-capability` (the hidden filesystem can host an overlay upper), `host-tools` (names any
  missing tool and its package), `backend-entries` (refuses a decoy crypttab or fstab line that
  opens or mounts the hidden volume), `decoy-persistence` (refuses a persistent journal or an active
  rsyslog, syslog-ng or auditd unless `accept_persistent_decoy` or `--accept-persistent-decoy` is
  set; warns about atime, crash-dump channels, sudo's own log files and the NixOS auto-upgrade
  timer, and passes systemd-coredump only when it has both `Storage=none` and `ProcessSizeMax=0`),
  and the warn-only `backend-detect` (discard, file container timestamps, copy-on-write hosts),
  `binary-location`, `inherited-autostart`, `incremental-history-flush`, `sleep-policy` (a lid or
  idle setting that would suspend the session, or a closed lid set to `ignore`, which leaves the
  session running and unlocked) and `residue-catalog`, and the informational `memory-wipe`
  (`init_on_free=1`). Failures end with one ordered list of fixes, and checks that depend on a
  failed one are skipped with a reason.
- Disks during the session (`[session_mounts]`): the session watcher raises a neutral desktop alert
  for every read-write mount of a disk outside the hidden volume and for a disk mounted over the
  hidden root or one of its parents, which `status` also names (`hidden_root_covered_by`); nothing
  NAILS writes reaches such a cover. Opt-in `read_only` makes every disk the session does not use
  read-only at the block layer until the way back. The alerts go to the account logged in on the
  machine's own screen and run as that account, since a desktop session bus admits no other (the
  child drops root's groups and ids before it starts), through `notify-send` or, where it is
  missing, `busctl`. Each alert runs in a session of its own with `no_new_privs` set, waits at most
  10 s for the notification daemon, and is sent from a thread of its own, so a daemon that never
  answers holds up no probe, no other alert and no emergency.
- The backend watcher (`[backend_watch]`) alerts when the hidden backend fails mid-session and,
  only when opted in, runs the emergency after a debounce.
- `[sleep_policy]` (`warn` by default, `block` or `teardown`): `block` holds sleep and idle block
  inhibitors, and the lid switch's when a closed lid would sleep; `teardown` powers off through the
  emergency before the machine sleeps.
- Persona options (`[persona]`): `mode = "fresh-home"` gives the operator an empty home in the upper
  instead of the decoy home, and `mask_inherited` lists inherited decoy autostart entries and user
  units to hide from the hidden session (`["*"]` hides all; empty by default), also one the
  inventory does not list: a name with a unit suffix as a user unit, any other as an autostart
  entry. The masks are written as the hidden root resolves their paths, so an absolute link on the
  way (a `/home` linked elsewhere, a `~/.config` linked to a dotfiles directory) never takes them
  onto the decoy disk. An optional NixOS module and NetworkManager drop-in give the hidden session
  its own MAC addresses and hostname; the way back can leave the random MAC address on the decoy's
  device, and the hostname on a decoy without `/etc/hostname`, so end a session that used them with
  `deactivate --poweroff` (or `emergency --poweroff`).
- Inherited decoy state: `nails check` and the `inherited-autostart` check report what the hidden
  session would inherit and needs review: autostart entries and user units in the decoy home,
  system-wide ones that are not part of the desktop or the distribution, lingering, display-manager
  autologin, and every entry on a documented list of known trace writers (sync, backup, messaging,
  mail and account clients, phone links). The desktop's and the distribution's own components are
  counted, not reported, and an entry `mask_inherited` names counts as handled. Autologin has a
  remedy of its own: turn it off for the hidden session only; it stays listed while the decoy keeps
  it. On NixOS the autostart directories of the system and user profiles are read too. `nails check`
  names a `mask_inherited` name that matches nothing, says on a line of its own when the hidden
  session starts in the decoy home (`shared-home`), and in JSON gives every entry its origin and
  status.
- `nails rehearse`: `plant` puts a random canary into a hidden session, and after the way back
  `scan` searches the raw decoy devices (or disk images with `--offline`) for it; `status` and
  `reset` follow the rehearsal. A scan is refused only inside the session the canary was planted
  in, which `plant` records by the session's entry time, so it runs on the decoy after a plain
  `nails deactivate` on every systemd version. The result lists the channels the canary could not
  be planted in (the notification, when no desktop session could show it) as not tested. The scan
  exits 0 when the canary is not found, 11 when it is and 9 when a device could not be read in
  full.
- `nails verify --offline --root <mount>` scans a mounted decoy image, and `--examiner` reports the
  setup traces an examiner looks for (encryption headers, containers, crypttab lines of every
  TrueCrypt and VeraCrypt kind, LVM archives, tooling and history), grouped by what they suggest;
  `--disk <device>` adds partition-level checks. A residue catalog names every class of trace a
  session or its setup can leave, with its mitigation; `verify` and the `residue-catalog` check run
  its probes, and the residue tables in the docs are generated from it.
- `nails activate` writes a read-only decoy residue report under `<hidden-root>/reports/` before
  the switch and prints a one-line summary: no known residue, or how many warnings and critical
  findings the report holds.
- `nails config path|show|validate`: `show` prints every effective value and its source
  (default, file, cli, derived), `--example` prints every key, and `validate` checks a file
  strictly.
- `nails reset-upper <PATH>` deletes a path's hidden copy from the upper, so the decoy's own files
  show through again (for example after a decoy update); it is refused in the hidden session.
- `nails completions <shell>`, a man page (`nails.1`), a Markdown CLI reference (`docs/cli.md`),
  JSON schemas under `docs/schemas/`, and EXAMPLES and an exit-code table in `--help`. The release
  archive ships the man page, the CLI reference, the operator guide and the threat model.
- `nails status` reports the live session from the mount table and the session plan (posture
  `decoy`, `active`, `transitioning`, `degraded` or `unknown`), the policy for every decoy
  filesystem, whether the decoy keeps a persistent log store, the persona mode and how long the last
  activation took, as `activate` printed it. It shows times in local time with their UTC offset;
  the JSON keeps UTC. An interrupted entry exits 7 and points at `nails recover`; a record that
  still says active after a power loss is named as such, and `nails recover` resets it.
- Ctrl+C (SIGINT) or SIGTERM cancels an activation at its next step up to the soft-reboot, during
  the residue baseline, the pre-flight checks and the hidden system's store copy too, and removes
  everything it built (exit 130); at the confirmation prompt it ends the prompt at once. A cancel
  reads "Activation cancelled; nothing was changed.", as an answer of n does (exit 1), and
  `activate --json` gives it the status `cancelled`. An answer of n at the `deactivate` and
  `reset-upper` prompts prints the same kind of notice ("Deactivation cancelled; nothing was
  changed.", "Reset cancelled; nothing was removed.") and exits 1; their JSON is the error envelope
  with the code `cancelled`. The hidden system's activation runs in a process group of its own,
  which a Ctrl+C on the terminal does not reach, and finishes first. SIGHUP no longer aborts a
  running command, and NAILS lowers its own OOM score.
- NAILS disables its own core dumps before parsing its arguments, so a crash cannot write its
  memory to the decoy.
- Documentation: an operator guide organised by where each step runs, with a recovery runbook,
  `docs/threat-model.md`, `docs/configuration.md`, `docs/backends.md`,
  `docs/decoy-requirements.md`, `docs/architecture.md`, `docs/distribution.md` and
  `docs/verify-release.md`.

### Changed

- Configuration is strict TOML: unknown keys are rejected with a did-you-mean hint, most keys of the
  old live-overlay design say they were removed, configured paths are validated when the file is
  loaded (relative, `..`, symlinked or out-of-root paths are rejected), and a missing or invalid
  `--config` file exits 3. So does a configuration the command cannot read: `init` writes it
  readable by root only, and a run without root then names the full `sudo` line to use, every
  argument included, in the text and as the hint of the JSON error. Without a config file,
  `activate` says before its confirmation that it uses the built-in defaults, under `-q` too.
- One stable machine interface: a typed JSON envelope (`schema_version`, `command`, `ok`, and `data`
  or `error`; `activate --json` prints a progress line and then its result, one JSON object per
  line, and every log line goes to stderr) and one exit-code table for every command (pre-flight
  refusals 4, not run as root 5, untrusted state 6, degraded or interrupted 7, unsupported host 8,
  completed with warnings 9, `verify` warnings and critical findings 10 and 11, cancelled 130).
  `activate --json` lists the boot-loader units in `masked_units`, as `status --json` does.
- Output flags (`-c`, `-v`/`-q`, `--color`, `--ascii`, `--json`, `--no-log-file`) are global. Colour
  is never used on piped output and honours `NO_COLOR` and `CLICOLOR_FORCE`; console lines no longer
  carry a timestamp. At the default verbosity the console is compact: a log event prints its
  message, a warning or error its mark, message and details, and routine events (each passed check,
  the store and staging steps) go to the log file only; `-v` and `-vv` show the full records. Counts
  on the console take the singular for one and the plural otherwise (`1 residue channel is live`,
  `4 catalog probes`).
- `activate`, `deactivate`, `emergency` and `recover` refuse to run without root before writing
  anything, with exit 5 and the full `sudo` line to use, every argument included.
- `nails init` checks the target, the attach gate first, before writing anything, supports `--json`,
  `--hardware-config` and `--no-hardware-config`, reports each item as created or already present,
  and ends with numbered next steps that keep editing off the decoy (prepare `nails.toml` on another
  machine, or as `nails.toml.new` in a hidden session), then `check` and `activate`. On Debian and
  Ubuntu the root overlay's upper is made by the first activation, with the decoy root's mode and
  owner; `storage-readiness` counts that as part of its pass.
- The swap check classifies each device: RAM-only zram passes, swap on dm-crypt with a random key
  warns, and disk or file swap, fixed-key encrypted swap and hibernation are refused. A hidden
  NixOS hardware configuration that NAILS seeds has the decoy's `swapDevices` and `resumeDevice`
  commented out.
- The disk-space check is one floor (`minimum_space_mb`, 500 MB); `rebuild_space_mb` (4096 MB) is
  checked before a hidden NixOS build.
- `nails verify` names the checks it ran and the areas it did not, reports session leftovers, and
  counts only warnings and critical findings in its header. Inside the hidden session it tells the
  session's own files from traces on the decoy: its runtime files, the mounted hidden volume and its
  state make one note, and a NAILS path that the hidden layer holds (on NixOS, the module link
  `nails init` stages) is a note that points to `verify --offline --root` instead of advice to
  delete it. On the decoy, the runtime directory of an interrupted activation is reported once, as
  critical, with `nails recover` as its fix; a read-only disk rule that an unfinished way back left
  says to power off or to remove it as root, and the fixed `/run` paths of an earlier release say to
  power off. The memory note no longer suggests a cold boot: it says to power off (in the hidden
  session, `nails deactivate --poweroff`) and to leave the machine off for a few minutes. `--deep`
  also searches the journal for the tool, the configuration file, `cryptsetup` and the hidden volume
  path, and names sudo's records of your own commands as such: notes while the journal is in RAM,
  warnings when it keeps files on disk. Artifact paths are probed without following links, so a
  leaked link is found even where its target does not resolve.
- On NixOS the hidden `hardware-configuration.nix` wraps the original (kept as
  `hardware-configuration.base.nix`) instead of patching it, a `nix-instantiate --parse` check
  rejects an unparseable configuration, and the hidden NixOS module forces
  `system.autoUpgrade.enable = false`. The base-configuration check (`suspicious-nails-reference`)
  reads every `.nix` file under `/etc/nixos`, following strings, `with` and `let … in` and reading
  comments as code, and refuses a line that names the hidden environment: the hidden volume's mount
  point or device as a whole path (`/mnt/data2` is not `/mnt/data`) and the units systemd names
  after them, in both spellings of an escaped name; what the volume is stored on, unless the decoy's
  own volumes sit on it too: the partition or disk and an image file behind a loop device by their
  paths, every link udev made for them or for the volume's own device (`/dev/disk/by-id`, `by-path`,
  `by-partlabel`, `by-uuid`, `by-label` and the LVM path `/dev/<vg>/<lv>` among them), the
  partition, LUKS and filesystem uuids, and the labels as `LABEL=`, `PARTLABEL=` or a `fileSystems`
  or `swapDevices` entry's `label`; its mapping name where a line opens the volume: a
  `boot.initrd.luks.devices` or `clevis.devices` entry, in nested blocks and in a block commented
  out line by line whose lines are indented at least as deep as its first, the `name` of such an
  entry, `encrypted.label`, crypttab text, `systemd-cryptsetup@<name>.service`, or a word after
  `cryptsetup` and a verb that opens, closes or asks about a mapping (`open`, `create`, `close`,
  `status` and the like), up to the end of the command, continued lines, comments and prose
  included; or NAILS itself. Ordinary configuration passes: the mapping name as an ordinary word
  (`description = "Back up user data"` with the mapping `data`, `cryptsetup` next to it in a package
  list or in prose that puts none of those verbs between `cryptsetup` and the name, or the comment
  `nixos-generate-config` writes above `system.stateVersion`), the decoy's own mapping whose name
  merely ends like the hidden one, and the word `hidden` and options such as `services.plausible`,
  which 0.2 refused. The check does not follow a mapping defined through a `let` binding,
  `lib.listToAttrs` or an interpolated name, and does not know the storage's kernel name without
  `/dev/` (as a udev rule writes it), `/dev/dm-<n>`, `/dev/block/<major>:<minor>` or a path written
  with a doubled slash. A refusal names the file, the line and the text, why it counts and what to
  do; with no `.nix` file under `/etc/nixos`, the check says it inspected nothing. Only `.nix` files
  are read: keep the other files in `/etc/nixos`, and its history where it is a git repository, free
  of the hidden volume too.
- Unsupported hosts are refused before any write, with exit 8: Debian before 13, Ubuntu before
  24.04, non-merged-`/usr` Debian-family layouts, ostree or image-based systems, systems without
  systemd, and distributions not yet validated (Fedora, Arch). Hosts with systemd older than 254
  fail the `systemd-version` check (exit 4). Derivatives whose `ID_LIKE` names debian or ubuntu are
  accepted provisionally.
- A corrupt or unreadable state file is reported as an unknown state: `status` shows it and
  `activate` refuses, instead of treating it as inactive.
- `nails --help` now describes the tool as "Run a hidden session on a decoy Linux system". Sources
  carry SPDX headers, and `REUSE.toml`, `NOTICE` and DCO sign-off guidance are added.
- Vulnerabilities are reported through GitHub private vulnerability reporting first, with
  `security@nails.run` as the fallback; conduct reports go to `contact@nails.run`.
- Releases come from one tag-triggered workflow that checks the tag against the version,
  `Cargo.lock` and this changelog, builds from source, rebuilds on a fresh runner, runs the full
  E2E suite, attests the assets and an SBOM, and drafts the release with this section as its
  notes. `docs/verify-release.md` explains how to verify the assets.
- Development: the library is split into crates along the session's boundaries, unsafe
  code is denied outside scoped, commented sites, the toolchain is pinned in
  `rust-toolchain.toml` (1.93.0), the flake pins nixos-unstable of 2026-10-11, and a `justfile` is
  the single source of local and CI commands. The VM tests cover the session on NixOS, Debian 13
  and Ubuntu 24.04, with host-side checks of the decoy disk image.
- CI: one required `gate` check per pull request, E2E VM tests on GitHub-hosted runners (affected
  tests per pull request, the full suite on `main` and nightly), scheduled advisory, stress,
  mutation and benchmark jobs, and dependency checks through cargo-deny only.

### Removed

- The per-directory live overlays (`/etc`, `/home`, `/var`, … on the running decoy) and everything
  that served them: process detection, restart and kill, the display-manager restart, the
  overlay pivot, the shell-history cleaner, the shell prompt marker and terminal colour scheme, and
  the desktop notifications after activation with their XDG autostart entry.
- The `notify-dispatch` command; the `activate` flags `--no-clear-history`, `--kill-session`,
  `--no-kill-session`, `--accept-pivot-risks`, `--no-pivot` and `--interactive`;
  `deactivate --no-clear-history`; `emergency --no-countdown` (emergency now acts at once); and the
  per-command `--plain` and `--no-color` flags and the global `--no-logs`.
- The configuration keys `overlays`, `overlay_mode`, `overlay_exclusions`,
  `overlay_exclusions_remove`, `extended_overlays` and the ephemeral overlays, `clear_history`,
  `color_scheme`, `preflight_checks`, `default_verbosity`, `color_output`, `verify_on_deactivate`,
  `milestone_tips`, `max_log_size_mb` and `retention_days`.
- The XOR string obfuscation: the binary is identifiable, and the documentation says so.
- `docs/USER-SECURITY-GUIDE.md` and `docs/vulnerability-handling.md`, replaced by the operator
  guide, the threat model and `SECURITY.md`.

### Fixed

- On NixOS, `activate`, `deactivate` and `emergency` work when a systemd unit starts them (a panic
  key, `systemd-run`): the Nix tools are found in the root-owned system directories when the
  caller's `PATH` lacks them, and a legacy build without `NIX_PATH` takes `nixpkgs` from root's
  `nixos` channel.
- Pre-flight results are reported once and honour `--quiet` and `--json`.
- Updated dependencies to clear the RUSTSEC advisories that affect the shipped binary (anyhow,
  crossbeam-epoch) and restored the Nix release build
  ([#54](https://github.com/WitteShadovv/nails/pull/54)).

### Security

- Nothing NAILS writes reaches the decoy: the state file, its lock, logs, reports and staged
  configuration are written only onto an attached hidden root, through `openat2` beneath it, so a
  planted symlink or `..` cannot redirect them; log files are created mode 0600, and a panic goes
  to the hidden-root log, not stderr.
- Commands NAILS starts run from a cleared environment with a fixed, root-owned `PATH`, so a
  caller's `PATH` or `NIX_*` cannot steer which binaries a root child runs.
- The release binary carries no test hook: test-only code compiles only under a non-default
  `test-hooks` feature.
- The release binary links the musl of the pinned nixpkgs (1.2.6, with nixpkgs' patches for
  CVE-2026-6042 and CVE-2026-40200) instead of the musl 1.2.5 that ships with the Rust toolchain,
  so the musl the release SBOM names is the one in the binary. The build fails if its linker map
  shows `libc.a` or one of musl's crt files from anywhere else.
- The release binary no longer refers to the Rust toolchain that built it, so installing the
  `nails` package through Nix no longer keeps the toolchain (about 2.6 GB) alive.
- The release SBOM records the CVEs that nixpkgs patches musl against as backported fixes in the
  musl component's `pedigree` and gives musl its CPE. A new attested release asset,
  `musl.openvex.json`, marks those CVEs as fixed; scan with
  `grype sbom:sbom.cdx.json --vex musl.openvex.json`.
- The way back keeps the network state the hidden session set up: its links, addresses, routes and
  VPN tunnels stay up in the decoy until power-off, the decoy's NetworkManager records a link it
  adopts, with the time, in `/var/lib/NetworkManager/timestamps` as soon as the decoy starts, the
  random MAC address of the network-identity snippet can stay on the decoy's device, and so can the
  hidden hostname on a decoy without `/etc/hostname`. Take down the connections and tunnels you
  brought up and delete the links you created before deactivating, or end with
  `deactivate --poweroff`; end a session that used the network-identity snippet with
  `deactivate --poweroff` (or `emergency --poweroff`).

## [0.2.0] - 2026-05-08

### Changed

- Bumped the Rust workspace version to `0.2.0`.
- Hardened release publication around immutable tag-based workflows: exact stable tags are
  verification-only, stable publication is deliberate/manual, and prerelease publication is tied to
  suffixed prerelease tags.
- Refined release workflow permissions and repository targeting so GitHub release automation works
  reliably under repository rulesets.

### Fixed

- Created `state.json` during `nails init` and preflight when needed, preventing init/preflight
  flows from missing expected state metadata.
- Fixed release workflow regressions after the immutable-release restructuring.

## [0.1.0] - 2026-04-27

### Added

- Established the Rust workspace split between `nails-cli` and `nails-core`, including shared
  workspace metadata, custom error types, a filesystem abstraction for testing, and the initial
  quality-gate infrastructure.
- Implemented the core lifecycle model: typed state transitions, state-file serialization,
  checksummed state metadata, RAII state guards, and the `NailsManager` orchestration layer.
- Added the preflight validation system with checks for hidden storage readiness, swap exposure,
  available space, overlay directories, current state, NixOS configuration, symlink support, and
  selected flake build targets.
- Implemented activation support for OverlayFS-based hidden sessions, NixOS configuration overlays,
  deterministic mount ordering, reverse-order rollback, process/session handling, display-manager
  restart behavior, and NixOS build/switch integration.
- Added support for flake-based activation via `--flake`, config-fingerprint fast paths,
  missing-only build paths, automatic overlay strategy selection, `/var` overlays, optional `/boot`
  pivoting, and bind-mounted fallbacks for overlay-incompatible targets.
- Implemented deactivation and emergency cleanup flows, including standard reboot-based cleanup,
  emergency no-reboot cleanup, force-unmount fallback behavior, cleanup reporting, and post-cleanup
  verification hooks.
- Added user-facing commands and output for status reporting, verification scans, emergency
  deactivation, progress indicators, verbosity controls, no-color handling, desktop notifications,
  and notification dispatch.
- Added shell integration and forensic-safety support, including prompt/alias management,
  in-memory and on-disk history cleanup, automatic terminal color-scheme switching, structured
  logging, sanitized log paths, and timestamp-based log rotation.
- Added Nix-based end-to-end validation infrastructure covering the basic workflow, emergency
  deactivation, forensic cleanliness, snapshot diffs, and performance scenarios.
- Added reproducible Nix release packaging for the canonical Linux artifact, checksum generation,
  SBOM/supply-chain checks, dependency auditing, coverage gates, and release-path verification.
- Added public project documentation and governance files, including release reproducibility
  guidance, CI documentation, support and security policies, issue templates, code of conduct,
  roadmap updates, and public README guidance.

### Changed

- Migrated the project surface from early prototype planning into a Rust-first implementation with a
  focused CLI crate and domain-oriented core library.
- Refactored the CLI and core library into focused modules for activation, deactivation, cleanup,
  config, filesystem access, logging, manager orchestration, NixOS integration, overlays,
  preflight checks, shell integration, state, status, and verification.
- Reworked CI from the initial pipeline into consolidated, cached workflows using `cargo-llvm-cov`,
  pinned tooling, reusable release/reproducibility jobs, and trusted full E2E validation.
- Replaced deprecated `serde_yaml` usage with `serde-saphyr` and refreshed Rust/GitHub Actions
  dependencies, including `thiserror`, `colored`, `signal-hook`, and Node.js 24-compatible actions.
- Aligned public documentation with the current alpha threat model, release process, support scope,
  NAILS OS separation, artifact format, and AI-assisted development disclosure.

### Removed

- Removed the legacy Python implementation after the Rust migration became the maintained code path.

### Fixed

- Hardened activation and deactivation around partial overlays, same-device submounts, overlay
  permission mismatches, display-manager restart timing, NixOS generation switching, fast-path
  activation, and deactivation base-configuration checks.
- Hardened hidden configuration and hardware-configuration handling to fail earlier and avoid unsafe
  or ambiguous activation states.
- Improved forensic cleanup by addressing shell-history persistence, alias stdout leakage,
  cleanup/log formatting, temporary-file cleanup, and post-deactivation artifact checks.
- Stabilized E2E and unit coverage by serializing fragile switch-to-configuration tests, moving real
  filesystem tests into test-only paths, expanding activation/deactivation guard coverage, and
  bringing measured coverage above the documented threshold.
- Fixed release and CI regressions around workflow permissions, reproducibility comparisons,
  GitHub CLI repository targeting, artifact naming, release tag handling, cargo-sbom output format,
  Dependabot configuration, and pre-commit coverage parity.

### Security

- Added comprehensive shell-history protection and cleanup verification for forensic-safety goals.
- Added SBOM generation, dependency/security audit workflows, cargo-geiger integration, and public
  vulnerability-handling documentation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for public contribution guidance.

[Unreleased]: https://github.com/WitteShadovv/nails/compare/v0.3.0-rc.3...HEAD
[0.3.0-rc.3]: https://github.com/WitteShadovv/nails/compare/v0.3.0-rc.2...v0.3.0-rc.3
[0.3.0-rc.2]: https://github.com/WitteShadovv/nails/compare/v0.2.0...v0.3.0-rc.2
[0.2.0]: https://github.com/WitteShadovv/nails/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/WitteShadovv/nails/releases/tag/v0.1.0
