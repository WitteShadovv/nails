# Threat model

This is the only place the NAILS threat model is written down. The README, the
[operator guide](operator-guide.md) and [SECURITY.md](../SECURITY.md) link here
instead of restating it; per-platform setup lives in
[decoy-requirements.md](decoy-requirements.md).

## Adversary

The adversary gains full, **offline** access to the host's disks and firmware
after the fact — typically after seizing a powered-off device — and runs a
dead-disk forensic analysis to prove that a hidden environment ever existed.
They can image every disk, read every unencrypted block, filesystem journal and
log, inspect the ESP and EFI variables, and compare the decoy against what a
plain installation would contain.

Anything that survives a session and reveals that a hidden mode existed is
evidence, even when the hidden data itself stays encrypted. The adversary does
not need the hidden data; a single trace of its use is enough.

The adversary may also make the operator unlock the decoy once, by legal
order or by demand, and then examine the unlocked decoy offline. That is the
case NAILS is built for: see
[Compelled disclosure of the decoy](#compelled-disclosure-of-the-decoy) for
what it covers there and where it stops.

## Assumptions

The claims below hold only when all of these are true:

- **Outer encryption.** The decoy's disk is protected by full-disk encryption
  whose credentials unlock the decoy and nothing else, so disclosing them (see
  [Compelled disclosure of the decoy](#compelled-disclosure-of-the-decoy))
  does not open the hidden volume, and the hidden volume sits inside a
  deniable backend (for example a VeraCrypt hidden volume). Encryption is not
  provided by NAILS; see [backends.md](backends.md).
- **Amnesic decoy.** The base system keeps no durable record of the hidden
  session: volatile journald, no classic syslog or audit daemon, no persistent
  crash dumps. NAILS enforces the load-bearing parts at pre-flight and fails
  closed otherwise; [decoy-requirements.md](decoy-requirements.md) has the full
  list and how to satisfy it per platform.
- **No swap or hibernation.** Memory pages from the hidden session must never be
  written to a decoy disk.
- **Volatile journald.** The journal lives in RAM only, so what the decoy logs
  around each soft-reboot (the activation command, the decoy's shutdown before
  the switch and its start after the way back; see
  [Residual channels](#residual-channels)) never reaches disk.
- **Storage of its own, prepared elsewhere.** The hidden volume is a device,
  partition or encrypted volume the decoy does not use, created on another
  computer or from a setup medium, never on the decoy itself. NAILS refuses a
  root on the decoy's storage ([the attach gate](#the-attach-gate)) but cannot
  see what creating a volume on the decoy left behind; see
  [Where setup happens](operator-guide.md#where-setup-happens).
- **Trusted root.** The NAILS binary, its configuration and the hidden flake on
  the hidden volume are intact. NAILS runs as root and performs no runtime
  self-integrity check.
- **Clean teardown.** The operator deactivates (or runs `nails emergency`) and
  powers off before the device is seized. Both close the hidden backend
  themselves; powering off clears what a soft-reboot keeps in RAM.
- **systemd 254 or newer.** The hidden session is entered and left with
  `systemctl soft-reboot`; older hosts are refused.

## Out of scope

NAILS does not defend against:

- live compromise of a running system, including while the hidden session is
  active;
- memory forensics during or shortly after use, including cold-boot attacks;
- hardware implants, firmware compromise, or physical surveillance and
  keylogging;
- side channels such as timing, power or electromagnetic analysis;
- coercion beyond a single disclosure of the decoy credentials: compelled
  disclosure of the hidden volume's credentials, physical coercion, and
  repeated or sustained coercion (see
  [Compelled disclosure of the decoy](#compelled-disclosure-of-the-decoy) for
  the line between what is in scope and what is not);
- an adversary who images the disk more than once and compares the images;
- **network-provider logs**: anything an ISP, Wi-Fi operator, VPN provider or
  other network observer records about the host's traffic;
- **remote-service records**: anything a server, cloud service or peer device
  holds about what the hidden session did (accounts, sync state, mail, messages,
  access logs);
- correlation through the network identifiers the hidden session shares with
  the decoy (see the next section);
- operator mistakes such as skipping deactivation or leaving the backend
  mounted.

## Compelled disclosure of the decoy

**In scope.** The adversary obtains the decoy's credentials once (the disk
passphrase, the login password) and examines the unlocked decoy offline, with
the operator absent or uncooperative from then on. This is the dead-disk
adversary above with the outer encryption removed, and it is the case the
forensic claims are made for. What NAILS offers there:

- **No session residue on the decoy, except the residual channels.** After a
  clean teardown the overlays leave nothing of the hidden session on the decoy
  disk beyond the channels in [Residual channels](#residual-channels), each of
  which an amnesic decoy bounds. `verify` and `nails rehearse` let the operator
  check this on their own machine before relying on it.
- **No enabler on the decoy.** The binary, configuration and hidden NixOS
  module live on the hidden volume, and nothing on the decoy knows about them
  (see the [Invariant](#invariant)).
- **A way to see the setup traces.** The decoy unlocked is still a machine
  with encryption tooling, encryption headers and history. NAILS does not hide
  these; `verify --offline --examiner` lists them on a decoy image, grouped by
  what an examiner would conclude, so the operator can remove or explain each
  one before it matters. The classes are in the
  [residue catalog](decoy-requirements.md#setup-traces-an-examiner-looks-for).

What it does not offer:

- **Deniability of the hidden volume itself.** Whether a hidden volume can be
  told apart from random data or an outer volume's free space depends on the
  backend, not on NAILS. A LUKS volume next to the decoy is visibly an
  encrypted volume; a VeraCrypt hidden volume is indistinguishable from its
  outer volume's free space, but the outer volume is visible. NAILS adds
  nothing to the backend's own claim.
- **Compelled disclosure of the hidden volume.** Whoever obtains the hidden
  volume's credentials sees everything: the hidden data, NAILS itself and its
  configuration. Out of scope.
- **Physical coercion.** Deniability does not end coercion: an adversary who
  believes a hidden volume exists can keep demanding credentials whatever the
  operator says, and an operator known to be capable of running a hidden
  volume may not be believed when there is none. Out of scope.
- **Repeated coercion and repeated imaging.** An adversary who images the disk
  twice, before and after further use, can see which encrypted regions
  changed. A hidden volume inside an outer volume that changed while the outer
  volume's files did not is the classic way such volumes are found. Changes on
  the decoy that its own logs do not explain (the
  [session-time records](decoy-requirements.md#session-time-records): the
  timesyncd stamp, timer stamps, SMART power-on hours) also accumulate across
  sessions. Out of scope.
- **An examiner who knows NAILS.** NAILS is public, and nothing here relies on
  the examiner not knowing it. A knowledgeable examiner looks for its artifact
  registry, a sudo record naming a binary on another volume, encryption
  tooling with recent access times and random-looking disk space. NAILS keeps
  the first off the decoy and reports the others; whether the remaining
  traces have a plausible explanation is the operator's to establish, and the
  examiner may still believe a hidden volume exists without being able to
  prove it.

What the operator must do for the in-scope case to hold:

- Use a deniable backend, and keep the decoy credentials separate from the
  hidden volume's, so disclosing one never opens the other.
- Run an amnesic decoy ([decoy-requirements.md](decoy-requirements.md)),
  deactivate cleanly and power off before the machine can be taken.
- Before relying on the setup, run `nails rehearse` on the real machine and
  `verify --offline --examiner` against an image of the decoy, and remove or
  be ready to explain every trace they report.
- Keep the decoy in plausible, regular use, so its logs account for the time
  the machine ran.
- Assume that a second examination, or coercion that goes beyond handing over
  the decoy once, is not something NAILS can help with.

## What the hidden environment shares with the decoy

The whole-root overlay isolates **writes to the on-disk filesystems**: in the
hidden session every process runs inside an overlay of the decoy root whose
upper is on the hidden volume, so every write through the decoy's mounts lands in
the upper; only what goes around the mount layer, listed under
[Residual channels](#residual-channels), reaches the decoy. It does not give the
hidden environment a separate
machine, kernel, account or online identity: the hidden userspace is the decoy's
own system (or, on NixOS, a hidden generation of it) started again on the same
kernel, with the decoy's units, accounts and configuration plus whatever the
upper changes.

- **Account and home.** In the default `shared-home` persona the hidden session
  runs as the decoy user, in the decoy home seen through the overlay. The
  decoy's browser profiles, SSH/GPG keys, password-manager state and history
  are live in the hidden session; changes land in the upper. The opt-in
  `fresh-home` persona gives the operator an empty (opaque) home in the upper
  instead, so the decoy home is not visible; see
  [Persona modes](configuration.md#persona-modes) and the
  [operator guide](operator-guide.md#shared-decoy-account-and-persona-modes).
  A separate hidden account does not exist yet.
- **Inherited system and user units.** Every decoy system service the decoy
  enables starts again in the hidden session (unless a hidden NixOS
  configuration changes it), and in `shared-home` the hidden session also
  inherits the decoy account's autostart entries, enabled user services and
  timers, lingering and display-manager autologin. `nails check` inventories
  them, and `[persona] mask_inherited` writes masks for autostart entries and
  user units into the upper at entry, so they never run in the hidden session.
  Lingering and autologin are reported, not masked.
- **Network identity.** The overlay does not change machine-id, hostname, MAC
  addresses or NetworkManager profiles (including VPN autoconnect). The kernel
  keeps its interfaces and addresses across the soft-reboot; the network
  daemons restart and reconnect. An optional hidden network-identity
  configuration (random MAC, distinct hostname; VPN autoconnect disabled per
  profile) can be applied in the hidden NixOS generation or as a NetworkManager
  drop-in in the upper. It is opt-in.
- **Remote state, never rolled back.** Deactivation leaves the upper on the
  hidden volume and changes nothing else. Anything the hidden session sent through a
  shared account, token or sync client lives on the remote, and a decoy sync
  client can pull it back onto the decoy disk after deactivation. Masking
  changes what runs; it never reaches the remote side. See
  [Remote state and sync clients](operator-guide.md#remote-state-and-sync-clients).

## Invariant

**No hidden-mode enabler may persist on the decoy.** A boot entry, initramfs
hook, config file or EFI NVRAM variable that enables the hidden mode is itself
evidence, even when the hidden data stays encrypted. Everything NAILS needs to
start a hidden session lives on the hidden volume, and the decoy carries no hook
that knows about it.

For the bootloader this means: activating and then deactivating the hidden
environment must not change any boot entry, ESP file or EFI NVRAM variable
relative to a plain reboot.

How the code upholds this:

- **Everything is set up at runtime from the hidden volume.** The next root,
  the session plan, the transition drop-in and the runtime units live in RAM
  (`/run`) and the hidden volume only; the transition step removes them on the
  way back. Nothing is installed on the decoy disk.
- **The ESP is read-only in the hidden root.** The fstab policy binds the ESP
  and other boot filesystems read-only into the next root before the switch, so
  no hidden process (a bootloader install, `systemd-boot-random-seed`, a
  `grub-reboot`) can write it.
- **Activation never installs.** On NixOS the hidden generation is built into
  the next root's store and only its `activate` script runs, chrooted;
  `/run/current-system` is repointed for the switch. No `switch-to-configuration
  switch` or `boot` runs, and the system profile is not changed. The boot
  default therefore always remains the decoy.
- **Deactivation never installs.** It soft-reboots back into the plain decoy
  root, repointing `/run/current-system` to the decoy's toplevel; no firmware or
  bootloader is involved.
- **No decoy entry opens the hidden volume.** A line in the decoy's
  `/etc/crypttab` or `/etc/fstab` that opens or mounts the hidden volume (or a
  device it is stored on), or carries `tcrypt-hidden`, is such an enabler: the
  `backend-entries` pre-flight check refuses activation while one exists, and
  no flag overrides it: `activate --no-preflight` still runs it on its own. A
  line that opens only another volume on the same drive warns.

This invariant is checked by the end-to-end tests `uefi-esp-nvram-invariant`
and `soft-reboot-mechanics`: they hash the ESP file listing and capture the EFI
variable list (`efibootmgr -v` / efivarfs) before activation and after
deactivation, and assert both are unchanged relative to a plain-reboot control
(apart from `loader/random-seed`, which the decoy's own start refreshes, as any
boot does).

## The attach gate

Every write NAILS makes goes to the hidden root, so every claim above assumes
that the hidden root is storage of its own. One gate decides that before
anything is written: `init`, `activate`, `check`, the log file, the state file
and its lock, the staged NixOS configuration, the residue baseline and the
rehearsal state all ask it first. It refuses:

- a root that is not a mount point (a folder of `/`, `/home` or any other
  filesystem): `init` refuses before it probes the folder, so its timestamps do
  not change either;
- a root that this computer's own storage holds: a btrfs subvolume or a bind
  mount of a filesystem the decoy mounts, the filesystem the decoy's fstab
  mounts there, a logical volume or other device stacked on the decoy's
  storage or swap, or an unencrypted image file on a decoy filesystem;
- a root with a second filesystem mounted over it (`root_covered`), and in the
  hidden session a root whose filesystem is not the one the session started
  from: the writes would reach the disk on top;
- a root whose storage cannot be judged because `/etc/fstab`, `/etc/crypttab`
  or the block devices in sysfs cannot be read (`storage_unjudged`; run the
  command with sudo), or because its filesystem shows no disk it stores its
  data on: an overlay, a FUSE or network filesystem, or an image file on one
  (`storage_unjudged`).

An encrypted container file on a decoy filesystem only warns: filesystem
journals and copy-on-write snapshots of that filesystem can keep old copies of
the parts of the container that changed. `--allow-unmounted` (on `init`,
`activate` and `check`) turns the refusal of the decoy's storage into a
warning; activation then repeats it in the logout confirmation, the session
plan records it for `status`, and `rehearse plant` refuses, since a rehearsal
on that storage cannot pass. The override never covers a folder, a covered
root, storage that cannot be judged, or `backend-entries`. `--no-preflight`
does not skip the gate.

In the hidden session, `deactivate` refuses a covered root with `root_covered`:
it would write its state onto the disk on top. `emergency` always runs, with or
without the state lock; when the mounts the way back needs are covered too, it
powers off instead of returning to the decoy. The session watcher writes no
probe onto a covered root.

The gate's limits: it judges the storage this computer's mount table, fstab,
crypttab and sysfs describe. It cannot see a decoy filesystem mounted only by
hand and never listed, storage another operating system on the same machine
uses, or a remote block device's other users. Nor can it see the traces that
creating the volume on this computer left behind (the setup tools' own files,
shell history, a changed partition table): only preparing the volume elsewhere
avoids them. A refusal names the storage and says nothing was written. The
override is for storage the gate takes for the decoy's that the operator knows
the decoy does not use (for example a disk its fstab lists but never mounts);
everything written there lands on that storage.

## Residual channels

The whole-root overlay cannot cover these. Each is either bounded by an
assumption above or documented as a known gap. The table is generated from the residue catalog
(`nails-forensics/src/residue_catalog/rows.rs`), which also holds the classes the
overlay does cover; [decoy-requirements.md](decoy-requirements.md#residue-catalog)
has the whole catalog.

<!-- residue-catalog:begin residual -->
| Channel | Why it survives the overlay | Bounded by | Detected by |
|---|---|---|---|
| [Journal window around each soft-reboot](decoy-requirements.md#the-sudo-log-exposure-and-its-mitigation) | The sudo command line, the hidden build's progress and the decoy's own shutdown and start are logged by the decoy journal, under one boot ID with a soft-reboot gap. | Run on a volatile journal, so the window stays in RAM; keep the binary at a neutral path. | `journal-scan` |
| [sudo log file](decoy-requirements.md#the-sudo-log-exposure-and-its-mitigation) | `Defaults logfile=` writes every sudo command line, including the activation command and binary path, to a file on the decoy disk. | Remove `Defaults logfile=` from sudoers and sudoers.d. | path probe (warn) |
| [sudo I/O logging](decoy-requirements.md#the-sudo-log-exposure-and-its-mitigation) | `log_input`, `log_output` or the LOG_INPUT/LOG_OUTPUT tags record whole terminal sessions, keystrokes and output included, under iolog_dir on the decoy disk. | Remove every I/O logging option and tag from sudoers and sudoers.d. | path probe (warn) |
| [Disks mounted during the hidden session](configuration.md#disks-mounted-during-the-session) | A disk the hidden session mounts itself is a real disk outside every overlay: a read-write mount takes the session's writes, and mounting it rw already writes its superblock. | The session watcher alerts on every read-write disk mount outside the hidden volume; `[session_mounts] read_only` makes every disk the session does not use read-only at the block layer for the session; deactivate unmounts them and the way back makes them writable again. | none: verify cannot tell what a session wrote to another disk |
| [Hidden kernel records imported by the decoy journal](#residual-channels) | Records logged after the hidden journald stopped (PID 1's stop lines, a late /dev/kmsg writer) would be imported by the decoy journal, on disk with a persistent journal. | The transition step writes the decoy journald's kmsg cursor past every hidden record; only PID 1's last generic lines and the hidden filesystem's unmount line follow it. | `journal-scan` |
| [Soft-reboot counter and boot ID](#residual-channels) | Anyone with a shell sees two soft-reboots per session; a persistent decoy journal shows a shutdown and start under one boot ID. | Power off after the session; keep the decoy journal volatile. | none: RAM only, gone at power-off |
| [EFI NVRAM, RTC and firmware pstore](#invariant) | These are not filesystem writes, so the overlay cannot redirect them; other software in the session can write them. | NAILS never writes NVRAM; avoid firmware tools inside the session. | none: EFI variables and firmware storage are not part of a disk image |
| [Memory remanence](operator-guide.md#cold-boot-and-running-memory-attacks) | RAM holds hidden-session data until the machine is powered off; a warm reboot does not clear it. | Power off (`--poweroff`) before handing the machine over; boot the decoy with init_on_free=1. | `memory-swap` |
| [timesyncd clock stamp](decoy-requirements.md#session-time-records) | systemd-timesyncd touches this file at every sync and at shutdown, so its mtime records when the machine last ran, which can fall after the decoy's last logged activity. | Session touches land in the upper; on a persistent decoy, use the decoy normally after a session so its own activity follows the stamp. | path probe (info) |
| [Persistent timer stamps](decoy-requirements.md#session-time-records) | Persistent=true timers stamp their last run; a stamp from the session, or a catch-up run at the next decoy boot, dates the session. | Session stamps land in the upper; expect catch-up runs at the next decoy boot. | path probe (info) |
| [SMART power-on hours](decoy-requirements.md#session-time-records) | The drive counts every hour it runs; hours the decoy's logs do not account for point to unlogged use. | None in software; use the decoy normally so its logged uptime is plausible. | none: a disk image does not carry SMART counters |
| [SSD flash-translation-layer remnants](operator-guide.md#ssd-wear-levelling) | Old copies of rewritten blocks survive in cells the host can no longer address; a chip-off read can recover them. | Full-disk encryption on the decoy, so remnants are ciphertext; no TRIM on a volume that holds a hidden volume. | none: no host-side read reaches remapped flash cells, so `nails rehearse` cannot see them either |
<!-- residue-catalog:end residual -->

## Answer to "cannot trust the OS"

A common argument, made for example by the Shufflecake authors, is that hiding
a whole operating system by customising it to avoid leaks is hopeless: every
application, daemon and indexer may write somewhere, and auditing them one by
one never ends.

NAILS does not tune individual applications. It redirects **every write outside
pseudo filesystems at the mount layer**: the hidden session runs entirely inside
one overlay of the decoy root (and an overlay of each other decoy filesystem),
so whatever program writes — known or unknown — writes into an upper on the
hidden volume. No process of the hidden session reaches a decoy filesystem
through its mounts, because every one of them starts inside the overlay after a
soft-reboot. The question "which application leaks?" becomes "which writes
bypass the mount layer?", and that set is small and enumerable: the residual
channels listed above, and the decoy filesystems the fstab policy has to
handle. Residual risk is limited to those channels and
to the shared state in the previous section, which the overlay does not claim to
isolate. All of this assumes the upper is on storage of its own, which
[the attach gate](#the-attach-gate) checks before the first write; an upper on
the decoy's own storage would put every redirected write back on its disk.

## Known residual changes

**`/var/lib/nixos` drift: settled by design, pending a VM run.**

On a NixOS decoy, `/var/lib/nixos` holds the declarative account bookkeeping
(`declarative-users`, `declarative-groups`, `uid-map`, `gid-map`,
`auto-subuid-map`). An earlier evaluation of the live-overlay design saw these
files rewritten across a hidden session, without a control run.

In the whole-root session `/var/lib/nixos` is part of the root overlay (or of
an overlay over its own filesystem): the hidden generation's activation and
every later write go to the upper on the hidden volume. The VM test
`session-nixos-hidden-system` (`nix/e2e-tests/tests/session/session-nixos-hidden-system.nix`)
enters a hidden generation that declares a canary user and group
(`hiddencanary`, uid/gid 64123), proves the canary is live in the hidden
session, and asserts that after the way back the decoy's `/var/lib/nixos`,
`/etc/passwd` and `/etc/group` are byte-identical to before. This section is
closed once that test has run on a Nix host
(`nix build .#legacyPackages.x86_64-linux.e2e.session-nixos-hidden-system`).

## Evaluation scope

The forensic claims rest on this configuration:

- a NixOS decoy with a **tmpfs root** and only `/persist` (plus the Nix store)
  on disk (an impermanent root like this is refused by the whole-root session,
  whose way back mounts the decoy root by device; this evaluation predates it
  and must be repeated on a disk-backed decoy root);
- **no swap**, and volatile journald;
- a **VeraCrypt hidden volume** with ext4 inside, opened with
  `cryptsetup open --type tcrypt --tcrypt-hidden`, as the hidden backend;
- **dead-disk analysis** of the powered-off decoy disk image.

That full configuration was evaluated manually, once. The automated E2E
disk-image checks cover NixOS VMs with a **LUKS2/ext4** hidden backend and, in
the VeraCrypt backend test, a **VeraCrypt hidden volume** opened with
`cryptsetup`, plus the Debian 13 and Ubuntu 24.04 smoke runs. Other backends
and filesystems, and physical hardware (time to the greeter, GPU and Wi-Fi after
the soft-reboot, TPM-sealed decoy roots, GRUB) are not covered; see
[backends.md](backends.md) for the per-backend status. Claims outside this scope
are unverified.
