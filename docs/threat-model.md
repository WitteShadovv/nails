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
  session: volatile journald, no classic syslog or audit daemon, no daemon
  that logs its own stop and start to a file of its own, as tuned with its log
  option does, no persistent crash dumps. NAILS enforces the load-bearing parts
  at pre-flight and fails closed otherwise, and warns of what it judges
  weaker, such as firewalld's log file and ABRT's crash reports;
  [decoy-requirements.md](decoy-requirements.md) has the full list and how to
  satisfy it per platform. A daemon NAILS does not know of can still write to
  the decoy disk as it stops for the switch into the session.
- **No swap or hibernation.** Memory pages from the hidden session must never be
  written to a decoy disk.
- **Volatile journald.** The journal lives in RAM only, so what the decoy logs
  before the switch (the activation command, the decoy's own shutdown) never
  reaches disk. The hidden session writes the same runtime journal. The
  power-off at the end of the session ends both. See
  [Residual channels](#residual-channels).
- **Storage of its own, prepared elsewhere.** The hidden volume is a device,
  partition or encrypted volume the decoy does not use, created on another
  computer or from a setup medium, never on the decoy itself. NAILS refuses a
  root on the decoy's storage ([the attach gate](#the-attach-gate)) but cannot
  see what creating a volume on the decoy left behind; see
  [Where setup happens](operator-guide.md#where-setup-happens).
- **Trusted root.** The NAILS binary, its configuration and the hidden flake on
  the hidden volume are intact. NAILS runs as root and performs no runtime
  self-integrity check.
- **Clean teardown.** The operator ends the session with `deactivate` or
  `nails emergency` before the device is seized. Both power the machine off,
  and the shutdown closes the hidden backend. RAM keeps data for a while after
  the power-off, so the machine stays off for a few minutes before it is
  handed over. See [How a session ends](#how-a-session-ends).
- **systemd 254 or newer.** The hidden session is entered with
  `systemctl soft-reboot`. Older hosts are refused.

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
- **de-anonymisation by a network observer**: NAILS provides no network
  anonymity and routes nothing through Tor — the hidden session reaches the
  network over the decoy's own IP address and connection. Anonymity is a
  separate goal; for it, use a tool built for it, such as Tor Browser, Tails or
  Whonix (see
  [What the hidden environment shares with the decoy](#what-the-hidden-environment-shares-with-the-decoy));
- **network-provider logs**: anything an ISP, Wi-Fi operator, VPN provider or
  other network observer records about the host's traffic;
- **remote-service records**: anything a server, cloud service or peer device
  holds about what the hidden session did (accounts, sync state, mail, messages,
  access logs);
- **decoys joined to a domain** (Active Directory or FreeIPA, through sssd):
  the domain controller keeps its own records of the hidden session's logins
  and account lookups, out of NAILS's reach, and NAILS is not tested on such
  decoys. `nails check` and activation warn while sssd is in use on the decoy
  (see [Decoys joined to a domain](decoy-requirements.md#decoys-joined-to-a-domain));
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
  which an assumption or a documented mitigation bounds. `verify` and
  `nails rehearse` let the operator check this on their own machine before
  relying on it.
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
  encrypted volume. VeraCrypt's own claim is conditional: a
  [hidden volume](https://veracrypt.jp/en/Hidden%20Volume.html) should be
  impossible to prove exists *provided its requirements are followed*. Its
  [Security Requirements for Hidden Volumes](https://veracrypt.jp/en/Security%20Requirements%20for%20Hidden%20Volumes.html)
  note that an adversary who sees the volume at several points over time may
  still find signs of one, and so may one who reads the old copies a
  wear-levelling device keeps; its page on the
  [trim operation](https://veracrypt.jp/en/Trim%20Operation.html) says that
  TRIM shows which sectors are free and can weaken deniability. The outer
  volume is in any case visible. NAILS adds nothing to the backend's own
  claim.
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
- Keep the hidden volume off a partition whose type systemd mounts or uses as
  swap at boot, and its outer volume closed or read-only while the
  hidden one is in use: `backend-partition-type` refuses or warns about the
  first, `outer-volume` warns about the second
  ([backends.md](backends.md#partition-type-in-preflight)).
- Run an amnesic decoy ([decoy-requirements.md](decoy-requirements.md)),
  deactivate before the machine can be taken, and leave it off for a few
  minutes.
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
  Activation makes that home directly in the upper, before the overlay is
  mounted, so it looks up and makes each directory on the way inside the
  upper without following a symbolic link: a link a hidden session left
  there in place of `/home` or a directory below it, absolute or relative,
  could otherwise lead the new home, its mode, owner and opaque attribute
  onto the decoy disk. Such a link refuses the activation.
  A separate hidden account does not exist yet.
- **Inherited system and user units.** Every decoy system service the decoy
  enables starts again in the hidden session (unless a hidden NixOS
  configuration changes it), and in `shared-home` the hidden session also
  inherits the decoy account's autostart entries, enabled user services and
  timers, lingering and display-manager autologin. `nails check` inventories
  them and reports those that need review (anything the desktop or the
  distribution does not ship, and known trace writers such as sync clients),
  and `[persona] mask_inherited` writes masks for autostart entries and user
  units into the upper at entry, so they never run in the hidden session.
  Lingering and autologin are reported, not masked; autologin logs the account
  in again at the switch into the hidden session (Plasma Login Manager 6.7 and later, on systemd 256
  and later, only with `Relogin=true`), and can be turned off in the hidden
  session's own configuration (see the
  [operator guide](operator-guide.md#inherited-autostart-services-and-autologin)).
- **Network identity.** The overlay does not change machine-id, hostname, MAC
  addresses or NetworkManager profiles (including VPN autoconnect). The hidden
  session shares the decoy's network identity by design and reaches the network
  over the decoy's own IP address and connection: NAILS does not anonymise
  network traffic and will not route the session through Tor by default.
  Anonymity against a network observer is a different goal, out of scope here;
  for it, use a tool built for it — Tor Browser, Tails or Whonix (NAILS is
  itself installed from [Tails](install-from-tails.md)). Running Tor Browser or
  a Whonix gateway inside the hidden session is possible but carries a
  deniability caveat; see
  [Network anonymity and Tor](operator-guide.md#network-anonymity-and-tor). The
  kernel keeps its interfaces and addresses across the soft-reboot into the
  session, so the hidden session starts with the decoy's network state, and the
  network daemons restart and reconnect. An optional hidden network-identity
  configuration (random MAC, distinct hostname, VPN autoconnect disabled per
  profile) can be applied in the hidden NixOS generation or as a
  NetworkManager drop-in in the upper. It is opt-in. The session ends in a
  power-off, so nothing it set up in the kernel (links, addresses, a random
  MAC, firewall tables) reaches the decoy, which boots afresh.
- **SELinux labels.** On a host that runs SELinux, activation gives two kinds
  of directory on the hidden volume the label of the decoy directory they
  stand for: the root of each upper, which becomes the hidden `/` or the root
  of an overlaid decoy filesystem, and each directory the upper holds below it
  on the way to the operator's home. It only reads the decoy's labels, without
  changing anything on the decoy, and writes each one onto the hidden volume
  before the overlay over that upper is mounted. No other directory NAILS
  makes on the hidden volume takes a label from the decoy, and on a volume
  nobody relabelled each of them shows as `unlabeled_t`. Among them are
  `root`, `root/mounts/<unit>` and the work directories (`root/work`,
  `root/mounts/<unit>/work`), which the hidden session sees through the hidden
  volume's bind at its path, and, where `init` was given `--hardware-config`,
  the hidden `/etc/nixos` it makes in the root upper for the hidden NixOS
  configuration, with the hidden `/etc` where it made that too. Where a label
  cannot be copied, activation is refused (see the
  [decoy requirements](decoy-requirements.md)). Before any of this, `check`
  and activation refuse a host where SELinux runs unless `lsm-status` finds it
  running the targeted policy with NAILS's processes where they can do their
  work (next item).
- **The SELinux label of NAILS's program in RAM.** On a host whose kernel may
  run SELinux, NAILS gives every copy of its binary that PID 1 starts its
  steps from, in `/run`, the label of the system's programs, so that the
  loaded policy starts those steps in its unconfined service domain rather
  than in PID 1's confined one. It writes that label onto those copies alone,
  in RAM, and installs nothing into the decoy's policy and writes nothing to
  its disk for it. The copies go with the rest of the session's `/run` at the
  power-off. The activation is refused where the loaded policy would not start
  the steps as they need. `check` and activation ask the loaded policy the same before anything else
  (`lsm-status`), and where `[session_mounts] read_only` is on, also whether
  it grants the domain udevd starts the disk guard in, `udev_t` under a
  targeted policy, every operation the guard makes: where it does not, the
  guard could leave a disk that appears in the session writable, and the host
  is refused. That question leaves out the policy's rules for single `ioctl`
  numbers, which selinuxfs does not answer, and the labels a relabel of `/run`
  would give the guard's files, so a policy that denies the guard only there is
  not refused. Fedora, whose hosts run SELinux by default, is not admitted yet,
  so this applies only where a host of a family NAILS admits runs SELinux. A
  switch at which PID 1 loads the policy anew gives the copies in `/run` the
  label of the files there again, so the units PID 1 starts from a copy after
  a switch check their own domain. So does the last step of the switch into
  the session, which an `SELinuxContext=` given to
  `systemd-soft-reboot.service` or a relabel after the arm would start
  elsewhere. One that runs outside the unconfined service domain gives its
  copy the label again and starts itself again from it. Where one still runs
  outside it, the watcher, the sleep guard and the last step power the machine
  off (see the [decoy requirements](decoy-requirements.md)).
- **Remote state, never rolled back.** Deactivation leaves the upper on the
  hidden volume and changes nothing else. Anything the hidden session sent through a
  shared account, token or sync client lives on the remote, and a decoy sync
  client can pull it back onto the decoy disk at the decoy's next boot. Masking
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
  the session plan, the transition drop-in, the runtime units and the masks
  live in RAM (`/run`) and the hidden volume only, and the power-off at the end
  of the session clears what is in RAM. Nothing is installed on the decoy
  disk.
- **The ESP is read-only in the hidden root.** The fstab policy binds the ESP
  and other boot filesystems read-only into the next root before the switch, so
  no hidden process (a bootloader install, `systemd-boot-random-seed`, a
  `grub-reboot`) can write it.
- **Activation never installs.** On NixOS the hidden generation is built into
  the next root's store and only its `activate` script runs, chrooted;
  `/run/current-system` is repointed for the switch. No `switch-to-configuration
  switch` or `boot` runs, and the system profile is not changed. The boot
  default therefore always remains the decoy.
- **Deactivation never installs.** It powers the machine off. No firmware or
  bootloader setting changes, and the decoy boots from power-on as it always
  does.
- **No decoy entry opens the hidden volume.** A line in the decoy's
  `/etc/crypttab` or `/etc/fstab` that opens or mounts the hidden volume (or a
  device it is stored on), or the container file or image the volume is stored
  in, by its path or by any path to the same file (a hard link, a bind of its
  folder; not a path through a FUSE view or an overlay of its folder, which
  shows another device and inode), or carries `tcrypt-hidden` for a
  device on its drive or one that cannot be found, is such an enabler, and so is
  one that has the boot write to a device of the hidden drive, its whole disk, a
  partition of it or a device stacked on one of these, through an option such as
  `journal_path=`, `tpm2-device=` or a device it reads a header from, or over
  the device it names itself (`x-systemd.makefs`, a crypttab line's `swap`,
  `tmp`, plain mode or a header kept apart from it): the `backend-entries`
  pre-flight check refuses activation while one exists, among the lines it reads
  (the decoy requirements list what it reads and what it lets pass). No flag
  overrides the check, except that for a root `--allow-decoy-storage` accepted
  as a folder or a btrfs subvolume of a filesystem the decoy uses, the check
  lets be the decoy's own fstab lines that the boot mounted at `/` or at a
  system folder, a folder below `/var` or `/.snapshots` among them, outside the
  hidden root for another part of that filesystem, while the mount there shows
  it, never one that mounts the volume itself, and, while the decoy mounts
  another part of that filesystem at `/` or by such a line, the crypttab lines
  the boot opens as LUKS for the LUKS device it lies on, never a `noauto` one,
  one with `tcrypt-hidden`, `swap` or `tmp`, one that opens the device in
  another mode or one for any other device. A TrueCrypt or VeraCrypt line that
  opens only another volume on the same drive warns, unless it has the boot
  write over that drive.

This invariant is checked by the end-to-end tests `uefi-esp-nvram-invariant`
and `soft-reboot-mechanics`: they hash the ESP file listing and capture the EFI
variable list (`efibootmgr -v` / efivarfs) before activation and after the
session, and assert both are unchanged relative to a plain-reboot control
(apart from `loader/random-seed`, which the decoy's own start refreshes, as any
boot does).

## How a session ends

A hidden session never goes back to the decoy. The kernel that ran it holds
traces of it in its memory, its kernel log, its network state, its process
counter and its `/run`, and a decoy started again on that kernel would take
them in. So every ending powers the machine off:

- `deactivate` stops every hidden program in order and powers off. It refuses
  while a program blocks shutdown.
- `nails emergency` kills every hidden program and powers off. With `--reboot`
  it reboots fully instead, through the firmware, so the decoy boots afresh
  there too.
- The session watcher, the sleep guard and the window's Emergency control
  power off. The window can be set to reboot fully instead.
- A switch that hangs past systemd's 30-minute job timeout powers off. The
  guard for this stays for the whole session.
- The last step before the switch into the hidden session powers off on any
  failure. In a hidden session every soft-reboot powers off, whatever sits at
  `/run/nextroot`. On the decoy it lets the switch go on only where NAILS
  staged nothing in this boot (no session plan), where nothing was armed and
  nothing waits at `/run/nextroot`, or where a tree nobody armed sits there and
  can be detached with nothing left mounted. Two parts of the entry are best
  effort: the masks of the units the hidden root does not need, which fail or
  do nothing there (the boot filesystems they would write to are bound
  read-only), and the cleanup of `utab`, which lives in RAM.

After a session the decoy boots from power-on, as after any power cycle. The
traces a soft-reboot back into the decoy would leave (the soft-reboot count,
the import of the hidden kernel log, what journald's sockets carry over, the
process counter, the session's network state, the login and boot records of a
soft-reboot, what the session kept in `/run`) do not arise from ending a
session. The entry is still a soft-reboot of the decoy, and the decoy's
shutdown before it writes what any shutdown writes (see
[Residual channels](#residual-channels)).

The limits:

- A failed entry or a failed check leaves the machine off, not at the decoy's
  login, and nothing on the screen says why. Where it can, NAILS keeps the
  reason on the hidden volume, and `status` shows it once the volume is open
  again. A failure before the session plan can be read keeps no reason.
- A root user in the hidden session who runs `systemctl --force soft-reboot`
  while a tree is mounted at `/run/nextroot` skips every unit and the last
  step: PID 1 switches straight into the tree. NAILS cannot stop root from
  doing that, and nothing of NAILS does it.
- The drop-in, the timeout guard and the masks live in `/run`. A root user in
  the hidden session can remove them, and a soft-reboot then runs without the
  last step.
- A NAILS tree at `/run/nextroot` whose runtime directory someone deleted by
  hand looks like no plan, and a soft-reboot enters it like any other tree.
  NAILS itself always detaches the tree before it removes that directory.
- A tree that an activation left on the decoy before it armed the switch turns
  a later plain `reboot` into a soft-reboot (systemd 255 and newer). The last
  step detaches it, and the decoy then starts its userspace again in place,
  with the records a soft-reboot writes. Run `nails recover` after an
  interrupted activation to remove such a tree.
- RAM keeps data for a while after the power-off, which a cold-boot attack can
  read. Leave the machine off for a few minutes before you hand it over.

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
  mounts there, a logical volume, a device-mapper mapping, an md array or a
  loop device stacked on the decoy's storage or swap, or an unencrypted image
  file on a decoy filesystem, a partition of one attached with `losetup -P`
  and an image file in a filesystem that one holds included;
- a root with a second filesystem mounted over it (`root_covered`), and in the
  hidden session a root whose filesystem is not the one the session started
  from: the writes would reach the disk on top;
- a root whose storage cannot be judged because `/etc/fstab` or `/etc/crypttab`
  cannot be read (`storage_unjudged`; run the command with sudo), or the block
  devices in `/sys/class/block`, or the devices of a btrfs filesystem in
  `/sys/fs/btrfs`, cannot be listed (`storage_unjudged`; run it as root on the
  host, with `/sys` mounted), or because its filesystem shows no
  disk it stores its data on: an overlay, a FUSE, network or ZFS filesystem, or
  an image file on one that the decoy neither mounts at `/` or a system folder
  such as `/home` nor lists in its fstab (`storage_unjudged`), or because it
  lies on a partition whose disk the kernel does not show
  (`storage_unjudged`; run the command on the host, with `/sys` mounted), or
  because its data reaches a ZFS volume, or a disk whose driver the kernel
  does not name or `/proc/devices` cannot be read to tell
  (`storage_unjudged`; see below);
- a root whose data reaches a network or userspace block device, `nbd` or
  `ublk` (`not_separate_volume`): a program serves such a device, and nothing
  on this computer shows where the program keeps the data, which can be an
  image file on the decoy's disk;
- a root on an image file that no filesystem mounted here holds
  (`storage_unjudged`). The filesystem that holds an image file is the one on
  the device the loop driver recorded for the file, not the one its path leads
  to now, so a filesystem mounted over the image's folder cannot make it look
  separate. Reading that record needs root (`storage_unjudged`; run the
  command with sudo).

The gate follows what sysfs shows below a device. A root on a partition of a
loop device, a device-mapper mapping or an md array is judged as one on that
device, which holds the partition's data, but two partitions of one disk or md
array share nothing: a partition the decoy uses does not make another one
beside it the decoy's. Some disks show nothing below them in sysfs: a network
block device (`nbd`, as `qemu-nbd` serves an image file), a userspace block
device (`ublk`) and a ZFS volume (`zvol`), whose data lies in its pool. The
gate tells them by the driver `/proc/devices` lists for their device number
(`nbd`, `zvol`), and a `ublk` disk, whose number comes from a range the kernel
shares between drivers, by the name its driver gives it (`ublkb<N>`). It
refuses a root whose data reaches one wherever it sits on the way down: the
disk itself, a partition of it, an encrypted mapping, a logical volume or an
md array on it, or an image file on a filesystem on it, a filesystem of the
decoy's included. A filesystem's way down starts at every device it keeps data
on, not only the one it is mounted from: an XFS log or realtime device, which
its mount options name, an ext3 or ext4 journal on a device of its own, which
jbd2 lists in `/proc/fs/jbd2` and the filesystem's journal thread names, and
the other devices of a bcachefs filesystem, which its source names. The gate
weighs those devices as it weighs the one the filesystem is mounted from, for
the root, for a filesystem that holds an image file on the root's way and for
the filesystems the decoy has mounted, and it refuses a root
(`storage_unjudged`) when one of them cannot be read or found. It refuses a
root just the same when it cannot tell what a disk on that way is: when
`/proc/devices` cannot be read (run the command where `/proc` is mounted), or
names no driver for the disk's number, when sysfs does not list a device that
another names below it or cannot list what lies below a device, or when a loop
device shows no file (as for a path longer than the kernel shows). The range
of numbers the kernel shares between drivers names no driver either, so a disk
on it that sits below no other device in sysfs, a `ublk` disk aside, is
refused as one whose driver the kernel does not name (a zoned loop device,
`zloop`, keeps its zones in files that sysfs does not show), while an NVMe
disk, below its controller or its multipath subsystem, counts as one of its
own. It refuses a ZFS volume, and a disk or a way down it cannot tell, before
it weighs the decoy's storage, so the override lifts that refusal for no root,
not even one on a filesystem of the decoy's that lies on such a volume. An
image file on a filesystem of the decoy's that lies on an `nbd` or `ublk`
device is refused as an image file on that filesystem; an encrypted container
there, which would only warn on another disk, is refused as on the device. A
loop device over the node of a device outside `/dev` lies on that device, as
the loop driver's record shows, and a `zram` device on the device it writes
pages back to, if it has one. A disk the root's data does not reach changes
nothing, and the gate takes an ordinary disk, an iSCSI disk (a SCSI disk to
the kernel) and a `zram` device that writes nothing back for disks of their
own. When the filesystem that holds the root's image file lies in an image
file itself, the gate judges that file as it judges the root's own, as deep as
such files go.

An encrypted container file on a decoy filesystem only warns (unless that
filesystem lies on a ZFS volume or an `nbd` or `ublk` device, see above):
filesystem journals and copy-on-write snapshots of that filesystem can keep old
copies of the parts of the container that changed. `--allow-decoy-storage` (on
`init`, `activate`, `check` and `discard`) turns the refusal of the decoy's
storage into a warning; activation then repeats it in the logout confirmation, the session
plan records it for `status`, and `rehearse plant` refuses a root the override
accepted: on the decoy's storage a rehearsal cannot pass, and on a disk a
program serves nothing shows where the canary lands. It also turns the refusal of an `nbd` or `ublk`
device into a warning, for one you know is served from storage the decoy does
not use, such as another computer. The override never covers a folder, a
covered root, a root whose files another mount of its filesystem reaches too
(one that neither `/` nor a line of the fstab makes), storage that cannot be
judged (a ZFS volume among it), or `backend-entries`, except that for a root it
accepted as a folder or a btrfs subvolume of a filesystem the decoy uses, that
check lets be the decoy's own fstab lines that the boot mounted at `/` or at a
system folder, a folder below `/var` or `/.snapshots` among them, outside the
hidden root for another part of that filesystem, while the mount there shows
it, and the crypttab lines without `tcrypt-hidden`, `swap` or `tmp` that the
boot opens as LUKS for the LUKS device that filesystem lies on while the decoy
mounts another part of it at `/` or by such a line. Nor does it cover
`suspicious-nails-reference` on NixOS: the check still refuses such a root
while the decoy's `/etc/nixos` names a device that filesystem lies on, as
`hardware-configuration.nix` usually does, since it reads the configuration as
text and cannot tell whether Nix uses such a name only for the decoy's own
mounts; a later release may tell these apart by evaluating the configuration.
For such a root it also refuses a line that names the root's own folder or
subvolume, with the flag or without it.

In the hidden session, `deactivate` refuses a covered root with `root_covered`:
it would write its state onto the disk on top. `emergency` always runs, with or
without the state lock, and powers off. The session watcher writes no
probe onto a covered root and raises no emergency for it; it raises one neutral
desktop alert per covering mount ("Disk mounted over a folder in use", naming
the disk and `sudo umount` on its mount point), and `status` names the disk,
since every file saved under the root goes to that disk until it is unmounted.
A disk mounted on a parent of the root (`/mnt` over a root at `/mnt/data`)
hides the volume the same way and counts as a cover, not as a failed backend.

The gate's limits: it judges the storage this computer's mount table, fstab,
crypttab and sysfs describe. It cannot see a decoy filesystem mounted only by
hand and never listed, storage another operating system on the same machine
uses, or a remote block device's other users. It does not follow a ZFS dataset
or a ZFS volume to the disks of its pool, so it refuses a hidden root on ZFS
even on a pool of its own, and it cannot see where the program behind an `nbd`
or `ublk` device keeps the data. A remote disk that shows as an ordinary one,
such as an iSCSI disk, counts as a disk of its own. It reads which other
devices an XFS, ext3, ext4 or bcachefs filesystem keeps data on, but not those
of an f2fs filesystem made over several devices or a JFS log on a device of its
own: it takes such a filesystem for one on the device it is mounted from. Nor can it see the traces
that creating the volume on this computer left behind (the setup tools' own
files, shell history, a changed partition table): only preparing the volume
elsewhere avoids them. A refusal names the storage and says nothing was
written. The override is for storage the gate takes for the decoy's that the
operator knows the decoy does not use (for example a disk its fstab lists but
never mounts), and for an `nbd` or `ublk` device the operator knows is served
from storage elsewhere; everything written there lands on that storage.

## The write fence

The overlay keeps the hidden session's file writes off the decoy, but it only
sees writes through its own mounts. For the whole hidden session the kernel
also refuses writes to the decoy's disks that go around it, so a program NAILS
does not know of gets an error instead of leaving a trace. The entry
transition puts the fence up, after the decoy's own shutdown and before PID 1
switches root, around every disk the decoy mounts at entry (its root, its
other filesystems, its ESP, the other devices a multi-device btrfs or an
external journal or log keeps data on, its swap), each partition of those
disks and every device stacked on them (the decoy's LUKS, LVM and md). Only
the hidden volume's own top device, and what is stacked on it, is left out.
A hidden session never goes back to the decoy's kernel, so the fence stays up
until the power-off ends it:

- every decoy filesystem still mounted is made read-only at the superblock,
  after a `sync`. This is what refuses file writes (`EROFS`) and keeps the
  filesystem from writing a journal, metadata or access times of its own
  (btrfs writes no read repair on a read-only superblock either). An ext4 or
  btrfs read-only remount commits its journal and marks itself clean, once,
  at entry: that superblock then records the entry time as its last write,
  where a decoy that ran on would record its power-off. A plain `sync` would
  not be enough for XFS, which writes back its metadata log items and covers
  its log tens of seconds later; its read-only reconfigure pushes them all,
  waits for them, writes its unmount record and stops its log worker, so
  nothing of it is left to write once the device is read-only;
- the devices are set read-only at the block layer (`BLKROSET`): writes
  through a device node, read-write mounts and remounts, and the journal or
  log replay of a new mount are refused. The flag alone would not stop a
  mounted filesystem, a device-mapper mapping, md or swap: the kernel only
  warns about such a write and lets it through, which is also why the hidden
  volume keeps writing where it sits on a partition, a LUKS mapping or a
  volume group of the decoy's;
- discard is turned off on them (`queue/discard_max_bytes` 0), as a read-only
  ext4 or btrfs still sends `fstrim`'s discards;
- a device-cgroup program on the root cgroup denies every open of those
  devices, reading included, and of the character devices that reach the same
  hardware (sg, bsg, the NVMe controllers and their generic nodes, an NVMe
  multipath head's controllers through its paths; every sg node where a
  fenced disk is a SCSI device, since sg nodes can appear later): no process
  can send SCSI (SG_IO) or NVMe commands past the block layer, `mknod` a new
  node for them, swap onto them or mount them read-write. It needs only
  `CONFIG_CGROUP_BPF` and a cgroup2 hierarchy, which every supported
  distribution has; a kernel lockdown would not close these paths. A
  read-only mount of a decoy filesystem with its type given still works: the
  kernel finds the filesystem's live superblock by its device number without
  opening the device, and that superblock is read-only;
- efivarfs and pstore are made read-only, and the program denies the
  firmware's own nodes past them (`/dev/efi_test`, `/dev/efi_capsule_loader`);
- the kernel's crash log is kept from the firmware. pstore's EFI backend
  writes the kernel log of every oops and panic into an EFI variable itself,
  past efivarfs, and the decoy's next boot finds it and `systemd-pstore`
  copies it onto the decoy disk. The fence turns the backend off
  (`efi_pstore.pstore_disable`, which unregisters it from Linux 6.12 on; on
  an older kernel it unloads the module, and a later load stays disabled).

Activation refuses what the fence cannot cover, before the soft-reboot: no
decoy disk is found; the hidden root shares a filesystem with the decoy (a
folder or subvolume of a decoy filesystem, which `--allow-decoy-storage`
accepts for `check`, or a container file on one), which the session would
have to keep writable; an md array on a decoy disk, since md writes its
bitmap and its superblock (with the time of the update) to its members
seconds after the last write it carried, whatever their read-only flag says;
a crash-log backend that keeps records past a
power-off and cannot be turned off for the session (ACPI ERST, mtd, a block
device, a built-in EFI backend on a kernel older than 6.12); or the kernel
does not load the device program for the devices it would deny. Before
anything is written, where PID 1 still maps or holds a deleted file (an
`ld.so.cache` or library a package update replaced, which it keeps until it
executes itself again) the activation has it do so (`systemctl
daemon-reexec`), and where udevd does, it restarts udevd, steps the decoy's
journal records in the window around the switch. At the switch the
transition first ends the decoy's leftover processes but udevd, which PID 1
kills a moment later as at a plain soft-reboot, and a
step of the fence that fails then ends the session in a power-off, with what
is up of the fence: a swap area active on a decoy disk, or a filesystem that
cannot go read-only, because a process still holds a file of it open for
writing or a deleted file of it open (the reason, which `status` shows once
the hidden volume is open again, names those processes). All of it is kernel
state in RAM: nothing of the fence is written to a disk, and the power-off
ends it.

What it does not cover:

- **A root user who sets out to undo it.** Detaching the program, clearing the
  flag and remounting read-write take deliberate steps; no stock kernel stops
  root from taking them. So does a root user who loads a new table into the
  hidden volume's own mapping that names a decoy device the mapping already
  holds (device-mapper reuses that open device), and one who sends SCSI
  commands through the hidden volume's mapping where it is a linear part of a
  decoy disk (device-mapper passes the command to the whole disk below for a
  caller with `CAP_SYS_RAWIO`). The fence is against programs that write where
  they should not, not against the operator.
- **A read-write remount of btrfs.** btrfs keeps no block device of its own
  on its superblock, so the kernel's refusal of a read-write remount on a
  read-only device skips it, and btrfs itself only counts the devices it
  opened writable at mount. A `mount -o remount,rw` on a mount of a decoy
  btrfs the session can see (the decoy filesystems the session carries below
  `<hidden_volume_root>/root/decoy`) makes it read-write again, and its next
  transaction reaches the disk. A new mount of it, another subvolume
  included, is refused, since that opens the device.
- **Writers that hold their access from before the fence**: a process that
  survives the switch (a unit with `SurviveFinalKillSignal=`) and holds a
  decoy device open or mapped shared, and a loop device the decoy set up over
  a decoy device before the entry, write through what they hold.
- **USB passthrough**: a decoy disk on USB is also reachable through its USB
  device node (`/dev/bus/usb`), which the program does not deny, by a program
  that speaks the mass-storage protocol itself.
- **Linux 6.8**: a revalidation of a decoy disk (a rescan, a media change)
  gives it its discard limit back.
- **Disks the decoy does not mount at entry**: a second disk outside its
  fstab, a USB drive, a disk attached during the session. These keep the
  behaviour of [disks mounted during the session](configuration.md#disks-mounted-during-the-session),
  whose `session_mounts.read_only` sets them read-only at the block layer but
  leaves their device nodes open.
- **Stores that are no block device**: the TPM, the drive's own logs and
  counters (SMART, the flash translation layer) and firmware logs are out of
  reach. A `ramoops` crash log stays on: it lives in RAM, which a power-off
  clears.
- The hidden session cannot open a decoy disk raw either, so tools that probe
  devices (`blkid` on a change event, udisks, smartd) fail on them.

## Residual channels

The whole-root overlay cannot cover these. Each is either bounded by an
assumption above or documented as a known gap. The table is generated from the residue catalog
(the rows under `nails-forensics/src/residue_catalog/rows/`), which also holds the classes the
overlay does cover; [decoy-requirements.md](decoy-requirements.md#residue-catalog)
has the whole catalog.

<!-- residue-catalog:begin residual -->
| Channel | Why it survives the overlay | Bounded by | Detected by |
|---|---|---|---|
| [Journal window around each soft-reboot](decoy-requirements.md#what-the-decoy-journal-keeps) | The decoy journal logs the sudo command line, the hidden build's progress, PID 1 executing itself again and udevd restarting where either held a deleted file (the write fence needs that), and the decoy's own shutdown before the switch. A persistent journal keeps them on the decoy disk, ending in a soft-reboot. A volatile journal holds them in RAM until the power-off that ends the session. The decoy's next boot starts a new journal under a new boot ID. | Run on a volatile journal, so the window never reaches the decoy disk; keep the binary at a neutral path. | `journal-scan` |
| [Decoy journal reset by the old way back](decoy-requirements.md#what-the-decoy-journal-keeps) | No session opens this channel now: every session ends in a power-off, so the decoy never starts again on the kernel that ran the hidden session. The runtime journal ends with RAM at the power-off, and the decoy's next boot starts a fresh one from the kernel's boot records. | Power off after the session. | none: RAM only, gone at power-off |
| [sudo log file](decoy-requirements.md#the-sudo-log-exposure-and-its-mitigation) | `Defaults logfile=` writes every sudo command line, including the activation command and binary path, to a file on the decoy disk. | Remove `Defaults logfile=` from sudoers and sudoers.d. | path probe (warn) |
| [sudo I/O logging](decoy-requirements.md#the-sudo-log-exposure-and-its-mitigation) | `log_input`, `log_output` or the LOG_INPUT/LOG_OUTPUT tags record whole terminal sessions, keystrokes and output included, under iolog_dir on the decoy disk. | Remove every I/O logging option and tag from sudoers and sudoers.d. | path probe (warn) |
| [Disks mounted during the hidden session](configuration.md#disks-mounted-during-the-session) | A disk the hidden session mounts itself is a real disk outside every overlay: a read-write mount takes the session's writes, and mounting it rw already writes its superblock. | Every disk the decoy mounts at entry is read-only in the kernel and closed to every process for the whole session (the write fence): no process can open it, and none of its filesystems can be mounted read-write. For other disks, the session watcher alerts on every read-write disk mount that is not the session's own storage, which it tells by device (and by path below `<root>/root`, where NAILS keeps its layers), so a disk mounted elsewhere below the hidden root alerts too. `[session_mounts] read_only` makes every disk the session does not use read-only at the block layer for the session. The power-off that ends the session unmounts them. | none: verify cannot tell what a session wrote to another disk |
| [Hidden kernel records imported by the decoy journal on the old way back](#residual-channels) | No session opens this channel now: every session ends in a power-off, so the decoy never starts again on the kernel that ran the hidden session. The decoy's journald starts on a fresh kernel log at its next boot. The hidden journald still imports the decoy's kernel records at the entry, into the hidden journal on the hidden volume. | Every session ends in a power-off. Keep the decoy journal volatile, so the decoy's own records before the switch never reach its disk. | `journal-scan` |
| [Hidden records journald's sockets would carry into the decoy journal](decoy-requirements.md#what-the-decoy-journal-keeps) | No session opens this channel now: every session ends in a power-off, so the decoy never starts again on the kernel that ran the hidden session. What the hidden root sends journald after its own journald stopped ends with RAM at the power-off, and the decoy's next boot opens journald's sockets anew. | Every session ends in a power-off. | none: they name the hidden root's units and processes, which no check tells from the decoy's own |
| [Network state the hidden session created or changed](operator-guide.md#how-it-works) | The links, addresses, routes, policy-routing rules, firewall tables and network settings the hidden session sets up, and any MAC address or hostname it changes, live in the running kernel. Every session ends in a power-off, which ends them: none of it reaches the decoy's next boot. Remote records are another matter: what the network saw of the session stays there. | Every session ends in a power-off. Activation warns before entry about the network identity the session shares with the decoy. | none: a link the decoy adopted looks like one the decoy made itself |
| [Access times of the decoy's links NAILS follows](operator-guide.md#what-check-touches) | Run as root, check and activation read the decoy's files with O_NOATIME, start the decoy's programs they ask (systemctl, busctl, loginctl) with every mount of a disk noatime, keep every local disk mount that a lookup reaches through local filesystems alone noatime from the service manager's reload at entry to a second reload at its end and ask the kernel for the network state themselves. A lookup of NAILS' own still updates the access time of each link it follows or reads on the way, such as /bin, /sbin and /lib on a merged /usr, /etc/os-release and the links in the unit directories, so on a relatime decoy those links carry the moment of the check or the activation. The overlay module's first load also updates the access times of what modprobe and udevd read for it, sudo, doas or pkexec those of what it reads to start NAILS (its binary and libraries, its configuration, the PAM stack, the account databases), and an unprivileged check those of every file it reads and every program it starts. An activation killed while the mounts are noatime leaves them so until nails recover or a reboot gives them their modes back, which findmnt shows and which keeps the decoy from recording access times meanwhile. | Mount the decoy root noatime, which leaves the links' access times alone too, run check as root, start NAILS from a shell that is root already, and run nails recover after an interrupted activation. | none: an access time a session left looks like one any other read left |
| [Soft-reboot counter and boot ID](#residual-channels) | In the hidden session anyone with a shell sees one soft-reboot where systemd reports the count (256 and newer), and the decoy's boot ID and uptime. A persistent decoy journal shows the decoy's shutdown before the switch. Every session ends in a power-off, so the decoy's next boot starts with a count of zero, a new boot ID and fresh process numbers. | Every session ends in a power-off. Keep the decoy journal volatile. | none: RAM only, gone at power-off |
| [Login and boot records around a session](#residual-channels) | The decoy reaches the hidden session through a soft-reboot, and its own writers may record that shutdown. Every session ends in a power-off, so the decoy's next start is a cold boot, which its writers record as any boot. No session makes the decoy start again on the kernel that ran it, so no soft-reboot row, backdated boot record or process numbers that continue from the decoy's boot arise from ending a session. | Every session ends in a power-off. Leave the machine off for a few minutes before you hand it over. | none: the records are the decoy's own |
| [The decoy's mounts made again by the old way back](operator-guide.md#how-it-works) | No session opens this channel now: every session ends in a power-off, so the decoy never starts again on the kernel that ran the hidden session. The decoy's next boot makes its mount table afresh, as any boot does. | Every session ends in a power-off. | none: RAM only, gone at power-off |
| [EFI NVRAM, RTC and firmware pstore](#invariant) | These are not filesystem writes, so the overlay cannot redirect them; other software in the session can write them. | The write fence makes efivarfs and pstore read-only for the session and closes /dev/efi_test and /dev/efi_capsule_loader, so a program that writes an EFI variable or archives a crash record gets an error; a root user can undo that. It also turns pstore's EFI backend off, which writes a kernel crash log into an EFI variable itself, and activation refuses a crash-log backend that keeps records past a power-off and cannot be turned off. NAILS never writes NVRAM; avoid firmware tools inside the session. | none: EFI variables and firmware storage are not part of a disk image |
| [Memory remanence](operator-guide.md#cold-boot-and-running-memory-attacks) | RAM holds hidden-session data until the machine is powered off; a warm reboot does not clear it. | Every session ends in a power-off. Leave the machine off for a few minutes before you hand it over, and boot the decoy with init_on_free=1. A warm reboot (`nails emergency --reboot`) does not clear RAM. | `memory-swap` |
| [timesyncd clock stamp](decoy-requirements.md#session-time-records) | systemd-timesyncd touches this file at every sync and at shutdown, so its mtime records when the machine last ran, which can fall after the decoy's last logged activity. | Session touches land in the upper; on a persistent decoy, use the decoy normally after a session so its own activity follows the stamp. | path probe (info) |
| [Persistent timer stamps](decoy-requirements.md#session-time-records) | Persistent=true timers stamp their last run; a stamp from the session, or a catch-up run at the next decoy boot, dates the session. | Session stamps land in the upper; expect catch-up runs at the next decoy boot. | path probe (info) |
| [SMART power-on hours](decoy-requirements.md#session-time-records) | The drive counts every hour it runs; hours the decoy's logs do not account for point to unlogged use. | None in software; use the decoy normally so its logged uptime is plausible. | none: a disk image does not carry SMART counters |
| [SSD flash-translation-layer remnants](operator-guide.md#ssd-wear-levelling) | Old copies of rewritten blocks survive in cells the host can no longer address; a chip-off read can recover them. | Full-disk encryption on the decoy, so remnants are ciphertext; no TRIM on a volume that holds a hidden volume. | none: no host-side read reaches remapped flash cells, so `nails rehearse` cannot see them either |
| [chrony clock drift and RTC records](decoy-requirements.md#session-time-records) | chrony, the time-sync daemon Fedora installs by default and Ubuntu installs on new systems since 25.10 (26.04 among them; Debian uses systemd-timesyncd, and NixOS runs chrony when services.chrony is enabled), keeps its measured drift and real-time-clock offset under /var/lib/chrony and rewrites them periodically and at shutdown, so on a decoy that runs it the files date when the machine last ran. | Session writes land in the upper; on a persistent decoy, use the decoy normally after a session so its own clock activity follows the stamp. | path probe (info) |
| [NetworkManager connection records](operator-guide.md#how-it-works) | A connection the hidden session brings up through the decoy's NetworkManager lands in the upper. A link the session creates and a profile the hidden NetworkManager keeps only in memory, below /run, live in the running kernel and in RAM. Every session ends in a power-off, so the decoy's NetworkManager never sees them. | Every session ends in a power-off, which ends the session's links and in-memory profiles. | none: a connection record the decoy wrote after adopting a session's link looks like one the decoy made itself |
| [Plymouth boot log](decoy-requirements.md#session-time-records) | Plymouth, where the decoy boots with it, records the boot console to /var/log/boot.log. Every session ends in a power-off, so on a persistent decoy the file holds the decoy's next boot as an ordinary boot, dated when you power the machine on again. | Keep /var/log out of the decoy's persistent storage. | path probe (info) |
| [Snapper timeline snapshots](decoy-requirements.md#session-time-records) | Snapper keeps timeline snapshots of btrfs subvolumes and a bookkeeping record of each under /.snapshots and /var/lib/snapper, every one stamped with its time. A timeline snapshot taken while the machine runs dates that activity, and an older snapshot preserves decoy state for an examiner to compare. | Keep the overlay upper on the hidden volume, which NAILS enforces, so a decoy snapshot never captures a session's writes; disable the snapper timeline timer on the decoy if you want no snapshot dating the machine's activity. | path probe (info) |
| [Copy-on-write and compressed storage history](#residual-channels) | A copy-on-write filesystem keeps old copies of overwritten or deleted blocks in extents the live tree no longer references, recoverable with filesystem-specific tools. A raw scan reads those extents, so a leaked-then-deleted trace is still found there; but the same filesystems compress file contents, per file or subvolume and invisibly to the mount options, and a raw plaintext scan cannot read a compressed extent. | Full-disk encryption on the decoy keeps old extents as ciphertext; power off after the session. A rehearsal on a compressed or copy-on-write decoy is inconclusive by design, and `nails rehearse` says so rather than reporting it clean. | none: a raw scan reads old copy-on-write extents but cannot read compressed ones, so `nails rehearse` reports a compressed or copy-on-write decoy as not checked rather than clean: a mounted one (a zfs dataset included) by its mount, an image or an unmounted device by its superblock, and a whole disk partition by partition, where an encrypted partition, or one on which no filesystem is identified, is not checked either |
| [Fedora GRUB boot-success state](decoy-requirements.md#session-time-records) | Fedora's boot-success logic writes boot_success and boot_indeterminate into the GRUB environment block after a boot. Every session ends in a power-off, so the decoy's next boot is an ordinary one, and the block records it as any boot. | Nothing to do: every session ends in a power-off, and the block is the decoy's own, written at its next boot as on any boot. | path probe (info) |
| [sssd and the domain controller's records](decoy-requirements.md#decoys-joined-to-a-domain) | On a decoy joined to a domain (Active Directory or FreeIPA, through sssd) the hidden session's logins and account lookups reach the domain controller as the decoy's do, and the controller keeps its own records of them, with their times, where nothing NAILS does reaches them. In the hidden session sssd's caches and logs land in the upper. The decoy's own sssd, stopped before the switch and started at the decoy's next boot, logs both under /var/log/sssd on the decoy disk by default, as at any shutdown and boot. | NAILS is not tested on decoys joined to a domain; check and activation warn while sssd is in use on the decoy. Use a decoy that is not joined to a domain, and where nothing on it needs sssd, disable it. | none: the domain controller keeps its records on the controller, out of reach of any scan of this computer; what a scan of the decoy disk sees of sssd is the decoy's own, its caches under /var/lib/sss and the lines it logs under /var/log/sssd when it stops before the switch and starts at the decoy's next boot, as at any shutdown and boot |
<!-- residue-catalog:end residual -->

## Answer to "cannot trust the OS"

A common argument is that hiding a whole operating system by tuning it
application by application to avoid leaks is endless work: every application,
daemon and indexer may write somewhere, and auditing them one by one never
finishes. The Shufflecake authors, for instance, say in their
[FAQ](https://shufflecake.net/) that they do not try to stop the operating
system from logging, and treat a fully hidden operating system as hard enough
that theirs is still in progress (a booting prototype).

NAILS does not tune individual applications. It redirects **every write outside
pseudo filesystems at the mount layer**: the hidden session runs entirely inside
one overlay of the decoy root (and an overlay of each other decoy filesystem),
so whatever program writes — known or unknown — writes into an upper on the
hidden volume. No process of the hidden session reaches a decoy filesystem
through its mounts, because every one of them starts inside the overlay after a
soft-reboot. The question "which application leaks?" becomes "which writes
bypass the mount layer?", and that set is small and enumerable: the residual
channels listed above, and the decoy filesystems the fstab policy has to
handle: the decoy's fstab lines (and those of the fstab the hidden `/etc` holds
in its place), and the mount, swap and automount units its boot targets link
in their `.wants` and `.requires` directories, which the
policy decides as fstab lines (systemd's GPT auto-generator, which would mount
partitions the fstab does not list, is masked in the hidden session). A mount
unit that only another unit pulls in is not decided: it is one of the
[disks mounted during the session](configuration.md#disks-mounted-during-the-session).
Residual risk is limited to
those channels and to the shared state in the previous section, which the
overlay does not claim to isolate. All of this assumes the upper is on storage
of its own, which [the attach gate](#the-attach-gate) checks before the first
write; an upper on the decoy's own storage would put every redirected write
back on its disk.

## Known residual changes

**`/var/lib/nixos` drift: settled by design and by a VM test.**

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
session, and asserts that once the session has ended the decoy's `/var/lib/nixos`,
`/etc/passwd` and `/etc/group` are byte-identical to before. The test passes
(`nix build .#legacyPackages.x86_64-linux.e2e.session-nixos-hidden-system`), so
no drift remains.

**Login and boot records: the decoy's own power cycle.**

A session ends in a power-off, and the decoy's next start is a boot from
power-on. Its boot writers record an ordinary boot, and its getty and login
records get the low process numbers a fresh kernel gives. The records a
soft-reboot back into the decoy would write (a boot row named `soft-reboot`, a
boot record dated to the decoy's first boot, process numbers that continue from
the decoy's boot) do not arise from ending a session. What the hidden session
logs itself lands in the upper. The decoy's own shutdown before the switch
into the session writes what any shutdown writes.

## Evaluation scope

The forensic claims rest on this configuration:

- a NixOS decoy with a **tmpfs root** and only `/persist` (plus the Nix store)
  on disk (the whole-root session refuses an impermanent root like this, so
  this evaluation predates it and must be repeated on a disk-backed decoy
  root);
- **no swap**, and volatile journald;
- a **VeraCrypt hidden volume** with ext4 inside, opened with
  `cryptsetup open --type tcrypt --tcrypt-hidden`, as the hidden backend;
- **dead-disk analysis** of the powered-off decoy disk image.

That full configuration was evaluated manually, once. The automated E2E
disk-image checks cover NixOS VMs with a **LUKS2/ext4** hidden backend and, in
the VeraCrypt backend test, a **VeraCrypt hidden volume** opened with
`cryptsetup`, plus the Debian 13, Ubuntu 24.04 and Ubuntu 26.04 smoke runs.
Other backends and filesystems, and physical hardware (time to the greeter, GPU
and Wi-Fi after the soft-reboot, TPM-sealed decoy roots, GRUB) are not covered; see
[backends.md](backends.md) for the per-backend status. Claims outside this scope
are unverified.
