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
  the switch and its start after the way back) never reaches disk. The hidden
  session writes the same runtime journal, and the way back deletes it with the
  decoy's records from before the session, so the decoy journal starts again at
  the return; see [Residual channels](#residual-channels).
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
  in again at every switch (Plasma Login Manager 6.7 and later, on systemd 256
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
  kernel keeps its interfaces and addresses across the soft-reboot, in both
  directions, so the clean way back restores what the hidden session set up
  before it returns to the decoy (see [residual channels](#residual-channels)),
  and the network daemons restart and reconnect. An optional hidden
  network-identity configuration (random MAC, distinct hostname; VPN autoconnect
  disabled per profile) can be applied in the hidden NixOS generation or as a
  NetworkManager drop-in in the upper. It is opt-in, and the clean way back
  undoes it too, setting the MAC back (with the device taken down for the
  change where its driver refuses it on a running device) and restoring the
  hostname on a decoy without `/etc/hostname`. Only a device whose MAC address
  the way back still cannot set back keeps the random one, until power-off,
  and nothing reports it: end such a session with `deactivate --poweroff` or
  `emergency --poweroff` when that address must never reach the decoy.
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
  [decoy requirements](decoy-requirements.md)).
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
  the session plan, the transition drop-in, the runtime units and the masks
  live in RAM (`/run`) and the hidden volume only; the transition step removes
  them on the way back. Nothing is installed on the decoy disk.
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
  device it is stored on), or carries `tcrypt-hidden` for a device on its drive
  or one that cannot be found, is such an enabler: the `backend-entries`
  pre-flight check refuses activation while one exists, and no flag overrides
  it. A line that opens only
  another volume on the same drive warns.

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
- a root whose storage cannot be judged because `/etc/fstab` or `/etc/crypttab`
  cannot be read (`storage_unjudged`; run the command with sudo), or the block
  devices in `/sys/class/block` cannot be listed (`storage_unjudged`; run it as
  root on the host, with `/sys` mounted), or because its filesystem shows no
  disk it stores its data on: an overlay, a FUSE, network or ZFS filesystem, or
  an image file on one that the decoy neither mounts at `/` or a system folder
  such as `/home` nor lists in its fstab (`storage_unjudged`);
- a root on an image file that no filesystem mounted here holds
  (`storage_unjudged`). The filesystem that holds an image file is the one on
  the device the loop driver recorded for the file, not the one its path leads
  to now, so a filesystem mounted over the image's folder cannot make it look
  separate. Reading that record needs root (`storage_unjudged`; run the
  command with sudo).

An encrypted container file on a decoy filesystem only warns: filesystem
journals and copy-on-write snapshots of that filesystem can keep old copies of
the parts of the container that changed. `--allow-decoy-storage` (on `init`,
`activate`, `check` and `discard`) turns the refusal of the decoy's storage into
a warning; activation then repeats it in the logout confirmation, the session
plan records it for `status`, and `rehearse plant` refuses, since a rehearsal
on that storage cannot pass. The override never covers a folder, a covered
root, storage that cannot be judged, or `backend-entries`.

In the hidden session, `deactivate` refuses a covered root with `root_covered`:
it would write its state onto the disk on top. `emergency` always runs, with or
without the state lock; when the mounts the way back needs are covered too, it
powers off instead of returning to the decoy. The session watcher writes no
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
to the disks of its pool, so it refuses a hidden root on ZFS even on a pool of
its own. Nor can it see the traces that creating the volume on this computer
left behind (the setup tools' own files, shell history, a changed partition
table): only preparing the volume elsewhere avoids them. A refusal names the
storage and says nothing was written. The override is for storage the gate takes
for the decoy's that the operator knows the decoy does not use (for example a
disk its fstab lists but never mounts); everything written there lands on that
storage.

## Residual channels

The whole-root overlay cannot cover these. Each is either bounded by an
assumption above or documented as a known gap. The table is generated from the residue catalog
(the rows under `nails-forensics/src/residue_catalog/rows/`), which also holds the classes the
overlay does cover; [decoy-requirements.md](decoy-requirements.md#residue-catalog)
has the whole catalog.

<!-- residue-catalog:begin residual -->
| Channel | Why it survives the overlay | Bounded by | Detected by |
|---|---|---|---|
| [Journal window around each soft-reboot](decoy-requirements.md#what-the-decoy-journal-keeps) | The decoy journal logs the sudo command line, the hidden build's progress and the decoy's own shutdown before the switch, and its start after the way back, under one boot ID. A persistent journal keeps them on the decoy disk, with a soft-reboot gap; a volatile journal holds them in RAM, where the way back deletes every record from before the return. | Run on a volatile journal, so the window never reaches the decoy disk; keep the binary at a neutral path. | `journal-scan` |
| [Decoy journal reset by the way back](decoy-requirements.md#what-the-decoy-journal-keeps) | On a volatile decoy, anyone with a shell after the way back sees a journal that starts at the return, mid-uptime and without the kernel's boot records, while uptime and dmesg go back to the boot: the decoy's own records from before the session are gone with the hidden ones. | Power off after the session. | none: RAM only, gone at power-off |
| [sudo log file](decoy-requirements.md#the-sudo-log-exposure-and-its-mitigation) | `Defaults logfile=` writes every sudo command line, including the activation command and binary path, to a file on the decoy disk. | Remove `Defaults logfile=` from sudoers and sudoers.d. | path probe (warn) |
| [sudo I/O logging](decoy-requirements.md#the-sudo-log-exposure-and-its-mitigation) | `log_input`, `log_output` or the LOG_INPUT/LOG_OUTPUT tags record whole terminal sessions, keystrokes and output included, under iolog_dir on the decoy disk. | Remove every I/O logging option and tag from sudoers and sudoers.d. | path probe (warn) |
| [Disks mounted during the hidden session](configuration.md#disks-mounted-during-the-session) | A disk the hidden session mounts itself is a real disk outside every overlay: a read-write mount takes the session's writes, and mounting it rw already writes its superblock. | The session watcher alerts on every read-write disk mount outside the hidden volume; `[session_mounts] read_only` makes every disk the session does not use read-only at the block layer for the session; deactivate unmounts them and the way back makes them writable again. | none: verify cannot tell what a session wrote to another disk |
| [Hidden kernel records imported by the decoy journal](#residual-channels) | Records logged after the hidden journald stopped (PID 1's stop lines, a late /dev/kmsg writer) would be imported by the decoy journal, on disk with a persistent journal. | The transition step writes the decoy journald's kmsg cursor past every hidden record; only PID 1's last generic lines and the hidden filesystem's unmount line follow it. | `journal-scan` |
| [Network state the hidden session created or changed](operator-guide.md#how-it-works) | The way back puts most of this back before the switch, after a deactivate and a plain emergency alike: it deletes the links the session created (its virtual links, and the Wi-Fi interfaces it added on a decoy radio), sets each device's MAC address back (taking the device down for the change when its driver refuses it while the device is up) and the hostname, deletes the policy-routing rules and nftables tables the session added, writes back the network settings for all devices and for new ones (net.ipv4.ip_forward and the all and default keys of net.ipv4.conf and net.ipv6.conf), and puts the per-link NetworkManager and systemd-resolved state under /run back in place, so the decoy's NetworkManager does not adopt a session link or record a profile for it in /var/lib/NetworkManager/timestamps. What it leaves stays until power-off: the addresses and routes the session gave the decoy's own devices, what the session added inside a firewall table the decoy already had or with legacy iptables, the settings of a single device, anything the session deleted or renamed (a decoy Wi-Fi interface that software in the session replaced with its own included, which leaves that radio without Wi-Fi), a MAC address the way back cannot set back, every firewall table on a decoy without nft, and a part of the state activation could not record in full. A firewall table a VPN app leaves to block traffic keeps the decoy offline. | A deactivate or a plain emergency puts most of it back on its own. Stop VPN apps, containers and virtual machines in the session before you deactivate (wg-quick down, nmcli connection down, the app's own disconnect), keep nftables installed on the decoy so the way back sees the firewall tables, and end the session with `--poweroff` when none of its network state may reach the decoy. | none: a link the decoy adopted looks like one the decoy made itself |
| [Soft-reboot counter and boot ID](#residual-channels) | Anyone with a shell sees two soft-reboots per session where systemd reports the count (256 and newer); a persistent decoy journal shows a shutdown and start under one boot ID. Where the way back set the process-number counter back, the decoy's units after it can hold numbers below those of kernel threads that started before them, an order neither a cold boot nor a plain soft-reboot gives (`ps -eo pid,lstart,comm --sort=pid` shows it), and a persistent decoy journal can hold the same process numbers twice under one boot ID. | Power off after the session; keep the decoy journal volatile. | none: RAM only, gone at power-off |
| [Login and boot records around a switch](#residual-channels) | A whole-root session reaches the decoy again through a soft-reboot, and the decoy's own writers record that start. On Debian 13 with wtmpdb the boot row would be named soft-reboot, or, with the writer kept from the system bus before the kernel has been up for five minutes, dated to the decoy's cold boot, which wtmpdb last lists as a crash; where the service manager keeps the userspace start time across a soft-reboot (systemd 255 and earlier, classic wtmp), the boot record would carry the decoy's first boot time, so the file would hold a boot dated before the shutdown before it. Ordinary use writes none of these. Where the decoy keeps classic wtmp, the getty and login records written after the way back would also carry process numbers that continue from the decoy's boot, where a fresh kernel starts them low; they would stay in the file on the decoy disk, next to the low numbers of every earlier boot. | The way back dates the decoy's start with the time of the switch, without masking either writer, so no row goes missing: the wtmpdb boot writer starts in a time namespace whose boot clock starts at the switch and itself writes the ordinary reboot row, and a backdated classic-wtmp boot record is corrected to that time, so the login and boot records read as one clean power cycle. Until the next power-off, anyone with a shell on the decoy sees the one-shot that did this in the journal and both units loaded from files that are gone in systemctl status. As its last step before the decoy starts, the way back also sets the kernel's process-number counter back: the entry records the number the decoy's boot gave its getty (else logind), the hidden session's own start shows how many numbers a start uses up to its copy of it, and the counter goes that many below. Where the getty is what it measures by, the decoy's getty gets about the number its own boot gave it, as far as the hidden start runs about as many processes up to its getty as the decoy's does. A getty or logind started more than a minute after the oldest process of its start that still runs, such as a getty started again after a logout, is passed over. When the getty is passed over, the measure goes by logind, or, without logind either, the counter goes to just below the lowest number the decoy's own userspace held at entry, and no test checks where the getty lands then. The decoy's other units are not measured. That step is best effort: where it cannot write the counter, deactivate warns before the switch and the numbers continue from the decoy's boot, and where it has neither a getty nor logind to measure by, deactivate warns as well; only ending the session with --poweroff, which has no way back, leaves none of them then. | none: the records are the decoy's own; verify reports the pieces the way back leaves in /run when their step never ran |
| [The decoy's mounts made again by the way back](operator-guide.md#how-it-works) | Anyone with a shell sees with findmnt that the decoy's root and the mounts its initrd made (such as the store bind) were made again after the boot, where a plain soft-reboot keeps them. A mount made after the boot by hand or by a service comes back as well, where a plain soft-reboot unmounts it. A decoy mount the way back cannot make again (a filesystem that another mount covers at a place the session carries, NixOS's /etc overlay) is missing until it is mounted again. | The way back makes every decoy mount it can take from the decoy root or a filesystem the session carried again as the decoy had it when the entry began (its filesystem, the directory of it the mount shows, its place in a stack, its options), NixOS's read-only store bind included, and gives the decoy its utab lines back with them. Power off after the session. | none: RAM only, gone at power-off |
| [EFI NVRAM, RTC and firmware pstore](#invariant) | These are not filesystem writes, so the overlay cannot redirect them; other software in the session can write them. | NAILS never writes NVRAM; avoid firmware tools inside the session. | none: EFI variables and firmware storage are not part of a disk image |
| [Memory remanence](operator-guide.md#cold-boot-and-running-memory-attacks) | RAM holds hidden-session data until the machine is powered off; a warm reboot does not clear it. | Power off (`--poweroff`) before handing the machine over; boot the decoy with init_on_free=1. | `memory-swap` |
| [timesyncd clock stamp](decoy-requirements.md#session-time-records) | systemd-timesyncd touches this file at every sync and at shutdown, so its mtime records when the machine last ran, which can fall after the decoy's last logged activity. | Session touches land in the upper; on a persistent decoy, use the decoy normally after a session so its own activity follows the stamp. | path probe (info) |
| [Persistent timer stamps](decoy-requirements.md#session-time-records) | Persistent=true timers stamp their last run; a stamp from the session, or a catch-up run at the next decoy boot, dates the session. | Session stamps land in the upper; expect catch-up runs at the next decoy boot. | path probe (info) |
| [SMART power-on hours](decoy-requirements.md#session-time-records) | The drive counts every hour it runs; hours the decoy's logs do not account for point to unlogged use. | None in software; use the decoy normally so its logged uptime is plausible. | none: a disk image does not carry SMART counters |
| [SSD flash-translation-layer remnants](operator-guide.md#ssd-wear-levelling) | Old copies of rewritten blocks survive in cells the host can no longer address; a chip-off read can recover them. | Full-disk encryption on the decoy, so remnants are ciphertext; no TRIM on a volume that holds a hidden volume. | none: no host-side read reaches remapped flash cells, so `nails rehearse` cannot see them either |
| [chrony clock drift and RTC records](decoy-requirements.md#session-time-records) | chrony, the time-sync daemon Fedora installs by default and Ubuntu installs on new systems since 25.10 (26.04 among them; Debian uses systemd-timesyncd, and NixOS runs chrony when services.chrony is enabled), keeps its measured drift and real-time-clock offset under /var/lib/chrony and rewrites them periodically and at shutdown, so on a decoy that runs it the files date when the machine last ran. | Session writes land in the upper; on a persistent decoy, use the decoy normally after a session so its own clock activity follows the stamp. | path probe (info) |
| [NetworkManager connection records](operator-guide.md#how-it-works) | A connection the hidden session brings up through the decoy's NetworkManager lands in the upper. A link the session creates could be adopted by the decoy's NetworkManager after the way back, recording the connection and its time on the decoy disk, and a profile the hidden NetworkManager kept only in memory, below /run, would be loaded by the decoy's. The way back deletes the session's links and those profiles before the decoy's NetworkManager starts (see the network-state class above), after a deactivate and a plain emergency alike, so neither leaves such a record. A link the way back leaves (see the network-state class) can still be adopted. | A deactivate or a plain emergency handles this with the network-state class above, deleting the session's links and in-memory profiles before the decoy's NetworkManager starts. Take down what that class leaves before you deactivate, or end the session with --poweroff. | none: a connection record the decoy wrote after adopting a session's link looks like one the decoy made itself |
| [Plymouth boot log](decoy-requirements.md#session-time-records) | Plymouth, where the decoy boots with it, records the boot console to /var/log/boot.log. The way back is a boot of the decoy, so on a persistent decoy the file's latest entries hold the way back's boot messages and their time, where a plain power cycle would not place a boot mid-day. | Keep /var/log out of the decoy's persistent storage, or expect boot.log to date the way back; power off after the session. | path probe (info) |
| [Snapper timeline snapshots](decoy-requirements.md#session-time-records) | Snapper keeps timeline snapshots of btrfs subvolumes and a bookkeeping record of each under /.snapshots and /var/lib/snapper, every one stamped with its time. A timeline snapshot taken while the machine runs dates that activity, and an older snapshot preserves decoy state for an examiner to compare. | Keep the overlay upper on the hidden volume, which NAILS enforces, so a decoy snapshot never captures a session's writes; disable the snapper timeline timer on the decoy if you want no snapshot dating the machine's activity. | path probe (info) |
| [Copy-on-write and compressed storage history](#residual-channels) | A copy-on-write filesystem keeps old copies of overwritten or deleted blocks in extents the live tree no longer references, recoverable with filesystem-specific tools. A raw scan reads those extents, so a leaked-then-deleted trace is still found there; but the same filesystems compress file contents, per file or subvolume and invisibly to the mount options, and a raw plaintext scan cannot read a compressed extent. | Full-disk encryption on the decoy keeps old extents as ciphertext; power off after the session. A rehearsal on a compressed or copy-on-write decoy is inconclusive by design, and `nails rehearse` says so rather than reporting it clean. | none: a raw scan reads old copy-on-write extents but cannot read compressed ones, so `nails rehearse` reports a compressed or copy-on-write decoy as not checked rather than clean: a mounted one (a zfs dataset included) by its mount, an image or an unmounted device by its superblock, and a whole disk partition by partition, where an encrypted partition, or one on which no filesystem is identified, is not checked either |
| [Fedora GRUB boot-success state](decoy-requirements.md#session-time-records) | Fedora's boot-success logic writes boot_success and boot_indeterminate into the GRUB environment block after a boot. The way back is a boot of the decoy, so the block can record it and the counter can move, where a plain power cycle would not. | Power off after the session so the decoy's next boot is a plain one; the block is the decoy's own, written on the way back as on any boot. | path probe (info) |
| [sssd and the domain controller's records](decoy-requirements.md#decoys-joined-to-a-domain) | On a decoy joined to a domain (Active Directory or FreeIPA, through sssd) the hidden session's logins and account lookups reach the domain controller as the decoy's do, and the controller keeps its own records of them, with their times, where nothing NAILS does reaches them. In the hidden session sssd's caches and logs land in the upper; the decoy's own sssd, stopped before the switch and started again after the way back, logs both under /var/log/sssd on the decoy disk by default, as at any shutdown and boot. | NAILS is not tested on decoys joined to a domain; check and activation warn while sssd is in use on the decoy. Use a decoy that is not joined to a domain, and where nothing on it needs sssd, disable it. | none: the domain controller keeps its records on the controller, out of reach of any scan of this computer; what a scan of the decoy disk sees of sssd is the decoy's own, its caches under /var/lib/sss and the lines it logs under /var/log/sssd when it stops before the switch and starts after the way back, as at any shutdown and boot |
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
handle, through the fstab or through a mount or swap unit of the decoy's own,
which the policy decides the same way (systemd's GPT auto-generator, which
would mount partitions the fstab does not list, is masked in the hidden
session). Residual risk is limited to
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
session, and asserts that after the way back the decoy's `/var/lib/nixos`,
`/etc/passwd` and `/etc/group` are byte-identical to before. The test passes
(`nix build .#legacyPackages.x86_64-linux.e2e.session-nixos-hidden-system`), so
no drift remains.

**Login and boot records: one clean power cycle, bar the process numbers.**

A session reaches the decoy again through a soft-reboot, and the decoy's own
boot writers record that start. On Debian 13 the wtmpdb boot writer names the
boot row `soft-reboot` when the service manager reports a soft-reboot. When it
cannot ask, it still does once the kernel has been up for five minutes, and
before that it dates a `reboot` row to the decoy's cold boot, which `wtmpdb
last` then lists as a crash. On a service manager that keeps the userspace start
time across a soft-reboot (systemd 255 and earlier, as on Ubuntu 24.04), the
classic-wtmp boot record carries the decoy's first boot time, so the file holds
a boot stamped before the shutdown that precedes it. An ordinary power cycle
writes none of this.

The way back dates the decoy's start with the time of the switch, read from the
kernel's boot clock just before it, and neutralises both without masking a
writer, so no shutdown row goes missing. It starts the wtmpdb boot writer in a
time namespace whose boot clock starts at the switch, kept from the system bus:
the writer takes its fallback, finds an uptime of seconds and itself writes the
`reboot` row a power cycle writes, stamped with the time of the switch. The word
`soft-reboot` never reaches the disk, and the database holds what one insert
leaves. A decoy that changes the writer's unit with a file of its own, or runs a
kernel older than Linux 6.2, gets its writer as it is, which records the
soft-reboot. A backdated classic-wtmp boot record is corrected in place to the
same time, before anyone can log in, without updating the file's access time.
After a full session the decoy's login and boot records then read as a shutdown
and a later boot, one clean power cycle. The cross-distro login- and boot-record
test under `nix/distro-tests` checks this on Debian 13 and Ubuntu 24.04 against
a power cycle with the record writers installed, with the way back past five
minutes of uptime.

What does this lives in `/run` and leaves traces in RAM only, until the next
power-off. The decoy's journal shows a one-shot unit,
`overlay-runtime-boot.service`, start and finish, and `systemctl status` shows
it and the wtmpdb writer's unit loaded from files that are gone, the writer's
unit with the start command and the drop-in the way back gave it. `nails
verify` reports any of the pieces still in `/run` when their step never ran.

Where the decoy keeps classic wtmp, the getty and login records written after
the way back would also carry process numbers that continue from the decoy's
boot, where a fresh kernel starts them low. Ubuntu 24.04 and NixOS keep classic
wtmp, and so does Debian 13: its getty still adds a record with its process
number to `/var/log/wtmp` each time it starts, although `last` there reads
wtmpdb. These records are written to the decoy disk and stay after any later
power-off, next to the low numbers of every earlier boot in the same file, so
the file itself would hold the baseline that sets them apart. wtmpdb keeps no
process numbers.

So the way back sets the kernel's process-number counter back
(`/proc/sys/kernel/ns_last_pid`) as its last step, once every hidden process has
stopped and before PID 1 starts a single decoy unit. Where to is measured: the
entry records the number the decoy's boot gave its getty (else logind), the
switch into the hidden root records the counter as it hands over, and, when the
way back is armed, the hidden session's own copy of that getty shows how many
numbers a start of the service manager uses up to it. The counter goes that many
below the decoy's number, so where the getty is what the way back measures by,
the decoy's getty gets about the number its own boot gave it. That assumes the
hidden start runs about as many processes up to its getty as the decoy's start
does: where the hidden system starts other units before it, the decoy's getty
lands off by the difference. The difference adds up over sessions without a
power-off between them, since each entry anchors on the number the last way back
gave: in two runs of the Ubuntu 24.04 smoke the getty moved up by 34 and by 74
numbers over two sessions. The kernel skips a number still in use. Only a getty
or logind that started at most a minute after the oldest process of the same
start that still runs counts: one started again after a logout, or on demand for
another terminal, took its number after everything that ran before it, so it is
passed over, in the decoy and in the hidden session alike. One started again
after a login that ended within that minute is not told apart. When the getty is
passed over, the measure goes by logind, and no test checks where the getty
lands then.

A process that a soft-reboot leaves running, in a unit with
`SurviveFinalKillSignal=yes` or a root storage daemon whose `argv[0]` begins
with `@`, keeps the number and the start time it started with, and after a way
back it still runs in the decoy's root. It is left out of both readings, so in
the second and later sessions without a power-off between them the entry reads
the decoy's start that the last way back ran, as the first entry reads the boot.
Left in, such a unit kept from the cold boot could hold a lower number than
every unit of that start and pass for its first process, and the getty and
logind, started long after it, would fall outside that minute.

Without a getty or logind to measure by, the counter goes to just below the
lowest number the decoy's own userspace held at entry. No test checks where the
getty lands from there. Only the getty, or logind, is measured: the decoy's
other units get their numbers in the order its start runs them, and a
soft-reboot need not run them in a cold boot's order, so their numbers can
differ more, also in their power-of-two range (logind's does in the NixOS test
of this).

This is best effort and never stops the way back: without a record, outside
PID 1's PID namespace, or where the counter cannot be written (a kernel built
without `CONFIG_CHECKPOINT_RESTORE` has no such file), the numbers continue as
before, and `deactivate` warns of that before the switch. It warns as well where
it finds no getty or logind to measure by, and the counter can only go to just
below that lowest number. Where the getty itself is measured, its number lands
near the decoy's own boot's, not on it, and so far in the same power-of-two
range in every test; an examiner who compares the getty records with those of
every earlier boot can still see one that sits above the rest, the more so after
several sessions without a power-off. Until the next power-off, anyone with a
shell can see the reset itself: the decoy's units can hold numbers below those
of kernel threads that started before them (the soft-reboot row of the residual
table above). Only a session ended with `deactivate --poweroff` (or
`emergency --poweroff`), which has no way back, leaves none of this to chance.

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
`cryptsetup`, plus the Debian 13, Ubuntu 24.04 and Ubuntu 26.04 smoke runs.
Other backends and filesystems, and physical hardware (time to the greeter, GPU
and Wi-Fi after the soft-reboot, TPM-sealed decoy roots, GRUB) are not covered; see
[backends.md](backends.md) for the per-backend status. Claims outside this scope
are unverified.
