# Operator guide

> **Required reading before any security-sensitive use.** This guide describes
> what NAILS actually does, organised by *where* each step runs. Following it
> literally should not leave an avoidable trace on the decoy. For the adversary
> model it assumes, read [threat-model.md](threat-model.md); to report a
> vulnerability, see [SECURITY.md](../SECURITY.md).

> **Amnesic decoy first.** NAILS requires a decoy base that keeps no durable
> record of the hidden session. Activation fails closed on a persistent journald
> journal, an active syslog/audit daemon or an armed kdump. Read
> [decoy-requirements.md](decoy-requirements.md) and set the decoy up before you
> rely on NAILS.

---

## Where each step runs

Every instruction in this guide belongs to exactly one of three places. Keeping
them straight is the difference between a clean session and a decoy that records
what you did.

1. **A separate machine** — creating the hidden volume, building, verifying and
   copying the release onto it. The decoy never sees this work.
2. **Inside the hidden session** — everything after activation's soft-reboot and
   before the way back. The whole root is an overlay whose upper is on the hidden
   volume, so every write lands there, not on the decoy.
3. **The decoy shell** — the plain decoy system, before activation and after the
   way back. This is the surface a forensic examiner images.

> **Type as little as possible on the decoy.**
>
> - On the decoy you unlock and mount the hidden volume and run `nails check`
>   and `nails activate` (once, before the first session, `nails init`; when
>   needed, `nails recover` or `nails discard`). Do nothing else with the
>   tool there, and do not edit its configuration there either (`nails config
>   set` belongs in the hidden session): do not read `state.json`, and do not
>   name the hidden volume, its mapper, its mount point or the tool in any
>   other command.
> - Type those commands in a shell with history off — see
>   [History off on the decoy](#history-off-on-the-decoy). Activation also kills
>   the decoy's interactive shells, yours included, right before it starts the
>   soft-reboot, so none of them writes the activation command to its history
>   file. Your terminal closes at that point; what activation printed up to then
>   is already on it.
> - Choose neutral names. A mapper called `data`, a mount at `/mnt/data` and a
>   plain filesystem label reveal nothing; `hidden`, `veracrypt`, `tcrypt`,
>   `decoy` or `nails` do. **Renaming alone is not enough** — the names still
>   surface in sudo logs, the kernel ring buffer, generated mount units and
>   `/dev/disk/by-label` (see [Pre-activation residue](#pre-activation-residue)).

Throughout, `<hidden-root>` is wherever you mounted the hidden volume (the
examples use `/mnt/data`), and the binary lives at `<hidden-root>/nails`. Always
invoke it by its absolute path.

---

## Where setup happens

Everything NAILS writes goes to the hidden root, so the hidden root must be
storage of its own: a whole device, a partition or an encrypted volume that the
decoy does not use. A folder, a btrfs subvolume or a bind mount of a filesystem
the decoy uses, a logical volume or other device stacked on the decoy's own
storage or swap, or an image file on a decoy filesystem is not: everything
written there lands on the decoy's disk, where an examination can find it.

Prepare the volume where nothing reaches the decoy's disk:

- **on an external drive prepared on another computer** (recommended): create
  and format the volume there, then attach the drive to this computer, unlock
  and mount it, and run `nails` from it;
- **or from a setup medium**: a live system started from a USB stick on this
  computer, which writes nothing to its internal disk. Tails is one;
  [First install from Tails](install-from-tails.md) shows the first
  installation from it.

`init`, `activate`, `check` and the other commands that write ask the attach
gate first and refuse anything else before they write or probe a single file.
The refusal reads `<root> is not a volume of its own: <reason>. Nothing was
written.` (code `not_separate_volume`, exit 4), names the storage, and says so
too when the running `nails` binary is itself on this computer's disk. A root
with a second filesystem mounted over it is refused with `root_covered`, and
one whose storage cannot be judged with `storage_unjudged`: on an unprivileged
run on a distribution whose `/etc/crypttab` only root can read, or on a root in
a file container (only root can read the loop device's record of where the file
lives), run the command with sudo; a filesystem that shows no disk it stores its data on (an overlay,
FUSE, a network filesystem) is never accepted. A decoy `/etc/crypttab` or
`/etc/fstab` line that opens or mounts the hidden volume fails the
`backend-entries` check: remove it long
before the next use and open the volume by hand each time. If the boot mounts
the volume through such a line, the gate refuses it as the decoy's own
filesystem and says to remove the line.

An encrypted container file on a decoy filesystem only warns: the filesystem's
journal and copy-on-write snapshots (btrfs, snapper) can keep old copies of the
parts of the container that changed. `--allow-decoy-storage` (on `init`,
`activate`, `check` and `discard`) turns the refusal of the decoy's own storage
into a warning; use it only for storage the gate takes for the decoy's that you
know the decoy does not use (for example a disk its fstab lists but never
mounts), since everything written there lands on it. It never covers a folder, a
covered root, storage that cannot be judged or a decoy entry for the volume.
See [the attach gate](threat-model.md#the-attach-gate).

Read this guide on another device, not on the decoy: opening it there leaves
viewer traces such as `~/.lesshst`. The guide ships in the release bundle.

---

## What NAILS does

NAILS runs the hidden session in one OverlayFS over the whole decoy root. The
decoy root is the read-only lower; the writable upper is on the hidden volume.
Activation builds that overlay at `/run/nextroot` and enters it with
`systemctl soft-reboot` (systemd 254 or newer): systemd stops every decoy
program, switches root into the overlay and starts a fresh userspace there. The
hidden desktop, its applications and its services all start inside the overlay,
and after the switch no userspace process can reach the decoy filesystem by any
path. Deactivation soft-reboots back into the plain decoy root.

The overlay separates *files*, not the machine: the hidden session runs on the
decoy's kernel and shares its network identity (see
[What the hidden environment shares with the decoy](threat-model.md#what-the-hidden-environment-shares-with-the-decoy)).
Both transitions log you out: every program closes, and the hidden session and,
afterwards, the decoy start at their own login screens. NAILS logs nobody in,
but a display manager set to log an account in automatically logs it in again
after each switch, as at boot (see
[Inherited autostart, services and autologin](#inherited-autostart-services-and-autologin)).

Two safeguards bracket the session:

- **Pre-activation residue baseline.** Before it builds anything, `nails
  activate` runs the read-only decoy residue scan and writes the result to
  `<hidden-root>/reports/`, then prints a one-line summary: `no known residue`,
  or the number of warnings and critical findings (the notes stay in the
  report). The scan only reads the decoy; the report lives on the hidden
  volume. It is a baseline, so if a later examination finds a trace you can tell
  whether it predated the session.
- **No shell history reaches the decoy.** Right before it starts the
  soft-reboot, activation SIGKILLs the decoy's interactive shells: stopping a
  login session sends its shells SIGHUP, on which bash writes its history, so
  they must be gone first. None of them can flush the activation command to a
  history file. `nails emergency` does the same before it starts the way back
  or the power-off. Shells in the hidden session write their history
  into the hidden home, which is in the upper (see [Shell history](#shell-history)).

Hardening the decoy's *own* shell history (environment, symlinks, boot-time
enforcement) is decoy configuration, not something NAILS does at runtime; it is
covered in [decoy-requirements.md](decoy-requirements.md).

---

## How it works

This is the operator's view of the design. Why it takes the whole root, in
short: an earlier design overlaid the running decoy directory by directory and
had to find, restart or kill every process that could still write to it, and a
writer it missed wrote to the decoy without any sign. Here every process of the
hidden session starts inside the overlay, so there is nothing left to find. The
[architecture overview](architecture.md#why-one-overlay-over-the-whole-root)
gives the full reasoning and the price.

**Hidden-root layout.** The hidden volume holds:

| Path | Content |
|---|---|
| `<hidden-root>/nails` | the binary |
| `<hidden-root>/config/` | `nails.toml` and, on NixOS, the hidden module `config/nixos/configuration.nix` |
| `<hidden-root>/nixos/` | on NixOS, optionally a hidden flake, built instead of the legacy configuration; it must import the hidden module |
| `<hidden-root>/root/upper`, `root/work` | the hidden root's upper and its overlayfs work directory |
| `<hidden-root>/root/mounts/<path>/upper` | the upper of each other decoy filesystem that is overlaid (a separate `/home`), named by its systemd path escape |
| `<hidden-root>/root/cache` | the Nix evaluation cache used while the hidden system is built |
| `<hidden-root>/logs/`, `state.json`, `reports/` | the log, the recorded state and the residue reports |

Keep all of it `root`-owned on the hidden volume.

**Activation, step by step.** `nails activate` runs on the decoy:

1. It runs the pre-flight checks, among them `platform` (the host is one NAILS
   supports; a Debian or Ubuntu release it has not been tested on warns),
   `systemd-version` (254 or newer), `soft-reboot-units` (the units that
   implement `systemctl soft-reboot` are installed), `decoy-root` (the decoy
   root can be mounted again by device for the way back), `session-state` (no
   session and no leftovers of an interrupted one), `shutdown-inhibitors` (no
   program blocks shutdown: one that does, such as a package or firmware
   update, is in the middle of something the switch would cut short; a logind
   that does not answer whether one does fails it too, unless PID 1 says
   logind does not run),
   `fstab-policy`,
   `kernel-modules` (no hidden session deleted or replaced the running
   kernel's module tree or its index; it only warns, see
   [below](#copy-up-cost-and-shadowed-decoy-updates)), `package-drift`
   (hidden sessions' package database still follows the decoy's; it only
   warns, see [below](#package-changes-in-hidden-sessions)),
   `hidden-volume`, `upper-fs-capability`,
   `backend-entries`, `suspicious-nails-reference` (NixOS: nothing in the
   decoy's `/etc/nixos` names the hidden volume's device, mount point or the
   storage it is on, opens its mapping, or names NAILS; [the decoy
   requirements](decoy-requirements.md#nixos) list each form), `backend-detect`, `storage-readiness`, `swap`,
   `memory-wipe`, `sleep-policy`, `decoy-persistence`, `inherited-autostart`,
   `incremental-history-flush` and `space`. `nails check` runs the same checks
   and leaves no file and no mount behind (see
   [What `check` touches](#what-check-touches)).
2. It snapshots `/run` and writes the session plan to `/run/overlay-runtime`,
   together with a RAM copy of the binary and the configuration, and a copy of
   libmount's `utab` with the mount table lines of the mounts it names.
3. It mounts the root overlay at `/run/nextroot`: the decoy root, read-only, as
   the lower; `<hidden-root>/root/upper` as the upper.
4. On NixOS with a hidden configuration it builds and activates the hidden
   system (see below).
5. It applies the **fstab policy** to every filesystem the hidden systemd would
   mount from the decoy's fstab:
   - the ESP and `/boot` filesystems are bound read-only, so nothing in the
     hidden session rewrites `loader/random-seed`, `grubenv` or a boot entry;
     the units that write there at every start
     (`systemd-boot-random-seed.service`; GRUB's `grub-common.service` on
     Debian and Ubuntu 24.04, `grub2-common.service` from Ubuntu 26.04 and
     `grub-initrd-fallback.service` on Ubuntu) are masked in the hidden
     session, so they do not fail there, and run as usual on the decoy;
   - a filesystem mounted read-only in the decoy is bound read-only;
   - every other mounted local filesystem (a separate `/home`, `/var` or
     `/nix`) gets an overlay of its own, with its upper under
     `<hidden-root>/root/mounts/`;
   - swap, local filesystems that are not mounted now, network filesystems and
     overlay entries that are not mounted now but have their upper on a disk
     are kept off, so the hidden systemd never activates them: masked in
     `/run`, or skipped where a boot target requires them (an entry without
     `nofail`), so that `local-fs.target`, `remote-fs.target` and `swap.target`
     are still reached. An entry a target requires whose device is not there
     is masked, and activation warns that the hidden session will not reach
     that target.

   Whatever the fstab says, the hidden session also masks
   `systemd-remount-fs.service` and `systemd-growfs-root.service`, which fail
   there or do nothing: the root filesystem they remount and grow is the root
   overlay in the hidden session. It masks systemd's GPT auto-generator as
   well, so the generator mounts no partition the fstab does not list. The full
   table is in [configuration.md](configuration.md#what-the-session-covers).

   `nails check` lists the decision for each entry.
6. It binds `/run` and the hidden volume into the next root (the hidden volume
   appears at the same path in the hidden session) and checks the init the way
   PID 1 will, so a broken tree is refused before the switch instead of freezing
   the machine.
7. It installs the transition step (a runtime drop-in for
   `systemd-soft-reboot.service`) and prints its result. While a program
   holds a shutdown block inhibitor (a package or firmware update in the
   middle of its work), or logind does not answer whether one does, it stops
   here: activation fails with the reason and removes everything it built,
   with the decoy's shells and every other program left as they were.
   Otherwise it kills the decoy's interactive shells and soft-reboots the way
   `systemctl soft-reboot` does, through logind. logind first tells the
   programs that wait for its shutdown signal that the system is going down
   and waits for them, as at an ordinary shutdown, for at most
   `InhibitDelayMaxSec=` (5 seconds by default; unattended-upgrades on Debian
   and Ubuntu raises it to 30). unattended-upgrades' shutdown helper is one of
   them: stopped without that signal, it writes a line to its log in
   `/var/log/unattended-upgrades` that an ordinary shutdown does not. With
   `Unattended-Upgrade::InstallOnShutdown` set, it installs the pending
   updates on that signal, at every activation as at every shutdown, and the
   switch waits for them, past logind's delay too
   ([decoy requirements](decoy-requirements.md#ubuntu)). Activation stays
   until PID 1 holds the soft-reboot's job: until then `status` shows it
   activating and `recover` leaves it alone, and the decoy's desktop runs on,
   so activation keeps killing every interactive shell opened meanwhile
   (within about a tenth of a second after it starts), and kills them once
   more when PID 1 holds the job. A terminal you open on the decoy in that
   time closes again as soon as its shell is killed. When logind refuses
   the soft-reboot, or
   drops it (`shutdown -c`), or PID 1 refuses it when logind's delay ends,
   nothing is queued: activation fails with the reason and removes everything
   it built. A soft-reboot dropped or refused that late was refused after
   logind's signal, so it is not free of traces: every program that waited
   for the signal has acted on it. unattended-upgrades' helper has sent an
   upgrade it found running SIGTERM and logged `Unattended-upgrade in progress
   during shutdown` on the decoy disk, and has exited until the next boot. When
   logind still holds the soft-reboot past its delay, activation drops it and
   fails (systemd 257 and newer) or, where logind cannot drop it (systemd 256
   and older), enqueues it with PID 1 directly, as logind would. It waits out
   at most 120 seconds of logind's delay, and 10 more for logind and PID 1:
   with `InhibitDelayMaxSec=` above 120 and a program that holds the switch
   back that long, activation fails at 130 seconds on systemd 257 and newer,
   and on 256 and older the direct soft-reboot stops that program, so
   unattended-upgrades' helper then writes its stop line after all. A second
   runtime drop-in clears the
   stop command of `blk-availability.service`, which Debian's and Ubuntu's
   lvm2 package enables: its `blkdeactivate -u` would unmount the hidden volume
   below `/run/nextroot` during the switch, or a LUKS or LVM decoy root on the
   way back. Debian's copy of that unit has no other command, so the drop-in
   also gives it a start command that does nothing; without one, systemd would
   refuse to load the unit. The way back removes both drop-ins, and leaves any
   other drop-in the decoy had for these units in place. Ctrl+C (or a
   SIGTERM) up to this point cancels the activation: it stops at the next step
   and removes everything it built, and the command exits with status 130. A
   step that runs a program to its end, such as the hidden system's
   activation, finishes first.

**The hidden NixOS system.** Activation builds the hidden toplevel into the
next root's store (`nix build --store /run/nextroot`) from the first of:

1. a flake given with `--nixos-flake` or `nixos_flake`, unless it is the
   decoy's own `/etc/nixos`, which is refused when it is named as a local
   path or a `path:`, `git+file:` or `file:` reference, also with a query
   (`?ref=main`), a `dir` parameter (`path:/etc?dir=nixos`) or through a link
   to the directory. Other spellings, such as a registry alias, `hg+file:` or
   a percent-encoded path, are not recognised, so the refusal does not catch
   them;
2. a flake in `<hidden-root>/nixos`, built for this machine's hostname; a link
   there to `/etc/nixos` is the decoy's own flake and refused the same way;
3. the legacy configuration: the decoy's `/etc/nixos` plus the hidden hardware
   configuration `init` placed in `<hidden-root>/root/upper/etc/nixos/`, which
   imports the hidden module `<hidden-root>/config/nixos/configuration.nix`.

Only the legacy configuration imports the hidden module by itself. A flake must
import it, or the hidden system lacks its settings (`system.autoUpgrade` forced
off, no shell history file) and whatever you added there, such as the [panic
switch](#panic-switch); the build runs with `--impure`, so a flake can import
it by its absolute path. A decoy whose `/etc/nixos` holds its own flake is
refused unless one of the first two applies: a build
of the decoy's flake reads only the decoy's files, so neither the hidden module
nor the hidden hardware configuration (the decoy's without its swap) would be
part of the hidden system. Give such a decoy a self-contained hidden flake:

1. Enter a hidden session with the decoy's own system:
   `sudo /mnt/data/nails activate --overlay-only`.
2. There, `/etc/nixos` shows the decoy's `configuration.nix` beside the hidden
   hardware configuration (`hardware-configuration.base.nix` is the decoy's
   without its swap). Copy what the hidden system needs into
   `<hidden-root>/nixos` and write a `flake.nix` there that builds this
   machine's hostname from those copies and imports the hidden module
   `<hidden-root>/config/nixos/configuration.nix` by its absolute path.
3. Lock it there with `nix flake lock`. Activation never updates `flake.lock`,
   so it must exist.
4. Build it there before you rely on it:
   `sudo nixos-rebuild build --flake <hidden-root>/nixos#<host> --impure`.
   `<host>` is the decoy's hostname, the configuration activation builds (in
   a session that uses the network-identity module, `hostname` prints the
   hidden name instead), and `--impure` lets the flake import the hidden
   module by its absolute path. `test` in place of `build` also applies it to
   the running session.
5. Deactivate. The next activation builds the hidden flake.

Never write or lock the flake on the decoy: the editor's state, root's
`~/.cache/nix` and the nixpkgs the lock fetches would land on the decoy disk.
Keep it self-contained, too. A flake that imports `/etc/nixos/configuration.nix`
by its absolute path reads the decoy's own files at every activation, which
updates their access times on a `relatime` decoy, and its
`./hardware-configuration.nix` is then the decoy's, swap included. `nails check`
names the choice under "NixOS profile". The build reads the decoy store through
the lower and writes every new path, the Nix database included, into the upper;
nothing reaches the decoy `/nix`.

Before it activates the toplevel, activation **copies the hidden system's
whole closure onto the hidden volume**: every store path the hidden toplevel
needs that is still read from the decoy store is copied up into the store
overlay's upper (`<hidden-root>/root/upper/nix/store`, or
`<hidden-root>/root/mounts/<store>/upper` when the decoy store is a separate
filesystem). The decoy can then garbage-collect or rebuild its own store
between sessions without breaking the hidden system: a path it deletes leaves
the lower only. The copy reads the decoy store through the read-only lower and
never writes it. It costs space and time once: the first entry copies the whole
closure (several GB for a desktop, minutes on a slow or encrypted backend; the
activation reports the megabytes copied every 15 seconds and the total time at
the end), later entries copy only the paths that are new
to the closure, which `<hidden-root>/root/store-kept` records. Activation is
refused before it copies anything when the hidden volume lacks the space.
Before the build, `nix-store --verify` also drops from the hidden store
database the paths the decoy deleted since the last session, so the build
realises them again instead of trusting them. What is not kept: store paths
only the hidden session's own profiles or results use (a `nix profile install`
in the hidden session); install them through the hidden configuration to keep
them. Building a changed hidden configuration after the decoy collected its
garbage may need build inputs that are gone; without a binary cache that build
fails, and the entry is refused and rolled back.

It then runs the toplevel's activation chrooted into the next root with a private
`/run`, in a process group of its own that a Ctrl+C on the terminal does not
reach, and the transition step repoints `/run/current-system` only after every
decoy unit has stopped, so PID 1 executes the hidden systemd against the hidden
`/etc`. The activation points the running kernel's module loader, hotplug
helper and firmware path at the hidden system's store, and so does a
`nixos-rebuild test` in a session entered without a build; every entry records
the decoy's values first, and every way back to the decoy (the return, an
emergency, an entry rolled back or recovered) writes them back. No bootloader is installed and no system profile changes. The hidden
toplevel must run on the decoy's kernel: the kernel modules come from
`/run/booted-system`. `--overlay-only` skips the build and enters with the
decoy's own system plus the hidden `/etc` and home.

**Debian and Ubuntu.** The same root overlay, with no build step: the hidden
configuration is whatever the upper's `/etc` holds. Change it from inside the
hidden session like any system configuration.

**The way back.** `nails deactivate`, in the hidden session, mounts the decoy
root at `/run/nextroot` (the same filesystem the overlay reads as its lower, so
mounting it writes nothing) and makes the decoy's other mounts again below it,
as the decoy had them when the entry began: every one it can take from the
decoy root or a filesystem the session carried (the filesystems its fstab
names, the RAM filesystems its initrd mounted, binds such as the read-only
bind NixOS puts over a `/nix/store` on the root filesystem, and mounts stacked
at one place), each with its own options, in the order the decoy mounted them.
A mount the entry recorded but the way back cannot make again from what it
holds (the hidden session unmounted a carried filesystem, or mounted something
on one) stops the way back instead of being left out or replaced: `deactivate`
then refuses, and `emergency` powers off. It then marks the hidden backend's
device-mapper stack for deferred removal, records the state as inactive and
soft-reboots, through logind as activation does. A program that holds a
shutdown block inhibitor in the session, or a logind that does not answer
whether one does, makes it refuse before it starts, with the session running
on (`emergency` does not wait for it). When the soft-reboot is not started
after all (logind refuses or drops it), the session runs on as well, but the
disks it unmounted for the switch stay unmounted: `deactivate` names them. A device it cannot mark (the hidden session removed `dmsetup`,
say) stays open after the switch, its key in RAM, until power-off:
`deactivate` and `emergency` name it once the soft-reboot is enqueued
(`backend_left_open` under `--json`). The orderly shutdown stops every hidden
program. The last step before the switch:

- scrubs the top of `/run`: it judges the entries two levels deep (three
  below `/run/systemd`), so a daemon's state deeper down stays, such as
  NetworkManager's per-link records. It deletes from an allowlist (the
  runtime journal, logind's session state, runtime units, `utmp`, and entries
  that the decoy did not leave when it stopped for the entry, such as the PID
  file of a decoy service that the hidden session's copy wrote again and an
  emergency's kill left) and never touches sockets, `/run/udev`, credentials
  or the current/booted system links, which the decoy's next userspace is
  built to inherit. The decoy's journald and the hidden session's write the
  same runtime journal, so on a volatile decoy the decoy's own records from
  before the session go too (see "What a soft-reboot leaves" below);
- puts back the name-server records below `/run/resolvconf` (openresolv, and
  Debian's resolvconf) as the decoy left them: NetworkManager leaves its record
  in place when it stops, and on NixOS the decoy's start would otherwise write
  the hidden session's name servers and search domains into `/etc/resolv.conf`
  on the decoy disk;
- gives the kernel back the decoy's module loader, hotplug helper and firmware
  path, which a hidden NixOS activation pointed at its own store;
- puts back most of the network state the hidden session changed, as the
  network bullet of "What a soft-reboot leaves" below lists;
- rewrites libmount's `utab` to the lines the decoy had at entry, each under
  the kernel mount ID of the mount the way back made in its mount's place,
  also where mounts are stacked at one place: the decoy's mounts come back as
  new mounts, and libmount joins a line to the mount with its ID, so it never
  joins one to another mount that got the old ID. None of the hidden session's
  lines stay, and a line of the decoy's that names no mount the way back
  restores is not given back;
- writes journald's kernel-message cursor, so the decoy journal imports no
  kernel record of the hidden session.

PID 1 then switches back into the plain decoy root, and the decoy starts at its
own login screen (a display manager set to log an account in automatically
logs it in again, as at boot). The hidden volume is unmounted and its mapping
closed by the switch itself, once the overlay that held it is released.

**What a soft-reboot leaves.** On the decoy disk, none of the hidden session's
files; in RAM until power-off, some kernel state and, on a volatile decoy, a
journal that starts late:

- the kernel ring buffer (`dmesg`), with the hidden session's kernel messages;
- `SoftRebootsCount`, two per session, readable with `systemctl show` on
  systemd 256 and newer;
- the same boot ID and continuous uptime across both transitions;
- where the way back set the kernel's process-number counter back, process
  numbers out of order: the decoy's units after it can hold numbers below
  those of kernel threads that started before them, which neither a cold boot
  nor a plain soft-reboot gives (`ps -eo pid,lstart,comm --sort=pid` shows the
  start times out of order), and a persistent decoy journal can hold the same
  process numbers twice under one boot ID;
- the network state the hidden session set up, as far as the way back does
  not put it back. Before the switch it puts back:
  - the links: it deletes the virtual links the session brought up (a tunnel,
    a dummy, the bridges and virtual ports of containers and virtual machines)
    and the Wi-Fi interfaces it added on one of the decoy's radios (a monitor
    or access point interface; this needs `iw` on the decoy, see below). A
    link counts as the decoy's only with the index it had at entry, and a
    link made again gets a new one, so a tunnel the session brought up under
    the name of one of the decoy's, which the decoy's own stop took down,
    goes too, while a link of the decoy's that the session only renamed
    stays;
  - the MAC address of each of the decoy's devices, where the session changed
    it. Many drivers refuse to change the MAC address of a device that is up
    (USB Ethernet adapters such as the ASIX AX88179, and many Wi-Fi cards);
    for those the way back takes the device down for the change and brings it
    up again, as NetworkManager does, and then reads the address back;
  - the hostname, wherever it differs from the decoy's at entry;
  - the policy-routing rules (`ip rule`, IPv4 and IPv6) and the nftables
    firewall tables the session added, such as those of a WireGuard full
    tunnel (wg-quick or NetworkManager), a VPN app, a container runtime or
    libvirt. Activation lists the decoy's own tables with `nft` and the way
    back lists them again with it, so this needs nftables installed on the
    decoy (see below);
  - the network settings for all devices and for new ones
    (`net.ipv4.ip_forward`, `net.ipv4.conf.all.*`, `net.ipv4.conf.default.*`,
    `net.ipv6.conf.all.*` and `net.ipv6.conf.default.*`), such as the
    forwarding a container runtime turns on or the `arp_ignore` and
    `src_valid_mark` a VPN app sets;
  - the per-link state NetworkManager and systemd-resolved keep below `/run`
    (NetworkManager's device state and the profiles it keeps only in memory,
    resolved's per-link DNS settings), rewritten in place, so each file keeps
    its owner and mode.

  The decoy's NetworkManager therefore does not adopt a session link as
  connected externally or record a profile for it in
  `/var/lib/NetworkManager/timestamps` on the decoy disk. A plain `emergency`
  puts back the same: by default it returns through the same way back as
  `deactivate`, and the variants that end otherwise (`--poweroff`, `--reboot`,
  or a degraded reboot) power off or reboot instead, where the decoy starts
  fresh and nothing the session changed lingers.

  The rest stays until the machine powers off or reboots: the addresses and
  routes the session gave the decoy's own devices; what it added inside a
  firewall table the decoy already had (a container runtime's chains in a
  table the decoy's own firewall uses) and the firewall rules it made with
  legacy iptables, outside nftables; every firewall table it added on a decoy
  without `nft`, where the way back cannot tell the session's tables from the
  decoy's, so a VPN app's table that blocks all traffic outside its tunnel
  keeps the decoy offline; the settings of a single device
  (`net.ipv4.conf.eth0.*`) and the network settings not listed above; any
  link, rule or table the session deleted, which is not made again, and the
  name it gave one of the decoy's links; a Wi-Fi interface of the decoy's
  that software in the session replaced with one of its own, as iwd does by
  default when it starts and airmon-ng does when it starts monitor mode: the
  way back deletes the replacement but does not make the decoy's interface
  again, so the decoy has no Wi-Fi on that radio; a Wi-Fi interface the
  session added where `iw` is not installed, and its links and rules where
  `ip` (iproute2) is not; and a MAC address the way back cannot set back,
  because the driver refuses the change even with the device down, because
  `ip` is not installed, or because the device was plugged in, or unplugged
  and plugged in again, during the session, which makes it a new link. The
  decoy's NetworkManager goes on using such an address unless the decoy's
  profile sets one, so it can reach the decoy disk (in a DHCP lease, for
  one). The way back also leaves alone a part of the network state that
  activation could not read in full, rather than take the decoy's for the
  session's: activation lists the decoy's own firewall tables with the
  decoy's `nft`, so a session that starts on a decoy without it leaves every
  table it adds even where the way back finds an `nft` later.

  `check` and `activate` warn before a session when the decoy has no `nft`,
  or has a Wi-Fi interface and no `iw` (the `network-tools` check), and name
  the package to install ([the decoy
  requirements](decoy-requirements.md#nixos) say how on NixOS). They warn and
  do not refuse, since a stock NixOS decoy has no `nft`.
  Before it asks, `deactivate` warns when the way back's last step will find
  no `ip` (iproute2), no `nft` (nftables) or, on a machine with a Wi-Fi
  interface, no `iw`, in the hidden session's system directories or, on
  NixOS, the decoy's system: without `ip` the virtual links the session
  made, the MAC addresses it changed and the policy-routing rules it added
  stay, without `nft` the nftables tables it added, and without `iw` the
  Wi-Fi interfaces it added on the decoy's radios. Beyond that, the step
  runs with no output after the session has ended, so nothing tells you what
  it left: take a VPN connection down with its own tool (`wg-quick down`,
  `nmcli connection down`, the app's disconnect), end monitor mode with
  `airmon-ng stop`, and stop the containers and virtual machines of the
  session before you deactivate, and end a session with
  `deactivate --poweroff` (or `emergency --poweroff`) when none of its
  network state may reach the decoy.
- on a volatile decoy, a journal that starts at the return. The way back
  deletes the runtime journal the decoy shared with the hidden session, so the
  decoy's own records from before the session (the activation's sudo line, the
  hidden build's progress, its shutdown) are gone with the hidden ones, and the
  kernel's boot messages are not read in again. `uptime` and `dmesg` still go
  back to the boot.
- the decoy's root and the mounts its initrd made (NixOS's store bind) as new
  mounts, where a plain soft-reboot keeps them; it unmounts the decoy's other
  mounts and mounts again what its fstab and units name, under new mount IDs
  as well. The way back makes every decoy mount it can take from the decoy
  root or a filesystem the session carried again as the decoy had it when the
  entry began (its filesystem, the directory of it the mount shows, its place
  in a stack, its options), NixOS's read-only store included, and PID 1 brings
  the API filesystems below `/dev`, `/proc` and `/sys` along itself. Each has a
  new mount ID (`findmnt -o ID`) and, once the decoy's PID 1 has marked the
  tree shared again, a peer group of its own: two mounts that propagated to
  each other (a bind made after the boot and its source) no longer do. Such a
  mount comes back also when it was made after the boot, by hand or by a
  service, where a plain soft-reboot unmounts it; a service that makes one at
  its start without looking whether it is there leaves it twice.
  `/run/credentials` is a mount of its own, and the mounts the boot made below
  `/run` (NixOS's `/run/keys`) are gone, as after a plain soft-reboot. A mount
  the way back does not make again is gone until it is mounted again, as
  after a plain soft-reboot: a mount of a filesystem the session does not
  carry (one the decoy's units mount outside its fstab, such as Debian's
  `/tmp` or a snap, an overlay or FUSE mount, a disk mounted by hand) and a
  filesystem on an automount point. The decoy's start mounts again what its
  fstab and units name and sets up its automounts again. `activate` warns
  about the others: one at a place the session carries (a filesystem another
  mount covers there, say), and one that a plain soft-reboot keeps (`/usr`,
  `/etc`, one marked `x-initrd.mount`), such as NixOS's `/etc` overlay.

On a persistent decoy journal (which the decoy requirements forbid), the decoy's
own shutdown and start lines appear under one boot ID, together with the kernel's
`EXT4-fs … unmounting filesystem` line for the hidden filesystem. The decoy's
shutdown before entry and its start after the way back write what an ordinary
shutdown and boot write: the random seed, a wtmp record, the journal if it is
persistent. With the ESP read-only in the hidden session, `loader/random-seed`
changes only when the decoy itself starts. **Power off after a session when RAM
residue matters.**

**Swap the binary only while inactive.** Replace the binary, flake or config on
the hidden volume only when no session is active. Never stage any of them on the
decoy, even briefly — see [Keeping NAILS off the decoy](#keeping-nails-off-the-decoy).

### Trusted computing base

NAILS runs as `root` and replaces the running userspace, so everything it loads
at activation is part of root's trusted computing base (TCB): the binary, its
config, and the hidden flake and `configuration.nix` it builds and enters. Keep
all of these on the hidden volume, `root`-owned, and treat their integrity as a
precondition for every run.

- **Root integrity is assumed.** NAILS performs no runtime self-integrity check
  and cannot detect a modified binary, config or flake while it runs. A root
  that is already compromised, or a hidden backend written to while it was
  unlocked, is outside the threat model. Protect the hidden volume's
  confidentiality and integrity at rest (strong passphrase, trusted hardware, no
  shared write access).
- **No unauthenticated or remote backends.** The flake, configuration and binary
  must come from storage you control and have verified. Building a
  configuration fetched from an unauthenticated source or a remote builder you
  do not trust is unsupported. NAILS gives root child processes a fixed,
  root-owned tool search path and a cleared environment so the caller's `PATH`
  and Nix settings cannot redirect which binaries run; do not reintroduce that
  exposure by pointing the backend at untrusted inputs.

---

## Standard vs emergency vs recover

NAILS has three ways to end or clean up a session. `deactivate` and `emergency`
run in the hidden session and end it with a soft-reboot back to the decoy;
`recover` runs on the decoy and removes what an interrupted activation left.

| Action | `deactivate` (standard) | `emergency` | `recover` |
|--------|-------------------------|-------------|-----------|
| Runs in | the hidden session | the hidden session (or the decoy, see below) | the decoy |
| Prepares the way back (decoy root at `/run/nextroot`) | Yes | Yes | — |
| Hidden programs | stopped in order by the shutdown | killed at once (`cgroup.kill` on every cgroup but PID 1's and its own) | — |
| Hidden backend | marked for deferred removal; closed by the switch | marked for deferred removal; closed by the switch | — |
| `/run` scrub, `utab` restore, kmsg cursor | Yes | Yes | — |
| Ends at | the decoy's login screen, or its desktop with autologin (`--poweroff`: off) | the decoy's login screen, or its desktop with autologin (`--poweroff`: off; `--reboot`: a full reboot) | the decoy, unchanged |
| Detaches a leftover `/run/nextroot` and removes `/run/overlay-runtime` and the drop-in | — | on the decoy: Yes | Yes |
| Reads the configuration first | Yes (falls back to defaults) | No: it runs before argument parsing, the configuration and logging | Yes |

### When to use each

- **`deactivate`** — the normal end of a session. Every hidden program gets an
  orderly stop, so applications can save. Pass `--poweroff` to power off instead
  of returning to the decoy, which is what clears RAM.
- **`emergency`** — an imminent threat. It acts immediately; pass
  `--countdown <SECS>` for an abortable wait, and `--poweroff` to power off
  (RAM decays: the strongest choice) or `--reboot` for a full reboot (which does
  not clear RAM).
- **`recover`** — on the decoy, after an activation that died part-way (a crash,
  a killed process, a failed `systemctl`). It detaches `/run/nextroot`, removes
  `/run/overlay-runtime` and the transition drop-in, reloads the service manager
  and resets the state. It also closes the hidden volume's device-mapper
  devices when nothing uses them, so the key leaves RAM; if the hidden volume
  is still mounted (for example because the configuration lives on it), it
  leaves the devices open and says so: unmount and close the volume yourself
  when you are done. It never reboots. In the hidden session it refuses and
  points at `deactivate`. It refuses as well while the interrupted
  activation's soft-reboot may still come (PID 1 has started it, logind holds
  it back for a delay inhibitor and cannot drop it, as systemd 256 and older
  cannot, or logind does not answer, unless PID 1 says logind does not run),
  and drops one logind can drop first. A plain `reboot` after an interrupted activation
  needs no `recover`: the leftover next root is detached during it and the
  hidden volume's devices are closed, as a full reboot would.

### What emergency does

In the hidden session, emergency:

1. prepares the way back (the decoy root at `/run/nextroot`, `/run` bound into
   it, the init checked);
2. marks the hidden backend's device-mapper stack for deferred removal (there
   is no option to leave it open; a device it cannot mark is named in its
   report and stays open until power-off);
3. enqueues the soft-reboot directly with PID 1, so the pending stop jobs keep
   `Restart=` from reviving anything;
4. kills every hidden cgroup at once with `cgroup.kill`. Only PID 1 and its own
   invocation survive until the switch.

The orderly shutdown then has nothing left to wait for, the `/run` scrub still
runs as the last step, and the machine returns to the plain decoy, which shows
its normal display-manager greeter (or a getty). **Log in normally, with the
decoy password.** NAILS logs nobody in; a display manager set to log an account
in automatically logs it in again, as at boot, and the decoy's desktop then
opens without a password. The screen goes to a text console for a few seconds in
between: to an observer this looks like a logout, not a crash, or, with
autologin, like a restart of the desktop.

- With `--poweroff` the machine powers off instead. RAM decays: the strongest
  answer to a seizure. Leave it off for a few minutes.
- If the way back cannot be prepared, emergency powers off instead: a
  soft-reboot without a prepared decoy root would restart the hidden userspace
  in place. If even the power-off cannot be enqueued, it asks the kernel to
  power off directly.
- Emergency runs before argument parsing, the configuration and logging, and
  reads nothing on the hidden volume to act. It logs its timed phases to the
  hidden-volume log afterwards, while it still can.
- If the hidden volume itself has failed, run the RAM copy that activation left
  in `/run`: `sudo /run/overlay-runtime/control emergency`.
- On the decoy, emergency removes what an interrupted activation left (it
  detaches `/run/nextroot` and removes `/run/overlay-runtime` and the drop-in),
  like `recover`, and drops the soft-reboot logind may still hold for that
  activation: that soft-reboot would restart the decoy's userspace a few
  seconds later, with records an ordinary boot never writes. A plain
  `emergency` drops it first, and `--poweroff` and `--reboot` right after
  their power action is enqueued, so they lose no time. Where it may still
  come (logind cannot drop it on systemd 256 and older, or does not answer,
  or PID 1 has already started it), emergency powers off (or reboots, as
  asked) at once, without the orderly stop of the decoy's services, so that
  soft-reboot cannot run first.

The backend watcher (`[backend_watch]`) and the sleep guard (`[sleep_policy]`)
run as runtime units of the hidden session from the RAM copy. The watcher's
opt-in automatic emergency returns to the decoy the same way; the sleep guard's
`teardown` mode powers off before the machine sleeps.

### Panic switch

Because emergency acts immediately, a single key that starts it is the fastest
panic button. The hazard is privilege escalation: the binary lives on the hidden
volume and is runnable by your account, so **never give it a passwordless
`sudo` rule**. Drive the panic switch through a root-owned systemd unit and a
polkit rule scoped to that one unit, and define both **only in the hidden
configuration** (the hidden NixOS generation, or the upper's `/etc` on Debian
and Ubuntu) so the decoy carries no unit and nothing that names the tool:

```nix
# Root-owned one-shot emergency. Kill the hidden session, then power off to clear RAM.
systemd.services.panic = {
  description = "Session teardown";
  serviceConfig = {
    Type = "oneshot";
    ExecStart = "/mnt/data/nails emergency --poweroff";
  };
};

# Let the operator start that one unit without a password — a scoped rule, not a
# blanket sudoers entry. It names the exact unit, so it grants nothing else.
security.polkit.extraConfig = ''
  polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units" &&
        action.lookup("unit") == "panic.service" &&
        subject.user == "operator") {
      return polkit.Result.YES;
    }
  });
'';
```

Bind a key to `systemctl start panic.service`. Drop `--poweroff` to return to
the decoy instead (its login screen, or its desktop with autologin). Keep
`<hidden-root>/nails` root-owned and not writable by any other account, or a
root-run `ExecStart` is the same escalation the passwordless-sudo warning is
about.

---

## On the separate machine

### Keeping NAILS off the decoy

The `nails` binary contains identifiable strings (path references, status
messages, environment-variable names). A raw string scan of a decoy disk that
ever held the binary will reveal them, and deletion does not help: the data can
survive in filesystem journals, unallocated blocks, SSD reserved areas and
backups.

- Build and verify the release on a separate machine, then copy it onto the
  hidden volume only. Never download or stage the binary on the decoy.
- Correct: `<hidden-root>/nails`, source under `<hidden-root>/src`.
- Wrong: anywhere on the decoy disk (`/usr/local/bin`, a persisted home, a
  downloads directory).

### Updating NAILS

New releases appear in the releases feed,
<https://github.com/WitteShadovv/nails/releases.atom>, which any feed reader can
follow without a GitHub account. Follow it inside a hidden session or on
another device, never on the decoy, where the reader's subscription would name
the tool. The feed shows a version as soon as its tag is pushed, before its
release is published, and keeps tags that never got a release (`v0.3.0-rc.1`):
a version is out once the
[Releases page](https://github.com/WitteShadovv/nails/releases) lists it with
its files. Versions ending in `-rc.N` are release candidates.

Update by replacing the binary (and, when they change, the flake and config) on
the hidden volume with a freshly built, verified release — never by downloading
onto the decoy:

1. Build or obtain a release following
   [release-artifact-reproducibility.md](release-artifact-reproducibility.md).
2. Verify it before trusting it: check the published `checksums.txt`, and prefer
   a build you reproduced yourself. An unverified binary is an untrusted addition
   to root's TCB.
3. Install on the hidden root only, `root`-owned, and only while no session is
   active. Download or build the new binary inside a hidden session and leave it
   on the hidden volume as `<hidden-root>/nails.new`; after the session, with
   the hidden volume mounted on the decoy and before you activate, move it over
   `<hidden-root>/nails`. Do not stage the new binary on the decoy at any point.
   Still in the session, run `<hidden-root>/nails.new config validate`: a new
   version can refuse a key the old one accepted, and the session is where the
   hidden configuration can be changed, not the decoy.
4. Re-read this guide after a version change; operational requirements can change
   between releases.

---

## On the decoy shell (before activation)

### History off on the decoy

Unlocking and mounting the hidden volume happens *before* NAILS runs, so the
unlock and mount commands you type are on the decoy. Run them, and `nails
activate`, in a shell with history off:

```bash
set +o history        # this session records nothing more to the history file
```

If you rely on `HISTCONTROL=ignorespace`, prefix each sensitive command with a
single leading space instead. Do not type the tool name, the mapper, the mount
point or the container path in any shell that still records history.

### Pre-activation residue

NAILS cannot clean up what happens before it runs. Account for this residue
yourself:

- **sudo command logging** records a `COMMAND=` line for every privileged
  command, including the full unlock and mount lines with the mapper name, label
  and container or device path, and the activation command itself.
- **Kernel ring-buffer messages** from opening the dm-crypt mapping and mounting
  the filesystem name the mapping and device, and reach the journal.
- **Generated systemd units**: systemd synthesises `.device` and `.mount` units
  named after the mapper and mount point, visible in `systemctl list-units`.
- **by-label / by-uuid symlinks**: udev creates `/dev/disk/by-label/<label>` and
  `/dev/mapper/<name>` while the volume is open.
- **The decoy's shutdown for the soft-reboot** writes what an ordinary shutdown
  writes (the random seed, a wtmp record, the journal if it is persistent).
- **Shell history**: covered above.

For the journal and kernel-message residue, the fix is to keep the journal off
persistent disk rather than to scrub it afterwards: configure journald with
`Storage=volatile` (or put the journal on impermanent storage) so these lines
never land on the decoy. See the "Common host traces" guidance in
[backends.md](backends.md). NAILS never touches a journal on the decoy disk; a
volatile journal loses these lines at the way back, together with the hidden
session's records (see "What a soft-reboot leaves" under
[How it works](#how-it-works)).

### What `check` touches

`nails check` (and `activate --dry-run`, which is the same command) writes no
log file, no state file and nothing in `/run`, and it leaves no file and no
mount behind. Activation runs the same checks and touches the same things with
them. On NixOS, unless it runs with `--overlay-only`, it first stages the
hidden configuration on the hidden volume, just before the checks: it
writes the hidden module in `config/nixos/`, and the link to it and the hidden
hardware configuration in `root/upper/etc/nixos/`, where they are missing.
`check` stages nothing. In detail:

- **Probes on the hidden volume.** Four checks try what the session needs and
  remove what they wrote before they finish. `hidden-volume` makes the file
  `.nails_write_test` in the hidden root, and `symlink-support` the link
  `.nails_symlink_probe`. `upper-fs-capability` makes the directory
  `.probe-<pid>-<time>` in the hidden root, sets and removes a `trusted.*`
  extended attribute on it, and tries a small overlay whose layers are inside
  it. `storage-readiness` makes the file `.nails_write_test` in `root/upper`
  and `root/work` when they exist. The hidden root, `root/upper` and
  `root/work` keep new modification times, and so does the container file of a
  hidden volume in a file container. A `check` killed in the middle of a probe
  can leave that probe's file or directory on the hidden volume, never on the
  decoy; remove it from inside a hidden session, not from the decoy shell.
- **With `--allow-decoy-storage`, on the decoy's storage.** The flag accepts a
  hidden root on storage the attach gate takes for the decoy's. The write and
  symlink probes then write there, and the modification times they move and
  anything a killed `check` leaves are on that storage too.
  `upper-fs-capability` does not run on such a root: it reports itself
  skipped.
- **No mount the system can see.** The trial overlay is mounted detached,
  through the kernel's mount API: no mount table lists it at any moment, so
  systemd never sees it and writes no `.mount` unit line about it to the
  journal. It is gone when the probe ends, and also when `nails` is killed.
  Where the kernel cannot mount it that way (without root, before Linux 5.2, or
  in a sandbox that blocks the call), `upper-fs-capability` fails before it
  writes anything; it never falls back to an ordinary mount. Trying the overlay
  loads the kernel's overlay module if it is not loaded yet, as activation
  does.
- **A kernel log line, in two cases.** When the filesystem under the trial
  overlay lacks something overlayfs wants (such as `upper fs does not support
  tmpfile`), overlayfs writes a warning to the kernel log, and journald keeps
  kernel messages like any other. ext4, xfs, btrfs and f2fs made with their
  default options, the filesystems [backends.md](backends.md) expects to work,
  lack none of it. And where an administrator has set the overlay module's
  parameter `nfs_export=Y`, the `index=off` that NAILS pins on each overlay it
  mounts, the trial overlay included, turns NFS export off for that overlay,
  and overlayfs logs `overlayfs: disabling nfs_export due to index=off`. This
  happens only with that parameter set: it is off by default, also in the
  kernels NixOS, Debian and Ubuntu ship.
- **Reads on the decoy.** `check` reads the decoy's configuration and state and
  runs some of the decoy's own tools to ask what they report, such as
  `systemctl` for the systemd version. On a decoy root mounted without
  `noatime`, a read or a program start can update an access time.

### Pre-activation checklist

```
[ ] Hidden volume mounted and writable at its own mount point (e.g. under /mnt),
    on storage of its own (see "Where setup happens"), with nothing mounted
    over it
[ ] No line in the decoy's /etc/crypttab or /etc/fstab opens or mounts it
[ ] Neither the outer nor the hidden volume opened with cryptsetup's --allow-discards
[ ] Hidden backend is a local Linux filesystem that can host an overlayfs upper
    (ext4/xfs/btrfs/f2fs; NOT NFS/SMB/9p/FUSE or FAT/exFAT/NTFS)
[ ] Hidden backend is kernel-managed (dm-crypt, loop), not a FUSE process that
    the soft-reboot would kill
[ ] `nails check` passes: systemd 254 or newer, the soft-reboot units, a decoy
    root that can be mounted again by device
[ ] Reviewed the fstab-policy decisions in `nails check`: the ESP read-only,
    other decoy filesystems overlaid, swap and unmounted disks masked
[ ] backend-detect preflight warnings resolved or accepted (see backends.md)
[ ] nails binary exists ONLY on the hidden volume; no copies on the decoy
[ ] Reviewed inherited decoy state in `nails check` (autostart, user services,
    lingering, autologin)
[ ] Accepted that shared accounts and network identifiers are not isolated by the
    overlay, or applied the hidden network-identity snippet
[ ] Decoy has plausible recent activity (generated with sync/account clients
    disconnected — see "Remote state and sync clients")
[ ] All unsaved work saved: activation logs you out
[ ] Emergency practiced
```

---

## Inside the hidden session

Everything in this section runs after activation's soft-reboot, logged in to the
hidden session (at its own login screen, or by the display manager's autologin).
The hidden volume is at the same path as on the decoy.

### Verifying the decoy

The `nails` binary lives on the hidden volume, so run `verify` from the hidden
side. A verify run never claims the system is clean; a run with no findings
prints "no known artifacts found" plus the list of areas it did not inspect.
Exit codes: `0` no known artifacts, `10` warnings, `11` critical, `1` the scan
could not run, `3` the configuration could not be loaded.

```bash
sudo /mnt/data/nails verify            # standard
sudo /mnt/data/nails verify --deep     # homes, histories, temp dirs, journal
sudo /mnt/data/nails verify --json     # machine-readable
```

Inside the session the live root is the session's overlay, and what belongs to
the session is not reported as residue. One note (`[INFO]`) says that its
runtime files in `/run`, the mounted hidden volume and its active state are
expected, and a NAILS path that the hidden layer holds, such as the link
`nails init` stages at `/etc/nixos/nails/configuration.nix` on NixOS, is a note
as well. The hidden layer hides whatever the decoy holds beneath such a path,
so check the decoy itself offline (below). The header counts warnings and
critical findings, not notes.

With `--deep`, verify also searches the systemd journal for the tool name, the
configuration file name, `cryptsetup` and the hidden volume path. sudo logs
every command run with it, so its records of your own commands (the unlock,
the mount, this verify run) match; verify names them as sudo's records. While
the journal is in RAM they are notes, as is every entry of the session's own
journal inside the session, because the way back or a power-off removes them.
When the journal keeps files on disk, every entry is a warning. On the decoy
any other entry is a warning too: only you can tell whether it is the decoy's
own record or one a hidden session left.

To inspect the decoy itself for leftovers, mount its image or partition
read-only and scan it offline (again from the hidden side):

```bash
sudo /mnt/data/nails verify --offline --root /mnt/decoy
```

In offline mode every path is read under `--root`, and the live-only checks
(running processes, the kernel mount table, open block devices, platform package
drift) are skipped. A decoy partition you mount by hand in the hidden session is
outside the fstab policy and is written directly, so mount it read-only
(`mount -o ro`).

To see the decoy the way an examiner would, add `--examiner`, and `--disk` with
the raw disk or image behind the mounted root:

```bash
sudo /mnt/data/nails verify --offline --root /mnt/decoy --examiner --disk /dev/sda
```

The examiner's view lists setup traces rather than session residue: LUKS headers
on partitions and in gaps, random-looking unpartitioned space, files that look
like encrypted containers, crypttab and fstab entries, LVM metadata archives,
udisks2 state, encryption tools and their access times, and recent-files or
history entries that name a container. Each trace is grouped under what an
examiner would conclude from it. It reports only, reads the disk read-only and
never changes the exit status; a LUKS header for the decoy's own full-disk
encryption is expected, and only you can tell which traces are explained.
[Setup traces an examiner looks for](decoy-requirements.md#setup-traces-an-examiner-looks-for)
says how to avoid each one.

`verify` reports only what the verify engine actually checks: known artifact
paths, running NAILS processes by binary identity, open crypt mappers and loop
devices, swap/memory warnings, platform package drift, and — with `--deep` —
shell history files, temp and log directories, `recently-used.xbel`/VeraCrypt
config naming the hidden root, and journal entries naming the tool or the
hidden volume. A clean result is evidence against *known* artifacts, not proof
the decoy is untouched.

### Rehearsing before you rely on it

The forensic E2E tests prove the leak claims on CI's virtual machines.
`nails rehearse` proves them on your machine, with your decoy, backend and
desktop, before you rely on them:

```bash
sudo /mnt/data/nails rehearse plant   # 1. inside an active hidden session
sudo /mnt/data/nails deactivate       # 2. end the session as usual
# on the decoy, unlock and mount the hidden volume again, then:
sudo /mnt/data/nails rehearse scan    # 3. from the decoy, or a later session
sudo /mnt/data/nails rehearse reset   # remove the rehearsal when done
```

`plant` puts a random token where a session most often leaks: a file named after
it in the hidden root and in your home, a `recently-used.xbel` bookmark, a
system-log line, a process command line and a desktop notification. Every file
write is checked first to land in the upper on the hidden volume; nothing is
written to the decoy. The token stays on the hidden volume
(`rehearse/state.json`) and is never printed, only a six-character fingerprint.

`scan` reads every mounted decoy block device (and active swap) raw and
read-only, without mounting anything, and searches allocated and unallocated
space for the token in ASCII and UTF-16LE. It refuses to run inside the session
the canary was planted in, which `plant` records by the session's entry time:
on the decoy after `nails deactivate`, after a power-off or in a later session
the scan runs, on every systemd version (`--allow-same-boot` overrides the
check, but a scan in the planting session proves little). To rehearse the
power-off exit instead, end the session with `nails deactivate --poweroff` and
boot the decoy again before the scan. Exit `0` means the token was not found,
`11` that it was (with the device and byte offset of each hit), `9` that a
device could not be scanned completely (it could not be read, it is empty, or
`--max-bytes` stopped it) or that its storage can hide the token from a raw
scan, which the result reports as not checked. Exit `9` is not a clean result,
although under `--json` its `ok` is `true` as for `0`: `ok` says only that the
scan ran to its end, so tell a clean result by the exit code. A channel the
canary could not be planted in (a notification with no desktop session to show
it, say) is listed with the result as not tested. `nails rehearse` alone shows
where you are and the next step.

A raw scan finds the token only where the decoy stores file contents as they
are. Where the storage can hide it, the result reports the device as not
checked, never as clean:

- a filesystem that can compress file contents: btrfs, bcachefs, zfs, or an
  f2fs made with the compression feature (`mkfs.f2fs -O compression`), which a
  mounted f2fs shows in its mount options and an image or an unmounted device
  in its superblock; an f2fs made without it stores every file as it is. A zfs
  dataset has no block device of its own to read, so it is listed as not
  scanned and not checked;
- NTFS, which can compress the files of a folder marked compressed: an `ntfs`
  or `ntfs3` mount, an NTFS image or unmounted device, and any `fuseblk`
  mount, the type ntfs-3g mounts NTFS as, which does not name the format;
- file-level encryption: an ext4 or f2fs with the encrypt feature (fscrypt),
  which the scan reads from its superblock whether it is mounted or not, and a
  device that holds the folder of an eCryptfs mount (an encrypted home or
  `Private` folder). That is the filesystem the folder lies on, and for a
  device named with `--device` also a whole disk with that filesystem in a
  partition, or a device below or above it (the partition under a LUKS or LVM
  mapping, an md array's member, a loop device or a mapping built on the
  partition or its disk, and a partition of such a device). Where the path to
  the folder runs through a mount point that the path to the eCryptfs mount
  does not, each filesystem mounted there counts, and so does the one below
  them, since the mount table does not show which of them was there when the
  folder was mounted. A `--device` the scan cannot place against such a folder,
  because the folder lies on a tmpfs, an overlay, a FUSE or network filesystem
  or in an image file stored on one, because more devices lie below its
  filesystem or below the device than the scan follows, because the device
  reads through a loop device a path that leads to no file (a deleted file, a
  device node outside `/dev`), or because sysfs lists no block device at the
  path, is reported as not checked too;
- an encrypted container (LUKS or BitLocker), of which a raw read is
  ciphertext: scan its unlocked mapping (`/dev/mapper/<name>`) instead;
- an LVM physical volume: scan each logical volume (`/dev/mapper/<vg>-<lv>`)
  instead;
- storage on which the scan identifies no filesystem at all;
- an image cut short, as a copy that stopped early leaves it: an ext4, xfs,
  f2fs, vfat or exFAT image that ends before its filesystem does, a swap image
  that ends before its swap area does, or a whole-disk image that ends before a
  partition its table lists, or before the disk its GPT was written for.

File-level encryption escapes that list in these cases, and a device that
holds it can read as clean:

- an eCryptfs folder that is not mounted while the scan runs, since the scan
  sees one only through its mount;
- an eCryptfs mount that was moved (`mount --move`) after it was made, or
  whose folder's filesystem was moved or detached (`umount -l`), since the
  scan places the folder by the paths the mount table shows;
- every eCryptfs folder in an `--offline` scan, which reads no mount table;
- a device that a program serves from the storage of an eCryptfs folder (an
  NBD or ublk device), which sysfs does not link to that storage, and one that
  reaches the image file holding such a folder by another path than its loop
  device shows (a hard link, another mount of the image's filesystem), as the
  scan knows an image file by its path;
- a vault a FUSE tool encrypts (gocryptfs, CryFS or EncFS, as Plasma Vaults
  use), which the scan does not recognise at all.

Log in as the eCryptfs folder's owner, which mounts it, and scan the decoy's
devices on the decoy itself rather than an image of them. Do not take a clean
scan of a disk that holds a FUSE tool's vault as proof.

A mounted device is judged by its mount. A device that is not mounted
(`--device`) or an image (`--offline --image`) has no mount to judge it by, so
the scan identifies it from its raw superblock. Give it the unlocked decoy
filesystem: the unlocked mapping itself, or an image of it. An image of a whole
disk is classified partition by partition, and the result names each partition
it could not check; on an encrypted disk that is the encrypted partition, whose
unlocked mapping is the one to scan. An empty image or device is reported as not
scanned.

A clean scan covers only what a host can read. It cannot see SSD cells the
drive has remapped or keeps in reserve, blocks discarded with TRIM, disks that
are not mounted (name them with `--device`), the encryption header area or
firmware storage; the scan prints this list with every result. To scan an image
of the unlocked decoy instead, use
`nails rehearse scan --offline --image <file>`.

### Shell history

NAILS keeps shell history off the decoy by where shells run, not by scrubbing
afterwards:

- Every shell of the hidden session runs inside the overlay. Its history file is
  in the hidden home, so it lands in the upper on the hidden volume, and the
  shell is stopped (or, in an emergency, killed) before the way back. Nothing of
  it reaches the decoy.
- As its last step activation SIGKILLs the decoy's interactive shells, including
  the one you ran it from, so none runs an exit trap or flushes its in-memory
  history with the activation command in it. A SIGKILLed shell writes nothing.
- NAILS makes no write to, and no read of, the decoy history after the fact,
  because such an access is itself an artifact. Your protection is that the
  history never reaches the decoy in the first place, backed by an amnesic decoy.
- The `incremental-history-flush` **preflight** warns when the shell you run
  NAILS from flushes history after every command (`INC_APPEND_HISTORY`/
  `SHARE_HISTORY`, or `history -a` in bash `PROMPT_COMMAND`): such a shell has
  already written the unlock and mount commands to disk before activation can
  help. Clear that warning before activating.

See [bash-history-forensics.md](bash-history-forensics.md) for the mechanics, and
[decoy-requirements.md](decoy-requirements.md) for the decoy-side history
hardening you configure yourself.

### Changing settings

Change `nails.toml` here, never on the decoy, and without an editor:

```bash
sudo <hidden-root>/nails config set persona.mode fresh-home
sudo <hidden-root>/nails config unset nixos_flake
sudo <hidden-root>/nails config show   # every effective value and its source
```

`config set` and `config unset` keep the file's comments and every other key,
check the result as `config validate` does and replace the file at once, only
when it lies on the hidden volume `nails` runs from. The backend watcher and the
sleep guard of the running session keep the settings it started with, so a
change reaches them at the next activation. The hidden volume root and the
state file stay where the session recorded them: the way back reads the
session's state there.
[Changing settings](configuration.md#changing-settings) has the rules.

### Changing the hidden configuration

On NixOS, `nixos-rebuild test` applies a change to the running hidden session.
Give it the target activation builds:

- the legacy configuration, when there is no hidden flake and `nixos_flake` is
  unset: `sudo nixos-rebuild test`. Inside the hidden session `/etc/nixos` is
  the hidden configuration (the decoy's files plus the hidden hardware
  configuration in the upper);
- a hidden flake: `sudo nixos-rebuild test --flake <hidden-root>/nixos#<host>
  --impure`, with `<host>` the decoy's hostname, the configuration activation
  builds (in a session that uses the network-identity module, `hostname`
  prints the hidden name instead), and `--impure` because the flake imports
  the hidden module by its absolute path. For a flake named with
  `nixos_flake`, pass that reference instead.

On a decoy whose `/etc/nixos` holds a flake, a plain `nixos-rebuild test`
builds that flake, the decoy's own, which activation refuses to build: it
fails, or it puts the decoy's own system into the session, without the hidden
module (no panic switch, `system.autoUpgrade` no longer forced off). Always
name the hidden flake there.

Do not use `switch` or `boot`: they try to install a bootloader into the
read-only ESP and fail. The next activation builds the hidden configuration
again from `<hidden-root>/config/nixos/` or your flake, so keep that source in
step with what you test.

On Debian and Ubuntu, change the hidden system like any other: `apt`, edits in
`/etc`, `systemctl enable`. Every change lands in the upper and is the hidden
configuration from then on. A package change also gives hidden sessions a
record of their own, which a later update of the decoy does not reach: see
[Package changes in hidden sessions](#package-changes-in-hidden-sessions).

### Copy-up cost and shadowed decoy updates

The hidden root's upper persists across sessions. OverlayFS copies a lower file
into the upper **in full** the first time you open it for writing, truncate it
or change its mode or owner — even a one-byte edit of a multi-gigabyte file
copies the whole file. On a slow or encrypted backend this can stall for
seconds or minutes.

- The first write to a large file (the Nix database, browser profiles, VM images)
  is slow; later writes are fast.
- The upper only grows: copied-up files and whiteouts persist across sessions.
  Watch space with `df -h <hidden-root>` (`nails check` fails when free space is
  below `minimum_space_mb`); run `nix-collect-garbage -d` and clear caches
  inside the session.
- **A copied-up file shadows later decoy updates.** Once a file is in the upper,
  the hidden session sees that copy, whatever the decoy does to its own file
  afterwards. After the decoy updates itself between sessions, the hidden session
  can see an outdated mix: the Nix database copied up in one session does not
  list store paths the decoy built later, and a hidden `/etc` keeps its old files
  after a decoy rebuild or package upgrade. Store paths the decoy garbage-collects
  do not break the hidden NixOS system: its closure is kept on the hidden volume
  (see "The hidden NixOS system").
- **A kernel update in the hidden session deletes the running kernel's
  modules.** Every hidden session runs on the decoy's kernel and loads its
  modules from `/usr/lib/modules/<release>`. A kernel package update inside the
  session (on Arch Linux, a `pacman -Syu` that brings a new `linux`) deletes
  that tree in the upper, so every later session starts without modules for the
  kernel it runs on: a USB stick, a filesystem or a network card whose driver is
  not loaded yet does not work there. Update the kernel on the decoy instead.
  The `kernel-modules` check warns, and never refuses, when a hidden session
  deleted or replaced that tree, a directory above it or its index
  (`modules.dep`, or `modules.dep.bin`, the form `modprobe` reads), made one
  of those directories anew so the decoy's copy no longer shows through, or
  wrote its own index before the decoy last rebuilt its own; and when the
  decoy itself lacks the tree, as after a kernel update without a reboot. It
  names the path that holds the change and the `discard` that deletes the
  hidden sessions' copy of it. When that path is `/usr/lib/modules/<release>`
  itself, updating the decoy's kernel to a new release and rebooting the decoy
  into it works too, since the new kernel's modules are in a tree of their
  own; a change above it (to `/usr/lib/modules`, `/usr/lib` or `/usr`) hides
  the decoy's modules for every kernel, so there a kernel update does not
  bring them back. For an outdated index, `sudo depmod <release>` in a hidden
  session rebuilds it. An index a hidden session wrote no earlier than the
  decoy's (a `depmod` after installing a module) passes with a note, and a
  decoy without `/usr/lib/modules`, such as NixOS, keeps its modules elsewhere
  and passes. Only root can see whether a directory was made anew, so an
  unprivileged `nails check` that needs to know says it cannot tell and names
  the `sudo` line.
- To drop a path's hidden copy so the decoy's own files show through again, run
  `discard` **on the decoy**, with the hidden volume mounted:
  `sudo /mnt/data/nails discard /etc/nixos` (it lists what it deletes and
  confirms first; discarding `/nix` drops the hidden Nix store and warns first).
  For a separately overlaid filesystem it also removes that filesystem's upper.
  It is refused in the hidden session, where the upper is the live root.

### Package changes in hidden sessions

A hidden session can install, update and remove packages with the
distribution's package manager, and the changes land in the upper like any
other. The package manager keeps its record of what is installed there too,
and that record is where hidden sessions and the decoy drift apart:

- **dpkg** (Debian, Ubuntu) writes each change of a run to its journal in
  `/var/lib/dpkg/updates` first, and its whole record, `/var/lib/dpkg/status`,
  again at the end of the run (and after every 250 changes). The first
  package a hidden session installs, updates or removes gives hidden sessions
  a copy of the record of their own, which
  they keep whatever the decoy does afterwards: after an update of the decoy
  they run its new files under a record that still lists the old versions,
  does not know the packages the decoy installed since, and lists the ones it
  removed. Their `apt` then works from that old record.
- **pacman** (Arch Linux) keeps one directory per package in
  `/var/lib/pacman/local`, which the overlay merges: hidden sessions see the
  decoy's packages with their own changes on top. A package that both a
  hidden session and the decoy changed is listed twice in hidden sessions, and
  they keep their own, older files of it over the decoy's; one a hidden
  session removed and the decoy updated since is listed without its files.
  After a full update in a hidden session and a later one on the decoy, a
  hidden session can fail to start.
- **rpm** (Fedora) keeps a SQLite database,
  `/usr/lib/sysimage/rpm/rpmdb.sqlite`, with its write-ahead log next to it,
  which hidden sessions copy at their first change and keep from then on, as
  with dpkg.

The `package-drift` check warns, and never refuses, when hidden sessions'
record no longer follows the decoy's. For dpkg it names each package the decoy
installed, updated or removed since hidden sessions made their copy of the
record, with its version on each side, and leaves out the packages a hidden
session changed itself: dpkg writes or deletes a package's files in
`/var/lib/dpkg/info` whenever it changes the package, so their copies in the
upper show which packages those are. For pacman it names each package listed
twice or without its files. For rpm it reads both databases with a reader of
its own (no SQLite library, no `rpm` command, nothing written), the
transactions rpm committed to the write-ahead log but has not copied into the
database yet included, and names each package the decoy installed, updated or
removed since, as for dpkg. rpm keeps no file per package beside its database,
so a package counts as one a hidden session changed when the upper holds, or
deleted, one of the files the package installs by either side's record (not
its directories, configuration files or ghost files, which other packages
share or the operator edits), at the place rpm installed it: through the
directory links that rpm's own records give, never read on the decoy. Fedora
records a kernel's modules below `/lib`, which its `filesystem` package
installs as a link to `usr/lib`, so a kernel update in a hidden session
counts as its own by the modules it wrote below `/usr/lib` or the tree it
deleted there. A package that installs no such file, other
than the public keys rpm records as `gpg-pubkey`, which the check leaves out,
is named when its record differs. Activation shows
the same warning before it asks to log you out (unless `-y` skips the
question), so you can answer no, and again among the warnings of its result,
which then exits `9`. A hidden session that deleted or replaced the database
itself draws a warning that names the `discard` that brings the decoy's back.
Where the mount table cannot be read, the kernel's own word on each directory
above a database or a package's file (`statx`) tells whether it lies on a decoy
filesystem of its own, such as a separate `/var`. The check asks only about a
directory whose own directories it has seen to be neither symbolic links nor
automount points, such as an EFI system partition mounted on first use,
since asking about a path below a link follows the link and asking about one
below an automount point mounts it, and takes a directory the decoy lacks for
no mount point.

The check says it cannot tell only where nothing can decide without leaving a
trace or reading what cannot be read:

- an unprivileged `nails check` that would need to read the decoy's database
  on a filesystem that keeps access times: only root reads it without changing
  its access time, so it names the `sudo` line (on a filesystem mounted
  `noatime` no read changes one, and the check reads it without root);
- a symbolic link on the way to the decoy's database: following it changes the
  link's access time;
- a database or an upper that cannot be read (an I/O error, a file larger than
  any package database, a dpkg record in a format NAILS does not know whose
  copy differs from it, an rpm database whose pages or headers do not hold, an
  rpm database or log over 4 GiB, one that records a directory, a file's path
  or a link's target of 4096 bytes or more, longer than a path can be, one
  whose packages, with the links they record and the paths resolved through
  them, would take more than the 256 MiB of memory the check keeps for both
  databases, or one rpm wrote while it was read, twice in a row);
- links in rpm's records on the way to a package's file that make a loop, or
  that lead to a path of 4096 bytes or more: no system resolves such a path,
  so the check cannot tell where the file lies;
- an rpm transaction stopped half way that left a rollback journal: rpm rolls
  it back the next time it opens the database, so the check names neither
  state;
- a dpkg run stopped half way, in a hidden session or on the decoy, that left
  its journal in `/var/lib/dpkg/updates` where hidden sessions see it: dpkg
  adds the journal to its record the next time it runs, so the check names
  neither record and gives the `sudo dpkg --configure -a` that finishes the
  run, which apt asks for there too (the decoy's journal counts only once
  hidden sessions keep a copy of the record, since before that they see the
  decoy's record as the decoy does);
- no mount table, and a kernel older than 5.8, which does not say what is a
  mount point, or a directory on the way that the kernel cannot be asked
  about.

To bring hidden sessions back in line, make the decoy's changes in a hidden
session too:

- Debian and Ubuntu: `sudo apt-get update` and `sudo apt-get full-upgrade`,
  then install there what the decoy installed and remove what it removed;
- Arch Linux: install the decoy's version of each package the warning names
  again from the decoy's package cache, `sudo pacman -U
  /var/cache/pacman/pkg/<name>-<version>-<arch>.pkg.tar.zst`, or remove one a
  hidden session had removed there again with `sudo pacman -R <name>`. A full
  `pacman -Syu` in a hidden session also updates the kernel package when a
  newer one is out, which deletes the running kernel's modules for every later
  session (see [above](#copy-up-cost-and-shadowed-decoy-updates));
- Fedora: `sudo dnf upgrade --refresh`, then install there what the decoy
  installed and remove what it removed.

Update the system on the decoy, and install in hidden sessions only what the
hidden system needs and the decoy must not have. While no hidden session has
changed a package, hidden sessions see the decoy's record as it is, updates
included. With dpkg or rpm, the first package change in a hidden session means
that every later update of the decoy needs the same update in a hidden
session.

### On-screen visibility

Any on-screen tell that you are in the hidden environment is a shoulder-surfing
and screen-recording liability. NAILS adds none: it changes no prompt and no
terminal colours. What the hidden session looks like is up to its configuration;
a hidden desktop that looks different from the decoy's, or a login screen that
does, is itself a tell.

### Disks mounted during the session

The fstab policy covers what the decoy's fstab names. A disk you mount in the
hidden session — a USB drive the desktop automounts, a decoy partition the
policy masked, a Windows partition — is a real disk outside every overlay, and a
read-write mount of it takes your writes (mounting it read-write alone already
writes its superblock).

- The session watcher raises a desktop alert ("Disk mounted with write access")
  for every read-write mount of a disk outside the hidden volume
  (`session_mounts.alert`, on by default). Its alerts appear on the desktop of
  the account logged in on the machine's own screen; while nobody is logged in
  there, none can be shown.
- A disk mounted over the hidden root itself (with `/mnt` as the root, an
  ordinary `mount /dev/sdc1 /mnt`) takes every file saved under `/mnt` from
  then on. The watcher raises "Disk mounted over a folder in use", naming the
  disk, and `nails status` shows it under the hidden volume; `sudo umount
  /mnt` takes it off. A disk mounted on a parent of the root (`/mnt` over a
  root at `/mnt/data`) hides it the same way and is reported the same way,
  naming its own mount point. NAILS writes nothing there meanwhile, and the
  cover triggers no emergency.
- With `session_mounts.read_only = true`, every disk the session does not use is
  read-only for the session, from the hidden boot on and for every disk attached
  later: mounts come up read-only (`mount` warns "write-protected, mounted
  read-only"), `mount -o rw` fails, and writes fail. Turn it on unless you need
  to write to an external disk in the hidden session.
- `nails deactivate` unmounts these disks before the way back (a busy one is
  detached and its users end with the session), and the way back makes the disks
  writable again, so the decoy mounts them as usual.

A root shell can always set a disk writable again and mount it; the guard is
against automounts and mistakes. See
[Disks mounted during the session](configuration.md#disks-mounted-during-the-session).

### During the session

```
[ ] Work only inside the hidden session; every write lands on the hidden volume
[ ] Do not mount decoy partitions or external disks read-write: the fstab
    policy covers only what the hidden systemd mounts (session_mounts.read_only
    enforces this; the watcher alerts otherwise)
[ ] On NixOS, apply changes with `nixos-rebuild test` (with a hidden flake:
    `--flake <hidden-root>/nixos#<host> --impure`), never `switch` or `boot`
[ ] Keep the emergency command ready: sudo /mnt/data/nails emergency
[ ] Know your physical emergency procedure
```

---

## When things go wrong

Every recovery here follows the same shape. In the hidden session, the way out
is `deactivate`, then `emergency`, then a power-off; a power-off is always safe,
because nothing of the session is installed on the decoy. On the decoy, the
cleanup is `nails recover`, run from a shell with **history off**
(`set +o history`).

### Cleaning up by hand

If `nails recover` cannot run on the decoy (the hidden volume is gone, the binary
does not start), remove an interrupted activation's leftovers yourself:

```bash
set +o history

# 1. Detach the next root and everything below it.
umount -R /run/nextroot

# 2. Remove the session plan and RAM copy, the transition drop-in and the
#    runtime guards (blk-availability's stop, NixOS's static addresses and
#    the D-Bus units).
rm -rf /run/overlay-runtime
rm -rf /run/systemd/system/systemd-soft-reboot.service.d
rm -f /run/systemd/system/blk-availability.service.d/zz-overlay-runtime.conf
rm -f /run/systemd/system/network-addresses-.service.d/zz-overlay-runtime.conf
rm -f /run/systemd/system/dbus.service.d/zz-overlay-runtime.conf
rm -f /run/systemd/system/dbus.socket.d/zz-overlay-runtime.conf
systemctl daemon-reload

# 3. Confirm nothing is left.
findmnt -R /run/nextroot          # prints no rows
ls /run/overlay-runtime           # no such file or directory
```

Then close the backend as usual (`umount <hidden-root>`, `cryptsetup close
<mapper>`). If `cryptsetup close` reports the device busy, a service that
started during the activation holds a copy of the next root's mounts in a
mount namespace of its own: `grep -l /run/nextroot /proc/*/mountinfo` names
its processes; restart that service, or power off. Powering off instead does
the same: everything above lives in `/run` and is gone at power-off.

If the activation built a hidden NixOS system, or its switch failed, power
off instead. `nails recover` also writes back the kernel's module loader,
hotplug helper and firmware path, which the hidden system's activation
pointed at its store (the decoy then loads no module and no firmware), and
removes the session's masks in `/run/systemd/system`,
`/run/systemd/system.control` and `/run/systemd/system-generators`, which
keep the decoy's swap, its boot-loader units and the other units the hidden
root does not need masked, and systemd's GPT auto-generator from running. By
hand, only a power-off does.

**Do not edit or delete `state.json` by hand** — `recover` resets it once the
hidden volume is back.

A plain `reboot` with a leftover populated `/run/nextroot` would be turned into a
soft-reboot into that tree by systemd 255 and newer. The transition step refuses
any tree the plan did not arm and detaches it, so this cannot enter the hidden
root; clean up anyway.

### Specific situations

**Interrupted activation** (the activation was killed, crashed or failed after it
built `/run/nextroot`). `nails status` reports an interrupted entry and exits 7
with "run `nails recover`". Run it. Residue: whatever the build wrote stays in the
upper on the hidden volume; the decoy is untouched. Ctrl+C during activation
rolls the entry back by itself.

**Deactivation refuses or fails** in the hidden session. Use `nails emergency`:
with the session plan it returns to the decoy where it can prepare the way back
and powers off where it cannot. Without the plan a plain `emergency` does
nothing (next paragraph): use `nails emergency --poweroff` there.

**The session plan is gone** (`nails status` reports the hidden root without a
way back: the plan in `/run/overlay-runtime` is missing, unreadable, or was
written by another NAILS version). Nothing knows how to return to the decoy
then: `deactivate` refuses before it asks anything, with exit 6, and a plain
`emergency` finds no plan either and does nothing. Power off:
`nails emergency --poweroff`, which needs no plan.

**The switch is refused** (the soft-reboot comes back to the root it left).
Right before PID 1 switches, NAILS checks the other root's init the way PID 1
will (and, entering, masks the decoy units the hidden system must not start).
When that fails it takes the prepared root down again, so PID 1 restarts the
root it is on instead of freezing, and it keeps the reason, never on the decoy
disk. The next `activate` or `deactivate` clears it.

- Entering: you are back on the plain decoy, with the hidden volume unmounted
  and its mapping closed. Open the volume again: `nails status` shows
  `Last switch: refused at <time>` with the reason, which was kept on the
  hidden volume (`switch_refused` in `status --json`). The record still says
  active, so run `nails recover` once, fix the cause and activate again. A
  hidden root accepted on the decoy's own storage (`--allow-decoy-storage`)
  keeps no reason: the switch writes nothing to the decoy's disk.
- Leaving: the hidden session starts again, but its shutdown has unmounted the
  hidden volume from its path, and the binary on it with it. The reason was
  kept in RAM: `sudo /run/overlay-runtime/control status` shows it, and `sudo
  /run/overlay-runtime/control emergency` takes the way back again or powers
  off.

**The hidden session hangs.** Switch to a text console (Ctrl+Alt+F2), log in and
run `nails emergency`; if nothing responds, power off. A stuck user service can
delay an orderly `deactivate` by up to `DefaultTimeoutStopSec` (90 s by
default); `emergency` does not wait for it.

**Suspend / resume.** Suspend keeps the whole hidden session — the overlay, the
open mapper and the master key — resident behind the hidden lock screen, and the
decoy is not running at all. Do not suspend during a session. Set the decoy's
logind lid switch to `lock`
([decoy-requirements.md](decoy-requirements.md)), and set `sleep_policy.mode` in
`nails.toml`: `block` keeps the host awake for the session, a closed lid
included, `teardown` powers off when the host is about to sleep.

**Power loss / crash / hang.** On the next boot the decoy comes up normally:
nothing of the session is installed on the decoy, and `/run` is gone. If
`nails status` reports a recorded state that does not match, run `nails recover`
once. Residue: the upper on the hidden volume only.

**Backend loss** (USB pulled, I/O errors) in the hidden session. The hidden
root's upper is on the backend, so the session itself starts failing. The backend
watcher alerts you. Run emergency from the RAM copy: `sudo
/run/overlay-runtime/control emergency`; it needs nothing from the hidden volume.
Power off if that does not respond.

**Volume full (ENOSPC).** Copy-up or a session write fails. Free space from
inside the session (`nix-collect-garbage -d`, clear caches) or deactivate
normally and `discard` a bloated path from the decoy. Do not delete files
directly out of an upper or work directory by hand.

**OOM.** If the kernel killed the NAILS process during activation, treat it as
an interrupted activation above.

---

## Threat-model limitations

The adversary, assumptions and out-of-scope list are defined in
[threat-model.md](threat-model.md). This section covers the operational side of
the limits operators most often miss.

### Compelled disclosure

NAILS is built for one coercion case: you are made to unlock the **decoy**
once, and the decoy is then examined offline. For that case to hold:

- The decoy's credentials must open the decoy and nothing else. Use a deniable
  backend for the hidden volume and never reuse a passphrase between the two.
- The decoy must be amnesic, the last session must have ended with a clean
  `deactivate` or `emergency`, and the machine must have been powered off.
- Check before you rely on it: `nails rehearse` on the real machine, and
  `verify --offline --examiner` against an image of the decoy. Remove, or be
  ready to explain, every setup trace it lists: encryption tooling, headers,
  random-looking space, crypttab entries, history.
- Use the decoy normally between sessions, so its logs account for the hours
  the machine ran.

NAILS does not help if you are made to disclose the **hidden** volume's
credentials, if coercion continues after the decoy is unlocked, if the disk is
imaged more than once and compared, or against an examiner who concludes a
hidden volume exists from the setup traces even without proof. The
[threat model](threat-model.md#compelled-disclosure-of-the-decoy) states the
line precisely.

### Shared decoy account and persona modes

The hidden root's lower is the decoy root, so the hidden session starts with the
decoy's users and **the decoy's homes**: every account, credential store and
application profile in the decoy home is visible and usable inside the hidden
session — browser profiles and cookies, SSH/GPG keys and agents, password-manager
databases, shell/editor/application history and caches. Changes made in the
hidden session go to the upper, so the decoy home on disk stays as it was.

`[persona]` in `nails.toml` sets how the hidden session relates to the decoy
account. `persona.mode = "fresh-home"` gives the hidden session an empty home,
created once in the upper at the first entry, so nothing of the decoy home shows
through. `persona.mask_inherited` writes masks for the named autostart entries
and user units into the upper at each entry. See
[configuration.md](configuration.md#persona-modes). In the default
`shared-home` mode, sign in to the hidden session's own accounts for sensitive
work rather than the decoy's, and treat using the decoy's logins in the hidden
session as an informed choice.

#### Inherited autostart, services and autologin

The hidden session inherits what the decoy starts automatically: enabled system
services, autostart entries (`~/.config/autostart`, `/etc/xdg/autostart` and, on
NixOS, the autostart directories of the Nix profiles), enabled user services and
timers, lingering, and display-manager autologin. Sync, cloud and messaging
clients therefore run under the decoy identity and can contact remote servers
and your other devices. `nails check`, and the `inherited-autostart` warning in
activation's pre-flight output, report what needs review: what you or
third-party software added, lingering, autologin, and the clients on a short
list of known trace writers, tagged remote-linked (a name-only heuristic). The
desktop's and the distribution's own components are counted but not reported;
see [Inherited decoy state](configuration.md#inherited-decoy-state). In
`shared-home`, `nails check` also says on a line of its own that the hidden
session starts in the decoy home.

Disable what you do not want **inside the hidden session**: mask the unit
(`systemctl --user mask syncthing.service`), remove or override the autostart
entry, or, on NixOS, leave it out of the hidden configuration. The change lands
in the upper, so it takes effect for the hidden session only and the decoy is
unchanged. **Lingering is a decoy setting** — disable it on the decoy itself.
Disabling changes what *runs*; it does not roll back remote or account state.

**Autologin repeats at every switch.** Each soft-reboot starts a fresh display
manager, and one set to log an account in automatically logs it in again, as
at boot: after `activate` the hidden desktop opens without a password, and after
`deactivate` or `emergency` the decoy's does. Plasma Login Manager 6.7 and
later are the exception on systemd 256 and later, which counts soft-reboots:
they log in on their own after a full boot, and after a soft-reboot only with
`Relogin=true` under `[Autologin]` or, from 6.8, under the seat's
`[Autologin][seat0]`, whose `Relogin` counts first where it sets one. NAILS
logs nobody in and leaves the setting alone; `nails check` lists an autologin
it finds in the decoy's GDM, SDDM, Plasma Login Manager or LightDM
configuration, whatever `Relogin` says, and keeps listing it while the decoy
has it, even once the hidden session turns it off. It reads the files as the
display manager does, in its order (in each order it may take, where its
locale decides), so an empty setting in a file read later turns autologin off
(see [Inherited decoy state](configuration.md#inherited-decoy-state)). To keep
autologin on the decoy but have the hidden session start at its login screen,
turn it off in the hidden session only:

- NixOS, with any display manager: add
  `services.displayManager.autoLogin.enable = lib.mkForce false;` to the hidden
  configuration (`config/nixos/configuration.nix` on the hidden volume, or the
  hidden flake). The next activation builds it in.
- Debian and Ubuntu: inside a hidden session, edit the display manager's file.
  For GDM set `AutomaticLoginEnable=false` in the `[daemon]` section of
  `/etc/gdm3/daemon.conf` (Debian) or `/etc/gdm3/custom.conf` (Ubuntu). For
  the others, empty the setting in the file the display manager reads last,
  which overrides its drop-ins: `autologin-user=` in the `[Seat:*]` section
  of `/etc/lightdm/lightdm.conf` for LightDM, `User=` under `[Autologin]` in
  `/etc/sddm.conf` for SDDM or in `/etc/plasmalogin.conf` for Plasma Login
  Manager; create the file if it is missing. Empty it in the same file under
  the sections for the seat as well, wherever a file sets it there: LightDM
  applies each `[Seat:…]` section that matches the seat, such as
  `[Seat:seat0]` or `[Seat:seat*]`, after `[Seat:*]`, and Plasma Login
  Manager 6.8 and later read `[Autologin][seat0]` instead of `[Autologin]`
  when a file has it. A Plasma Login Manager drop-in that marks the setting
  immutable with `[$i]` has to be edited itself. The edit lands in the upper,
  so it applies from the next activation and the decoy keeps its own setting.

#### Remote state and sync clients

Ending a session keeps the hidden changes in the upper, out of the decoy's view.
It cannot reach state a remote server or another device already holds. For
two-way sync and account-bound clients (Syncthing, Nextcloud/Dropbox, an IMAP
Sent folder, browser sync, messaging apps) running under the decoy identity:

1. The hidden session writes to a synced folder (in the upper, invisible on the
   decoy).
2. The live client pushes that data to the server or peer before the session
   ends.
3. Back on the decoy, the client reconciles and **pulls it back onto the decoy
   disk**, where an examiner can recover it.

The overlay cannot prevent this. **Ending the session is not a rollback of your
online accounts.** Mitigations, strongest first: do not start the decoy's
account-bound clients in the hidden session (mask them as above), and quit or
disconnect every sync/cloud/mail/messaging client before sensitive work; treat
anything they touched as already on the remote.

#### Shared network identifiers

The hidden session shares the host's network identity. It also starts with the
decoy's machine-id, hostname, MAC addresses and NetworkManager profiles
(including VPN autoconnect), because they come from the decoy root; NAILS changes
none of them. Correlation through these is out of scope for the overlay. To
present a different identity, apply it in the hidden configuration (the hidden
NixOS generation, or the upper's `/etc`); NAILS ships optional snippets
(`nix/modules/hidden-network-identity.nix`,
`nix/modules/network-identity/00-hidden-identity.conf`). NetworkManager has no
global VPN-autoconnect switch, so disable it per profile with `nmcli connection
modify <vpn> connection.autoconnect no`. The clean way back now undoes what the
snippet changed on the running system: it sets each device's MAC address back
to the decoy's, taking the device down for the change when its driver refuses
it while the device is up, and sets the hostname back, so a normal
`deactivate` leaves neither on the decoy. A plain `emergency` puts them back
the same way, returning through the clean way back by default; `--poweroff`
and `--reboot` power off or reboot instead, where the decoy starts fresh. The
one exception is a device whose MAC address the way back still cannot set
back: it keeps the random address until the machine powers off or reboots,
and nothing tells you so (see [How it works](#how-it-works)). When the random
address must never reach the decoy, end a session that used the snippet with
`nails deactivate --poweroff` (or `nails emergency --poweroff`).

### Network anonymity and Tor

NAILS hides the hidden session from an offline examiner of the decoy disk, not
from a network observer. The session reaches the network over the decoy's own IP
address and connection, with the decoy's machine-id, hostname and MAC addresses
([Shared network identifiers](#shared-network-identifiers) above). It does not
anonymise traffic and routes nothing through Tor. For anonymity against an ISP,
a Wi-Fi operator or a remote service, use a tool built for it — Tor Browser,
Tails or Whonix. NAILS is itself installed from [Tails](install-from-tails.md).

You may run Tor Browser, or route the hidden session through a Whonix gateway,
inside the session if you choose. Run it from inside the session so its files
live in the upper and never reach the decoy disk: a Tor Browser bundle or
flatpak in the hidden home, Tor Browser added to the hidden NixOS generation,
or a Whonix gateway VM the session routes through. A gateway VM's virtual
network is kernel state, which the way back puts back only in part (see
[How it works](#how-it-works)): shut the VM down and stop its network before
you deactivate. One caveat, and it matters: doing so is
deniability-neutral only if the decoy plausibly uses Tor too. Tor traffic is
recognisable on the wire, so if the decoy never touches Tor, even occasional Tor
use from the hidden session leaves an ISP-visible "Tor from this machine, at
these times" signal — a network record that places Tor use on this machine
during the hours a hidden session ran, and so works against the decoy.

The rule: keep the hidden session's network behaviour consistent with the
decoy's, or do not route it through Tor.

### SSD wear-levelling

SSDs distribute writes and keep spare blocks, so `shred`/`truncate`/`wipe` on an
SSD are mostly ineffective and old data can survive in remapped cells. Use
full-disk encryption so wear-levelled blocks are encrypted, prefer a whole-device
or partition hidden volume over a file container, and **never enable TRIM/discard
on, or `fstrim` through, a volume that contains a hidden volume** — discards
destroy or expose it.

### Storage backend hazards

[backends.md](backends.md) has the support matrix and per-backend guidance.
Across all setups:

- **Discards destroy or expose hidden volumes.** Never pass cryptsetup's `--allow-discards`,
  never mount with `-o discard`, never `fstrim` the outer or hidden volume.
- **File containers expose timestamps.** Using a container updates its
  mtime/ctime; ctime cannot be restored, so it shows when it was last used.
- **Do not open a container file for writing during a session** — overlayfs
  copies the whole file up.
- **Copy-on-write filesystems and SSDs keep old blocks.** Put the hidden volume
  on a whole device or partition on CoW/SSD decoys, and disable automatic
  snapshots of any filesystem that holds a container.

### Outer-volume maintenance

For a VeraCrypt hidden volume, **write to the outer volume only in protection
mode** (`--protect-hidden=yes`): without it, writing to the outer volume can
overwrite and destroy the hidden volume. `cryptsetup --type tcrypt` **cannot**
provide this protection, so do not use cryptsetup to write to the outer volume of
a VeraCrypt container that holds a hidden volume. Seed the decoy content of the
outer volume **once**, when the volume is created, so you rarely need to write to
it again.

### Cold-boot and running-memory attacks

DRAM retains data briefly after power-off (longer when cold). A soft-reboot back
to the decoy keeps the kernel running and frees the hidden session's memory
without zeroing it. A warm reboot does not clear RAM either: the memory stays
powered across the reset, and the firmware wipes it only if it honours the TCG
Platform Reset Attack Mitigation request (the MOR bit). Setting MOR writes an EFI
variable, that is NVRAM on the decoy machine, so NAILS does not set it. Only a
power-off, followed by a few minutes without power, lets the contents decay:

- Power off completely (not suspend) in threat situations — `nails emergency
  --poweroff` — and end a normal session with `nails deactivate --poweroff`
  before handing the machine over.
- Harden the decoy kernel so freed memory is wiped: add `init_on_free=1` to the
  decoy kernel command line. The hidden session runs on the same kernel, so this
  covers it too. Do not add `page_poison=1`: on a kernel built with page
  poisoning (the NixOS kernel is) it takes precedence over `init_on_free` and
  turns it off, so the kernel overwrites freed pages with a pattern but leaves
  its freed small allocations (slab objects, such as the names of files the
  session opened) as they were. The `memory-wipe` pre-flight check reads the
  booted command line and, when it is silent, the kernel config
  (`CONFIG_INIT_ON_FREE_DEFAULT_ON`, from the running kernel's own
  `/proc/config.gz` or the copy in `/boot` or `/usr/lib/modules`), and warns
  when the decoy kernel does not zero freed memory, `page_poison=1` included.
- There is no complete software defense against a memory dump of a running
  system; the protection is preventing access while it runs.

Keeping the key out of RAM or encrypting idle RAM does not cover a live
seizure. TRESOR holds the master key in the CPU's debug registers instead of
RAM, and FridgeLock encrypts pages while the machine is suspended, but both
protect only the *key* and *cold* memory: the live working set — the overlay's
writable upper, the page cache and every running process's memory — must be
plaintext in RAM to be usable at all while the volume is mounted, and neither
mechanism touches it. A DMA-capable peripheral (a Thunderbolt or USB4 device, a
PCIe or NVMe/M.2 card, an ExpressCard) makes this worse: it reads RAM straight
off the bus without involving the CPU, so a register-only key is no defence —
the TRESOR-HUNT attack (ACSAC 2012) used a DMA write to inject kernel code that
spilled TRESOR's key out of the debug registers into ordinary RAM and then
DMA-read it. An IOMMU set to remap DMA is the hardware defence against this. The
`dma-protection` pre-flight check reads whether the IOMMU is remapping DMA
(from `/sys` and the kernel command line) and whether a Thunderbolt/USB4
controller reports DMA protection (`iommu_dma_protection`), and warns when a
live memory attacker could read RAM over the bus. It judges each IOMMU group:
where the kernel leaves the IOMMU off by default (no `intel_iommu=on`, as on
NixOS), the firmware's Kernel DMA Protection still turns it on, but remaps only
the devices behind a Thunderbolt or USB4 port and leaves every internal device,
and any card added to an internal PCIe or M.2 slot, identity-mapped, so the
check warns about the identity-mapped groups even while a docked device's group
is remapped. The warning names the devices in those groups, and
`lspci -s <address>` tells you what each is: a kernel also identity-maps some
built-in devices on purpose, as AMD's does for an APU's integrated GPU while
memory encryption is off, and the names tell such a device from a card in a
slot or a docked one. Like the MOR bit it cannot enable the firmware's DMA
protection for you, so the fix is to turn VT-d/AMD-Vi and Kernel DMA Protection
on in BIOS/UEFI setup (and `intel_iommu=on` on the decoy kernel command line
where the kernel does not remap by default) and, above all, to power off before
the machine leaves your control.

### What has not been validated on hardware

The session is validated in virtual machines. These are open until measured on
real hardware:

- the time from trigger to the login screen on a real desktop (in the test VM:
  about 3 s to a shell, 9 to 15 s until the system has settled);
- GPU, Wi-Fi, VPN and Bluetooth coming back after each transition, NVIDIA's
  proprietary driver, docks and external displays;
- the way back setting a MAC address back on a USB Ethernet adapter or Wi-Fi
  card whose driver refuses the change while the device is up: taking the
  device down for it is tested in a VM on an emulated NE2000 network card,
  whose driver refuses the change in the same way, not on such an adapter or
  card;
- the way back deleting a Wi-Fi interface the session added on one of the
  decoy's radios (a monitor or access point interface): tested against a
  simulated `iw` and radio, not a real card;
- decoy roots unlocked with a TPM-sealed key (the mapping survives the
  soft-reboot, but anything in the hidden session that measures into PCRs changes
  them for the rest of the uptime);
- decoy roots on storage the initrd assembled beyond LUKS and LVM (mdraid,
  multipath, an iSCSI root): a soft-reboot never assembles that storage again,
  so no service stopped at either transition may tear it down;
- GRUB's `grubenv` (keep `/boot` read-only, as the fstab policy does);
- user services that do not stop promptly, delaying an orderly transition up to
  `DefaultTimeoutStopSec`.

Secure Boot does not affect a soft-reboot, which loads no new kernel.

Rehearse on your own machine before relying on it.

---

## Additional resources

- [threat-model.md](threat-model.md) — the adversary model NAILS assumes
- [decoy-requirements.md](decoy-requirements.md) — amnesic decoy setup and
  decoy-side history hardening
- [backends.md](backends.md) — storage backend matrix and deniability notes
- [architecture.md](architecture.md) — how the session is built, and why it
  takes the whole root with a soft-reboot
- [bash-history-forensics.md](bash-history-forensics.md) — history-protection
  mechanics
- [SECURITY.md](../SECURITY.md) — vulnerability reporting policy
- [README](../README.md) — project overview
