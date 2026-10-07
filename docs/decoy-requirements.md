# Decoy requirements: making the base system amnesic

NAILS hides a session behind a decoy system by running it inside one overlay of
the whole decoy root, entered and left with `systemctl soft-reboot`, so the
hidden session's writes land on the hidden volume instead of the decoy disk.
That guarantee only holds if the decoy itself keeps **no durable record** of the
hidden session. The decoy runs before the soft-reboot into the hidden session
and again after the way back: a decoy that writes logs, audit records, crash
dumps or swap to its own disk records the activation command, its own shutdown
and start under one boot ID, and anything it imports from the kernel ring
buffer.

The decoy also has to be one the session can enter and leave:

- **systemd 254 or newer** with `soft-reboot.target` and
  `systemd-soft-reboot.service` installed (`systemd-version`,
  `soft-reboot-units`). Debian 13, Ubuntu 24.04 and current NixOS qualify;
  Debian 12 and Ubuntu 22.04 are refused. A NixOS decoy on a nixpkgs that does
  not install the two units needs the module `nails check` prints (and so does a
  hidden NixOS configuration, or the session could not leave).
- **A decoy root on a block device** (`decoy-root`): ext4, xfs, btrfs (including
  a subvolume) or f2fs. The way back mounts it again by device, so a tmpfs root
  (impermanence), an overlay root (overlayroot, bilibop-lockfs) and ZFS are
  refused.

This document lists what an amnesic decoy must look like, what NAILS enforces at
pre-flight, and how to satisfy each requirement on the supported platforms. The
[residue catalog](#residue-catalog) at the end lists every class of trace in one
place, with the check that warns about it, the check that detects it and the VM
test that asserts it.

## What NAILS enforces

The `decoy-persistence` pre-flight check inspects the decoy before any state is
written. It performs **no writes** — it never rotates or vacuums the decoy's own
logs, because destroying the decoy's log history is itself a deniability tell.

### Fail closed (activation is refused)

<!-- residue-catalog:begin fail-closed -->
| Finding | Why it matters |
|---|---|
| [Persistent systemd journal](#fail-closed-activation-is-refused) | The decoy journal records the sudo command line (including the hidden-root binary path) before the soft-reboot, and the decoy's own shutdown and start around each transition. |
| [Classic syslog daemon](#fail-closed-activation-is-refused) | rsyslog or syslog-ng writes every logged line to /var/log on the decoy disk, outside the journal. |
| [Audit daemon log](#fail-closed-activation-is-refused) | auditd records executed commands and file access in /var/log/audit, independent of journald. |
<!-- residue-catalog:end fail-closed -->

Override these with `--accept-persistent-decoy` on `activate`/`check`, or
`accept_persistent_decoy = true` in `nails.toml`, only if you understand and
accept that what the decoy logs around each soft-reboot may survive on the
decoy disk.

### Warn (surfaced, never blocking)

- **Root filesystem type** — the persistent substrate the decoy's own records
  live on, outside the overlays.
- **atime policy** — a root mounted without `noatime`/`relatime` records read
  access, leaving an atime trail on the decoy.
- **Crash-dump channels** — a disk `kernel.core_pattern`, systemd-coredump
  `Storage=external`, registered pstore records, or an armed kdump. Each can
  persist process or kernel memory (which may contain hidden-session data) to the
  decoy disk or firmware-backed storage.
- **Maintenance timers** (NixOS) — `nixos-upgrade.timer`, which can trigger an
  automatic decoy rebuild (and touch EFI NVRAM) while the hidden session runs.
  The generated hidden module force-disables `system.autoUpgrade`.
- **sudo's own logs** — `Defaults logfile=` in `/etc/sudoers` or
  `/etc/sudoers.d/*` writes every sudo command line to a file, and I/O logging
  (`log_input`, `log_output`, the `log_stdin`/`log_ttyout`/... flags, or the
  `LOG_INPUT:`/`LOG_OUTPUT:` command tags, stored under `iolog_dir`) records
  whole terminal sessions, keystrokes and output included. Both write to the
  decoy disk, outside the journal.

The `residue-catalog` pre-flight check adds the channels the catalog probes by
path: a populated LVM metadata archive, udisks2 state, and the session-time
stamps described below. It warns or notes them and never blocks.

## Suspend and the lid switch

Suspend and hibernate are not a filesystem concern, so they sit outside the
overlay model, but they are a direct hazard: suspending while a session is active
leaves the whole hidden environment — overlays, the open dm-crypt mapper and the
master key — resident in RAM behind the decoy lock screen. On resume the decoy
login unlocks a still-live hidden session. logind's defaults make this the normal
case: `HandleLidSwitch` and `HandleLidSwitchExternalPower` both default to
`suspend`, and desktops add their own idle auto-suspend.

The `sleep-policy` pre-flight check parses `/etc/systemd/logind.conf` and its
`logind.conf.d/*.conf` drop-ins and warns (never blocks) when the effective lid
or idle settings would suspend an active session.

Set the decoy's lid switch so a closed lid does not suspend. The neutral choice
is `lock` (lock the screen, stay running) or `ignore`; add a drop-in rather than
editing the main file:

```ini
# /etc/systemd/logind.conf.d/10-lid.conf
[Login]
HandleLidSwitch=lock
HandleLidSwitchExternalPower=lock
HandleLidSwitchDocked=ignore
IdleAction=ignore
```

On NixOS, set it declaratively in the **decoy** configuration (a drop-in on the
decoy, not the hidden module):

```nix
services.logind.settings.Login = {
  HandleLidSwitch = "lock";
  HandleLidSwitchExternalPower = "lock";
  HandleLidSwitchDocked = "ignore";
  IdleAction = "ignore";
};
```

Also disable any desktop-level auto-suspend (GNOME/KDE power settings), which
logind does not govern.

For defence in depth, set `sleep_policy.mode` in `nails.toml`. `block` holds a
sleep/idle inhibitor for the life of the session so the host cannot suspend while
active; `teardown` holds a sleep *delay* inhibitor and powers the machine off
when the host is about to sleep, within logind's `InhibitDelayMaxSec` window
(default 5s). Both run as runtime units of the hidden session. The inhibitor is a runtime backstop — still fix the lid
switch above, since a blocked suspend with the lid shut can overheat a laptop.

## Satisfying the requirements per platform

### NixOS

- **Soft-reboot units**: until nixpkgs installs `soft-reboot.target` and
  `systemd-soft-reboot.service`, declare them as `nails check` shows
  (`systemd.units`); the hidden configuration needs them too.
- **A disk-backed root**: a tmpfs root (`nixos-impermanence` on `/`) is refused.
  Keep the root on disk; a wiped-on-boot `/var` or `/home` on its own tmpfs is
  fine (the hidden session mounts a fresh tmpfs there, in RAM).
- **Volatile journald**: `services.journald.storage = "volatile";`.
- **No classic syslog / audit**: do not enable `services.rsyslogd`,
  `services.syslog-ng` or `security.auditd` / the audit framework on the decoy.
- **noatime**: add `"noatime"` to the root filesystem's mount options.
- **No swap / hibernation**: leave `swapDevices` empty and do not configure
  `boot.resumeDevice` or a resume kernel parameter.

### Ubuntu

- **Ubuntu 24.04 or newer** (systemd 255+). `overlayroot` is not supported: an
  overlay root cannot be mounted again for the way back.
- **Volatile journald**: set `Storage=volatile` under `[Journal]` in
  `/etc/systemd/journald.conf`, or in a drop-in such as
  `/etc/systemd/journald.conf.d/50-volatile.conf`. NAILS resolves the main
  file and every `journald.conf.d/*.conf` drop-in the way systemd does, so a
  drop-in that sets `Storage=persistent` is caught too.
- Remove or disable `rsyslog` and `auditd` if installed.
- Mount the root with `noatime`; disable swap and hibernation.

### Debian

- **Debian 13 or newer** (systemd 257+). `bilibop-lockfs` and other RAM-overlay
  roots are not supported: the way back mounts the decoy root by device.
- **Volatile journald**: `Storage=volatile` in `journald.conf` or a
  `journald.conf.d/*.conf` drop-in.
- Remove or disable `rsyslog`/`syslog-ng` and `auditd`.
- `noatime`; no swap; no hibernation.

## The sudo-log exposure and its mitigation

Running `sudo nails …` is itself a sensitive event: sudo logs the invoking user,
the target command and its full path through its configured log channel
(journald, syslog, or `/var/log/sudo.log`). On a persistent decoy that record
names the hidden-root binary path; `nails activate` runs on the decoy, before
the soft-reboot into the overlay.

**Mitigation**: run NAILS on an amnesic decoy (volatile journald, no syslog,
no sudo `logfile` or I/O logging in sudoers) so the sudo record is never durably
written, and keep the binary at a neutral path
on the hidden volume. NAILS cannot suppress sudo's own logging without tampering
with the decoy, which would itself be a tell.

## Shell history hardening

Hidden-session history never reaches the decoy: every hidden shell runs inside
the overlay and writes its history file into the upper. On the decoy,
`nails activate` SIGKILLs the decoy's interactive shells as its last step, so a
shell that saves history on exit (bash on SIGHUP) never writes the activation
command (see [bash-history-forensics.md](bash-history-forensics.md)). NAILS does
**not** configure the decoy's own shells, and a shell that flushes history after
every command (zsh `INC_APPEND_HISTORY`, `history -a` in `PROMPT_COMMAND`) has
already written it; the `incremental-history-flush` check warns about that. If you type on the decoy — and the
pre-activation unlock and mount commands must be typed there — harden the decoy's
history yourself so an interactive shell has nowhere to write:

- **Environment.** Set `HISTSIZE=0` and `HISTFILESIZE=0`, and point the history
  file at the null device, in the decoy's shell profile so a login shell keeps no
  on-disk history.
- **Shell options.** Disable history recording (`set +o history`) and append mode
  (`shopt -u histappend`) for sessions where you unlock the volume.
- **Filesystem redirection.** Symlink `~/.bash_history` and `~/.zsh_history` to
  the null device so even a shell that ignores the environment writes nowhere.
- **Boot-time enforcement.** A systemd unit that truncates any regular history
  file and re-creates the symlinks early in boot closes the gap before the first
  interactive login.

On an amnesic decoy (impermanence, overlayroot, bilibop) the history file is on
volatile storage and discarded at power-off regardless, so these steps are
defence in depth. Do **not** disable them during a session, re-enable history
recording, or run `history -a`/`history -w`: each of those writes the commands
you typed back to the decoy.

## Writes that bypass the overlays

The root overlay covers only the root filesystem. The hidden systemd reads the
decoy's fstab (or the hidden NixOS generation's) and would mount every other
decoy filesystem **directly and read-write**, and activate decoy swap. Before
the switch the `fstab-policy` decides each entry, and activation puts the
decision in place inside the next root:

| Entry | In the hidden session |
| --- | --- |
| `/boot`, `/boot/efi`, `/efi` (ESP, boot partitions), and filesystems mounted read-only | read-only bind |
| other mounted local filesystems (a separate `/home`, `/var`, `/srv`), mounted VM host shares and overlays | overlay, upper at `<hidden>/root/mounts/<unit name>/upper` |
| swap | masked: never activated |
| local filesystems not mounted now but mounted at boot, network filesystems, overlay entries with an upper on a disk | masked: not available in the hidden session |
| tmpfs and kernel filesystems, `noauto` entries, the hidden volume | left alone |

A mount that is not in fstab (an automounted USB drive, a disk mounted by hand)
is not carried into the hidden session at all; the hidden session can mount it
again itself, and then writes to it directly. `verify` cannot tell what a
session wrote there, but
[`nails rehearse`](operator-guide.md#rehearsing-before-you-rely-on-it) scans
every mounted disk for its canary.

## Session-time records

Some records do not hold what the session did, only that the machine was
running. An examiner compares them with the decoy's own logs, and unexplained
uptime points to use the decoy does not account for.

- **The timesyncd clock stamp.** `systemd-timesyncd` touches
  `/var/lib/systemd/timesync/clock` at each sync and at shutdown. The session's
  touches go to the upper, but the decoy's own shutdown before the session and
  its start after it stamp the decoy copy.
- **Persistent timer stamps.** Timers with `Persistent=true` record their last
  run under `/var/lib/systemd/timers`. Runs during the session land in the
  upper; at the next decoy boot, missed timers catch up at once, which dates the
  gap.
- **SMART power-on hours.** The drive counts the hours it is powered, in
  firmware. No software can change or hide this; a decoy that is used normally
  keeps its logged uptime plausible.

On an amnesic decoy (impermanence, overlayroot) the first two are wiped at every
boot anyway. `verify` reports their timestamps as notes, so you can see what an
examiner would see.

## Setup traces an examiner looks for

An examiner looks for traces of the setup as well as of a session: the backend's
headers and tooling, configuration that opens encrypted storage, and history
that names a container. `nails verify --offline --root <image> --examiner`
reports these on a mounted decoy image, grouped by what an examiner would
conclude from them. It reports only and changes nothing.

### LVM metadata archives

LVM writes a copy of a volume group's metadata to `/etc/lvm/archive` before
every change and to `/etc/lvm/backup` after it, with the command line, host name
and time. Running `pvcreate`, `vgcreate` or `lvchange` on the hidden backend from
the decoy records a volume group the decoy does not use. Do not run LVM tools on
the hidden backend from the decoy, or set `archive = 0` and `backup = 0` in the
decoy's `/etc/lvm/lvm.conf` before you ever do.

### udisks2 state

Unlocking or mounting the backend through udisks (a file manager, GNOME Disks,
`udisksctl`) leaves per-drive state under `/var/lib/udisks2` and asks the
keyring to remember passphrases. Unlock and mount the backend with `cryptsetup`
and `mount` from a shell instead.

### crypttab and fstab

An entry in `/etc/crypttab` or `/etc/fstab` for the hidden backend (a tcrypt or
VeraCrypt mapping, a loop-mounted container, an unexplained mapper name) tells an
examiner where to look. The decoy's own full-disk encryption legitimately has an
entry; the hidden backend never should. Open it by hand each time.

### Encryption headers, high-entropy space and containers

The audit reads the raw disk when given `--disk` and reports:

- LUKS1 and LUKS2 headers at partition starts, in gaps and in the LUKS2
  secondary-header slots;
- gaps between partitions and space after the last one, sampled for entropy:
  random-looking bytes where a fresh disk holds zeros suggest a headerless
  encrypted volume;
- partitions with no known filesystem signature and high entropy;
- files larger than the threshold whose size is a multiple of 512, with no known
  header and high entropy: the TCHunt heuristic for TrueCrypt and VeraCrypt
  containers.

A VeraCrypt hidden volume inside an outer volume is indistinguishable from the
outer volume's free space; what stands out is the outer volume itself. Fill free
disk space with random data when the disk is set up so the encrypted region does
not stand out, and prefer a partition or whole device over a container file on
the decoy.

### Backend tooling and history

VeraCrypt installed on a decoy, or a `cryptsetup` binary whose access time is
recent, says encrypted volumes were opened. VeraCrypt's `History.xml` and
`Favorite Volumes.xml`, a `recently-used.xbel` entry and a shell history line
running `cryptsetup` or `veracrypt` name the container and when it was used.
Disable VeraCrypt's history, harden the decoy shell history (see
[Shell history hardening](#shell-history-hardening)) and mount the decoy root
`noatime`.

## Residue catalog

Generated from `nails-core/src/residue_catalog/rows.rs`; do not edit the tables
by hand. A unit test fails when they drift; regenerate them with
`REGENERATE_CATALOG_DOCS=1 cargo test -p nails-core residue_catalog`.

A row with "none" in the pre-flight or verify column says why nothing at that
point can see the class; verify lists those classes among the areas it did not
check. A row with "none" in the VM-test column says why no VM test asserts it.

### Session residue

<!-- residue-catalog:begin session -->
| Class | Where | Platforms | Pre-flight | Verify | Mitigation | VM test |
|---|---|---|---|---|---|---|
| [Persistent systemd journal](#fail-closed-activation-is-refused) (`persistent-journal`) | `/var/log/journal` | all | `decoy-persistence` (refuses) | `journal-scan` | Set Storage=volatile under [Journal] in journald.conf or a journald.conf.d drop-in. | `decoy-persistence-preflight` |
| [Journal window around each soft-reboot](#the-sudo-log-exposure-and-its-mitigation) (`pre-entry-journal-window`) | journald records of `sudo nails activate`, the decoy shutdown before the soft-reboot and the decoy start after the way back | all | `decoy-persistence` (refuses) | `journal-scan` | Run on a volatile journal, so the window stays in RAM; keep the binary at a neutral path. | `decoy-journal-leak` |
| [Classic syslog daemon](#fail-closed-activation-is-refused) (`classic-syslog`) | `/var/log/syslog`, `/var/log/messages`, `/var/log/auth.log` | all | `decoy-persistence` (refuses) | `deep-scan-files` | Remove or disable rsyslog and syslog-ng on the decoy. | `decoy-persistence-preflight` |
| [Audit daemon log](#fail-closed-activation-is-refused) (`auditd`) | `/var/log/audit` | all | `decoy-persistence` (refuses) | path probe (warn) | Disable auditd and the audit framework on the decoy. | `decoy-persistence-preflight` |
| [sudo log file](#the-sudo-log-exposure-and-its-mitigation) (`sudo-logfile`) | `/var/log/sudo.log` | all | `decoy-persistence` | path probe (warn) | Remove `Defaults logfile=` from sudoers and sudoers.d. | `examiner-audit` |
| [sudo I/O logging](#the-sudo-log-exposure-and-its-mitigation) (`sudo-io-log`) | `/var/log/sudo-io` | all | `decoy-persistence` | path probe (warn) | Remove every I/O logging option and tag from sudoers and sudoers.d. | `examiner-audit` |
| [Swap and hibernation](threat-model.md#assumptions) (`swap-hibernation`) | swap partitions and files, the hibernation image | all | `swap` (refuses) | `memory-swap` | No disk or file swap and no resume device; RAM-only zram is fine. | `preflight-swap` |
| [Crash dumps](#warn-surfaced-never-blocking) (`crash-dumps`) | `/var/lib/systemd/coredump`, `/var/crash` | all | `decoy-persistence` | path probe (warn) | Send core dumps nowhere persistent and disarm kdump on the decoy. | `examiner-audit` |
| [Shell history](#shell-history-hardening) (`shell-history`) | `~/.bash_history`, `~/.zsh_history` | all | `incremental-history-flush` | `deep-scan-history` | Harden the decoy shells' history and do not flush history during a session. | `session-emergency` |
| [Desktop recent-files lists](threat-model.md#what-the-hidden-environment-shares-with-the-decoy) (`desktop-recent-files`) | `~/.local/share/recently-used.xbel` | all | none: written by desktop applications during the session, into the /home overlay | `deep-scan-recent-files` | Hidden sessions write recent-file lists into the upper; never open hidden files from a decoy session. | `rehearse-canary` |
| [NAILS's own files and markers](threat-model.md#invariant) (`nails-artifacts`) | the paths and content markers listed in the artifact registry (nails-core/src/artifacts.rs) | all | `suspicious-nails-reference` (refuses) | `artifact-files` | Deactivate normally; `nails recover` finishes an interrupted teardown. | `verify-seeded-artifacts` |
| [NixOS account bookkeeping](threat-model.md#known-residual-changes) (`var-lib-nixos`) | `/var/lib/nixos` | NixOS | none: the decoy rewrites these files on every boot; only a control run tells noise from a leak | `platform-scanners` | Overlay /var; the drift test compares against a plain-reboot control. | `session-nixos-hidden-system` |
| [Decoy filesystems the hidden systemd would mount](#writes-that-bypass-the-overlays) (`decoy-filesystems`) | fstab entries of the hidden root: a separate /home or /var, the ESP, decoy swap, a second disk | all | `fstab-policy` (refuses) | none: verify cannot tell what a session wrote to another filesystem | NAILS binds the ESP and boot filesystems read-only, overlays other mounted decoy filesystems with an upper on the hidden volume, and masks swap and unmounted disks before the switch. | `soft-reboot-mechanics` |
| [The hidden session's /run carried into the decoy](threat-model.md#residual-channels) (`run-carry-over`) | a soft-reboot carries /run: logind state, utmp, the runtime journal, utab lines, stray files | all | none: the scrub runs as the last step before the switch back | `session-leftovers` | The transition step deletes everything the hidden session added two levels below /run (three below /run/systemd), restores utab, and never touches sockets or /run/udev. | `soft-reboot-mechanics` |
| [An interrupted entry's runtime files in /run](threat-model.md#residual-channels) (`interrupted-entry`) | an activation killed before the soft-reboot leaves /run/nextroot, the session plan and the transition drop-in | all | `session-state` (refuses) | `session-leftovers` | The transition drop-in is installed before the next root is populated, so an unarmed entry is disarmed by any soft-reboot; `nails recover` removes the leftovers. | `session-interrupted-entry` |
| [Hidden kernel records imported by the decoy journal](threat-model.md#residual-channels) (`kmsg-import`) | journald reads /dev/kmsg from its stored sequence number after every soft-reboot | all | `decoy-persistence` | `journal-scan` | The transition step writes the decoy journald's kmsg cursor past every hidden record; only PID 1's last generic lines and the hidden filesystem's unmount line follow it. | `soft-reboot-mechanics` |
| [Soft-reboot counter and boot ID](threat-model.md#residual-channels) (`soft-reboot-counter`) | SoftRebootsCount and the unchanged boot ID and uptime, readable with systemctl and journalctl | all | none: kernel and PID 1 state, not a file | none: RAM only, gone at power-off | Power off after the session; keep the decoy journal volatile. | `soft-reboot-mechanics` |
| [EFI NVRAM, RTC and firmware pstore](threat-model.md#invariant) (`firmware-state`) | EFI variables, the real-time clock, firmware-backed pstore | all | none: not filesystem state, so nothing on the decoy root shows it | none: EFI variables and firmware storage are not part of a disk image | NAILS never writes NVRAM; avoid firmware tools inside the session. | `uefi-esp-nvram-invariant` |
| [Memory remanence](operator-guide.md#cold-boot-and-running-memory-attacks) (`ram-remanence`) | DRAM contents until power-off | all | `memory-wipe` | `memory-swap` | Power off (`--poweroff`) before handing the machine over; boot the decoy with init_on_free=1. | none: memory forensics is out of scope; no VM test images RAM |
| [timesyncd clock stamp](#session-time-records) (`timesync-clock`) | `/var/lib/systemd/timesync/clock` | all | path probe (info) | path probe (info) | Session touches land in the upper; on a persistent decoy, use the decoy normally after a session so its own activity follows the stamp. | `examiner-audit` |
| [Persistent timer stamps](#session-time-records) (`timer-stamps`) | `/var/lib/systemd/timers` | all | path probe (info) | path probe (info) | Session stamps land in the upper; expect catch-up runs at the next decoy boot. | `examiner-audit` |
| [SMART power-on hours](#session-time-records) (`smart-power-on-hours`) | the drive's own power-on-hours and power-cycle counters | all | none: not filesystem state, so nothing on the decoy root shows it | none: a disk image does not carry SMART counters | None in software; use the decoy normally so its logged uptime is plausible. | none: virtual disks have no SMART log |
| [SSD flash-translation-layer remnants](operator-guide.md#ssd-wear-levelling) (`ssd-ftl-remnants`) | remapped and over-provisioned flash blocks | all | none: not filesystem state, so nothing on the decoy root shows it | none: no host-side read reaches remapped flash cells, so `nails rehearse` cannot see them either | Full-disk encryption on the decoy, so remnants are ciphertext; no TRIM on a volume that holds a hidden volume. | none: virtual disks have no flash translation layer |
<!-- residue-catalog:end session -->

### Setup traces

<!-- residue-catalog:begin setup -->
| Class | Where | Platforms | Pre-flight | Verify | Mitigation | VM test |
|---|---|---|---|---|---|---|
| [LVM metadata archive and backup](#lvm-metadata-archives) (`lvm-metadata-archive`) | `/etc/lvm/archive`, `/etc/lvm/backup` | all | path probe (warn) | `examiner-lvm` | Never run LVM tools on the hidden backend from the decoy, or disable archive and backup in the decoy's lvm.conf first. | `examiner-audit` |
| [udisks2 state](#udisks2-state) (`udisks2-state`) | `/var/lib/udisks2` | all | path probe (warn) | path probe (warn) | Unlock and mount the backend with cryptsetup and mount from a shell, not through the desktop. | `examiner-audit` |
| [crypttab and fstab entries](#crypttab-and-fstab) (`crypttab-fstab`) | `/etc/crypttab`, `/etc/fstab` | all | none: the decoy's own full-disk encryption legitimately lists entries here; review them with verify --examiner | `examiner-config` | Never add the hidden backend to the decoy's crypttab or fstab; open it by hand each time. | `examiner-audit` |
| [LUKS headers on partitions](#encryption-headers-high-entropy-space-and-containers) (`luks-headers`) | LUKS1/LUKS2 signatures at partition starts, in gaps and in LUKS2 secondary-header slots | all | `backend-detect` | `examiner-disk` | Prefer a deniable backend (a VeraCrypt hidden volume) over a bare LUKS volume next to the decoy. | `examiner-audit` |
| [High-entropy unpartitioned space](#encryption-headers-high-entropy-space-and-containers) (`high-entropy-space`) | partition gaps, space after the last partition, partitions with no known signature | all | none: needs the raw disk, which verify --offline --examiner --disk reads | `examiner-disk` | Fill free space with random data when the disk is set up, so the hidden region does not stand out; explain it as wiped space. | `examiner-audit` |
| [Encrypted container candidates](#encryption-headers-high-entropy-space-and-containers) (`container-candidates`) | large files whose size is a multiple of 512, with no known header and high entropy | all | `backend-detect` | `examiner-containers` | Put the hidden volume on a whole device or partition rather than in a file on the decoy. | `examiner-audit` |
| [Encryption tooling and its access times](#backend-tooling-and-history) (`backend-tooling`) | `/usr/bin/veracrypt`, `/usr/sbin/cryptsetup`, `/sbin/cryptsetup` | all | none: the tools are part of the decoy install; their access times are what an examiner reads | `examiner-tooling` | Mount the decoy root noatime; run the backend tools from the separate machine or a live medium when you can. | `examiner-audit` |
| [History naming a container or unlock](#backend-tooling-and-history) (`container-history`) | `~/.local/share/recently-used.xbel`, `~/.config/VeraCrypt/History.xml`, `~/.config/VeraCrypt/Favorite Volumes.xml`, `~/.bash_history`, `~/.zsh_history` | all | `incremental-history-flush` | `examiner-history` | Disable VeraCrypt's history, harden the decoy shell history, and unlock from a shell that records nothing. | `examiner-audit` |
<!-- residue-catalog:end setup -->

## Out of scope

These sit outside the overlay model and NAILS does not attempt to manage them:

- **EFI / firmware variables** and **RTC** — writes here are not filesystem
  writes and are not overlaid.
- **Firmware-backed pstore** that survives a disk wipe (surfaced as a warning
  only).

See also [threat-model.md](threat-model.md) for the overall model and
[operator-guide.md](operator-guide.md) for operational guidance.
