# Decoy requirements: making the base system amnesic

NAILS hides a session behind a decoy system by overlaying the writable trees so
the hidden session's writes land on the hidden volume instead of the decoy disk.
That guarantee only holds if the decoy itself keeps **no durable record** of the
hidden session. A decoy that writes logs, audit records, crash dumps or swap to
its own disk defeats the overlay model: those traces are created outside the
overlays (or before they are mounted) and survive deactivation and reboot.

This document lists what an amnesic decoy must look like, what NAILS enforces at
pre-flight, and how to satisfy each requirement on the supported platforms.

## What NAILS enforces

The `decoy-persistence` pre-flight check inspects the decoy before any state is
written. It performs **no writes** — it never rotates or vacuums the decoy's own
logs, because destroying the decoy's log history is itself a deniability tell.

### Fail closed (activation is refused)

| Finding | Why it matters |
|---|---|
| systemd-journald `Storage=persistent`, or `auto` with an on-disk `/var/log/journal` | The journal records sudo command lines (including the hidden-root binary path), transient unit names and overlay events on the decoy disk before `/var` is overlaid. |
| Active `rsyslog` or `syslog-ng` | A classic syslog daemon writes `/var/log/*` on the decoy disk. |
| Active `auditd` | The audit daemon writes `/var/log/audit` on the decoy disk, independent of journald. |

Override these with `--accept-persistent-decoy` on `activate`/`check`, or
`accept_persistent_decoy = true` in `nails.toml`, only if you understand and
accept that records written before the overlays are mounted may survive on the
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
active; `teardown` holds a sleep *delay* inhibitor and runs the bounded emergency
teardown when the host is about to sleep, within logind's `InhibitDelayMaxSec`
window (default 5s). The inhibitor is a runtime backstop — still fix the lid
switch above, since a blocked suspend with the lid shut can overheat a laptop.

## Satisfying the requirements per platform

### NixOS

- **Impermanence** (`nixos-impermanence`): keep `/` (or at least `/var`, `/home`,
  `/etc`) on a tmpfs or a wiped-on-boot dataset so the decoy is amnesic by
  construction. This is the strongest documented posture.
- **Volatile journald**: `services.journald.storage = "volatile";`.
- **No classic syslog / audit**: do not enable `services.rsyslogd`,
  `services.syslog-ng` or `security.auditd` / the audit framework on the decoy.
- **noatime**: add `"noatime"` to the root filesystem's mount options.
- **No swap / hibernation**: leave `swapDevices` empty and do not configure
  `boot.resumeDevice` or a resume kernel parameter.

### Ubuntu

- **overlayroot**: use the `overlayroot` package to make `/` a RAM-backed overlay
  wiped on reboot.
- **Volatile journald**: set `Storage=volatile` in
  `/etc/systemd/journald.conf`.
- Remove or disable `rsyslog` and `auditd` if installed.
- Mount the root with `noatime`; disable swap and hibernation.

### Debian

- **bilibop-lockfs** (or an equivalent RAM-overlay setup) to make the base
  system amnesic.
- **Volatile journald**: `Storage=volatile`.
- Remove or disable `rsyslog`/`syslog-ng` and `auditd`.
- `noatime`; no swap; no hibernation.

## The sudo-log exposure and its mitigation

Running `sudo nails …` is itself a sensitive event: sudo logs the invoking user,
the target command and its full path through its configured log channel
(journald, syslog, or `/var/log/sudo.log`). On a persistent decoy that record
names the hidden-root binary path before any overlay exists.

**Mitigation**: run NAILS on an amnesic decoy (volatile journald, no syslog,
no sudo `logfile` or I/O logging in sudoers) so the sudo record is never durably
written, and keep the binary at a neutral path
on the hidden volume. NAILS cannot suppress sudo's own logging without tampering
with the decoy, which would itself be a tell.

## Shell history hardening

NAILS keeps hidden-session history off the decoy by killing shells before the
unmount (see [bash-history-forensics.md](bash-history-forensics.md)), but it does
**not** configure the decoy's own shells. If you type on the decoy — and the
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

## Out of scope

These sit outside the overlay model and NAILS does not attempt to manage them:

- **EFI / firmware variables** and **RTC** — writes here are not filesystem
  writes and are not overlaid.
- **Firmware-backed pstore** that survives a disk wipe (surfaced as a warning
  only).

See also [threat-model.md](threat-model.md) for the overall model and
[operator-guide.md](operator-guide.md) for operational guidance.
