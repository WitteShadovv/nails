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

**Mitigation**: run NAILS on an amnesic decoy (volatile journald, no syslog) so
the sudo record is never durably written, and keep the binary at a neutral path
on the hidden volume. NAILS cannot suppress sudo's own logging without tampering
with the decoy, which would itself be a tell.

## Out of scope

These sit outside the overlay model and NAILS does not attempt to manage them:

- **EFI / firmware variables** and **RTC** — writes here are not filesystem
  writes and are not overlaid.
- **Firmware-backed pstore** that survives a disk wipe (surfaced as a warning
  only).

See also [threat-model.md](threat-model.md) for the overall model and
[USER-SECURITY-GUIDE.md](USER-SECURITY-GUIDE.md) for operational guidance.
