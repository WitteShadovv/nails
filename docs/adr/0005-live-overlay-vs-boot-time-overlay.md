# 5. Live overlay vs boot-time overlay mechanisms

- Status: accepted
- Date: 2026-10-04

## Context

NAILS mounts a full-root overlay while the decoy is running: it layers a hidden
upper over the live root, switches the session into it, and unmounts it again on
deactivation, all without a reboot. Several existing mechanisms implement the
same full-root-overlay primitive at boot instead: Kicksecure/Whonix `grub-live`,
Ubuntu `overlayroot`, the `systemd.volatile=overlay` kernel option, and dracut's
`rd.overlay` / dmsquash-live modules. They are the obvious prior art, yet NAILS
has never been compared against them and the trade-offs that led to the live
approach are not written down. The multi-distro port (Debian/Ubuntu first) is
going ahead, so the comparison and the decision need to be on record before a
contributor assumes a boot-time mechanism is a drop-in replacement.

These mechanisms are not interchangeable with NAILS. They take the overlay at
boot with a tmpfs (ephemeral) upper, they need a reboot to take effect, and
several of them leave an enabler on the decoy (a package, a config file, a boot
menu entry, or a kernel command-line flag) that is itself forensic evidence.

## Comparison

The "leak classes removed" column refers to the live-mount leak classes NAILS
has to defend against because it operates while the system runs: a boot-time
upper is taken before the session starts, so there is no live mount operation to
observe, no running tool to detect, and no in-session kill to perform.

| Mechanism | Needs reboot? | Upper layer | Enabler left on the decoy | Initrd requirement | NAILS leak classes it would remove |
| --- | --- | --- | --- | --- | --- |
| NAILS live overlay (baseline) | No | Persistent, externally backed | None | None (mounts from the running system) | n/a — this is the baseline the others are compared against |
| Kicksecure/Whonix `grub-live` | Yes | Ephemeral tmpfs | `grub-live` package and a persistent GRUB menu entry | initramfs hook | Process detection of the tool, the in-session kill, and the journald persistence window |
| Ubuntu `overlayroot` | Yes | Ephemeral tmpfs (can be device-backed) | `overlayroot` package and `/etc/overlayroot.conf` | initramfs-tools hook | Process detection of the tool, the in-session kill, and the journald persistence window |
| `systemd.volatile=overlay` | Yes | Ephemeral tmpfs | Kernel command line / bootloader entry carrying the option | Needs a systemd initrd; the Debian/Ubuntu default initramfs-tools does **not** support it | Process detection of the tool, the in-session kill, and the journald persistence window |
| dracut `rd.overlay` / dmsquash-live | Yes | tmpfs or a persistent overlay | dracut modules and a persistent kernel command line | dracut-built initrd | Process detection of the tool, the in-session kill, and the journald persistence window |

Two properties cut across the table. First, every boot-time mechanism removes
the live-mount leak classes for free, because nothing runs while the system is
up: that is their one genuine advantage over the live approach. Second, every
one of them pays for that with a reboot, a mostly ephemeral upper, and an enabler
that persists on the decoy — the package, config file, boot entry, or
command-line flag that tells a forensic examiner the host can be booted into a
hidden mode at all. That persistent enabler is the decisive problem: it survives
exactly when the hidden environment is not active, which is when the decoy is
meant to look untouched.

## Decision

NAILS stays with a **live overlay**: a full-root overlay mounted from the
running system, with a **persistent, externally backed upper layer** (for
example a tree on a removable device such as `/mnt/usb/data0`) plus declarative
hidden configuration, taken and released without a reboot.

The reasons follow from the comparison:

- **No enabler on the decoy.** NAILS installs nothing that has to remain on the
  host between sessions and names no hidden mode in the bootloader or a config
  file. When it is not active, the decoy carries no artefact that points at a
  hidden environment. Every boot-time mechanism fails this.
- **Persistence across sessions.** The upper is externally backed, so the hidden
  environment keeps its state between sessions. The boot-time mechanisms default
  to a tmpfs upper that is discarded on every reboot.
- **No reboot.** Activation and deactivation happen in place, which keeps the
  operator in one session and avoids the boot-time window where neither the
  decoy nor the hidden environment is fully in control.

The cost NAILS accepts in exchange is the live-mount leak classes in the table —
process detection of the running tool, the in-session session kill, and the
journald persistence window — which the rest of the threat model and the code
are built to minimise.

### When to revisit

A boot-time redesign becomes the better trade-off if the live-mount leak classes
can no longer be held to an acceptable level, or if a target platform cannot
mount a live full-root overlay at all. Concretely, revisit this decision if any
of the following holds:

- live-mount process detection or the in-session kill can no longer be made
  reliable enough for the threat model on a supported platform;
- the journald (or equivalent) persistence window cannot be closed in-session on
  a platform we need to support;
- a required platform refuses a live full-root overlay but supports a boot-time
  one, and a persistent externally-backed upper can be arranged there without
  leaving an enabler on the decoy.

A boot-time redesign would be a large change (initrd integration, an enabler
that does not betray the hidden mode, a persistent upper taken at boot) and is
tracked as its own backlog item rather than folded into the multi-distro port.

## Consequences

- The multi-distro port can proceed on the live-overlay model: a new platform
  backend has to make a live full-root overlay work, not integrate with an
  initrd.
- NAILS owns the live-mount leak classes that boot-time mechanisms avoid, so the
  process-detection, session-kill, and journald defences stay load-bearing and
  must keep pace with each new platform.
- The upper layer is a persistent store the operator is responsible for, not an
  ephemeral tmpfs the kernel discards; its confidentiality is out of scope for
  this record and handled by the hidden-volume design.
- If the revisit conditions are ever met, this record is superseded by a new ADR
  rather than edited.
