# NAILS User Security Guide

> **Version:** 1.0
> **Last Updated:** March 2026
> **Status:** Required reading before any security-sensitive use

This guide provides essential security information for NAILS users. Read this document completely before using NAILS in any security-sensitive context.

---

## Table of Contents

- [Introduction](#introduction)
  - [What NAILS Protects Against](#what-nails-protects-against)
  - [Threat Model Overview](#threat-model-overview)
- [Critical Operational Requirements](#critical-operational-requirements)
  - [Binary Location Requirements](#binary-location-requirements)
  - [Why This Matters](#why-this-matters)
- [Standard vs Emergency Deactivation](#standard-vs-emergency-deactivation)
  - [When to Use Each](#when-to-use-each)
  - [Cleanup Comparison](#cleanup-comparison)
  - [Tradeoffs](#tradeoffs)
- [Verifying Successful Deactivation](#verifying-successful-deactivation)
  - [Running Deep Verification](#running-deep-verification)
  - [Manual Verification Checklist](#manual-verification-checklist)
  - [Warning Signs of Incomplete Cleanup](#warning-signs-of-incomplete-cleanup)
- [Shell History Protection](#shell-history-protection)
  - [The 5-Layer Defense System](#the-5-layer-defense-system)
  - [What You Should NOT Do](#what-you-should-not-do)
  - [Understanding the Race Condition Risk](#understanding-the-race-condition-risk)
- [Threat Model Limitations](#threat-model-limitations)
  - [What NAILS Does NOT Protect Against](#what-nails-does-not-protect-against)
  - [SSD Wear-Leveling Limitations](#ssd-wear-leveling-limitations)
  - [Storage Backend Hazards](#storage-backend-hazards)
  - [Cold Boot Attacks](#cold-boot-attacks)
  - [Memory Forensics While Running](#memory-forensics-while-running)
- [Best Practices](#best-practices)
  - [Pre-Activation Checklist](#pre-activation-checklist)
  - [During Hidden Session](#during-hidden-session)
  - [Overlay Copy-Up Cost and Upper Growth](#overlay-copy-up-cost-and-upper-growth)
  - [On-Screen Visibility Trade-offs](#on-screen-visibility-trade-offs)
  - [Post-Deactivation Verification](#post-deactivation-verification)
- [Troubleshooting Common Issues](#troubleshooting-common-issues)
  - [What to Do If Deactivation Fails](#what-to-do-if-deactivation-fails)
  - [Recovering from Incomplete Deactivation](#recovering-from-incomplete-deactivation)

---

## Introduction

### What NAILS Protects Against

NAILS (NixOS Anti-forensics Isolation & Layering System) is intended to support plausible-deniability workflows for hidden computing environments on NixOS systems. When properly used within its documented threat model, NAILS helps reduce exposure from:

| Threat | NAILS Protection |
|--------|------------------|
| **Post-seizure disk forensics** | Hidden volumes may appear as random data and NAILS aims to reduce obvious host-side artifacts |
| **Artifact-based forensics** | Impermanence-style setups and cleanup workflows can reduce known/common traces of hidden environment usage |
| **Configuration fingerprinting** | Decoy system appears as a normal encrypted NixOS installation |
| **Hidden package detection** | All hidden packages and services exist only inside the mounted hidden volume |

**The fundamental goal:** After standard deactivation reboot, or after emergency cleanup followed by closing the backend, the offline host should present as an ordinary decoy NixOS system within the documented threat model. This is a design objective, not a guarantee that no trace remains.

### Threat Model Overview

NAILS assumes the following adversary model:

- **Adversary capability:** Physical control of your device in a powered-off state
- **Decryption assumption:** Adversary can decrypt the outer LUKS layer (via legal compulsion, password disclosure, or compromise)
- **Analysis timeframe:** Hours to days of forensic analysis with professional tools
- **Goal:** Prove existence of hidden environment or hidden activities

**NAILS is NOT designed to protect against:**
- Live system compromise (adversary with root access while hidden environment is active)
- Memory forensics during or immediately after operation
- State-level adversaries with unlimited resources and time
- Physical surveillance (keyloggers, cameras, electromagnetic analysis)

---

## Critical Operational Requirements

### Binary Location Requirements

> **CRITICAL:** The NAILS binary must **NEVER** exist on the decoy disk. It must only reside inside the hidden volume.

Correct setup:
```
/mnt/hidden/nails              # Correct - binary on hidden volume
/mnt/hidden/src/nails/         # Correct - source on hidden volume
```

Incorrect (DANGEROUS) setup:
```
~/Downloads/nails              # WRONG - exposes NAILS on decoy disk
/usr/local/bin/nails           # WRONG - visible in forensic scans
/persist/home/*/nails          # WRONG - persists across reboots
```

### Why This Matters

The NAILS binary contains identifiable strings that reveal its purpose:

- Path references: `/mnt/hidden`, `/tmp/nails.log`, `/var/log/nails.log`
- Status messages: `Run 'nails deactivate' to unmount overlays`
- Environment variables: `NAILS_SKIP_DETACH`, `NAILS_DETACHED`
- Process detection strings: `NAILS-related process is currently running`

**Forensic impact:** A raw string scan (`strings` command or bulk_extractor) of your decoy disk will reveal these strings if the binary ever existed there. Even if you delete the binary, the data may remain recoverable in:

- Filesystem journal entries
- Unallocated disk blocks
- SSD wear-leveling reserved areas
- Backup or snapshot systems

**Correct workflow:**
1. Open and mount the hidden volume first ([backends.md](./backends.md) lists the commands for each backend)
2. Run the binary directly from the hidden volume: `sudo /mnt/hidden/nails activate`
3. Never copy the binary to the decoy filesystem

---

## Standard vs Emergency Deactivation

NAILS provides two deactivation modes with different security and convenience tradeoffs.

### When to Use Each

| Scenario | Recommended Mode | Command |
|----------|------------------|---------|
| Normal session end, time available | Standard | `sudo nails deactivate` |
| Imminent physical threat | Emergency | `sudo nails emergency` |
| System instability | Standard (if possible) | `sudo nails deactivate` |
| Time-critical situation (< 10 seconds) | Emergency | `sudo nails emergency` |
| Cannot reboot immediately | Emergency | `sudo nails emergency` |

### Cleanup Comparison

| Cleanup Action | Standard | Emergency |
|----------------|----------|-----------|
| Restore `/run/current-system` symlink | Yes | Yes |
| Unmount overlay filesystems | Via reboot | Yes (explicit) |
| Clear shell history files | Yes | Yes |
| Clear in-memory bash history | Limited | Yes |
| Kill user shell processes | Via reboot | Yes (prevents flush) |
| Restart nix-daemon | Via reboot | Yes (if /nix overlaid) |
| Drop page cache | No | Configurable |
| Verification scan | No | Optional (fast mode) |
| System reboot | **Yes** | No |

### Tradeoffs

**Standard Deactivation (`nails deactivate`)**

Advantages:
- Cleaner state transition via full reboot
- NixOS impermanence automatically wipes tmpfs artifacts
- Lower risk of incomplete cleanup
- More time for thorough cleanup operations

Disadvantages:
- Requires reboot (visible system state change)
- Takes 30-60 seconds total
- Hidden volume may remain briefly mounted until reboot completes

**Emergency Deactivation (`nails emergency`)**

Advantages:
- Faster execution than the standard reboot path
- No reboot required
- Kills shell processes before they can flush history
- Immediate return to decoy appearance

Disadvantages:
- More cleanup happens in-process instead of being delegated to a reboot
- Relies on in-process cleanup rather than reboot guarantees
- Hidden volume may still need to be manually unmounted and closed
- Higher risk of incomplete cleanup if interrupted

---

## Verifying Successful Deactivation

### Running Deep Verification

After returning to the decoy state, run a verification scan:

```bash
# Basic verification
nails verify

# Deep verification (more thorough, slower)
nails verify --deep

# JSON output for scripting
nails verify --deep --json
```

**What `nails verify` checks:**

| Check | Basic | Deep |
|-------|-------|------|
| Active overlay mounts | Yes | Yes |
| Known NAILS artifact paths | Yes | Yes |
| Running NAILS processes | Yes | Yes |
| Memory state warnings | Yes | Yes |
| Shell history files (`~/.bash_history`, etc.) | No | Yes |
| `/tmp` and `/var/tmp` contents | No | Yes |
| `/var/log` for NAILS references | No | Yes |
| Recently-used file tracking | No | Yes |

**Interpreting results:**

```
Verification PASSED   # No known artifacts detected
Verification WARNING  # Some checks inconclusive
Verification FAILED   # Artifacts detected - take action
```

> **Important:** A passing verification is evidence, not proof. It checks for known/common artifacts but cannot detect all possible traces.

### Manual Verification Checklist

After deactivation, manually verify:

```bash
# 1. Check no overlays are mounted
findmnt | grep -E "overlay|/mnt/hidden"

# 2. Check shell history is clean
cat ~/.bash_history  # Should be empty or contain only decoy commands
cat /root/.bash_history

# 3. Check for NAILS processes
pgrep -f nails

# 4. Check hidden volume is not mounted or open
findmnt /mnt/hidden  # Should fail or print nothing
test ! -e /dev/mapper/veracrypt-hidden

# 5. Check recently-used files (GNOME)
cat ~/.local/share/recently-used.xbel | grep -i hidden
cat ~/.local/share/recently-used.xbel | grep -i veracrypt

# 6. Check systemd journal for leaks
journalctl --since "1 hour ago" | grep -i nails
```

### Warning Signs of Incomplete Cleanup

Take immediate action if you observe:

| Warning Sign | Severity | Action |
|--------------|----------|--------|
| Overlay mounts still visible in `findmnt` | Critical | Run `emergency` or reboot |
| Shell history contains hidden commands | Critical | Truncate files, investigate |
| NAILS process still running | High | Kill process, re-run deactivation |
| Hidden volume still mounted | High | Unmount and close immediately if not already rebooting |
| Recently-used.xbel shows hidden files | Medium | Clear file, check GNOME settings |
| Journal contains NAILS entries | Medium | Clear journal, configure volatile logging |

---

## Shell History Protection

### The 5-Layer Defense System

NAILS implements a defense-in-depth approach to shell history protection:

**Layer 1: Environment Variables**
```bash
HISTFILE=/dev/null    # Prevents history file writes
HISTSIZE=0            # Disables in-memory history
HISTFILESIZE=0        # Truncates history file on shell exit
```

**Layer 2: Bash Options**
```bash
set +o history        # Disables history recording
shopt -u histappend   # Prevents append mode
```

**Layer 3: Filesystem Symlinks**
```bash
~/.bash_history -> /dev/null    # Redirects writes to null device
~/.zsh_history -> /dev/null     # Same for zsh
```

**Layer 4: Boot-Time Enforcement**
- Systemd service truncates any regular history files at boot
- Re-creates symlinks if they were broken or replaced

**Layer 5: Deactivation Cleanup**
- Kills shell processes before overlay unmount (prevents flush race)
- Truncates real-disk history files after overlay removal
- Verifies cleanup completion

### What You Should NOT Do

| Action | Why It's Dangerous |
|--------|-------------------|
| Disable HISTFILE=/dev/null | History will be written to real disk |
| Remove ~/.bash_history symlink | Allows history file creation |
| Use `set -o history` | Re-enables history recording |
| Run `history -a` or `history -w` | Forces history write to disk |
| Open new terminal before verifying setup | May start with history enabled |
| Use shells that bypass /etc/profile | May not inherit protections |

### Understanding the Race Condition Risk

Bash maintains command history in two locations:

1. **In-memory buffer:** Commands during current session
2. **On-disk file:** Persisted across sessions

**The race condition:**
```
User runs commands in hidden environment
    ↓
Commands stored in bash's in-memory buffer
    ↓
Overlay unmounts, exposing real /persist filesystem
    ↓
User exits shell or shell receives SIGHUP
    ↓
Bash flushes in-memory buffer to REAL ~/.bash_history
    ↓
Hidden commands now exist on decoy disk
```

**NAILS mitigation:**
- Emergency deactivation kills shell processes with SIGKILL before unmounting
- This prevents the history flush from occurring
- Standard deactivation relies on reboot to terminate processes

**Your responsibility:**
- Do not manually exit shells after deactivation starts
- If using standard deactivation, wait for the reboot
- Verify history files are empty after returning to decoy

---

## Threat Model Limitations

### What NAILS Does NOT Protect Against

| Threat | Why NAILS Cannot Help |
|--------|----------------------|
| **Rubber hose attacks** | Cryptographic keys cannot resist physical coercion |
| **Live system compromise** | If adversary has root while hidden env is active, all protections are bypassed |
| **Pre-installed hardware implants** | Keyloggers, firmware backdoors operate below OS level |
| **Electromagnetic side-channels** | CPU emissions can leak encryption keys |
| **Network traffic analysis** | Hidden sessions may be detectable via timing/volume patterns |
| **Legal compulsion with forensic expertise** | Deniability is not immunity; sophisticated analysis may detect anomalies |

### SSD Wear-Leveling Limitations

Modern SSDs use wear-leveling algorithms that:

- Distribute writes across all flash cells evenly
- Maintain spare blocks for remapping bad cells
- May retain old data in cells marked as "free"

**Implications for NAILS:**

| Action | HDD | SSD |
|--------|-----|-----|
| `shred` file | Effective | Mostly ineffective |
| `truncate` file | Data recoverable | Data likely recoverable |
| `wipe` file | Effective | Mostly ineffective |
| TRIM/discard | N/A | Hints SSD to erase (not guaranteed); destroys or exposes a hidden volume |

**Mitigations:**
- Use full-disk encryption (LUKS) so wear-leveled blocks are encrypted
- Never enable TRIM/discard on, or run `fstrim` through, a volume that contains a hidden volume (see [Storage Backend Hazards](#storage-backend-hazards))
- On an SSD, prefer a hidden volume on a whole device or partition over a file container
- For highest security, use HDDs or encrypted RAM disks

TRIM on the decoy's own encrypted root, which holds no hidden volume, is a separate trade-off: cryptsetup-open(8) warns that it reveals that filesystem's type and used space.

### Storage Backend Hazards

The storage backend decides what a disk image reveals about the hidden volume. [backends.md](./backends.md) has the support matrix and the unlock, discard, timestamp and lock guidance for each backend. The hazards below apply to every hidden-volume setup; the `backend-detect` preflight check warns about each one it can see, without blocking activation.

**Discards destroy or expose hidden volumes.** cryptsetup-open(8) warns that `--allow-discards` makes filesystem-level operations visible on the physical device. For a VeraCrypt hidden volume, opened with `--tcrypt-hidden`, it is worse than a leak:

- Discards from the hidden volume zero or unmap its free blocks inside the outer volume's random-looking free space, which leaves a readable used/free map. In a loop-backed file container they punch holes in the file that record the same map.
- Discards from the outer volume trim its free space, which is where the hidden volume lives, and can destroy the hidden volume.

Never pass `--allow-discards` when opening the outer or the hidden volume, never mount either with `-o discard`, and never run `fstrim` on them. Without the flag dm-crypt drops discards, so a periodic fstrim timer cannot reach the device.

**File containers expose their timestamps.** Using a container read-write, through a cryptsetup loop device or the VeraCrypt application, updates its mtime and ctime in every session. `touch` can restore mtime but sets ctime to the current time, and ctime cannot be restored at all, so the container shows when it was last used.

**Copy-on-write filesystems and SSDs keep old blocks.** A container on btrfs, zfs or bcachefs is not rewritten in place: old versions of changed blocks stay in free space or in snapshots, and an SSD keeps old copies of remapped blocks. An adversary with one or several disk images can compare the versions and see which parts of the outer volume's "unused" space changed.

**Recommendation:** on a copy-on-write or SSD decoy, put the hidden volume on a whole device or partition instead of in a file container, and disable automatic snapshots (snapper, timeshift, btrbk, zfs auto-snapshot) of every filesystem that holds a container.

### Cold Boot Attacks

After power-off, DRAM retains data for a period depending on temperature:

| Temperature | Retention Time |
|-------------|----------------|
| Room temp (20°C) | 1-5 seconds |
| Cold (0°C) | 30-60 seconds |
| Frozen (-50°C) | Minutes to hours |

**What can be recovered:**
- Encryption keys (LUKS master key, VeraCrypt keys)
- In-memory command history
- Recent file contents
- Process memory

**NAILS mitigations:**
- Emergency deactivation can optionally drop page cache (`echo 3 > /proc/sys/vm/drop_caches`)
- Deactivation can reduce some residual host state, but it is not a defense against direct memory acquisition shortly after use

**Your responsibility:**
- Power off completely (not suspend) in threat situations
- Keep physical control of device for 5+ minutes after power-off
- In extreme scenarios, physically remove and secure RAM modules

### Memory Forensics While Running

If an adversary can dump memory while the hidden environment is active:

- All encryption keys are exposed
- Current shell history is readable
- Hidden file contents in cache are accessible
- Process state reveals NAILS operation

**There is no complete software defense against a running-system memory dump.** The primary protection is preventing the adversary from gaining access while the system is running.

---

## Best Practices

### Pre-Activation Checklist

Before activating the hidden environment:

```
[ ] Hidden volume is mounted and writable
[ ] Neither the outer nor the hidden volume was opened with
    --allow-discards
[ ] Hidden backend is a local Linux filesystem that can host an overlayfs
    upper (ext4/xfs/btrfs/f2fs; NOT NFS/SMB/9p/FUSE or FAT/exFAT/NTFS)
[ ] Hidden volume mount survives session termination
    (kernel-managed mount, NOT session-scoped FUSE)
[ ] backend-detect preflight warnings are resolved or accepted
    (see backends.md)
[ ] NAILS binary exists ONLY on hidden volume
[ ] No copies of NAILS binary on decoy filesystem
[ ] Decoy system has plausible recent activity
[ ] All unsaved work is saved (activation may kill session)
[ ] No other users logged in who might observe
[ ] Screen lock configured for interruption
[ ] Emergency deactivation procedure is practiced
```

### During Hidden Session

While operating in the hidden environment:

```
[ ] Work only with files on the hidden volume
[ ] Avoid creating files in /tmp (use hidden volume's temp)
[ ] Do not copy files to decoy filesystem locations
[ ] Use leading space for sensitive commands: ` sensitive-cmd`
    (if HISTCONTROL=ignorespace is set)
[ ] Avoid installing packages to decoy Nix store
[ ] Monitor for unusual system behavior
[ ] Have emergency deactivation command ready:
    sudo nails emergency
[ ] Know your physical emergency procedure (power button hold)
```

### Overlay Copy-Up Cost and Upper Growth

Each overlaid directory gets a writable *upper* on the hidden volume. OverlayFS
copies a lower file into that upper **in full** the first time you open it for
writing, truncate it, or change its mode or owner — even a one-byte edit of a
multi-gigabyte file copies the whole file. On a slow USB stick or an encrypted
(VeraCrypt/LUKS) backend this copy-up can stall the program for seconds or
minutes with no progress indication. Plan for it:

- **Expect the first write to be slow** for large files (Nix database, browser
  profiles, VM disk images). Subsequent writes hit the upper directly and are
  fast.
- **The upper only grows.** Every copied-up file and every deletion (stored as a
  whiteout) stays on the hidden volume across sessions; deactivation does not
  reclaim it. Watch the space with `nails status`, which now shows the hidden
  volume's total, used and free space without scanning it.

To keep the upper small and activation quick:

- **Exclude bulky directories you do not need hidden.** List them under
  `overlay_exclusions` in `nails.toml` so they are never overlaid and never
  copied up. VM-image and large data directories are the usual candidates.
- **Put caches on ephemeral tmpfs overlays.** Add directories such as
  `~/.cache` to `extended_overlays` as tmpfs-backed layers: they live in RAM
  during the session and vanish on deactivation, so cache churn never grows the
  hidden volume and leaves no trace.
- **Run maintenance inside the hidden session, not on the decoy.** Reclaim Nix
  store space with `nix-collect-garbage -d` and clear application caches from
  within the hidden environment; the freed space returns to the hidden volume.

If a target's upper has accumulated cruft or you want it to fall back to the
decoy lower, reset it **while deactivated**:

```bash
# The system must be Inactive and the target unmounted.
sudo nails reset-upper /home
```

`reset-upper` lists what it will delete and asks for confirmation (`-y` skips
the prompt). It deletes only that target's upper and work directories; it prunes
no whiteouts automatically (that would resurrect files you deleted in earlier
sessions) and never relocates `/nix/var` to tmpfs (that holds the hidden Nix
database). Resetting `/nix` drops the hidden Nix store and database entirely, so
`reset-upper` warns before doing it.

### On-Screen Visibility Trade-offs

Any on-screen indication that you are in the hidden environment is a
shoulder-surfing and screenshot/screen-recording liability. NAILS keeps these
tells off by default:

- **Prompt label** (`prompt_label`): empty by default, so the shell prompt is
  unchanged while the hidden environment is active. Setting it to a non-empty
  string prepends that label to your prompt in every new shell. It makes the
  hidden session convenient to spot — but equally visible to anyone looking at
  your screen or to any recording. Enable it only if you accept that exposure.
- **Terminal color scheme** (`color_scheme.enabled`): when enabled, the hidden
  session repaints the terminal background (default `#1a1a2e`) so you can tell
  the two environments apart at a glance. That distinct color is itself a visual
  tell. Set `color_scheme.enabled = false` if you prefer no color change, or
  keep it for the convenience of an obvious indicator.

Neither tell is written to the decoy disk: the prompt and color scripts live on
the hidden volume and the shell integration is written only into the overlaid
home, so it disappears when the overlays are unmounted. The visibility concern
is purely what is shown on your screen during the session.

### Post-Deactivation Verification

After deactivation completes:

```
[ ] System has rebooted (for standard deactivation) OR
    emergency cleanup confirmed complete
[ ] Run: nails verify --deep
[ ] Manually check: cat ~/.bash_history
[ ] Manually check: findmnt | grep overlay
[ ] If using emergency/no-reboot cleanup and the backend is still mounted:
    sudo umount /mnt/hidden && sudo cryptsetup close veracrypt-hidden
[ ] Verify hidden backend is not mounted or open
[ ] Check recently-used.xbel if using GNOME
[ ] Review last hour of journal: journalctl --since "1 hour ago"
[ ] Create some decoy activity (browsing, document editing)
[ ] Verify decoy system appears normal
```

---

## Troubleshooting Common Issues

### What to Do If Deactivation Fails

**Symptom: Standard deactivation hangs**

```bash
# Force emergency cleanup
sudo nails emergency

# If NAILS binary is unresponsive
sudo kill -9 $(pgrep -f nails)

# Manual overlay unmount
sudo umount -lf /nix /etc /home /var 2>/dev/null

# Force reboot if nothing else works
sudo systemctl reboot --force
```

**Symptom: Emergency deactivation fails partway**

```bash
# Check what overlays remain
findmnt | grep overlay

# Force unmount remaining overlays
for mp in /nix /etc /home /var /boot; do
    sudo umount -lf "$mp" 2>/dev/null
done

# Restart affected services
sudo systemctl restart nix-daemon
sudo systemctl restart display-manager

# Verify state
nails status
```

**Symptom: NAILS reports "already deactivating"**

```bash
# Check state file
cat /mnt/hidden-volume/state.json

# Force state reset (DANGEROUS - verify overlays are down first)
findmnt | grep overlay  # Must be empty
sudo rm /mnt/hidden-volume/state.json

# Re-run status
nails status  # Should show INACTIVE
```

### Recovering from Incomplete Deactivation

If you suspect incomplete cleanup occurred:

**1. Immediate Actions**

```bash
# Unmount and close hidden volume immediately
sudo umount /mnt/hidden
sudo cryptsetup close veracrypt-hidden
```

**2. Clean Residual Artifacts**

```bash
# Clear all shell history files
for histfile in ~/.bash_history ~/.zsh_history ~/.history /root/.bash_history; do
    sudo truncate -s 0 "$histfile" 2>/dev/null
    sudo ln -sf /dev/null "$histfile" 2>/dev/null
done

# Clear recently-used.xbel
truncate -s 0 ~/.local/share/recently-used.xbel

# Drop page cache
echo 3 | sudo tee /proc/sys/vm/drop_caches

# Clear temp files
sudo rm -rf /tmp/* /var/tmp/*
```

**3. Verify Cleanup**

```bash
# Reboot for clean state
sudo systemctl reboot

# After reboot, verify
nails verify --deep
cat ~/.bash_history  # Should be empty
findmnt /mnt/hidden  # Should fail or print nothing
```

**4. Consider Reboot Cycle**

If uncertain about cleanup completeness:

```bash
# Multiple reboots help clear volatile state
sudo systemctl reboot
# Wait for boot, login, then:
sudo systemctl reboot
# Repeat once more for highest assurance
```

**5. Document and Analyze**

After recovering:
- Note what went wrong
- Check logs (if safe) to understand failure
- Update procedures to prevent recurrence
- Consider whether exposure occurred and assess risk

---

## Additional Resources

- [NAILS README](../README.md) - Full project documentation
- [backends.md](./backends.md) - Storage backend matrix and per-backend deniability notes
- [SECURITY.md](../SECURITY.md) - Vulnerability reporting policy
- [bash-history-forensics.md](./bash-history-forensics.md) - Technical details on history protection
- [CHANGELOG.md](../CHANGELOG.md) - Release notes and published fixes

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | March 2026 | Initial release |

---

*This document is part of the NAILS project. Report security vulnerabilities privately as described in [SECURITY.md](../SECURITY.md): GitHub private vulnerability reporting first, `security@nails.run` as the fallback.*
