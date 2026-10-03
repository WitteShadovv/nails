# NAILS User Security Guide

> **Version:** 1.0
> **Last Updated:** March 2026
> **Status:** Required reading before any security-sensitive use

This guide provides essential security information for NAILS users. Read this document completely before using NAILS in any security-sensitive context.

> **Before anything else:** NAILS requires an *amnesic decoy* — a base system
> that keeps no durable record of the hidden session. Activation fails closed on
> a persistent journald journal or an active syslog/audit daemon. Read
> [decoy-requirements.md](decoy-requirements.md) and set your decoy up
> accordingly before relying on NAILS.

---

## Table of Contents

- [Introduction](#introduction)
  - [What NAILS Protects Against](#what-nails-protects-against)
  - [Threat Model Overview](#threat-model-overview)
- [Critical Operational Requirements](#critical-operational-requirements)
  - [Binary Location Requirements](#binary-location-requirements)
  - [Why This Matters](#why-this-matters)
  - [Trusted Computing Base](#trusted-computing-base)
  - [Updating NAILS](#updating-nails)
  - [Pre-Activation Residue](#pre-activation-residue)
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
  - [Shared Decoy Account and Persona Modes](#shared-decoy-account-and-persona-modes)
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
/mnt/data/nails              # Correct - binary on hidden volume
/mnt/data/src/nails/         # Correct - source on hidden volume
```

Incorrect (DANGEROUS) setup:
```
~/Downloads/nails              # WRONG - exposes NAILS on decoy disk
/usr/local/bin/nails           # WRONG - visible in forensic scans
/persist/home/*/nails          # WRONG - persists across reboots
```

### Why This Matters

The NAILS binary contains identifiable strings that reveal its purpose:

- Path references: `/mnt/data`, `/tmp/nails.log`, `/var/log/nails.log`
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
2. Run the binary directly from the hidden volume: `sudo /mnt/data/nails activate`
3. Never copy the binary to the decoy filesystem

### Trusted Computing Base

NAILS runs as `root` and reconfigures the running system. Everything it loads at
activation time is therefore part of root's **trusted computing base (TCB)**: if
any of it is tampered with, the hidden session offers no protection. The TCB is:

- the `nails` binary itself,
- its configuration file (`nails.toml`),
- the hidden Nix flake and `configuration.nix` it builds and switches to.

Keep all of these on the hidden volume alongside the binary, under `root`
ownership, and treat their integrity as a precondition for every run:

- **Root integrity is assumed.** NAILS does **not** perform a runtime
  self-integrity check and cannot detect a modified binary, config, or flake
  while it runs. If an adversary has already obtained root on the decoy system,
  or has written to the hidden backend while it was mounted and unlocked, that is
  outside the threat model — a compromised root can defeat any tool that runs as
  root. Protect the hidden volume's confidentiality and integrity at rest
  (strong passphrase, trusted hardware, no shared write access) rather than
  relying on NAILS to notice tampering.
- **No unauthenticated or remote backends.** The flake, configuration, and
  binary must come from storage you control and have verified. Building or
  switching to a configuration fetched from an unauthenticated source, a remote
  builder you do not trust, or a network location is **unsupported**: it would
  place an attacker-controlled component inside root's TCB. NAILS deliberately
  gives root child processes a fixed, root-owned tool search path and a cleared
  environment, so the caller's `PATH` and Nix settings cannot redirect which
  binaries run or steer evaluation; do not reintroduce that exposure by pointing
  the backend at untrusted inputs.

### Updating NAILS

Update NAILS by replacing the binary and backend on the hidden volume with a
freshly built, verified release — never by downloading a binary onto the decoy
disk:

1. **Build or obtain a release artifact** following
   [Release Artifact Reproducibility](./release-artifact-reproducibility.md).
   The release is built deterministically, so an independently built binary
   should match the published artifact byte for byte.
2. **Verify the artifact before trusting it.** Check the published
   `checksums.txt` against the binary you intend to install, and prefer a build
   you reproduced yourself over one you only downloaded. An unverified binary is
   an untrusted addition to root's TCB (see
   [Trusted Computing Base](#trusted-computing-base)).
3. **Install it on the hidden root only.** Replace the binary (and, when they
   change, the flake and configuration) on the hidden volume, keeping everything
   `root`-owned. Do not stage the new binary on the decoy filesystem at any
   point — the same string-leakage hazard from
   [Binary Location Requirements](#binary-location-requirements) applies to an
   update as much as to a first install.
4. **Re-read this guide after a version change**, since operational requirements
   can change between releases.

### Pre-Activation Residue

Unlocking and mounting the hidden volume happens **before** NAILS runs, so NAILS
cannot clean up after it. The `cryptsetup` and `mount` commands you type, and the
kernel work they trigger, leave traces on the decoy side regardless of how
cleanly the session later deactivates. Treat these as your responsibility.

First, **choose neutral names.** The device-mapper mapping name, the mount point
and the filesystem label must not hint at hidden storage — use something like
`data` and `/mnt/data`, never `hidden`, `veracrypt`, `tcrypt`, `decoy` or
`nails`. Those strings surface in several places the overlay never touches, and
the `hidden-volume` preflight check warns at activation when it finds one. The
residue to account for:

- **sudo command logging.** sudo records a `COMMAND=` line in the journal for
  every privileged command, including the full `cryptsetup open …` and
  `mount …` lines with the mapping name, label and container or device path.
- **Kernel ring-buffer messages.** Opening a dm-crypt mapping and mounting the
  filesystem emit kernel log lines (device-mapper table loads, the ext4 mount
  banner) that name the mapping and the device; these reach the journal too.
- **Generated systemd units.** systemd synthesises `.device` and `.mount` units
  named after the mapping and the mount point (for example `mnt-data.mount`).
  A telling mount point therefore becomes a telling unit name in
  `systemctl list-units` and the journal.
- **by-label and by-uuid symlinks.** udev creates `/dev/disk/by-label/<label>`
  (and `/dev/mapper/<name>`) while the volume is open. A label such as
  `hidden` is visible there to anyone listing the directory.
- **Shell history.** The unlock and mount commands name the tool, the mapping
  and the container path. Type them in a shell with history disabled, or scrub
  them yourself; see [Shell History Protection](#shell-history-protection).

For the journal and kernel-message residue, the fix is to keep the journal off
persistent disk rather than to scrub it afterwards: configure journald with
`Storage=volatile` (or put the journal on impermanent storage) so these lines
never land on the decoy disk in the first place. See the "Common host traces"
guidance in [backends.md](./backends.md). Do not rely on NAILS deactivation or
cleanup to remove pre-activation journal entries — by design it does not touch
them.

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

The `nails` binary lives on the hidden volume, not on the decoy, so run
`verify` **from the hidden side** — while the hidden environment is still
mounted, before `deactivate`:

```bash
# Basic verification
sudo nails verify

# Deep verification (more thorough, slower)
sudo nails verify --deep

# JSON output for scripting
sudo nails verify --deep --json
```

To inspect the decoy itself for leftovers, mount its image or partition
read-only and scan it offline (again from the hidden side, which has the
binary):

```bash
sudo nails verify --offline --root /mnt/decoy
```

In offline mode every path is read from under `--root`, and the live-only
checks (running processes, the kernel mount table, open block devices and
the platform package-drift scan) are skipped.

**What `nails verify` checks:**

| Check | Basic | Deep |
|-------|-------|------|
| Leftover overlays (by `upperdir` on the hidden volume, from `/proc/self/mountinfo`) | Yes | Yes |
| Known NAILS artifact paths (shared registry) | Yes | Yes |
| Running NAILS processes (binary identity, not a name substring) | Yes | Yes |
| Open crypt mappers / loop devices (name-independent) | Yes | Yes |
| Memory state warnings | Yes | Yes |
| Platform package drift (apt/dpkg on Debian vs. activation baseline) | Yes | Yes |
| Shell history files, every home from `/etc/passwd` | No | Yes |
| `/tmp`, `/var/tmp` and `/var/log` for NAILS-named files | No | Yes |
| `recently-used.xbel` / VeraCrypt config naming the hidden root | No | Yes |

**Interpreting results:**

The headline never claims the system is clean. A run with no findings prints:

```
No known artifacts found (N checks, <depth> scan). This is not proof of absence.
```

followed by the list of areas the run did not inspect (for example, the
systemd journal, or shell histories when `--deep` was not given). Exit codes:
`0` clean, `10` warnings, `11` critical findings, `2` the scan could not run.

> **Important:** A clean verification is evidence against *known* artifacts,
> not proof the decoy is untouched. It cannot detect every possible trace, and
> it names what it skipped so you do not read more into a clean result than it
> supports.

### Manual Verification Checklist

After deactivation, manually verify:

```bash
# 1. Check no overlays are mounted
findmnt | grep -E "overlay|/mnt/data"

# 2. Check shell history is clean
cat ~/.bash_history  # Should be empty or contain only decoy commands
cat /root/.bash_history

# 3. Check for NAILS processes
pgrep -f nails

# 4. Check hidden volume is not mounted or open
findmnt /mnt/data  # Should fail or print nothing
test ! -e /dev/mapper/data

# 4b. Name-independent check: no crypt mapper or loop device is left open.
#     These do not rely on the mapping being called "data", so they also catch a
#     second hidden volume opened under any neutral name.
findmnt -S /dev/mapper -o TARGET,SOURCE  # Any row backed by /dev/mapper is suspect
dmsetup ls --target crypt                # Should print "No devices found"
losetup -a                               # Should list no unexpected backing files

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

### The Layered Defense System

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

**Layer 5: Deactivation shell kill**
- Before overlay unmount, NAILS SIGKILLs **every** interactive shell, including
  root's, so no shell is left to flush its in-memory history. SIGKILL (not SIGHUP)
  is used so the shell runs no exit trap and writes nothing.
- NAILS does **not** write to the decoy disk after unmount by default. Editing
  history files on the decoy after it is unmounted is itself a forensic artifact
  (fresh timestamps at the exact moment of deactivation), so the default teardown
  makes no post-unmount write at all. Your protection is that the hidden-session
  history never reaches the decoy disk in the first place (the shell kill above),
  backed by an amnesic decoy base.
- An opt-in post-unmount edit exists for operators whose decoy root is verified
  **amnesic** (a volatile backing, or accepted with `--accept-persistent-decoy`).
  When enabled it edits the resolved operator's history (plus `/root`) in place on
  the same inode — it does not whole-file truncate or secure-delete by default, so
  it leaves no new inode and no zeroed-file tell. It is off unless you turn it on.

**Layer 6: Incremental-flush preflight**
- A pre-flight check warns when the shell you run NAILS from flushes history to
  disk after **every** command (zsh `INC_APPEND_HISTORY`/`SHARE_HISTORY`, or
  `history -a` in bash `PROMPT_COMMAND`). Such a shell writes the unlock/mount
  commands to disk immediately, long before the teardown shell kill can help, so
  the check tells you to disable incremental flushing in that session.

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
- Both standard and emergency deactivation SIGKILL every interactive shell —
  including root's — before unmounting, so no shell is left to flush its buffer.
- NAILS does not write to the decoy disk after unmount by default; the defense is
  that the commands never reach the decoy, not that they are scrubbed afterwards.
- A shell configured to flush after every command defeats this, because the
  commands are already on disk before teardown. The incremental-flush preflight
  warns about exactly that; heed it.

**Your responsibility:**
- Run NAILS from a shell that does not flush history incrementally (clear the
  preflight warning before activating).
- Keep the decoy base amnesic if you rely on post-unmount history editing.
- Verify history files contain only decoy commands after returning to the decoy.

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
| **Shared network identifiers** | Machine-id, hostname, MAC addresses and NetworkManager profiles (including VPN autoconnect) are shared between the decoy and the hidden session; correlation through them is out of scope for the overlay (see [Shared Decoy Account and Persona Modes](#shared-decoy-account-and-persona-modes)) |
| **Inherited remote and account state** | Accounts, tokens and sync history the hidden session uses from the decoy are shared and are never rolled back on deactivation |
| **Legal compulsion with forensic expertise** | Deniability is not immunity; sophisticated analysis may detect anomalies |

### Shared Decoy Account and Persona Modes

By default, NAILS runs the hidden session **as the decoy user, in the decoy home**. The `/home`
overlay merges the decoy home read-write (and `/home` is deliberately not excluded), so every account,
credential store and application profile configured in the decoy home is live inside the hidden
session:

- browser profiles, saved logins and cookies
- SSH and GPG keys and agents
- password-manager databases and unlocked sessions
- shell, editor and application history and caches

This shared-account model is convenient — you keep one login — but it means hidden-session activity is
tied to the decoy's identity, and anything the hidden session opens from the decoy home can leave
traces the overlay cannot contain in the decoy's own online accounts and remote services.

`persona.mode` in `nails.toml` controls the model:

| Mode | Behaviour | Use when |
|------|-----------|----------|
| `shared-home` (default) | Hidden session uses the decoy home; the decoy's accounts and secrets are live. Activation prints a warning; `nails status` and `nails check` report the mode. | You deliberately want the decoy's existing login and accept that the two identities overlap. |
| `fresh-home` | After the `/home` overlay is mounted, a clean, empty home from the hidden volume (`<hidden_volume_root>/persona/home`) is bind-mounted over your home, so the decoy home contents are not visible. The hidden persona keeps its own state on the hidden volume between sessions. | You want the hidden session isolated from the decoy's credentials and history. |

A fully separate hidden account (`separate-user`, a fixed-UID account distinct from the decoy user)
is planned for a later release; it requires switching the hidden NixOS generation before login and is
not an accepted value yet.

**Recommendation:** for sensitive work, set `persona.mode = "fresh-home"` and sign in to the hidden
session's accounts from the clean home rather than reusing the decoy's. Treat `shared-home` as an
explicit, informed choice — the activation warning is there to make that choice visible.

#### Inherited autostart, services and autologin

In `shared-home` mode the hidden session also inherits what the decoy account starts automatically:

- autostart entries in `~/.config/autostart` and `/etc/xdg/autostart`
- enabled systemd **user** services and timers
- lingering (`loginctl enable-linger`), which runs the user manager without a login
- display-manager autologin (GDM, SDDM, LightDM)

Sync, cloud, messaging and account clients (Dropbox, Nextcloud, Syncthing, Telegram, Signal,
Thunderbird, online-account daemons, …) therefore run under the decoy identity in the hidden session
and can contact remote servers and your other devices.

`nails check` and the activation confirmation list this inherited state and flag names that look like
remote-linked clients. The flag is a **name-only** heuristic: it tells you a name looks like a client
that talks to remote servers, not that it is signed in or active.

To hide specific entries from the hidden session, list them under `[persona]`:

```toml
[persona]
mask_inherited = ["dropbox", "syncthing.service"]   # or ["*"] to mask all maskable entries
```

Autostart entries are masked with a `Hidden=true` override and user services with a `/dev/null` mask,
both written through the merged home after the overlays mount and before the session restarts, so they
take effect only in the hidden session and disappear on deactivation. **Lingering and autologin are
reported but not masked** — disable those on the decoy itself if they matter.

Masking changes what *runs* in the hidden session. It does **not** roll back remote or account state:
anything the hidden session did through a shared account, token or sync client stays on the decoy's
online services and is never undone.

#### Shared network identifiers

The overlay shares the host's network identity between the decoy and the hidden session.
`clean_stale_network_config` preserves **only** DNS (`resolv.conf`, `nsswitch.conf`); it does not
change the machine-id, hostname, MAC addresses or NetworkManager profiles (including VPN autoconnect).
Correlation through these identifiers is **out of scope** for the overlay.

If your threat model needs the hidden session to present a different network identity, apply it in the
hidden NixOS generation (so it switches before the session restarts) or as a NetworkManager drop-in on
an FHS host. NAILS ships an optional snippet for both:

- NixOS: `nix/modules/hidden-network-identity.nix` (random Wi-Fi/Ethernet MAC and a distinct
  `networking.hostName`, forced over the decoy's values)
- FHS/NetworkManager: `nix/modules/network-identity/00-hidden-identity.conf` (random MAC)

These take effect only once the hidden switch runs before the session restarts; the overlay alone
cannot change them.

NetworkManager has no global switch for VPN autoconnect, so neither snippet can turn it off. From the
hidden session, run `nmcli connection modify <vpn> connection.autoconnect no` for each VPN profile and
remove the VPN from the `connection.secondaries` of the Wi-Fi/Ethernet profiles that start it. With
`/etc` overlaid, NetworkManager rewrites those profiles in the hidden upper only.

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

**Do not open a container file for writing during a hidden session.** The container is a file on an overlaid directory, so writing to it from inside the session makes overlayfs copy the whole file up onto the hidden volume.

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
[ ] Hidden volume is mounted and writable, at its own mount point under
    /mnt or /run/media (an overlay of /media would hide a volume mounted
    there, so activation refuses it unless /media is excluded)
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
[ ] Reviewed the inherited decoy state in `nails check` (autostart,
    user services, lingering, autologin); masked or accepted the
    remote-linked clients via [persona] mask_inherited
[ ] Accepted that shared accounts and network identifiers (machine-id,
    hostname, MAC, NetworkManager/VPN profiles) are not isolated by the
    overlay, or applied the hidden network-identity snippet
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
  Everything the session writes there reaches the decoy disk, so excluding a
  directory the session writes to (`/home`, `/root`, `/etc`, `/var`, `/nix`,
  `/srv`, `/opt`, or a disk-backed `/tmp`) is refused unless you also list it
  in `allow_leaky_exclusions`.
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
    sudo umount /mnt/data && sudo cryptsetup close data
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
cat /mnt/data/state.json

# Reconcile the stuck state and finish the teardown. recover reads the live
# kernel mount table, unmounts any NAILS overlays it still finds, and resets the
# state to the decoy. Never delete state.json by hand: that hides live mounts
# from status instead of removing them.
sudo /mnt/data/nails recover

# Re-run status
nails status  # Should show INACTIVE
```

### Recovering from Incomplete Deactivation

If you suspect incomplete cleanup occurred:

**1. Immediate Actions**

```bash
# Unmount and close hidden volume immediately
sudo umount /mnt/data
sudo cryptsetup close data
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
findmnt /mnt/data  # Should fail or print nothing
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
