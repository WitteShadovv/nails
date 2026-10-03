# NAILS Operator Guide

> **Required reading before any security-sensitive use.** This guide describes
> what NAILS actually does, organised by *where* each step runs. Following it
> literally should not leave an avoidable trace on the decoy. For the adversary
> model it assumes, read [threat-model.md](threat-model.md); to report a
> vulnerability, see [SECURITY.md](../SECURITY.md).

> **Amnesic decoy first.** NAILS requires a decoy base that keeps no durable
> record of the hidden session. Activation fails closed on a persistent journald
> journal or an active syslog/audit daemon. Read
> [decoy-requirements.md](decoy-requirements.md) and set the decoy up before you
> rely on NAILS.

---

## Where each step runs

Every instruction in this guide belongs to exactly one of three places. Keeping
them straight is the difference between a clean session and a decoy that records
what you did.

1. **A separate machine** — building, verifying and copying the release onto the
   hidden volume. The decoy never sees this work.
2. **Inside the hidden session** — everything you do while the overlays are
   mounted. Writes land on the hidden volume, not the decoy.
3. **The decoy shell** — the plain decoy system, before activation and after
   teardown. This is the surface a forensic examiner images.

> **Never type on the decoy.**
>
> - Do not run `nails`, read `state.json`, or name the hidden volume, its mapper,
>   its mount point or the tool from a decoy shell.
> - The unlock and mount commands you must type on the decoy (NAILS runs *after*
>   them) go in a shell with history off — see
>   [History off on the decoy](#history-off-on-the-decoy).
> - Choose neutral names. A mapper called `data0`, a mount at `/mnt/usb` and a
>   plain filesystem label reveal nothing; `hidden`, `veracrypt`, `tcrypt`,
>   `decoy` or `nails` do. **Renaming alone is not enough** — the names still
>   surface in sudo logs, the kernel ring buffer, generated mount units and
>   `/dev/disk/by-label` (see [Pre-activation residue](#pre-activation-residue)).

Throughout, `<hidden-root>` is wherever you mounted the hidden volume (the
examples use `/mnt/usb`), and the binary lives at `<hidden-root>/nails`. Always
invoke it by its absolute path.

---

## What NAILS does

NAILS layers a hidden environment over the decoy with OverlayFS: writes made in
the session land on a writable *upper* on the hidden volume, and the decoy's own
files underneath are never modified. The overlay separates *writes*, not
processes or identity: hidden services run on the same kernel and init as the
decoy's, next to whatever the decoy keeps running, and share its network
identity (see
[What the hidden environment shares with the decoy](threat-model.md#what-the-hidden-environment-shares-with-the-decoy)).
Two cleanups bracket the session:

- **Pre-activation residue baseline.** Before it mounts any overlay, `nails
  activate` runs the read-only decoy residue scan and writes the result to
  `<hidden-root>/reports/`, then prints a one-line summary. The scan only reads
  the decoy; the report lives on the hidden volume and is torn down with the
  session. It is a baseline, so if a later examination finds a trace you can tell
  whether it predated the session.
- **History truncation on deactivate.** Before unmounting, teardown SIGKILLs
  every interactive shell (including root's) so none is left to flush its
  in-memory history to the decoy. By default teardown makes **no** write to the
  decoy after unmount; an opt-in post-unmount history edit exists for a decoy you
  have verified amnesic (see [Shell history](#shell-history)).

Hardening the decoy's *own* shell history (environment, symlinks, boot-time
enforcement) is decoy configuration, not something NAILS does at runtime; it is
covered in [decoy-requirements.md](decoy-requirements.md).

---

## How it works

**Hidden-root layout.** The hidden volume holds the `nails` binary, its
configuration (`nails.toml`), the hidden Nix flake and `configuration.nix`, the
overlay uppers, `state.json`, and the `reports/` directory. Keep all of it
`root`-owned on the hidden volume.

**The `hardware-configuration.nix` import.** On NixOS, the hidden configuration
imports the decoy's `hardware-configuration.nix` so the hidden generation boots
on the same hardware without duplicating that file.

**The auto overlay set and activation order.** Activation mounts the overlay set
derived from the configuration, deepest paths last so a child overlay is never
hidden by its parent, then switches `/run/current-system` to the hidden
generation. On a non-NixOS host the config layer is skipped and only the
overlays are mounted.

**Swap the binary only while inactive.** Replace the binary, flake or config on
the hidden volume only when no session is active. Never stage any of them on the
decoy, even briefly — see [Keeping NAILS off the decoy](#keeping-nails-off-the-decoy).

### Trusted computing base

NAILS runs as `root` and reconfigures the running system, so everything it loads
at activation is part of root's trusted computing base (TCB): the binary, its
config, and the hidden flake and `configuration.nix` it builds and switches to.
Keep all of these on the hidden volume, `root`-owned, and treat their integrity
as a precondition for every run.

- **Root integrity is assumed.** NAILS performs no runtime self-integrity check
  and cannot detect a modified binary, config or flake while it runs. A root
  that is already compromised, or a hidden backend written to while it was
  unlocked, is outside the threat model. Protect the hidden volume's
  confidentiality and integrity at rest (strong passphrase, trusted hardware, no
  shared write access).
- **No unauthenticated or remote backends.** The flake, configuration and binary
  must come from storage you control and have verified. Building or switching to
  a configuration fetched from an unauthenticated source or a remote builder you
  do not trust is unsupported. NAILS gives root child processes a fixed,
  root-owned tool search path and a cleared environment so the caller's `PATH`
  and Nix settings cannot redirect which binaries run; do not reintroduce that
  exposure by pointing the backend at untrusted inputs.

---

## Standard vs emergency vs recover

NAILS has three teardown paths. All of them unmount the overlays **explicitly**
from inside the process — none relies on a reboot to do the unmounting.

| Action | `deactivate` (standard) | `emergency` | `recover` |
|--------|-------------------------|-------------|-----------|
| Overlay list taken from | recorded state (verified Active) | live mount table when state is untrusted, else recorded state | always the live mount table |
| Kill shells before unmount | Yes | Yes | Yes (reconcile) |
| Stop hidden-added units / end hidden graphical session | Yes | Yes | Yes |
| Unmount overlays explicitly | Yes | Yes | Yes |
| Restore `/run/current-system` to the decoy (symlink swap) | Yes | Yes | Yes |
| Restart nix-daemon / journald after unmount (if overlaid) | Yes | Yes | Yes |
| Restart display-manager (decoy greeter) | — | Yes | — |
| Scrub the volatile runtime journal | Yes | Yes | Yes |
| Reboot into the decoy | **Yes** | No (recommended; `--reboot`/`--poweroff`) | No |
| Close the encrypted backend | cleared by the reboot | Opt-in (`[emergency] lock_backend`, `--lock-backend`) | No |
| Edit decoy history after unmount | Opt-in (amnesic decoy only) | No | No |

The decoy restore is a symlink swap of `/run/current-system`, not a
`switch-to-configuration switch`: settings the hidden generation applied
imperatively (for example the hostname) are not reverted until a reboot. Standard
deactivation reboots, so it ends on a clean decoy generation; emergency and
recover do not, which is why both recommend a reboot and emergency offers
`--poweroff`/`--reboot`.

### When to use each

- **`deactivate`** — the normal end of a session, when you have time to reboot.
- **`emergency`** — an imminent threat, or you cannot reboot right now. Teardown
  starts immediately; pass `--countdown <SECS>` for an abortable wait and
  `--poweroff`/`--reboot` to clear RAM afterwards.
- **`recover`** — a system left inconsistent by a crash, a killed process or an
  interrupted teardown. It reads the live mount table, unmounts any NAILS overlay
  it finds, restores the decoy symlink and resets the state to Inactive.

### Emergency leaves more running

Emergency is a fast, partial teardown, not a switch back to the decoy
configuration:

- Hidden settings applied by the switch are not reverted until a reboot.
- **The encrypted backend is left open by default.** Overlay teardown always
  runs, but closing the backend is opt-in. Without the opt-in the hidden
  filesystem stays **mounted and readable** and the master key stays in kernel
  memory until you close it or power off. `nails status` and `nails verify`
  report this loudly as **Critical — hidden root still mounted**.
- Processes the hidden session started that do not hold an overlay keep running.

To let NAILS close the backend, set `[emergency] lock_backend = true` in
`nails.toml` or pass `nails emergency --lock-backend`: after the overlays are
down it syncs, lazy-unmounts the hidden root and marks its device-mapper stack
for deferred removal, so the key is wiped once the NAILS process exits. For a
non-device-mapper backend, set `[emergency] close_command` to the argv that
closes it. Otherwise close it by hand once no overlay remains — see
[The teardown sequence](#the-teardown-sequence).

### Panic switch

Because emergency teardown runs immediately, a single key that starts it is the
fastest panic button. The hazard is privilege escalation: the binary lives on the
hidden volume and is runnable by your account, so **never give it a passwordless
`sudo` rule**. Drive the panic switch through a root-owned systemd unit and a
polkit rule scoped to that one unit, and define both **only in the hidden NixOS
generation** so the decoy carries no unit and nothing that names the tool:

```nix
# Root-owned one-shot teardown. Immediate emergency, then power off to clear RAM.
systemd.services.panic = {
  description = "Session teardown";
  serviceConfig = {
    Type = "oneshot";
    ExecStart = "/mnt/usb/nails emergency --poweroff";
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

Bind a key to `systemctl start panic.service`. Keep `<hidden-root>/nails`
root-owned and not writable by any other account, or a root-run `ExecStart` is
the same escalation the passwordless-sudo warning is about.

---

## On the separate machine

### Keeping NAILS off the decoy

The `nails` binary contains identifiable strings (path references, status
messages, environment-variable names, process-detection strings). A raw string
scan of a decoy disk that ever held the binary will reveal them, and deletion
does not help: the data can survive in filesystem journals, unallocated blocks,
SSD reserved areas and backups.

- Build and verify the release on a separate machine, then copy it onto the
  hidden volume only. Never download or stage the binary on the decoy.
- Correct: `<hidden-root>/nails`, source under `<hidden-root>/src`.
- Wrong: anywhere on the decoy disk (`/usr/local/bin`, a persisted home, a
  downloads directory).

### Updating NAILS

Update by replacing the binary (and, when they change, the flake and config) on
the hidden volume with a freshly built, verified release — never by downloading
onto the decoy:

1. Build or obtain a release following
   [release-artifact-reproducibility.md](release-artifact-reproducibility.md).
2. Verify it before trusting it: check the published `checksums.txt`, and prefer
   a build you reproduced yourself. An unverified binary is an untrusted addition
   to root's TCB.
3. Install on the hidden root only, `root`-owned. Do not stage the new binary on
   the decoy at any point.
4. Re-read this guide after a version change; operational requirements can change
   between releases.

---

## On the decoy shell (before activation)

### History off on the decoy

Unlocking and mounting the hidden volume happens *before* NAILS runs, so the
unlock and mount commands you type are on the decoy. Run them in a shell with
history off:

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
  and container or device path.
- **Kernel ring-buffer messages** from opening the dm-crypt mapping and mounting
  the filesystem name the mapping and device, and reach the journal.
- **Generated systemd units**: systemd synthesises `.device` and `.mount` units
  named after the mapper and mount point, visible in `systemctl list-units`.
- **by-label / by-uuid symlinks**: udev creates `/dev/disk/by-label/<label>` and
  `/dev/mapper/<name>` while the volume is open.
- **Shell history**: covered above.

For the journal and kernel-message residue, the fix is to keep the journal off
persistent disk rather than to scrub it afterwards: configure journald with
`Storage=volatile` (or put the journal on impermanent storage) so these lines
never land on the decoy. See the "Common host traces" guidance in
[backends.md](backends.md). NAILS deactivation does not touch pre-activation
journal entries.

### Pre-activation checklist

```
[ ] Hidden volume mounted and writable at its own mount point under /mnt or
    /run/media (an overlay of /media would hide a volume mounted there)
[ ] Neither the outer nor the hidden volume opened with --allow-discards
[ ] Hidden backend is a local Linux filesystem that can host an overlayfs upper
    (ext4/xfs/btrfs/f2fs; NOT NFS/SMB/9p/FUSE or FAT/exFAT/NTFS)
[ ] Hidden volume mount survives session termination (kernel-managed, not
    session-scoped FUSE)
[ ] backend-detect preflight warnings resolved or accepted (see backends.md)
[ ] nails binary exists ONLY on the hidden volume; no copies on the decoy
[ ] Reviewed inherited decoy state in `nails check` (autostart, user services,
    lingering, autologin); masked or accepted remote-linked clients
[ ] Accepted that shared accounts and network identifiers are not isolated by the
    overlay, or applied the hidden network-identity snippet
[ ] Decoy has plausible recent activity (generated with sync/account clients
    disconnected, or in fresh-home mode — see "Remote state and sync clients")
[ ] All unsaved work saved (activation may end the session)
[ ] Emergency teardown practiced
```

---

## Inside the hidden session

### Verifying the decoy

The `nails` binary lives on the hidden volume, so run `verify` from the hidden
side, while the session is mounted. A verify run never claims the system is
clean; a run with no findings prints "no known artifacts found" plus the list of
areas it did not inspect. Exit codes: `0` clean, `10` warnings, `11` critical,
`2` the scan could not run.

```bash
sudo /mnt/usb/nails verify            # standard
sudo /mnt/usb/nails verify --deep     # homes, histories, temp dirs
sudo /mnt/usb/nails verify --json     # machine-readable
```

To inspect the decoy itself for leftovers, mount its image or partition
read-only and scan it offline (again from the hidden side):

```bash
sudo /mnt/usb/nails verify --offline --root /mnt/decoy
```

In offline mode every path is read under `--root`, and the live-only checks
(running processes, the kernel mount table, open block devices, platform package
drift) are skipped.

`verify` reports only what the verify engine actually checks: leftover overlays
by upperdir, known artifact paths, running NAILS processes by binary identity,
open crypt mappers and loop devices, swap/memory warnings, platform package
drift, and — with `--deep` — shell history files, temp and log directories, and
`recently-used.xbel`/VeraCrypt config naming the hidden root. A clean result is
evidence against *known* artifacts, not proof the decoy is untouched.

### Shell history

NAILS keeps hidden-session shell history off the decoy by killing shells before
the unmount, not by scrubbing afterwards:

- Both standard and emergency teardown SIGKILL every interactive shell (including
  root's) before unmounting, so none runs an exit trap or flushes its in-memory
  buffer. A reboot (standard) then terminates everything else.
- By default teardown makes no post-unmount write to the decoy, because such a
  write is itself a deactivation-time artifact. Your protection is that the
  history never reaches the decoy in the first place, backed by an amnesic decoy.
- An **opt-in** post-unmount edit (`[cleanup] post_unmount_cleanup`) edits the
  resolved operator's history in place for operators whose decoy root is verified
  amnesic (volatile backing, or accepted with `--accept-persistent-decoy`).
- A **preflight** warns when the shell you run NAILS from flushes history after
  every command (`INC_APPEND_HISTORY`/`SHARE_HISTORY`, or `history -a` in bash
  `PROMPT_COMMAND`): such a shell writes the unlock/mount commands to disk before
  teardown can help. Clear that warning before activating.

See [bash-history-forensics.md](bash-history-forensics.md) for the mechanics, and
[decoy-requirements.md](decoy-requirements.md) for the decoy-side history
hardening you configure yourself.

### Overlay copy-up cost and upper growth

Each overlaid directory gets a writable upper on the hidden volume. OverlayFS
copies a lower file into that upper **in full** the first time you open it for
writing, truncate it or change its mode or owner — even a one-byte edit of a
multi-gigabyte file copies the whole file. On a slow or encrypted backend this
can stall for seconds or minutes.

- The first write to a large file (Nix database, browser profiles, VM images) is
  slow; later writes are fast.
- The upper only grows: copied-up files and whiteouts persist across sessions and
  deactivation does not reclaim them. Watch space with `nails status`.
- Exclude bulky directories you do not need hidden via `overlay_exclusions`; put
  caches on tmpfs via `extended_overlays`; run `nix-collect-garbage -d` and clear
  caches inside the session.
- To reset a target's upper, do it **while deactivated**:
  `sudo /mnt/usb/nails reset-upper /home` (it confirms before deleting; resetting
  `/nix` drops the hidden Nix store and warns first).

### On-screen visibility

Any on-screen tell that you are in the hidden environment is a shoulder-surfing
and screen-recording liability. Both are off by default:

- `prompt_label`: empty by default. A non-empty value prepends a label to the
  prompt — convenient, but visible to anyone watching.
- `color_scheme.enabled`: when on, repaints the terminal background so you can
  tell the environments apart — itself a visual tell.

Neither is written to the decoy: both live on the hidden volume and in the
overlaid home, and disappear on unmount.

### During the session

```
[ ] Work only with files on the hidden volume
[ ] Avoid /tmp on the decoy; use the hidden volume's temp
[ ] Do not copy files to decoy locations
[ ] Avoid installing packages to the decoy Nix store
[ ] Keep the emergency command ready: sudo /mnt/usb/nails emergency
[ ] Know your physical emergency procedure
```

---

## When things go wrong

Every recovery here follows the same shape. Run it from a shell with **history
off** (`set +o history`), take the overlay list from the **live mount table**,
unmount the **overlays before the backend**, and never lazy-unmount. Where you
must reference the NAILS process, use the **PID NAILS recorded** (or the absolute
binary path), never a name match.

### The teardown sequence

```bash
set +o history

# 1. List live overlays, deepest first. These are your unmount targets.
findmnt -rn -t overlay -o TARGET | sort -r

# 2. If /nix is among them, stop nix-daemon before unmounting it.
systemctl stop nix-daemon.service nix-daemon.socket

# 3. Unmount each overlay target from step 1, deepest first. No -l / --lazy:
#    a lazy unmount detaches a still-busy mount and hides it from findmnt.
umount <target>        # repeat for each, deepest to shallowest

# 4. Only once no overlay remains, unmount and close the backend.
umount <hidden-root>
cryptsetup close data0            # for a dm-crypt/LUKS/VeraCrypt mapper

# 5. Confirm nothing is left.
findmnt -t overlay                # prints no rows
dmsetup ls                        # no hidden mapper
losetup -a                        # no unexpected backing file

# 6. Reset the recorded state to the decoy.
sudo <hidden-root>/nails recover
```

`nails recover` reads the live mount table, unmounts any NAILS overlay it still
finds, restores the decoy symlink and resets the state to Inactive. **Do not edit
or delete `state.json` by hand** — that hides live mounts from `status` instead
of removing them. Only if `recover` is unavailable, and only after `findmnt -t
overlay` is already empty, may you remove `state.json`.

Expected residue after a by-hand teardown: device-removal kernel messages may
reach the journal, and only a power-off or reboot clears all kernel and RAM
residue. Prefer `nails emergency --poweroff` where you can.

### Specific situations

**Interrupted activation** (process died mid-switch). You see a partial overlay
set and `status` reporting Activating or Degraded. Run the teardown sequence
above, then `nails recover`. Residue: whatever was copied up stays on the hidden
volume; the decoy is untouched.

**Stuck deactivating** (`status` reports Deactivating, or "already
deactivating"). Run `nails recover`; it reconciles from the live mount table and
finishes the teardown. If `recover` cannot run, use the teardown sequence by
hand.

**Emergency state — backend still mounted.** After an emergency without the
lock-backend opt-in, `status`/`verify` report Critical. Run steps 4–5 of the
sequence to unmount `<hidden-root>` and close the mapper, then power off to clear
the key from RAM.

**Suspend / resume.** Suspend keeps the whole session — overlays, the open
mapper and the master key — resident behind the decoy lock screen, so the decoy
login unlocks a live hidden session. Do not suspend while active. Set the decoy's
logind lid switch to `ignore` or `lock`
([decoy-requirements.md](decoy-requirements.md)), and set `sleep_policy.mode` in
`nails.toml`: `block` holds a sleep inhibitor for the session, `teardown` runs
the emergency teardown when the host is about to sleep.

**Power loss / crash / hang.** On the next boot the decoy comes up normally (the
hidden generation was never persisted as the boot default). Run `nails recover`
once if `status` is not Inactive. Residue: copied-up data on the hidden volume
only.

**Backend loss** (USB pulled, I/O errors). The overlays' upper is gone, so
processes writing to them will error. Run the teardown sequence; unmounts of a
vanished backend may need the I/O to time out. After the overlays are down,
confirm with `findmnt -t overlay` and `dmsetup ls`, then `nails recover`.

**Volume full (ENOSPC).** Copy-up or a session write fails. Free space from
inside the session (`nix-collect-garbage -d`, clear caches) or deactivate
normally and `reset-upper` a bloated target while inactive. Do not delete files
directly out of an upper or work directory by hand.

**OOM.** If the kernel killed the NAILS process mid-operation, treat it as an
interrupted activation or stuck deactivation above: run the teardown sequence
using the recorded PID or binary path, then `nails recover`.

---

## Threat-model limitations

The adversary, assumptions and out-of-scope list are defined in
[threat-model.md](threat-model.md). This section covers the operational side of
the limits operators most often miss.

### Shared decoy account and persona modes

By default NAILS runs the hidden session **as the decoy user, in the decoy
home**. The `/home` overlay merges the decoy home read-write, so every account,
credential store and application profile in the decoy home is live inside the
hidden session: browser profiles and cookies, SSH/GPG keys and agents,
password-manager databases, shell/editor/application history and caches.

`persona.mode` in `nails.toml` controls this:

| Mode | Behaviour | Use when |
|------|-----------|----------|
| `shared-home` (default) | Hidden session uses the decoy home; the decoy's accounts and secrets are live. Activation warns; `status`/`check` report the mode. | You deliberately want the decoy's login and accept the overlap. |
| `fresh-home` | A clean, empty home from the hidden volume is bind-mounted over your home after the `/home` overlay mounts, so the decoy home is not visible. The persona keeps its own state on the hidden volume. | You want the hidden session isolated from the decoy's credentials. |

For sensitive work, set `persona.mode = "fresh-home"` and sign in to the hidden
session's accounts from the clean home. Treat `shared-home` as an informed
choice.

#### Inherited autostart, services and autologin

In `shared-home` mode the hidden session inherits what the decoy account starts
automatically: `~/.config/autostart` and `/etc/xdg/autostart` entries, enabled
user services and timers, lingering, and display-manager autologin. Sync, cloud
and messaging clients therefore run under the decoy identity and can contact
remote servers and your other devices. `nails check` and the activation
confirmation list this and flag names that look like remote-linked clients (a
name-only heuristic). Mask entries you do not want:

```toml
[persona]
mask_inherited = ["dropbox", "syncthing.service"]   # or ["*"] to mask all
```

Autostart entries are masked with `Hidden=true` and user services with a
`/dev/null` mask, written through the merged home so they take effect only in the
hidden session. **Lingering and autologin are reported but not masked** — disable
those on the decoy itself. Masking changes what *runs*; it does not roll back
remote or account state.

#### Remote state and sync clients

Deactivation discards the overlay uppers and nothing else. It cannot reach state
a remote server or another device already holds. For two-way sync and
account-bound clients (Syncthing, Nextcloud/Dropbox, an IMAP Sent folder, browser
sync, messaging apps) running under the decoy identity in `shared-home`:

1. The hidden session writes to a synced folder (invisible on the decoy while
   active).
2. The live client pushes that data to the server or peer before deactivation.
3. On deactivation the upper is discarded, but the remote still has the data. The
   client reconciles and **pulls it back onto the decoy disk**, where an examiner
   can recover it.

The overlay cannot prevent this. **Deactivation is not a rollback of your online
accounts.** Mitigations, strongest first: use `fresh-home` and do not start the
decoy's account-bound clients in the session; if you must use `shared-home`, quit
or disconnect every sync/cloud/mail/messaging client before sensitive work and
treat anything they touched as already on the remote.

#### Shared network identifiers

The overlay shares the host's network identity. `clean_stale_network_config`
preserves only DNS; it does not change the machine-id, hostname, MAC addresses or
NetworkManager profiles (including VPN autoconnect). Correlation through these is
out of scope for the overlay. To present a different identity, apply it in the
hidden NixOS generation or as a NetworkManager drop-in; NAILS ships optional
snippets (`nix/modules/hidden-network-identity.nix`,
`nix/modules/network-identity/00-hidden-identity.conf`). NetworkManager has no
global VPN-autoconnect switch, so disable it per profile with `nmcli connection
modify <vpn> connection.autoconnect no`.

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

- **Discards destroy or expose hidden volumes.** Never pass `--allow-discards`,
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

DRAM retains data briefly after power-off (longer when cold). Emergency drops the
page cache after unmount (`echo 3 > /proc/sys/vm/drop_caches`), which frees only
*clean* pages and does not zero RAM. Only a power-off or reboot clears RAM:

- Power off completely (not suspend) in threat situations — `nails emergency
  --poweroff`.
- Harden the decoy kernel so freed memory is wiped: add `init_on_free=1
  page_poison=1` to the decoy kernel command line.
- There is no complete software defense against a memory dump of a running
  system; the protection is preventing access while it runs.

---

## Additional resources

- [threat-model.md](threat-model.md) — the adversary model NAILS assumes
- [decoy-requirements.md](decoy-requirements.md) — amnesic decoy setup and
  decoy-side history hardening
- [backends.md](backends.md) — storage backend matrix and deniability notes
- [bash-history-forensics.md](bash-history-forensics.md) — history-protection
  mechanics
- [SECURITY.md](../SECURITY.md) — vulnerability reporting policy
- [README](../README.md) — project overview
