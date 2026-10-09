# Operator guide

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
2. **Inside the hidden session** — everything after activation's soft-reboot and
   before the way back. The whole root is an overlay whose upper is on the hidden
   volume, so every write lands there, not on the decoy.
3. **The decoy shell** — the plain decoy system, before activation and after the
   way back. This is the surface a forensic examiner images.

> **Type as little as possible on the decoy.**
>
> - On the decoy you unlock and mount the hidden volume and run `nails check`
>   and `nails activate` (and, when needed, `nails recover` or
>   `nails reset-upper`). Do nothing else with the tool there: do not read
>   `state.json`, and do not name the hidden volume, its mapper, its mount point
>   or the tool in any other command.
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
afterwards, the decoy start at their own login screens.

Two safeguards bracket the session:

- **Pre-activation residue baseline.** Before it builds anything, `nails
  activate` runs the read-only decoy residue scan and writes the result to
  `<hidden-root>/reports/`, then prints a one-line summary. The scan only reads
  the decoy; the report lives on the hidden volume. It is a baseline, so if a
  later examination finds a trace you can tell whether it predated the session.
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

The design record is [ADR 0008](adr/0008-whole-root-soft-reboot.md); this is
the operator's view of it.

**Hidden-root layout.** The hidden volume holds:

| Path | Content |
|---|---|
| `<hidden-root>/nails` | the binary |
| `<hidden-root>/config/` | `nails.toml` and, on NixOS, the hidden module `config/nixos/configuration.nix` |
| `<hidden-root>/root/upper`, `root/work` | the hidden root's upper and its overlayfs work directory |
| `<hidden-root>/root/mounts/<path>/upper` | the upper of each other decoy filesystem that is overlaid (a separate `/home`), named by its systemd path escape |
| `<hidden-root>/root/cache` | the Nix evaluation cache used while the hidden system is built |
| `<hidden-root>/logs/`, `state.json`, `reports/` | the log, the recorded state and the residue reports |

Keep all of it `root`-owned on the hidden volume.

**Activation, step by step.** `nails activate` runs on the decoy:

1. It runs the pre-flight checks, among them `systemd-version` (254 or newer),
   `soft-reboot-units` (the units that implement `systemctl soft-reboot` are
   installed), `decoy-root` (the decoy root can be mounted again by device for
   the way back), `session-state` (no session and no leftovers of an
   interrupted one), `fstab-policy`, `hidden-volume`, `upper-fs-capability`,
   `backend-detect`, `storage-readiness`, `swap`, `memory-wipe`,
   `sleep-policy`, `decoy-persistence`, `inherited-autostart`,
   `incremental-history-flush` and `space`. `nails check` runs the same checks
   and changes nothing.
2. It snapshots `/run` and writes the session plan to `/run/overlay-runtime`,
   together with a RAM copy of the binary and the configuration.
3. It mounts the root overlay at `/run/nextroot`: the decoy root, read-only, as
   the lower; `<hidden-root>/root/upper` as the upper.
4. On NixOS with a hidden configuration it builds and activates the hidden
   system (see below).
5. It applies the **fstab policy** to every filesystem the hidden systemd would
   mount from the decoy's fstab:
   - the ESP and `/boot` filesystems are bound read-only, so nothing in the
     hidden session rewrites `loader/random-seed`, `grubenv` or a boot entry;
   - a filesystem mounted read-only in the decoy is bound read-only;
   - every other mounted local filesystem (a separate `/home`, `/var` or
     `/nix`) gets an overlay of its own, with its upper under
     `<hidden-root>/root/mounts/`;
   - swap, local filesystems that are not mounted now, network filesystems and
     overlay entries that are not mounted now but have their upper on a disk
     are masked in `/run`, so the hidden systemd never activates them.

   The full table is in
   [configuration.md](configuration.md#what-the-session-covers).

   `nails check` lists the decision for each entry.
6. It binds `/run` and the hidden volume into the next root (the hidden volume
   appears at the same path in the hidden session) and checks the init the way
   PID 1 will, so a broken tree is refused before the switch instead of freezing
   the machine.
7. It installs the transition step (a runtime drop-in for
   `systemd-soft-reboot.service`), prints its result, kills the decoy's
   interactive shells and soft-reboots. A second runtime drop-in clears the
   stop command of `blk-availability.service`, which Debian and Ubuntu enable
   wherever `dmsetup` is installed: its `blkdeactivate -u` would unmount the
   hidden volume below `/run/nextroot` during the switch, or a LUKS or LVM
   decoy root on the way back. The way back removes both.

**The hidden NixOS system.** With a hidden configuration — a flake given with
`--nixos-flake` or `nixos_flake`, or otherwise the legacy configuration, which
is the decoy's `/etc/nixos` plus the hidden hardware configuration `init` placed
in `<hidden-root>/root/upper/etc/nixos/` (it imports
`<hidden-root>/config/nixos/configuration.nix`) — activation builds the hidden
toplevel into the next root's store (`nix build --store /run/nextroot`). The
build reads the decoy store through the lower and writes every new path, the
Nix database included, into the upper; nothing reaches the decoy `/nix`.

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
`/run`, and the transition step repoints `/run/current-system` only after every
decoy unit has stopped, so PID 1 executes the hidden systemd against the hidden
`/etc`. No bootloader is installed and no system profile changes. The hidden
toplevel must run on the decoy's kernel: the kernel modules come from
`/run/booted-system`. `--overlay-only` skips the build and enters with the
decoy's own system plus the hidden `/etc` and home.

**Debian and Ubuntu.** The same root overlay, with no build step: the hidden
configuration is whatever the upper's `/etc` holds. Change it from inside the
hidden session like any system configuration.

**The way back.** `nails deactivate`, in the hidden session, mounts the decoy
root at `/run/nextroot` (the same filesystem the overlay reads as its lower, so
mounting it writes nothing), marks the hidden backend's device-mapper stack for
deferred removal, records the state as inactive and soft-reboots. The orderly
shutdown stops every hidden program. The last step before the switch:

- scrubs `/run` of what the hidden session added. It deletes from an allowlist
  (the hidden runtime journal, logind's session state, runtime units, `utmp`,
  and entries that were not there when the session was entered) and never
  touches sockets, `/run/udev`, credentials or the current/booted system links,
  which the decoy's next userspace is built to inherit;
- restores libmount's `utab` to the copy taken at entry;
- writes journald's kernel-message cursor, so the decoy journal imports no
  kernel record of the hidden session.

PID 1 then switches back into the plain decoy root, and the decoy starts at its
own login screen. The hidden volume is unmounted and its mapping closed by the
switch itself, once the overlay that held it is released.

**What a soft-reboot leaves.** Nothing of the hidden session's files, but some
kernel state, all of it in RAM and gone at power-off:

- the kernel ring buffer (`dmesg`), with the hidden session's kernel messages;
- `SoftRebootsCount`, two per session, readable with `systemctl show`;
- the same boot ID and continuous uptime across both transitions.

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
| Ends at | the decoy's login screen (`--poweroff`: off) | the decoy's login screen (`--poweroff`: off; `--reboot`: a full reboot) | the decoy, unchanged |
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
  points at `deactivate`. A plain `reboot` after an interrupted activation
  needs no `recover`: the leftover next root is detached during it and the
  hidden volume's devices are closed, as a full reboot would.

### What emergency does

In the hidden session, emergency:

1. prepares the way back (the decoy root at `/run/nextroot`, `/run` bound into
   it, the init checked);
2. marks the hidden backend's device-mapper stack for deferred removal (the
   backend is always closed; there is no option to leave it open);
3. enqueues the soft-reboot directly with PID 1, so the pending stop jobs keep
   `Restart=` from reviving anything;
4. kills every hidden cgroup at once with `cgroup.kill`. Only PID 1 and its own
   invocation survive until the switch.

The orderly shutdown then has nothing left to wait for, the `/run` scrub still
runs as the last step, and the machine returns to the plain decoy, which shows
its normal display-manager greeter (or a getty). **Log in normally, with the
decoy password; nothing logs in automatically.** The screen goes to a text
console for a few seconds in between: to an observer this is a logout, not a
crash.

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
  like `recover`.

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
the decoy's login screen instead. Keep `<hidden-root>/nails` root-owned and not
writable by any other account, or a root-run `ExecStart` is the same escalation
the passwordless-sudo warning is about.

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
[backends.md](backends.md). NAILS never touches pre-activation journal entries.

### Pre-activation checklist

```
[ ] Hidden volume mounted and writable at its own mount point (e.g. under /mnt)
[ ] Neither the outer nor the hidden volume opened with --allow-discards
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

Everything in this section runs after activation's soft-reboot, logged in at the
hidden session's own login screen. The hidden volume is at the same path as on
the decoy.

### Verifying the decoy

The `nails` binary lives on the hidden volume, so run `verify` from the hidden
side. A verify run never claims the system is clean; a run with no findings
prints "no known artifacts found" plus the list of areas it did not inspect.
Exit codes: `0` no known artifacts, `10` warnings, `11` critical, `1` the scan
could not run, `3` the configuration could not be loaded.

```bash
sudo /mnt/data/nails verify            # standard
sudo /mnt/data/nails verify --deep     # homes, histories, temp dirs
sudo /mnt/data/nails verify --json     # machine-readable
```

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
shell history files, temp and log directories, and `recently-used.xbel`/VeraCrypt
config naming the hidden root. A clean result is evidence against *known*
artifacts, not proof the decoy is untouched.

### Rehearsing before you rely on it

The forensic E2E tests prove the leak claims on CI's virtual machines.
`nails rehearse` proves them on your machine, with your decoy, backend and
desktop, before you rely on them:

```bash
sudo /mnt/data/nails rehearse plant         # 1. inside an active hidden session
sudo /mnt/data/nails deactivate --poweroff  # 2. end the session and power off
# boot the decoy, unlock and mount the hidden volume again, then:
sudo /mnt/data/nails rehearse scan          # 3. from the decoy, or a later session
sudo /mnt/data/nails rehearse reset         # remove the rehearsal when done
```

`plant` puts a random token where a session most often leaks: a file named after
it in the hidden root and in your home, a `recently-used.xbel` bookmark, a
system-log line, a process command line and a desktop notification. Every file
write is checked first to land in the upper on the hidden volume; nothing is
written to the decoy. The token stays on the hidden volume
(`rehearse/state.json`) and is never printed, only a six-character fingerprint.

`scan` reads every mounted decoy block device (and active swap) raw and
read-only, without mounting anything, and searches allocated and unallocated
space for the token in ASCII and UTF-16LE. It refuses to run in the session the
canary was planted in. A soft-reboot keeps the boot ID, so the session is told
apart by the boot ID together with systemd's soft-reboot count: after
`nails deactivate` the scan runs on the decoy. On a systemd that does not
report the count, power off between `plant` and `scan` (`--allow-same-boot`
overrides the check, but a scan in the planting session proves little).
Exit `0` means the token was not found, `11` that it was (with the device and
byte offset of each hit), `9` that a device could not be scanned completely.
`nails rehearse` alone shows where you are and the next step.

A clean scan covers only what a host can read. It cannot see SSD cells the
drive has remapped or keeps in reserve, blocks discarded with TRIM, disks that
are not mounted (name them with `--device`), the encryption header area or
firmware storage; the scan prints this list with every result. To scan a disk
image instead, use `nails rehearse scan --offline --image <file>`.

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

### Changing the hidden configuration

On NixOS, `/etc/nixos` inside the hidden session is the hidden configuration
(the decoy's files plus the hidden hardware configuration in the upper), and
`sudo nixos-rebuild test` applies a change to the running hidden session. Do not
use `switch` or `boot`: they try to install a bootloader into the read-only ESP
and fail. The change persists in the upper; the next activation builds the
hidden configuration again from `<hidden-root>/config/nixos/` or your flake, so
keep that source in step with what you test.

On Debian and Ubuntu, change the hidden system like any other: `apt`, edits in
`/etc`, `systemctl enable`. Every change lands in the upper and is the hidden
configuration from then on.

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
- To drop a path's hidden copy so the decoy's own files show through again, run
  `reset-upper` **on the decoy**, with the hidden volume mounted:
  `sudo /mnt/data/nails reset-upper /etc/nixos` (it lists what it deletes and
  confirms first; resetting `/nix` drops the hidden Nix store and warns first).
  For a separately overlaid filesystem it also removes that filesystem's upper.
  It is refused in the hidden session, where the upper is the live root.

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
  (`session_mounts.alert`, on by default).
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
[ ] On NixOS, apply changes with `nixos-rebuild test`, never `switch` or `boot`
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
#    drop-in that clears blk-availability.service's stop.
rm -rf /run/overlay-runtime
rm -rf /run/systemd/system/systemd-soft-reboot.service.d
rm -f /run/systemd/system/blk-availability.service.d/zz-overlay-runtime.conf
rm -f /run/systemd/system/network-addresses-.service.d/zz-overlay-runtime.conf
systemctl daemon-reload

# 3. Confirm nothing is left.
findmnt -R /run/nextroot          # prints no rows
ls /run/overlay-runtime           # no such file or directory
```

Then close the backend as usual (`umount <hidden-root>`, `cryptsetup close
<mapper>`). Powering off instead does the same: everything above lives in `/run`
and is gone at power-off. **Do not edit or delete `state.json` by hand** —
`recover` resets it once the hidden volume is back.

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

**Deactivation refuses or fails** in the hidden session. Use `nails emergency`.
If the way back cannot be prepared, emergency powers off instead.

**The hidden session hangs.** Switch to a text console (Ctrl+Alt+F2), log in and
run `nails emergency`; if nothing responds, power off. A stuck user service can
delay an orderly `deactivate` by up to `DefaultTimeoutStopSec` (90 s by
default); `emergency` does not wait for it.

**Suspend / resume.** Suspend keeps the whole hidden session — the overlay, the
open mapper and the master key — resident behind the hidden lock screen, and the
decoy is not running at all. Do not suspend during a session. Set the decoy's
logind lid switch to `ignore` or `lock`
([decoy-requirements.md](decoy-requirements.md)), and set `sleep_policy.mode` in
`nails.toml`: `block` holds a sleep inhibitor for the session, `teardown` powers
off when the host is about to sleep.

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
normally and `reset-upper` a bloated path from the decoy. Do not delete files
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
services, `~/.config/autostart` and `/etc/xdg/autostart` entries, enabled user
services and timers, lingering, and display-manager autologin. Sync, cloud and
messaging clients therefore run under the decoy identity and can contact remote
servers and your other devices. `nails check`, and the `inherited-autostart`
warning in activation's pre-flight output, list this inherited state and flag names that look like remote-linked clients (a
name-only heuristic).

Disable what you do not want **inside the hidden session**: mask the unit
(`systemctl --user mask syncthing.service`), remove or override the autostart
entry, or, on NixOS, leave it out of the hidden configuration. The change lands
in the upper, so it takes effect for the hidden session only and the decoy is
unchanged. **Lingering and autologin are decoy settings** — disable those on the
decoy itself. Disabling changes what *runs*; it does not roll back remote or
account state.

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
- Harden the decoy kernel so freed memory is wiped: add `init_on_free=1
  page_poison=1` to the decoy kernel command line. The hidden session runs on the
  same kernel, so this covers it too. The `memory-wipe` pre-flight check reports
  whether the booted command line sets `init_on_free=1`.
- There is no complete software defense against a memory dump of a running
  system; the protection is preventing access while it runs.

### What has not been validated on hardware

The session is validated in virtual machines. These are open until measured on
real hardware:

- the time from trigger to the login screen on a real desktop (in the test VM:
  about 3 s to a shell, 9 to 15 s until the system has settled);
- GPU, Wi-Fi, VPN and Bluetooth coming back after each transition, NVIDIA's
  proprietary driver, docks and external displays;
- decoy roots unlocked with a TPM-sealed key (the mapping survives the
  soft-reboot, but anything in the hidden session that measures into PCRs changes
  them for the rest of the uptime);
- GRUB's `grubenv` (keep `/boot` read-only, as the fstab policy does);
- user services that do not stop promptly, delaying an orderly transition up to
  `DefaultTimeoutStopSec`.

Rehearse on your own machine before relying on it.

---

## Additional resources

- [threat-model.md](threat-model.md) — the adversary model NAILS assumes
- [decoy-requirements.md](decoy-requirements.md) — amnesic decoy setup and
  decoy-side history hardening
- [backends.md](backends.md) — storage backend matrix and deniability notes
- [ADR 0008](adr/0008-whole-root-soft-reboot.md) — the whole-root soft-reboot
  design and its evidence
- [bash-history-forensics.md](bash-history-forensics.md) — history-protection
  mechanics
- [SECURITY.md](../SECURITY.md) — vulnerability reporting policy
- [README](../README.md) — project overview
