# 8. Whole-root overlay entered by soft-reboot

- Status: proposed (research; a decision waits on the spike results)
- Date: 2026-10-06
- Backlog: T-132 (whole-root / soft-reboot design), T-131 (alternatives matrix)
- Related: [ADR 0005](0005-live-overlay-vs-boot-time-overlay.md), [threat model](../threat-model.md)

## Context

NAILS overlays a running decoy system directory by directory: `/etc`, `/home`,
`/root`, `/var`, `/tmp`, `/srv`, `/usr`, `/bin` and `/lib64`, with every upper
on the hidden volume. Because the system keeps running across activation, every
process that existed before the overlays went up has to be found, classified and
restarted or killed. journald has to be re-homed onto the `/var` overlay, and the
display manager has to be restarted so the desktop picks up the hidden NixOS
configuration. On the way out, overlay-rooted processes are killed, the graphical
session is spared on purpose (the operator ruled that NAILS never touches the
display manager or X and never logs the user out), and overlays that are still
busy are lazily unmounted. A spared process can then write to the exposed decoy
through an absolute path.

T-132 points out the weak spots. Services in their own mount namespaces
(`PrivateTmp=`, `StateDirectory=`, `ProtectSystem=`) keep bind mounts onto the
decoy filesystem. A periodic writer that holds no open fd during the scan is never
detected. Per-distro heuristics will never be complete. A missed writer is a
**silent** leak.

The idea evaluated here is one overlay over the whole root filesystem, entered
with `systemctl soft-reboot` into `/run/nextroot` (systemd >= 254). The service
manager then stops all of userspace, switches root into the overlay and starts a
fresh userspace there. Every process of the hidden session starts inside the
overlay, so no process heuristics are needed. Deactivation soft-reboots back into
the plain decoy root.

ADR 0005 rejected the *boot-time* overlays (`grub-live`, `overlayroot`,
`systemd.volatile=overlay`, dracut). They need a reboot, they use a tmpfs upper,
and they leave an enabler on the decoy. A soft-reboot into `/run/nextroot` has
none of those three problems. It is set up at runtime from the hidden volume, the
upper is persistent and stays on the hidden volume, and nothing is installed on
the decoy. That is why it needs its own record.

### How to read this record

Each claim is tagged with how solid it is:

- **[V-src]** verified in systemd or nixpkgs source code or man pages (links
  under Sources).
- **[V-spike]** will be verified by the spike VM test once it has run. Its log is
  the evidence, and this record must be updated with the results.
- **[I]** inferred from the source or from experience, not yet observed.

The spike is
`nix/e2e-tests/tests/research/soft-reboot-whole-root.nix`; build it with
`nix build .#legacyPackages.x86_64-linux.e2e.research-soft-reboot-whole-root -L`.
**First run (commit `ea39acb`, 2026-10-06, KVM host):** both cycles ran, and
every vital check passed in the hidden root and on the decoy: units, network,
getty and a password login, `modprobe`, ESP and EFI entries, the Nix store and
daemon, LUKS, journald writing into the upper, strict and deferred close. The
run then failed in its last step: the raw-disk grep ran out of memory in the
guest, so the final power cycle did not run. It also found two leaks, now
mitigated in the spike (§5), and a timing artefact (§1). The run's results are
marked [V-spike] below.

**Second run (commit `8c69ea8`):** cycle 1 entered in the same times. On the way
back, the first version of the `/run` scrub sent the decoy into emergency mode
after a 300 s device timeout (§5). The scrub was rewritten as an allowlist of
what to delete.

**Third run (commit `7b30b12`):** the way back worked: shutdown phase 1.2 s,
backdoor after 3.0 s, and 783 `/run/udev` entries carried. The residue check
caught one carried entry not in the snapshot, the empty `/run/initramfs`
mountpoint (§5). It is now removed, and a fourth run is pending.

## 1. Soft-reboot semantics

### What happens, in order

1. `systemctl soft-reboot` enqueues `soft-reboot.target` with
   `--job-mode=replace-irreversibly` and returns at once. With logind present it
   goes through logind, so inhibitors apply unless `--check-inhibitors=no` is
   passed. [V-src: systemctl(1)]
2. The ordinary unit-based shutdown runs: every unit that conflicts with
   `shutdown.target` / `umount.target` is stopped. That includes the display
   manager, the user sessions, NetworkManager or networkd, and journald, whose
   unit has `Conflicts=soft-reboot.target`. Mount units are unmounted, except the
   *extrinsic* ones: `/`, `/usr`, `/etc`, and everything under `/run/initramfs`,
   `/run/nextroot`, `/proc`, `/sys` and `/dev`. [V-src: `fstab_is_extrinsic()`,
   present since v254]
3. `systemd-soft-reboot.service` succeeds with `SuccessAction=soft-reboot-force`.
   PID 1 then sends SIGTERM to every remaining process (without waiting) and
   SIGKILL right after. Cgroups of units with `SurviveFinalKillSignal=yes` are
   skipped. [V-src: `finish_remaining_processes()`]
4. VT reset: PID 1 switches to VT 1 and deallocates VTs 2 to 63. [V-src:
   `reduce_vt()`]
5. If `/run/nextroot` is an OS tree (`path_is_os_tree()`, which needs
   `/etc/os-release` or `/usr/lib/os-release` inside it), PID 1 switches root into
   it. Since v258 it first checks that its own binary (`SYSTEMD_BINARY_PATH`) or
   `/sbin/init` resolves *inside* the new root. If neither does, PID 1 gives up and
   freezes the machine. [V-src: `do_reexecute()`, v258+]
6. `switch_root()` syncs the filesystems that are about to become unreachable. It
   makes `/` recursively private, then bind-moves `/dev`, `/proc` and `/sys`
   (recursively), `/run` (**non-recursively**), and `/run/credentials`
   (recursively) into the new root. A target that is already a mount point is
   left as it is. It then calls `pivot_root()` and detaches the old root with
   `MNT_DETACH`. For a soft reboot it does **not** empty the old root. [V-src:
   `switch-root.c`]
7. PID 1 re-executes `SYSTEMD_BINARY_PATH` from the new root with
   `--switched-root --deserialize`, and a normal boot transaction starts (minus
   firmware, bootloader, kernel and initrd). [V-src]

### What survives and what is torn down

| Survives | Torn down |
| --- | --- |
| The kernel, loaded modules, sysctl and `/sys` settings [V-src] | Every userspace process, except units built to survive [V-src] |
| dm-crypt/LUKS mappings and their keys. Nothing closes them, because the second shutdown phase (`systemd-shutdown`, which detaches DM devices) is not run [V-src: man page "Notes"; I for "keys stay"] | Mounts that are not below the new root. They are detached together with the old root [V-src] |
| Mounts below `/run/nextroot`. They become the new tree [V-src] | Mounts *below* `/run` (for example `/run/user/<uid>` and `/run/wrappers`). `/run` is carried non-recursively [V-src] |
| The contents of `/run`, including `/run/log/journal`, `/run/utmp`, `/run/systemd/transient` and `/run/nextroot` (left as an empty directory) [V-src for `/run`; V-spike for the individual files] | VTs 2 to 63 (deallocated), and the graphical session with them [V-src] |
| fd stores of surviving units, and sockets of units that are never stopped (`DefaultDependencies=no` without a conflict, for example `systemd-journald.socket`) [V-src] | `/usr/lib/systemd/system-shutdown/` hooks: they do **not** run [V-src] |
| The boot ID, the kernel ring buffer, uptime and network addresses held by the kernel [I: kernel state, nothing resets it] | |

Two consequences matter for NAILS:

- If `/run/nextroot` is left populated, a plain `reboot` becomes a soft-reboot
  (v255+, unless `SYSTEMCTL_SKIP_AUTO_SOFT_REBOOT=1` is set). [V-src] NAILS must
  never leave a tree there.
- `systemctl switch-root` is refused outside the initrd since v255. Soft-reboot is
  the only supported way to switch between real roots. [V-src: NEWS 255]

### Timing, console, GPU and network

- **Timing.** Red Hat's bootc material only says "seconds", against minutes for
  a full reboot. [V-src, qualitative] Measured in the spike VM (2 vCPUs,
  headless NixOS, from the guest's serial-console kernel timestamps) [V-spike]:

  | Transition | Trigger to "Soft-rebooting." (shutdown phase) | Trigger to backdoor shell | Trigger to `multi-user.target` (PID 1: "Soft-reboot finished in") |
  | --- | --- | --- | --- |
  | cycle 1, enter | 1.2 s | 3.0 s | 9.1 s |
  | cycle 1, leave | 1.0 s | 2.7 s | 9.1 s |
  | cycle 2, enter | 2.4 s | 6.4 s | 13.5 s |
  | cycle 2, leave | 0.7 s | 2.7 s | 9.6 s |

  About 6 s of every figure in the last column is dhcpcd waiting for its lease
  (`multi-user.target` waits for the DHCP client in this VM). Userspace is usable
  2.7 to 6.4 s after the trigger. For comparison, the kernel-to-`multi-user`
  time of a full boot in the same VM is 13.3 s, on top of OVMF and systemd-boot.
  The first run reported ~290 s per transition. That was an artefact:
  the driver's `wait_for_console_text()` consumes one queued console line per
  second, and a soft-reboot prints ~300 lines. The spike now reconnects directly
  (bounded by an alarm) and logs PID 1's own `ShutdownStart`, `Userspace` and
  `Finish` timestamps. A misbehaving unit can still stall the shutdown up to
  `DefaultTimeoutStopSec` (90 s by default). Estimate for a real desktop, with
  its display manager and user session: 5 to 15 s to the greeter. [I] The
  headless VM cannot show the time to the greeter.
- **What the user sees.** The desktop disappears. VT 1 comes to the front with a
  text console (systemd status output or a getty) for the grey-out, then the
  display manager greeter appears. **The user is logged out.** [V-src for the VT
  reset and the process kill; I for the exact picture]
- **DRM/GPU.** The kernel driver is not reset; only its userspace clients (the
  compositor or X server) restart. [I] This is gentler than kexec, where the
  driver re-initialises the hardware.
- **Network.** Kernel interfaces, addresses and routes stay. The daemons restart:
  Wi-Fi (wpa_supplicant/iwd) and VPN tunnels drop and reconnect, and DHCP leases
  are renewed. [I] The spike checks that `network.target` comes up and that an
  address is present [V-spike]. An address alone proves little, because the
  kernel keeps addresses.

## 2. `/run/nextroot` as an overlay over the decoy root

What the spike builds, and what a NAILS implementation would build:

```sh
mount --bind / /run/nails-lower                # non-recursive: only the root fs
mount -o remount,bind,ro /run/nails-lower      # read-only, so no atime writes
mount -t overlay overlay \
  -o lowerdir=/run/nails-lower,upperdir=$HIDDEN/root/upper,workdir=$HIDDEN/root/work \
  /run/nextroot
umount /run/nails-lower                        # overlayfs keeps private clones of its layers
mount --bind /run  /run/nextroot/run           # see "NixOS" below; same as what PID 1 does
mount --bind $HIDDEN /run/nextroot$HIDDEN      # keep the hidden volume reachable
mount --bind /boot /run/nextroot/boot          # ESP policy: read-only in the hidden root
mount -o remount,bind,ro /run/nextroot/boot
mount --make-rprivate /run/nextroot
systemctl soft-reboot
```

- **Ordering and propagation.** Everything under `/run/nextroot` is extrinsic, so
  the decoy's shutdown never unmounts it. [V-src] `--make-rprivate` stops the
  hidden mounts from propagating into other mount namespaces. PID 1 makes `/`
  recursively private just before the switch anyway. [V-src]
- **The hidden volume.** Its mount in the decoy (`/mnt/data`) is unmounted by the
  decoy's shutdown, because it is an ordinary mount unit. The bind inside
  `/run/nextroot`, plus the overlay's private clone of the upper, keep the
  superblock alive, so it appears at the same path in the hidden root. A mount
  placed under `/run` would **not** survive, because `/run` moves
  non-recursively. [V-src; V-spike]
- **The decoy root mount.** It is detached with `MNT_DETACH`. Its superblock stays
  alive only as the overlay's read-only lower. After the switch, no userspace
  process can reach the decoy filesystem by any path. [V-src] This is the core
  forensic gain over today's design (§7). The superblock itself is still mounted
  read-write. Nothing writes it, because there are no openers, but making it
  read-only at superblock level (mount it again, `remount,ro`, unmount) is an open
  hardening step. [I]
- **Changes to the lower.** overlayfs leaves concurrent changes to a lower
  undefined. They happen only during setup, while the decoy still runs. After the
  switch nothing writes the lower. Offline changes between sessions (the decoy
  running and updating itself) are allowed, but a file copied up earlier shadows
  newer decoy versions. Example: the Nix DB `db.sqlite` copied up in session 1
  hides store paths that the decoy builds or garbage-collects later. Today's
  `/nix` overlay has the same issue. [I]
- **`/boot` and the ESP.** The decoy fstab is evaluated again inside the hidden
  root. Without a policy, the hidden session would mount the ESP **read-write**,
  and `systemd-boot-random-seed.service` would rewrite `loader/random-seed` from
  inside the hidden session. Pre-mounting a read-only bind at
  `/run/nextroot/boot` makes `boot.mount` count as already active. [I; V-spike:
  ESP hash unchanged in the hidden root, `touch /boot/...` refused, and the
  random-seed unit allowed to fail.] A hidden NixOS configuration can instead set
  `fileSystems."/boot".options = [ "ro" ]` or `noauto`.
- **Other decoy filesystems.** Every other local filesystem in the decoy fstab
  (separate `/home`, `/var`, `/nix`, swap) would be mounted **directly and
  read-write** by the hidden systemd, which is a leak. Before the switch, NAILS
  has to mount an overlay for each of them inside `/run/nextroot`; already-mounted
  units are left alone. Swap must never be activated, which the decoy
  requirements already demand. A hidden NixOS generation can declare its own
  `fileSystems` instead. [I] This is the main piece of generic FHS work.
- **`/etc`, machine-id, initrd.** `/etc` is the decoy's (from the lower) plus
  hidden changes. The machine-id is the decoy's unless the upper overrides it
  (§3, network identity). The initrd does not run again. Whatever it set up stays,
  including the decoy's own LUKS root mapping and any keys in the kernel keyring.
  [V-src: initrd not re-run; I for the rest]

## 3. NixOS specifics

- **Units missing in the pinned nixpkgs.** The pinned 26.05 nixpkgs ships systemd
  259 but does not install `soft-reboot.target` or
  `systemd-soft-reboot.service`. nixpkgs PR #514100 (merged 2026-05-14) adds them
  to `upstreamSystemUnits`. [V-src] The spike declares them through
  `systemd.units`. PR #496888 ("nixos/systemd: support soft-reboot", still open)
  adds a `/run/next-system` hook that runs the next generation's `activate` from a
  unit ordered before `systemd-soft-reboot.service`, plus a test-driver
  `disconnect()`. Issue #341564 (soft-reboot fails on NixOS) is still open.
- **PID 1's pre-switch check.** On NixOS, `SYSTEMD_BINARY_PATH` is
  `/run/current-system/systemd/lib/systemd/systemd`, and a NixOS root has no
  `/sbin/init`. [V-src: nixpkgs systemd package, NixOS modules] Inside a bare
  `/run/nextroot`, `/run` is empty, so the v258+ check fails and **PID 1
  freezes**. Bind-mounting `/run` onto `/run/nextroot/run` before the switch fixes
  this: the check then resolves `current-system`, and `switch_root()` skips the
  `/run` move because the target is already mounted, which gives exactly the same
  result. Nothing is written to the decoy disk; `/run` exists there as an empty
  mountpoint. [V-src for the check and the skip; V-spike for the end-to-end
  behaviour]
- **No stage-2 activation.** A soft-reboot executes the systemd binary directly.
  NixOS's stage-2 init and its activation script do **not** run again.
  `/run/current-system` and `/run/booted-system` carry over in `/run`. [V-src]
  The kernel module tree is found through `/run/booted-system`, which is why the
  spike checks `modprobe` [V-spike].
- **A hidden NixOS toplevel.** Three ways:
  - **A. Two steps, closest to today.** Soft-reboot into the overlay with the
    decoy generation, then run the hidden `switch-to-configuration test`. It
    reuses the existing switch code. Units that changed are restarted once, but
    there are no decoy processes left to worry about. [I]
  - **B. One step.** Before the switch, run the hidden toplevel's `activate`
    chrooted into `/run/nextroot` (with `/proc`, `/sys` and `/dev` bound there).
    Then a late unit, ordered `Before=systemd-soft-reboot.service` like PR
    #496888's hook, repoints `/run/current-system` to the hidden toplevel after
    every decoy unit has stopped. PID 1 then executes the hidden systemd against
    the hidden `/etc`. This is the cleanest experience: one grey-out, and the
    greeter already belongs to the hidden configuration. Risks:
    `/run/current-system` lives in the shared `/run` and must be repointed back
    on the way out. The chrooted activation runs against the overlay's own empty
    `/run` directory and must not touch the real `/run`. [I]
  - **C. Fallback.** A, but instead of `test`, run the hidden `activate` and then
    a second soft-reboot without `/run/nextroot`. This means two grey-outs. [I]

  For every variant the hidden activation must never install a bootloader. Only
  `activate` or `switch-to-configuration test` are allowed, as today
  (threat-model invariant). The hidden toplevel must also run on the decoy's
  kernel, because the modules come from `/run/booted-system`.

## 4. Debian and Ubuntu

systemd versions in the release pockets (sources.debian.org and Launchpad,
2026-10-06):

| Release | systemd | soft-reboot | v258+ init check |
| --- | --- | --- | --- |
| Debian 12 bookworm | 252.39 (254.26 in bookworm-backports) | no (backports: yes) | no |
| Debian 13 trixie | 257.13 | yes | no |
| Debian forky/sid | 262 | yes | yes |
| Ubuntu 22.04 jammy | 249.11 | no | no |
| Ubuntu 24.04 noble | 255.4 | yes | no |
| Ubuntu 25.10 questing | 257.9 | yes | no |
| Ubuntu 26.04 resolute | 259.5 | yes | yes |

On a generic FHS root, `SYSTEMD_BINARY_PATH` is `/usr/lib/systemd/systemd` and
exists on disk, so the init check passes without the `/run` bind; the bind still
does no harm. What the overlay root needs on FHS:

- an overlay for every local filesystem in fstab (§2), and `/boot` / `/boot/efi`
  read-only;
- swap masked;
- the decoy's encrypted-root mapping left as it is (it survives);
- for a hidden configuration: a drop-in tree in the upper's `/etc`. On FHS,
  `/etc/systemd/system` is a real directory, so this is easy, unlike on NixOS.

Nothing of the NixOS-specific activation applies. That makes FHS the simpler
target for the overlay itself; the hidden configuration is just whatever the
upper's `/etc` holds. [I]

## 5. Deactivation

1. In the hidden root, mount the decoy root device at `/run/nextroot`. It is the
   same superblock as the overlay's lower, so the mount writes nothing. Then bind
   `/run` there (NixOS init check) and `--make-rprivate`. [V-spike]
2. Close the hidden backend: either `cryptsetup close --deferred data` before the
   switch, so the mapping and its key go away the moment the last opener (the
   detached overlay) is released, or a strict `cryptsetup close` from the decoy
   after the switch. The spike tests strict close in cycle 1 and deferred close in
   cycle 2. [V-spike]
3. `systemctl soft-reboot`. Every hidden process is killed. The overlay, the
   hidden volume bind and everything else in the hidden tree are detached with the
   old root and freed once unreferenced. [V-src; V-spike: no overlay or nextroot
   mount remains, the mapping closes]

**What the first run found leaking into the decoy** [V-spike]:

- **The hidden `/run`.** A file written to `/run` in the hidden session was
  present in the decoy after the switch back, in both cycles. A stopped transient
  unit's file did not survive; systemd garbage-collects it. Everything else the
  hidden session leaves in `/run` carries over: logind session state,
  `/run/utmp`, the volatile journal if the hidden journald is volatile, and stray
  files.
- **A hidden kernel record in the decoy's persistent journal.** The spike's probe
  unit writes a token to `/dev/kmsg` while it stops, after the hidden journald
  has stopped. The token was in the decoy journal once per cycle. PID 1's own
  last lines from the hidden shutdown ("systemd-soft-reboot.service: Deactivated
  successfully.", "Soft-rebooting.") were imported the same way. Mechanism
  [V-src: `journald-kmsg.c`]: journald reads `/dev/kmsg` from the oldest record
  still in the ring buffer. It skips every record whose sequence number is below
  the value stored in `/run/systemd/journal/kernel-seqnum`, and that file is the
  hidden journald's, carried in `/run`. So the decoy journald imports
  **everything logged after the hidden journald stopped**: hidden unit names in
  PID 1's stop messages, kernel messages from the hidden teardown, and any
  `/dev/kmsg` writer. Without the file it would import the **whole** ring
  buffer.

**Mitigation, implemented in the spike** (a NAILS implementation would do the
same): a script in the hidden `/run`, run as the `ExecStart=` of
`systemd-soft-reboot.service` through a runtime drop-in. That service is ordered
after `shutdown.target`, `umount.target` and `final.target`, so it is the last
userspace code before the switch: every hidden unit, journald included, has
stopped, and the hidden volume is unmounted. The script:

1. **Scrubs `/run`, deleting only what the hidden session added.** The first
   version deleted everything except a keep list. In the second run that sent
   the decoy into emergency mode [V-spike]. It had deleted the udev database
   in `/run/udev`. `systemd-udev-trigger.service` has
   `DefaultDependencies=no`, `RemainAfterExit=yes` and no shutdown conflict, so
   it stays "active" across a soft-reboot and never re-triggers [V-src: unit
   file]. Every `.device` job (`/dev/hvc0`, the ESP, `eth1`) timed out after
   300 s, `local-fs.target` failed, and the decoy fell into emergency mode.
   `/run` is the state the next userspace is built to inherit, so the scrub is
   now an allowlist of what to delete:

   | Deleted | Why |
   | --- | --- |
   | `/run/log/journal/*` | the hidden runtime journal; journald has stopped |
   | `/run/systemd/{sessions,users,seats,inhibit,shutdown}/*` | logind's state of the hidden session; logind has stopped and every session process is dead |
   | `/run/systemd/{transient,system,system.control}/*` | hidden transient and runtime unit files and drop-ins (including the scrub's own) |
   | `/run/utmp` | hidden logins; `systemd-update-utmp` recreates it at the decoy start |
   | `/run/user/<uid>` (empty dirs only) | mountpoints of the hidden user runtime dirs; their tmpfs mounts are not carried |
   | entries up to two levels below `/run` that are not in a snapshot taken in the decoy just before entering | runtime directories, lock files and stray files of the hidden session, plus what the hidden *shutdown* created (`/run/nologin`, `/run/systemd/ask-password-block`, `/run/initramfs`, see below) |

   | Kept | Why |
   | --- | --- |
   | every socket | PID 1's notify and varlink sockets and the never-stopped socket units are carried as fds bound to these inodes |
   | `/run/udev` | the device database the decoy's device units are rebuilt from (see above). It may hold records for devices the hidden session created; the spike reports how many entries are carried |
   | `/run/credentials`, `/run/current-system`, `/run/booted-system`, `/run/nextroot` | system credentials, the init check and module tree, and the transition itself |
   | everything else that was in the snapshot | the decoy's own pre-entry state; deleting it is what broke the second run. The content of kept files such as `/run/mount/utab` and `/run/cryptsetup/*` can still have been changed by the hidden session; the spike prints it for review |

   **`/run/initramfs` (third run).** NixOS's `generate-shutdown-ramfs.service`
   is pulled in by `shutdown.target` on every shutdown, soft-reboots included.
   It mounts a tmpfs at `/run/initramfs` and fills it with an exitrd built from
   the *running* system's store paths: `systemd-shutdown`, coreutils, a shell
   and `os-release` [V-src: `nixos/modules/system/boot/systemd/shutdown.nix`].
   On the way back the running system is the hidden one, so with a hidden NixOS
   toplevel this exitrd would hold hidden store paths. It is never used on a
   soft-reboot, because `systemd-shutdown`, which would exec
   `/run/initramfs/shutdown`, does not run [V-src: man page]. Being a mount
   below `/run`, it is not carried by the non-recursive `/run` move either, so
   its content dies with the old root. What the third run saw in the decoy was
   only the empty mountpoint directory [V-spike]. The scrub now unmounts any
   mount it meets among the entries to delete, then removes the directory. The
   decoy's next real shutdown builds its own exitrd again (its
   `ConditionFileIsExecutable=!/run/initramfs/shutdown` holds).

2. **Seeks the decoy journald's kmsg cursor.** It writes "last kmsg sequence +
   1", read from `/dev/kmsg` without blocking, into
   `/run/systemd/journal/kernel-seqnum`. The decoy journald then skips every
   record of the hidden session. Only PID 1's last generic lines, written after
   the script, are still imported.

The spike asserts the result. No planted probe may survive, at any depth. Every
entry two levels deep that was carried over the switch must already have been
in the pre-entry snapshot: carried means its inode change time predates the
trigger, and sockets and `/run/udev` are exempt. No late hidden kernel record
may be in the decoy journal or on the raw disk. As spike-only diagnostics, the
scrub logs every path it removes to `/dev/kmsg`. That puts the names in the
ring buffer (RAM), though not in the journal, because of the cursor; a real
implementation must not log them. If the next userspace reaches emergency mode
or PID 1 freezes, the spike now fails within seconds and prints the timeouts
and failed dependencies from the console. [V-spike: the third run removed every
probe; the `/run/initramfs` fix is pending]

Alternatives considered and rejected:

- **A fresh tmpfs at `/run/nextroot/run`** instead of the bind (a private `/run`
  per side). [V-src; effect I] PID 1 serializes its notify socket and varlink
  server sockets as open fds bound to paths in the old `/run`
  (`manager-serialize.c`). Socket units that are never stopped
  (`systemd-journald.socket`, `-dev-log.socket`, udev control) are carried the
  same way, and `socket.c` does not re-check their paths after deserialization.
  A fresh `/run` orphans all of them: `sd_notify()` fails, so `Type=notify`
  services (journald, logind) time out, and clients cannot reach journald by
  path. A fresh `/run` also has no `kernel-seqnum`, so the decoy journald would
  re-import the entire ring buffer.
- **`dmesg --clear`** (`SYSLOG_ACTION_CLEAR`). It only moves the
  `syslog(2)`/`SEEK_DATA` start point. journald opens `/dev/kmsg` without
  seeking, so it still reads every record. [V-src: journald opens without a seek;
  I: kernel `devkmsg` semantics] It would also blank the decoy's own boot
  messages in `dmesg`, which is itself a tell.
- **`ReadKMsg=no` for the decoy journald, via a `/run` drop-in.** When reading is
  enabled again, journald re-opens `/dev/kmsg` and unlinks the cursor file, so it
  again imports from the oldest record. [V-src: `manager_reopen_dev_kmsg()`]

**What stays in RAM after the switch back** (gone at power-off, so outside the
offline threat model, but visible to someone at the keyboard):

- `SoftRebootsCount` (v256+): 2 per session, readable with `systemctl show`. It
  cannot be reset without a real reboot. [V-src; V-spike: 1, 2, 3, 4]
- The kernel ring buffer itself (`dmesg`): hidden-session kernel messages and
  the late records stay readable until they are overwritten or the machine
  powers off. [V-spike]
- PID 1's last generic lines ("Soft-rebooting.") in the decoy journal, plus the
  decoy PID 1's own "Soft-reboot finished in …, counter is now at N". On a
  persistent decoy journal these reach disk under the same boot ID. [V-spike]

**Writes on the decoy disk at deactivation** are those of an ordinary decoy boot:
the random seed refreshed, a wtmp boot record (if utmp is built in),
`loader/random-seed` on the ESP, and the journal if it is persistent. [I; V-spike:
the ESP changes no more than `loader/random-seed`]

## 6. Emergency

In whole-root mode the desktop, its session and every application **are** hidden
processes: their `/` is the overlay. There is no decoy desktop to fall back to
while they keep running. Today's emergency (a live teardown that spares the
graphical session) cannot be carried over. Unmounting the root from under the
running desktop is impossible, and sparing the session means keeping the hidden
environment alive.

Options:

| Emergency path | Speed (estimate [I]) | What an observer sees | RAM afterwards |
| --- | --- | --- | --- |
| E1. Soft-reboot back to the decoy | VM: shell after 2.7 s, `multi-user` after 9–10 s (§1); desktop est. 5–15 s; 90 s worst case per stuck unit | Desktop vanishes, text console, then the decoy greeter: **a logout** | Hidden `/run` and kmsg residue until power-off |
| E2. `systemctl --force soft-reboot` (skips the orderly unit stop; processes are killed) | Faster than E1, mostly the decoy's startup [I] | Same as E1, shorter | Same as E1 |
| E3. Lock the screen at once, then E1/E2 | The lock is instant; E1/E2 runs behind it | A lock screen, then a greeter | Same as E1 |
| E4. Power off (`--poweroff`) | Seconds | A black screen; reads as "turned off" | Cleared (the strongest answer to the threat model) |

**The conflict, stated plainly.** The operator ruled that emergency must not look
suspicious at first glance and must never log the user out. **No whole-root
emergency path satisfies "never log out".** E1 to E3 end at a login screen; E4
ends with the machine off. A login screen or a powered-off laptop are arguably
unremarkable to a casual observer, but they are a logout. If the ruling stands
unchanged, whole-root mode cannot be the only mode. The live-overlay mode (and its
emergency) has to stay available for operators who need the desktop to survive
emergency.

## 7. Forensic comparison

| Transition | Today (live overlays) | Whole-root soft-reboot |
| --- | --- | --- |
| Activation, on the decoy disk | Journal window before `/var` is overlaid (volatile on an amnesic decoy); writes by processes the scan missed; decoy units restarted | The decoy's own shutdown writes (random seed, wtmp shutdown record, journal if persistent). It looks like a shutdown; after it no userspace process can reach the decoy fs [V-src] |
| During the session, on the decoy disk | **Silent leak class:** namespaced services with binds onto the decoy fs, periodic writers without open fds, absolute-path writers [T-132] | Nothing in userspace can reach it. Remaining channels: decoy fstab entries not overlaid (§2), the ESP unless read-only, EFI NVRAM (efivarfs is carried in `/sys`) [I; V-spike for the ESP and NVRAM] |
| Deactivation, on the decoy disk | Unmount, then a full reboot (today's standard path), including firmware and bootloader writes | An ordinary decoy boot's writes, without firmware or bootloader (lighter than today) [I; V-spike] |
| Emergency, on the decoy disk | Live teardown; spared processes can write through absolute paths | Same as deactivation (E1/E2) or none (E4) |
| Left in RAM | Lazily detached overlays held by spared processes; the backend open unless locked | With the §5 scrub: the kmsg ring buffer (`dmesg`) and `SoftRebootsCount`; the backend can be closed exactly (deferred close) |
| Timeline as seen on the decoy disk | Decoy "running but idle" during the session | Decoy "shut down at T1, booted at T2" with the **same boot ID** and continuous kernel uptime. A persistent journal makes this visible (one boot ID with a soft-reboot transition and a gap); the amnesic-decoy requirement removes it [I] |

## 8. Alternatives (T-131 decision matrix)

Scores: ++ strong, + good, 0 neutral, − weak, −− disqualifying. Each entry is
inferred unless noted.

| Criterion | Live overlays (today) | Whole-root soft-reboot | kexec into a hidden kernel/initrd | Full reboot into a hidden boot entry | Boot from removable media |
| --- | --- | --- | --- | --- | --- |
| Process heuristics needed | −− (core of today's design) | ++ none | ++ none | ++ none | ++ none |
| Silent missed-writer leak class | −− | ++ | ++ | ++ | ++ |
| Enabler persisted on the decoy | ++ none | ++ none (set up at runtime from the hidden volume) | + none if the kernel and initrd come from the hidden volume | −− a boot entry on the decoy ESP (violates the invariant) | + none on the decoy; some firmware adds `Boot####` NVRAM entries for new devices |
| Persistent hidden upper | ++ | ++ | + (the initrd must unlock the hidden volume, and the decoy FDE again) | + | ++ (a separate OS) |
| Activation UX | − DM restart, logout | − logout, ~10 s grey-out (VM, §1) | −− full kernel boot, GPU re-init, FDE passphrase again | −− firmware plus boot | −− power cycle plus boot |
| Emergency keeps the desktop | + (current ruling met) | −− impossible (§6) | −− | −− | −− |
| Deactivation UX | − full reboot today | + soft-reboot (no firmware) | − kexec back or reboot | − reboot | − reboot |
| Kernel state reset (boot ID, kmsg, RAM) | −− never | − never | + new kernel, but old RAM is not cleared | ++ | ++ |
| Secure Boot | ++ unaffected | ++ unaffected (same kernel) | −− lockdown refuses unsigned kernels; the decoy's signed kernel with a hidden initrd might work | + if signed | + with a shim-signed loader |
| Multi-distro portability | − heuristics per distro | + systemd ≥ 254 (bookworm and jammy excluded); fstab handling per distro | − initrd per distro | − bootloader per distro | + |
| Implementation effort | (exists) | XL | XL | L | L (but no longer "a hidden session on the decoy OS") |

## Decision (proposed)

Do **not** replace the live overlays yet. Pursue the whole-root soft-reboot as a
second, opt-in **session mode** and decide after the spike.

Reasons for pursuing it:

- It removes the entire process-detection, restart and kill machinery, the
  journald re-homing and the display-manager restart. Above all it removes the
  silent missed-writer leak class, which no amount of heuristics closes (T-132).
- Today's standard deactivation already reboots, so a soft-reboot back is *better*
  UX than today's exit (no firmware, no bootloader) and leaves fewer ESP and NVRAM
  writes.
- It adds no enabler to the decoy, has a persistent upper and needs no initrd
  work. That answers the three objections of ADR 0005 against boot-time overlays.

Reasons it cannot simply replace today's design:

- Emergency cannot keep the desktop (§6). This conflicts with the operator's
  ruling, which must be revisited for this mode, or this mode must stay optional.
- NixOS support upstream is immature: units are missing in the pinned nixpkgs, the
  init-check workaround is needed, and there is no stage-2 activation (§3).
- Each distro needs fstab-aware overlay setup, and the hidden `/run` residue needs
  a scrubber (§5).

**Go/no-go criteria** (all must hold before implementation starts):

1. The spike passes: both cycles, every vital check, the raw decoy disk free of
   hidden tokens, the LUKS mapping closed in both close modes, and no hidden
   `/run` or kmsg residue in the decoy. First run: everything up to the raw-disk
   scan passed; the `/run` and kmsg leaks it found are mitigated, and the second
   run is pending.
2. On real hardware: trigger to usable greeter ≤ 15 s in both directions on a
   GNOME or KDE decoy, and the GPU and Wi-Fi come back without intervention.
3. A hidden NixOS toplevel can be entered with variant B (or C) without touching
   the bootloader.
4. A Debian trixie / Ubuntu noble variant of the spike passes on the nix-vm-test
   tier, including a decoy with a separate `/home` partition.
5. The operator accepts the §6 emergency semantics for this mode.

## Risks

- **A frozen machine on a bad `/run/nextroot`.** A missing init or a wrong layout
  freezes PID 1 (v258+) with no way back except a power cycle. NAILS must run the
  same check itself (the spike's `precheck_nextroot()`: chroot and resolve the
  binary and `os-release`) before triggering.
- **A stray `/run/nextroot` turns a later `reboot` into a soft-reboot** into
  whatever is there. NAILS must keep it empty outside its own transitions.
- **Unmanaged decoy fstab entries** are mounted read-write by the hidden systemd
  (§2). This is the same class of silent leak this design is meant to remove, now
  per filesystem instead of per process.
- **The last-step scrub must really be last** (§5). Anything a later step logs
  to `/dev/kmsg`, or writes into `/run`, reaches the decoy. Today that is only
  PID 1's generic "Soft-rebooting." lines. If `/dev/kmsg` overflows while the
  script reads it (a read returns `EPIPE`), the cursor can come out too low, and
  the records after it are imported again. A NAILS implementation should read
  until the read would block, retrying on `EPIPE`.
- **The scrub runs in the same `/run` that PID 1 and the surviving units
  use.** Deleting state that a unit kept "active" across the soft-reboot relies
  on breaks the next boot (the second run's udev failure). The scrub therefore
  deletes only an allowlist, plus entries missing from the pre-entry snapshot.
  A hidden configuration with its own never-stopped units (`DefaultDependencies=no`,
  `RemainAfterExit=yes`) could still leave state that the decoy would then
  reuse.
- **Overlay copy-up versus a decoy that keeps changing** (§2), especially the Nix
  DB and `/etc` after a decoy rebuild between sessions.
- **The emergency ruling conflict** (§6).

### What the VM cannot show

These could break boot or leak on real hosts and are not exercised by the spike:

- **Secure Boot.** It does not affect soft-reboot (no new kernel). It matters for
  the kexec and removable alternatives.
- **A TPM-sealed decoy root (systemd-cryptenroll / Clevis).** The mapping survives
  a soft-reboot, so no unseal happens. Any service in the hidden root that
  re-measures or extends PCRs, or `systemd-pcrphase` units, changes PCR state for
  the rest of the uptime. A later real reboot is unaffected (PCRs reset).
- **systemd-boot versus GRUB.** The spike uses systemd-boot. With GRUB, a
  read-write `/boot` in the hidden root lets `grub-reboot` or grubenv writes
  (`boot_success`, `next_entry`) through. The read-only bind policy must also cover
  `/boot/grub/grubenv` and `/boot/efi`.
- **Initrd-based setups.** An initrd that leaves state in `/run/initramfs` (an
  exitrd): soft-reboot never runs `/run/initramfs/shutdown`. Storage that the
  initrd set up (LVM, mdraid, multipath, iSCSI root) is never re-assembled, which
  is fine as long as nothing in the hidden root tries to stop it.
- **Hibernation resume.** If the decoy has a resume device and the hidden root
  activates swap or `systemd-hibernate-resume`, hidden RAM can reach the decoy
  swap. This is excluded by the decoy requirements, but the hidden fstab policy
  must mask swap explicitly.
- **GPUs that do not survive a compositor restart cleanly** (NVIDIA proprietary),
  docks, displays and Bluetooth peripherals that need re-pairing after their
  daemons restart.
- **Real desktop shutdown time**: stuck user services delaying the grey-out up to
  `DefaultTimeoutStopSec`.

## Open questions

- Does `systemctl --force soft-reboot` still switch into `/run/nextroot`, and how
  much faster is it? (E2)
- Does a fresh `/run` at the switch back really break the surviving sockets, or
  does systemd re-create path-bound sockets on deserialisation?
- Is a superblock-level read-only remount of the decoy root after the switch safe
  and useful?
- Which variant of hidden NixOS activation (B or C) is robust, and what does
  `switch-to-configuration test` do when it is the first action after a
  soft-reboot (variant A)?
- How should the hidden volume's own unlock be handled when the operator starts
  from a desktop session (today: `sudo` from the decoy session, which the
  soft-reboot then ends)?

## Sources

- systemd-soft-reboot.service(8):
  https://www.freedesktop.org/software/systemd/man/latest/systemd-soft-reboot.service.html
  (source: https://github.com/systemd/systemd/blob/main/man/systemd-soft-reboot.service.xml)
- systemctl(1) (`soft-reboot`, `--force`, `SYSTEMCTL_SKIP_AUTO_SOFT_REBOOT`):
  https://www.freedesktop.org/software/systemd/man/latest/systemctl.html
- bootup(7): https://www.freedesktop.org/software/systemd/man/latest/bootup.html
- systemd NEWS (254: soft-reboot; 255: auto soft-reboot on `reboot`,
  `switch-root` initrd-only, `SurviveFinalKillSignal=`; 256: soft-reboot counter;
  257: `$SYSTEMD_SOFT_REBOOTS_COUNT`): https://github.com/systemd/systemd/blob/main/NEWS
- PID 1 re-exec, init check, process kill and VT reset (`do_reexecute()`,
  `finish_remaining_processes()`, `reduce_vt()`):
  https://github.com/systemd/systemd/blob/main/src/core/main.c (the init check
  appears in v258; v254 had no check:
  https://github.com/systemd/systemd/blob/v254/src/core/main.c)
- `switch_root()`: https://github.com/systemd/systemd/blob/main/src/shared/switch-root.c
- Extrinsic mounts (`/run/nextroot` never unmounted at shutdown):
  https://github.com/systemd/systemd/blob/main/src/shared/fstab-util.c,
  https://github.com/systemd/systemd/blob/main/src/core/mount.c
- Unit files: https://github.com/systemd/systemd/blob/main/units/soft-reboot.target,
  https://github.com/systemd/systemd/blob/main/units/systemd-soft-reboot.service,
  https://github.com/systemd/systemd/blob/main/units/systemd-journald.service.in
- nixpkgs PR #514100 (soft-reboot units, merged 2026-05-14):
  https://github.com/NixOS/nixpkgs/pull/514100
- nixpkgs PR #496888 (soft-reboot support, `/run/next-system`, test-driver
  `disconnect()`, open): https://github.com/NixOS/nixpkgs/pull/496888 (supersedes
  https://github.com/NixOS/nixpkgs/pull/309911)
- nixpkgs issue #341564 (`systemctl soft-reboot` fails on NixOS, open):
  https://github.com/NixOS/nixpkgs/issues/341564
- NixOS `SYSTEMD_BINARY_PATH`: `pkgs/os-specific/linux/systemd/default.nix` in
  nixpkgs; the test driver's backdoor and `switch_root()` reconnect pattern:
  `nixos/modules/testing/test-instrumentation.nix`,
  `nixos/lib/test-driver/src/test_driver/machine/__init__.py`
- Prior art, bootc/ostree staging `/run/nextroot`:
  https://developers.redhat.com/articles/2025/11/17/image-mode-rhel-10-updates-seconds-soft-reboot
- Soft Reboot talk, All Systems Go 2023 (L. Boccassi):
  https://media.ccc.de/v/all-systems-go-2023-184-soft-reboot-atomically-replace-rootfs-and-reboot-userspace-without-kernel-restart
- Debian systemd versions: https://sources.debian.org/src/systemd/ ; Ubuntu:
  https://launchpad.net/ubuntu/+source/systemd
- overlayfs (changes to underlying filesystems, layer handling):
  https://docs.kernel.org/filesystems/overlayfs.html
