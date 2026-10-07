# 7. Emergency teardown architecture

- Status: proposed
- Date: 2026-10-06

## Context

`nails emergency` is the panic path. It must quickly tear down every NAILS
overlay and leave a host that looks like the plain decoy. The operator's rulings
are fixed inputs to this record:

- never touch the display manager or X server, and never log the user out;
- keep the targeted kill of overlay-rooted processes *outside* the graphical
  session, and keep the interactive-shell kill;
- keep working with a dead hidden volume and with a missing or corrupt state
  file;
- tolerate broken pipes;
- make no writes to the decoy disk;
- do not look suspicious at first glance.

### What the emergency path does today

The binary is the static musl release build. It is copied to
`/run/overlay-runtime/control` at activation, so it still runs after the hidden
volume dies. A backend watcher unit can also start the teardown on its own. One
invocation goes through the whole CLI stack:

1. `nails-cli/src/cli/commands/emergency.rs` loads the config (falling back to the
   RAM copy) and builds a full `NailsManager`. It try-locks the state file on the
   hidden volume (`EMERGENCY_LOCK_TIMEOUT`), then calls `emergency_deactivate()`.
2. `manager/deactivation.rs::run_deactivation` reads and classifies the state
   file, then discovers mounts from mountinfo. It SIGTERMs a recorded owner pid
   and waits for it (up to 10 × 300 ms). It inspects the overlay context and
   removes guards and submount attachments. It stops `nix-daemon` and unbinds
   `/nix/store`, also in PID 1's namespace through `fork`/`setns`.
3. `stop_hidden_units_before_teardown` runs `systemctl stop` for each unit the
   hidden configuration added. `kill_overlay_rooted_processes` then takes a
   `/proc` snapshot and enumerates logind sessions through `loginctl` (the
   graphical-session guard). It classifies each process by path prefix, then
   confirms the match by `stat()`ing every `/proc/<pid>/{cwd,root,fd/*}` against
   the overlay devices. It sends signals by **spawning a `kill` process per pid**
   (`signal_pid`), sleeping 300 ms between TERM and KILL.
4. It kills interactive shells, then runs `journalctl --relinquish-var`. The
   orchestrator writes state transitions to the hidden volume (tolerated on
   failure) and unmounts in reverse order, graceful first and then
   `MNT_FORCE|MNT_DETACH`.
5. It restarts `nix-daemon` and `journald` with `systemctl`, stops the watcher
   unit, removes the runtime copy, rotates and scrubs `/run/log/journal`, and
   finally runs the power action.

That path spans about 5,400 lines across `emergency.rs`,
`manager/deactivation*`, `backend_lock.rs`, `runtime_copy.rs` and the mountinfo
parser. It uses another ~5,900 lines of `process/`, links a 143-crate
dependency graph (zbus included), and runs a dozen child processes. The bugs
the last review found are being fixed on another branch: aborting on an
unwritable state, power actions skipped on failure, decoy writes after unmount,
the invoking shell surviving, the auto-emergency killing itself, and wrong
process matching. Every one of them comes from this shape:

- **Order and coupling.** Hidden-volume I/O (state, lock) and decoy-touching
  steps are interleaved with the one step that matters.
- **Heuristic process selection.** Path prefixes, device `stat()`s and pid lists
  can race with forks and pid reuse. They also *touch the possibly dead
  backend*: a `stat()` through `/proc/<pid>/fd/N` on an overlay whose upper
  sits on a dead device can block in D-state.
- **Self-reference.** The watcher runs emergency inside its own unit, and
  `teardown_backend_runtime_copy` stops that unit, which kills the teardown
  before it scrubs the journal.
- **Subprocess dependence.** `systemctl`, `journalctl`, `loginctl` and `kill` are
  executed from `/nix/store`. When `/nix` is overlaid with its upper on the dead
  volume, every exec goes through an overlay lookup that consults the upper
  first.

The proposal on the table is a separate minimal emergency binary. It would have
few dependencies and no config parsing, be preloaded into RAM, and be driven by
a step journal written at activation (each mount/bind/journald/switch step with
its undo), falling back to the live mount table. This record compares it with
the alternatives.

## Evidence gathered for this record

Two experiments back the comparison. Both run against a real kernel, not a mock.

**Kernel proof of concept** (`nails-core/tests/research_emergency_kernel.rs`).
It runs unprivileged inside a fresh user, mount and cgroup namespace; the run
below was on Linux 7.2. Whether a superblock is released is checked with
overlayfs itself: an `index=on` overlay refuses (`EBUSY`) to mount an upper
directory that any live overlay superblock still uses. A successful probe mount
is therefore the kernel stating that nothing pins the upper. On a real host
that is the condition for closing the hidden volume.

| Scenario | Result (three runs, debug build) |
| --- | --- |
| `cgroup.kill` on a cgroup holding a cwd holder, an fd holder, a SIGTERM-ignoring writer, a SIGSTOPped process, a `setsid` daemon and a parent forking up to 1,000 children | 310–551 processes at kill time. The cgroup drained in 16–78 ms, and a **non-lazy** `umount2` succeeded 25–83 ms after the kill. Upper released, lower byte-identical, sibling "desktop" cgroup untouched. |
| `MNT_DETACH` with one fd holder still alive | The mount table is clean at once, but the holder still reads hidden data through `/proc/<pid>/fd/0` and the upper stays pinned (`EBUSY`). The upper is released 1–5 ms after the holder is killed through a pidfd. |
| Overlay mounted only inside a private mount namespace | Never visible in the outer `/proc/self/mountinfo`. After `cgroup.kill` of the namespace's processes, the namespace and its overlay are freed within 3–9 ms, and no process remains in that namespace. |

**VM experiment** (`nix/e2e-tests/tests/research/01-emergency-cgroup-kill.nix`,
tag `research`, outside every default group). It runs on a real systemd host
with an overlay mounted over its own lower directory, the live-overlay shape. A
`Restart=always` unit with its working directory in the overlay is torn down
three ways:

| Variant | Kill → non-lazy unmount | systemd restarted it? | Restarted unit wrote to the decoy? | Journal lines |
| --- | --- | --- | --- | --- |
| raw `cgroup.kill` | 62–87 ms | yes (`Failed with result 'signal'`, then restart) | **yes** | 6 |
| `systemctl stop --no-block`, then `cgroup.kill` | 113 ms | no (clean `Stopped`) | no | 5 |
| `systemctl kill --signal=SIGKILL` | 65 ms | yes | **yes** | 8 (two of them say "on client request") |

A desktop stand-in in a sibling cgroup survived every variant. The finding that
matters: **any kill of a service process, whether by cgroup, by `systemctl kill`,
or by today's per-pid `kill`, lets systemd restart the unit.** The restart lands
*after* the detach, so it runs on the decoy and writes there. Only an enqueued
stop job suppresses `Restart=`. The same applies to today's
`kill_overlay_rooted_processes` whenever a matched pid belongs to a service with
`Restart=` set.

## The options

The candidates differ along three independent axes, and the useful answer picks
one point on each:

- **Packaging:** where the code lives and what gets executed.
- **Knowledge:** how emergency learns what to undo.
- **Kill mechanism:** how it picks and stops the processes that pin overlays.

### A. Status quo hardened

Same binary and crate, with a dedicated slim code path inside the existing
manager. This is the cheapest to land, and it keeps one implementation of
discovery and the session guard. The slim path still constructs the manager,
config and `Filesystem` abstractions, so a review must prove that none of the
~11k surrounding lines runs before the unmount. That property is easy to regress
and hard to enforce, because every helper is reachable.

### B. Separate small binary (`nails-emergency`)

A second executable with minimal dependencies, preloaded into RAM. It is isolated
by construction and small enough to review in one sitting. Its costs:

- a **second artifact** in the release, reproducibility and signature tooling
  (`docs/verify-release.md`, `RELEASING.md`);
- a second unusual file under `/run`;
- version skew between the binary that writes the plan and the one that reads it;
- a duplicate mountinfo parser and ownership logic, or a shared crate anyway.

The isolation it buys does not come from being a separate *process*. The release
binary is already static and already copied to `/run`. What isolates is that the
hot path never runs the CLI stack, and a crate boundary plus early dispatch
deliver exactly that.

### C. Everything prepared at activation: a teardown plan in RAM

Activation already knows every mount it made, in order, and in which namespace.
It also knows every unit it started, restarted or added, and the decoy system it
replaced. It can write a declarative **teardown plan** to the tmpfs: an ordered
list of idempotent operations. A tiny interpreter executes the plan without
config, state, D-Bus or subprocesses. The live mount table remains the fallback
when the plan is missing, and the reconciliation sweep after it.

This beats the proposal's undo *journal* in one detail. The undo of every NAILS
step is a fixed function of the step (mount → unmount, bind → unmount, service
restarted → stop/start), so the journal collapses into the plan anyway. A plan
that describes the target end state (these mounts gone, these cgroups empty, the
`current-system` link pointing here) is idempotent: running it twice, or after a
partial run, is safe. The plan is rewritten atomically (temp file and rename on
tmpfs) after each activation step, so it is always consistent with what is
mounted.

### D. Kernel-assisted mechanisms

- **`MNT_DETACH`** (lazy unmount) clears the mount table in microseconds and
  never fails with `EBUSY`. The PoC shows it releases nothing on its own: hidden
  data stays readable through any held fd, and the upper keeps the hidden volume
  pinned. It is the right *second* step after a kill, never a substitute. Use it
  with `UMOUNT_NOFOLLOW`, and never `MNT_FORCE` (meaningless for overlayfs).
- **`cgroup.kill`** (Linux 5.14) SIGKILLs a whole cgroup tree atomically. It
  handles racing forkers and migrations and needs no pid list, so pid reuse and
  forks stop mattering. It touches no file on the hidden filesystem. Completion
  is observable by polling or `poll()`ing `cgroup.events` for `populated 0`. A
  task in D-state keeps the cgroup populated until its sleep ends, so the wait
  must be bounded. On systemd hosts every service already has its own cgroup and
  every login session its own `session-N.scope`, so the kill granularity is
  already there with no new units.
- **pidfds** (`pidfd_open` 5.3, `pidfd_send_signal` 5.1) signal one process
  without a pid-reuse race and can be `poll()`ed for exit. `process_mrelease`
  (5.15) reaps a killed process's memory immediately instead of whenever the
  exit path gets to it, which shrinks the window in which hidden data stays in
  RAM. These fit the per-pid cases the cgroup model cannot cover: interactive
  shells inside the spared graphical scope, and the invoking shell, killed last.
- **Mount namespaces.** Running the hidden session in its own mount namespace
  would make emergency trivial: kill its processes and the namespace and its
  overlays vanish (the PoC proves it), and the overlay never appears in PID 1's
  mount table. It **does not fit the live-overlay model under the rulings.** The
  hidden session *is* the operator's graphical session: activation restarts the
  display manager so the desktop logs back in under the overlays. Putting the
  overlays in a private namespace means the display manager and session must
  live in it, and killing the namespace is a logout. Hidden services would also
  have to be relaunched inside the namespace. Mount namespaces remain relevant
  in two ways:
  - services with `PrivateTmp=`/`ProtectSystem=` already have private (slave)
    namespaces whose own mounts on overlay paths are not removed by an unmount
    in PID 1's namespace. Killing the unit's cgroup frees them, which is one
    more reason to kill by cgroup;
  - `/proc/<pid>/mountinfo` still reveals a namespaced overlay to a root
    observer, so it is not a visibility win either.

### E. systemd-native: a dedicated slice or scope plus `systemctl kill`/`stop`

Put hidden-session processes into a dedicated slice and make emergency a stop
of that slice. A dedicated *new* slice or scope costs a transient unit at
activation, which shows up in `systemctl list-units` and in the journal
("Created slice …", "Started …"). It also needs services moved by restart into
the slice, and it does not cover the graphical session, which the rulings spare
anyway. `systemctl kill` makes emergency depend on PID 1's D-Bus being
responsive and on executing `systemctl` from a possibly overlaid `/nix/store`,
and it logs "on client request" lines (VM experiment). `systemctl stop` is the
only way to suppress `Restart=` (VM experiment), so the systemd side cannot be
dropped entirely. What remains useful from E is systemd's existing per-unit
cgroups as the kill granularity, plus one enqueued stop job per recorded unit.

### F. Recommended hybrid

- **Packaging:** a new workspace crate, `nails-teardown`, linked into the one
  static binary (B's isolation, A's single artifact). Its dependencies are
  limited to `rustix`/`libc` (and `serde_json` only if the plan format needs it).
- **Knowledge:** an activation-time plan in RAM (C), always reconciled against
  the live mount table.
- **Kill mechanism:** cgroup-granular kills of recorded unit and session cgroups,
  with an enqueued stop job for restartable units. pidfds for the remaining
  per-pid kills. `MNT_DETACH` after the kill (D).

## Decision matrix

`++` best … `--` worst, relative to the other options on the same row.

| Criterion | A hardened | B separate binary | C plan + interpreter | D mount ns | D cgroup.kill + pidfd + detach | E systemd slice | **F hybrid** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Fits the rulings (no logout, targeted kill) | `+` | `+` | `+` | `--` (kill = logout) | `+` | `0` (new units) | `+` |
| Panic robustness: dead backend | `-` (stat/exec through overlays, state I/O) | `+` | `++` (no hidden-fs access in the hot path) | `+` | `++` (no file access to pick victims) | `-` (D-Bus, exec from `/nix`) | `++` |
| Hung / D-state processes | `-` (unbounded waits in helpers) | `0` | `+` (bounded ops) | `0` | `+` (bounded wait, then detach) | `-` (stop jobs time out at 90 s) | `+` |
| Broken pipes / own session | `-` (bugs found) | `+` | `+` | `0` | `++` (refuse to kill own cgroup ancestry) | `0` | `++` |
| Speed to overlays gone | `-` (seconds: lock, owner wait, 300 ms sleeps, spawns) | `+` | `++` | `++` | `++` (tens of ms measured) | `0` | `++` |
| Visibility to an observer | `0` | `-` (second binary in `/run`) | `0` (plan file in `/run`, as `mounts.json` today) | `0` | `+` (no new units) | `-` (transient units listed) | `+` |
| Forensic residue | `0` | `0` | `+` (no decoy-write op exists in the plan) | `0` | `0` (systemd logs the unit death, into the runtime journal) | `-` (unit lines) | `+` |
| Code size / reviewability of the hot path | `--` (~11k reachable lines) | `+` | `++` | `0` | `+` | `0` | `++` (one small crate) |
| Testable on a real kernel | `0` (needs a VM for the whole stack) | `+` | `++` (userns tests like the PoC) | `++` | `++` (PoC exists) | `0` (VM only) | `++` |
| Migration cost | `++` (S) | `-` (M + release tooling) | `0` (M) | `--` (XL, redesign) | `+` (S–M) | `-` (M) | `0` (M–L, staged) |
| Fit with whole-root soft-reboot (T-132) | `0` | `+` | `++` (ops grow `SoftReboot`) | `0` | `++` | `+` | `++` |

## Decision

Adopt **F**. Do not ship a separate emergency binary. Do take the proposal's two
sound ideas, activation-time knowledge in RAM and the live mount table as the
fallback, and change three things: a crate boundary instead of an executable
boundary, a declarative idempotent plan instead of an undo journal, and
cgroup-granular kills instead of `/proc` heuristics.

### Shape

1. **`nails-teardown` crate.** It holds the plan types, the interpreter, the
   mountinfo reconcile pass and the cgroup and pidfd helpers. It has no
   dependency on `nails-core`'s config, state, manager, tracing or process
   runner, and Cargo enforces that, so reviewers can read the whole hot path in
   one place. `nails-core` depends on it for writing plans; `nails-cli` for
   executing them.
2. **Early dispatch.** `main` recognises `emergency` (and the watcher's trigger)
   before clap, config, platform detection and tracing set-up, and calls the
   interpreter directly. The full CLI is never initialised on the panic path.
3. **The plan** lives at `/run/overlay-runtime/` (mode 0600, rewritten
   atomically after every activation step; it supersedes `mounts.json`). The op
   set is closed and contains no op that writes to a decoy filesystem:
   - `StopUnit{name}`: an enqueued `--no-block` stop, fire-and-forget, with a
     short deadline, so `Restart=` cannot bring the unit back. It goes through
     the original-store loader path activation already prepares, never through
     an overlaid `/nix/store`.
   - `KillCgroup{path}`: write `cgroup.kill`. On kernels without it, loop over
     `cgroup.procs` with pidfd SIGKILL. The interpreter refuses any cgroup that
     contains it or is an ancestor of its own cgroup, which fixes the self-kill
     by construction.
   - `AwaitEmpty{paths, deadline}`: poll `cgroup.events`, bounded at around
     500 ms. A cgroup still populated, for example by a D-state task, is
     reported and the plan continues.
   - `KillShells`: a pidfd kill of every interactive shell outside the
     interpreter's own invocation, with the invoking shell recorded for the end.
   - `Detach{path, namespace}`: `umount2(path, UMOUNT_NOFOLLOW)`, falling back
     to `MNT_DETACH`, in reverse mount order. The `/nix/store` bind in PID 1's
     namespace keeps the existing `setns` helper.
   - `RelinkCurrentSystem{target}`: a symlink swap on tmpfs.
   - `DropCaches`.
   - `ScrubRuntimeJournal`.
   - `StartUnit{name}`: for decoy units such as `journald` and `nix-daemon`,
     started again after their overlays are gone.
   - `Power{poweroff|reboot}`: always last, and reached regardless of earlier
     failures.
4. **Hot-path order:**
   1. `StopUnit` for every recorded unit;
   2. `KillCgroup` for the recorded unit cgroups and non-graphical session
      scopes;
   3. `KillShells`;
   4. `AwaitEmpty`;
   5. `Detach` everything;
   6. **reconcile:** detach any NAILS-owned overlay or bind still in mountinfo
      (upper or source under the recorded hidden root), so a stale or missing
      plan can never leave a mount behind.

   The bookkeeping comes after the unmount: relink, `StartUnit`, scrub, drop
   caches, the optional backend lock, and the power action. A best-effort
   state-file update on the hidden volume, if it is still writable, runs after
   everything else. Output is written once at the end, through the pipe-safe
   writer, and the invoking shell is killed through its pidfd after that.
5. **No plan, or a corrupt plan:** the interpreter derives the same op list
   from mountinfo (NAILS-owned overlays and binds), the cgroups of every process
   pinning those mounts, read from `/proc/<pid>/cgroup` without `stat()`ing
   anything on the overlay, and minus the graphical-session cgroups. This is
   today's `recover` logic, moved into the crate.
6. **The graphical session** keeps today's policy (option 2 in
   `session_guard.rs`): its cgroups are never in `KillCgroup`. The guard's cgroup
   fragments are computed at activation and stored in the plan, so no `loginctl`
   runs at panic time.

### Why F beats the proposal

- It keeps one release artifact and one unusual file in `/run`, and no second
  build, signature or verification path.
- It gets the same isolation through a Cargo-enforced dependency boundary and
  early dispatch. Extracting the crate into its own binary later stays a
  mechanical change if a reason ever appears.
- A declarative plan is idempotent and survives a partial or repeated run.
- It replaces heuristic process matching, which is the source of three of the
  review's bugs, with kernel-exact cgroup membership. That kill is atomic
  against forks, cannot hit a reused pid, and touches no file on the dead
  volume.
- It closes the `Restart=` hole the VM experiment found. The proposal would have
  carried today's per-pid kill, and that hole, over unchanged.

## Consequences and risks

- **Minimum kernel.** `cgroup.kill` needs 5.14 (Ubuntu 22.04: 5.15; Debian 12:
  6.1; NixOS stable: newer). Older kernels take the `cgroup.procs` + pidfd loop
  fallback, which is weaker against fork races. Do **not** fall back to
  `cgroup.freeze` (ADR 0004).
- **systemd sees the kills.** Each killed unit logs 5–8 lines. At this point in
  the teardown `/var` is still the hidden overlay or has been relinquished to
  `/run/log/journal`, which the scrub then wipes. A decoy unit killed without a
  stop job could otherwise be left `failed` and show in `systemctl --failed`.
  The stop job plus `StartUnit` for decoy units avoids that.
- **The stop job needs PID 1 over D-Bus** and an exec. Both are fire-and-forget
  with deadlines, and the kill does not wait for them. If they fail, a
  restartable unit may come back, either on the decoy after the detach or
  pinning a lazily detached overlay before it. The report says so.
- **D-state.** Nothing in userspace can end an uninterruptible sleep. With a
  hung backend, the opt-in backend lock can replace the dm table with the
  `error` target so blocked I/O fails and the tasks can die. That interaction
  needs a fault VM test (`faults/91-hidden-disk-removed.nix`) before it is
  claimed.
- **Spared graphical processes** still pin lazily detached overlays and the
  backend, as today. Report that honestly and recommend `--poweroff`.
- **The plan file** reveals the mount points only while a session is active,
  when `/proc/mounts` shows them anyway. It is removed at the end of the
  teardown. Its bytes stay in freed tmpfs pages until overwritten, the same
  residue `init_on_free=1` (operator guide) addresses.
- **Power actions.** `systemctl poweroff` can stall on stop jobs for hung
  mounts. Consider an immediate `reboot(2)` fallback after a deadline, at the
  price of an unclean-shutdown marker on decoy filesystems. That trade-off is
  left to the operator guide.
- **Migration** is staged, and each stage is shippable:
  1. the crate with userns tests modelled on the PoC (overlays, binds, cgroups,
     pidfds, reconcile);
  2. activation writes the plan, recording unit cgroups and session-guard
     fragments;
  3. early dispatch, with the watcher calling the interpreter in-process;
  4. the `/proc` device-matching kill and `signal_pid` remain only in the
     no-plan fallback;
  5. the research VM test grows into a regular `faults` test.

## Fit with the whole-root soft-reboot mode (T-132)

In a whole-root mode the entire userspace runs on the overlay root after
`systemctl soft-reboot` into `/run/nextroot`. A soft reboot sends SIGTERM and
SIGKILL to everything without `SurviveFinalKillSignal=`, keeps `/run`, and
starts the new root's systemd. Returning to the decoy means switching userspace
again: a soft reboot into the decoy root, or a power-off. Both necessarily end
the graphical session, so **the no-logout ruling cannot hold in that mode** and
needs its own ruling.

Architecture F carries over unchanged. The plan gains a `SoftReboot{root}` op,
and `KillCgroup` on the hidden userspace's slices before it shortens the
switch. It also stops exit handlers from flushing hidden data, and frees any
private mount namespaces, so the old overlay root is not pinned when the
userspace switches. The cgroup model is the natural fit there because, in that
mode, every hidden process is by definition in a cgroup of the hidden boot.
Mount namespaces add nothing beyond what the soft reboot itself does.

## Sources

- Linux cgroup v2 documentation: `cgroup.kill`, `cgroup.events`, delegation.
  <https://docs.kernel.org/admin-guide/cgroup-v2.html>
- "A 'kill' button for control groups", LWN (`cgroup.kill`, Linux 5.14).
  <https://lwn.net/Articles/855049/>
- cgroup pull for v5.14-rc1. <https://lkml.iu.edu/hypermail/linux/kernel/2107.0/00573.html>
- "Hastening process cleanup with process_mrelease()", LWN (Linux 5.15).
  <https://lwn.net/Articles/864184/>
- `umount2(2)`: `MNT_DETACH`, `UMOUNT_NOFOLLOW`. <https://man7.org/linux/man-pages/man2/umount2.2.html>
- `pidfd_open(2)`, `pidfd_send_signal(2)`. <https://man7.org/linux/man-pages/man2/pidfd_open.2.html>,
  <https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html>
- `mount_namespaces(7)`: propagation and namespace lifetime.
  <https://man7.org/linux/man-pages/man7/mount_namespaces.7.html>
- overlayfs documentation: `index=on` and the upper/work in-use check.
  <https://docs.kernel.org/filesystems/overlayfs.html>
- `systemd-soft-reboot.service(8)`. <https://man7.org/linux/man-pages/man8/systemd-soft-reboot.service.8.html>
- systemd 254 release (soft-reboot, `/run/nextroot`). <https://lwn.net/Articles/939511/>,
  <https://github.com/systemd/systemd/releases/tag/v254>
- `systemd.kill(5)` and `systemd.service(5)` (`Restart=`, `KillMode=`).
  <https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html>
- In-repo evidence: `nails-core/tests/research_emergency_kernel.rs`,
  `nix/e2e-tests/tests/research/01-emergency-cgroup-kill.nix`; ADR 0004 (no
  `cgroup.freeze`, no `systemd-mount`), ADR 0005 (live overlay), T-132.
